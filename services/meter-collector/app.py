#!/usr/bin/env python3
"""
SDN Meter Collector — Colector de Telemetría de Medidores IoT
==============================================================
Microservicio dual:
  1. Servidor UDP: escucha en :5555, recibe lecturas JSON de los medidores.
  2. API Flask:    expone /api/meters y /api/meters/<id> para consulta.
  3. Web UI:       dashboard en tiempo real con actualización automática.
  4. Redis:        persiste las últimas lecturas y estadísticas por device_id.

Variables de entorno:
  REDIS_SENTINEL_HOST  Host del Sentinel (default: redis-sentinel.sdn-controller.svc.cluster.local)
  REDIS_SENTINEL_PORT  Puerto Sentinel (default: 26379)
  UDP_PORT             Puerto de escucha UDP (default: 5555)
  FLASK_PORT           Puerto HTTP (default: 5000)
  MAX_READINGS_PER_DEVICE  Historial máximo por medidor en Redis (default: 100)
  HMAC_ENABLED         Requiere firma HMAC-SHA256 (default: true)
  HMAC_SECRET          Secreto global de fallback para medidores
  HMAC_DEVICE_SECRETS  JSON opcional {"device_id":"secret"}
  MAX_TIME_SKEW_SECONDS Ventana permitida de timestamp Unix (default: 60)
  NONCE_TTL_SECONDS    TTL de nonces aceptados para evitar replay (default: 300)
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import threading
import logging
import hmac
import hashlib
import heapq
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from flask import Flask, Response, jsonify, render_template, request
from redis.sentinel import Sentinel
import redis as redis_lib

import registry

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [COLLECTOR] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger(__name__)

SENTINEL_HOST         = os.environ.get("REDIS_SENTINEL_HOST", "redis-sentinel.sdn-controller.svc.cluster.local")
SENTINEL_PORT         = int(os.environ.get("REDIS_SENTINEL_PORT", 26379))
# Servicio HEADLESS: su DNS resuelve a TODOS los pods sentinel (uno por nodo). Se
# usa para construir la lista multi-endpoint de Sentinel, de modo que la caída de
# un control-plane (un sentinel inalcanzable) no deje a la API sin Redis (503): el
# cliente prueba los demás sentinels. El ClusterIP único no permite ese failover.
SENTINEL_HEADLESS     = os.environ.get("REDIS_SENTINEL_HEADLESS", "redis-headless.sdn-controller.svc.cluster.local")
REDIS_SOCKET_TIMEOUT = float(os.environ.get("REDIS_SOCKET_TIMEOUT", "1.0"))
# Reintento de reconexión más ágil: un control-plane caído debe recuperarse en
# segundos, no en ~10s (ventana en la que la API devolvía 503 prolongado).
REDIS_RECONNECT_INTERVAL = float(os.environ.get("REDIS_RECONNECT_INTERVAL", "3.0"))
REDIS_RECONNECT_ATTEMPTS = int(os.environ.get("REDIS_RECONNECT_ATTEMPTS", "2"))
UDP_PORT              = int(os.environ.get("UDP_PORT", 5555))
FLASK_PORT            = int(os.environ.get("FLASK_PORT", 5000))
MAX_READINGS          = int(os.environ.get("MAX_READINGS_PER_DEVICE", 100))
HMAC_ENABLED          = os.environ.get("HMAC_ENABLED", "true").lower() in ("1", "true", "yes", "on")
HMAC_SECRET           = os.environ.get("HMAC_SECRET", "")
MAX_TIME_SKEW_SECONDS = int(os.environ.get("MAX_TIME_SKEW_SECONDS", 60))
NONCE_TTL_SECONDS     = int(os.environ.get("NONCE_TTL_SECONDS", 300))
ACTIVE_METER_MAX_AGE_SECONDS = int(os.environ.get("ACTIVE_METER_MAX_AGE_SECONDS", 30))

try:
    HMAC_DEVICE_SECRETS = json.loads(os.environ.get("HMAC_DEVICE_SECRETS", "{}"))
except json.JSONDecodeError:
    HMAC_DEVICE_SECRETS = {}
    log.warning("HMAC_DEVICE_SECRETS inválido; se ignora configuración por dispositivo.")

# Cache en memoria (fallback si Redis no está disponible)
_memory_cache: dict[str, list] = defaultdict(list)
_memory_nonces: dict[str, float] = {}
_memory_hmac_counters: dict[str, int] = defaultdict(int)
_cache_lock = threading.Lock()
_redis_metrics: dict[tuple[str, str], dict[str, float]] = {}
_redis_metrics_lock = threading.Lock()

# Última vista buena del registro persistente de nodos (topology:switches /
# node_names / node_ips). Sirve para no colapsar las APIs SDN a "0 nodos" cuando
# una lectura transitoria de Redis devuelve vacío (failover de Sentinel o una
# réplica resincronizando durante el reinicio de un worker).
_node_registry_snapshot: dict = {"switches": set(), "node_names": {}, "node_ips": {}, "ts": 0.0}
_node_registry_lock = threading.Lock()
# Cuánto tiempo (s) servir el snapshot persistente cuando Redis responde vacío.
NODE_SNAPSHOT_TTL = float(os.environ.get("NODE_SNAPSHOT_TTL", "600"))
# Ventana de gracia (s) para seguir mostrando un switch (marcado stale) tras
# perder su heartbeat switch:alive. Evita que un nodo que solo reconverge
# desaparezca de la topología; los nodos realmente ausentes caen al superarla.
NODE_STALE_GRACE = float(os.environ.get("NODE_STALE_GRACE", "600"))
# Ventana (s) tras la cual un nodo SIN switch:alive se considera AUSENTE para el
# MAPA SDN (no solo stale) y se retira, aunque ningun vecino haya publicado
# switch:dead (la deteccion por probe/OSPF falla cuando el nodo se ELIMINA de la
# topologia: OSPF retira su ruta y el probe deja de medirlo). Mayor que el TTL de
# switch:alive (~45s) para no parpadear ante un blip de heartbeat, y mucho menor
# que NODE_STALE_GRACE (600s) para que un nodo borrado salga del mapa en ~2-3min
# sin esperar la gracia completa. La SEGURIDAD conserva la gracia larga (lo marca
# inactivo). Un nodo vivo refresca node_last_seen mucho antes de este umbral.
NODE_MAP_DEAD_AFTER = float(os.environ.get("NODE_MAP_DEAD_AFTER", "150"))


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class RedisMetricsProxy:
    def __init__(self, client, service: str):
        self._client = client
        self._service = service

    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        def wrapped(*args, **kwargs):
            start = time.time()
            status = "ok"
            try:
                return attr(*args, **kwargs)
            except Exception:
                status = "error"
                raise
            finally:
                record_redis_metric(name, status, time.time() - start)

        return wrapped


def record_redis_metric(operation: str, status: str, duration: float):
    key = (str(operation), str(status))
    with _redis_metrics_lock:
        metric = _redis_metrics.setdefault(key, {"count": 0, "seconds": 0.0, "max": 0.0})
        metric["count"] += 1
        metric["seconds"] += duration
        if duration > metric["max"]:
            metric["max"] = duration


def escape_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
def _resolve_sentinels() -> list[tuple[str, int]]:
    """Lista de endpoints sentinel. Resuelve el servicio HEADLESS a TODOS los pods
    sentinel (uno por nodo) para que el cliente pueda hacer failover si uno cae con
    su control-plane. Cae al ClusterIP si la resolución headless falla."""
    endpoints: list[tuple[str, int]] = []
    seen: set[str] = set()
    for host in (SENTINEL_HEADLESS, SENTINEL_HOST):
        try:
            for info in socket.getaddrinfo(host, SENTINEL_PORT, proto=socket.IPPROTO_TCP):
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    endpoints.append((ip, SENTINEL_PORT))
        except Exception:
            continue
    if not endpoints:
        endpoints = [(SENTINEL_HOST, SENTINEL_PORT)]
    return endpoints


def connect_redis(attempts: int | None = None, sleep_between: bool = True) -> redis_lib.Redis | None:
    """Conecta a Redis Sentinel con reintentos. Retorna None si falla."""
    attempts = attempts or REDIS_RECONNECT_ATTEMPTS
    for attempt in range(1, attempts + 1):
        try:
            sentinel = Sentinel(
                _resolve_sentinels(),
                socket_timeout=REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=REDIS_SOCKET_TIMEOUT,
            )
            r = sentinel.master_for(
                "mymaster",
                socket_timeout=REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=REDIS_SOCKET_TIMEOUT,
                decode_responses=True,
            )
            r.ping()
            log.info("Conexión a Redis Sentinel exitosa.")
            return RedisMetricsProxy(r, "meter-collector")
        except Exception as e:
            log.warning("Intento %d/%d — Redis no disponible: %s", attempt, attempts, e)
            if sleep_between and attempt < attempts:
                time.sleep(1)
    log.error("No se pudo conectar a Redis. Operando en modo memoria.")
    return None


r: redis_lib.Redis | None = None
_last_redis_connect_attempt = 0.0
_redis_lock = threading.Lock()
_redis_last_ok = 0.0
_redis_last_error = "not_connected"

def get_redis() -> redis_lib.Redis | None:
    """Retorna la conexión Redis (reconecta si perdió el enlace)."""
    global r, _last_redis_connect_attempt, _redis_last_ok, _redis_last_error
    if r is None:
        now = time.time()
        if now - _last_redis_connect_attempt < REDIS_RECONNECT_INTERVAL:
            return None
        if not _redis_lock.acquire(False):
            return None
        _last_redis_connect_attempt = now
        try:
            log.warning("Redis no está conectado. Intentando reconectar...")
            r = connect_redis(attempts=1, sleep_between=False)
            if r is not None:
                _redis_last_ok = time.time()
                _redis_last_error = ""
        except Exception as e:
            _redis_last_error = str(e)
            r = None
        finally:
            _redis_lock.release()
        return r
    try:
        r.ping()
        _redis_last_ok = time.time()
        _redis_last_error = ""
        return r
    except Exception as e:
        _redis_last_error = str(e)
        log.warning("Redis perdió conexión: %s", e)
        r = None
        return r


def redis_is_ready() -> bool:
    redis = get_redis()
    if redis is None:
        return False
    try:
        redis.ping()
        return True
    except Exception:
        return False


def redis_status_snapshot() -> dict:
    return {
        "connected": r is not None,
        "last_ok_seconds_ago": round(time.time() - _redis_last_ok, 1) if _redis_last_ok else None,
        "last_error": _redis_last_error,
    }


def telemetry_source_authorization(source_ip: str, device_id: str = "") -> tuple[bool, str]:
    redis = get_redis()
    if redis is None or not source_ip:
        return False, "security_unavailable"
    try:
        observed = _observed_guests_for_ip(redis, source_ip)
        if not observed:
            return False, "source_not_observed"
        if len(observed) > 1:
            return False, "ambiguous_source_ip"
        guest = observed[0]
        allowed, reason, device = registry.validate_observed_device(
            redis,
            guest.get("mac", ""),
            source_ip,
            guest.get("dpid", ""),
            guest.get("in_port", ""),
        )
        if not allowed:
            return False, reason
        if device_id and device and device.get("device_id") != device_id:
            return False, "device_id_mismatch"
        return True, "authorized"
    except Exception as e:
        log.warning("No se pudo validar estado de seguridad para source=%s: %s", source_ip, e)
        return False, "security_error"


def telemetry_source_allowed(source_ip: str) -> bool:
    return telemetry_source_authorization(source_ip)[0]


def _observed_guests_for_ip(redis, source_ip: str) -> list[dict]:
    if not source_ip:
        return []
    observed = []
    guest_ips = redis.hgetall("topology:guest_ips")
    for mac, ip in guest_ips.items():
        if ip != source_ip:
            continue
        mac = registry.normalize_mac(mac)
        location = redis.hget("topology:guest_locations", mac) or ""
        dpid, _, in_port = str(location).partition(":")
        observed.append({"mac": mac, "ip": source_ip, "dpid": dpid, "in_port": in_port})
    return observed


def _observed_guest_for_ip(redis, source_ip: str) -> dict | None:
    observed = _observed_guests_for_ip(redis, source_ip)
    if len(observed) != 1:
        return None
    return observed[0]


def _cleanup_recreated_meter(redis, device_id: str, current_mac: str, current_ip: str):
    if not device_id or not current_mac:
        return
    for key in redis.scan_iter("meter:latest:*"):
        if key == f"meter:latest:{device_id}":
            continue
        latest = redis.hgetall(key) or {}
        if latest.get("device_id") == device_id:
            redis.delete(key)

    for mac, ip in redis.hgetall("topology:guest_ips").items():
        mac = registry.normalize_mac(mac)
        if mac == current_mac or ip == current_ip:
            continue
        health_key = f"health:{mac}"
        health_matches = False
        if redis.type(health_key) == "hash":
            health = redis.hgetall(health_key) or {}
            health_matches = health.get("device_id") == device_id or health.get("name") == device_id
        if health_matches:
            redis.hdel("topology:guest_ips", mac)
            redis.hdel("topology:guest_locations", mac)
            redis.hdel("topology:guest_names", mac)
            redis.delete(health_key)


def _record_identity_rejection(reason: str, device_id: str, source_ip: str, detail: dict | None = None):
    """Registra (sin mutar identidad) un intento de spoofing detectado al
    sincronizar. Comparte el stream `security:events` con Ryu para que la
    API/Grafana/Loki muestren un unico flujo de eventos de seguridad."""
    with _cache_lock:
        _memory_hmac_counters["identity_rejected_total"] += 1
        _memory_hmac_counters[f"identity_rejected_total:{reason}"] += 1

    redis = get_redis()
    if redis is not None:
        try:
            event = {
                "time": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "device_id": device_id,
                "source_ip": source_ip,
                "component": "meter-collector",
            }
            if detail:
                event["detail"] = detail
            pipe = redis.pipeline()
            pipe.lpush("security:events", json.dumps(event))
            pipe.ltrim("security:events", 0, 499)
            pipe.incr(f"security:event_counter:{reason}")
            pipe.incr("security:event_counter:total")
            pipe.execute()
        except Exception as e:
            log.warning("No se pudo registrar rechazo de identidad reason=%s: %s", reason, e)
    log.warning("Identidad AMI NO mutada reason=%s device=%s source=%s detail=%s", reason, device_id, source_ip, detail)


def _register_observed_meter(redis, device_id: str, source_ip: str) -> bool:
    if not device_id.startswith("SDNSmartMeter-"):
        return False
    observed = _observed_guest_for_ip(redis, source_ip)
    if not observed or not observed.get("mac"):
        return False

    existing = registry.get_device(redis, device_id)
    if existing and existing.get("status") in ("blocked", "quarantined"):
        return False

    # Only auto-register VMs that were previously authorized (MAC/IP changed on recreation).
    # New devices require explicit operator approval via the UI (POST /api/devices).
    if not existing or existing.get("status") != "authorized":
        return False

    # Ancla de confianza: la MAC observada debe coincidir con la MAC registrada
    # (determinista por hostname, estable ante reboot/recreacion). Si difiere es
    # un posible spoof L2 -> NO adoptar la identidad basandose solo en trafico.
    observed_mac = registry.normalize_mac(observed.get("mac", ""))
    registered_mac = registry.normalize_mac(existing.get("mac", ""))
    if registered_mac and observed_mac and observed_mac != registered_mac:
        _record_identity_rejection("identity_conflict", device_id, source_ip,
                                   {"registered_mac": registered_mac, "observed_mac": observed_mac})
        return False

    registry.save_device(redis, {
        "device_id": device_id,
        "mac": registered_mac or observed_mac,
        "ip": source_ip,
        "role": "smart_meter",
        "allowed_dst_ip": "10.0.0.1",
        "allowed_udp_port": UDP_PORT,
        "status": "authorized",
        "dpid": observed.get("dpid", ""),
        "in_port": observed.get("in_port", ""),
    })
    _cleanup_recreated_meter(redis, device_id, registered_mac or observed_mac, source_ip)
    log.info("Smart Meter recreado adoptado automaticamente device=%s source=%s mac=%s", device_id, source_ip, registered_mac or observed_mac)
    return True


def sync_security_identity(device_id: str, source_ip: str):
    if not device_id or not source_ip:
        return
    redis = get_redis()
    if redis is None:
        return
    try:
        current_id = redis.get(f"security:ip_to_device:{source_ip}")
        raw = None
        if current_id == device_id:
            raw = redis.get(f"security:device:{device_id}")
        elif current_id:
            raw = redis.get(f"security:device:{current_id}")
        else:
            raw = redis.get(f"security:device:{device_id}")

        if not raw:
            _register_observed_meter(redis, device_id, source_ip)
            return
        device = json.loads(raw)
        if device.get("role") != "smart_meter":
            return

        # ENDURECIDO (anti-IP/MAC-spoofing): NUNCA mutar la identidad de un
        # dispositivo ya autorizado basandose solo en trafico recibido. La MAC
        # registrada es el ancla de confianza (alta manual, determinista por
        # hostname). Solo se refresca IP/ubicacion cuando la MAC OBSERVADA en el
        # binding L2 coincide con la registrada (caso real: VM recreada / IP nueva
        # por DHCP). Cualquier discrepancia de MAC o de propietario de IP es un
        # posible spoof: se registra el rechazo y NO se muta nada.
        registered_mac = registry.normalize_mac(device.get("mac", ""))
        observed = _observed_guest_for_ip(redis, source_ip) or {}
        observed_mac = registry.normalize_mac(observed.get("mac", ""))

        # La IP de origen ya pertenece a OTRO dispositivo registrado -> conflicto.
        if current_id and current_id != device_id:
            _record_identity_rejection("identity_conflict", device_id, source_ip,
                                       {"ip_owner": current_id})
            return

        # Sin binding L2 observado confiable para esa IP no hay senal segura:
        # se exige intervencion manual (no se auto-actualiza).
        if not observed_mac:
            _record_identity_rejection("identity_unverified", device_id, source_ip)
            return

        # MAC observada distinta de la registrada -> spoofing de MAC/identidad.
        if registered_mac and observed_mac != registered_mac:
            _record_identity_rejection("identity_conflict", device_id, source_ip,
                                       {"registered_mac": registered_mac, "observed_mac": observed_mac})
            return

        # MAC verificada: refresco seguro de IP/ubicacion (la MAC no cambia).
        old_id = device.get("device_id", current_id or device_id)
        old_ip = device.get("ip", "")
        old_dpid = device.get("dpid", "")
        old_in_port = device.get("in_port", "")
        device["device_id"] = device_id
        device["ip"] = source_ip
        device["mac"] = registered_mac or observed_mac
        device["dpid"] = observed.get("dpid", device.get("dpid", ""))
        device["in_port"] = observed.get("in_port", device.get("in_port", ""))
        mac = registry.normalize_mac(device.get("mac", ""))

        if (
            old_id == device_id
            and old_ip == source_ip
            and old_dpid == str(device.get("dpid", ""))
            and old_in_port == str(device.get("in_port", ""))
        ):
            return
        pipe = redis.pipeline()
        pipe.set(f"security:device:{device_id}", json.dumps(device, sort_keys=True))
        pipe.sadd("security:devices", device_id)
        if old_id != device_id:
            pipe.srem("security:devices", old_id)
        pipe.set(f"security:ip_to_device:{source_ip}", device_id)
        if old_ip and old_ip != source_ip:
            pipe.delete(f"security:ip_to_device:{old_ip}")
        if mac:
            pipe.set(f"security:mac_to_device:{mac}", device_id)
        if old_id != device_id:
            pipe.delete(f"security:device:{old_id}")
        pipe.execute()
        _cleanup_recreated_meter(redis, device_id, mac, source_ip)
        log.info("Registro AMI refrescado (MAC verificada) source=%s old_device=%s device=%s old_ip=%s old_dpid=%s new_dpid=%s old_in_port=%s new_in_port=%s",
                 source_ip, old_id, device_id, old_ip, old_dpid, device.get("dpid"), old_in_port, device.get("in_port"))
    except Exception as e:
        log.warning("No se pudo sincronizar identidad AMI source=%s device=%s: %s", source_ip, device_id, e)


def normalize_dpid(dpid):
    if not dpid:
        return ""
    value = str(dpid)
    if value.isdigit():
        return value
    try:
        return str(int(value, 16))
    except Exception:
        return value


def raw_dpid_from(dpid):
    if not dpid:
        return ""
    value = str(dpid)
    if value.isdigit():
        return "0000" + hex(int(value))[2:].zfill(12)
    return value if value.startswith("0000") else "0000" + value[-12:]


def mac_from_raw_dpid(raw_dpid):
    raw_mac = str(raw_dpid or "")[-12:]
    if len(raw_mac) != 12:
        return ""
    return ":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower()


def edge_link_id(source, target):
    return "--".join(sorted([str(source), str(target)]))


def looks_like_worker_name(name):
    value = (name or "").lower()
    return value.startswith(("worker", "master", "maestro", "control-"))


def observed_workers(redis):
    # Registro persistente con fallback a la última vista buena: una lectura
    # transitoria vacía durante el reinicio de un worker no debe devolver 0
    # workers. La liveness se refleja en "online"/"stale", no ocultando el nodo.
    switches, node_names, node_ips, _degraded = read_node_registry(redis)
    known = known_switch_dpids(redis, node_names, switches)
    # Seguridad (a diferencia del mapa): además de los vivos/en-gracia, mostrar los
    # nodos CONFIRMADOS muertos (marca switch:dead que pone Ryu vía probe) aunque
    # excedan la ventana de gracia, para reflejarlos como INACTIVO de forma
    # persistente —como Grafana— mientras siguen caídos. La marca caduca sola y se
    # borra al revivir el nodo, así que NO reaparecen entradas stale (las viejas no
    # tienen marca). El mapa, en cambio, los oculta (exclude_dead=True).
    for raw_dpid in node_names:
        if redis.exists(f"switch:dead:{raw_dpid}"):
            known.add(normalize_dpid(raw_dpid))
    workers = []
    for raw_dpid, name in sorted(node_names.items(), key=lambda item: item[1]):
        if not looks_like_worker_name(name):
            continue
        if normalize_dpid(raw_dpid) not in known:
            continue  # nodo fuera de la ventana de gracia: realmente ausente
        mac = ""
        if len(raw_dpid) >= 12:
            raw_mac = raw_dpid[-12:]
            mac = ":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower()
        online = bool(redis.exists(f"switch:alive:{raw_dpid}"))
        workers.append({
            "mac": mac,
            "ip": node_ips.get(raw_dpid, ""),
            "name": name,
            "dpid": normalize_dpid(raw_dpid),
            "raw_dpid": raw_dpid,
            "in_port": "",
            "port_name": "node",
            "node_name": name,
            "online": online,
            "stale": not online,
            "kind": "worker",
        })
    return workers


def observed_guests(redis):
    guest_ips = redis.hgetall("topology:guest_ips")
    guest_names = redis.hgetall("topology:guest_names")
    node_names = redis.hgetall("topology:node_names")
    worker_macs = registry.known_worker_macs(redis)
    registered_macs = {registry.normalize_mac(device.get("mac", "")) for device in registry.list_devices(redis)}
    guests = {}
    active_mac_locations = {}

    for key in redis.scan_iter("active_mac:*"):
        parts = key.split(":", 2)
        if len(parts) == 3:
            active_mac_locations[registry.normalize_mac(parts[2])] = parts[1]

    def guest_is_online(mac):
        if redis.exists(f"health:{mac}"):
            return True
        return mac in active_mac_locations

    def guest_is_registered(mac):
        return mac in registered_macs or bool(registry.get_by_index(redis, registry.KEY_MAC_TO_DEVICE, mac))

    def raw_dpid_from(dpid):
        return "0000" + hex(int(dpid))[2:].zfill(12) if str(dpid).isdigit() else str(dpid)

    for mac, ip in guest_ips.items():
        mac = registry.normalize_mac(mac)
        if mac in worker_macs or looks_like_worker_name(guest_names.get(mac, "")):
            continue
        guests[mac] = {
            "mac": mac,
            "ip": ip,
            "name": guest_names.get(mac, ""),
            "dpid": "",
            "in_port": "",
            "port_name": "",
            "node_name": "",
            "online": guest_is_online(mac),
            "kind": "guest",
        }

    for mac, dpid in active_mac_locations.items():
        if mac in guests or mac in worker_macs or looks_like_worker_name(guest_names.get(mac, "")):
            continue
        ip = redis.get(f"dhcp:bind:{mac}") or ""
        if not ip:
            continue
        raw_dpid = raw_dpid_from(dpid)
        guests[mac] = {
            "mac": mac,
            "ip": ip,
            "name": guest_names.get(mac, ""),
            "dpid": str(dpid),
            "in_port": "",
            "port_name": "active_mac",
            "node_name": node_names.get(raw_dpid, ""),
            "online": guest_is_online(mac),
            "kind": "guest",
        }

    for mac, location in redis.hgetall("topology:guest_locations").items():
        mac = registry.normalize_mac(mac)
        if mac in worker_macs or looks_like_worker_name(guest_names.get(mac, "")):
            continue
        dpid, _, in_port = str(location).partition(":")
        if not dpid or not in_port:
            continue
        ports = redis.hgetall(f"switch_ports:{dpid}")
        port_name = ports.get(str(in_port), "")
        if port_name.startswith("vx") or port_name == "br-sdn" or str(in_port) == "4294967294":
            continue
        dhcp_ip = redis.get(f"dhcp:bind:{mac}") or guest_ips.get(mac, "")
        raw_dpid = raw_dpid_from(dpid)
        guest = guests.setdefault(mac, {
            "mac": mac,
            "ip": dhcp_ip,
            "name": guest_names.get(mac, ""),
            "online": guest_is_online(mac),
            "kind": "guest",
        })
        if dhcp_ip and not guest.get("ip"):
            guest["ip"] = dhcp_ip
        guest.update({
            "dpid": str(dpid),
            "in_port": str(in_port),
            "port_name": port_name,
            "node_name": node_names.get(raw_dpid, ""),
            "online": guest_is_online(mac),
            "kind": "guest",
        })

    for key in redis.scan_iter("mac_to_port:*"):
        dpid = key.split(":", 1)[1]
        ports = redis.hgetall(f"switch_ports:{dpid}")
        for mac, in_port in redis.hgetall(key).items():
            mac = registry.normalize_mac(mac)
            if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                continue
            if mac in worker_macs or looks_like_worker_name(guest_names.get(mac, "")):
                continue
            if mac in guests and guests[mac].get("dpid") and guests[mac].get("in_port"):
                continue
            port_name = ports.get(str(in_port), "")
            if not port_name.startswith("ens"):
                continue
            dhcp_ip = redis.get(f"dhcp:bind:{mac}") or ""
            if mac not in guests and not dhcp_ip:
                continue
            guest = guests.setdefault(mac, {"mac": mac, "ip": dhcp_ip, "name": guest_names.get(mac, ""), "online": guest_is_online(mac)})
            raw_dpid = raw_dpid_from(dpid)
            guest.update({
                "dpid": str(dpid),
                "in_port": str(in_port),
                "port_name": port_name,
                "node_name": node_names.get(raw_dpid, ""),
                "online": guest_is_online(mac),
                "kind": "guest",
            })

    meter_by_ip = {}
    for key in redis.scan_iter("meter:latest:*"):
        source_ip = (redis.hget(key, "source_ip") or "").strip()
        device_id = (redis.hget(key, "device_id") or "").strip()
        if source_ip:
            meter_by_ip[source_ip] = device_id
    live_meter_ips = set(meter_by_ip)

    rejected_meter_by_ip = {}
    recent_rejection_cutoff = datetime.now(timezone.utc) - timedelta(minutes=2)
    for raw_event in redis.lrange("meter:hmac:events", 0, 199) or []:
        try:
            event = json.loads(raw_event)
            event_time = datetime.fromisoformat(str(event.get("time", "")).replace("Z", "+00:00"))
        except Exception:
            continue
        if event_time < recent_rejection_cutoff:
            continue
        source_ip = str(event.get("source_ip", "")).strip()
        device_id = str(event.get("device_id", "")).strip()
        if source_ip and device_id and source_ip not in rejected_meter_by_ip:
            rejected_meter_by_ip[source_ip] = device_id

    registered_devices = registry.list_devices(redis)
    device_by_mac = {registry.normalize_mac(device.get("mac", "")): device for device in registered_devices}

    for device in registered_devices:
        mac = registry.normalize_mac(device.get("mac", ""))
        if not mac or mac in guests or mac in worker_macs:
            continue
        ip = device.get("ip", "")
        guests[mac] = {
            "mac": mac,
            "ip": ip,
            "name": device.get("device_id", ""),
            "dpid": device.get("dpid", ""),
            "in_port": device.get("in_port", ""),
            "port_name": "registered",
            "node_name": "",
            "online": ip in meter_by_ip or guest_is_online(mac),
            "kind": "guest",
        }
    for guest in guests.values():
        guest["telemetry_device_id"] = meter_by_ip.get(guest.get("ip", ""), "") or rejected_meter_by_ip.get(guest.get("ip", ""), "")
        if guest.get("ip") in meter_by_ip:
            guest["online"] = True
            if not guest.get("name") and guest["telemetry_device_id"]:
                guest["name"] = guest["telemetry_device_id"]
        elif not guest.get("name") and guest["telemetry_device_id"]:
            guest["name"] = guest["telemetry_device_id"]
    def should_show_guest(guest):
        if guest.get("ip") in live_meter_ips:
            return True
        if not guest_is_registered(guest["mac"]):
            return bool(guest.get("telemetry_device_id"))
        device = device_by_mac.get(guest["mac"], {})
        return device.get("status") in ("quarantined", "blocked") and bool(guest.get("dpid") and guest.get("in_port"))

    current_guests = [guest for guest in guests.values() if should_show_guest(guest)]
    return sorted(current_guests, key=lambda item: (item.get("ip") or "", item["mac"]))


def with_security_state(redis, guest):
    if guest.get("kind") == "worker":
        guest["registered"] = True
        guest["security_status"] = "worker"
        guest["validation"] = {"allowed": True, "reason": "worker_auto_allowed"}
        guest["device"] = None
        return guest
    device = registry.get_by_index(redis, registry.KEY_MAC_TO_DEVICE, registry.normalize_mac(guest["mac"]))
    if not device:
        guest["registered"] = False
        guest["security_status"] = "unregistered"
        guest["device"] = None
        return guest
    allowed, reason, _ = registry.validate_observed_device(redis, guest["mac"], guest.get("ip", ""), guest.get("dpid", ""), guest.get("in_port", ""))
    guest["registered"] = True
    guest["security_status"] = device.get("status", "unknown")
    guest["validation"] = {"allowed": allowed, "reason": reason}
    guest["device"] = device
    guest["device_id"] = guest.get("telemetry_device_id") or device.get("device_id", "")
    return guest


def read_node_registry(redis):
    """Lee el registro persistente de nodos con fallback a la última vista buena.

    Devuelve (switches, node_names, node_ips, degraded). Si Redis responde con un
    registro vacío (lectura transitoria contra una réplica resincronizando o
    durante un failover de Sentinel) pero hay un snapshot reciente no vacío,
    devuelve ese snapshot con degraded=True en lugar de propagar un estado vacío
    que vaciaría /api/guests y /api/sdn-topology de forma global.
    """
    switches = set(redis.smembers("topology:switches") or [])
    node_names = redis.hgetall("topology:node_names") or {}
    node_ips = redis.hgetall("topology:node_ips") or {}
    if node_names or switches:
        with _node_registry_lock:
            _node_registry_snapshot.update(
                switches=set(switches), node_names=dict(node_names),
                node_ips=dict(node_ips), ts=time.time())
        return switches, node_names, node_ips, False
    with _node_registry_lock:
        age = time.time() - _node_registry_snapshot["ts"]
        if _node_registry_snapshot["node_names"] and age < NODE_SNAPSHOT_TTL:
            return (set(_node_registry_snapshot["switches"]),
                    dict(_node_registry_snapshot["node_names"]),
                    dict(_node_registry_snapshot["node_ips"]), True)
    return switches, node_names, node_ips, False


def alive_switch_dpids(redis, node_names, switches):
    """Switches con heartbeat switch:alive vigente (vivos en este instante)."""
    alive = set()
    for dpid in switches:
        if redis.exists(f"switch:alive:{raw_dpid_from(dpid)}"):
            alive.add(normalize_dpid(dpid))
    for raw in node_names:
        if redis.exists(f"switch:alive:{raw}"):
            alive.add(normalize_dpid(raw))
    return alive


def known_switch_dpids(redis, node_names, switches, exclude_dead=False):
    """Todos los switches conocidos del registro persistente, visibles aunque su
    heartbeat haya expirado mientras sigan dentro de la ventana de gracia
    (node_last_seen) o estén vivos. Así un nodo que solo reconverge no se borra
    de la topología, pero los realmente ausentes caen tras NODE_STALE_GRACE.

    Con exclude_dead=True se omiten además los nodos CONFIRMADOS muertos (marca
    switch:dead:{dpid} que pone Ryu cuando un vecino detecta la caída vía probe
    activo) Y los nodos sin switch:alive cuyo último heartbeat supera
    NODE_MAP_DEAD_AFTER: esto último cubre el caso de un nodo ELIMINADO de la
    topología, donde OSPF retira su ruta y el probe deja de medirlo, así que nunca
    se publica switch:dead y el nodo quedaría hasta NODE_STALE_GRACE (600s). El
    mapa SDN usa este modo para retirar el nodo en ~2-3min. La sección de seguridad
    NO lo usa: ahí el nodo sigue listado (hasta la gracia larga) pero inactivo.
    """
    last_seen = redis.hgetall("topology:node_last_seen") or {}
    now = time.time()
    known = set()
    for dpid in set(switches) | set(node_names.keys()):
        raw = raw_dpid_from(dpid)
        if redis.exists(f"switch:alive:{raw}"):
            known.add(normalize_dpid(dpid))
            continue
        if exclude_dead and redis.exists(f"switch:dead:{raw}"):
            continue  # confirmado muerto por el probe: fuera del mapa ya
        seen = last_seen.get(raw) or last_seen.get(str(dpid))
        if seen:
            try:
                age = now - float(seen)
            except (TypeError, ValueError):
                continue
            # Mapa: retirar un nodo sin heartbeat que lleva ausente más que el
            # umbral de muerte (nodo borrado que nunca generó switch:dead).
            if exclude_dead and age >= NODE_MAP_DEAD_AFTER:
                continue
            if age < NODE_STALE_GRACE:
                known.add(normalize_dpid(dpid))
    return known


def vxlan_edges(redis, dpids, ip_to_dpid):
    edges = {}
    peer_map = redis.hgetall("topology:vxlan_peers") or {}
    for raw, peers in peer_map.items():
        local_dpid = normalize_dpid(raw)
        if local_dpid not in dpids:
            continue
        for remote_ip in str(peers or "").split():
            remote_dpid = ip_to_dpid.get(str(remote_ip).replace(".", ""))
            if not remote_dpid or remote_dpid not in dpids or remote_dpid == local_dpid:
                continue
            source, target = sorted([local_dpid, remote_dpid])
            edge_id = f"vxlan:{source}:{target}"
            entry = edges.setdefault(edge_id, {
                "id": edge_id,
                "source": source,
                "target": target,
                "type": "vxlan",
                "status": "up",
                "label": "VXLAN",
                "port": "",
                "remote_ip": remote_ip,
                "details_list": [],
            })
            entry["details_list"].append(f"{local_dpid}->{remote_ip}")

    if edges:
        return edges

    for key in (redis.hkeys("topology:link_cost") or []):
        left, sep, right = str(key).partition(":")
        if not sep:
            continue
        source = normalize_dpid(left)
        target = normalize_dpid(right)
        if source not in dpids or target not in dpids or source == target:
            continue
        source, target = sorted([source, target])
        edge_id = f"vxlan:{source}:{target}"
        edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "type": "vxlan",
            "status": "up",
            "label": "VXLAN",
            "port": "",
            "remote_ip": "",
            "details_list": ["Enlace VXLAN inferido por costo de enlace"],
        }
    return edges


def physical_edges(redis, dpids, ip_to_dpid):
    edges = {}
    peer_map = redis.hgetall("topology:vxlan_peers") or {}
    for raw, peers in peer_map.items():
        local_dpid = normalize_dpid(raw)
        if local_dpid not in dpids:
            continue
        for remote_ip in str(peers or "").split():
            remote_dpid = ip_to_dpid.get(str(remote_ip).replace(".", ""))
            if not remote_dpid or remote_dpid not in dpids or remote_dpid == local_dpid:
                continue
            source, target = sorted([local_dpid, remote_dpid])
            edge_id = f"physical:{source}:{target}"
            entry = edges.setdefault(edge_id, {
                "id": edge_id,
                "source": source,
                "target": target,
                "type": "fabric_physical",
                "status": "up",
                "label": "Fabric fisico",
                "port": "",
                "remote_ip": remote_ip,
                "details_list": [],
            })
            entry["details_list"].append(f"{local_dpid}->{remote_ip}")
    return edges


def build_sdn_topology(redis):
    # Estructura desde el registro persistente (con fallback a la última vista
    # buena) y liveness desde switch:alive. Un switch cuyo heartbeat expiró sigue
    # en la topología marcado "stale" en vez de desaparecer: así reconvergencia
    # de un worker no vacía la vista global.
    switches, node_names, node_ips, degraded = read_node_registry(redis)
    # exclude_dead=True: un nodo confirmado muerto (switch:dead) desaparece del
    # mapa al instante, sin esperar NODE_STALE_GRACE. Seguridad sí lo conserva
    # (marcado inactivo) usando known_switch_dpids sin exclude_dead.
    dpids = known_switch_dpids(redis, node_names, switches, exclude_dead=True)
    alive = alive_switch_dpids(redis, node_names, switches)
    nodes = []
    edges_by_id = {}
    ip_to_dpid = {}

    for raw, ip in node_ips.items():
        if ip:
            ip_to_dpid[str(ip).replace(".", "")] = normalize_dpid(raw)

    for dpid in sorted(dpids, key=lambda value: node_names.get(raw_dpid_from(value), value)):
        raw = raw_dpid_from(dpid)
        name = node_names.get(raw, f"switch-{dpid}")
        ip = node_ips.get(raw, "")
        role = "control-plane" if looks_like_worker_name(name) and not str(name).startswith("worker") else "worker"
        is_alive = dpid in alive
        nodes.append({
            "id": str(dpid),
            "label": name,
            "type": "switch",
            "role": role,
            "name": name,
            "ip": ip,
            "mac": mac_from_raw_dpid(raw),
            "dpid": str(dpid),
            "raw_dpid": raw,
            "online": is_alive,
            "status": "online" if is_alive else "stale",
        })

    for guest in [with_security_state(redis, item) for item in observed_guests(redis)]:
        mac = registry.normalize_mac(guest.get("mac", ""))
        if not mac:
            continue
        device = guest.get("device") or {}
        device_id = guest.get("device_id") or guest.get("telemetry_device_id") or device.get("device_id", "")
        nodes.append({
            "id": mac,
            "label": device_id or guest.get("name") or mac,
            "type": "smart_meter" if device_id else "guest",
            "name": guest.get("name") or device_id or mac,
            "device_id": device_id,
            "ip": guest.get("ip", ""),
            "mac": mac,
            "dpid": str(guest.get("dpid", "")),
            "in_port": str(guest.get("in_port", "")),
            "port_name": guest.get("port_name", ""),
            "security_status": guest.get("security_status", "unknown"),
            "online": bool(guest.get("online")),
        })
        if guest.get("dpid") in dpids:
            edge_id = f"guest:{guest.get('dpid')}:{mac}"
            edges_by_id[edge_id] = {
                "id": edge_id,
                "source": str(guest.get("dpid")),
                "target": mac,
                "type": "guest",
                "status": "online" if guest.get("online") else "stale",
                "label": guest.get("port_name") or str(guest.get("in_port", "")),
                "port": str(guest.get("in_port", "")),
                "details": "Conexion local guest-switch",
            }

    # Aristas físicas/VXLAN entre todos los switches conocidos (no solo los
    # vivos), marcadas "stale" si algún extremo perdió su heartbeat. Así el grafo
    # no pierde enlaces durante la reconvergencia de un nodo.
    for edge_id, edge in physical_edges(redis, dpids, ip_to_dpid).items():
        edge["details"] = ", ".join(edge.get("details_list", []))
        edge["status"] = "up" if (edge["source"] in alive and edge["target"] in alive) else "stale"
        edges_by_id[edge_id] = edge

    for edge_id, edge in vxlan_edges(redis, dpids, ip_to_dpid).items():
        edge["details"] = ", ".join(edge.get("details_list", []))
        edge["status"] = "up" if (edge["source"] in alive and edge["target"] in alive) else "stale"
        edges_by_id[edge_id] = edge

    if dpids:
        nodes.append({
            "id": "mgmt-switch",
            "label": "Mgmt-Switch",
            "type": "mgmt_switch",
            "role": "management-plane",
            "name": "Mgmt-Switch",
            "ip": "",
            "mac": "",
            "dpid": "",
            "status": "online",
        })
        for dpid in sorted(dpids, key=lambda value: node_names.get(raw_dpid_from(value), value)):
            raw = raw_dpid_from(dpid)
            name = node_names.get(raw, "")
            if str(name).startswith("worker"):
                continue
            edge_id = f"mgmt:{dpid}:mgmt-switch"
            ports = redis.hget("topology:mgmt_switch_links", raw) or "edge"
            edges_by_id[edge_id] = {
                "id": edge_id,
                "source": dpid,
                "target": "mgmt-switch",
                "type": "mgmt_link",
                "status": "up" if dpid in alive else "stale",
                "label": "Gestion",
                "port": ports,
                "details": f"Plano de gestion / edge a internet ({ports})",
            }

    edges = []
    for edge in edges_by_id.values():
        edge.pop("details_list", None)
        edge["link"] = edge_link_id(edge["source"], edge["target"])
        edges.append(edge)

    return {
        "nodes": sorted(nodes, key=lambda item: (item.get("type", ""), item.get("label", ""), item["id"])),
        "edges": sorted(edges, key=lambda item: (item.get("type", ""), item["id"])),
        "degraded": degraded,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _dijkstra_shortest_path(adjacency, src, dst):
    """Camino de menor costo con Dijkstra (heapq).

    adjacency: {dpid: [(vecino, costo), ...]}. Con costos uniformes (1.0)
    equivale al menor numero de saltos. Empata por orden de dpid para que
    el resultado sea determinista. Devuelve [] si no hay camino.
    """
    if src == dst:
        return [src]
    dist = {src: 0.0}
    prev = {}
    heap = [(0.0, src)]
    visited = set()
    while heap:
        d, node = heapq.heappop(heap)
        if node in visited:
            continue
        visited.add(node)
        if node == dst:
            break
        for neighbor, cost in sorted(adjacency.get(node, [])):
            if neighbor in visited:
                continue
            nd = d + cost
            if neighbor not in dist or nd < dist[neighbor]:
                dist[neighbor] = nd
                prev[neighbor] = node
                heapq.heappush(heap, (nd, neighbor))
    if dst not in dist:
        return []
    path = [dst]
    while path[-1] != src:
        node = prev.get(path[-1])
        if node is None:
            return []
        path.append(node)
    path.reverse()
    return path


def trace_sdn_path(redis, src_guest, dst_guest):
    topology = build_sdn_topology(redis)
    # Solo switches VIVOS para el camino: un nodo stale/caido no debe aparecer
    # como ruta activa (debe converger con los flows reales que instala Ryu,
    # que excluye nodos sin switch:alive del grafo Dijkstra).
    dpids = {node["id"] for node in topology["nodes"]
             if node.get("type") == "switch" and node.get("online")}
    ip_to_dpid = {}
    for raw, ip in (redis.hgetall("topology:node_ips") or {}).items():
        if ip:
            ip_to_dpid[str(ip).replace(".", "")] = normalize_dpid(raw)
    vx_edges = vxlan_edges(redis, dpids, ip_to_dpid)

    guest_locations = redis.hgetall("topology:guest_locations") or {}
    switch_ports = {dpid: redis.hgetall(f"switch_ports:{dpid}") or {} for dpid in dpids}
    mac_tables = {dpid: redis.hgetall(f"mac_to_port:{dpid}") or {} for dpid in dpids}

    def guest_switch(mac):
        # topology:guest_locations es la fuente autoritativa (se fija en el
        # packet-in cuando el guest llega por un puerto local no-vx). Se respeta
        # aunque su switch este offline: es el dueno real. Si el switch esta
        # caido, el camino resultara path_not_found (honesto), en vez de ubicar
        # falsamente el guest en otro switch via mac_to_port (flood) y devolver
        # un camino imposible (ambos guests colgando del mismo DPID).
        location = str(guest_locations.get(mac, ""))
        if ":" in location:
            return location.split(":", 1)[0]
        # Fallback SOLO si no hay guest_location: exige un puerto de guest real
        # (ens*, no vx ni uplink) en mac_to_port.
        for dpid, table in mac_tables.items():
            port = table.get(mac)
            if port and str(switch_ports.get(dpid, {}).get(str(port), "")).startswith("ens"):
                return dpid
        return None

    src_switch = guest_switch(src_guest)
    dst_switch = guest_switch(dst_guest)
    if not src_switch or not dst_switch:
        return {"nodes": [], "edges": [], "reason": "guest_location_unknown"}

    # Camino mas corto con Dijkstra sobre el grafo VXLAN.
    # NO seguimos mac_to_port: esa tabla aprende MACs origen via flood MST y
    # registra puertos sub-optimos, lo que producia rutas no optimas e
    # intermitentes en el mapa. El camino mostrado debe coincidir siempre con
    # el que instala Ryu (Dijkstra sobre el mismo grafo VXLAN con
    # topology:link_cost; costo por defecto 1.0 = menor numero de saltos).
    link_costs = redis.hgetall("topology:link_cost") or {}
    adjacency = {dpid: [] for dpid in dpids}
    for edge in vx_edges.values():
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if source not in adjacency or target not in adjacency:
            continue
        raw_cost = link_costs.get(f"{source}:{target}",
                                  link_costs.get(f"{target}:{source}", 1.0))
        try:
            cost = float(raw_cost)
        except (TypeError, ValueError):
            cost = 1.0
        adjacency[source].append((target, cost))
        adjacency[target].append((source, cost))

    path = _dijkstra_shortest_path(adjacency, src_switch, dst_switch)

    if not path:
        return {"nodes": [src_guest, dst_guest], "edges": [], "reason": "path_not_found"}

    edge_ids = [f"guest:{src_switch}:{src_guest}"]
    for source, target in zip(path, path[1:]):
        a, b = sorted([str(source), str(target)])
        edge_ids.append(f"vxlan:{a}:{b}")
    edge_ids.append(f"guest:{dst_switch}:{dst_guest}")
    return {"nodes": [src_guest] + path + [dst_guest], "edges": edge_ids, "reason": "ok"}


def get_device_secrets(device_id: str) -> list[str]:
    secrets = []
    if device_id in HMAC_DEVICE_SECRETS:
        configured = HMAC_DEVICE_SECRETS[device_id]
        if isinstance(configured, list):
            secrets.extend(str(secret) for secret in configured if secret)
        elif configured:
            secrets.append(str(configured))

    redis = get_redis()
    if redis is not None:
        try:
            data = redis.hgetall(f"meter:secret:{device_id}") or {}
            for field in ("active", "next"):
                if data.get(field):
                    secrets.append(data[field])
        except Exception as e:
            log.warning("No se pudo leer secreto HMAC para device=%s desde Redis: %s", device_id, e)

    if HMAC_SECRET:
        secrets.append(HMAC_SECRET)
    return secrets


def _record_invalid_event(reason: str, device_id: str, source_ip: str):
    with _cache_lock:
        _memory_hmac_counters["invalid_total"] += 1
        _memory_hmac_counters[f"invalid_total:{reason}"] += 1

    redis = get_redis()
    if redis is not None:
        try:
            pipe = redis.pipeline()
            pipe.incr(f"meter:hmac:invalid_total:{reason}")
            pipe.incr("meter:hmac:invalid_total")
            pipe.lpush("meter:hmac:events", json.dumps({
                "time": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "device_id": device_id,
                "source_ip": source_ip,
            }))
            pipe.ltrim("meter:hmac:events", 0, 199)
            pipe.execute()
        except Exception as e:
            log.warning("No se pudo registrar evento HMAC inválido: %s", e)

    log.warning("Telemetría rechazada reason=%s device=%s source=%s", reason, device_id or "unknown", source_ip)


def _is_policy_rejection(reason: str) -> bool:
    return reason in {"status_blocked", "status_quarantine", "status_quarantined", "status_pending"}


def _record_policy_rejection(reason: str, device_id: str, source_ip: str):
    with _cache_lock:
        _memory_hmac_counters["policy_rejected_total"] += 1
        _memory_hmac_counters[f"policy_rejected_total:{reason}"] += 1

    redis = get_redis()
    if redis is not None:
        try:
            pipe = redis.pipeline()
            pipe.incr(f"meter:policy:rejected_total:{reason}")
            pipe.incr("meter:policy:rejected_total")
            pipe.hset("meter:policy:last_rejected", device_id or source_ip, json.dumps({
                "time": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "device_id": device_id,
                "source_ip": source_ip,
            }))
            pipe.execute()
        except Exception as e:
            log.warning("No se pudo registrar rechazo por política: %s", e)

    log.info("Telemetría bloqueada por política reason=%s device=%s source=%s", reason, device_id or "unknown", source_ip)


def record_hmac_accept(device_id: str):
    with _cache_lock:
        _memory_hmac_counters["accepted_total"] += 1

    redis = get_redis()
    if redis is not None:
        try:
            pipe = redis.pipeline()
            pipe.incr("meter:hmac:accepted_total")
            pipe.hset("meter:hmac:last_valid", device_id, datetime.now(timezone.utc).isoformat())
            pipe.execute()
        except Exception as e:
            log.warning("No se pudo registrar telemetría HMAC válida: %s", e)


def _claim_nonce(device_id: str, nonce: str) -> bool:
    redis = get_redis()
    nonce_key = f"meter:nonce:{device_id}:{nonce}"
    if redis is not None:
        try:
            return bool(redis.set(nonce_key, "1", ex=NONCE_TTL_SECONDS, nx=True))
        except Exception as e:
            log.warning("No se pudo validar nonce en Redis; usando memoria local: %s", e)

    now = time.time()
    with _cache_lock:
        expired = [key for key, expires_at in _memory_nonces.items() if expires_at <= now]
        for key in expired:
            _memory_nonces.pop(key, None)
        if nonce_key in _memory_nonces:
            return False
        _memory_nonces[nonce_key] = now + NONCE_TTL_SECONDS
    return True


def verify_hmac(reading: dict, source_ip: str) -> bool:
    if not HMAC_ENABLED:
        return True

    device_id = str(reading.get("device_id", ""))
    signature = reading.get("signature")
    nonce = str(reading.get("nonce", ""))
    if not device_id or not signature or not nonce:
        _record_invalid_event("missing_hmac_fields", device_id, source_ip)
        return False

    try:
        timestamp = int(reading.get("timestamp"))
    except (TypeError, ValueError):
        _record_invalid_event("invalid_timestamp", device_id, source_ip)
        return False

    if abs(int(time.time()) - timestamp) > MAX_TIME_SKEW_SECONDS:
        _record_invalid_event("timestamp_skew", device_id, source_ip)
        return False

    secrets = get_device_secrets(device_id)
    if not secrets:
        _record_invalid_event("missing_secret", device_id, source_ip)
        return False

    signed_payload = dict(reading)
    signed_payload.pop("signature", None)
    canonical_payload = canonical_json(signed_payload)
    valid_signature = False
    for secret in secrets:
        expected = hmac.new(
            secret.encode("utf-8"),
            canonical_payload,
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(str(signature), expected):
            valid_signature = True
            break
    if not valid_signature:
        _record_invalid_event("invalid_signature", device_id, source_ip)
        return False

    if not _claim_nonce(device_id, nonce):
        _record_invalid_event("replay_nonce", device_id, source_ip)
        return False

    return True


def hmac_counter_snapshot() -> dict:
    counters = defaultdict(int)
    with _cache_lock:
        counters.update(_memory_hmac_counters)

    redis = get_redis()
    if redis is not None:
        try:
            counters["accepted_total"] = int(redis.get("meter:hmac:accepted_total") or 0)
            counters["invalid_total"] = int(redis.get("meter:hmac:invalid_total") or 0)
            counters["policy_rejected_total"] = int(redis.get("meter:policy:rejected_total") or 0)
            for key in redis.scan_iter("meter:hmac:invalid_total:*"):
                reason = key.rsplit(":", 1)[-1]
                counters[f"invalid_total:{reason}"] = int(redis.get(key) or 0)
            for key in redis.scan_iter("meter:policy:rejected_total:*"):
                reason = key.rsplit(":", 1)[-1]
                counters[f"policy_rejected_total:{reason}"] = int(redis.get(key) or 0)
        except Exception as e:
            log.warning("No se pudieron leer contadores HMAC desde Redis: %s", e)
    return dict(counters)


def prometheus_metrics() -> str:
    counters = hmac_counter_snapshot()
    meters = get_all_latest()
    lines = [
        "# HELP meter_hmac_accepted_total Telemetry packets accepted after HMAC validation",
        "# TYPE meter_hmac_accepted_total counter",
        f"meter_hmac_accepted_total {counters.get('accepted_total', 0)}",
        "# HELP meter_hmac_invalid_total Telemetry packets rejected by HMAC/replay validation",
        "# TYPE meter_hmac_invalid_total counter",
        f"meter_hmac_invalid_total {counters.get('invalid_total', 0)}",
        "# HELP meter_hmac_invalid_by_reason_total Telemetry packets rejected by reason",
        "# TYPE meter_hmac_invalid_by_reason_total counter",
    ]
    for key, value in sorted(counters.items()):
        if not key.startswith("invalid_total:"):
            continue
        reason = key.split(":", 1)[1].replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'meter_hmac_invalid_by_reason_total{{reason="{reason}"}} {value}')
    lines.extend([
        "# HELP meter_policy_rejected_total Telemetry packets rejected by configured device policy",
        "# TYPE meter_policy_rejected_total counter",
        f"meter_policy_rejected_total {counters.get('policy_rejected_total', 0)}",
        "# HELP meter_policy_rejected_by_reason_total Telemetry packets rejected by configured policy reason",
        "# TYPE meter_policy_rejected_by_reason_total counter",
    ])
    for key, value in sorted(counters.items()):
        if not key.startswith("policy_rejected_total:"):
            continue
        reason = key.split(":", 1)[1].replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'meter_policy_rejected_by_reason_total{{reason="{reason}"}} {value}')
    lines.extend([
        "# HELP meter_latest_power_kw Latest active power reported by a smart meter",
        "# TYPE meter_latest_power_kw gauge",
        "# HELP meter_latest_energy_kwh Latest cumulative energy reported by a smart meter",
        "# TYPE meter_latest_energy_kwh gauge",
        "# HELP meter_latest_info Latest smart meter metadata; value is always 1",
        "# TYPE meter_latest_info gauge",
    ])
    for meter in meters:
        device_id = str(meter.get("device_id", "unknown")).replace('\\', '\\\\').replace('"', '\\"')
        source_ip = str(meter.get("source_ip", "")).replace('\\', '\\\\').replace('"', '\\"')
        power = float(meter.get("active_power_kw", 0) or 0)
        energy = float(meter.get("energy_kwh", 0) or 0)
        lines.append(f'meter_latest_power_kw{{device_id="{device_id}",source_ip="{source_ip}"}} {power}')
        lines.append(f'meter_latest_energy_kwh{{device_id="{device_id}",source_ip="{source_ip}"}} {energy}')
        lines.append(f'meter_latest_info{{device_id="{device_id}",source_ip="{source_ip}"}} 1')
    with _redis_metrics_lock:
        redis_metrics = dict(_redis_metrics)
    lines.extend([
        "# HELP redis_query_total Total Redis operations executed by application services",
        "# TYPE redis_query_total counter",
    ])
    for (operation, status), metric in sorted(redis_metrics.items()):
        labels = f'service="meter-collector",operation="{escape_label(operation)}",status="{escape_label(status)}"'
        lines.append(f'redis_query_total{{{labels}}} {metric["count"]}')
    lines.extend([
        "# HELP redis_query_duration_seconds_total Total Redis operation duration in seconds",
        "# TYPE redis_query_duration_seconds_total counter",
    ])
    for (operation, status), metric in sorted(redis_metrics.items()):
        labels = f'service="meter-collector",operation="{escape_label(operation)}",status="{escape_label(status)}"'
        lines.append(f'redis_query_duration_seconds_total{{{labels}}} {metric["seconds"]}')
    lines.extend([
        "# HELP redis_query_duration_seconds_max Maximum observed Redis operation duration in seconds since process start",
        "# TYPE redis_query_duration_seconds_max gauge",
    ])
    for (operation, status), metric in sorted(redis_metrics.items()):
        labels = f'service="meter-collector",operation="{escape_label(operation)}",status="{escape_label(status)}"'
        lines.append(f'redis_query_duration_seconds_max{{{labels}}} {metric["max"]}')
    return "\n".join(lines) + "\n"


def normalize_reading(reading: dict) -> dict:
    normalized = dict(reading)
    if "voltage_v" not in normalized and "voltage" in normalized:
        normalized["voltage_v"] = normalized["voltage"]
    if "current_a" not in normalized and "current" in normalized:
        normalized["current_a"] = normalized["current"]
    if "active_power_kw" not in normalized and "active_power" in normalized:
        normalized["active_power_kw"] = round(float(normalized["active_power"]) / 1000, 3)
    if "reactive_power_kvar" not in normalized and "reactive_power" in normalized:
        normalized["reactive_power_kvar"] = round(float(normalized["reactive_power"]) / 1000, 3)
    if "energy_kwh" not in normalized and "energy" in normalized:
        normalized["energy_kwh"] = normalized["energy"]
    if isinstance(normalized.get("timestamp"), (int, float)):
        normalized["timestamp"] = datetime.fromtimestamp(int(normalized["timestamp"]), timezone.utc).isoformat()
    return normalized


def reading_age_seconds(reading: dict) -> float | None:
    timestamp = reading.get("timestamp")
    if not timestamp:
        return None
    try:
        if isinstance(timestamp, (int, float)):
            seen = datetime.fromtimestamp(float(timestamp), timezone.utc)
        else:
            seen = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - seen).total_seconds()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Almacenamiento de lecturas
# ---------------------------------------------------------------------------
def store_reading(reading: dict):
    """Persiste la lectura en Redis y en caché de memoria."""
    device_id = reading.get("device_id", "unknown")
    timestamp = reading.get("timestamp", datetime.now(timezone.utc).isoformat())

    # ---- Caché en memoria ----
    with _cache_lock:
        _memory_cache[device_id].append(reading)
        if len(_memory_cache[device_id]) > MAX_READINGS:
            _memory_cache[device_id] = _memory_cache[device_id][-MAX_READINGS:]

    # ---- Redis ----
    redis = get_redis()
    if redis is None:
        return
    try:
        pipe = redis.pipeline()

        # Lista del historial del dispositivo (Redis List, max MAX_READINGS)
        key_history = f"meter:history:{device_id}"
        pipe.lpush(key_history, json.dumps(reading))
        pipe.ltrim(key_history, 0, MAX_READINGS - 1)
        pipe.expire(key_history, 86400)  # TTL 24h

        # Última lectura del dispositivo (Hash para consulta rápida)
        key_latest = f"meter:latest:{device_id}"
        pipe.hset(key_latest, mapping={
            "device_id"          : device_id,
            "timestamp"          : timestamp,
            "voltage_v"          : str(reading.get("voltage_v", 0)),
            "current_a"          : str(reading.get("current_a", 0)),
            "active_power_kw"    : str(reading.get("active_power_kw", 0)),
            "reactive_power_kvar": str(reading.get("reactive_power_kvar", 0)),
            "power_factor"       : str(reading.get("power_factor", 0)),
            "energy_kwh"         : str(reading.get("energy_kwh", 0)),
            "source_ip"          : str(reading.get("source_ip", "")),
            "seq"                : str(reading.get("seq", 0)),
        })
        pipe.expire(key_latest, 300)  # TTL 5 min (medidor vivo si actualizó recientemente)

        # Set de device_ids activos
        pipe.sadd("meter:devices", device_id)

        pipe.execute()
    except Exception as e:
        log.warning("Error almacenando en Redis: %s", e)


def get_all_latest() -> list[dict]:
    """Retorna la última lectura de todos los medidores."""
    redis = get_redis()
    result = []

    if redis:
        try:
            devices = redis.smembers("meter:devices") or set()
            for dev in devices:
                data = redis.hgetall(f"meter:latest:{dev}")
                if data:
                    age = reading_age_seconds(data)
                    if age is None or age > ACTIVE_METER_MAX_AGE_SECONDS:
                        redis.delete(f"meter:latest:{dev}")
                        redis.srem("meter:devices", dev)
                        continue
                    if not telemetry_source_allowed(data.get("source_ip", "")):
                        redis.delete(f"meter:latest:{dev}")
                        redis.srem("meter:devices", dev)
                        continue
                    result.append(data)
                else:
                    redis.srem("meter:devices", dev)
            return result
        except Exception as e:
            log.warning("Error leyendo Redis, usando caché: %s", e)

    # Fallback a memoria
    with _cache_lock:
        for dev, readings in _memory_cache.items():
            if readings:
                result.append(readings[-1])
    return result


def get_device_history(device_id: str, limit: int = 50) -> list[dict]:
    """Retorna el historial de lecturas de un dispositivo."""
    redis = get_redis()
    if redis:
        try:
            raw = redis.lrange(f"meter:history:{device_id}", 0, limit - 1)
            return [json.loads(r) for r in raw]
        except Exception as e:
            log.warning("Error leyendo historial de Redis: %s", e)

    with _cache_lock:
        readings = _memory_cache.get(device_id, [])
        return list(reversed(readings[-limit:]))


# ---------------------------------------------------------------------------
# Servidor UDP
# ---------------------------------------------------------------------------
def udp_listener():
    """Escucha paquetes UDP en el puerto configurado y los persiste."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Habilitar recepción de broadcast
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    log.info("Servidor UDP escuchando en 0.0.0.0:%d", UDP_PORT)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            reading = json.loads(data.decode("utf-8"))
            if not verify_hmac(reading, addr[0]):
                continue
            reading = normalize_reading(reading)
            reading["source_ip"] = addr[0]
            device_id = reading.get("device_id", "unknown")
            allowed, reason = telemetry_source_authorization(addr[0], str(device_id))

            if not allowed and reason in (
                "mac_not_registered",
                "source_not_observed",
                "port_mismatch",
                "dpid_mismatch",
            ):
                try:
                    sync_security_identity(str(device_id), addr[0])
                    allowed, reason = telemetry_source_authorization(addr[0], str(device_id))
                except Exception as sync_exc:
                    log.warning("Auto-registro fallido para %s: %s", device_id, sync_exc)

            if not allowed:
                if _is_policy_rejection(reason):
                    _record_policy_rejection(reason, str(device_id), addr[0])
                else:
                    _record_invalid_event(reason, str(device_id), addr[0])
                continue
            if HMAC_ENABLED:
                record_hmac_accept(str(device_id))
            seq = reading.get("seq", "?")
            log.info("UDP [%s] seq=%s device=%s P=%.3fkW",
                     addr[0], seq, device_id,
                     float(reading.get("active_power_kw", 0)))
            store_reading(reading)
        except json.JSONDecodeError:
            log.warning("Paquete UDP inválido (no JSON) de %s", addr)
        except Exception as e:
            log.error("Error en UDP listener: %s", e)


# ---------------------------------------------------------------------------
# Flask API + Web UI
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/meters")
def api_meters():
    """Retorna la última lectura de todos los medidores."""
    meters = get_all_latest()
    return jsonify({
        "count": len(meters),
        "meters": meters,
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/meters/<device_id>/history")
def api_history(device_id: str):
    """Retorna el historial de lecturas de un dispositivo específico."""
    limit = min(int(request.args.get("limit", 50)), MAX_READINGS)
    history = get_device_history(device_id, limit=limit)
    return jsonify({
        "device_id": device_id,
        "count": len(history),
        "readings": history,
    })


@app.route("/api/stats")
def api_stats():
    """Estadísticas globales del sistema de medición."""
    redis = get_redis()
    use_memory = redis is None
    if use_memory:
        with _cache_lock:
            devices = list(_memory_cache.keys())
    else:
        try:
            devices = list(redis.smembers("meter:devices") or [])
        except Exception as e:
            log.warning("Error leyendo dispositivos desde Redis, usando caché: %s", e)
            use_memory = True
            with _cache_lock:
                devices = list(_memory_cache.keys())

    total_energy = 0.0
    total_power = 0.0
    online_count = 0
    device_stats = []

    for dev in devices:
        latest = {}
        if not use_memory:
            try:
                latest = redis.hgetall(f"meter:latest:{dev}") or {}
                if not latest:
                    redis.srem("meter:devices", dev)
                    continue
                if not telemetry_source_allowed(latest.get("source_ip", "")):
                    continue
            except Exception as e:
                log.warning("Error leyendo última lectura de %s desde Redis: %s", dev, e)
                continue

        if use_memory:
            with _cache_lock:
                readings = _memory_cache.get(dev, [])
                latest = readings[-1] if readings else {}

        if latest:
            age = reading_age_seconds(latest)
            is_online = age is not None and age <= ACTIVE_METER_MAX_AGE_SECONDS
            if is_online:
                online_count += 1
            energy = float(latest.get("energy_kwh", 0))
            power = float(latest.get("active_power_kw", 0))
            if is_online:
                total_energy += energy
                total_power += power
            device_stats.append({
                "device_id": dev,
                "source_ip": latest.get("source_ip", ""),
                "energy_kwh": round(energy, 4),
                "active_power_kw": round(power, 3),
                "last_seen": latest.get("timestamp", ""),
                "online": is_online,
                "age_seconds": round(age, 1) if age is not None else None,
                "seq": latest.get("seq", 0),
            })

    return jsonify({
        "total_devices": len(devices),
        "online_devices": online_count,
        "total_energy_kwh": round(total_energy, 4),
        "total_power_kw": round(total_power, 3),
        "devices": device_stats,
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/guests")
def api_guests():
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        workers = [with_security_state(redis, worker) for worker in observed_workers(redis)]
        guests = [with_security_state(redis, guest) for guest in observed_guests(redis)]
        registered = registry.list_devices(redis)
        observed_macs = {item["mac"] for item in workers + guests}
        offline_raw = [device for device in registered if device["mac"] not in observed_macs]
        # Enrich each offline device with its last telemetry signal so the UI can
        # surface stale entries without blindly deleting persisted registrations.
        offline_registered = []
        for device in offline_raw:
            enriched = dict(device)
            dev_id = device.get("device_id", "")
            last_ts = None
            if dev_id:
                try:
                    raw = redis.get(f"meter:latest:{dev_id}")
                    if raw:
                        last_ts = json.loads(raw).get("timestamp")
                except Exception:
                    pass
            enriched["last_telemetry"] = last_ts
            # Mark as stale if no telemetry in the last 24 h.
            if last_ts:
                try:
                    from datetime import datetime, timezone, timedelta
                    ts = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                    enriched["stale"] = (datetime.now(timezone.utc) - ts) > timedelta(hours=24)
                except Exception:
                    enriched["stale"] = True
            else:
                enriched["stale"] = True
            offline_registered.append(enriched)
        return jsonify({"guests": guests, "workers": workers, "offline_registered": offline_registered})
    except Exception as e:
        log.exception("No se pudo listar estado de seguridad")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sdn-topology")
def api_sdn_topology():
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        return jsonify(build_sdn_topology(redis))
    except Exception as e:
        log.exception("No se pudo construir topologia SDN")
        return jsonify({"error": str(e)}), 500


@app.route("/api/sdn-trace")
def api_sdn_trace():
    try:
        src = registry.normalize_mac(request.args.get("src", ""))
        dst = registry.normalize_mac(request.args.get("dst", ""))
        if not src or not dst or src == dst:
            return jsonify({"error": "Selecciona dos Smart Meters diferentes"}), 400
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        return jsonify(trace_sdn_path(redis, src, dst))
    except Exception as e:
        log.exception("No se pudo trazar ruta SDN")
        return jsonify({"error": str(e)}), 500


@app.route("/api/telemetry-security")
def api_telemetry_security():
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        counters = {
            "accepted_total": int(redis.get("meter:hmac:accepted_total") or 0),
            "invalid_total": int(redis.get("meter:hmac:invalid_total") or 0),
            "policy_rejected_total": int(redis.get("meter:policy:rejected_total") or 0),
            "by_reason": {},
            "policy_by_reason": {},
            "recent_events": [],
        }
        for key in redis.scan_iter("meter:hmac:invalid_total:*"):
            counters["by_reason"][key.rsplit(":", 1)[-1]] = int(redis.get(key) or 0)
        for key in redis.scan_iter("meter:policy:rejected_total:*"):
            counters["policy_by_reason"][key.rsplit(":", 1)[-1]] = int(redis.get(key) or 0)
        for raw in redis.lrange("meter:hmac:events", 0, 9):
            try:
                counters["recent_events"].append(json.loads(raw))
            except Exception:
                continue
        return jsonify(counters)
    except Exception as e:
        log.exception("No se pudo leer seguridad de telemetria")
        return jsonify({"error": str(e)}), 500


@app.route("/api/devices", methods=["POST"])
def api_register_device():
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        device = registry.save_device(redis, request.get_json(force=True))
        return jsonify(device), 201
    except Exception as e:
        log.exception("No se pudo registrar dispositivo")
        return jsonify({"error": str(e)}), 400


@app.route("/api/devices/<device_id>/status", methods=["PATCH"])
def api_set_device_status(device_id):
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        device = registry.update_status(redis, device_id, request.get_json(force=True).get("status"))
        return jsonify(device)
    except Exception as e:
        log.exception("No se pudo cambiar estado de %s", device_id)
        return jsonify({"error": str(e)}), 400


@app.route("/api/devices/<device_id>", methods=["DELETE"])
def api_delete_device(device_id):
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503
        return jsonify({"deleted": registry.delete_device(redis, device_id)})
    except Exception as e:
        log.exception("No se pudo eliminar dispositivo %s", device_id)
        return jsonify({"error": str(e)}), 400


@app.route("/api/nodes/<raw_dpid>", methods=["DELETE"])
def api_delete_node(raw_dpid):
    """Elimina un nodo INACTIVO del registro de topología (vista de seguridad/mapa).

    Solo permite borrar nodos sin heartbeat `switch:alive` vigente: borrar uno vivo
    sería inútil (su heartbeat lo re-registra al instante) y arriesgado. Si un nodo
    borrado revive, se re-registra solo, así que esto solo limpia entradas de nodos
    realmente ausentes (VM eliminada/recreada con otra loopback, etc.).
    """
    try:
        redis = get_redis()
        if redis is None:
            return jsonify({"error": "Redis no disponible"}), 503

        dec = normalize_dpid(raw_dpid)
        # Resolver también la forma hex por si llega el dpid decimal.
        raw = raw_dpid if not str(raw_dpid).isdigit() else raw_dpid_from(raw_dpid)

        if redis.exists(f"switch:alive:{raw}") or redis.exists(f"switch:alive:{dec}"):
            return jsonify({"error": "el nodo está activo (switch:alive); no se borra un nodo vivo"}), 409

        name = (redis.hget("topology:node_names", raw)
                or redis.hget("topology:node_names", dec) or "")
        node_ip = (redis.hget("topology:node_ips", raw)
                   or redis.hget("topology:node_ips", dec) or "")

        pipe = redis.pipeline()
        for key in ("topology:node_names", "topology:node_ips", "topology:node_last_seen",
                    "topology:vxlan_peers", "topology:mgmt_switch_links"):
            pipe.hdel(key, raw, dec)
        pipe.srem("topology:switches", raw, dec)
        for k in (f"switch:alive:{raw}", f"switch:alive:{dec}",
                  f"switch:dead:{raw}", f"switch:dead:{dec}",
                  f"mac_to_port:{raw}", f"mac_to_port:{dec}",
                  f"switch_ports:{raw}", f"switch_ports:{dec}"):
            pipe.delete(k)
        pipe.execute()

        # Limpiar referencias a este nodo en los vxlan_peers de los OTROS nodos
        # (su IP listada como peer) para que no quede una arista fantasma en el mapa.
        if node_ip:
            for other, peers in (redis.hgetall("topology:vxlan_peers") or {}).items():
                kept = " ".join(p for p in str(peers or "").split() if p != node_ip)
                if kept != str(peers or ""):
                    redis.hset("topology:vxlan_peers", other, kept)

        # Borrar la última vista buena en memoria para que no reaparezca por el fallback.
        with _node_registry_lock:
            for reg_key in ("node_names", "node_ips"):
                _node_registry_snapshot[reg_key].pop(raw, None)
                _node_registry_snapshot[reg_key].pop(dec, None)
            _node_registry_snapshot["switches"].discard(raw)
            _node_registry_snapshot["switches"].discard(dec)

        log.info("Nodo inactivo eliminado del registro: raw=%s dec=%s name=%s", raw, dec, name)
        return jsonify({"deleted": True, "raw_dpid": raw, "name": name})
    except Exception as e:
        log.exception("No se pudo eliminar el nodo %s", raw_dpid)
        return jsonify({"error": str(e)}), 400


@app.route("/api/health")
def health():
    redis_state = redis_status_snapshot()
    return jsonify({
        "status": "ok",
        "redis": "connected" if redis_state["connected"] else "disconnected (memory mode)",
        "redis_detail": redis_state,
        "udp_port": UDP_PORT,
    })


@app.route("/metrics")
def metrics():
    return Response(prometheus_metrics(), mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.route("/api/ready")
def ready():
    redis_state = redis_status_snapshot()
    return jsonify({
        "status": "ready",
        "redis": "connected" if redis_state["connected"] else "disconnected (fail-closed)",
        "redis_detail": redis_state,
    })


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log.info("=" * 60)
    log.info("SDN Meter Collector v1.0")
    log.info("  Redis Sentinel : %s:%d", SENTINEL_HOST, SENTINEL_PORT)
    log.info("  UDP Port       : %d", UDP_PORT)
    log.info("  HTTP Port      : %d", FLASK_PORT)
    log.info("=" * 60)

    # Conectar Redis en background (no bloquear arranque)
    def _redis_init():
        global r
        r = connect_redis(attempts=10, sleep_between=True)

    threading.Thread(target=_redis_init, daemon=True).start()

    # Lanzar UDP listener en hilo separado
    udp_thread = threading.Thread(target=udp_listener, daemon=True, name="udp-listener")
    udp_thread.start()

    # Lanzar Flask
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, threaded=True)
