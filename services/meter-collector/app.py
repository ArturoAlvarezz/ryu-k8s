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
REDIS_SOCKET_TIMEOUT = float(os.environ.get("REDIS_SOCKET_TIMEOUT", "1.0"))
REDIS_RECONNECT_INTERVAL = float(os.environ.get("REDIS_RECONNECT_INTERVAL", "10.0"))
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
def connect_redis(attempts: int | None = None, sleep_between: bool = True) -> redis_lib.Redis | None:
    """Conecta a Redis Sentinel con reintentos. Retorna None si falla."""
    attempts = attempts or REDIS_RECONNECT_ATTEMPTS
    for attempt in range(1, attempts + 1):
        try:
            sentinel = Sentinel(
                [(SENTINEL_HOST, SENTINEL_PORT)],
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


def _register_observed_meter(redis, device_id: str, source_ip: str) -> bool:
    if not device_id.startswith("SDNSmartMeter-"):
        return False
    observed = _observed_guest_for_ip(redis, source_ip)
    if not observed or not observed.get("mac"):
        return False

    existing = registry.get_device(redis, device_id)
    if existing and existing.get("status") in ("blocked", "quarantined"):
        return False

    registry.save_device(redis, {
        "device_id": device_id,
        "mac": observed["mac"],
        "ip": source_ip,
        "role": "smart_meter",
        "allowed_dst_ip": "10.0.0.1",
        "allowed_udp_port": UDP_PORT,
        "status": "authorized",
        "dpid": observed.get("dpid", ""),
        "in_port": observed.get("in_port", ""),
    })
    _cleanup_recreated_meter(redis, device_id, observed["mac"], source_ip)
    log.info("Smart Meter recreado adoptado automaticamente device=%s source=%s mac=%s", device_id, source_ip, observed["mac"])
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
        old_id = device.get("device_id", current_id or device_id)
        old_ip = device.get("ip", "")
        old_mac = registry.normalize_mac(device.get("mac", ""))
        observed = _observed_guest_for_ip(redis, source_ip) or {}
        observed_mac = registry.normalize_mac(observed.get("mac", ""))
        device["device_id"] = device_id
        device["ip"] = source_ip
        if observed_mac:
            device["mac"] = observed_mac
            device["dpid"] = observed.get("dpid", device.get("dpid", ""))
            device["in_port"] = observed.get("in_port", device.get("in_port", ""))
        mac = registry.normalize_mac(device.get("mac", ""))
        if (
            old_id == device_id
            and old_ip == source_ip
            and old_mac == mac
            and (not observed.get("dpid") or str(device.get("dpid", "")) == str(observed.get("dpid", "")))
            and (not observed.get("in_port") or str(device.get("in_port", "")) == str(observed.get("in_port", "")))
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
        if old_mac and old_mac != mac:
            pipe.delete(f"security:mac_to_device:{old_mac}")
        if old_id != device_id:
            pipe.delete(f"security:device:{old_id}")
        pipe.execute()
        _cleanup_recreated_meter(redis, device_id, mac, source_ip)
        log.info("Registro AMI sincronizado source=%s old_device=%s device=%s", source_ip, old_id, device_id)
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
    node_names = redis.hgetall("topology:node_names")
    node_ips = redis.hgetall("topology:node_ips")
    workers = []
    for raw_dpid, name in sorted(node_names.items(), key=lambda item: item[1]):
        if not looks_like_worker_name(name):
            continue
        mac = ""
        if len(raw_dpid) >= 12:
            raw_mac = raw_dpid[-12:]
            mac = ":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower()
        workers.append({
            "mac": mac,
            "ip": node_ips.get(raw_dpid, ""),
            "name": name,
            "dpid": normalize_dpid(raw_dpid),
            "in_port": "",
            "port_name": "node",
            "node_name": name,
            "online": bool(redis.exists(f"switch:alive:{raw_dpid}")),
            "kind": "worker",
        })
    return workers


def observed_guests(redis):
    guest_ips = redis.hgetall("topology:guest_ips")
    guest_names = redis.hgetall("topology:guest_names")
    node_names = redis.hgetall("topology:node_names")
    worker_macs = registry.known_worker_macs(redis)
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
    for raw_event in redis.lrange("meter:hmac:events", 0, 199) or []:
        try:
            event = json.loads(raw_event)
        except Exception:
            continue
        source_ip = str(event.get("source_ip", "")).strip()
        device_id = str(event.get("device_id", "")).strip()
        if source_ip and device_id and source_ip not in rejected_meter_by_ip:
            rejected_meter_by_ip[source_ip] = device_id

    for device in registry.list_devices(redis):
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
    current_guests = [
        guest for guest in guests.values()
        if guest.get("telemetry_device_id")
        or guest.get("ip") in live_meter_ips
        or guest.get("port_name") == "registered"
    ]
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


def active_switch_dpids(redis):
    dpids = set()
    for dpid in redis.smembers("topology:switches") or []:
        raw = raw_dpid_from(dpid)
        if redis.exists(f"switch:alive:{raw}"):
            dpids.add(normalize_dpid(dpid))
    for raw in redis.hkeys("topology:node_names") or []:
        if redis.exists(f"switch:alive:{raw}"):
            dpids.add(normalize_dpid(raw))
    return dpids


def vxlan_peer_state(redis, local_dpid, remote_ip):
    raw = raw_dpid_from(local_dpid)
    for key in (f"vxlan:peer:state:{local_dpid}:{remote_ip}", f"vxlan:peer:state:{raw}:{remote_ip}"):
        state = redis.get(key)
        if state:
            return state
    return "unknown"


def forwarding_br0_links(redis, dpids, ip_to_dpid):
    states = {}
    for key, value in (redis.hgetall("topology:br0_stp_ports") or {}).items():
        if ":" not in key:
            continue
        raw, _ = key.split(":", 1)
        local_dpid = normalize_dpid(raw)
        state, _, remote_ip = str(value).partition(":")
        remote_dpid = ip_to_dpid.get(remote_ip.replace(".", ""))
        if local_dpid not in dpids or remote_dpid not in dpids:
            continue
        link = edge_link_id(local_dpid, remote_dpid)
        entry = states.setdefault(link, {"forwarding": set(), "blocked": False})
        if state == "forwarding":
            entry["forwarding"].add(local_dpid)
        else:
            entry["blocked"] = True
    return {
        link for link, state in states.items()
        if not state["blocked"] and len(state["forwarding"]) >= 2
    }


def build_sdn_topology(redis):
    dpids = active_switch_dpids(redis)
    node_names = redis.hgetall("topology:node_names") or {}
    node_ips = redis.hgetall("topology:node_ips") or {}
    nodes = []
    edges_by_id = {}
    ip_to_dpid = {}

    for raw, ip in node_ips.items():
        if ip:
            ip_to_dpid[str(ip).replace(".", "")] = normalize_dpid(raw)
    valid_br0_links = forwarding_br0_links(redis, dpids, ip_to_dpid)

    for dpid in sorted(dpids, key=lambda value: node_names.get(raw_dpid_from(value), value)):
        raw = raw_dpid_from(dpid)
        name = node_names.get(raw, f"switch-{dpid}")
        ip = node_ips.get(raw, "")
        role = "control-plane" if looks_like_worker_name(name) and not str(name).startswith("worker") else "worker"
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
            "status": "online",
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

    for dpid in dpids:
        ports = redis.hgetall(f"switch_ports:{dpid}") or {}
        for port_no, port_name in ports.items():
            if not str(port_name).startswith("vx"):
                continue
            remote_key = str(port_name)[2:]
            remote_dpid = ip_to_dpid.get(remote_key)
            if not remote_dpid or remote_dpid not in dpids or str(remote_dpid) == str(dpid):
                continue
            source, target = sorted([str(dpid), str(remote_dpid)])
            if edge_link_id(source, target) not in valid_br0_links:
                continue
            edge_id = f"vxlan:{source}:{target}"
            remote_ip = ".".join([remote_key[0:3], remote_key[3:6], remote_key[6:9], remote_key[9:]]) if len(remote_key) == 12 else remote_key
            state = vxlan_peer_state(redis, dpid, remote_ip)
            existing = edges_by_id.get(edge_id)
            status = "down" if state == "down" or (existing and existing.get("status") == "down") else ("up" if state == "up" else "unknown")
            edges_by_id[edge_id] = {
                "id": edge_id,
                "source": source,
                "target": target,
                "type": "vxlan",
                "status": status,
                "label": "VXLAN",
                "port": str(port_no),
                "remote_ip": remote_ip,
                "details": f"Puerto {port_no} hacia {remote_ip} ({state})",
            }

    has_mgmt_switch = False
    for key, value in (redis.hgetall("topology:br0_stp_ports") or {}).items():
        if ":" not in key:
            continue
        raw, intf = key.split(":", 1)
        local_dpid = normalize_dpid(raw)
        state, _, remote_ip = str(value).partition(":")
        if local_dpid not in dpids:
            continue
        if remote_ip == "mgmt-switch":
            has_mgmt_switch = True
            edge_id = f"br0:{local_dpid}:mgmt-stp-switch"
            edges_by_id[edge_id] = {
                "id": edge_id,
                "source": local_dpid,
                "target": "mgmt-stp-switch",
                "type": "br0_mgmt_switch",
                "status": state,
                "label": f"br0 {state}",
                "port": intf,
                "details": f"{intf}: {state}",
            }
            continue
        remote_dpid = ip_to_dpid.get(remote_ip.replace(".", ""))
        if not remote_dpid or remote_dpid not in dpids:
            continue
        source, target = sorted([str(local_dpid), str(remote_dpid)])
        edge_id = f"br0:{source}:{target}"
        existing = edges_by_id.get(edge_id)
        status = "blocking" if state == "blocking" or (existing and existing.get("status") == "blocking") else state
        details = list(existing.get("details_list", [])) if existing else []
        details.append(f"{local_dpid}:{intf}={state}")
        edges_by_id[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "type": "br0_stp_blocked" if status == "blocking" else "br0_stp",
            "status": status,
            "label": "STP bloqueado" if status == "blocking" else "br0 STP",
            "port": intf,
            "details": ", ".join(details),
            "details_list": details,
        }

    if has_mgmt_switch:
        nodes.append({
            "id": "mgmt-stp-switch",
            "label": "Mgmt-STP-Switch",
            "type": "mgmt_switch",
            "role": "stp-root",
            "name": "Mgmt-STP-Switch",
            "ip": "",
            "mac": "",
            "dpid": "",
            "status": "online",
        })

    edges = []
    for edge in edges_by_id.values():
        edge.pop("details_list", None)
        edge["link"] = edge_link_id(edge["source"], edge["target"])
        edges.append(edge)

    return {
        "nodes": sorted(nodes, key=lambda item: (item.get("type", ""), item.get("label", ""), item["id"])),
        "edges": sorted(edges, key=lambda item: (item.get("type", ""), item["id"])),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def trace_sdn_path(redis, src_guest, dst_guest):
    topology = build_sdn_topology(redis)
    dpids = {node["id"] for node in topology["nodes"] if node.get("type") == "switch"}
    ip_to_dpid = {}
    for raw, ip in (redis.hgetall("topology:node_ips") or {}).items():
        if ip:
            ip_to_dpid[str(ip).replace(".", "")] = normalize_dpid(raw)
    valid_br0_links = forwarding_br0_links(redis, dpids, ip_to_dpid)

    guest_locations = redis.hgetall("topology:guest_locations") or {}
    switch_ports = {dpid: redis.hgetall(f"switch_ports:{dpid}") or {} for dpid in dpids}
    mac_tables = {dpid: redis.hgetall(f"mac_to_port:{dpid}") or {} for dpid in dpids}

    def guest_switch(mac):
        location = str(guest_locations.get(mac, ""))
        if ":" in location:
            dpid = location.split(":", 1)[0]
            if dpid in dpids:
                return dpid
        for dpid, table in mac_tables.items():
            port = table.get(mac)
            if port and not str(switch_ports.get(dpid, {}).get(str(port), "")).startswith("vx"):
                return dpid
        return None

    src_switch = guest_switch(src_guest)
    dst_switch = guest_switch(dst_guest)
    if not src_switch or not dst_switch:
        return {"nodes": [], "edges": [], "reason": "guest_location_unknown"}

    path = [src_switch]
    visited = set()
    current = src_switch
    while current != dst_switch:
        if current in visited:
            path = []
            break
        visited.add(current)
        out_port = mac_tables.get(current, {}).get(dst_guest)
        port_name = switch_ports.get(current, {}).get(str(out_port), "") if out_port else ""
        if not str(port_name).startswith("vx"):
            path = []
            break
        next_switch = ip_to_dpid.get(str(port_name)[2:])
        if not next_switch or next_switch not in dpids:
            path = []
            break
        if edge_link_id(current, next_switch) not in valid_br0_links:
            path = []
            break
        path.append(next_switch)
        current = next_switch

    if not path:
        adjacency = {dpid: [] for dpid in dpids}
        for dpid, ports in switch_ports.items():
            for _, port_name in ports.items():
                if not str(port_name).startswith("vx"):
                    continue
                target = ip_to_dpid.get(str(port_name)[2:])
                if target and target in dpids and edge_link_id(dpid, target) in valid_br0_links:
                    adjacency[dpid].append(target)
        queue = [(src_switch, [src_switch])]
        seen = {src_switch}
        while queue:
            current, candidate = queue.pop(0)
            if current == dst_switch:
                path = candidate
                break
            for target in sorted(adjacency.get(current, [])):
                if target in seen:
                    continue
                seen.add(target)
                queue.append((target, candidate + [target]))

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
    return reason in {"status_blocked", "status_quarantine", "status_quarantined"}


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
        offline_registered = [device for device in registered if device["mac"] not in observed_macs]
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
