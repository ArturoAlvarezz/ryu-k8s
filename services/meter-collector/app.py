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
UDP_PORT              = int(os.environ.get("UDP_PORT", 5555))
FLASK_PORT            = int(os.environ.get("FLASK_PORT", 5000))
MAX_READINGS          = int(os.environ.get("MAX_READINGS_PER_DEVICE", 100))
HMAC_ENABLED          = os.environ.get("HMAC_ENABLED", "true").lower() in ("1", "true", "yes", "on")
HMAC_SECRET           = os.environ.get("HMAC_SECRET", "")
MAX_TIME_SKEW_SECONDS = int(os.environ.get("MAX_TIME_SKEW_SECONDS", 60))
NONCE_TTL_SECONDS     = int(os.environ.get("NONCE_TTL_SECONDS", 300))

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


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
def connect_redis() -> redis_lib.Redis | None:
    """Conecta a Redis Sentinel con reintentos. Retorna None si falla."""
    for attempt in range(1, 11):
        try:
            sentinel = Sentinel([(SENTINEL_HOST, SENTINEL_PORT)], socket_timeout=1.0)
            r = sentinel.master_for("mymaster", socket_timeout=1.0, decode_responses=True)
            r.ping()
            log.info("Conexión a Redis Sentinel exitosa.")
            return r
        except Exception as e:
            log.warning("Intento %d/10 — Redis no disponible: %s", attempt, e)
            time.sleep(3)
    log.error("No se pudo conectar a Redis. Operando en modo memoria.")
    return None


r: redis_lib.Redis | None = None
_last_redis_connect_attempt = 0.0

def get_redis() -> redis_lib.Redis | None:
    """Retorna la conexión Redis (reconecta si perdió el enlace)."""
    global r, _last_redis_connect_attempt
    if r is None:
        now = time.time()
        if now - _last_redis_connect_attempt < 5:
            return None
        _last_redis_connect_attempt = now
        log.warning("Redis no está conectado. Intentando reconectar...")
        try:
            r = connect_redis()
        except Exception:
            r = None
        return r
    try:
        r.ping()
        return r
    except Exception:
        log.warning("Redis perdió conexión. Reconectando...")
        try:
            r = connect_redis()
        except Exception:
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

    record_hmac_accept(device_id)
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
            for key in redis.scan_iter("meter:hmac:invalid_total:*"):
                reason = key.rsplit(":", 1)[-1]
                counters[f"invalid_total:{reason}"] = int(redis.get(key) or 0)
        except Exception as e:
            log.warning("No se pudieron leer contadores HMAC desde Redis: %s", e)
    return dict(counters)


def prometheus_metrics() -> str:
    counters = hmac_counter_snapshot()
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
            device_id = reading.get("device_id", "unknown")
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
            except Exception as e:
                log.warning("Error leyendo última lectura de %s desde Redis: %s", dev, e)
                continue

        if use_memory:
            with _cache_lock:
                readings = _memory_cache.get(dev, [])
                latest = readings[-1] if readings else {}

        if latest:
            online_count += 1
            energy = float(latest.get("energy_kwh", 0))
            power = float(latest.get("active_power_kw", 0))
            total_energy += energy
            total_power += power
            device_stats.append({
                "device_id": dev,
                "energy_kwh": round(energy, 4),
                "active_power_kw": round(power, 3),
                "last_seen": latest.get("timestamp", ""),
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


@app.route("/api/health")
def health():
    redis_ok = redis_is_ready()
    return jsonify({
        "status": "ok",
        "redis": "connected" if redis_ok else "disconnected (memory mode)",
        "udp_port": UDP_PORT,
    })


@app.route("/metrics")
def metrics():
    return Response(prometheus_metrics(), mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.route("/api/ready")
def ready():
    if not redis_is_ready():
        return jsonify({
            "status": "not-ready",
            "redis": "disconnected",
        }), 503
    return jsonify({
        "status": "ready",
        "redis": "connected",
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
        r = connect_redis()

    threading.Thread(target=_redis_init, daemon=True).start()

    # Lanzar UDP listener en hilo separado
    udp_thread = threading.Thread(target=udp_listener, daemon=True, name="udp-listener")
    udp_thread.start()

    # Lanzar Flask
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, threaded=True)
