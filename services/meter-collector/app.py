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
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import threading
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from flask import Flask, jsonify, render_template, request
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

# Cache en memoria (fallback si Redis no está disponible)
_memory_cache: dict[str, list] = defaultdict(list)
_cache_lock = threading.Lock()

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
    devices = set()
    result = []

    if redis:
        try:
            devices = redis.smembers("meter:devices") or set()
            for dev in devices:
                data = redis.hgetall(f"meter:latest:{dev}")
                if data:
                    result.append(data)
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
    devices = []

    if redis:
        try:
            devices = list(redis.smembers("meter:devices") or [])
        except Exception:
            pass

    if not devices:
        with _cache_lock:
            devices = list(_memory_cache.keys())

    total_energy = 0.0
    total_power = 0.0
    online_count = 0
    device_stats = []

    for dev in devices:
        latest = {}
        redis_inst = get_redis()
        if redis_inst:
            try:
                latest = redis_inst.hgetall(f"meter:latest:{dev}") or {}
            except Exception:
                pass

        if not latest:
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
