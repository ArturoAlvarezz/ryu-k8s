#!/usr/bin/env python3
"""
SDN Smart Meter - Simulador de Medidor Inteligente IoT
======================================================
Simula un medidor eléctrico inteligente que publica telemetría periódica
vía UDP. Diseñado para generar tráfico real sobre la red SDN (br-sdn / VXLAN)
y validar el ruteo de la topología.

Variables de entorno:
  DEVICE_ID        Identificador único del medidor (default: hostname)
  COLLECTOR_IP     IP del colector (default: 10.0.0.1)
  COLLECTOR_PORT   Puerto UDP destino (default: 5555)
  REPORT_INTERVAL  Segundos entre reportes (default: 5)
  HMAC_ENABLED     Firma telemetría con HMAC-SHA256 (default: true)
  HMAC_SECRET      Secreto compartido del medidor
  PEER_IPS         Lista opcional de smart meters pares, separada por coma
  PEER_API_PORT    Puerto HTTP de diagnóstico (default: 8080)
  PEER_ECHO_PORT   Puerto UDP echo para pruebas entre medidores (default: 5560)
"""

from __future__ import annotations

import os
import sys
import socket
import json
import time
import random
import math
import uuid
import logging
import hmac
import hashlib
import secrets
import threading
import subprocess
import statistics
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [METER] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger(__name__)

DEVICE_ID       = os.environ.get("DEVICE_ID") or socket.gethostname()
COLLECTOR_IP    = os.environ.get("COLLECTOR_IP", "10.0.0.1")
COLLECTOR_PORT  = int(os.environ.get("COLLECTOR_PORT", 5555))
REPORT_INTERVAL = float(os.environ.get("REPORT_INTERVAL", 5))
HMAC_ENABLED    = os.environ.get("HMAC_ENABLED", "true").lower() in ("1", "true", "yes", "on")
HMAC_SECRET     = os.environ.get("HMAC_SECRET", "sdn-ami-hmac-lab-secret-v1")
PEER_IPS        = [ip.strip() for ip in os.environ.get("PEER_IPS", "").split(",") if ip.strip()]
PEER_API_PORT   = int(os.environ.get("PEER_API_PORT", 8080))
PEER_ECHO_PORT  = int(os.environ.get("PEER_ECHO_PORT", 5560))

# Parámetros eléctricos base para la simulación (distribución trifásica)
VOLTAGE_BASE    = 220.0   # Voltios RMS
CURRENT_BASE    = 15.0    # Amperios base
POWER_FACTOR    = 0.92    # Factor de potencia típico
RECENT_TESTS: list[dict] = []
RECENT_TESTS_LOCK = threading.Lock()


def remember_test(result: dict) -> None:
    """Guarda los últimos resultados para inspección vía API."""
    with RECENT_TESTS_LOCK:
        RECENT_TESTS.append(result)
        del RECENT_TESTS[:-20]


def summarize_rtts(rtts_ms: list[float]) -> dict:
    if not rtts_ms:
        return {
            "min_ms": None,
            "avg_ms": None,
            "max_ms": None,
            "stddev_ms": None,
            "jitter_ms": None,
        }

    deltas = [abs(rtts_ms[i] - rtts_ms[i - 1]) for i in range(1, len(rtts_ms))]
    return {
        "min_ms": round(min(rtts_ms), 3),
        "avg_ms": round(statistics.mean(rtts_ms), 3),
        "max_ms": round(max(rtts_ms), 3),
        "stddev_ms": round(statistics.pstdev(rtts_ms), 3) if len(rtts_ms) > 1 else 0.0,
        "jitter_ms": round(statistics.mean(deltas), 3) if deltas else 0.0,
    }


def run_icmp_ping(target: str, count: int = 5, timeout: int = 2) -> dict:
    """Ejecuta ping ICMP y retorna métricas estructuradas."""
    count = max(1, min(count, 100))
    timeout = max(1, min(timeout, 10))
    started = time.time()
    cmd = ["ping", "-c", str(count), "-W", str(timeout), target]
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=(count * timeout) + 5)

    rtts_ms: list[float] = []
    transmitted = count
    received = 0
    loss_percent = 100.0

    for line in proc.stdout.splitlines():
        if " bytes from " in line and "time=" in line:
            try:
                rtts_ms.append(float(line.rsplit("time=", 1)[1].split()[0]))
            except (IndexError, ValueError):
                pass
        elif "packets transmitted" in line:
            parts = [part.strip() for part in line.split(",")]
            try:
                transmitted = int(parts[0].split()[0])
                received = int(parts[1].split()[0])
                loss_percent = float(parts[2].split("%", 1)[0])
            except (IndexError, ValueError):
                pass

    if rtts_ms and received == 0:
        received = len(rtts_ms)
        loss_percent = round(((transmitted - received) / transmitted) * 100, 3)

    result = {
        "type": "icmp_ping",
        "device_id": DEVICE_ID,
        "source_ip": get_local_ip(),
        "target": target,
        "timestamp": int(started),
        "duration_ms": round((time.time() - started) * 1000, 3),
        "transmitted": transmitted,
        "received": received,
        "loss_percent": loss_percent,
        "rtt_ms": summarize_rtts(rtts_ms),
        "returncode": proc.returncode,
        "error": proc.stderr.strip() or None,
    }
    remember_test(result)
    return result


def start_udp_echo_server() -> None:
    """Servidor UDP simple para medir tráfico de aplicación entre medidores."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PEER_ECHO_PORT))
    log.info("UDP echo entre smart meters escuchando en 0.0.0.0:%d", PEER_ECHO_PORT)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)
        except Exception as exc:
            log.warning("Error en UDP echo: %s", exc)


def run_udp_probe(target: str, count: int = 10, interval: float = 0.2, size: int = 64,
                  timeout: float = 1.0, port: int | None = None) -> dict:
    """Envía paquetes UDP al echo peer y calcula RTT/loss/jitter."""
    count = max(1, min(count, 500))
    interval = max(0.01, min(interval, 10.0))
    size = max(16, min(size, 1400))
    timeout = max(0.1, min(timeout, 10.0))
    port = port or PEER_ECHO_PORT
    started = time.time()
    rtts_ms: list[float] = []
    received = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for seq in range(1, count + 1):
            nonce = secrets.token_hex(8)
            payload = json.dumps({
                "device_id": DEVICE_ID,
                "seq": seq,
                "nonce": nonce,
                "timestamp_ns": time.time_ns(),
                "pad": "x" * max(0, size - 96),
            }, separators=(",", ":")).encode("utf-8")

            sent_at = time.monotonic_ns()
            sock.sendto(payload, (target, port))
            try:
                data, _ = sock.recvfrom(65535)
                elapsed_ms = (time.monotonic_ns() - sent_at) / 1_000_000
                if data == payload:
                    received += 1
                    rtts_ms.append(elapsed_ms)
            except socket.timeout:
                pass

            if seq < count:
                time.sleep(interval)
    finally:
        sock.close()

    loss_percent = round(((count - received) / count) * 100, 3)
    duration_s = max(time.time() - started, 0.001)
    result = {
        "type": "udp_probe",
        "device_id": DEVICE_ID,
        "source_ip": get_local_ip(),
        "target": target,
        "target_port": port,
        "timestamp": int(started),
        "duration_ms": round(duration_s * 1000, 3),
        "packet_size_bytes": size,
        "transmitted": count,
        "received": received,
        "loss_percent": loss_percent,
        "rtt_ms": summarize_rtts(rtts_ms),
        "throughput_kbps": round((received * size * 8) / duration_s / 1000, 3),
    }
    remember_test(result)
    return result


class DiagnosticsHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        log.info("api %s - %s", self.client_address[0], fmt % args)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path in ("/", "/api/status"):
            with RECENT_TESTS_LOCK:
                recent = list(RECENT_TESTS)
            self.send_json(200, {
                "device_id": DEVICE_ID,
                "local_ip": get_local_ip(),
                "collector": {"ip": COLLECTOR_IP, "port": COLLECTOR_PORT},
                "peer_api_port": PEER_API_PORT,
                "peer_echo_port": PEER_ECHO_PORT,
                "configured_peers": PEER_IPS,
                "recent_tests": recent,
            })
            return

        if parsed.path == "/api/ping":
            target = query.get("target", [""])[0].strip()
            if not target:
                self.send_json(400, {"error": "missing target query parameter"})
                return
            count = int(query.get("count", ["5"])[0])
            timeout = int(query.get("timeout", ["2"])[0])
            self.send_json(200, run_icmp_ping(target, count=count, timeout=timeout))
            return

        if parsed.path == "/api/udp-probe":
            target = query.get("target", [""])[0].strip()
            if not target:
                self.send_json(400, {"error": "missing target query parameter"})
                return
            count = int(query.get("count", ["10"])[0])
            interval = float(query.get("interval", ["0.2"])[0])
            size = int(query.get("size", ["64"])[0])
            timeout = float(query.get("timeout", ["1.0"])[0])
            port = int(query.get("port", [str(PEER_ECHO_PORT)])[0])
            self.send_json(200, run_udp_probe(target, count=count, interval=interval,
                                              size=size, timeout=timeout, port=port))
            return

        self.send_json(404, {"error": "not found"})


def start_diagnostics_api() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PEER_API_PORT), DiagnosticsHandler)
    log.info("API diagnóstico smart meter escuchando en 0.0.0.0:%d", PEER_API_PORT)
    server.serve_forever()


def canonical_json(payload: dict) -> bytes:
    """Representación estable usada para firmar y verificar HMAC."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: dict) -> str:
    return hmac.new(
        HMAC_SECRET.encode("utf-8"),
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Generador de telemetría sintética
# ---------------------------------------------------------------------------
class SmartMeter:
    """Genera lecturas sintéticas que simulan un medidor eléctrico real."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.session_id = str(uuid.uuid4())[:8]
        self.energy_kwh = 0.0          # Acumulador de energía (kWh)
        self.reading_count = 0
        self._phase_offset = random.uniform(0, 2 * math.pi)
        log.info("Medidor inicializado: id=%s session=%s", device_id, self.session_id)

    def _simulate_phase_noise(self, t: float) -> float:
        """Retorna un factor de ruido senoidal para emular carga variable."""
        noise = 0.05 * math.sin(t / 30 + self._phase_offset)   # ciclo ~30s
        spike = 0.10 * random.gauss(0, 0.3)                     # ruido aleatorio
        return 1.0 + noise + spike

    def read(self) -> dict:
        """Genera y retorna una lectura del medidor."""
        t = time.monotonic()
        factor = self._simulate_phase_noise(t)

        voltage   = round(VOLTAGE_BASE * (1.0 + random.uniform(-0.02, 0.02)), 2)
        current   = round(max(0.1, CURRENT_BASE * factor), 2)
        power_kw  = round((voltage * current * POWER_FACTOR) / 1000, 3)
        reactive  = round(power_kw * math.tan(math.acos(POWER_FACTOR)), 3)

        # Acumular energía (kWh = kW * h, pero enviamos cada pocos segundos)
        self.energy_kwh += power_kw * (REPORT_INTERVAL / 3600)
        self.energy_kwh  = round(self.energy_kwh, 4)
        self.reading_count += 1

        active_power = round(voltage * current * POWER_FACTOR, 2)
        reactive_power = round((active_power / 1000) * math.tan(math.acos(POWER_FACTOR)), 3)

        reading = {
            "device_id"      : self.device_id,
            "timestamp"      : int(time.time()),
            "nonce"          : secrets.token_hex(16),
            "session_id"     : self.session_id,
            "seq"            : self.reading_count,
            "voltage"        : voltage,
            "current"        : current,
            "active_power"   : active_power,
            "reactive_power" : reactive_power,
            "voltage_v"      : voltage,
            "current_a"      : current,
            "active_power_kw": power_kw,
            "reactive_power_kvar": reactive,
            "power_factor"   : POWER_FACTOR,
            "energy_kwh"     : self.energy_kwh,
            "energy"         : self.energy_kwh,
            "status"         : "OK",
        }
        if HMAC_ENABLED:
            reading["signature"] = sign_payload(reading)
        return reading


# ---------------------------------------------------------------------------
# Publicador UDP
# ---------------------------------------------------------------------------
def get_local_ip() -> str | None:
    """
    Obtiene la IP real de eth0 sin depender de ruta a Internet.
    La SDN de guests es L2 aislada, por lo que usar un socket hacia 8.8.8.8
    puede fallar aunque DHCP ya haya entregado una IP válida.
    """
    try:
        import fcntl
        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack("256s", b"eth0")
        res = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        return socket.inet_ntoa(res[20:24])
    except Exception:
        return None


def wait_for_network(timeout: int = 60) -> str:
    """
    Espera hasta que la interfaz de red tenga una IP válida (no loopback).
    Retorna la IP obtenida o lanza TimeoutError.
    """
    log.info("Esperando dirección IP en la interfaz de red (timeout=%ds)...", timeout)
    # Primer intento inmediato — el entrypoint ya hizo DHCP
    ip = get_local_ip()
    if ip:
        log.info("IP detectada inmediatamente: %s", ip)
        return ip

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(2)
        ip = get_local_ip()
        if ip:
            log.info("IP detectada: %s", ip)
            return ip

    raise TimeoutError(f"No se obtuvo IP en {timeout}s. Verificar DHCP.")


def create_udp_socket(broadcast: bool) -> socket.socket:
    """Crea y configura un socket UDP (broadcast o unicast)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return sock


def main():
    log.info("=" * 60)
    log.info("SDN Smart Meter v1.0")
    log.info("  device_id      : %s", DEVICE_ID)
    log.info("  collector      : %s:%d", COLLECTOR_IP, COLLECTOR_PORT)
    log.info("  interval       : %.1fs", REPORT_INTERVAL)
    log.info("  hmac_enabled   : %s", HMAC_ENABLED)
    log.info("  peer_api       : 0.0.0.0:%d", PEER_API_PORT)
    log.info("  peer_udp_echo  : 0.0.0.0:%d", PEER_ECHO_PORT)
    log.info("  peer_ips       : %s", ",".join(PEER_IPS) or "none")
    log.info("=" * 60)

    if HMAC_ENABLED and not HMAC_SECRET:
        log.error("HMAC_ENABLED=true pero HMAC_SECRET no está configurado.")
        sys.exit(1)

    # Esperar IP de la red SDN. En GNS3 es normal que el puerto tarde en
    # estabilizarse si se recrean enlaces; no salimos para evitar que el nodo
    # se cierre antes de que DHCP esté disponible.
    while True:
        try:
            my_ip = wait_for_network(timeout=120)
            break
        except TimeoutError as e:
            log.error("%s Reintentando en 10s sin cerrar el medidor.", e)
            time.sleep(10)

    threading.Thread(target=start_udp_echo_server, daemon=True).start()
    threading.Thread(target=start_diagnostics_api, daemon=True).start()

    is_broadcast = (COLLECTOR_IP == "255.255.255.255")
    sock = create_udp_socket(broadcast=is_broadcast)
    meter = SmartMeter(device_id=DEVICE_ID)

    log.info("Iniciando publicación de telemetría hacia %s:%d ...",
             COLLECTOR_IP, COLLECTOR_PORT)

    consecutive_errors = 0
    while True:
        try:
            reading = meter.read()
            payload = json.dumps(reading).encode("utf-8")
            sock.sendto(payload, (COLLECTOR_IP, COLLECTOR_PORT))

            log.info(
                "seq=%d  V=%.1fV  I=%.2fA  P=%.3fkW  E=%.4fkWh",
                reading["seq"],
                reading["voltage_v"],
                reading["current_a"],
                reading["active_power_kw"],
                reading["energy_kwh"],
            )
            consecutive_errors = 0

        except OSError as e:
            consecutive_errors += 1
            log.warning("Error de red (%d consecutivos): %s", consecutive_errors, e)
            if consecutive_errors >= 10:
                log.error("Demasiados errores consecutivos. Reiniciando socket...")
                sock.close()
                sock = create_udp_socket(broadcast=is_broadcast)
                consecutive_errors = 0

        except Exception as e:
            log.error("Error inesperado: %s", e)

        time.sleep(REPORT_INTERVAL)


if __name__ == "__main__":
    main()
