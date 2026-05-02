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
from datetime import datetime, timezone

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

# Parámetros eléctricos base para la simulación (distribución trifásica)
VOLTAGE_BASE    = 220.0   # Voltios RMS
CURRENT_BASE    = 15.0    # Amperios base
POWER_FACTOR    = 0.92    # Factor de potencia típico


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

        return {
            "device_id"      : self.device_id,
            "session_id"     : self.session_id,
            "seq"            : self.reading_count,
            "timestamp"      : datetime.now(timezone.utc).isoformat(),
            "voltage_v"      : voltage,
            "current_a"      : current,
            "active_power_kw": power_kw,
            "reactive_power_kvar": reactive,
            "power_factor"   : POWER_FACTOR,
            "energy_kwh"     : self.energy_kwh,
            "status"         : "OK",
        }


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
    log.info("=" * 60)

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
