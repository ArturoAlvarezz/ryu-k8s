#!/usr/bin/env python3
"""CLI de pruebas entre Smart Meters.

Se ejecuta dentro del contenedor del medidor, por ejemplo:
  meter-test ping 10.0.0.12
  meter-test udp 10.0.0.12 --count 50 --size 128
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import app


def print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def configured_peers() -> list[str]:
    return [ip.strip() for ip in os.environ.get("PEER_IPS", "").split(",") if ip.strip()]


def command_status(_args: argparse.Namespace) -> int:
    print_json({
        "device_id": app.DEVICE_ID,
        "local_ip": app.get_local_ip(),
        "collector": {"ip": app.COLLECTOR_IP, "port": app.COLLECTOR_PORT},
        "peer_echo_port": app.PEER_ECHO_PORT,
        "configured_peers": configured_peers(),
    })
    return 0


def command_ping(args: argparse.Namespace) -> int:
    result = app.run_icmp_ping(args.target, count=args.count, timeout=args.timeout)
    print_json(result)
    return 0 if result.get("received", 0) > 0 else 1


def command_udp(args: argparse.Namespace) -> int:
    result = app.run_udp_probe(
        args.target,
        count=args.count,
        interval=args.interval,
        size=args.size,
        timeout=args.timeout,
        port=args.port,
    )
    print_json(result)
    return 0 if result.get("received", 0) > 0 else 1


def command_matrix(args: argparse.Namespace) -> int:
    targets = args.targets or configured_peers()
    if not targets:
        print("No hay destinos. Usa: meter-test matrix 10.0.0.12 10.0.0.13", file=sys.stderr)
        print("O configura PEER_IPS=10.0.0.12,10.0.0.13 en el appliance.", file=sys.stderr)
        return 2

    results = []
    exit_code = 0
    for target in targets:
        if args.mode in ("icmp", "both"):
            result = app.run_icmp_ping(target, count=args.count, timeout=args.timeout)
            results.append(result)
            if result.get("received", 0) == 0:
                exit_code = 1

        if args.mode in ("udp", "both"):
            result = app.run_udp_probe(
                target,
                count=args.udp_count,
                interval=args.interval,
                size=args.size,
                timeout=args.timeout,
                port=args.port,
            )
            results.append(result)
            if result.get("received", 0) == 0:
                exit_code = 1

    print_json({
        "device_id": app.DEVICE_ID,
        "source_ip": app.get_local_ip(),
        "targets": targets,
        "results": results,
    })
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meter-test",
        description="Ejecuta pruebas ICMP/UDP entre Smart Meters desde la consola del medidor.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="muestra IP local y configuración")
    status.set_defaults(func=command_status)

    ping = subparsers.add_parser("ping", help="mide conectividad ICMP hacia un medidor")
    ping.add_argument("target", help="IP destino, por ejemplo 10.0.0.12")
    ping.add_argument("--count", type=int, default=20, help="cantidad de paquetes ICMP")
    ping.add_argument("--timeout", type=int, default=2, help="timeout por paquete en segundos")
    ping.set_defaults(func=command_ping)

    udp = subparsers.add_parser("udp", help="mide UDP echo hacia un medidor")
    udp.add_argument("target", help="IP destino, por ejemplo 10.0.0.12")
    udp.add_argument("--count", type=int, default=50, help="cantidad de paquetes UDP")
    udp.add_argument("--interval", type=float, default=0.1, help="segundos entre paquetes")
    udp.add_argument("--size", type=int, default=128, help="tamano del payload UDP en bytes")
    udp.add_argument("--timeout", type=float, default=1.0, help="timeout por respuesta en segundos")
    udp.add_argument("--port", type=int, default=app.PEER_ECHO_PORT, help="puerto UDP echo destino")
    udp.set_defaults(func=command_udp)

    matrix = subparsers.add_parser("matrix", help="prueba uno o varios destinos")
    matrix.add_argument("targets", nargs="*", help="IPs destino; si se omiten usa PEER_IPS")
    matrix.add_argument("--mode", choices=("icmp", "udp", "both"), default="both")
    matrix.add_argument("--count", type=int, default=20, help="cantidad de paquetes ICMP por destino")
    matrix.add_argument("--udp-count", type=int, default=50, help="cantidad de paquetes UDP por destino")
    matrix.add_argument("--interval", type=float, default=0.1, help="segundos entre paquetes UDP")
    matrix.add_argument("--size", type=int, default=128, help="tamano del payload UDP en bytes")
    matrix.add_argument("--timeout", type=float, default=2.0, help="timeout por paquete/respuesta")
    matrix.add_argument("--port", type=int, default=app.PEER_ECHO_PORT, help="puerto UDP echo destino")
    matrix.set_defaults(func=command_matrix)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
