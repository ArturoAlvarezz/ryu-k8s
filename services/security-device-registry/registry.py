import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

from redis.sentinel import Sentinel


SENTINEL_HOST = os.environ.get("REDIS_SENTINEL_HOST", "redis-sentinel.sdn-controller.svc.cluster.local")
SENTINEL_PORT = int(os.environ.get("REDIS_SENTINEL_PORT", "26379"))
SENTINEL_MASTER = os.environ.get("REDIS_SENTINEL_MASTER", "mymaster")

KEY_DEVICES = "security:devices"
KEY_DEVICE = "security:device:{}"
KEY_MAC_TO_DEVICE = "security:mac_to_device:{}"
KEY_IP_TO_DEVICE = "security:ip_to_device:{}"

REQUIRED_FIELDS = (
    "device_id",
    "mac",
    "ip",
    "role",
    "allowed_dst_ip",
    "allowed_udp_port",
    "status",
    "registered_at",
    "last_seen",
    "dpid",
    "in_port",
)
VALID_STATUSES = {"authorized", "blocked", "quarantined"}


log = logging.getLogger("security-device-registry")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_mac(mac):
    return mac.strip().lower()


def normalize_device(raw):
    now = utc_now()
    device = {
        "device_id": str(raw.get("device_id", "")).strip(),
        "mac": normalize_mac(str(raw.get("mac", ""))),
        "ip": str(raw.get("ip", "")).strip(),
        "role": str(raw.get("role", "smart_meter")).strip(),
        "allowed_dst_ip": str(raw.get("allowed_dst_ip", "10.0.0.1")).strip(),
        "allowed_udp_port": int(raw.get("allowed_udp_port", 5555)),
        "status": str(raw.get("status", "authorized")).strip(),
        "registered_at": str(raw.get("registered_at") or now),
        "last_seen": str(raw.get("last_seen") or ""),
        "dpid": str(raw.get("dpid") or "").strip(),
        "in_port": str(raw.get("in_port") or "").strip(),
    }
    validate_device(device)
    return device


def validate_device(device):
    missing = [field for field in REQUIRED_FIELDS if field not in device]
    if missing:
        raise ValueError(f"Campos requeridos ausentes: {', '.join(missing)}")
    if not device["device_id"]:
        raise ValueError("device_id no puede estar vacio")
    if not device["mac"]:
        raise ValueError("mac no puede estar vacia")
    if not device["ip"]:
        raise ValueError("ip no puede estar vacia")
    if device["status"] not in VALID_STATUSES:
        raise ValueError(f"status invalido: {device['status']}")


def connect_redis():
    try:
        sentinel = Sentinel([(SENTINEL_HOST, SENTINEL_PORT)], socket_timeout=1.0)
        redis_client = sentinel.master_for(SENTINEL_MASTER, socket_timeout=1.0, decode_responses=True)
        redis_client.ping()
        log.info("Conectado a Redis Sentinel %s:%s master=%s", SENTINEL_HOST, SENTINEL_PORT, SENTINEL_MASTER)
        return redis_client
    except Exception as exc:
        raise RuntimeError(
            f"Redis no disponible via Sentinel {SENTINEL_HOST}:{SENTINEL_PORT} master={SENTINEL_MASTER}: {exc}"
        ) from exc


def save_device(redis_client, device):
    device = normalize_device(device)
    old_payload = redis_client.get(KEY_DEVICE.format(device["device_id"]))
    pipe = redis_client.pipeline()

    if old_payload:
        old = json.loads(old_payload)
        if old.get("mac") and old.get("mac") != device["mac"]:
            pipe.delete(KEY_MAC_TO_DEVICE.format(old["mac"]))
        if old.get("ip") and old.get("ip") != device["ip"]:
            pipe.delete(KEY_IP_TO_DEVICE.format(old["ip"]))

    pipe.sadd(KEY_DEVICES, device["device_id"])
    pipe.set(KEY_DEVICE.format(device["device_id"]), json.dumps(device, sort_keys=True))
    pipe.set(KEY_MAC_TO_DEVICE.format(device["mac"]), device["device_id"])
    pipe.set(KEY_IP_TO_DEVICE.format(device["ip"]), device["device_id"])
    pipe.execute()
    log.info("Dispositivo registrado: %s mac=%s ip=%s status=%s", device["device_id"], device["mac"], device["ip"], device["status"])
    return device


def get_device(redis_client, device_id):
    payload = redis_client.get(KEY_DEVICE.format(device_id))
    return json.loads(payload) if payload else None


def get_by_index(redis_client, key_pattern, value):
    device_id = redis_client.get(key_pattern.format(value))
    return get_device(redis_client, device_id) if device_id else None


def list_devices(redis_client):
    devices = []
    for device_id in sorted(redis_client.smembers(KEY_DEVICES)):
        device = get_device(redis_client, device_id)
        if device:
            devices.append(device)
    return devices


def update_status(redis_client, device_id, status):
    if status not in VALID_STATUSES:
        raise ValueError(f"status invalido: {status}")
    device = get_device(redis_client, device_id)
    if not device:
        raise LookupError(f"Dispositivo no encontrado: {device_id}")
    device["status"] = status
    return save_device(redis_client, device)


def validate_observed_device(redis_client, mac, ip, dpid, in_port):
    device = get_by_index(redis_client, KEY_MAC_TO_DEVICE, normalize_mac(mac))
    if not device:
        return False, "mac_not_registered", None
    if device["status"] != "authorized":
        return False, f"status_{device['status']}", device
    if device["ip"] != ip:
        return False, "ip_mismatch", device
    if device["dpid"] and device["dpid"] != str(dpid):
        return False, "dpid_mismatch", device
    if device["in_port"] and device["in_port"] != str(in_port):
        return False, "port_mismatch", device
    return True, "authorized", device


def print_json(data):
    print(json.dumps(data, indent=2, sort_keys=True))


def cmd_register(redis_client, args):
    raw = {
        "device_id": args.device_id,
        "mac": args.mac,
        "ip": args.ip,
        "role": args.role,
        "allowed_dst_ip": args.allowed_dst_ip,
        "allowed_udp_port": args.allowed_udp_port,
        "status": args.status,
        "dpid": args.dpid or "",
        "in_port": args.in_port or "",
    }
    print_json(save_device(redis_client, raw))


def cmd_list(redis_client, _args):
    devices = list_devices(redis_client)
    print_json({"count": len(devices), "devices": devices})


def cmd_get_mac(redis_client, args):
    device = get_by_index(redis_client, KEY_MAC_TO_DEVICE, normalize_mac(args.mac))
    if not device:
        raise LookupError(f"Dispositivo no encontrado para MAC: {args.mac}")
    print_json(device)


def cmd_get_ip(redis_client, args):
    device = get_by_index(redis_client, KEY_IP_TO_DEVICE, args.ip)
    if not device:
        raise LookupError(f"Dispositivo no encontrado para IP: {args.ip}")
    print_json(device)


def cmd_set_status(redis_client, args):
    print_json(update_status(redis_client, args.device_id, args.status))


def cmd_validate(redis_client, args):
    allowed, reason, device = validate_observed_device(redis_client, args.mac, args.ip, args.dpid, args.in_port)
    print_json({"allowed": allowed, "reason": reason, "device": device})
    if not allowed:
        return 2
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Registro Redis de dispositivos autorizados SDN AMI")
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register", help="Registra o actualiza un dispositivo autorizado")
    register.add_argument("--device-id", required=True)
    register.add_argument("--mac", required=True)
    register.add_argument("--ip", required=True)
    register.add_argument("--role", default="smart_meter")
    register.add_argument("--allowed-dst-ip", default="10.0.0.1")
    register.add_argument("--allowed-udp-port", type=int, default=5555)
    register.add_argument("--status", choices=sorted(VALID_STATUSES), default="authorized")
    register.add_argument("--dpid", default="")
    register.add_argument("--in-port", default="")
    register.set_defaults(handler=cmd_register)

    list_cmd = sub.add_parser("list", help="Lista dispositivos registrados")
    list_cmd.set_defaults(handler=cmd_list)

    get_mac = sub.add_parser("get-mac", help="Consulta dispositivo por MAC")
    get_mac.add_argument("mac")
    get_mac.set_defaults(handler=cmd_get_mac)

    get_ip = sub.add_parser("get-ip", help="Consulta dispositivo por IP")
    get_ip.add_argument("ip")
    get_ip.set_defaults(handler=cmd_get_ip)

    status = sub.add_parser("set-status", help="Cambia estado del dispositivo")
    status.add_argument("device_id")
    status.add_argument("status", choices=sorted(VALID_STATUSES))
    status.set_defaults(handler=cmd_set_status)

    validate = sub.add_parser("validate", help="Valida MAC/IP/DPID/in_port observado por Ryu")
    validate.add_argument("--mac", required=True)
    validate.add_argument("--ip", required=True)
    validate.add_argument("--dpid", required=True)
    validate.add_argument("--in-port", required=True)
    validate.set_defaults(handler=cmd_validate)

    return parser


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    try:
        redis_client = connect_redis()
        result = args.handler(redis_client, args)
        return int(result or 0)
    except Exception as exc:
        log.error("Error ejecutando %s: %s", args.command, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
