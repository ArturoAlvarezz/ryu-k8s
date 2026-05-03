import logging
import os
import json

from flask import Flask, jsonify, render_template, request

import registry


logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("security-device-registry-web")

app = Flask(__name__)


def redis_client():
    return registry.connect_redis()


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


def looks_like_worker_name(name):
    value = (name or "").lower()
    return value.startswith("worker") or value.startswith("master") or value.startswith("maestro")


def observed_workers(r):
    node_names = r.hgetall("topology:node_names")
    node_ips = r.hgetall("topology:node_ips")
    workers = []

    for raw_dpid, name in sorted(node_names.items(), key=lambda item: item[1]):
        if not looks_like_worker_name(name):
            continue
        dpid = normalize_dpid(raw_dpid)
        mac = ""
        if len(raw_dpid) >= 12:
            raw_mac = raw_dpid[-12:]
            mac = ":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower()
        workers.append({
            "mac": mac,
            "ip": node_ips.get(raw_dpid, ""),
            "name": name,
            "dpid": dpid,
            "in_port": "",
            "port_name": "node",
            "node_name": name,
            "online": bool(r.exists(f"switch:alive:{raw_dpid}")),
            "kind": "worker",
        })

    return workers


def observed_guests(r):
    guest_ips = r.hgetall("topology:guest_ips")
    guest_names = r.hgetall("topology:guest_names")
    node_names = r.hgetall("topology:node_names")
    worker_macs = registry.known_worker_macs(r)
    guests = {}

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
            "online": bool(r.exists(f"health:{mac}")),
            "kind": "guest",
        }

    for key in r.scan_iter("active_mac:*"):
        parts = key.split(":", 2)
        if len(parts) != 3:
            continue
        dpid = parts[1]
        mac = registry.normalize_mac(parts[2])
        if mac in guests or mac in worker_macs or looks_like_worker_name(guest_names.get(mac, "")):
            continue
        ip = r.get(f"dhcp:bind:{mac}") or ""
        if not ip:
            continue
        raw_dpid = "0000" + hex(int(dpid))[2:].zfill(12) if str(dpid).isdigit() else str(dpid)
        guests[mac] = {
            "mac": mac,
            "ip": ip,
            "name": guest_names.get(mac, ""),
            "dpid": str(dpid),
            "in_port": "",
            "port_name": "active_mac",
            "node_name": node_names.get(raw_dpid, ""),
            "online": bool(r.exists(key)) or bool(r.exists(f"health:{mac}")),
            "kind": "guest",
        }

    for key in r.scan_iter("mac_to_port:*"):
        dpid = key.split(":", 1)[1]
        ports = r.hgetall(f"switch_ports:{dpid}")
        for mac, in_port in r.hgetall(key).items():
            mac = registry.normalize_mac(mac)
            if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                continue
            port_name = ports.get(str(in_port), "")
            if mac in worker_macs or looks_like_worker_name(guest_names.get(mac, "")):
                continue
            if not port_name.startswith("ens"):
                continue
            dhcp_ip = r.get(f"dhcp:bind:{mac}") or ""
            if mac not in guests and not dhcp_ip:
                continue
            guest = guests.setdefault(
                mac,
                {
                    "mac": mac,
                    "ip": dhcp_ip,
                    "name": guest_names.get(mac, ""),
                    "online": bool(r.exists(f"health:{mac}")),
                },
            )
            raw_dpid = "0000" + hex(int(dpid))[2:].zfill(12) if str(dpid).isdigit() else str(dpid)
            guest.update(
                {
                    "dpid": str(dpid),
                    "in_port": str(in_port),
                    "port_name": port_name,
                    "node_name": node_names.get(raw_dpid, ""),
                    "kind": "guest",
                }
            )

    return sorted(guests.values(), key=lambda item: (item.get("ip") or "", item["mac"]))


def with_security_state(r, guest):
    if guest.get("kind") == "worker":
        guest["registered"] = True
        guest["security_status"] = "worker"
        guest["validation"] = {"allowed": True, "reason": "worker_auto_allowed"}
        guest["device"] = None
        return guest

    device = registry.get_by_index(r, registry.KEY_MAC_TO_DEVICE, registry.normalize_mac(guest["mac"]))
    if not device:
        guest["registered"] = False
        guest["security_status"] = "unregistered"
        guest["device"] = None
        return guest

    allowed, reason, _ = registry.validate_observed_device(
        r,
        guest["mac"],
        guest.get("ip", ""),
        guest.get("dpid", ""),
        guest.get("in_port", ""),
    )
    guest["registered"] = True
    guest["security_status"] = device.get("status", "unknown")
    guest["validation"] = {"allowed": allowed, "reason": reason}
    guest["device"] = device
    return guest


def telemetry_security_state(r):
    counters = {
        "accepted_total": int(r.get("meter:hmac:accepted_total") or 0),
        "invalid_total": int(r.get("meter:hmac:invalid_total") or 0),
        "by_reason": {},
        "recent_events": [],
    }
    for key in r.scan_iter("meter:hmac:invalid_total:*"):
        reason = key.rsplit(":", 1)[-1]
        counters["by_reason"][reason] = int(r.get(key) or 0)
    for raw in r.lrange("meter:hmac:events", 0, 9):
        try:
            counters["recent_events"].append(json.loads(raw))
        except Exception:
            continue
    return counters


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/ready")
def ready():
    try:
        redis_client().ping()
        return jsonify({"ready": True})
    except Exception as exc:
        return jsonify({"ready": False, "error": str(exc)}), 503


@app.route("/api/guests")
def api_guests():
    try:
        r = redis_client()
        workers = [with_security_state(r, worker) for worker in observed_workers(r)]
        guests = [with_security_state(r, guest) for guest in observed_guests(r)]
        registered = registry.list_devices(r)
        observed_macs = {item["mac"] for item in workers + guests}
        offline_registered = [device for device in registered if device["mac"] not in observed_macs]
        return jsonify({"guests": guests, "workers": workers, "offline_registered": offline_registered})
    except Exception as exc:
        log.exception("No se pudo listar guests")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/telemetry-security")
def api_telemetry_security():
    try:
        return jsonify(telemetry_security_state(redis_client()))
    except Exception as exc:
        log.exception("No se pudo leer seguridad de telemetría")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/devices", methods=["POST"])
def api_register_device():
    try:
        payload = request.get_json(force=True)
        device = registry.save_device(redis_client(), payload)
        return jsonify(device), 201
    except Exception as exc:
        log.exception("No se pudo registrar dispositivo")
        return jsonify({"error": str(exc)}), 400


@app.route("/api/devices/<device_id>/status", methods=["PATCH"])
def api_set_status(device_id):
    try:
        payload = request.get_json(force=True)
        status = payload.get("status")
        device = registry.update_status(redis_client(), device_id, status)
        return jsonify(device)
    except Exception as exc:
        log.exception("No se pudo cambiar estado de %s", device_id)
        return jsonify({"error": str(exc)}), 400


@app.route("/api/devices/<device_id>", methods=["DELETE"])
def api_delete_device(device_id):
    try:
        deleted = registry.delete_device(redis_client(), device_id)
        return jsonify({"deleted": deleted})
    except Exception as exc:
        log.exception("No se pudo eliminar dispositivo %s", device_id)
        return jsonify({"error": str(exc)}), 400


@app.route("/api/validate", methods=["POST"])
def api_validate():
    try:
        payload = request.get_json(force=True)
        allowed, reason, device = registry.validate_observed_device(
            redis_client(),
            payload.get("mac", ""),
            payload.get("ip", ""),
            payload.get("dpid", ""),
            payload.get("in_port", ""),
        )
        return jsonify({"allowed": allowed, "reason": reason, "device": device})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
