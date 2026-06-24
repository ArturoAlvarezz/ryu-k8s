#!/usr/bin/env python3
"""
Test script for Ryu SDN Controller Security Features
Simulates MAC spoofing, IP spoofing, ARP poisoning and gateway spoofing.

Each vector uses a DISTINCT source MAC so the high-priority drop flow that Ryu
installs for one offending source does not silently suppress the Packet-In of
the next vector (the controller only records one event per source before the
hardware drop kicks in). Run from the attacker guest node (e.g. SDN-Attacker-1).

Usage: python3 test_security_threats.py [interface]   (default iface: eth0)

Expected Ryu reasons (one security:event per vector):
  mac_location_mismatch  - registered MAC seen on the wrong dpid/in_port
  ip_mismatch            - registered MAC using an IP != its registered IP
  ip_claim_conflict      - using another Smart Meter's IP with a foreign MAC
  mac_not_registered     - unregistered MAC speaking L3 on a guest port
                           (OBSERVE, no drop: un dispositivo DESCONOCIDO que no
                           suplanta identidad/IP ajena se deja descubrir para
                           poder darlo de alta en Operaciones; el collector sigue
                           fail-closed. SECURITY_DROP_UNREGISTERED=true lo bloquea)
  arp_gateway_spoof      - guest claiming to own the gateway 10.0.0.1 via ARP
  arp_mac_mismatch       - ARP where hwsrc != Ethernet src
"""

import sys
import time

try:
    from scapy.all import Ether, IP, UDP, ARP, Raw, sendp
except ImportError:
    print("Scapy not found. Install it with: pip install scapy")
    sys.exit(1)

# Identidades legitimas conocidas del lab (registro de seguridad).
SM1_MAC = "02:42:53:4d:00:01"
SM1_IP = "10.0.0.11"
SM2_MAC = "02:42:53:4d:00:02"
SM2_IP = "10.0.0.12"
SM3_IP = "10.0.0.13"
ATTACKER_MAC = "02:42:f0:47:3a:00"
GATEWAY = "10.0.0.1"

# NOTA: el trafico IP generico al gateway (10.0.0.1) va a LOCAL por el flow
# `priority=200,ip,nw_dst=10.0.0.1` del initializer. La TELEMETRIA (udp:5555 ->
# 10.0.0.1) desde puertos guest se desvia a CONTROLLER por el guard de telemetria
# de Ryu (`_install_telemetry_guard`), asi que Ryu valida su MAC real. Estos
# vectores L3 usan destino a otro guest para forzar Packet-In de forma simple;
# la MAC-spoof de telemetria a 10.0.0.1 se prueba aparte (ver test_mac_spoof_gw).
GUEST_DST = SM3_IP


def _udp(src_mac, src_ip, iface, dst=GUEST_DST):
    pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
           / IP(src=src_ip, dst=dst)
           / UDP(sport=12345, dport=9999)
           / Raw(load="test_telemetry"))
    sendp(pkt, iface=iface, verbose=False)


def _arp(eth_src, hwsrc, psrc, iface):
    pkt = (Ether(src=eth_src, dst="ff:ff:ff:ff:ff:ff")
           / ARP(op=1, hwsrc=hwsrc, psrc=psrc,
                 hwdst="00:00:00:00:00:00", pdst="10.0.0.100"))
    sendp(pkt, iface=iface, verbose=False)


def test_mac_spoof_gw(iface):
    """Telemetria con MAC Ethernet falsa pero IP/device_id legitimos de SM1 hacia
    el gateway 10.0.0.1:5555. Antes pasaba directo al collector (flow LOCAL); ahora
    el guard de telemetria de Ryu la desvia y la bloquea como ip_claim_conflict.
    El HMAC no es necesario: Ryu bloquea en L2 antes de que llegue al collector.
    Usa una MAC distinta de la del vector 3 para no quedar suprimido por su drop."""
    pkt = (Ether(src="ba:ad:f0:0d:00:07", dst="ff:ff:ff:ff:ff:ff")
           / IP(src=SM1_IP, dst=GATEWAY)
           / UDP(sport=40000, dport=5555)
           / Raw(load='{"device_id":"SDN-SmartMeter-1"}'))
    sendp(pkt, iface=iface, verbose=False)


def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    print(f"[*] Running security threat simulation on iface {iface}")

    print("[1] mac_location_mismatch: SM2 identity from the attacker port")
    _udp(SM2_MAC, SM2_IP, iface)
    time.sleep(1)

    print("[2] ip_mismatch: SM1 MAC with spoofed IP 10.0.0.250")
    _udp(SM1_MAC, "10.0.0.250", iface)
    time.sleep(1)

    print("[3] ip_claim_conflict: foreign MAC using SM1's IP 10.0.0.11")
    _udp("aa:bb:cc:dd:ee:ff", SM1_IP, iface)
    time.sleep(1)

    print("[4] mac_not_registered: unknown MAC with unregistered IP 10.0.0.240")
    _udp("de:ad:be:ef:00:99", "10.0.0.240", iface)
    time.sleep(1)

    print("[5] arp_gateway_spoof: claiming to be the gateway 10.0.0.1")
    _arp(ATTACKER_MAC, ATTACKER_MAC, GATEWAY, iface)
    time.sleep(1)

    print("[6] arp_mac_mismatch: ARP hwsrc != Ethernet src")
    _arp("12:34:56:78:9a:bc", "ca:fe:ca:fe:ca:fe", "10.0.0.50", iface)
    time.sleep(1)

    print("[7] ip_claim_conflict (telemetria a gateway): MAC falsa + IP/device_id de SM1")
    test_mac_spoof_gw(iface)
    time.sleep(1)

    print("[*] Done. Inspect Ryu logs and security:events / security:event_counter:*")


if __name__ == "__main__":
    main()
