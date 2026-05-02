#!/usr/bin/env python3
"""
Test script for Ryu SDN Controller Security Features
Simulates MAC spoofing, IP spoofing, and ARP poisoning.

Usage: python3 test_security_threats.py <target_ip> <target_mac> [interface]
"""

import sys
import time
try:
    from scapy.all import *
except ImportError:
    print("Scapy not found. Install it with: pip install scapy")
    sys.exit(1)

def send_telemetry(src_mac, src_ip, dst_ip="10.0.0.1", dst_port=5555, iface="ens3"):
    print(f"[*] Sending telemetry from {src_mac} / {src_ip}")
    pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst=dst_ip) / UDP(sport=12345, dport=dst_port) / Raw(load="test_telemetry")
    sendp(pkt, iface=iface, verbose=False)

def test_mac_spoofing(legit_mac, legit_ip, iface):
    print("\n--- Testing MAC Spoofing ---")
    # Sending telemetry from unregistered MAC
    fake_mac = "aa:bb:cc:dd:ee:ff"
    print(f"[*] Sending from unregistered MAC: {fake_mac}")
    send_telemetry(fake_mac, legit_ip, iface=iface)

def test_ip_spoofing(legit_mac, iface):
    print("\n--- Testing IP Spoofing ---")
    fake_ip = "10.0.0.250"
    print(f"[*] Sending from registered MAC {legit_mac} but spoofed IP {fake_ip}")
    send_telemetry(legit_mac, fake_ip, iface=iface)

    print(f"[*] Sending from registered MAC {legit_mac} but claiming reserved IP 10.0.0.1")
    send_telemetry(legit_mac, "10.0.0.1", iface=iface)

def test_arp_poisoning(legit_mac, legit_ip, iface):
    print("\n--- Testing ARP Poisoning ---")
    print(f"[*] Claiming to be the gateway 10.0.0.1 from {legit_mac}")
    arp_req = Ether(src=legit_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=legit_mac, psrc="10.0.0.1", hwdst="00:00:00:00:00:00", pdst="10.0.0.100")
    sendp(arp_req, iface=iface, verbose=False)

    print(f"[*] Sending ARP with mismatched MACs")
    arp_mismatch = Ether(src=legit_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="11:22:33:44:55:66", psrc=legit_ip, hwdst="00:00:00:00:00:00", pdst="10.0.0.100")
    sendp(arp_mismatch, iface=iface, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 test_security_threats.py <your_legit_mac> <your_legit_ip> [interface]")
        sys.exit(1)
        
    legit_mac = sys.argv[1]
    legit_ip = sys.argv[2]
    iface = sys.argv[3] if len(sys.argv) > 3 else "ens3"
    
    print("Starting Security Threats Simulation...")
    print(f"Ensure you are running this from a guest node in the SDN network (using iface {iface}).")
    
    # 1. Legitimate traffic
    print("\n--- Testing Legitimate Traffic ---")
    send_telemetry(legit_mac, legit_ip, iface=iface)
    time.sleep(1)
    
    # 2. MAC Spoofing
    test_mac_spoofing(legit_mac, legit_ip, iface)
    time.sleep(1)
    
    # 3. IP Spoofing
    test_ip_spoofing(legit_mac, iface)
    time.sleep(1)
    
    # 4. ARP Poisoning
    test_arp_poisoning(legit_mac, legit_ip, iface)
    time.sleep(1)
    
    print("\nTests complete. Check the Ryu controller logs and Security Registry UI.")
