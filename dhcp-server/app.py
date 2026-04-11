import os
import time
import redis
from scapy.all import *

REDIS_HOST = os.environ.get('REDIS_HOST', 'redis.sdn-controller.svc.cluster.local')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
IFACE = "br-sdn"

try:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    r.ping()
    print("Conexión a Redis SDN exitosa.")
except Exception as e:
    print(f"Error conectando a Redis: {e}")
    exit(1)

def get_ip_for_mac(mac):
    allocated = r.get(f"dhcp:bind:{mac}")
    if allocated:
        return allocated
    
    # Calculate new IP
    next_index = r.incr("dhcp:next_ip")
    # If next_index was empty and initialized by incr, start at 10
    if next_index == 1: 
        r.set("dhcp:next_ip", 10)
        next_index = 10
        
    if next_index > 250:
        print("¡El Pool de direcciones DHCP está agotado (Límite 250)!")
        return None
        
    new_ip = f"10.0.0.{next_index}"
    r.set(f"dhcp:bind:{mac}", new_ip)
    # Registrar también en el listado general de Topología a futuro
    r.hset("topology:guest_ips", mac, new_ip)
    
    return new_ip

def handle_dhcp(pkt):
    if not (DHCP in pkt and BOOTP in pkt):
        return

    dhcp_options = pkt[DHCP].options
    msg_type = None
    for opt in dhcp_options:
        if isinstance(opt, tuple) and opt[0] == 'message-type':
            msg_type = opt[1]
            break

    if not msg_type:
        return

    # message-type: 1 = DISCOVER, 3 = REQUEST
    if msg_type not in [1, 3]:
        return

    xid = pkt[BOOTP].xid
    mac_str = pkt[Ether].src
    
    # -------------------------------------------------------------
    # GESTOR DE COLISIONES CAPA 2 (Distributed Redis Locks)
    # -------------------------------------------------------------
    # Como todos los DaemonSets DHCP oirán este Broadcast a través de VXLAN,
    # competirán para clavar este candado con expiración de 2 segundos.
    # El primero en ejecutar Nx=True ganará.
    # Además concatenamos el estado para que Discover y Request tengan llaves separadas.
    lock_key = f"dhcp:lock:{xid}:{msg_type}"
    acquired = r.set(lock_key, "1", ex=2, nx=True)
    
    if not acquired:
        # Out of bounds: Otro DaemonSet del anillo contestó más rápido.
        return
        
    print(f"[{mac_str}] He ganado el Bloqueo Atómico. Procesando DHCP msg_type={msg_type}")
    
    client_ip = get_ip_for_mac(mac_str)
    if not client_ip:
        print(f"[{mac_str}] Operación abortada, no hay IPs.")
        return
        
    # Gateway virtual representativo de la SDN
    server_ip = "10.0.0.1" 
    
    # Respuesta: DHCPOFFER (2) o DHCPACK (5)
    reply_type = 2 if msg_type == 1 else 5 
    
    ether = Ether(src=get_if_hwaddr(IFACE), dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src=server_ip, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    
    bootp = BOOTP(
        op=2, # BOOTREPLY
        yiaddr=client_ip,
        siaddr=server_ip,
        hwtype=1,
        hlen=6,
        xid=xid,
        flags=0x8000, # Broadcast flag
        chaddr=pkt[BOOTP].chaddr
    )
    
    dhcp = DHCP(options=[
        ("message-type", reply_type),
        ("subnet_mask", "255.255.255.0"),
        ("router", server_ip),
        ("name_server", "8.8.8.8"),
        ("server_id", server_ip),
        ("lease_time", 86400),
        "end"
    ])
    
    response = ether / ip / udp / bootp / dhcp
    sendp(response, iface=IFACE, verbose=False)
    print(f"[{mac_str}] Enviada respuesta tipo {reply_type} asignando IP {client_ip}")

if __name__ == "__main__":
    print("Iniciando SDN DHCP Server Distribuido sobre nodo local...")
    
    # Inicializar semilla del contador si la BD está limpia
    if not r.exists("dhcp:next_ip"):
        r.set("dhcp:next_ip", 10)
        
    print(f"Escuchando descubrimientos en interfaz maestra {IFACE}... ")
    sniff(iface=IFACE, filter="udp and (port 67 or port 68)", prn=handle_dhcp, store=0)
