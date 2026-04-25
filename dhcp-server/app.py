import os
import time
import redis
import threading
import glob
from scapy.all import *

SENTINEL_HOST = os.environ.get('REDIS_SENTINEL_HOST', 'redis-sentinel.sdn-controller.svc.cluster.local')
SENTINEL_PORT = int(os.environ.get('REDIS_SENTINEL_PORT', 26379))
IFACE = "br-sdn"
NODE_NAME = os.environ.get("NODE_NAME", "")
LOCAL_DPID = None
HEALTHCHECK_SOURCE_IP = os.environ.get(
    "HEALTHCHECK_SOURCE_IP",
    "10.0.0.1" if NODE_NAME == "master" else "0.0.0.0"
)

print("Inicializando entorno de red...")
from redis.sentinel import Sentinel
r = None
while True:
    try:
        sentinel = Sentinel([(SENTINEL_HOST, SENTINEL_PORT)], socket_timeout=0.5)
        r = sentinel.master_for('mymaster', socket_timeout=0.5, decode_responses=True)
        r.ping()
        print("Conexión a Redis Sentinel SDN exitosa.")
        break
    except Exception as e:
        print(f"Esperando a Redis Sentinel en {SENTINEL_HOST}:{SENTINEL_PORT}... ({e})")
        time.sleep(3)

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

def get_local_dpid():
    global LOCAL_DPID
    if LOCAL_DPID:
        return LOCAL_DPID
    try:
        br0_mac = get_if_hwaddr("br0").replace(":", "")
        LOCAL_DPID = str(int("0000" + br0_mac, 16))
        return LOCAL_DPID
    except Exception as e:
        print(f"No se pudo calcular DPID local desde br0: {e}")
        return None

def get_local_guest_iface(mac):
    dpid = get_local_dpid()
    if not dpid:
        return None

    port_no = r.hget(f"mac_to_port:{dpid}", mac)
    if not port_no:
        return None

    iface = r.hget(f"switch_ports:{dpid}", port_no)
    if not iface or not iface.startswith("ens"):
        return None

    if not os.path.exists(f"/sys/class/net/{iface}"):
        return None

    return iface

def get_guest_interfaces():
    interfaces = []
    for path in glob.glob("/sys/class/net/ens*"):
        iface = os.path.basename(path)
        master_path = os.path.join(path, "master")
        if not os.path.exists(master_path):
            continue
        master = os.path.basename(os.path.realpath(master_path))
        if master == "ovs-system":
            interfaces.append(iface)
    return sorted(interfaces)

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
    source_iface = getattr(pkt, "sniffed_on", IFACE)
    
    # -------------------------------------------------------------
    # GESTOR DE COLISIONES CAPA 2 (Distributed Redis Locks)
    # -------------------------------------------------------------
    # Como todos los DaemonSets DHCP oirán este Broadcast a través de VXLAN,
    # competirán para clavar este candado con expiración de 2 segundos.
    # El primero en ejecutar Nx=True ganará.
    # Además concatenamos el estado para que Discover y Request tengan llaves separadas.
    lock_key = f"dhcp:lock:{mac_str}:{xid}:{msg_type}"
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
    
    server_mac = get_if_hwaddr(IFACE)
    ether = Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src=server_ip, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    
    bootp = BOOTP(
        op=2, # BOOTREPLY
        yiaddr=client_ip,
        siaddr=server_ip,
        htype=1,
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

    # Algunos guests en GNS3 no procesan de forma consistente el OFFER/ACK
    # cuando el retorno atraviesa OVS como broadcast. Enviar una copia L2
    # unicast mantiene el paquete DHCP en broadcast IP, pero lo dirige al NIC
    # exacto del cliente.
    unicast_response = Ether(src=server_mac, dst=mac_str) / ip / udp / bootp / dhcp
    sendp(unicast_response, iface=IFACE, verbose=False)

    local_iface = source_iface if source_iface.startswith("ens") else get_local_guest_iface(mac_str)
    if local_iface:
        local_mac = get_if_hwaddr(local_iface)
        direct_response = Ether(src=local_mac, dst=mac_str) / ip / udp / bootp / dhcp
        sendp(direct_response, iface=local_iface, verbose=False)
        print(f"[{mac_str}] Copia directa enviada por {local_iface}")

    print(f"[{mac_str}] Enviada respuesta tipo {reply_type} asignando IP {client_ip}")

def healthcheck_loop():
    print("Iniciando Radar de Healthcheck Activo L2 en hilo paralelo...")
    print(f"Healthcheck ARP usando psrc={HEALTHCHECK_SOURCE_IP} en nodo={NODE_NAME or 'desconocido'}")
    while True:
        try:
            guest_ips = r.hgetall('topology:guest_ips')
            for guest_mac, ip in guest_ips.items():
                if not ip.startswith("10."): 
                    continue
                # Solo el Maestro puede anunciar 10.0.0.1. Los workers usan
                # 0.0.0.0 para evitar envenenar la caché ARP de los guests y
                # desviar telemetría destinada al collector del Maestro.
                ans, unans = srp(
                    Ether(dst=guest_mac) / ARP(op=1, pdst=ip, psrc=HEALTHCHECK_SOURCE_IP),
                    iface=IFACE,
                    timeout=1,
                    verbose=False
                )
                if ans:
                    # Si respondió el ARP, inyectar el pulso de vida (TTL 30s)
                    r.set(f"health:{guest_mac}", "1", ex=30)
        except Exception as e:
            print(f"Aviso en hilo de Healthcheck L2: {e}")
        time.sleep(10)


if __name__ == "__main__":
    print("Iniciando SDN DHCP Server Distribuido sobre nodo local...")
    
    # Inicializar semilla del contador si la BD está limpia
    if not r.exists("dhcp:next_ip"):
        r.set("dhcp:next_ip", 10)
        
    while True:
        try:
            get_if_hwaddr(IFACE)
            os.system(f"ip link set {IFACE} up")
            print(f"Interfaz {IFACE} detectada correctamente. Estado forzado a UP.")
            break
        except Exception:
            print(f"Esperando a que la interfaz {IFACE} sea creada por el Orquestador OVS...")
            time.sleep(3)
            
    threading.Thread(target=healthcheck_loop, daemon=True).start()

    sniff_ifaces = get_guest_interfaces()
    if not sniff_ifaces:
        sniff_ifaces = [IFACE]
    print(f"Escuchando descubrimientos DHCP en interfaces: {', '.join(sniff_ifaces)}")
    while True:
        try:
            sniff(iface=sniff_ifaces, filter="udp and (port 67 or port 68)", prn=handle_dhcp, store=0)
        except OSError as e:
            print(f"Error de Socket (La red saltó temporalmente): {e}. Reintentando...")
            time.sleep(3)
        except Exception as e:
            print(f"Excepción general en Sniffer: {e}. Reintentando...")
            time.sleep(3)
