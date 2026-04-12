import os
import redis
import json
from flask import Flask, jsonify, render_template

app = Flask(__name__)

# Configuración de Redis
REDIS_HOST = os.environ.get('REDIS_HOST', 'redis.sdn-controller.svc.cluster.local')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/topology')
def get_topology():
    try:
        switches = r.smembers('topology:switches')
        node_names = r.hgetall('topology:node_names')

        nodes = []
        edges = []
        guests = []
        
        def get_raw_dpid(dpid_decimal):
            try:
                return "0000" + hex(int(dpid_decimal))[2:].zfill(12)
            except Exception:
                return dpid_decimal
        
        maestro_dpid = None
        role_to_dpid = {}

        # Mapear roles lógicos a sus respectivos DPID dinámicos
        for dpid in switches:
            raw_dpid = get_raw_dpid(dpid)
            name = node_names.get(raw_dpid, "").lower()
            if "maestro" in name:
                maestro_dpid = dpid
                role_to_dpid["maestro"] = dpid
            elif "worker1" in name:
                role_to_dpid["w1"] = dpid
            elif "worker2" in name:
                role_to_dpid["w2"] = dpid
            elif "worker3" in name:
                role_to_dpid["w3"] = dpid
            elif "worker4" in name:
                role_to_dpid["w4"] = dpid

        # Construir nodos físicos de switches (K3s Nodes)
        for dpid in switches:
            raw_dpid = get_raw_dpid(dpid)
            # Convertir el identificador decimal de vuelta a la MAC hexadecimal original para la UI
            try:
                hex_dpid = hex(int(dpid))[2:].zfill(12)
                formatted_hex = ':'.join(hex_dpid[i:i+2] for i in range(0, 12, 2))
            except Exception:
                formatted_hex = dpid
                
            raw_name = node_names.get(raw_dpid, "Nuevo Nodo")
            # El panel lateral leerá esta etiqueta saltando los retornos de carro
            name = f"{raw_name}\n({formatted_hex})"
            
            is_maestro = (dpid == maestro_dpid)
            
            nodes.append({
                "id": dpid,
                "label": name,
                "group": "maestro" if is_maestro else "worker",
                "title": f"DPID Numérico: {dpid}"
            })
            
            # Obtener el mapa global de IPs asignadas por el DHCP
            guest_ips = r.hgetall('topology:guest_ips')
            
            # Escanear tabla de direcciones MAC aprendidas para encontrar a los Guests locales
            mac_table = r.hgetall(f"mac_to_port:{dpid}")
            for mac, port_str in mac_table.items():
                port = int(port_str)
                # Omitir MACs de broadcast/multicast (IPV6)
                if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                    continue
                    
                # Healthcheck L2: Si el Ping ARP falló durante 30s, declaramos Muerte Sistemática.
                if not r.exists(f"health:{mac}"):
                    r.hdel(f"mac_to_port:{dpid}", mac)
                    r.hdel('topology:guest_ips', mac)
                    continue

                # Filtro algorítmico de Anillo (Ring) y limpieza de Fantasmas OVS Locales (port 65534)
                # Cada nodo tiene ahora exactamente 2 túneles VXLAN configurados en su script inicial (Left/Right).
                # Es decir, los puertos OVS virtuales 1 y 2 son las salidas del anillo al resto del clúster K3s.
                # Cualquier MAC aprendida en un puerto > 2 pertenece obligadamente a un cable físico enchufado localmente (Guest).
                if port > 2 and port < 60000:
                    guest_id = mac
                    if guest_id not in [g['id'] for g in guests]:
                        ip_text = guest_ips.get(guest_id, "Desconocida / DHCP Pendiente")
                        guests.append({
                            "id": guest_id,
                            "label": f"{guest_id}\nIP: {ip_text}",
                            "group": "guest",
                            "switch": dpid
                        })
                        
        # Dibujar la red OVS nativa consultando la topología L2 LLDP auto-descubierta
        db_links = r.smembers("topology:links")
        for link in db_links:
            # link format: "dpid1:portno1-dpid2:portno2"
            try:
                src_str, dst_str = link.split('-')
                src_dpid, src_port = src_str.split(':')
                dst_dpid, dst_port = dst_str.split(':')
                
                edges.append({
                    "from": str(src_dpid),
                    "to": str(dst_dpid),
                    "color": "#00ffcc",
                    "width": 3,
                    "smooth": {"type": "curvedCW"},
                    "title": f"LLDP Enlace Físico L2 (P{src_port} ↔ P{dst_port})"
                })
            except Exception:
                continue

        # Extraer Telemetría de Protección de Bucles (RSTP Analytics)
        blocked_ports = r.hgetall('topology:blocked_ports')
        blocked_edges = []
        for key in blocked_ports.keys():
            # key format: "dpid:ofport" -> e.g. "1234567890:1"
            if ":" not in key:
                continue
            src_raw_dpid, port_no = key.split(":")
            
            # Encontrar el DPID numérico original del source
            src_dpid = None
            for d in switches:
                if get_raw_dpid(d) == src_raw_dpid:
                    src_dpid = d
                    break
                    
            if not src_dpid:
                continue
                
            # Determinar el nodo destino inspeccionando los túneles LLDP reales en vez de adivinar nombres
            dst_dpid = None
            for link in db_links:
                try:
                    s_str, d_str = link.split('-')
                    s_dp, s_po = s_str.split(':')
                    d_dp, d_po = d_str.split(':')
                    
                    if str(s_dp) == str(src_dpid) and str(s_po) == str(port_no):
                        dst_dpid = d_dp
                        break
                    # Enlaces bidireccionales, verificar el inverso
                    elif str(d_dp) == str(src_dpid) and str(d_po) == str(port_no):
                        dst_dpid = s_dp
                        break
                except Exception:
                    continue
            
            if src_dpid and dst_dpid:
                blocked_edges.append({
                    "from": str(src_dpid),
                    "to": str(dst_dpid)
                })

        # Agregar los guests al gráfico y dibujar sus conexiones a sus switches padre
        for guest in guests:
            nodes.append({
                "id": guest["id"],
                "label": guest["label"],
                "group": guest["group"]
            })
            edges.append({
                "from": guest["switch"],
                "to": guest["id"],
                "color": "#ff00ee",
                "width": 1,
                "dashes": True,
                "title": "Cable Físico Local"
            })

        return jsonify({
            "nodes": nodes,
            "edges": edges,
            "guests": guests,
            "blocked_edges": blocked_edges,
            "maestro_dpid": maestro_dpid
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
