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
            
            # Extraer mapeo de puertos de este switch
            switch_ports_map = r.hgetall(f"switch_ports:{dpid}")

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

                # Identificación determinista: Solo las MACs en los puertos con nombre 'ens' son Guests locales!
                port_name = switch_ports_map.get(port_str, "")
                if port_name.startswith("ens"):
                    guest_id = mac
                    if guest_id not in [g['id'] for g in guests]:
                        ip_text = guest_ips.get(guest_id, "Desconocida / DHCP Pendiente")
                        guests.append({
                            "id": guest_id,
                            "label": f"{guest_id}\nIP: {ip_text}",
                            "group": "guest",
                            "switch": dpid
                        })
                        
        # Topología Determinista usando Port Names de Ryu
        # En lugar de depender del tráfico, leemos la estructura exacta del switch!
        seen_pairs = set()
        
        # Necesitamos cruzar el DPID numérico (decimal) usado por los Nodos visuales 
        # con la IP, pasando por la MAC en crudo.
        node_ips = r.hgetall('topology:node_ips')
        ip_to_dpid = {}
        for dp_dec in switches:
             raw = get_raw_dpid(dp_dec)
             ip = node_ips.get(raw)
             if ip:
                 # Mapa de IP sin puntos directamente al DPID numérico del backend
                 ip_to_dpid[ip.replace('.', '')] = str(dp_dec)

        # Mapeo universal de {DPID_ORIGEN: {PORT_NO: DPID_DESTINO}}
        # Servirá para construir los links y detectar puertos bloqueados
        dst_by_port = {}

        for dpid in switches:
            dst_by_port[str(dpid)] = {}
            ports = r.hgetall(f"switch_ports:{dpid}")
            for port_no_str, port_name in ports.items():
                port_no = int(port_no_str)
                # Si el puerto es un tunel VXLAN, su nombre es "vx" + IP remota sin puntos
                if port_name.startswith("vx"):
                    # Extraer la IP remota sin puntos: "vx192168122101" -> "192168122101"
                    raw_ip = port_name[2:]
                    
                    target_dpid = ip_to_dpid.get(raw_ip)
                    
                    if target_dpid:
                        dst_by_port[dpid][port_no_str] = target_dpid
                        # Normalizar par para evitar duplicados bidireccionales en el dibujo visual
                        pair = tuple(sorted([str(dpid), str(target_dpid)]))
                        if pair not in seen_pairs:
                            seen_pairs.add(pair)
                            edges.append({
                                "from": str(dpid),
                                "to": str(target_dpid),
                                "color": "#00ffcc",
                                "width": 3,
                                "smooth": {"type": "curvedCW"},
                                "title": f"Enlace VXLAN (P{port_no} ↔ Host: {ip})"
                            })

        # Extraer Telemetría de Protección de Bucles (RSTP Analytics)
        blocked_ports = r.hgetall('topology:blocked_ports')
        blocked_edges = []
        for key in blocked_ports.keys():
            # key format: "dpid:ofport" -> e.g. "1234567890:1"
            if ":" not in key:
                continue
            src_raw_dpid, port_no_str = key.split(":")
            
            # Encontrar el DPID numérico original del source
            src_dpid = None
            for d in switches:
                if get_raw_dpid(d) == src_raw_dpid:
                    src_dpid = d
                    break
                    
            if not src_dpid:
                continue
                
            # Buscar el destino usando nuestro mapa determinista!
            dst_dpid = dst_by_port.get(str(src_dpid), {}).get(str(port_no_str))
            
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

@app.route('/api/trace/<src_guest>/<dst_guest>')
def trace_path(src_guest, dst_guest):
    try:
        # Encontrar los switches origen y destino
        switches = r.smembers('topology:switches')
        src_switch = None
        dst_switch = None
        
        for dpid in switches:
            mac_table = r.hgetall(f"mac_to_port:{dpid}")
            # Si el switch conoce localmente al origen (puerto no es de tunnel)
            port_src_str = mac_table.get(src_guest)
            if port_src_str:
                port_name = r.hget(f"switch_ports:{dpid}", port_src_str) or ""
                if not port_name.startswith("vx"):
                    src_switch = dpid

            port_dst_str = mac_table.get(dst_guest)
            if port_dst_str:
                port_name = r.hget(f"switch_ports:{dpid}", port_dst_str) or ""
                if not port_name.startswith("vx"):
                    dst_switch = dpid

        if not src_switch or not dst_switch:
            return jsonify({"error": "Guests no localizados (o no tienen tráfico reciente)"}), 404

        # Realizar Tracing usando las tablas reales decididas por Ryu
        path = [src_switch]
        curr_switch = src_switch
        # Construir mapa de IP a DPID Decimal
        node_ips = r.hgetall('topology:node_ips')
        ip_to_dpid = {}
        for dp_dec in switches:
             raw = "0000" + hex(int(dp_dec))[2:].zfill(12)
             ip = node_ips.get(raw)
             if ip:
                 ip_to_dpid[ip.replace('.', '')] = str(dp_dec)
        visited = set()

        while curr_switch != dst_switch:
            if curr_switch in visited:
                break # Evitar bucles infinitos en caso de inconsistencia
            visited.add(curr_switch)

            # Ryu dice que para llegar a dst_guest, debe salir por este puerto:
            out_port_str = r.hget(f"mac_to_port:{curr_switch}", dst_guest)
            if not out_port_str:
                break # Faltan tablas
                
            port_name = r.hget(f"switch_ports:{curr_switch}", out_port_str)
            if not port_name or not port_name.startswith("vx"):
                break # Puerto invalido o no es tunel

            raw_ip = port_name[2:]
            next_switch = ip_to_dpid.get(raw_ip)
            
            if next_switch:
                path.append(next_switch)
                curr_switch = next_switch
            else:
                break

        return jsonify({"path": path})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
