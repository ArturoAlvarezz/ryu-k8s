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
            
            # Escanear tabla de direcciones MAC aprendidas para encontrar a los Guests locales
            mac_table = r.hgetall(f"mac_to_port:{dpid}")
            for mac, port_str in mac_table.items():
                port = int(port_str)
                # Omitir MACs de broadcast/multicast (IPV6)
                if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                    continue
                    
                # Filtro algorítmico de Anillo (Ring):
                # Cada nodo tiene ahora exactamente 2 túneles VXLAN configurados en su script inicial (Left/Right).
                # Es decir, los puertos OVS virtuales 1 y 2 son las salidas del anillo al resto del clúster K3s.
                # Cualquier MAC aprendida en un puerto > 2 pertenece obligadamente a un cable físico enchufado localmente (Guest).
                if port > 2:
                    guest_id = mac
                    if guest_id not in [g['id'] for g in guests]:
                        guests.append({
                            "id": guest_id,
                            "label": f"{guest_id}",
                            "group": "guest",
                            "switch": dpid
                        })
                        
        # Enlazar la red OVS centralizada según la estructura topológica de Pentágono/Anillo Físico
        ring_links = [
            ("maestro", "w1"),
            ("w1", "w2"),
            ("w2", "w3"),
            ("w3", "w4"),
            ("w4", "maestro")
        ]
        
        for src_role, dst_role in ring_links:
            src_dpid = role_to_dpid.get(src_role)
            dst_dpid = role_to_dpid.get(dst_role)
            if src_dpid and dst_dpid:
                edges.append({
                    "from": src_dpid,
                    "to": dst_dpid,
                    "color": "#00ffcc",
                    "width": 3,
                    "smooth": {"type": "curvedCW"}
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
            "maestro_dpid": maestro_dpid
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
