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
        
        maestro_dpid = None
        
        def get_raw_dpid(dpid_decimal):
            try:
                return "0000" + hex(int(dpid_decimal))[2:].zfill(12)
            except Exception:
                return dpid_decimal
        
        # Identificar qué DPID pertenece al Maestro
        for dpid in switches:
            raw_dpid = get_raw_dpid(dpid)
            name = node_names.get(raw_dpid, "")
            if "maestro" in name.lower():
                maestro_dpid = dpid
                break

        # Construir la red física de switches (K3s Nodes)
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
            
            # Dibujar el enlace maestro-worker de la topología estrella de VXLAN
            if not is_maestro and maestro_dpid:
                edges.append({
                    "from": maestro_dpid,
                    "to": dpid,
                    "color": "#00ffcc",
                    "width": 3,
                    "smooth": {"type": "curvedCW"}
                })
            
            # Escanear tabla de direcciones MAC aprendidas para encontrar a los Guests locales
            mac_table = r.hgetall(f"mac_to_port:{dpid}")
            for mac, port_str in mac_table.items():
                port = int(port_str)
                # Omitir MACs de broadcast/multicast (IPV6)
                if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                    continue
                    
                # Filtro algorítmico infalible:
                # El script OVS en el DaemonSet asigna primero los puertos VXLAN.
                # En Maestro: puertos VXLAN son 1..10.
                # En Workers: puerto VXLAN es 1.
                # Cualquier MAC aprendida en un puerto superior a su cuota VXLAN, significa que está físicamente conectada (Local Guest).
                is_local_guest = False
                if is_maestro and port > 10:
                    is_local_guest = True
                elif not is_maestro and port > 1:
                    is_local_guest = True
                    
                if is_local_guest:
                    guest_id = mac
                    if guest_id not in [g['id'] for g in guests]:
                        guests.append({
                            "id": guest_id,
                            "label": f"{guest_id}",
                            "group": "guest",
                            "switch": dpid
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
