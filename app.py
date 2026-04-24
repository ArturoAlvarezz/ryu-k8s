import os
import redis
import eventlet
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.topology import event
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.topology import event, switches

# Patch eventlet heavily used by Ryu to work properly with Redis and other sockets
eventlet.monkey_patch()

METRICS_PORT = int(os.environ.get("METRICS_PORT", 8000))


def _escape_label(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class DistributedL2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(DistributedL2Switch, self).__init__(*args, **kwargs)
        
        # Redis connection setup (Sentinel HA)
        from redis.sentinel import Sentinel
        sentinel_host = os.environ.get('REDIS_SENTINEL_HOST', 'redis-sentinel.sdn-controller.svc.cluster.local')
        sentinel_port = int(os.environ.get('REDIS_SENTINEL_PORT', 26379))
        self.sentinel = Sentinel([(sentinel_host, sentinel_port)], socket_timeout=0.5)
        self.redis = self.sentinel.master_for('mymaster', socket_timeout=0.5, decode_responses=True)
        self.logger.info("Connected to Redis Sentinel at %s:%d", sentinel_host, sentinel_port)
        self.datapaths = {}
        self.packet_in_total = {}
        self.flow_mod_total = {}
        self.installed_flows = {}
        self.port_stats = {}
        self.metrics_started_at = datetime.utcnow().timestamp()
        self.monitor_thread = hub.spawn(self._monitor_datapaths)
        self.metrics_thread = hub.spawn(self._start_metrics_server)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Externalize State: Register switch in the global Redis topology set
        self.redis.sadd('topology:switches', dpid)
        self.datapaths[dpid] = datapath
        self.installed_flows.setdefault(dpid, 0)
        self.logger.info("Switch connected and registered in Redis: dpid=%s", dpid)

        # Install table-miss flow entry
        # We specify NO BUFFER to max_len of the output action due to OVS bug.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Solicitar la lista de puertos físicos y virtuales al switch para la topología determinista
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == DEAD_DISPATCHER:
            if datapath.id is None:
                return
            dpid = datapath.id
            self.datapaths.pop(dpid, None)
            self.installed_flows.pop(dpid, None)
            self.port_stats = {
                key: value for key, value in self.port_stats.items()
                if key[0] != dpid
            }
            self.logger.info("Switch disconnected, removing from Redis: dpid=%s", dpid)
            
            # Borrar de la lista global de switches
            self.redis.srem('topology:switches', dpid)
            
            # Formatear el dpid a hexadecimal de 16 caracteres (formato raw_dpid de k8s)
            try:
                raw_dpid = "0000" + hex(int(dpid))[2:].zfill(12)
                self.redis.hdel('topology:node_names', raw_dpid)
                self.redis.hdel('topology:node_ips', raw_dpid)
            except Exception as e:
                self.logger.error("Error formatting dpid for deletion: %s", e)
                
            # Borrar tablas de puertos asociadas al switch fantasma
            self.redis.delete(f"mac_to_port:{dpid}")
            self.redis.delete(f"switch_ports:{dpid}")



    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for p in ev.msg.body:
            port_no = p.port_no
            name = p.name.decode('utf-8')
            self.redis.hset(f"switch_ports:{dpid}", port_no, name)
            self.logger.info("Port registered: DPID %s, Port %s, Name %s", dpid, port_no, name)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        name = msg.desc.name.decode('utf-8')
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        if reason == ofproto.OFPPR_ADD or reason == ofproto.OFPPR_MODIFY:
            self.redis.hset(f"switch_ports:{dpid}", port_no, name)
            self.logger.info("Port status UPDATE: DPID %s, Port %s, Name %s", dpid, port_no, name)
        elif reason == ofproto.OFPPR_DELETE:
            self.redis.hdel(f"switch_ports:{dpid}", port_no)
            self.logger.info("Port status DELETE: DPID %s, Port %s", dpid, port_no)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        dpid = datapath.id
        self.flow_mod_total[dpid] = self.flow_mod_total.get(dpid, 0) + 1

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        # Registrar link bidireccional L2 detectado por LLDP
        link_str = f"{src.dpid}:{src.port_no}-{dst.dpid}:{dst.port_no}"
        self.redis.sadd("topology:links", link_str)
        self.logger.info("LLDP Auto-Discovery: Enlace Agregado %s", link_str)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        link_str = f"{src.dpid}:{src.port_no}-{dst.dpid}:{dst.port_no}"
        self.redis.srem("topology:links", link_str)
        self.logger.info("LLDP Auto-Discovery: Enlace Removido %s", link_str)

    def _get_switch_mac_map(self):
        """Devuelve un dict {mac_hex: dpid} de todos los switches registrados."""
        switches = self.redis.smembers('topology:switches')
        mac_map = {}
        for dpid in switches:
            try:
                # El DPID numérico -> MAC hex del bridge (ej: e65c876d5837)
                mac_hex = hex(int(dpid))[2:].zfill(12)
                mac_fmt = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
                mac_map[mac_fmt] = dpid
            except Exception:
                pass
        return mac_map

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Dejar cruzar los paquetes LLDP hacia el kernel de Topology/Switches
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.packet_in_total[dpid] = self.packet_in_total.get(dpid, 0) + 1

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Externalize State: Learn the mac address to avoid FLOOD next time.
        # Store the mac_to_port table for this dpid in Redis natively (Hash)
        mac_table_key = f"mac_to_port:{dpid}"
        self.redis.hset(mac_table_key, src, in_port)
        
        # MAC Ageing (Auto Limpieza): Marcamos la MAC con un temporizador de vida (TTL) de 25 segundos
        self.redis.set(f"active_mac:{dpid}:{src}", "1", ex=25)

        # ─── TOPOLOGY INFERENCE ───────────────────────────────────────────────
        # Si el src MAC pertenece a otro switch conocido y llega por un puerto
        # inter-nodo (1-10), deducimos que hay un enlace físico y lo guardamos.
        if 1 <= in_port <= 10:
            switch_mac_map = self._get_switch_mac_map()
            if src in switch_mac_map:
                neighbor_dpid = switch_mac_map[src]
                if str(neighbor_dpid) != str(dpid):
                    link_str = f"{dpid}:{in_port}-{neighbor_dpid}:0"
                    self.redis.sadd("topology:links", link_str)
                    self.redis.expire("topology:links", 300)  # TTL 5min para frescura
        # ─────────────────────────────────────────────────────────────────────

        # Retrieve destination port from Redis
        out_port_str = self.redis.hget(mac_table_key, dst)
        
        if out_port_str:
            out_port = int(out_port_str)
            actions = [parser.OFPActionOutput(out_port)]
        else:
            out_port = ofproto.OFPP_FLOOD
            # Inyectar una copia del tráfico Broadcast al stack Linux local (br-sdn)
            # para que los DaemonSets hostNetwork como sdn-dhcp-server puedan leerlo.
            actions = [
                parser.OFPActionOutput(out_port),
                parser.OFPActionOutput(ofproto.OFPP_LOCAL)
            ]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # Distributed Control Logic: Use Redis Locks to prevent two replicas
            # from attempting to write contradictory flow rules for the same 
            # Packet-In event. A lock unique to (dpid, src, dst) ensures safety.
            lock_name = f"lock:flow:{dpid}:{src}:{dst}"
            lock = self.redis.lock(lock_name, timeout=5, blocking_timeout=1)
            
            acquired = lock.acquire()
            if acquired:
                try:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    # Verify if a valid buffer_id is available
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                finally:
                    lock.release()
            else:
                self.logger.info("Flow mod for %s->%s on %s is concurrently handled by another replica", src, dst, dpid)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor_datapaths(self):
        while True:
            for datapath in list(self.datapaths.values()):
                try:
                    parser = datapath.ofproto_parser
                    datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                    datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY))
                except Exception as e:
                    self.logger.warning("Error requesting OpenFlow stats: %s", e)
            hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        # Exclude table-miss when reporting installed forwarding flows.
        self.installed_flows[dpid] = sum(1 for stat in ev.msg.body if stat.priority > 0)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        ports = self.redis.hgetall(f"switch_ports:{dpid}") or {}
        for stat in ev.msg.body:
            if stat.port_no > 0xffffff00:
                continue
            port_name = ports.get(str(stat.port_no), str(stat.port_no))
            self.port_stats[(dpid, stat.port_no)] = {
                "port_name": port_name,
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_bytes": stat.rx_bytes,
                "tx_bytes": stat.tx_bytes,
                "rx_errors": stat.rx_errors,
                "tx_errors": stat.tx_errors,
            }

    def _redis_metric_counts(self):
        counts = {
            "active_switches": 0,
            "active_nodes": 0,
            "learned_macs": {},
        }
        try:
            switches = self.redis.smembers("topology:switches") or set()
            alive_switches = self.redis.keys("switch:alive:*") or []
            counts["active_switches"] = len(alive_switches)
            counts["active_nodes"] = len(alive_switches)
            for dpid in switches:
                counts["learned_macs"][dpid] = self.redis.hlen(f"mac_to_port:{dpid}")
        except Exception as e:
            self.logger.warning("Error reading Redis metrics: %s", e)
        return counts

    def _raw_dpid_to_decimal(self, raw_dpid):
        try:
            return str(int(str(raw_dpid), 16))
        except Exception:
            return str(raw_dpid)

    def _decimal_dpid_to_raw(self, dpid):
        try:
            return "0000" + hex(int(dpid))[2:].zfill(12)
        except Exception:
            return str(dpid)

    def _get_alive_switch_dpids(self):
        alive_keys = self.redis.keys("switch:alive:*") or []
        dpids = set()
        for key in alive_keys:
            raw_dpid = str(key).split("switch:alive:", 1)[-1]
            dpids.add(self._raw_dpid_to_decimal(raw_dpid))
        return dpids

    def _build_topology_snapshot(self):
        dpids = self._get_alive_switch_dpids()
        node_names = self.redis.hgetall("topology:node_names") or {}
        node_ips = self.redis.hgetall("topology:node_ips") or {}
        guest_ips = self.redis.hgetall("topology:guest_ips") or {}
        rstp_ports = self.redis.hgetall("topology:rstp_ports") or {}

        nodes = []
        edges = []
        guests = {}

        ip_to_dpid = {}
        for raw_dpid, ip in node_ips.items():
            ip_to_dpid[str(ip).replace(".", "")] = self._raw_dpid_to_decimal(raw_dpid)

        for dpid in sorted(dpids):
            raw_dpid = self._decimal_dpid_to_raw(dpid)
            name = node_names.get(raw_dpid, "Nodo SDN")
            ip = node_ips.get(raw_dpid, "")
            nodes.append({
                "id": dpid,
                "title": name,
                "subtitle": ip or raw_dpid,
                "mainstat": "switch",
                "color": "#00ffcc" if name == "master" else "#7dd3fc",
                "icon": "server",
                "type": "switch",
            })

            ports = self.redis.hgetall(f"switch_ports:{dpid}") or {}
            mac_table = self.redis.hgetall(f"mac_to_port:{dpid}") or {}

            for port_no, port_name in ports.items():
                if str(port_name).startswith("vx"):
                    target = ip_to_dpid.get(str(port_name)[2:])
                    if target and target in dpids:
                        rstp_status = rstp_ports.get("%s:%s" % (raw_dpid, port_name), "")
                        rstp_state, _, rstp_role = rstp_status.partition(":")
                        is_blocked = rstp_state == "Discarding" and rstp_role != "Disabled"
                        edge_id = "vx:%s:%s:%s" % (dpid, target, port_no)
                        edges.append({
                            "id": edge_id,
                            "source": dpid,
                            "target": target,
                            "mainstat": "RSTP blocked" if is_blocked else "VXLAN",
                            "secondarystat": rstp_status or "RSTP unknown",
                            "color": "#ef4444" if is_blocked else "#64748b",
                            "strokeDasharray": "8 5" if is_blocked else "",
                            "thickness": "4" if is_blocked else "1",
                            "type": "rstp_blocked" if is_blocked else "vxlan",
                        })

            for mac, port_no in mac_table.items():
                if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                    continue
                if not self.redis.exists(f"health:{mac}"):
                    continue

                port_name = ports.get(str(port_no), "")
                if not str(port_name).startswith("ens"):
                    continue

                ip = guest_ips.get(mac, "sin IP")
                if mac not in guests:
                    guests[mac] = {
                        "id": mac,
                        "title": mac,
                        "subtitle": ip,
                        "mainstat": "guest",
                        "color": "#ff00ee",
                        "icon": "desktop",
                        "type": "guest",
                        "switch": dpid,
                    }
                edges.append({
                    "id": "guest:%s:%s" % (dpid, mac),
                    "source": dpid,
                    "target": mac,
                    "mainstat": "local",
                    "secondarystat": "guest",
                    "color": "#ff00ee",
                    "strokeDasharray": "3 3",
                    "thickness": "1",
                    "type": "guest",
                })

        nodes.extend(guests.values())
        return nodes, edges, guests, ip_to_dpid

    def _trace_guest_path(self, src_guest, dst_guest, dpids, ip_to_dpid):
        src_switch = None
        dst_switch = None

        for dpid in dpids:
            mac_table = self.redis.hgetall(f"mac_to_port:{dpid}") or {}
            ports = self.redis.hgetall(f"switch_ports:{dpid}") or {}

            src_port = mac_table.get(src_guest)
            if src_port and not str(ports.get(str(src_port), "")).startswith("vx"):
                src_switch = dpid

            dst_port = mac_table.get(dst_guest)
            if dst_port and not str(ports.get(str(dst_port), "")).startswith("vx"):
                dst_switch = dpid

        if not src_switch or not dst_switch:
            return []

        path_edges = [("guest:%s:%s" % (src_switch, src_guest), src_guest, src_switch)]
        visited = set()
        curr_switch = src_switch

        while curr_switch != dst_switch:
            if curr_switch in visited:
                break
            visited.add(curr_switch)

            out_port = self.redis.hget(f"mac_to_port:{curr_switch}", dst_guest)
            if not out_port:
                break

            port_name = self.redis.hget(f"switch_ports:{curr_switch}", out_port) or ""
            if not str(port_name).startswith("vx"):
                break

            next_switch = ip_to_dpid.get(str(port_name)[2:])
            if not next_switch:
                break

            path_edges.append(("path:%s:%s:%s" % (curr_switch, next_switch, out_port), curr_switch, next_switch))
            curr_switch = next_switch

        if curr_switch == dst_switch:
            path_edges.append(("guest:%s:%s" % (dst_switch, dst_guest), dst_switch, dst_guest))
            return path_edges
        return []

    def _append_topology_metrics(self, lines):
        nodes, edges, guests, ip_to_dpid = self._build_topology_snapshot()
        dpids = {node["id"] for node in nodes if node["type"] == "switch"}

        lines.extend([
            "# HELP ryu_topology_node_info SDN topology nodes for Grafana node graph.",
            "# TYPE ryu_topology_node_info gauge",
        ])
        for node in nodes:
            labels = (
                'id="%s",title="%s",subtitle="%s",mainstat="%s",color="%s",icon="%s",type="%s"'
                % (
                    _escape_label(node["id"]),
                    _escape_label(node["title"]),
                    _escape_label(node["subtitle"]),
                    _escape_label(node["mainstat"]),
                    _escape_label(node["color"]),
                    _escape_label(node["icon"]),
                    _escape_label(node["type"]),
                )
            )
            lines.append("ryu_topology_node_info{%s} 1" % labels)

        lines.extend([
            "# HELP ryu_topology_edge_info SDN topology edges for Grafana node graph.",
            "# TYPE ryu_topology_edge_info gauge",
        ])
        for edge in edges:
            labels = (
                'id="%s",source="%s",target="%s",mainstat="%s",secondarystat="%s",color="%s",strokeDasharray="%s",thickness="%s",type="%s"'
                % (
                    _escape_label(edge["id"]),
                    _escape_label(edge["source"]),
                    _escape_label(edge["target"]),
                    _escape_label(edge["mainstat"]),
                    _escape_label(edge.get("secondarystat", "")),
                    _escape_label(edge["color"]),
                    _escape_label(edge.get("strokeDasharray", "")),
                    _escape_label(edge.get("thickness", "1")),
                    _escape_label(edge["type"]),
                )
            )
            lines.append("ryu_topology_edge_info{%s} 1" % labels)

        lines.extend([
            "# HELP ryu_trace_path_edge_info Highlighted guest-to-guest path edges for Grafana node graph.",
            "# TYPE ryu_trace_path_edge_info gauge",
        ])
        guest_ids = sorted(guests.keys())
        for src_guest in guest_ids:
            for dst_guest in guest_ids:
                if src_guest == dst_guest:
                    continue
                for edge_id, source, target in self._trace_guest_path(src_guest, dst_guest, dpids, ip_to_dpid):
                    labels = (
                        'src_guest="%s",dst_guest="%s",id="%s",source="%s",target="%s",mainstat="%s",secondarystat="%s",color="%s",strokeDasharray="%s",thickness="%s",type="%s"'
                        % (
                            _escape_label(src_guest),
                            _escape_label(dst_guest),
                            _escape_label(edge_id),
                            _escape_label(source),
                            _escape_label(target),
                            "path",
                            "",
                            "#facc15",
                            "",
                            "5",
                            "path",
                        )
                    )
                    lines.append("ryu_trace_path_edge_info{%s} 1" % labels)

    def _render_prometheus_metrics(self):
        redis_counts = self._redis_metric_counts()
        lines = [
            "# HELP ryu_packet_in_total Total Packet-In messages processed by Ryu.",
            "# TYPE ryu_packet_in_total counter",
        ]
        for dpid, value in sorted(self.packet_in_total.items()):
            lines.append('ryu_packet_in_total{dpid="%s"} %s' % (_escape_label(dpid), value))

        lines.extend([
            "# HELP ryu_flow_mod_total Total FlowMod messages sent by Ryu.",
            "# TYPE ryu_flow_mod_total counter",
        ])
        for dpid, value in sorted(self.flow_mod_total.items()):
            lines.append('ryu_flow_mod_total{dpid="%s"} %s' % (_escape_label(dpid), value))

        lines.extend([
            "# HELP ryu_installed_flows Current installed forwarding flows per switch.",
            "# TYPE ryu_installed_flows gauge",
        ])
        for dpid, value in sorted(self.installed_flows.items()):
            lines.append('ryu_installed_flows{dpid="%s"} %s' % (_escape_label(dpid), value))

        lines.extend([
            "# HELP ryu_active_switches Switches currently registered in Redis topology.",
            "# TYPE ryu_active_switches gauge",
            "ryu_active_switches %s" % redis_counts["active_switches"],
            "# HELP ryu_active_nodes Nodes currently registered in Redis topology.",
            "# TYPE ryu_active_nodes gauge",
            "ryu_active_nodes %s" % redis_counts["active_nodes"],
            "# HELP ryu_learned_macs Current learned MAC addresses per switch.",
            "# TYPE ryu_learned_macs gauge",
        ])
        for dpid, value in sorted(redis_counts["learned_macs"].items()):
            lines.append('ryu_learned_macs{dpid="%s"} %s' % (_escape_label(dpid), value))

        lines.extend([
            "# HELP ryu_port_rx_bytes_total OpenFlow port received bytes.",
            "# TYPE ryu_port_rx_bytes_total counter",
        ])
        for (dpid, port_no), stats in sorted(self.port_stats.items()):
            labels = 'dpid="%s",port_no="%s",port_name="%s"' % (
                _escape_label(dpid), _escape_label(port_no), _escape_label(stats["port_name"]))
            lines.append("ryu_port_rx_bytes_total{%s} %s" % (labels, stats["rx_bytes"]))

        lines.extend([
            "# HELP ryu_port_tx_bytes_total OpenFlow port transmitted bytes.",
            "# TYPE ryu_port_tx_bytes_total counter",
        ])
        for (dpid, port_no), stats in sorted(self.port_stats.items()):
            labels = 'dpid="%s",port_no="%s",port_name="%s"' % (
                _escape_label(dpid), _escape_label(port_no), _escape_label(stats["port_name"]))
            lines.append("ryu_port_tx_bytes_total{%s} %s" % (labels, stats["tx_bytes"]))

        lines.extend([
            "# HELP ryu_process_start_time_seconds Unix timestamp when this Ryu process started.",
            "# TYPE ryu_process_start_time_seconds gauge",
            "ryu_process_start_time_seconds %s" % self.metrics_started_at,
        ])
        self._append_topology_metrics(lines)
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _metrics_wsgi_app(self, env, start_response):
        if env.get("PATH_INFO") != "/metrics":
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"not found\n"]
        body = self._render_prometheus_metrics()
        start_response("200 OK", [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")])
        return [body]

    def _start_metrics_server(self):
        try:
            listener = eventlet.listen(("0.0.0.0", METRICS_PORT))
            self.logger.info("Prometheus metrics endpoint listening on 0.0.0.0:%d/metrics", METRICS_PORT)
            eventlet.wsgi.server(listener, self._metrics_wsgi_app, log_output=False)
        except Exception as e:
            self.logger.error("Unable to start metrics endpoint: %s", e)
