import os
import eventlet
import redis
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import datapath_connection_factory
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from ryu.topology import event
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types

from ryu.topology import event, switches

METRICS_PORT = int(os.environ.get("METRICS_PORT", 8000))
SECURITY_LEARNING_MODE = os.environ.get("SECURITY_LEARNING_MODE", "false").lower() == "true"


def _escape_label(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _edge_link_id(source, target):
    return "%s--%s" % tuple(sorted([str(source), str(target)]))


def _mac_from_dpid(dpid):
    try:
        hex_dpid = hex(int(str(dpid)))[2:].zfill(12)[-12:]
        return ":".join(hex_dpid[i:i + 2] for i in range(0, 12, 2)).lower()
    except Exception:
        return ""


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
        self.security_sync_thread = hub.spawn(self._sync_quarantine_flows)

    def start(self):
        super(DistributedL2Switch, self).start()
        self.openflow_controller_thread = hub.spawn(self._start_openflow_controller)
        self.threads.append(self.openflow_controller_thread)

    def _start_openflow_controller(self):
        try:
            self.logger.info("Starting OpenFlow controller listener from app.py")
            server = StreamServer(('0.0.0.0', 6653), datapath_connection_factory)
            server.serve_forever()
        except Exception as e:
            self.logger.warning("OpenFlow controller listener was not started by app.py: %s", e)

    def _known_worker_macs(self):
        worker_macs = set()
        for known_dpid in self.redis.smembers("topology:switches") or []:
            worker_mac = _mac_from_dpid(known_dpid)
            if worker_mac:
                worker_macs.add(worker_mac)
        for raw_dpid in self.redis.hkeys("topology:node_names") or []:
            if len(raw_dpid) >= 12:
                raw_mac = raw_dpid[-12:]
                worker_macs.add(":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower())
        return worker_macs

    def _get_security_device_by_mac(self, mac):
        import json

        device_id = self.redis.get(f"security:mac_to_device:{mac}")
        if not device_id:
            return None
        payload = self.redis.get(f"security:device:{device_id}")
        return json.loads(payload) if payload else None

    def _record_security_event(self, threat_type, mac, ip, dpid, in_port, reason, action):
        import uuid
        import time
        import json
        event_id = str(uuid.uuid4())
        timestamp = int(time.time())
        
        event_data = {
            "id": event_id,
            "type": threat_type,
            "mac": mac,
            "ip": ip,
            "dpid": dpid,
            "in_port": in_port,
            "reason": reason,
            "action": action,
            "timestamp": timestamp
        }
        
        self.redis.setex(f"security:event:{timestamp}:{event_id}", 86400 * 7, json.dumps(event_data))
        self.redis.incr("security:events_total")
        self.redis.incr(f"security:events:{threat_type}")
        
        if action in ["quarantine", "suspicious"]:
            device_id = self.redis.get(f"security:mac_to_device:{mac}")
            if device_id:
                payload = self.redis.get(f"security:device:{device_id}")
                if payload:
                    dev = json.loads(payload)
                    dev["status"] = action
                    self.redis.set(f"security:device:{device_id}", json.dumps(dev))

    def _evaluate_security_threats(self, eth, ip_pkt, arp_pkt, udp_pkt, dpid, in_port, in_port_name=""):
        mac = str(eth.src).lower()
        if mac in self._known_worker_macs():
            return True, None, None

        device = self._get_security_device_by_mac(mac)
        
        if not device:
            if udp_pkt and udp_pkt.dst_port == 5555:
                return False, "MAC_SPOOFING", "unregistered_mac_telemetry"
        else:
            if device.get("status") not in ["authorized", "learning"]:
                return False, "MAC_SPOOFING", f"status_{device.get('status')}"
                
            is_tunnel = in_port_name.startswith("vx") or in_port_name in ["br-sdn", "br0"]
            if not is_tunnel:
                if device.get("dpid") and device.get("dpid") != str(dpid):
                    return False, "MAC_SPOOFING", "dpid_mismatch"
                if device.get("in_port") and device.get("in_port") != str(in_port):
                    return False, "MAC_SPOOFING", "port_mismatch"
        
        if ip_pkt:
            src_ip = ip_pkt.src
            if not (udp_pkt and udp_pkt.src_port == 68 and udp_pkt.dst_port == 67):
                if device and device.get("ip") and device.get("ip") != src_ip:
                    return False, "IP_SPOOFING", "ip_mismatch"
                
                owner_id = self.redis.get(f"security:ip_to_device:{src_ip}")
                if owner_id and device and owner_id != device.get("device_id"):
                    return False, "IP_SPOOFING", "ip_in_use_by_other_device"
                
                if src_ip == "10.0.0.1":
                    return False, "IP_SPOOFING", "reserved_ip_used"

        if arp_pkt:
            if arp_pkt.src_ip == "10.0.0.1":
                return False, "ARP_POISONING", "unauthorized_gateway_claim"
                
            if arp_pkt.src_mac.lower() != mac:
                return False, "ARP_POISONING", "arp_mac_mismatch"
                
            if device and device.get("ip") and arp_pkt.src_ip != device.get("ip"):
                return False, "ARP_POISONING", "arp_ip_mismatch"
                
        return True, None, None

    def _drop_guest_packet(self, datapath, in_port, src, eth_type=None, reason="security", install_flow=False):
        if install_flow:
            parser = datapath.ofproto_parser
            match_fields = {"in_port": in_port, "eth_src": src}
            if eth_type is not None:
                match_fields["eth_type"] = eth_type
            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 100, match, [], None)
        self.logger.warning("Security drop installed: dpid=%s in_port=%s mac=%s eth_type=%s reason=%s", datapath.id, in_port, src, eth_type or "any", reason)

    def _sync_quarantine_flows(self):
        while True:
            try:
                for device_id in self.redis.smembers("security:devices") or []:
                    payload = self.redis.get(f"security:device:{device_id}")
                    if not payload:
                        continue
                    import json
                    device = json.loads(payload)
                    if device.get("status") not in ("quarantine", "quarantined", "blocked"):
                        continue
                    try:
                        dpid = int(device.get("dpid"))
                        in_port = int(device.get("in_port"))
                    except (TypeError, ValueError):
                        continue
                    datapath = self.datapaths.get(dpid)
                    mac = str(device.get("mac", "")).lower()
                    if not datapath or not mac:
                        continue
                    self._drop_guest_packet(datapath, in_port, mac, reason="status_%s" % device.get("status"), install_flow=True)
            except Exception as e:
                self.logger.warning("Error syncing quarantine flows: %s", e)
            hub.sleep(5)

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
            self.logger.debug("Port registered: DPID %s, Port %s, Name %s", dpid, port_no, name)

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
        timeouts = {}
        if priority > 0:
            timeouts = {"idle_timeout": 120, "hard_timeout": 0}

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, **timeouts)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, **timeouts)
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

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Externalize State: Learn the mac address to avoid FLOOD next time.
        # Store the mac_to_port table for this dpid in Redis natively (Hash)
        mac_table_key = f"mac_to_port:{dpid}"
        self.redis.hset(mac_table_key, src, in_port)
        
        # MAC Ageing (Auto Limpieza): mantener el mapa sensible a cambios STP.
        self.redis.set(f"active_mac:{dpid}:{src}", "1", ex=180)

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
        
        known_worker_macs = self._known_worker_macs()
        ports = self.redis.hgetall(f"switch_ports:{dpid}") or {}
        in_port_name = str(ports.get(str(in_port), ""))
        if (
            src not in known_worker_macs and
            in_port != ofproto.OFPP_LOCAL and
            not in_port_name.startswith("vx") and
            in_port_name != "br-sdn"
        ):
            self.redis.hset("topology:guest_locations", src, f"{dpid}:{in_port}")

        udp_pkt = pkt.get_protocol(udp.udp)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        allowed, threat_type, reason = self._evaluate_security_threats(eth, ip_pkt, arp_pkt, udp_pkt, dpid, in_port, in_port_name)
        if not allowed:
            action = "log_only" if SECURITY_LEARNING_MODE else "quarantine"
            
            src_ip = ip_pkt.src if ip_pkt else (arp_pkt.src_ip if arp_pkt else "")
            self.logger.warning("%s_DETECTED: dpid=%s in_port=%s mac=%s ip=%s reason=%s action=%s", 
                                threat_type, dpid, in_port, src, src_ip, reason, action)
            
            self._record_security_event(threat_type, src, src_ip, dpid, in_port, reason, action)
            
            if not SECURITY_LEARNING_MODE:
                self._drop_guest_packet(datapath, in_port, src, reason=reason, install_flow=True)
                return

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == "10.0.0.1":
            raw_dpid = self._decimal_dpid_to_raw(dpid)
            gateway_mac = ":".join(raw_dpid[-12:][i:i + 2] for i in range(0, 12, 2))
            reply = packet.Packet()
            reply.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst=src,
                src=gateway_mac,
            ))
            reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=gateway_mac,
                src_ip="10.0.0.1",
                dst_mac=src,
                dst_ip=arp_pkt.src_ip,
            ))
            reply.serialize()
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(in_port)],
                data=reply.data,
            )
            datapath.send_msg(out)
            return

        if ip_pkt and ip_pkt.dst == "10.0.0.1":
            out_port = ofproto.OFPP_LOCAL
            actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        elif out_port_str:
            out_port = int(out_port_str)
            actions = [parser.OFPActionOutput(out_port)]
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = []
            for port_no, port_name in ports.items():
                try:
                    port_no_int = int(port_no)
                except Exception:
                    continue
                if port_no_int == in_port or port_no_int == ofproto.OFPP_LOCAL:
                    continue
                port_name = str(port_name)
                if in_port_name.startswith("vx") and port_name.startswith("vx"):
                    continue
                actions.append(parser.OFPActionOutput(port_no_int))

            # Inyectar una copia del trafico broadcast al stack Linux local
            # para que servicios hostNetwork como DHCP puedan leerlo.
            if in_port != ofproto.OFPP_LOCAL:
                actions.append(parser.OFPActionOutput(ofproto.OFPP_LOCAL))

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
                    datapath.send_msg(parser.OFPPortDescStatsRequest(datapath, 0))
                    datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                    datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY))
                except Exception as e:
                    self.logger.warning("Error requesting OpenFlow stats: %s", e)
            hub.sleep(30)

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

    def _get_blocked_br0_links(self, ip_to_dpid, dpids):
        br0_stp_ports = self.redis.hgetall("topology:br0_stp_ports") or {}
        blocked_links = set()
        for key, status in br0_stp_ports.items():
            if ":" not in key:
                continue
            raw_dpid, _ = key.split(":", 1)
            local_dpid = self._raw_dpid_to_decimal(raw_dpid)
            state, _, remote_ip = str(status).partition(":")
            remote_dpid = ip_to_dpid.get(remote_ip.replace(".", ""))
            if not remote_dpid or local_dpid not in dpids or remote_dpid not in dpids:
                continue
            if state != "forwarding":
                blocked_links.add(_edge_link_id(local_dpid, remote_dpid))
        return blocked_links

    def _is_recent_guest(self, mac, dpid):
        return (
            self.redis.exists(f"active_mac:{dpid}:{mac}") or
            self.redis.exists(f"health:{mac}") or
            mac in (self.redis.hgetall("topology:guest_ips") or {})
        )

    def _add_guest_node_edge(self, guests, edges, mac, dpid, port_no, guest_ips):
        ports = self.redis.hgetall(f"switch_ports:{dpid}") or {}
        port_name = ports.get(str(port_no), "")
        if str(port_name).startswith("vx") or str(port_no) == "4294967294" or str(port_name) == "br-sdn":
            return False
        if not self._is_recent_guest(mac, dpid):
            return False

        guests[mac] = {
            "id": mac,
            "title": mac,
            "subtitle": guest_ips.get(mac, "DHCP pendiente"),
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
        return True

    def _build_topology_snapshot(self):
        dpids = self._get_alive_switch_dpids()
        node_names = self.redis.hgetall("topology:node_names") or {}
        node_ips = self.redis.hgetall("topology:node_ips") or {}
        guest_ips = self.redis.hgetall("topology:guest_ips") or {}
        guest_locations = self.redis.hgetall("topology:guest_locations") or {}
        br0_stp_ports = self.redis.hgetall("topology:br0_stp_ports") or {}

        nodes = []
        edges = []
        vxlan_edges = {}
        br0_edges = {}
        guests = {}

        ip_to_dpid = {}
        for raw_dpid, ip in node_ips.items():
            ip_to_dpid[str(ip).replace(".", "")] = self._raw_dpid_to_decimal(raw_dpid)
        blocked_br0_links = self._get_blocked_br0_links(ip_to_dpid, dpids)

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
                        if _edge_link_id(dpid, target) in blocked_br0_links:
                            continue
                        source, dest = sorted([str(dpid), str(target)])
                        edge_id = "vx:%s:%s" % (source, dest)
                        edge = vxlan_edges.setdefault(edge_id, {
                            "id": edge_id,
                            "source": source,
                            "target": dest,
                            "mainstat": "VXLAN",
                            "secondarystat": "SDN tunnel",
                            "color": "#64748b",
                            "strokeDasharray": "",
                            "thickness": "1",
                            "type": "vxlan",
                            "details": [],
                        })
                        edge["details"].append("%s:%s=active" % (dpid, port_name))

            for mac, port_no in mac_table.items():
                if mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff":
                    continue
                if mac in guest_locations:
                    continue

                port_name = ports.get(str(port_no), "")
                is_known_guest = mac in guest_ips
                is_local_guest_port = str(port_name).startswith("ens")
                is_non_tunnel_port = (
                    is_known_guest and
                    str(port_no) != "4294967294" and
                    not str(port_name).startswith("vx") and
                    str(port_name) != "br-sdn"
                )
                if not is_local_guest_port and not is_non_tunnel_port:
                    continue

        worker_macs = self._known_worker_macs()
        for mac, location in guest_locations.items():
            if mac in worker_macs:
                continue
            if mac in guests:
                continue
            location_dpid, _, port_no = str(location).partition(":")
            if not location_dpid or not port_no or location_dpid not in dpids:
                continue
            self._add_guest_node_edge(guests, edges, mac, location_dpid, port_no, guest_ips)

        import json
        for device_id in self.redis.smembers("security:devices") or []:
            payload = self.redis.get(f"security:device:{device_id}")
            if not payload:
                continue
            try:
                device = json.loads(payload)
            except Exception:
                continue
            mac = str(device.get("mac", "")).lower()
            dpid = str(device.get("dpid", ""))
            port_no = str(device.get("in_port", ""))
            if not mac or mac in worker_macs or mac in guests:
                continue
            if not dpid or not port_no or dpid not in dpids:
                continue
            if self._add_guest_node_edge(guests, edges, mac, dpid, port_no, {mac: device.get("ip", "") or "DHCP pendiente"}):
                if device.get("status") not in ("authorized", "learning"):
                    guests[mac]["color"] = "#f97316"
                    guests[mac]["mainstat"] = device.get("status", "restricted")

        for edge in vxlan_edges.values():
            if edge["details"]:
                edge["secondarystat"] = " | ".join(sorted(edge["details"]))
            edge.pop("details", None)
            edges.append(edge)

        for key, status in br0_stp_ports.items():
            if ":" not in key:
                continue
            raw_dpid, intf = key.split(":", 1)
            local_dpid = self._raw_dpid_to_decimal(raw_dpid)
            state, _, remote_ip = str(status).partition(":")
            remote_dpid = ip_to_dpid.get(remote_ip.replace(".", ""))
            if not remote_dpid or local_dpid not in dpids or remote_dpid not in dpids:
                continue

            source, dest = sorted([str(local_dpid), str(remote_dpid)])
            edge_id = "br0:%s:%s" % (source, dest)
            edge = br0_edges.setdefault(edge_id, {
                "id": edge_id,
                "source": source,
                "target": dest,
                "mainstat": "br0 STP",
                "secondarystat": "physical forwarding",
                "color": "#94a3b8",
                "strokeDasharray": "",
                "thickness": "1",
                "type": "br0_stp",
                "details": [],
            })
            edge["details"].append("%s:%s=%s" % (local_dpid, intf, state))
            if state == "blocking":
                edge.update({
                    "mainstat": "br0 STP blocked",
                    "color": "#ef4444",
                    "strokeDasharray": "",
                    "thickness": "6",
                    "type": "br0_stp_blocked",
                })

        for edge in br0_edges.values():
            if edge["details"]:
                edge["secondarystat"] = " | ".join(sorted(edge["details"]))
            edge.pop("details", None)
            link = _edge_link_id(edge["source"], edge["target"])
            if edge["type"] == "br0_stp_blocked":
                # Reemplazar VXLAN si existe para el mismo par — STP bloqueado tiene prioridad visual
                edges = [existing for existing in edges if _edge_link_id(existing["source"], existing["target"]) != link]
                edges.append(edge)

        nodes.extend(guests.values())
        return nodes, edges, guests, ip_to_dpid

    def _trace_guest_path(self, src_guest, dst_guest, dpids, ip_to_dpid):
        src_switch = None
        dst_switch = None
        switch_ports = {}
        mac_tables = {}
        guest_locations = self.redis.hgetall("topology:guest_locations") or {}
        blocked_br0_links = self._get_blocked_br0_links(ip_to_dpid, dpids)

        for dpid in dpids:
            mac_table = self.redis.hgetall(f"mac_to_port:{dpid}") or {}
            ports = self.redis.hgetall(f"switch_ports:{dpid}") or {}
            mac_tables[dpid] = mac_table
            switch_ports[dpid] = ports

            src_port = mac_table.get(src_guest)
            if src_port and not str(ports.get(str(src_port), "")).startswith("vx"):
                src_switch = dpid

            dst_port = mac_table.get(dst_guest)
            if dst_port and not str(ports.get(str(dst_port), "")).startswith("vx"):
                dst_switch = dpid

        if not src_switch:
            src_switch = str(guest_locations.get(src_guest, "")).split(":", 1)[0] or None
        if not dst_switch:
            dst_switch = str(guest_locations.get(dst_guest, "")).split(":", 1)[0] or None
        if src_switch not in dpids or dst_switch not in dpids:
            return []

        if not src_switch or not dst_switch:
            return []

        path_edges = [("path:%s" % _edge_link_id(src_guest, src_switch), src_guest, src_switch)]
        visited = set()
        curr_switch = src_switch

        while curr_switch != dst_switch:
            if curr_switch in visited:
                break
            visited.add(curr_switch)

            out_port = mac_tables.get(curr_switch, {}).get(dst_guest)
            if not out_port:
                break

            port_name = switch_ports.get(curr_switch, {}).get(str(out_port), "")
            if not str(port_name).startswith("vx"):
                break

            next_switch = ip_to_dpid.get(str(port_name)[2:])
            if not next_switch:
                break
            if _edge_link_id(curr_switch, next_switch) in blocked_br0_links:
                break

            path_edges.append(("path:%s" % _edge_link_id(curr_switch, next_switch), curr_switch, next_switch))
            curr_switch = next_switch

        if curr_switch == dst_switch:
            path_edges.append(("path:%s" % _edge_link_id(dst_switch, dst_guest), dst_switch, dst_guest))
            return path_edges

        adjacency = {str(dpid): set() for dpid in dpids}
        for dpid, ports in switch_ports.items():
            for port_name in ports.values():
                if not str(port_name).startswith("vx"):
                    continue
                target = ip_to_dpid.get(str(port_name)[2:])
                if target and target in dpids:
                    if _edge_link_id(dpid, target) in blocked_br0_links:
                        continue
                    adjacency[str(dpid)].add(str(target))
                    adjacency[str(target)].add(str(dpid))

        queue = [(str(src_switch), [str(src_switch)])]
        visited = {str(src_switch)}
        while queue:
            curr_switch, path = queue.pop(0)
            if curr_switch == str(dst_switch):
                graph_edges = [("path:%s" % _edge_link_id(src_guest, src_switch), src_guest, src_switch)]
                for source, target in zip(path, path[1:]):
                    graph_edges.append(("path:%s" % _edge_link_id(source, target), source, target))
                graph_edges.append(("path:%s" % _edge_link_id(dst_switch, dst_guest), dst_switch, dst_guest))
                return graph_edges

            for next_switch in sorted(adjacency.get(curr_switch, [])):
                if next_switch in visited:
                    continue
                visited.add(next_switch)
                queue.append((next_switch, path + [next_switch]))
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
                'id="%s",source="%s",target="%s",link="%s",mainstat="%s",secondarystat="%s",color="%s",strokeDasharray="%s",thickness="%s",type="%s"'
                % (
                    _escape_label(edge["id"]),
                    _escape_label(edge["source"]),
                    _escape_label(edge["target"]),
                    _escape_label(_edge_link_id(edge["source"], edge["target"])),
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
                        'src_guest="%s",dst_guest="%s",id="%s",source="%s",target="%s",link="%s",mainstat="%s",secondarystat="%s",color="%s",strokeDasharray="%s",thickness="%s",type="%s"'
                        % (
                            _escape_label(src_guest),
                            _escape_label(dst_guest),
                            _escape_label(edge_id),
                            _escape_label(source),
                            _escape_label(target),
                            _escape_label(_edge_link_id(source, target)),
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
        security_total = self.redis.get("security:events_total") or 0
        mac_spoofing = self.redis.get("security:events:MAC_SPOOFING") or 0
        ip_spoofing = self.redis.get("security:events:IP_SPOOFING") or 0
        arp_poisoning = self.redis.get("security:events:ARP_POISONING") or 0

        lines = [
            "# HELP ryu_security_events_total Total security events detected.",
            "# TYPE ryu_security_events_total counter",
            "ryu_security_events_total %s" % security_total,
            "# HELP ryu_security_events_by_type Security events by type.",
            "# TYPE ryu_security_events_by_type counter",
            'ryu_security_events_by_type{type="MAC_SPOOFING"} %s' % mac_spoofing,
            'ryu_security_events_by_type{type="IP_SPOOFING"} %s' % ip_spoofing,
            'ryu_security_events_by_type{type="ARP_POISONING"} %s' % arp_poisoning,
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
