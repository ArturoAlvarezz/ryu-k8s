import os
import eventlet
import redis
import time
from datetime import datetime, timezone
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
NODE_NAME = os.environ.get("NODE_NAME", "")
METRICS_EXPORTER_NODE = os.environ.get("METRICS_EXPORTER_NODE", "master")
METRICS_CACHE_SECONDS = float(os.environ.get("METRICS_CACHE_SECONDS", 30))
RYU_CACHE_NODE_IPS_SECONDS = float(os.environ.get("RYU_CACHE_NODE_IPS_SECONDS", 5))
RYU_CACHE_SWITCH_PORTS_SECONDS = float(os.environ.get("RYU_CACHE_SWITCH_PORTS_SECONDS", 5))
RYU_CACHE_WORKER_MACS_SECONDS = float(os.environ.get("RYU_CACHE_WORKER_MACS_SECONDS", 10))
RYU_CACHE_LIVENESS_SECONDS = float(os.environ.get("RYU_CACHE_LIVENESS_SECONDS", 2))
RYU_CACHE_BR0_STP_SECONDS = float(os.environ.get("RYU_CACHE_BR0_STP_SECONDS", 5))
RYU_CACHE_SECURITY_SECONDS = float(os.environ.get("RYU_CACHE_SECURITY_SECONDS", 5))
RYU_CACHE_PATH_SECONDS = float(os.environ.get("RYU_CACHE_PATH_SECONDS", 5))
ACTIVE_METER_MAX_AGE_SECONDS = int(os.environ.get("ACTIVE_METER_MAX_AGE_SECONDS", 30))
MONITOR_INTERVAL_SECONDS = float(os.environ.get("MONITOR_INTERVAL_SECONDS", 5))
FORWARDING_FLOW_IDLE_TIMEOUT = int(os.environ.get("FORWARDING_FLOW_IDLE_TIMEOUT", 120))
VXLAN_REQUIRES_FORWARDING_BR0_EDGE = os.environ.get("VXLAN_REQUIRES_FORWARDING_BR0_EDGE", "true").lower() == "true"
SECURITY_LEARNING_MODE = os.environ.get("SECURITY_LEARNING_MODE", "false").lower() == "true"
MGMT_SWITCH_ID = "mgmt-stp-switch"


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


class RedisMetricsProxy:
    def __init__(self, client, recorder):
        self._client = client
        self._recorder = recorder

    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        def wrapped(*args, **kwargs):
            start = time.time()
            status = "ok"
            try:
                return attr(*args, **kwargs)
            except Exception:
                status = "error"
                raise
            finally:
                self._recorder(name, status, time.time() - start)

        return wrapped


class DistributedL2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(DistributedL2Switch, self).__init__(*args, **kwargs)
        
        # Redis connection setup (Sentinel HA)
        from redis.sentinel import Sentinel
        sentinel_host = os.environ.get('REDIS_SENTINEL_HOST', 'redis-sentinel.sdn-controller.svc.cluster.local')
        sentinel_port = int(os.environ.get('REDIS_SENTINEL_PORT', 26379))
        redis_timeout = float(os.environ.get('REDIS_SOCKET_TIMEOUT', '5.0'))
        self.sentinel = Sentinel(
            [(sentinel_host, sentinel_port)],
            socket_timeout=redis_timeout,
            socket_connect_timeout=redis_timeout,
        )
        redis_client = self.sentinel.master_for(
            'mymaster',
            socket_timeout=redis_timeout,
            socket_connect_timeout=redis_timeout,
            decode_responses=True,
        )
        self.redis_metrics = {}
        self.cache = {}
        self.metrics_cache_body = None
        self.metrics_cache_until = 0.0
        self.redis = RedisMetricsProxy(redis_client, self._record_redis_metric)
        self.logger.info("Connected to Redis Sentinel at %s:%d", sentinel_host, sentinel_port)
        self.datapaths = {}
        self.packet_in_total = {}
        self.flow_mod_total = {}
        self.installed_flows = {}
        self.port_stats = {}
        self.security_flow_state = {}
        self.metrics_started_at = datetime.utcnow().timestamp()
        self.monitor_thread = hub.spawn(self._monitor_datapaths)
        self.metrics_thread = hub.spawn(self._start_metrics_server)
        self.security_sync_thread = hub.spawn(self._sync_quarantine_flows)

    def _record_redis_metric(self, operation, status, duration):
        key = (str(operation), str(status))
        metric = self.redis_metrics.setdefault(key, {"count": 0, "seconds": 0.0, "max": 0.0})
        metric["count"] += 1
        metric["seconds"] += duration
        if duration > metric["max"]:
            metric["max"] = duration

    def _is_metrics_exporter(self):
        return not METRICS_EXPORTER_NODE or NODE_NAME == METRICS_EXPORTER_NODE

    def _cached(self, key, ttl, loader):
        now = time.time()
        cached = self.cache.get(key)
        if cached and cached[0] > now:
            return cached[1]
        value = loader()
        self.cache[key] = (now + ttl, value)
        return value

    def _cache_delete_prefix(self, prefix):
        for key in list(self.cache.keys()):
            if str(key).startswith(prefix):
                self.cache.pop(key, None)

    def _get_node_ips(self):
        return self._cached(
            "topology:node_ips",
            RYU_CACHE_NODE_IPS_SECONDS,
            lambda: self.redis.hgetall("topology:node_ips") or {},
        )

    def _get_switch_ports(self, dpid):
        return self._cached(
            f"switch_ports:{dpid}",
            RYU_CACHE_SWITCH_PORTS_SECONDS,
            lambda: self.redis.hgetall(f"switch_ports:{dpid}") or {},
        )

    def _get_br0_stp_ports(self):
        return self._cached(
            "topology:br0_stp_ports",
            RYU_CACHE_BR0_STP_SECONDS,
            lambda: self.redis.hgetall("topology:br0_stp_ports") or {},
        )

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
        def load_worker_macs():
            worker_macs = set()
            try:
                for known_dpid in self.redis.smembers("topology:switches") or []:
                    worker_mac = _mac_from_dpid(known_dpid)
                    if worker_mac:
                        worker_macs.add(worker_mac)
                for raw_dpid in self.redis.hkeys("topology:node_names") or []:
                    if len(raw_dpid) >= 12:
                        raw_mac = raw_dpid[-12:]
                        worker_macs.add(":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower())
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while reading worker MACs: %s", e)
            return worker_macs
        return self._cached("known_worker_macs", RYU_CACHE_WORKER_MACS_SECONDS, load_worker_macs)

    def _get_security_device_by_mac(self, mac):
        import json

        mac = str(mac).lower()
        def load_device():
            try:
                device_id = self.redis.get(f"security:mac_to_device:{mac}")
                if not device_id:
                    return None
                payload = self.redis.get(f"security:device:{device_id}")
                return json.loads(payload) if payload else None
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while reading security device: %s", e)
                return None
        return self._cached(f"security:device_by_mac:{mac}", RYU_CACHE_SECURITY_SECONDS, load_device)

    def _get_security_device_id_by_ip(self, ip_addr):
        ip_addr = str(ip_addr).strip()
        if not ip_addr:
            return None
        def load_owner():
            try:
                return self.redis.get(f"security:ip_to_device:{ip_addr}")
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while checking IP ownership: %s", e)
                return None
        return self._cached(f"security:ip_to_device:{ip_addr}", RYU_CACHE_SECURITY_SECONDS, load_owner)

    def _refresh_security_device_location(self, device, dpid, in_port):
        current_dpid = str(dpid)
        current_port = str(in_port)
        if device.get("dpid") == current_dpid and device.get("in_port") == current_port:
            return

        import json
        device["dpid"] = current_dpid
        device["in_port"] = current_port
        try:
            self.redis.set(f"security:device:{device['device_id']}", json.dumps(device, sort_keys=True))
            self._cache_delete_prefix(f"security:device_by_mac:{str(device.get('mac', '')).lower()}")
            self._cache_delete_prefix(f"security:ip_to_device:{str(device.get('ip', '')).strip()}")
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while updating security device location: %s", e)
            return
        self.logger.info(
            "Security device location refreshed: device=%s mac=%s dpid=%s in_port=%s",
            device.get("device_id"), device.get("mac"), current_dpid, current_port,
        )

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

        try:
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
                        self._cache_delete_prefix(f"security:device_by_mac:{str(dev.get('mac', mac)).lower()}")
                        self._cache_delete_prefix(f"security:ip_to_device:{str(dev.get('ip', ip)).strip()}")
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while recording security event: %s", e)

    def _is_policy_block_reason(self, reason):
        return reason in {"status_blocked", "status_quarantine", "status_quarantined"}

    def _record_policy_block(self, mac, ip, dpid, in_port, reason):
        try:
            self.redis.incr("security:policy_blocks_total")
            self.redis.incr(f"security:policy_blocks:{reason}")
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while recording policy block: %s", e)

    def _evaluate_security_threats(self, eth, ip_pkt, arp_pkt, udp_pkt, dpid, in_port, in_port_name=""):
        mac = str(eth.src).lower()
        if mac in self._known_worker_macs():
            return True, None, None

        device = self._get_security_device_by_mac(mac)
        is_dhcp_request = bool(udp_pkt and udp_pkt.src_port == 68 and udp_pkt.dst_port == 67)
        observed_ip = ip_pkt.src if ip_pkt else (arp_pkt.src_ip if arp_pkt else "")
        
        if not device:
            if udp_pkt and udp_pkt.dst_port == 5555:
                return False, "MAC_SPOOFING", "unregistered_mac_telemetry"
        else:
            if device.get("status") not in ["authorized", "learning"]:
                return False, "POLICY_BLOCK", f"status_{device.get('status')}"
                
            is_tunnel = in_port_name.startswith("vx") or in_port_name in ["br-sdn", "br0"]
            is_local_guest_port = str(in_port_name).startswith("ens") and str(in_port) != "4294967294"
            if not is_tunnel:
                dpid_mismatch = device.get("dpid") and device.get("dpid") != str(dpid)
                port_mismatch = device.get("in_port") and device.get("in_port") != str(in_port)
                missing_location = is_local_guest_port and (not device.get("dpid") or not device.get("in_port"))
                if dpid_mismatch or port_mismatch or missing_location:
                    ip_matches = observed_ip in ("", "0.0.0.0", device.get("ip", ""))
                    if is_local_guest_port and (is_dhcp_request or ip_matches):
                        self._refresh_security_device_location(device, dpid, in_port)
                    elif dpid_mismatch:
                        return False, "MAC_SPOOFING", "dpid_mismatch"
                    else:
                        return False, "MAC_SPOOFING", "port_mismatch"
        
        if ip_pkt:
            src_ip = ip_pkt.src
            if not is_dhcp_request:
                if device and device.get("ip") and device.get("ip") != src_ip:
                    return False, "IP_SPOOFING", "ip_mismatch"
                
                owner_id = self._get_security_device_id_by_ip(src_ip)
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
        message = "Security drop installed: dpid=%s in_port=%s mac=%s eth_type=%s reason=%s"
        args = (datapath.id, in_port, src, eth_type or "any", reason)
        if self._is_policy_block_reason(reason):
            self.logger.debug(message, *args)
        else:
            self.logger.warning(message, *args)

    def _delete_guest_drop_flow(self, datapath, in_port, src):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_src=src)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=100,
            match=match,
        )
        datapath.send_msg(mod)
        self.logger.info("Security drop removed: dpid=%s in_port=%s mac=%s", datapath.id, in_port, src)

    def _sync_quarantine_flows(self):
        while True:
            try:
                for device_id in self.redis.smembers("security:devices") or []:
                    payload = self.redis.get(f"security:device:{device_id}")
                    if not payload:
                        continue
                    import json
                    device = json.loads(payload)
                    try:
                        dpid = int(device.get("dpid"))
                        in_port = int(device.get("in_port"))
                    except (TypeError, ValueError):
                        continue
                    datapath = self.datapaths.get(dpid)
                    mac = str(device.get("mac", "")).lower()
                    if not datapath or not mac:
                        continue
                    state_key = (device.get("device_id"), dpid, in_port, mac)
                    desired_state = "blocked" if device.get("status") in ("quarantine", "quarantined", "blocked") else "authorized"
                    if self.security_flow_state.get(state_key) == desired_state:
                        continue
                    if desired_state == "blocked":
                        self._drop_guest_packet(datapath, in_port, mac, reason="status_%s" % device.get("status"), install_flow=True)
                    else:
                        self._delete_guest_drop_flow(datapath, in_port, mac)
                    self.security_flow_state[state_key] = desired_state
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while syncing quarantine flows: %s", e)
            except Exception as e:
                self.logger.warning("Unexpected quarantine flow sync failure: %s", e)
            hub.sleep(5)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Externalize State: Register switch in the global Redis topology set
        try:
            self.redis.sadd('topology:switches', dpid)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while registering switch %s: %s", dpid, e)
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
            
            try:
                # Borrar de la lista global de switches
                self.redis.srem('topology:switches', dpid)

                # Node metadata is owned by ovs-sdn-initializer heartbeats; do
                # not delete it here on transient OpenFlow reconnects.
                self.redis.delete(f"mac_to_port:{dpid}")
                self.redis.delete(f"switch_ports:{dpid}")
                self._cache_delete_prefix(f"switch_ports:{dpid}")
                self._cache_delete_prefix("path_next_hop:")
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while removing switch %s: %s", dpid, e)



    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        ports_key = f"switch_ports:{dpid}"
        self._cache_delete_prefix(ports_key)
        self._cache_delete_prefix("path_next_hop:")
        try:
            self.redis.delete(ports_key)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while refreshing ports for %s: %s", dpid, e)
        for p in ev.msg.body:
            port_no = p.port_no
            name = p.name.decode('utf-8')
            try:
                self.redis.hset(ports_key, port_no, name)
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while registering port %s/%s: %s", dpid, port_no, e)
                continue
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
            try:
                self.redis.hset(f"switch_ports:{dpid}", port_no, name)
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while updating port %s/%s: %s", dpid, port_no, e)
                return
            self._cache_delete_prefix(f"switch_ports:{dpid}")
            self._cache_delete_prefix("path_next_hop:")
            self.logger.info("Port status UPDATE: DPID %s, Port %s, Name %s", dpid, port_no, name)
        elif reason == ofproto.OFPPR_DELETE:
            self._delete_flows_outputting_to_port(msg.datapath, port_no)
            try:
                self.redis.hdel(f"switch_ports:{dpid}", port_no)
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while deleting port %s/%s: %s", dpid, port_no, e)
                return
            self._cache_delete_prefix(f"switch_ports:{dpid}")
            self._cache_delete_prefix("path_next_hop:")
            self.logger.info("Port status DELETE: DPID %s, Port %s", dpid, port_no)

    def _delete_flows_outputting_to_port(self, datapath, port_no):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=port_no,
            out_group=ofproto.OFPG_ANY,
            table_id=ofproto.OFPTT_ALL,
        )
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        timeouts = {}
        if priority > 0:
            timeouts = {"idle_timeout": FORWARDING_FLOW_IDLE_TIMEOUT, "hard_timeout": 0}

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
        try:
            self.redis.sadd("topology:links", link_str)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while adding LLDP link %s: %s", link_str, e)
            return
        self.logger.info("LLDP Auto-Discovery: Enlace Agregado %s", link_str)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        link_str = f"{src.dpid}:{src.port_no}-{dst.dpid}:{dst.port_no}"
        try:
            self.redis.srem("topology:links", link_str)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while deleting LLDP link %s: %s", link_str, e)
            return
        self.logger.info("LLDP Auto-Discovery: Enlace Removido %s", link_str)

    def _get_switch_mac_map(self):
        """Devuelve un dict {mac_hex: dpid} de todos los switches registrados."""
        def load_switch_mac_map():
            try:
                switches = self.redis.smembers('topology:switches')
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while reading switch MAC map: %s", e)
                return {}
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
        return self._cached("switch_mac_map", RYU_CACHE_WORKER_MACS_SECONDS, load_switch_mac_map)

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
        try:
            self.redis.hset(mac_table_key, src, in_port)
            # MAC Ageing (Auto Limpieza): mantener el mapa sensible a cambios STP.
            self.redis.set(f"active_mac:{dpid}:{src}", "1", ex=180)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while learning MAC %s on %s: %s", src, dpid, e)

        # ─── TOPOLOGY INFERENCE ───────────────────────────────────────────────
        # Si el src MAC pertenece a otro switch conocido y llega por un puerto
        # inter-nodo (1-10), deducimos que hay un enlace físico y lo guardamos.
        if 1 <= in_port <= 10:
            switch_mac_map = self._get_switch_mac_map()
            if src in switch_mac_map:
                neighbor_dpid = switch_mac_map[src]
                if str(neighbor_dpid) != str(dpid):
                    link_str = f"{dpid}:{in_port}-{neighbor_dpid}:0"
                    try:
                        self.redis.sadd("topology:links", link_str)
                        self.redis.expire("topology:links", 300)  # TTL 5min para frescura
                    except redis.RedisError as e:
                        self.logger.warning("Redis unavailable while inferring link %s: %s", link_str, e)
        # ─────────────────────────────────────────────────────────────────────

        # Retrieve destination port from Redis
        try:
            out_port_str = self.redis.hget(mac_table_key, dst)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while reading destination %s on %s: %s", dst, dpid, e)
            out_port_str = None
        
        known_worker_macs = self._known_worker_macs()
        try:
            ports = self._get_switch_ports(dpid)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while reading ports for %s: %s", dpid, e)
            ports = {}
        if out_port_str and str(out_port_str) not in ports:
            self.logger.info(
                "Ignoring stale learned port: dpid=%s dst=%s port=%s",
                dpid, dst, out_port_str,
            )
            try:
                self.redis.hdel(mac_table_key, dst)
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while deleting stale MAC %s on %s: %s", dst, dpid, e)
            out_port_str = None
        if out_port_str and not self._is_forwarding_port_alive(str(ports.get(str(out_port_str), "")), dpid):
            self.logger.info(
                "Ignoring learned port to inactive VXLAN peer: dpid=%s dst=%s port=%s",
                dpid, dst, out_port_str,
            )
            try:
                self.redis.hdel(mac_table_key, dst)
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while deleting inactive-peer MAC %s on %s: %s", dst, dpid, e)
            out_port_str = None
        in_port_name = str(ports.get(str(in_port), ""))
        if (
            src not in known_worker_macs and
            in_port != ofproto.OFPP_LOCAL and
            not in_port_name.startswith("vx") and
            in_port_name != "br-sdn"
        ):
            try:
                self.redis.hset("topology:guest_locations", src, f"{dpid}:{in_port}")
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while updating guest location %s: %s", src, e)

        udp_pkt = pkt.get_protocol(udp.udp)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        allowed, threat_type, reason = self._evaluate_security_threats(eth, ip_pkt, arp_pkt, udp_pkt, dpid, in_port, in_port_name)
        if not allowed:
            src_ip = ip_pkt.src if ip_pkt else (arp_pkt.src_ip if arp_pkt else "")
            if threat_type == "POLICY_BLOCK" or self._is_policy_block_reason(reason):
                self.logger.debug("POLICY_BLOCK: dpid=%s in_port=%s mac=%s ip=%s reason=%s",
                                  dpid, in_port, src, src_ip, reason)
                self._record_policy_block(src, src_ip, dpid, in_port, reason)
            else:
                action = "log_only" if SECURITY_LEARNING_MODE else "quarantine"
                self.logger.warning("%s_DETECTED: dpid=%s in_port=%s mac=%s ip=%s reason=%s action=%s",
                                    threat_type, dpid, in_port, src, src_ip, reason, action)
                self._record_security_event(threat_type, src, src_ip, dpid, in_port, reason, action)
            
            if not SECURITY_LEARNING_MODE:
                self._drop_guest_packet(datapath, in_port, src, reason=reason, install_flow=True)
                return

        observed_src_ip = ip_pkt.src if ip_pkt else (arp_pkt.src_ip if arp_pkt else "")
        if (
            src not in known_worker_macs and
            in_port != ofproto.OFPP_LOCAL and
            not in_port_name.startswith("vx") and
            in_port_name != "br-sdn"
        ):
            self._learn_guest_ip(src, observed_src_ip)

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == "10.0.0.1":
            raw_dpid = self._decimal_dpid_to_raw(dpid)
            gateway_mac = ":".join(raw_dpid[-12:][i:i + 2] for i in range(0, 12, 2))
            self._send_arp_reply(datapath, in_port, src, arp_pkt.src_ip,
                                 gateway_mac, "10.0.0.1")
            return

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            guest_mac = self._guest_mac_for_ip(arp_pkt.dst_ip)
            if guest_mac and guest_mac.lower() != src.lower():
                self._send_arp_reply(datapath, in_port, src, arp_pkt.src_ip,
                                     guest_mac, arp_pkt.dst_ip)
                return

        if ip_pkt and ip_pkt.dst == "10.0.0.1":
            out_port = ofproto.OFPP_LOCAL
            actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        elif out_port_str:
            out_port = int(out_port_str)
            actions = [parser.OFPActionOutput(out_port)]
        else:
            guest_out_port = self._resolve_guest_out_port(dpid, dst)
            if guest_out_port:
                out_port = guest_out_port
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
            lock = None
            acquired = False
            try:
                lock = self.redis.lock(lock_name, timeout=5, blocking_timeout=1)
                acquired = lock.acquire()
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while acquiring flow lock %s: %s", lock_name, e)
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
                    try:
                        lock.release()
                    except redis.RedisError as e:
                        self.logger.warning("Redis unavailable while releasing flow lock %s: %s", lock_name, e)
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
            self.logger.debug("Ryu monitor heartbeat: datapaths=%d", len(self.datapaths))
            for datapath in list(self.datapaths.values()):
                try:
                    parser = datapath.ofproto_parser
                    datapath.send_msg(parser.OFPPortDescStatsRequest(datapath, 0))
                    datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                    datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY))
                except Exception as e:
                    self.logger.warning("Error requesting OpenFlow stats: %s", e)
            hub.sleep(MONITOR_INTERVAL_SECONDS)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        try:
            ports = self._get_switch_ports(dpid)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while checking flow output ports for %s: %s", dpid, e)
            ports = {}
        for stat in ev.msg.body:
            if stat.priority <= 0:
                continue
            delete_flow = False
            for instruction in getattr(stat, "instructions", []):
                for action in getattr(instruction, "actions", []):
                    out_port = getattr(action, "port", None)
                    if out_port is None:
                        continue
                    port_name = str(ports.get(str(out_port), ""))
                    if port_name.startswith("vx") and not self._is_forwarding_port_alive(port_name, dpid):
                        delete_flow = True
                        break
                if delete_flow:
                    break
            if not delete_flow:
                continue
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE_STRICT,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=stat.priority,
                match=stat.match,
            )
            datapath.send_msg(mod)
            self.logger.info(
                "Deleted flow using inactive VXLAN peer: dpid=%s priority=%s match=%s",
                dpid, stat.priority, stat.match,
            )
        # Exclude table-miss when reporting installed forwarding flows.
        self.installed_flows[dpid] = sum(1 for stat in ev.msg.body if stat.priority > 0)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        try:
            ports = self._get_switch_ports(dpid)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while reading port stats names for %s: %s", dpid, e)
            ports = {}
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
            switches = self._cached(
                "topology:switches",
                RYU_CACHE_NODE_IPS_SECONDS,
                lambda: self.redis.smembers("topology:switches") or set(),
            )
            node_ips = self._get_node_ips()
            topology_dpids = self._get_topology_switch_dpids(node_ips)
            if not topology_dpids:
                topology_dpids.update(str(dpid) for dpid in switches)
            counts["active_switches"] = len(topology_dpids)
            counts["active_nodes"] = len(topology_dpids)
            for dpid in topology_dpids:
                counts["learned_macs"][dpid] = self.redis.hlen(f"mac_to_port:{dpid}")
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while reading Redis metrics: %s", e)
        except Exception as e:
            self.logger.warning("Unexpected Redis metrics failure: %s", e)
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
        def load_alive_switch_dpids():
            alive_keys = self.redis.keys("switch:alive:*") or []
            dpids = set()
            for key in alive_keys:
                raw_dpid = str(key).split("switch:alive:", 1)[-1]
                dpids.add(self._raw_dpid_to_decimal(raw_dpid))
            return dpids
        return self._cached("switch:alive:dpids", RYU_CACHE_LIVENESS_SECONDS, load_alive_switch_dpids)

    def _get_topology_switch_dpids(self, node_ips):
        import time

        ttl = int(os.environ.get("TOPOLOGY_NODE_TTL_SECONDS", "180"))
        now = int(time.time())
        last_seen = self._cached(
            "topology:node_last_seen",
            RYU_CACHE_NODE_IPS_SECONDS,
            lambda: self.redis.hgetall("topology:node_last_seen") or {},
        )
        dpids = set()
        for raw_dpid, timestamp in last_seen.items():
            try:
                if now - int(float(timestamp)) <= ttl:
                    dpids.add(self._raw_dpid_to_decimal(raw_dpid))
            except (TypeError, ValueError):
                continue
        dpids.update(self._get_alive_switch_dpids())
        if not dpids:
            dpids.update(str(dpid) for dpid in self._cached(
                "topology:switches",
                RYU_CACHE_NODE_IPS_SECONDS,
                lambda: self.redis.smembers("topology:switches") or set(),
            ))
        return dpids

    def _guest_mac_for_ip(self, ip_addr):
        try:
            guest_ips = self.redis.hgetall("topology:guest_ips") or {}
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while resolving guest IP %s: %s", ip_addr, e)
            return None
        for mac, guest_ip in guest_ips.items():
            if guest_ip == ip_addr:
                return mac
        try:
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
                if mac and device.get("ip") == ip_addr:
                    self.redis.hset("topology:guest_ips", mac, ip_addr)
                    return mac
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while resolving security IP %s: %s", ip_addr, e)
        return None

    def _learn_guest_ip(self, mac, ip_addr):
        if not ip_addr or ip_addr in ("0.0.0.0", "10.0.0.1"):
            return
        if not str(ip_addr).startswith("10.0.0."):
            return
        try:
            dhcp_ip = self.redis.get(f"dhcp:bind:{mac}")
            guest_ips = self.redis.hgetall("topology:guest_ips") or {}
            for other_mac, other_ip in guest_ips.items():
                if other_mac != mac and other_ip == ip_addr and dhcp_ip != ip_addr:
                    self.logger.warning(
                        "Ignoring duplicate guest IP learn mac=%s ip=%s already owned by mac=%s",
                        mac, ip_addr, other_mac,
                    )
                    return
            current_ip = self.redis.hget("topology:guest_ips", mac)
            if current_ip != ip_addr:
                self.redis.hset("topology:guest_ips", mac, ip_addr)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while learning guest IP %s=%s: %s", mac, ip_addr, e)

    def _send_arp_reply(self, datapath, in_port, dst_mac, dst_ip, src_mac, src_ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac,
        ))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip,
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

    def _resolve_guest_out_port(self, current_dpid, dst_mac):
        try:
            guest_locations = self.redis.hgetall("topology:guest_locations") or {}
            node_ips = self._get_node_ips()
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while resolving guest path to %s: %s", dst_mac, e)
            return None

        location = guest_locations.get(dst_mac)
        if not location or ":" not in location:
            return None
        dst_dpid, dst_port = location.split(":", 1)
        current_dpid = str(current_dpid)
        if current_dpid == str(dst_dpid):
            return int(dst_port)

        path_cache_key = f"path_next_hop:{current_dpid}:{dst_dpid}"
        cached_out_port = self.cache.get(path_cache_key)
        if cached_out_port and cached_out_port[0] > time.time():
            try:
                out_port = int(cached_out_port[1])
                ports = self._get_switch_ports(current_dpid)
                port_name = str(ports.get(str(out_port), ""))
                if port_name and self._is_forwarding_port_alive(port_name, current_dpid):
                    return out_port
            except Exception:
                pass
            self.cache.pop(path_cache_key, None)

        dpids = {
            str(dpid) for dpid in self._get_topology_switch_dpids(node_ips)
            if self._is_switch_alive(dpid)
        }
        if self._is_switch_alive(current_dpid):
            dpids.add(current_dpid)
        if self._is_switch_alive(dst_dpid):
            dpids.add(str(dst_dpid))
        ip_to_dpid = {
            str(ip).replace(".", ""): self._raw_dpid_to_decimal(raw_dpid)
            for raw_dpid, ip in node_ips.items()
        }
        blocked_br0_links = self._get_blocked_br0_links(ip_to_dpid, dpids)

        switch_ports = {}
        adjacency = {str(dpid): [] for dpid in dpids}
        for dpid in dpids:
            try:
                ports = self._get_switch_ports(dpid)
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while reading ports for path %s: %s", dpid, e)
                ports = {}
            switch_ports[str(dpid)] = ports
            for port_no, port_name in ports.items():
                port_name = str(port_name)
                if not port_name.startswith("vx"):
                    continue
                next_dpid = ip_to_dpid.get(port_name[2:])
                if not next_dpid or str(next_dpid) not in dpids:
                    continue
                if not self._is_valid_vxlan_edge(dpid, next_dpid, node_ips, switch_ports, blocked_br0_links):
                    continue
                edge_blocked = (
                    _edge_link_id(dpid, next_dpid) in blocked_br0_links or
                    self._is_br0_edge_blocked(dpid, next_dpid, node_ips)
                )
                adjacency.setdefault(str(dpid), []).append((edge_blocked, str(next_dpid), int(port_no)))

        for dpid in adjacency:
            adjacency[dpid].sort(key=lambda edge: edge[0])

        queue = [(0, 0, current_dpid, [])]
        best = {current_dpid: (0, 0)}
        while queue:
            queue.sort(key=lambda item: (item[0], item[1]))
            blocked_cost, hops, dpid, path_ports = queue.pop(0)
            if dpid == str(dst_dpid):
                out_port = path_ports[0] if path_ports else int(dst_port)
                self.cache[path_cache_key] = (time.time() + RYU_CACHE_PATH_SECONDS, out_port)
                return out_port
            for edge_blocked, next_dpid, out_port in adjacency.get(dpid, []):
                next_cost = blocked_cost + (1 if edge_blocked else 0)
                next_hops = hops + 1
                previous = best.get(next_dpid)
                if previous is not None and previous <= (next_cost, next_hops):
                    continue
                best[next_dpid] = (next_cost, next_hops)
                queue.append((next_cost, next_hops, next_dpid, path_ports + [out_port]))
        return None

    def _is_switch_alive(self, dpid):
        raw_dpid = self._decimal_dpid_to_raw(dpid)
        def load_switch_alive():
            try:
                return bool(self.redis.exists(f"switch:alive:{raw_dpid}"))
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while checking switch liveness %s: %s", dpid, e)
                return False
        return self._cached(f"switch:alive:{raw_dpid}", RYU_CACHE_LIVENESS_SECONDS, load_switch_alive)

    def _is_forwarding_port_alive(self, port_name, local_dpid=None):
        if not port_name.startswith("vx"):
            return True
        try:
            node_ips = self._get_node_ips()
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while checking VXLAN peer %s: %s", port_name, e)
            return False
        peer_ip = port_name[2:]
        for raw_dpid, ip in node_ips.items():
            if str(ip).replace(".", "") != peer_ip:
                continue
            if not self._is_switch_alive(self._raw_dpid_to_decimal(raw_dpid)):
                return False
            if local_dpid is not None and not self._is_vxlan_peer_reachable(local_dpid, str(ip)):
                return False
            return True
        return False

    def _is_vxlan_peer_reachable(self, local_dpid, peer_ip):
        raw_local = self._decimal_dpid_to_raw(local_dpid)
        def load_peer_state():
            try:
                state = self.redis.get(f"vxlan:peer:state:{raw_local}:{peer_ip}")
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while checking VXLAN reachability %s->%s: %s", local_dpid, peer_ip, e)
                return False
            # Missing state is allowed during rollout or before the first probe.
            return str(state or "up").lower() != "down"
        return self._cached(f"vxlan:peer:state:{raw_local}:{peer_ip}", RYU_CACHE_LIVENESS_SECONDS, load_peer_state)

    def _node_ip_for_dpid(self, dpid, node_ips):
        raw_dpid = self._decimal_dpid_to_raw(dpid)
        return node_ips.get(raw_dpid, "")

    def _has_vxlan_to_ip(self, ports, peer_ip):
        expected = "vx%s" % str(peer_ip).replace(".", "")
        return expected in {str(port_name) for port_name in ports.values()}

    def _is_valid_vxlan_edge(self, local_dpid, remote_dpid, node_ips, switch_ports, blocked_br0_links):
        local_dpid = str(local_dpid)
        remote_dpid = str(remote_dpid)
        if not self._is_switch_alive(local_dpid) or not self._is_switch_alive(remote_dpid):
            return False
        if VXLAN_REQUIRES_FORWARDING_BR0_EDGE:
            if not self._has_forwarding_br0_edge(local_dpid, remote_dpid, node_ips, blocked_br0_links):
                return False
        local_ip = self._node_ip_for_dpid(local_dpid, node_ips)
        remote_ip = self._node_ip_for_dpid(remote_dpid, node_ips)
        if not local_ip or not remote_ip:
            return False
        if not self._is_vxlan_peer_reachable(local_dpid, remote_ip):
            return False
        if not self._is_vxlan_peer_reachable(remote_dpid, local_ip):
            return False
        local_ports = switch_ports.get(local_dpid)
        if local_ports is None:
            local_ports = self._get_switch_ports(local_dpid)
            switch_ports[local_dpid] = local_ports
        remote_ports = switch_ports.get(remote_dpid)
        if remote_ports is None:
            remote_ports = self._get_switch_ports(remote_dpid)
            switch_ports[remote_dpid] = remote_ports
        return self._has_vxlan_to_ip(local_ports, remote_ip) and self._has_vxlan_to_ip(remote_ports, local_ip)

    def _has_forwarding_br0_edge(self, local_dpid, remote_dpid, node_ips, blocked_br0_links=None):
        local_dpid = str(local_dpid)
        remote_dpid = str(remote_dpid)
        if blocked_br0_links and _edge_link_id(local_dpid, remote_dpid) in blocked_br0_links:
            return False
        remote_ip = self._node_ip_for_dpid(remote_dpid, node_ips)
        local_ip = self._node_ip_for_dpid(local_dpid, node_ips)
        if not local_ip or not remote_ip:
            return False
        try:
            br0_stp_ports = self._get_br0_stp_ports()
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while checking br0 forwarding edge %s-%s: %s", local_dpid, remote_dpid, e)
            return False
        local_raw = self._decimal_dpid_to_raw(local_dpid)
        remote_raw = self._decimal_dpid_to_raw(remote_dpid)
        local_forwarding = False
        remote_forwarding = False
        for key, status in br0_stp_ports.items():
            if ":" not in key:
                continue
            raw_dpid, _ = str(key).split(":", 1)
            state, _, peer_ip = str(status).partition(":")
            state = state.strip()
            peer_ip = peer_ip.strip()
            if raw_dpid == local_raw and peer_ip == remote_ip:
                if state != "forwarding":
                    return False
                local_forwarding = True
            elif raw_dpid == remote_raw and peer_ip == local_ip:
                if state != "forwarding":
                    return False
                remote_forwarding = True
        return local_forwarding and remote_forwarding

    def _is_br0_edge_blocked(self, local_dpid, remote_dpid, node_ips):
        local_dpid = str(local_dpid)
        remote_dpid = str(remote_dpid)
        remote_ip = self._node_ip_for_dpid(remote_dpid, node_ips)
        local_ip = self._node_ip_for_dpid(local_dpid, node_ips)
        if not local_ip or not remote_ip:
            return True
        try:
            br0_stp_ports = self._get_br0_stp_ports()
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while checking br0 STP edge %s-%s: %s", local_dpid, remote_dpid, e)
            return True
        local_raw = self._decimal_dpid_to_raw(local_dpid)
        remote_raw = self._decimal_dpid_to_raw(remote_dpid)
        seen = False
        for key, status in br0_stp_ports.items():
            if ":" not in key:
                continue
            raw_dpid, _ = str(key).split(":", 1)
            state, _, peer_ip = str(status).partition(":")
            state = state.strip()
            peer_ip = peer_ip.strip()
            if raw_dpid == local_raw and peer_ip == remote_ip:
                seen = True
                if state != "forwarding":
                    return True
            if raw_dpid == remote_raw and peer_ip == local_ip:
                seen = True
                if state != "forwarding":
                    return True
        return not seen

    def _get_blocked_br0_links(self, ip_to_dpid, dpids):
        br0_stp_ports = self._get_br0_stp_ports()
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
        try:
            raw_dpid = self._decimal_dpid_to_raw(dpid)
            if not self.redis.exists(f"switch:alive:{raw_dpid}"):
                return False
            ip = (self.redis.hget("topology:guest_ips", mac) or "").strip()
            is_smart_meter = False
            device_id = self.redis.get(f"security:mac_to_device:{mac}")
            if device_id:
                import json
                raw = self.redis.get(f"security:device:{device_id}")
                if raw:
                    device = json.loads(raw)
                    if not ip:
                        ip = str(device.get("ip", "")).strip()
                    if device.get("role") == "smart_meter":
                        is_smart_meter = True
            if ip:
                if not is_smart_meter:
                    for key in self.redis.scan_iter("meter:latest:*"):
                        if (self.redis.hget(key, "source_ip") or "").strip() == ip:
                            is_smart_meter = True
                            break
            if is_smart_meter:
                if ip:
                    for key in self.redis.scan_iter("meter:latest:*"):
                        if (self.redis.hget(key, "source_ip") or "").strip() != ip:
                            continue
                        timestamp = self.redis.hget(key, "timestamp")
                        try:
                            seen = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                            if seen.tzinfo is None:
                                seen = seen.replace(tzinfo=timezone.utc)
                            if (datetime.now(timezone.utc) - seen).total_seconds() <= ACTIVE_METER_MAX_AGE_SECONDS:
                                return True
                        except Exception:
                            continue
                return False
            if self.redis.exists(f"active_mac:{dpid}:{mac}"):
                return True
            if self.redis.exists(f"health:{mac}"):
                return True
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while checking guest freshness %s: %s", mac, e)
        return False

    def _has_fresh_meter_telemetry(self, ip):
        if not ip:
            return False
        try:
            for key in self.redis.scan_iter("meter:latest:*"):
                if (self.redis.hget(key, "source_ip") or "").strip() != ip:
                    continue
                timestamp = self.redis.hget(key, "timestamp")
                try:
                    seen = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                    if seen.tzinfo is None:
                        seen = seen.replace(tzinfo=timezone.utc)
                    return (datetime.now(timezone.utc) - seen).total_seconds() <= ACTIVE_METER_MAX_AGE_SECONDS
                except Exception:
                    continue
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while checking meter telemetry %s: %s", ip, e)
        return False

    def _sync_security_guest_locations(self, guest_ips, guest_locations, dpids):
        import json

        try:
            for device_id in self.redis.smembers("security:devices") or []:
                payload = self.redis.get(f"security:device:{device_id}")
                if not payload:
                    continue
                try:
                    device = json.loads(payload)
                except Exception:
                    continue
                if device.get("role") != "smart_meter":
                    continue
                if device.get("status", "authorized") not in ("authorized", "learning"):
                    continue

                mac = str(device.get("mac", "")).lower()
                ip = str(device.get("ip", "")).strip()
                dpid = str(device.get("dpid", "")).strip()
                in_port = str(device.get("in_port", "")).strip()
                if not mac or not ip or not dpid or not in_port or dpid not in dpids:
                    continue
                if not self._is_switch_alive(dpid):
                    continue
                if not self._has_fresh_meter_telemetry(ip):
                    continue

                ports = self._get_switch_ports(dpid)
                port_name = str(ports.get(in_port, ""))
                if port_name.startswith("vx") or in_port == "4294967294" or port_name == "br-sdn":
                    continue

                location = f"{dpid}:{in_port}"
                if guest_ips.get(mac) != ip:
                    self.redis.hset("topology:guest_ips", mac, ip)
                    guest_ips[mac] = ip
                if guest_locations.get(mac) != location:
                    self.redis.hset("topology:guest_locations", mac, location)
                    self.redis.hset("topology:guest_names", mac, device.get("device_id", device_id))
                    guest_locations[mac] = location
                    self.logger.info(
                        "Guest location restored from security registry: device=%s mac=%s location=%s",
                        device.get("device_id", device_id), mac, location,
                    )
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while syncing security guest locations: %s", e)

    def _add_guest_node_edge(self, guests, edges, mac, dpid, port_no, guest_ips):
        ports = self._get_switch_ports(dpid)
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
        node_names = self.redis.hgetall("topology:node_names") or {}
        node_ips = self._get_node_ips()
        dpids = self._get_topology_switch_dpids(node_ips)
        guest_ips = self.redis.hgetall("topology:guest_ips") or {}
        guest_locations = self.redis.hgetall("topology:guest_locations") or {}
        br0_stp_ports = self._get_br0_stp_ports()
        self._sync_security_guest_locations(guest_ips, guest_locations, dpids)

        nodes = []
        edges = []
        vxlan_edges = {}
        br0_edges = {}
        guests = {}
        has_mgmt_switch = False

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

            ports = self._get_switch_ports(dpid)
            mac_table = self.redis.hgetall(f"mac_to_port:{dpid}") or {}

            for port_no, port_name in ports.items():
                if str(port_name).startswith("vx"):
                    target = ip_to_dpid.get(str(port_name)[2:])
                    if target and target in dpids:
                        if not self._is_valid_vxlan_edge(dpid, target, node_ips, {str(dpid): ports}, blocked_br0_links):
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
                if not self._is_recent_guest(mac, dpid):
                    continue
                self._add_guest_node_edge(guests, edges, mac, dpid, port_no, guest_ips)

        worker_macs = self._known_worker_macs()
        for mac, location in guest_locations.items():
            if mac in worker_macs:
                continue
            if mac in guests:
                continue
            location_dpid, _, port_no = str(location).partition(":")
            if not location_dpid or not port_no or location_dpid not in dpids:
                continue
            if not self._is_recent_guest(mac, location_dpid):
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
            if not self._is_recent_guest(mac, dpid):
                continue
            status = device.get("status", "authorized")
            guests[mac] = {
                "id": mac,
                "title": mac,
                "subtitle": device.get("ip", "") or "DHCP pendiente",
                "mainstat": "guest" if status in ("authorized", "learning") else status,
                "color": "#ff00ee" if status in ("authorized", "learning") else "#f97316",
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
                "color": "#ff00ee" if status in ("authorized", "learning") else "#f97316",
                "strokeDasharray": "3 3",
                "thickness": "1",
                "type": "guest",
            })

        for edge in vxlan_edges.values():
            edge.pop("details", None)
            edges.append(edge)

        for key, status in br0_stp_ports.items():
            if ":" not in key:
                continue
            raw_dpid, intf = key.split(":", 1)
            local_dpid = self._raw_dpid_to_decimal(raw_dpid)
            state, _, remote_ip = str(status).partition(":")
            if remote_ip == "mgmt-switch":
                if local_dpid not in dpids:
                    continue
                has_mgmt_switch = True
                edge_id = "br0:%s:%s" % (local_dpid, MGMT_SWITCH_ID)
                edge = br0_edges.setdefault(edge_id, {
                    "id": edge_id,
                    "source": local_dpid,
                    "target": MGMT_SWITCH_ID,
                    "mainstat": "br0 switch",
                    "secondarystat": "mgmt uplink",
                    "color": "#22c55e" if state == "forwarding" else "#f59e0b",
                    "strokeDasharray": "" if state == "forwarding" else "5 5",
                    "thickness": "2" if state == "forwarding" else "1",
                    "type": "br0_mgmt_switch",
                    "details": [],
                })
                edge["details"].append("%s:%s=%s" % (local_dpid, intf, state))
                continue

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
            if state != "forwarding":
                edge.update({
                    "mainstat": "br0 STP blocked" if state == "blocking" else "br0 disabled",
                    "secondarystat": "STP blocked" if state == "blocking" else "STP disabled",
                    "color": "#ef4444",
                    "strokeDasharray": "",
                    "thickness": "6",
                    "type": "br0_stp_blocked",
                })

        for edge in br0_edges.values():
            edge.pop("details", None)
            link = _edge_link_id(edge["source"], edge["target"])
            # Grafana debe recibir una sola arista por par de nodos. Si hay
            # enlace físico br0, este reemplaza la arista VXLAN conceptual.
            edges = [existing for existing in edges if _edge_link_id(existing["source"], existing["target"]) != link]
            edges.append(edge)

        if has_mgmt_switch:
            nodes.append({
                "id": MGMT_SWITCH_ID,
                "title": "Mgmt-STP-Switch",
                "subtitle": "br0 STP root",
                "mainstat": "mgmt switch",
                "color": "#22c55e",
                "icon": "server",
                "type": "switch",
            })

        nodes.extend(guests.values())
        return nodes, edges, guests, ip_to_dpid

    def _trace_guest_path(self, src_guest, dst_guest, dpids, ip_to_dpid):
        src_switch = None
        dst_switch = None
        switch_ports = {}
        mac_tables = {}
        guest_locations = self.redis.hgetall("topology:guest_locations") or {}
        node_ips = self._get_node_ips()
        blocked_br0_links = self._get_blocked_br0_links(ip_to_dpid, dpids)

        for dpid in dpids:
            mac_table = self.redis.hgetall(f"mac_to_port:{dpid}") or {}
            ports = self._get_switch_ports(dpid)
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
            if not self._is_valid_vxlan_edge(curr_switch, next_switch, node_ips, switch_ports, blocked_br0_links):
                break

            path_edges.append(("path:%s" % _edge_link_id(curr_switch, next_switch), curr_switch, next_switch))
            curr_switch = next_switch

        if curr_switch == dst_switch:
            path_edges.append(("path:%s" % _edge_link_id(dst_switch, dst_guest), dst_switch, dst_guest))
            return path_edges

        adjacency = {str(dpid): [] for dpid in dpids}
        for dpid, ports in switch_ports.items():
            for _, port_name in sorted(ports.items(), key=lambda item: int(item[0]) if str(item[0]).isdigit() else 0):
                if not str(port_name).startswith("vx"):
                    continue
                target = ip_to_dpid.get(str(port_name)[2:])
                if target and target in dpids:
                    if not self._is_valid_vxlan_edge(dpid, target, node_ips, switch_ports, blocked_br0_links):
                        continue
                    adjacency[str(dpid)].append(str(target))

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

            for next_switch in adjacency.get(curr_switch, []):
                if next_switch in visited:
                    continue
                visited.add(next_switch)
                queue.append((next_switch, path + [next_switch]))
        return []

    def _append_topology_metrics(self, lines):
        nodes, edges, guests, ip_to_dpid = self._build_topology_snapshot()
        dpids = {
            node["id"] for node in nodes
            if node["type"] == "switch" and node["id"] != MGMT_SWITCH_ID
        }
        sample_value = str(datetime.utcnow().timestamp())

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
            lines.append("ryu_topology_node_info{%s} %s" % (labels, sample_value))

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
            lines.append("ryu_topology_edge_info{%s} %s" % (labels, sample_value))

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
                    lines.append("ryu_trace_path_edge_info{%s} %s" % (labels, sample_value))

    def _render_prometheus_metrics(self):
        export_global_metrics = self._is_metrics_exporter()
        redis_counts = {"active_switches": 0, "active_nodes": 0, "learned_macs": {}}
        security_total = mac_spoofing = ip_spoofing = arp_poisoning = 0
        policy_blocks_total = status_blocked = status_quarantine = status_quarantined = 0
        if export_global_metrics:
            redis_counts = self._redis_metric_counts()
            try:
                security_total = self.redis.get("security:events_total") or 0
                mac_spoofing = self.redis.get("security:events:MAC_SPOOFING") or 0
                ip_spoofing = self.redis.get("security:events:IP_SPOOFING") or 0
                arp_poisoning = self.redis.get("security:events:ARP_POISONING") or 0
                policy_blocks_total = self.redis.get("security:policy_blocks_total") or 0
                status_blocked = self.redis.get("security:policy_blocks:status_blocked") or 0
                status_quarantine = self.redis.get("security:policy_blocks:status_quarantine") or 0
                status_quarantined = self.redis.get("security:policy_blocks:status_quarantined") or 0
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while reading security metrics: %s", e)

        lines = [
            "# HELP ryu_security_events_total Total security events detected.",
            "# TYPE ryu_security_events_total counter",
            "ryu_security_events_total %s" % security_total,
            "# HELP ryu_security_events_by_type_total Security events by type.",
            "# TYPE ryu_security_events_by_type_total counter",
            'ryu_security_events_by_type_total{type="MAC_SPOOFING"} %s' % mac_spoofing,
            'ryu_security_events_by_type_total{type="IP_SPOOFING"} %s' % ip_spoofing,
            'ryu_security_events_by_type_total{type="ARP_POISONING"} %s' % arp_poisoning,
            "# HELP ryu_security_policy_blocks_total Total packets blocked by configured security policy.",
            "# TYPE ryu_security_policy_blocks_total counter",
            "ryu_security_policy_blocks_total %s" % policy_blocks_total,
            "# HELP ryu_security_policy_blocks_by_reason Policy blocks by reason.",
            "# TYPE ryu_security_policy_blocks_by_reason counter",
            'ryu_security_policy_blocks_by_reason{reason="status_blocked"} %s' % status_blocked,
            'ryu_security_policy_blocks_by_reason{reason="status_quarantine"} %s' % status_quarantine,
            'ryu_security_policy_blocks_by_reason{reason="status_quarantined"} %s' % status_quarantined,
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
            "# HELP redis_query_total Total Redis operations executed by application services",
            "# TYPE redis_query_total counter",
        ])
        for (operation, status), metric in sorted(self.redis_metrics.items()):
            labels = 'service="ryu",operation="%s",status="%s"' % (
                _escape_label(operation), _escape_label(status))
            lines.append("redis_query_total{%s} %s" % (labels, metric["count"]))
        lines.extend([
            "# HELP redis_query_duration_seconds_total Total Redis operation duration in seconds",
            "# TYPE redis_query_duration_seconds_total counter",
        ])
        for (operation, status), metric in sorted(self.redis_metrics.items()):
            labels = 'service="ryu",operation="%s",status="%s"' % (
                _escape_label(operation), _escape_label(status))
            lines.append("redis_query_duration_seconds_total{%s} %s" % (labels, metric["seconds"]))
        lines.extend([
            "# HELP redis_query_duration_seconds_max Maximum observed Redis operation duration in seconds since process start",
            "# TYPE redis_query_duration_seconds_max gauge",
        ])
        for (operation, status), metric in sorted(self.redis_metrics.items()):
            labels = 'service="ryu",operation="%s",status="%s"' % (
                _escape_label(operation), _escape_label(status))
            lines.append("redis_query_duration_seconds_max{%s} %s" % (labels, metric["max"]))
        if export_global_metrics:
            self._append_topology_metrics(lines)
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _metrics_wsgi_app(self, env, start_response):
        if env.get("PATH_INFO") != "/metrics":
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"not found\n"]
        now = time.time()
        if self.metrics_cache_body is not None and now < self.metrics_cache_until:
            body = self.metrics_cache_body
        else:
            body = self._render_prometheus_metrics()
            self.metrics_cache_body = body
            self.metrics_cache_until = now + METRICS_CACHE_SECONDS
        start_response("200 OK", [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")])
        return [body]

    def _start_metrics_server(self):
        try:
            listener = eventlet.listen(("0.0.0.0", METRICS_PORT))
            self.logger.info("Prometheus metrics endpoint listening on 0.0.0.0:%d/metrics", METRICS_PORT)
            eventlet.wsgi.server(listener, self._metrics_wsgi_app, log_output=False)
        except Exception as e:
            self.logger.error("Unable to start metrics endpoint: %s", e)
