import os
import redis
import eventlet
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.topology import event, switches

# Patch eventlet heavily used by Ryu to work properly with Redis and other sockets
eventlet.monkey_patch()

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Externalize State: Register switch in the global Redis topology set
        self.redis.sadd('topology:switches', dpid)
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
