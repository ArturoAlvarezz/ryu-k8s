# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Distributed Simple Switch for OpenFlow 1.3
Uses Redis as shared state backend for MAC table
"""

import os
import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class DistributedSimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DistributedSimpleSwitch13, self).__init__(*args, **kwargs)
        
        # Initialize Redis connection
        self.redis_client = None
        if REDIS_AVAILABLE:
            redis_host = os.getenv('REDIS_HOST', 'redis-svc')
            redis_port = int(os.getenv('REDIS_PORT', '6379'))
            redis_db = int(os.getenv('REDIS_DB', '0'))
            
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True,
                    socket_connect_timeout=10,
                    socket_timeout=10,
                    socket_keepalive=True,
                    health_check_interval=30,
                    retry_on_timeout=True
                )
                # Test connection
                self.redis_client.ping()
                self.logger.info("Connected to Redis at %s:%d", redis_host, redis_port)
            except Exception as e:
                self.logger.warning("Failed to connect to Redis: %s - Falling back to local memory", e)
                self.redis_client = None
        
        # Fallback to local memory if Redis is not available
        self.mac_to_port = {}
        self.use_redis = self.redis_client is not None
        
        if self.use_redis:
            self.logger.info("Running in DISTRIBUTED mode with Redis")
        else:
            self.logger.warning("Running in STANDALONE mode (no Redis)")

    def _get_mac_table_key(self, dpid):
        """Generate Redis key for MAC table"""
        return f"ryu:switch:{dpid}:mac_table"

    def _learn_mac(self, dpid, src_mac, in_port):
        """Learn MAC address and port mapping"""
        if self.use_redis:
            try:
                key = self._get_mac_table_key(dpid)
                # Store MAC -> Port mapping in Redis hash
                self.redis_client.hset(key, src_mac, in_port)
                # Set expiration to 5 minutes for stale entries
                self.redis_client.expire(key, 300)
            except Exception as e:
                self.logger.error("Redis error in _learn_mac: %s", e)
                # Fallback to local
                self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port
        else:
            self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

    def _lookup_mac(self, dpid, dst_mac):
        """Lookup MAC address to find output port"""
        if self.use_redis:
            try:
                key = self._get_mac_table_key(dpid)
                port = self.redis_client.hget(key, dst_mac)
                return int(port) if port else None
            except Exception as e:
                self.logger.error("Redis error in _lookup_mac: %s", e)
                # Fallback to local
                return self.mac_to_port.get(dpid, {}).get(dst_mac)
        else:
            return self.mac_to_port.get(dpid, {}).get(dst_mac)

    def _get_all_macs(self, dpid):
        """Get all MAC entries for statistics/debugging"""
        if self.use_redis:
            try:
                key = self._get_mac_table_key(dpid)
                return self.redis_client.hgetall(key)
            except Exception as e:
                self.logger.error("Redis error in _get_all_macs: %s", e)
                return {}
        else:
            return self.mac_to_port.get(dpid, {})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        dpid = format(datapath.id, "d").zfill(16)
        self.logger.info("Switch connected: %s", dpid)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.Ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packet
            return
        
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Learn source MAC address to avoid FLOOD next time
        self._learn_mac(dpid, src, in_port)

        # Lookup destination MAC
        out_port = self._lookup_mac(dpid, dst)
        
        if out_port is None:
            out_port = ofproto.OFPP_FLOOD
        else:
            out_port = int(out_port)

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Verify if we have a valid buffer_id
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
