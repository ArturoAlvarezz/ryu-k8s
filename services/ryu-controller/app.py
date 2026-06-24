"""
DistributedL2Switch - Ryu SDN controller for ring topology without STP.

Architecture:
- Each node runs one Ryu instance (DaemonSet, hostNetwork=true).
- Each OVS (br-sdn) connects to local 127.0.0.1:6653.
- Topology, MAC tables, and spanning tree are shared via Redis.
- LLDP discovers physical links (via ryu-topology).
- Dijkstra computes shortest paths between switches.
- MST (Prim) computed from the graph for broadcast-only trees.
- ARP proxy: controller synthesizes ARP replies for known IPs.
- Controlled flood: broadcast only via MST edges (no OFPP_FLOOD).
- Path stitching: multi-hop unicast via VXLAN tunnel concatenation.
- Link failures trigger MST + Dijkstra recomputation.

No STP, no RSTP. Loops prevented by explicit flow installation and MST.
"""

import os
import eventlet
import redis
import time
import json
import networkx as nx
from datetime import datetime, timezone
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import datapath_connection_factory
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from ryu.topology import event
from ryu.topology import switches
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types

METRICS_PORT = int(os.environ.get("METRICS_PORT", 8000))
NODE_NAME = os.environ.get("NODE_NAME", "")
METRICS_EXPORTER_NODE = os.environ.get("METRICS_EXPORTER_NODE", "master")
METRICS_CACHE_SECONDS = float(os.environ.get("METRICS_CACHE_SECONDS", 30))
RYU_CACHE_NODE_IPS_SECONDS = float(os.environ.get("RYU_CACHE_NODE_IPS_SECONDS", 5))
RYU_CACHE_SWITCH_PORTS_SECONDS = float(os.environ.get("RYU_CACHE_SWITCH_PORTS_SECONDS", 5))
RYU_CACHE_WORKER_MACS_SECONDS = float(os.environ.get("RYU_CACHE_WORKER_MACS_SECONDS", 10))
RYU_CACHE_LIVENESS_SECONDS = float(os.environ.get("RYU_CACHE_LIVENESS_SECONDS", 2))
RYU_CACHE_SECURITY_SECONDS = float(os.environ.get("RYU_CACHE_SECURITY_SECONDS", 5))
RYU_CACHE_PATH_SECONDS = float(os.environ.get("RYU_CACHE_PATH_SECONDS", 5))
ACTIVE_METER_MAX_AGE_SECONDS = int(os.environ.get("ACTIVE_METER_MAX_AGE_SECONDS", 30))
MONITOR_INTERVAL_SECONDS = float(os.environ.get("MONITOR_INTERVAL_SECONDS", 5))
FORWARDING_FLOW_IDLE_TIMEOUT = int(os.environ.get("FORWARDING_FLOW_IDLE_TIMEOUT", 120))
SECURITY_LEARNING_MODE = os.environ.get("SECURITY_LEARNING_MODE", "false").lower() == "true"
# Anti-spoofing en el plano de datos (MAC/IP/ARP). Cuando esta deshabilitado el
# controlador no evalua amenazas (comportamiento previo). En modo learning solo
# registra eventos sin instalar drops.
SECURITY_ENFORCE = os.environ.get("SECURITY_ENFORCE", "true").lower() in ("1", "true", "yes", "on")
# Exigir que un MAC registrado se observe en su dpid/in_port de alta. La sincro
# del meter-collector mantiene esta ubicacion fresca; si causa falsos positivos
# se puede desactivar sin perder el resto de validaciones.
SECURITY_ENFORCE_LOCATION = os.environ.get("SECURITY_ENFORCE_LOCATION", "true").lower() in ("1", "true", "yes", "on")
# Prioridades de flow (br-sdn). El ovs-sdn-initializer instala
# `priority=200,ip,nw_dst=10.0.0.1 -> LOCAL` para entregar la telemetria al host
# SIN pasar por el controlador. Para validar la identidad L2 de esa telemetria
# (un atacante puede forjar la IP/device_id de un meter legitimo) se desvia a
# CONTROLLER con un flow de prioridad superior (DIVERT), y el veredicto
# (allow->LOCAL / drop) se instala por encima del divert para no re-disparar
# Packet-In continuo.
SECURITY_DIVERT_PRIORITY = int(os.environ.get("SECURITY_DIVERT_PRIORITY", 210))
SECURITY_DROP_PRIORITY = int(os.environ.get("SECURITY_DROP_PRIORITY", 220))
SECURITY_DROP_HARD_TIMEOUT = int(os.environ.get("SECURITY_DROP_HARD_TIMEOUT", 60))
SECURITY_TELEMETRY_ALLOW_IDLE = int(os.environ.get("SECURITY_TELEMETRY_ALLOW_IDLE", 60))
SECURITY_EVENTS_MAXLEN = int(os.environ.get("SECURITY_EVENTS_MAXLEN", 500))
GUEST_GATEWAY_IP = os.environ.get("GUEST_GATEWAY_IP", "10.0.0.1")
# Guard de telemetria: desvia la telemetria guest->gateway al controlador para
# validar su MAC Ethernet real (cierra el MAC-spoofing que el collector no ve).
TELEMETRY_UDP_PORT = int(os.environ.get("METER_UDP_PORT", 5555))
SECURITY_TELEMETRY_GUARD = os.environ.get("SECURITY_TELEMETRY_GUARD", "true").lower() in ("1", "true", "yes", "on")
# Dispositivo DESCONOCIDO (MAC no registrada que NO suplanta ninguna identidad ni
# IP ajena): por defecto NO se dropea, solo se registra como observacion y se deja
# fluir para que sea DESCUBRIBLE en la pagina de Operaciones y registrable por un
# operador (su telemetria llega al collector, que es fail-closed mientras el
# device_id no este dado de alta). La suplantacion ACTIVA de identidades/IP
# registradas (ip_claim_conflict, ip_mismatch, mac_location_mismatch, status_*,
# arp_*) SIEMPRE se dropea. Poner a true para bloquear tambien lo desconocido.
SECURITY_DROP_UNREGISTERED = os.environ.get("SECURITY_DROP_UNREGISTERED", "false").lower() in ("1", "true", "yes", "on")
# Intervalo del recompute periodico de topologia. Los nodos de TRANSITO (que no
# reciben eventos LLDP del enlace caido) dependen de este ciclo para detectar el
# cambio de grafo y re-resolver caminos; 30s era demasiado lento para el reroute.
MST_RECOMPUTE_INTERVAL = int(os.environ.get("MST_RECOMPUTE_INTERVAL", 8))
ARP_DEDUP_WINDOW = int(os.environ.get("ARP_DEDUP_WINDOW", 5))
DEFAULT_LINK_COST = float(os.environ.get("DEFAULT_LINK_COST", 1.0))


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


class TopologyManager:
    """Manages the topology graph, MST, and path computation.

    Each Ryu instance computes MST + Dijkstra independently from the
    shared Redis state. Results are published to Redis for monitoring.
    """

    def __init__(self, logger, redis_client):
        self.logger = logger
        self.redis = redis_client
        self.graph = None
        self.mst_edges = set()
        self.graph_edges = set()
        self.last_mst_computation = 0
        self.topology_version = 0

    def _raw_dpid_to_decimal(self, raw_dpid):
        try:
            return int(raw_dpid, 16)
        except Exception:
            return 0

    def _decimal_dpid_to_raw(self, dpid):
        return hex(int(dpid))[2:].zfill(16).zfill(16)[-16:]

    def _ip_to_dpid(self, node_ips):
        return {
            str(ip).replace(".", ""): self._raw_dpid_to_decimal(k)
            for k, ip in node_ips.items()
        }

    def _build_graph(self):
        """Build NetworkX graph from direct VXLAN peers and link costs."""
        try:
            vxlan_peers = self.redis.hgetall("topology:vxlan_peers") or {}
            link_costs = self.redis.hgetall("topology:link_cost") or {}
            node_ips = self.redis.hgetall("topology:node_ips") or {}
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while building graph: %s", e)
            return None

        # Solo switches vivos (heartbeat switch:alive vigente). Un nodo apagado
        # expira su heartbeat (TTL ~30s); excluirlo del grafo hace que MST y
        # Dijkstra computen un camino alternativo en vez de seguir tunelizando
        # hacia un nodo muerto (que provocaba blackhole hasta restaurar el nodo).
        # fail-open ante error de Redis: no excluir para no romper el grafo.
        def _is_alive(raw):
            try:
                return bool(self.redis.exists(f"switch:alive:{raw}"))
            except redis.RedisError:
                return True

        alive_dpids = set()
        for raw in set(node_ips.keys()) | set(vxlan_peers.keys()):
            if _is_alive(raw):
                d = self._raw_dpid_to_decimal(raw)
                if d:
                    alive_dpids.add(d)

        G = nx.Graph()
        for node_raw, ip in node_ips.items():
            dpid = self._raw_dpid_to_decimal(node_raw)
            if dpid and dpid in alive_dpids:
                G.add_node(dpid, ip=ip)

        ip_to_dpid = self._ip_to_dpid(node_ips)
        # Adyacencia declarada por cada switch vivo segun SU propia lista
        # topology:vxlan_peers.
        peer_map = {}
        for raw_dpid, peers in vxlan_peers.items():
            src_dpid = self._raw_dpid_to_decimal(raw_dpid)
            if not src_dpid or src_dpid not in alive_dpids:
                continue
            if not G.has_node(src_dpid):
                G.add_node(src_dpid)
            neigh = set()
            for peer_ip in str(peers).split():
                dst_dpid = ip_to_dpid.get(str(peer_ip).replace(".", ""))
                if dst_dpid and dst_dpid != src_dpid and dst_dpid in alive_dpids:
                    neigh.add(dst_dpid)
            peer_map[src_dpid] = neigh

        # Aristas con confirmacion BIDIRECCIONAL: ambos extremos deben listarse
        # mutuamente. Un nodo MUERTO conserva su lista vxlan_peers stale en Redis
        # (y su switch:alive vigente hasta el TTL ~45s), pero sus vecinos VIVOS lo
        # quitan de su propia lista en ~segundos (perdida de carrier -> LLDP).
        # Exigir reciprocidad hace que la arista hacia el nodo muerto desaparezca
        # de inmediato, desacoplando el reroute por CAIDA DE NODO del TTL de
        # switch:alive (que se subio a 45s por resiliencia ante blips de Redis).
        # El corte de ENLACE entre dos nodos vivos ya funcionaba: ambos extremos
        # se quitan mutuamente. fail-open: si un nodo no publico aun su lista,
        # peer_map.get(dst) vacio -> la arista no se añade hasta que ambos esten.
        for src_dpid, neigh in peer_map.items():
            for dst_dpid in neigh:
                if src_dpid not in peer_map.get(dst_dpid, ()):
                    continue
                if not G.has_node(dst_dpid):
                    G.add_node(dst_dpid)
                edge_key = _edge_link_id(src_dpid, dst_dpid)
                cost = float(link_costs.get(edge_key, DEFAULT_LINK_COST))
                G.add_edge(src_dpid, dst_dpid, weight=cost)

        return G

    def recompute(self):
        """Recompute el grafo/MST. Devuelve True si cambio el conjunto de aristas
        del grafo (no solo del MST): el forwarding usa Dijkstra sobre TODAS las
        aristas, asi que cortar un enlace redundante (fuera del MST) tambien debe
        forzar re-resolucion de caminos."""
        now = time.time()
        if now - self.last_mst_computation < 5:
            return False

        G = self._build_graph()
        if G is None or G.number_of_nodes() == 0:
            return False

        try:
            mst = nx.minimum_spanning_tree(G)
        except Exception as e:
            self.logger.warning("MST computation failed: %s", e)
            return False

        new_mst_edges = set()
        for u, v in mst.edges():
            new_mst_edges.add(_edge_link_id(u, v))
        new_graph_edges = set(_edge_link_id(u, v) for u, v in G.edges())

        mst_changed = new_mst_edges != self.mst_edges
        graph_changed = new_graph_edges != self.graph_edges
        self.graph = G
        self.graph_edges = new_graph_edges

        if mst_changed:
            self.logger.info("MST changed: %d edges (was %d)", len(new_mst_edges), len(self.mst_edges))
            self.mst_edges = new_mst_edges
            self.last_mst_computation = now
            self.topology_version = self.redis.incr("topology:version")
            try:
                pipe = self.redis.pipeline()
                pipe.delete("topology:mst_edges")
                for edge in self.mst_edges:
                    pipe.sadd("topology:mst_edges", edge)
                pipe.execute()
            except redis.RedisError as e:
                self.logger.warning("Redis error saving MST: %s", e)

        if graph_changed and not mst_changed:
            self.logger.info("Graph edges changed: %d (MST unchanged)", len(new_graph_edges))

        return mst_changed or graph_changed

    def compute_dijkstra(self, src_dpid, dst_dpid):
        """Return list of dpids from src to dst, or None if unreachable."""
        if self.graph is None:
            self.recompute()
        if self.graph is None:
            return None

        try:
            return nx.dijkstra_path(self.graph, src_dpid, dst_dpid)
        except nx.NetworkXNoPath:
            return None
        except nx.NodeNotFound:
            return None

    def get_mst_neighbors(self, dpid):
        """Return list of neighbor dpids connected via MST edges."""
        if not self.mst_edges:
            self.recompute()
        neighbors = []
        for edge in self.mst_edges:
            parts = edge.split("--")
            if len(parts) != 2:
                continue
            n1, n2 = parts
            try:
                n1, n2 = int(n1), int(n2)
            except Exception:
                continue
            if n1 == dpid:
                neighbors.append(n2)
            elif n2 == dpid:
                neighbors.append(n1)
        return neighbors

    def get_switch_ports_for_link(self, src_dpid, dst_dpid):
        """Return (src_port, dst_port) for the edge between src and dst."""
        if self.graph is None:
            return None, None
        try:
            data = self.graph[src_dpid][dst_dpid]
            return data.get("src_port"), data.get("dst_port")
        except Exception:
            return None, None


class ArpHandler:
    """Handles ARP requests with proxy reply and deduplication.

    ARP deduplication key: (dpid, src_mac, src_ip, dst_ip, opcode)
    - dpid avoids cross-switch collisions when the same packet traverses
      the broadcast tree and reaches multiple switches.
    - opcode distinguishes request from reply if needed.

    Stored in a Redis sorted set with score=timestamp. Duplicates within
    ARP_DEDUP_WINDOW seconds are dropped.
    """

    def __init__(self, logger, redis_client):
        self.logger = logger
        self.redis = redis_client
        self.arp_table = {}
        self.metrics = {
            "proxy": 0,
            "flood": 0,
            "dedup": 0,
            "learn": 0,
        }

    def _arp_dedup_key(self, dpid, src_mac, src_ip, dst_ip, opcode):
        return f"{dpid}:{src_mac}:{src_ip}:{dst_ip}:{opcode}"

    def is_duplicate(self, dpid, src_mac, src_ip, dst_ip, opcode):
        """Return True if this exact ARP was seen within the dedup window."""
        key = self._arp_dedup_key(dpid, src_mac, src_ip, dst_ip, opcode)
        try:
            score = self.redis.zscore("topology:arp_dedup", key)
            if score and (time.time() - score) < ARP_DEDUP_WINDOW:
                self.metrics["dedup"] += 1
                return True
            return False
        except redis.RedisError:
            return False

    def mark_arp(self, dpid, src_mac, src_ip, dst_ip, opcode):
        """Record this ARP in the dedup set."""
        key = self._arp_dedup_key(dpid, src_mac, src_ip, dst_ip, opcode)
        try:
            pipe = self.redis.pipeline()
            pipe.zadd("topology:arp_dedup", {key: time.time()})
            pipe.zremrangebyscore("topology:arp_dedup", 0, time.time() - ARP_DEDUP_WINDOW * 2)
            pipe.execute()
        except redis.RedisError as e:
            self.logger.warning("Redis error in ARP dedup: %s", e)

    def learn_request_location(self, dpid, in_port, src_mac):
        """Record where an ARP request was observed: (dpid, in_port) per src_mac."""
        try:
            self.redis.hset("topology:arp_request_origin", src_mac, f"{dpid}:{in_port}")
        except redis.RedisError as e:
            self.logger.warning("Redis error recording ARP request origin: %s", e)

    def learn_ip(self, mac, ip_addr):
        """Learn IP->MAC mapping."""
        if not ip_addr or ip_addr in ("0.0.0.0", "10.0.0.1"):
            return
        if not str(ip_addr).startswith("10.0.0."):
            return
        self.arp_table[ip_addr] = mac
        self.metrics["learn"] += 1
        try:
            self.redis.hset("topology:arp_table", ip_addr, mac)
        except redis.RedisError as e:
            self.logger.warning("Redis error learning ARP: %s", e)

    def get_mac_for_ip(self, ip_addr):
        """Look up MAC for IP, first from local cache then from Redis."""
        if ip_addr in self.arp_table:
            return self.arp_table[ip_addr]
        try:
            mac = self.redis.hget("topology:arp_table", ip_addr)
            if mac:
                self.arp_table[ip_addr] = mac
            return mac
        except redis.RedisError:
            return None

    def handle_arp_request(self, datapath, in_port, src_mac, src_ip, dst_ip, parser):
        """Handle incoming ARP request.

        Returns (proxy_reply_sent, flood_needed).
        - proxy_reply_sent=True: a fabricated ARP reply was sent back via
          packet-out and the original request must NOT be flooded.
        - flood_needed=True: the controller does not know the target MAC,
          so the packet must be flooded through the controlled tree.
        """
        dpid = datapath.id
        opcode = arp.ARP_REQUEST

        self.learn_request_location(dpid, in_port, src_mac)
        self.mark_arp(dpid, src_mac, src_ip, dst_ip, opcode)
        self.learn_ip(src_mac, src_ip)

        if dst_ip == "10.0.0.1":
            gateway_mac = _mac_from_dpid(hex(int(dpid))[2:].zfill(16))
            if gateway_mac:
                self.metrics["proxy"] += 1
                self._send_arp_reply(
                    datapath, parser, in_port=in_port,
                    dst_mac=src_mac, dst_ip=src_ip,
                    src_mac=gateway_mac, src_ip=dst_ip,
                )
                return True, False

        target_mac = self.get_mac_for_ip(dst_ip)
        if target_mac:
            self.metrics["proxy"] += 1
            self._send_arp_reply(
                datapath, parser, in_port=in_port,
                dst_mac=src_mac, dst_ip=src_ip,
                src_mac=target_mac, src_ip=dst_ip,
            )
            return True, False

        self.metrics["flood"] += 1
        return False, True

    def _send_arp_reply(self, datapath, parser, in_port, dst_mac, dst_ip, src_mac, src_ip):
        """Build and send a fabricated ARP reply directly to the requester."""
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
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data,
        )
        datapath.send_msg(out)

    def _decimal_to_raw(self, dpid):
        return hex(int(dpid))[2:].zfill(16)


class BroadcastController:
    """Computes and applies logical spanning tree for broadcast traffic.

    Instead of OFPP_FLOOD (which sends to ALL ports including loops),
    broadcast uses only the edges of the MST computed by TopologyManager.

    Behavior:
    - Inter-switch ports (VXLAN) are only used if the peer is reachable
      via an MST edge. This guarantees no broadcast packet traverses a
      non-tree link, so cycles are impossible.
    - Local guest ports (`ens*`, `br-*`) are always included because they
      cannot form an L2 loop.
    - The incoming port is always excluded.
    - The OFPP_LOCAL port is excluded to avoid echoing the controller path
      back through the bridge.
    """

    def __init__(self, logger, topology_manager):
        self.logger = logger
        self.tm = topology_manager
        self.metrics = {
            "flood": 0,
            "mst_edges": 0,
            "ports_blocked": 0,
        }

    def get_broadcast_ports(self, dpid, in_port, ports):
        """Return list of output ports for broadcast, excluding in_port.

        Uses MST edges to determine which ports to flood.
        """
        mst_neighbors = self.tm.get_mst_neighbors(dpid)
        self.metrics["mst_edges"] = len(mst_neighbors)
        node_ips = self.tm.redis.hgetall("topology:node_ips") or {}
        ip_to_dpid = self.tm._ip_to_dpid(node_ips)

        out_ports = []
        for port_no, port_name in ports.items():
            try:
                port_no_int = int(port_no)
            except Exception:
                continue
            if port_no_int == in_port or port_no_int == ofproto_v1_3.OFPP_LOCAL:
                continue
            if port_no_int == ofproto_v1_3.OFPP_CONTROLLER:
                continue
            port_name = str(port_name)
            if port_name.startswith("vx"):
                peer_ip = port_name[2:]
                peer_dpid = ip_to_dpid.get(peer_ip)
                if peer_dpid and peer_dpid in mst_neighbors:
                    out_ports.append(port_no_int)
                else:
                    self.metrics["ports_blocked"] += 1
            elif port_name.startswith("ens") or port_name.startswith("br-"):
                out_ports.append(port_no_int)
        return out_ports


class ForwardingEngine:
    """Computes Dijkstra paths and installs explicit flows on switches.

    Path stitching: for a path [dpid1, dpid2, dpid3, dpid4], install:
    - On dpid1: match(eth_dst=host_mac) -> output vx_to_dpid2
    - On dpid2: match(eth_dst=host_mac) -> output vx_to_dpid3
    - On dpid3: match(eth_dst=host_mac) -> output local_port_to_host
    """

    def __init__(self, logger, redis_client, topology_manager):
        self.logger = logger
        self.redis = redis_client
        self.tm = topology_manager
        self.flow_stats_thread = None

    def _get_switch_ports(self, dpid):
        try:
            return self.redis.hgetall(f"switch_ports:{dpid}") or {}
        except redis.RedisError as e:
            self.logger.warning("Redis error reading ports for %s: %s", dpid, e)
            return {}

    def _vxlan_port_to_ip(self, port_name):
        if port_name.startswith("vx"):
            ip = port_name[2:]
            return f"192.168.122.{ip[-3:]}" if ip.startswith("122") else ip
        return None

    def _ip_to_dpid(self, node_ips):
        return {
            str(ip).replace(".", ""): self.tm._raw_dpid_to_decimal(k)
            for k, ip in node_ips.items()
        }

    def install_path_flows(self, src_dpid, dst_dpid, dst_mac, datapath_by_dpid):
        """Install flows on all switches along the Dijkstra path from src to dst.

        For each hop (dpid_i -> dpid_{i+1}), install:
        - match(eth_dst=dst_mac)
        - action(output local_port_or_vxlan_to_next_hop)
        """
        path = self.tm.compute_dijkstra(src_dpid, dst_dpid)
        if not path or len(path) < 2:
            self.logger.debug("No path or single node for %s -> %s", src_dpid, dst_dpid)
            return False

        self.logger.info("Installing path flows: %s -> %s via %s", src_dpid, dst_dpid, path)

        node_ips = self.redis.hgetall("topology:node_ips") or {}
        ip_to_dpid = self._ip_to_dpid(node_ips)
        dpid_to_ip = {v: k for k, v in ip_to_dpid.items()}

        installed = 0
        for i, current_dpid in enumerate(path):
            if i == len(path) - 1:
                break

            next_dpid = path[i + 1]
            src_port, dst_port = self.tm.get_switch_ports_for_link(current_dpid, next_dpid)

            if current_dpid not in datapath_by_dpid:
                self.logger.debug("No datapath for dpid %s, skipping flow install", current_dpid)
                continue

            dp = datapath_by_dpid[current_dpid]
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            ports = self._get_switch_ports(current_dpid)

            out_port = None
            for port_no, port_name in ports.items():
                port_name = str(port_name)
                if port_name.startswith("vx"):
                    peer_ip_raw = port_name[2:]
                    peer_ip = self._vxlan_port_to_ip(port_name)
                    peer_dpid = ip_to_dpid.get(peer_ip.replace(".", ""))
                    if peer_dpid == next_dpid:
                        out_port = int(port_no)
                        break

            if out_port is None:
                self.logger.debug("No VXLAN port found from %s to %s", current_dpid, next_dpid)
                continue

            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            try:
                self.add_flow(dp, 10, match, actions)
                installed += 1
                self.logger.debug("Flow installed: dpid=%s match(eth_dst=%s) -> output=%s",
                                  current_dpid, dst_mac, out_port)
            except Exception as e:
                self.logger.warning("Failed to install flow on dpid %s: %s", current_dpid, e)

        return installed > 0

    def add_flow(self, datapath, priority, match, actions, idle_timeout=FORWARDING_FLOW_IDLE_TIMEOUT):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_ADD,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=0,
        )
        datapath.send_msg(mod)


class DistributedL2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(DistributedL2Switch, self).__init__(*args, **kwargs)

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
        self.security_events_total = {}
        self.installed_flows = {}
        self.port_stats = {}
        self.metrics_started_at = time.time()
        # Cuando la topologia (MST/grafo) cambia, hay que re-resolver los caminos:
        # los flows de forwarding instalados pueden seguir un camino roto cuyos
        # saltos son nodos VIVOS (p.ej. tras un corte de enlace los nodos de
        # transito no reciben link_delete y sus flows salen a peers vivos). Esta
        # bandera pide al flow_stats handler vaciar los flows de forwarding del
        # switch local para que se recomputen via Dijkstra en el siguiente paquete.
        self._forwarding_flush_pending = False

        self.topology_manager = TopologyManager(self.logger, self.redis)
        self.arp_handler = ArpHandler(self.logger, self.redis)
        self.forwarding_engine = ForwardingEngine(self.logger, self.redis, self.topology_manager)
        self.broadcast_controller = BroadcastController(self.logger, self.topology_manager)

        self.monitor_thread = hub.spawn(self._monitor_datapaths)
        self.metrics_thread = hub.spawn(self._start_metrics_server)
        self.topology_recompute_thread = hub.spawn(self._periodic_topology_recompute)
        self.dead_switch_sub_thread = hub.spawn(self._subscribe_dead_switches)

    def _record_redis_metric(self, operation, status, duration):
        key = (str(operation), str(status))
        metric = self.redis_metrics.setdefault(key, {"count": 0, "seconds": 0.0, "max": 0.0})
        metric["count"] += 1
        metric["seconds"] += duration
        if duration > metric["max"]:
            metric["max"] = duration

    def _subscribe_dead_switches(self):
        try:
            sub = self.redis.pubsub()
            sub.subscribe("switch:dead")
            self.logger.info("Subscribed to switch:dead channel")
            while True:
                try:
                    msg = sub.get_message(timeout=1.0)
                    if msg and msg["type"] == "message":
                        raw_dpid = msg["data"]
                        self._clear_mac_to_port_for_dead_switch(raw_dpid)
                except redis.RedisError as e:
                    self.logger.warning("Redis error in dead switch subscriber: %s", e)
                except Exception as e:
                    self.logger.warning("Unexpected error in dead switch subscriber: %s", e)
                hub.sleep(0.5)
        except Exception as e:
            self.logger.warning("Failed to subscribe to dead switch channel: %s", e)

    def _clear_mac_to_port_for_dead_switch(self, raw_dpid):
        try:
            target_dpid = self._raw_dpid_to_decimal(raw_dpid)
            self.logger.info("Clearing mac_to_port entries for dead switch %s", target_dpid)
            # Invalidar la liveness del switch muerto INMEDIATAMENTE: sin esto, su
            # heartbeat switch:alive seguia vigente hasta el TTL (~45s) y tanto el
            # grafo de Ryu como /api/sdn-trace seguian usando el nodo caido como
            # transito durante esa ventana (path stale). Borrarlo aqui desacopla la
            # invalidacion del TTL: en cuanto CUALQUIER nodo detecta y publica la
            # muerte (switch:dead), todos los Ryu lo excluyen del calculo de caminos.
            # Si fuese un falso positivo, el ovs-configurator del nodo vivo re-setea
            # su switch:alive en el siguiente heartbeat (auto-correccion).
            try:
                self.redis.delete(f"switch:alive:{raw_dpid}")
                if target_dpid:
                    self.redis.delete(f"switch:alive:{target_dpid}")
                # Marcar el nodo como CONFIRMADO muerto (no un simple blip de
                # heartbeat): el dashboard de Operaciones usa esta marca para
                # quitar el nodo del mapa SDN de inmediato (sin esperar la ventana
                # de gracia de ~600s), igual de rapido que Grafana. La marca caduca
                # sola y el ovs-configurator del nodo la borra al revivir (re-set de
                # switch:alive), evitando que un falso positivo lo deje fantasma.
                # TTL 900s > NODE_STALE_GRACE (600s) del dashboard: asi la marca cubre
                # toda la ventana de gracia y el nodo muerto NO reaparece en el mapa
                # cuando la marca caducaria antes que la gracia (evita flicker).
                self.redis.set(f"switch:dead:{raw_dpid}", "1", ex=900)
            except redis.RedisError:
                pass
            self._cache_delete_prefix("path_next_hop:")
            # Forzar recomputo del grafo/MST para reinstalar flows por la ruta
            # alternativa sin esperar al ciclo periodico.
            try:
                self.topology_manager.last_mst_computation = 0
                if self.topology_manager.recompute():
                    self._forwarding_flush_pending = True
            except Exception:
                pass
            # Disparar YA el barrido de flows de forwarding stale (los que egresan
            # hacia el tunel del nodo muerto y harian blackhole). El borrado ocurre en
            # flow_stats_reply_handler cuando _forwarding_flush_pending esta activo;
            # normalmente se espera al poll de _monitor_datapaths (cada 5s), lo que
            # sumaba varios segundos al reroute. Pedir las stats AQUI lo hace inmediato.
            if self._forwarding_flush_pending:
                for datapath in list(self.datapaths.values()):
                    try:
                        parser = datapath.ofproto_parser
                        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                    except Exception:
                        pass
            for dpid in list(self.datapaths.keys()):
                mac_table_key = f"mac_to_port:{dpid}"
                try:
                    macs = self.redis.hkeys(mac_table_key) or []
                except redis.RedisError:
                    continue
                for mac in macs:
                    try:
                        port = self.redis.hget(mac_table_key, mac)
                    except redis.RedisError:
                        continue
                    if not port:
                        continue
                    try:
                        ports = self._get_switch_ports(dpid)
                    except redis.RedisError:
                        continue
                    port_name = str(ports.get(str(port), ""))
                    if port_name.startswith("vx"):
                        peer_ip = self._vxlan_port_to_ip(port_name)
                        ip_to_dpid = {
                            str(ip).replace(".", ""): self._raw_dpid_to_decimal(k)
                            for k, ip in self._get_node_ips().items()
                        }
                        peer_dpid = ip_to_dpid.get(peer_ip)
                        if peer_dpid == target_dpid:
                            try:
                                self.redis.hdel(mac_table_key, mac)
                                self.logger.info(
                                    "Cleared mac_to_port for dead switch: dpid=%s mac=%s port=%s",
                                    dpid, mac, port,
                                )
                            except redis.RedisError:
                                pass
                try:
                    self.redis.delete(f"mac_to_port:{target_dpid}")
                except redis.RedisError:
                    pass
        except Exception as e:
            self.logger.warning("Error clearing mac_to_port for dead switch %s: %s", raw_dpid, e)

    def _publish_switch_dead(self, raw_dpid):
        try:
            self.redis.publish("switch:dead", raw_dpid)
        except redis.RedisError as e:
            self.logger.warning("Failed to publish switch:dead for %s: %s", raw_dpid, e)

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

    def _get_switch_mac_map(self):
        def load_switch_mac_map():
            try:
                switches = self.redis.smembers('topology:switches')
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while reading switch MAC map: %s", e)
                return {}
            mac_map = {}
            for dpid in switches:
                try:
                    mac_hex = hex(int(dpid))[2:].zfill(12)
                    mac_fmt = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
                    mac_map[mac_fmt] = dpid
                except Exception:
                    pass
            return mac_map
        return self._cached("switch_mac_map", RYU_CACHE_WORKER_MACS_SECONDS, load_switch_mac_map)

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

    def _vxlan_port_to_ip(self, port_name):
        if port_name.startswith("vx"):
            ip = port_name[2:]
            if ip.startswith("122"):
                return f"192.168.{ip}"
            return f"192.168.122.{int(ip[-3:])}"
        return None

    def _ip_to_dpid(self, node_ips):
        return {
            str(ip).replace(".", ""): self._raw_dpid_to_decimal(k)
            for k, ip in node_ips.items()
        }

    def _raw_dpid_to_decimal(self, raw_dpid):
        try:
            return int(raw_dpid, 16)
        except Exception:
            return 0

    def _decimal_dpid_to_raw(self, dpid):
        return hex(int(dpid))[2:].zfill(16)

    def _is_switch_alive(self, dpid):
        try:
            raw_dpid = self._decimal_dpid_to_raw(dpid) if str(dpid).isdigit() else str(dpid)
            return self.redis.get(f"switch:alive:{dpid}") == "1" or self.redis.get(f"switch:alive:{raw_dpid}") == "1"
        except redis.RedisError:
            return False

    def _active_switch_count(self):
        try:
            return len(self._active_switch_dpids())
        except redis.RedisError:
            return len(self.datapaths)

    def _active_switch_dpids(self):
        active = set()
        for raw_dpid in self.redis.hkeys("topology:node_ips") or []:
            if self._is_switch_alive(raw_dpid):
                active.add(str(self._raw_dpid_to_decimal(raw_dpid)))
        for dpid in self.redis.smembers("topology:switches") or []:
            if self._is_switch_alive(dpid):
                active.add(str(dpid))
        return active

    def _metric_switch_dpids(self):
        try:
            return self._active_switch_dpids()
        except redis.RedisError:
            return {str(dpid) for dpid in self.datapaths}

    def _is_forwarding_port_alive(self, port_name, dpid):
        if not port_name:
            return False
        if port_name.startswith("vx"):
            peer_ip = self._vxlan_port_to_ip(port_name)
            if not peer_ip:
                return False
            try:
                node_ips = self._get_node_ips()
                ip_to_dpid = self._ip_to_dpid(node_ips)
                peer_dpid_str = ip_to_dpid.get(peer_ip.replace(".", ""))
                if peer_dpid_str and not self._is_switch_alive(peer_dpid_str):
                    return False
                # El peer puede estar VIVO pero el enlace/tunel directo caido
                # (corte de enlace br0): si ya no figura como vecino VXLAN de este
                # switch, el tunel no transporta -> puerto no apto para forwarding.
                # fail-open si vxlan_peers esta vacio (lapso transitorio del
                # heartbeat) para no romper el forwarding sano.
                raw_local = self._decimal_dpid_to_raw(dpid)
                peers = self.redis.hget("topology:vxlan_peers", raw_local) or ""
                if peers and peer_ip not in str(peers).split():
                    return False
                return True
            except Exception:
                pass
        return True

    def _periodic_topology_recompute(self):
        while True:
            try:
                changed = self.topology_manager.recompute()
                if changed:
                    self.logger.info("Topology changed, MST updated. version=%s",
                                     self.topology_manager.topology_version)
                    self._cache_delete_prefix("path_next_hop:")
                    self._forwarding_flush_pending = True
                    self._publish_topology_metrics()
            except Exception as e:
                self.logger.warning("Topology recompute error: %s", e)
            hub.sleep(MST_RECOMPUTE_INTERVAL)

    def _publish_topology_metrics(self):
        try:
            version = self.topology_manager.topology_version
            mst_edges = len(self.topology_manager.mst_edges)
            diameter = -1
            if self.topology_manager.graph and self.topology_manager.graph.number_of_nodes() > 0:
                try:
                    diameter = nx.diameter(self.topology_manager.graph)
                except Exception:
                    pass
            self.logger.info("TOPOLOGY version=%s mst_edges=%s diameter=%s",
                             version, mst_edges, diameter)
        except Exception as e:
            self.logger.warning("Error publishing topology metrics: %s", e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        try:
            n_ports = len(ev.msg.ports) if hasattr(ev.msg, 'ports') else 0
        except Exception:
            n_ports = 0
        self.logger.info("Switch connected: dpid=%s ports=%s", datapath.id, n_ports)

        try:
            self.redis.sadd("topology:switches", str(datapath.id))
            raw_dpid = self._decimal_dpid_to_raw(datapath.id)
            mac_addr = _mac_from_dpid(raw_dpid)
            self.redis.hset("topology:node_names", raw_dpid, NODE_NAME)
            node_ip = os.environ.get("NODE_IP", "")
            if node_ip:
                self.redis.hset("topology:node_ips", raw_dpid, node_ip)
            self.logger.info("Registered switch %s (mac=%s) in Redis", datapath.id, mac_addr)
        except redis.RedisError as e:
            self.logger.warning("Redis error registering switch: %s", e)

        ports = {}
        ports_iter = getattr(ev.msg, 'ports', None) or {}
        for port_no, port in ports_iter.items():
            if port_no > 0xffffff00:
                continue
            port_name = port.name.decode() if isinstance(port.name, bytes) else port.name
            ports[str(port_no)] = port_name
        if ports:
            try:
                pipe = self.redis.pipeline()
                pipe.delete(f"switch_ports:{datapath.id}")
                pipe.hset(f"switch_ports:{datapath.id}", mapping={k: v for k, v in ports.items()})
                pipe.execute()
            except redis.RedisError as e:
                self.logger.warning("Redis error saving switch ports: %s", e)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0)

        self._install_telemetry_guard(datapath, ports)

    def _install_telemetry_guard(self, datapath, ports):
        """Desvia la telemetria (UDP->10.0.0.1:5555) de cada puerto de guest al
        controlador para validar su identidad L2 antes de entregarla al host.

        Sin esto, el flow `priority=200,ip,nw_dst=10.0.0.1 -> LOCAL` del
        ovs-sdn-initializer entrega la telemetria directo al collector sin que Ryu
        vea la MAC Ethernet real: un atacante que forje la IP/device_id de un meter
        legitimo (con HMAC valido) pasaria. El divert (prioridad > 200) fuerza
        Packet-In; `_evaluate_security_threats` decide allow (flow a LOCAL) o drop.
        Solo afecta puertos de guest (no vxlan, no LOCAL); el resto del trafico al
        gateway sigue por el flow LOCAL original.
        """
        if not (SECURITY_ENFORCE and SECURITY_TELEMETRY_GUARD):
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        for port_no_str, port_name in (ports or {}).items():
            try:
                port_no = int(port_no_str)
            except (TypeError, ValueError):
                continue
            if port_no >= ofproto_v1_3.OFPP_MAX:
                continue
            if str(port_name).startswith("vx"):
                continue
            match = parser.OFPMatch(
                in_port=port_no, eth_type=0x0800, ip_proto=17,
                ipv4_dst=GUEST_GATEWAY_IP, udp_dst=TELEMETRY_UDP_PORT,
            )
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_ADD,
                priority=SECURITY_DIVERT_PRIORITY, match=match, instructions=inst,
            )
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ports = {}
        for port in ev.msg.body:
            if port.port_no > 0xffffff00:
                continue
            port_name = port.name.decode() if isinstance(port.name, bytes) else port.name
            ports[str(port.port_no)] = port_name
        if ports:
            try:
                pipe = self.redis.pipeline()
                pipe.delete(f"switch_ports:{datapath.id}")
                pipe.hset(f"switch_ports:{datapath.id}", mapping={k: v for k, v in ports.items()})
                pipe.execute()
            except redis.RedisError as e:
                self.logger.warning("Redis error saving port desc stats: %s", e)
            # Reafirmar el guard de telemetria periodicamente (idempotente): cubre
            # reconexiones de OVS o flushes de flujos que pudieran borrar el divert.
            self._install_telemetry_guard(datapath, ports)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        desc = msg.desc
        port_no = desc.port_no
        if port_no > 0xffffff00:
            return
        port_name = desc.name.decode() if isinstance(desc.name, bytes) else desc.name
        reason = msg.reason
        ofproto = datapath.ofproto
        key = f"switch_ports:{datapath.id}"
        try:
            if reason == ofproto.OFPPR_DELETE:
                self.redis.hdel(key, str(port_no))
                self.logger.info("Port removed from switch_ports: dpid=%s port=%s name=%s",
                                 datapath.id, port_no, port_name)
            else:
                self.redis.hset(key, str(port_no), port_name)
                self.logger.info("Port updated in switch_ports: dpid=%s port=%s name=%s reason=%s",
                                 datapath.id, port_no, port_name, reason)
                self._install_telemetry_guard(datapath, {str(port_no): port_name})
        except redis.RedisError as e:
            self.logger.warning("Redis error updating port status: %s", e)

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
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.packet_in_total[dpid] = self.packet_in_total.get(dpid, 0) + 1

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        mac_table_key = f"mac_to_port:{dpid}"

        try:
            ports = self._get_switch_ports(dpid)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while reading ports for %s: %s", dpid, e)
            ports = {}
        in_port_name = str(ports.get(str(in_port), ""))

        udp_pkt = pkt.get_protocol(udp.udp)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        src_ip = ip_pkt.src if ip_pkt else (arp_pkt.src_ip if arp_pkt else "")

        # Anti-spoofing: validar identidad L2/L3 de paquetes de guests ANTES de
        # aprender MAC/ubicacion en Redis, para no envenenar el estado compartido
        # con datos falsificados (MAC/IP/ARP spoofing). Un paquete malicioso se
        # registra como evento y se silencia con un drop flow de alta prioridad.
        allowed, reason, detail = self._evaluate_security_threats(
            eth, ip_pkt, arp_pkt, udp_pkt, dpid, in_port, in_port_name
        )
        if not allowed:
            # Un dispositivo DESCONOCIDO (mac_not_registered) no suplanta ninguna
            # identidad/IP registrada: se registra como observacion pero NO se
            # dropea, para que aparezca en Operaciones y un operador pueda darlo de
            # alta (su telemetria llega al collector, fail-closed hasta el registro).
            # La suplantacion activa de identidades/IP conocidas si se bloquea.
            enforce = SECURITY_DROP_UNREGISTERED if reason == "mac_not_registered" else True
            enforce = enforce and not SECURITY_LEARNING_MODE
            self._record_security_event(reason, src, src_ip, dpid, in_port, detail, enforced=enforce)
            if enforce:
                self._drop_guest_packet(datapath, in_port, src, reason)
                return

        try:
            self.redis.hset(mac_table_key, src, in_port)
            self.redis.set(f"active_mac:{dpid}:{src}", "1", ex=180)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while learning MAC %s on %s: %s", src, dpid, e)

        known_worker_macs = self._known_worker_macs()
        if (
            src not in known_worker_macs and
            in_port != ofproto.OFPP_LOCAL and
            not in_port_name.startswith("vx")
        ):
            try:
                self.redis.hset("topology:guest_locations", src, f"{dpid}:{in_port}")
            except redis.RedisError as e:
                self.logger.warning("Redis unavailable while updating guest location: %s", e)

        # Telemetria guest->gateway VALIDADA (llego via el divert del guard de
        # telemetria): entregarla al host (LOCAL) e instalar un allow por fuente.
        # Llegar aqui implica que _evaluate_security_threats la dejo pasar; el
        # spoofing (p.ej. MAC falsa con IP de SM1) ya fue bloqueado arriba.
        if (
            ip_pkt is not None and udp_pkt is not None
            and str(ip_pkt.dst) == GUEST_GATEWAY_IP
            and getattr(udp_pkt, "dst_port", 0) == TELEMETRY_UDP_PORT
            and in_port != ofproto.OFPP_LOCAL
            and not in_port_name.startswith("vx")
        ):
            self._deliver_gateway_telemetry(datapath, in_port, src, msg)
            return

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            is_dup = self.arp_handler.is_duplicate(
                dpid, src, arp_pkt.src_ip, arp_pkt.dst_ip, arp_pkt.opcode
            )
            if is_dup:
                self.logger.debug(
                    "Dropping duplicate ARP: dpid=%s %s %s -> %s",
                    dpid, src, arp_pkt.src_ip, arp_pkt.dst_ip,
                )
                return

            proxy_reply, should_flood = self.arp_handler.handle_arp_request(
                datapath, in_port, src, arp_pkt.src_ip, arp_pkt.dst_ip, parser
            )

            if proxy_reply:
                return

            if should_flood:
                self._do_controlled_flood(datapath, in_port, msg.data, ports, dpid, include_local=False)
                return

        if arp_pkt and arp_pkt.opcode == arp.ARP_REPLY:
            self.arp_handler.learn_ip(src, arp_pkt.src_ip)
            self.arp_handler.learn_request_location(dpid, in_port, src)
            self.arp_handler.mark_arp(dpid, src, arp_pkt.src_ip, arp_pkt.src_ip, arp.ARP_REPLY)

        # For known guest destinations always use Dijkstra (guest_locations → topology).
        # mac_to_port learns source MACs via MST flood, so a guest MAC may be recorded
        # under the flood-arrival port rather than the optimal direct VXLAN port.
        # Calling _resolve_guest_out_port first prevents stale flood-learned entries
        # from overriding the Dijkstra-computed optimal path.
        guest_location = self._resolve_guest_out_port(dpid, dst)
        if guest_location:
            out_port = guest_location
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return

        # Fallback: mac_to_port L2 learning for non-guest MACs (worker bridge MACs, etc.)
        try:
            out_port_str = self.redis.hget(mac_table_key, dst)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while reading destination %s on %s: %s", dst, dpid, e)
            out_port_str = None

        if out_port_str and str(out_port_str) not in ports:
            try:
                self.redis.hdel(mac_table_key, dst)
            except redis.RedisError:
                pass
            out_port_str = None

        if out_port_str and not self._is_forwarding_port_alive(str(ports.get(str(out_port_str), "")), dpid):
            try:
                self.redis.hdel(mac_table_key, dst)
            except redis.RedisError:
                pass
            out_port_str = None

        if out_port_str:
            out_port = int(out_port_str)
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return

        self._do_controlled_flood(datapath, in_port, msg.data, ports, datapath.id)

    def _do_controlled_flood(self, datapath, in_port, packet_data, ports, dpid=None, include_local=True):
        """Send a broadcast packet only through the logical spanning tree.

        The MST is published by TopologyManager. This function:
        - Excludes the incoming port explicitly (so the source never
          receives its own broadcast back).
        - Excludes OFPP_CONTROLLER.
        - Only floods VXLAN ports whose peer is reachable via an MST edge,
          preventing cycles regardless of physical ring topology.
        - Always includes local guest ports (ens*, br-*); these cannot form
          an L2 loop with any other switch.
        - Optionally includes OFPP_LOCAL for DHCP/broadcast consumers on the
          bridge host; ARP unknown flooding disables it.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid if dpid is not None else datapath.id

        bcast_ports = self.broadcast_controller.get_broadcast_ports(
            dpid, in_port, ports
        )
        if not bcast_ports:
            self.logger.debug("No broadcast ports available from dpid=%s in_port=%s",
                              dpid, in_port)
            return

        self.broadcast_controller.metrics["flood"] += 1

        actions = [parser.OFPActionOutput(p) for p in bcast_ports if p != in_port]
        if include_local and in_port != ofproto.OFPP_LOCAL:
            actions.append(parser.OFPActionOutput(ofproto.OFPP_LOCAL))

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=packet_data,
        )
        datapath.send_msg(out)
        self.logger.debug(
            "Controlled flood: dpid=%s in_port=%s -> ports=%s",
            dpid, in_port, bcast_ports,
        )

    def _resolve_guest_out_port(self, current_dpid, dst_mac):
        try:
            guest_locations = self.redis.hgetall("topology:guest_locations") or {}
        except redis.RedisError as e:
            self.logger.warning("Redis error resolving guest location for %s: %s", dst_mac, e)
            return None

        location = guest_locations.get(dst_mac)
        if not location or ":" not in location:
            return None
        dst_dpid, dst_port = location.split(":", 1)
        current_dpid = str(current_dpid)
        if current_dpid == str(dst_dpid):
            return int(dst_port)

        path_cache_key = f"path_next_hop:{current_dpid}:{dst_dpid}"
        cached = self.cache.get(path_cache_key)
        if cached and cached[0] > time.time():
            try:
                out_port = int(cached[1])
                ports = self._get_switch_ports(current_dpid)
                port_name = str(ports.get(str(out_port), ""))
                if port_name and self._is_forwarding_port_alive(port_name, current_dpid):
                    return out_port
            except Exception:
                pass
            self.cache.pop(path_cache_key, None)

        node_ips = self._get_node_ips()
        src_ip = self._node_ip_for_dpid(current_dpid, node_ips)
        dst_ip = self._node_ip_for_dpid(dst_dpid, node_ips)

        if not src_ip or not dst_ip:
            return None

        src_dpid_int = self._raw_dpid_to_decimal(src_ip.replace(".", ""))
        dst_dpid_int = self._raw_dpid_to_decimal(dst_ip.replace(".", ""))

        if current_dpid != str(src_dpid_int):
            return None

        path = self.topology_manager.compute_dijkstra(src_dpid_int, dst_dpid_int)
        if not path or len(path) < 2:
            return None

        if path[0] != src_dpid_int:
            return None

        next_dpid = path[1]
        _, dst_port_num = self.topology_manager.get_switch_ports_for_link(src_dpid_int, next_dpid)

        if dst_port_num is None:
            node_ips_raw = self._get_node_ips()
            ip_to_dpid = self._ip_to_dpid(node_ips_raw)
            ports = self._get_switch_ports(src_dpid_int)
            for port_no, port_name in ports.items():
                port_name = str(port_name)
                if port_name.startswith("vx"):
                    peer_ip_raw = port_name[2:]
                    peer_ip = self._vxlan_port_to_ip(port_name)
                    if not peer_ip:
                        continue
                    peer_dpid = ip_to_dpid.get(peer_ip.replace(".", ""))
                    if peer_dpid == next_dpid:
                        dst_port_num = int(port_no)
                        break

        if dst_port_num is None:
            return None

        self.cache[path_cache_key] = (time.time() + RYU_CACHE_PATH_SECONDS, str(dst_port_num))

        installed = self.forwarding_engine.install_path_flows(
            src_dpid_int, dst_dpid_int, dst_mac, self.datapaths
        )
        if installed:
            self.logger.info("Path flows installed for %s -> %s (cached next_hop=%s)",
                             current_dpid, dst_dpid, dst_port_num)

        return dst_port_num

    def _node_ip_for_dpid(self, dpid, node_ips):
        for raw_dpid, ip in node_ips.items():
            if str(self._raw_dpid_to_decimal(raw_dpid)) == str(dpid):
                return raw_dpid
        return None

    def _monitor_datapaths(self):
        unresponsive = {}
        while True:
            self.logger.debug("Ryu monitor heartbeat: datapaths=%d", len(self.datapaths))
            for datapath in list(self.datapaths.values()):
                try:
                    parser = datapath.ofproto_parser
                    datapath.send_msg(parser.OFPPortDescStatsRequest(datapath, 0))
                    datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
                    datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY))
                    unresponsive.pop(datapath.id, None)
                except Exception as e:
                    self.logger.warning("Error requesting OpenFlow stats: %s", e)
                    unresponsive[datapath.id] = unresponsive.get(datapath.id, 0) + 1
                    if unresponsive[datapath.id] >= 3:
                        raw_dpid = self._decimal_dpid_to_raw(datapath.id)
                        self.logger.warning("Switch %s unresponsive, broadcasting death", datapath.id)
                        self._publish_switch_dead(raw_dpid)
                        self._clear_mac_to_port_for_dead_switch(raw_dpid)
                        unresponsive.pop(datapath.id, None)
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
        try:
            guest_locations = self.redis.hgetall("topology:guest_locations") or {}
        except redis.RedisError:
            guest_locations = {}
        for stat in ev.msg.body:
            if stat.priority <= 0:
                continue
            # Si el destino del flow es un guest que ahora reside LOCALMENTE en
            # este switch, el flow debe sacarlo por su puerto local; cualquier
            # otro puerto (p.ej. un tunel VXLAN viejo) es stale tras la
            # reubicacion del guest y provoca blackhole.
            eth_dst = stat.match.get("eth_dst", "")
            local_port = None
            loc = str(guest_locations.get(eth_dst, "")) if eth_dst else ""
            if loc.startswith(f"{dpid}:"):
                try:
                    local_port = int(loc.split(":", 1)[1])
                except (ValueError, IndexError):
                    local_port = None
            # Flush por cambio de topologia: borrar flows de forwarding de guests
            # (priority 1 = aprendido por packet-in, 10 = install_path_flows) para
            # que se recomputen via Dijkstra sobre el grafo nuevo. Solo afecta
            # flows con eth_dst; no toca table-miss, ARP, gateway ni LLDP.
            delete_flow = bool(self._forwarding_flush_pending and eth_dst and stat.priority in (1, 10))
            for instruction in getattr(stat, "instructions", []):
                if delete_flow:
                    break
                for action in getattr(instruction, "actions", []):
                    out_port = getattr(action, "port", None)
                    if out_port is None:
                        continue
                    port_name = str(ports.get(str(out_port), ""))
                    if port_name.startswith("vx") and not self._is_forwarding_port_alive(port_name, dpid):
                        delete_flow = True
                        break
                    if local_port is not None and out_port < 0xffffff00 and out_port != local_port:
                        delete_flow = True
                        break
                    # (3) el puerto de salida ya no existe en el switch (ofport
                    #     obsoleto tras renumeracion de OVS en un reinicio): el
                    #     flow tira el trafico a un puerto inexistente -> borrar
                    #     para que Ryu reinstale el camino con el puerto vigente.
                    if ports and out_port < 0xffffff00 and str(out_port) not in ports:
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
            eth_dst = stat.match.get("eth_dst", "")
            if eth_dst:
                try:
                    self.redis.hdel(f"mac_to_port:{dpid}", eth_dst)
                    self.logger.info("Cleared mac_to_port for deleted flow: dpid=%s mac=%s", dpid, eth_dst)
                except redis.RedisError as e:
                    self.logger.warning("Redis error clearing mac_to_port for flow delete: %s", e)
        self.installed_flows[dpid] = sum(1 for stat in ev.msg.body if stat.priority > 0)
        # El flush por cambio de topologia se aplica de una vez sobre este switch.
        if self._forwarding_flush_pending:
            self._forwarding_flush_pending = False

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

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        self.logger.info("Switch entered: %s", ev.switch)
        self._cache_delete_prefix("path_next_hop:")
        try:
            if self.topology_manager.recompute():
                self._forwarding_flush_pending = True
        except Exception as e:
            self.logger.warning("MST recompute after switch enter failed: %s", e)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        dpid = None
        for port in ev.switch.ports:
            dpid = port.dpid
            break
        if dpid and dpid in self.datapaths:
            del self.datapaths[dpid]
        self.logger.warning("Switch left: %s (dpid=%s)", ev.switch, dpid)
        raw_dpid = self._decimal_dpid_to_raw(dpid) if dpid else None
        if raw_dpid:
            self._publish_switch_dead(raw_dpid)
            self._clear_mac_to_port_for_dead_switch(raw_dpid)
        self._cache_delete_prefix("path_next_hop:")
        try:
            if self.topology_manager.recompute():
                self._forwarding_flush_pending = True
        except Exception as e:
            self.logger.warning("MST recompute after switch leave failed: %s", e)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        self.logger.info("Link added: %s:%s <-> %s:%s", src.dpid, src.port_no, dst.dpid, dst.port_no)
        link_str = f"{src.dpid}:{src.port_no}-{dst.dpid}:{dst.port_no}"
        try:
            # Remove stale entries for this DPID pair before adding the current link.
            existing = self.redis.smembers("topology:links") or set()
            prefix_fwd = f"{src.dpid}:"
            prefix_rev = f"{dst.dpid}:"
            stale = {
                e for e in existing
                if (str(e).startswith(prefix_fwd) and f"-{dst.dpid}:" in str(e))
                or (str(e).startswith(prefix_rev) and f"-{src.dpid}:" in str(e))
            }
            pipe = self.redis.pipeline()
            for s in stale:
                pipe.srem("topology:links", s)
            pipe.sadd("topology:links", link_str)
            cost_src = self.redis.hget("topology:link_cost", f"{src.dpid}:{dst.dpid}") or DEFAULT_LINK_COST
            cost_dst = self.redis.hget("topology:link_cost", f"{dst.dpid}:{src.dpid}") or DEFAULT_LINK_COST
            pipe.hset("topology:link_cost", f"{src.dpid}:{dst.dpid}", cost_src)
            pipe.hset("topology:link_cost", f"{dst.dpid}:{src.dpid}", cost_dst)
            pipe.execute()
            if stale:
                self.logger.info("Removed %d stale links for pair %s<->%s", len(stale), src.dpid, dst.dpid)
        except redis.RedisError as e:
            self.logger.warning("Redis error saving link: %s", e)
        self._cache_delete_prefix("path_next_hop:")
        try:
            if self.topology_manager.recompute():
                self._forwarding_flush_pending = True
        except Exception as e:
            self.logger.warning("MST recompute after link add failed: %s", e)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        self.logger.warning("Link deleted: %s:%s <-> %s:%s", src.dpid, src.port_no, dst.dpid, dst.port_no)
        link_str = f"{src.dpid}:{src.port_no}-{dst.dpid}:{dst.port_no}"
        try:
            self.redis.srem("topology:links", link_str)
            self.redis.hdel("topology:link_cost", f"{src.dpid}:{dst.dpid}")
            self.redis.hdel("topology:link_cost", f"{dst.dpid}:{src.dpid}")
        except redis.RedisError as e:
            self.logger.warning("Redis error removing link: %s", e)
        self._cache_delete_prefix("path_next_hop:")
        self._invalidate_flows_via_link(src.dpid, dst.dpid)
        try:
            if self.topology_manager.recompute():
                self._forwarding_flush_pending = True
        except Exception as e:
            self.logger.warning("MST recompute after link delete failed: %s", e)

    def _invalidate_flows_via_link(self, dpid1, dpid2):
        for datapath in list(self.datapaths.values()):
            try:
                ports = self._get_switch_ports(datapath.id)
            except redis.RedisError:
                continue
            for port_no, port_name in ports.items():
                port_name = str(port_name)
                if port_name.startswith("vx"):
                    peer_ip = self._vxlan_port_to_ip(port_name)
                    node_ips = self._get_node_ips()
                    ip_to_dpid = self._ip_to_dpid(node_ips)
                    peer_dpid = ip_to_dpid.get(peer_ip.replace(".", ""))
                    if peer_dpid in (dpid1, dpid2):
                        parser = datapath.ofproto_parser
                        match = parser.OFPMatch(in_port=int(port_no))
                        mod = parser.OFPFlowMod(
                            datapath=datapath,
                            command=datapath.ofproto.OFPFC_DELETE_STRICT,
                            out_port=datapath.ofproto.OFPP_ANY,
                            out_group=datapath.ofproto.OFPG_ANY,
                            priority=100,
                            match=match,
                        )
                        datapath.send_msg(mod)
                        self.logger.info("Drop flow installed on dead port: dpid=%s port=%s",
                                         datapath.id, port_no)
            self.logger.info("Invalidated flows via link %s <-> %s", dpid1, dpid2)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=FORWARDING_FLOW_IDLE_TIMEOUT, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_ADD,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

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
                    return
            current_ip = self.redis.hget("topology:guest_ips", mac)
            if current_ip != ip_addr:
                self.redis.hset("topology:guest_ips", mac, ip_addr)
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while learning guest IP %s=%s: %s", mac, ip_addr, e)

    def _security_device_id_for_ip(self, ip_addr):
        def load():
            try:
                return self.redis.get(f"security:ip_to_device:{ip_addr}")
            except redis.RedisError:
                return None
        return self._cached(f"security:ip_to_device:{ip_addr}", RYU_CACHE_SECURITY_SECONDS, load)

    def _dhcp_lease_for_mac(self, mac):
        try:
            return self.redis.get(f"dhcp:bind:{mac}")
        except redis.RedisError:
            return None

    def _evaluate_security_threats(self, eth, ip_pkt, arp_pkt, udp_pkt, dpid, in_port, in_port_name):
        """Valida la identidad L2/L3 de un paquete que ingresa por un puerto de guest.

        Devuelve (allowed, reason, detail). allowed=True deja pasar el paquete;
        allowed=False indica spoofing o violacion de politica (el caller registra
        el evento e instala un drop flow). Solo se evaluan paquetes de guests: el
        overlay VXLAN, el puerto LOCAL del bridge (gateway/DHCP) y la infra
        (MAC de worker) quedan exentos. fail-open ante incertidumbre de estado
        para no romper el plano de datos legitimo ante un blip de Redis.
        """
        if not SECURITY_ENFORCE:
            return True, None, None

        if in_port == ofproto_v1_3.OFPP_LOCAL:
            return True, None, None
        if in_port_name.startswith("vx"):
            return True, None, None

        src_mac = str(eth.src).lower()
        if src_mac in self._known_worker_macs():
            return True, None, None

        # DHCP/bootstrap: permitir DISCOVER/REQUEST/replies aun de MAC no registrada.
        if udp_pkt is not None and (
            getattr(udp_pkt, "src_port", 0) in (67, 68)
            or getattr(udp_pkt, "dst_port", 0) in (67, 68)
        ):
            return True, None, None

        is_arp = arp_pkt is not None
        if is_arp:
            src_ip = str(arp_pkt.src_ip or "")
        elif ip_pkt is not None:
            src_ip = str(ip_pkt.src or "")
        else:
            src_ip = ""

        # --- ARP: comprobaciones estructurales (siempre maliciosas) ---
        if is_arp:
            arp_hwsrc = str(getattr(arp_pkt, "src_mac", "") or "").lower()
            if arp_hwsrc and arp_hwsrc != src_mac:
                return False, "arp_mac_mismatch", {
                    "eth_src": src_mac, "arp_hwsrc": arp_hwsrc, "arp_psrc": src_ip,
                }
            if src_ip == GUEST_GATEWAY_IP:
                return False, "arp_gateway_spoof", {"arp_psrc": src_ip, "src_mac": src_mac}

        device = self._get_security_device_by_mac(src_mac)
        my_id = device.get("device_id") if device else None

        # IP origen reclamada por OTRO dispositivo registrado (uso de IP ajena).
        # Nota: 10.0.0.1 (gateway) NO se exime aqui: si una IP de gateway llega
        # por un puerto de guest es spoofing (el gateway real entra por LOCAL).
        if src_ip and src_ip != "0.0.0.0":
            ip_owner = self._security_device_id_for_ip(src_ip)
            if ip_owner and ip_owner != my_id:
                reason = "arp_ip_mismatch" if is_arp else "ip_claim_conflict"
                return False, reason, {
                    "src_ip": src_ip, "src_mac": src_mac, "ip_owner": ip_owner,
                }

        # MAC no registrada en puerto de guest (no era DHCP/LLDP/infra) -> bloquear.
        if device is None:
            return False, "mac_not_registered", {"src_mac": src_mac, "src_ip": src_ip}

        status = str(device.get("status", "")).lower()
        if status and status != "authorized":
            reason = "status_blocked" if status == "blocked" else (
                "status_quarantined" if status in ("quarantine", "quarantined")
                else f"status_{status}"
            )
            return False, reason, {
                "src_mac": src_mac, "device_id": my_id, "status": status,
            }

        # IP origen debe coincidir con la IP registrada (o lease DHCP) del MAC.
        # Un guest que use 10.0.0.1 como IP origen cae aqui como ip_mismatch
        # (su IP registrada nunca es la del gateway).
        expected_ip = device.get("ip") or self._dhcp_lease_for_mac(src_mac)
        if src_ip and src_ip != "0.0.0.0" and expected_ip and src_ip != expected_ip:
            reason = "arp_ip_mismatch" if is_arp else "ip_mismatch"
            return False, reason, {
                "src_mac": src_mac, "src_ip": src_ip,
                "expected_ip": expected_ip, "device_id": my_id,
            }

        # MAC registrada pero observada en dpid/in_port distinto al de alta.
        if SECURITY_ENFORCE_LOCATION:
            reg_dpid = str(device.get("dpid") or "")
            reg_port = str(device.get("in_port") or "")
            if reg_dpid and reg_dpid != str(dpid):
                return False, "mac_location_mismatch", {
                    "src_mac": src_mac, "device_id": my_id,
                    "expected_dpid": reg_dpid, "observed_dpid": str(dpid),
                }
            if reg_port and reg_port != str(in_port):
                return False, "mac_location_mismatch", {
                    "src_mac": src_mac, "device_id": my_id,
                    "expected_in_port": reg_port, "observed_in_port": str(in_port),
                }

        return True, None, None

    def _record_security_event(self, reason, src_mac, src_ip, dpid, in_port, detail=None, enforced=None):
        if not reason:
            return
        if enforced is None:
            enforced = not SECURITY_LEARNING_MODE
        self.security_events_total[reason] = self.security_events_total.get(reason, 0) + 1
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "src_mac": str(src_mac or ""),
            "src_ip": str(src_ip or ""),
            "dpid": str(dpid),
            "in_port": str(in_port),
            "node": NODE_NAME,
            "component": "ryu",
            "enforced": enforced,
        }
        if detail:
            event["detail"] = detail
        try:
            payload = json.dumps(event)
            pipe = self.redis.pipeline()
            pipe.lpush("security:events", payload)
            pipe.ltrim("security:events", 0, SECURITY_EVENTS_MAXLEN - 1)
            pipe.incr(f"security:event_counter:{reason}")
            pipe.incr("security:event_counter:total")
            pipe.hset("security:last_event", str(src_mac or src_ip or "unknown"), payload)
            pipe.execute()
        except redis.RedisError as e:
            self.logger.warning("Redis unavailable while recording security event %s: %s", reason, e)
        self.logger.warning(
            "SECURITY %s reason=%s mac=%s ip=%s dpid=%s in_port=%s detail=%s",
            "BLOCK" if enforced else ("LEARN" if SECURITY_LEARNING_MODE else "OBSERVE"),
            reason, src_mac, src_ip, dpid, in_port, detail,
        )

    def _drop_guest_packet(self, datapath, in_port, src_mac, reason):
        """Instala un flow de drop de alta prioridad para la fuente ofensiva,
        evitando un Packet-In continuo. El flow caduca solo (hard_timeout) para
        re-evaluar si el dispositivo se autoriza/corrige mas adelante."""
        try:
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(in_port=int(in_port), eth_src=str(src_mac))
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_ADD,
                priority=SECURITY_DROP_PRIORITY,
                match=match,
                instructions=[],  # sin instrucciones => drop
                idle_timeout=0,
                hard_timeout=SECURITY_DROP_HARD_TIMEOUT,
            )
            datapath.send_msg(mod)
            self.flow_mod_total[datapath.id] = self.flow_mod_total.get(datapath.id, 0) + 1
            self.logger.info(
                "Drop flow installed: dpid=%s in_port=%s src=%s reason=%s",
                datapath.id, in_port, src_mac, reason,
            )
        except Exception as e:
            self.logger.warning("Failed to install drop flow for %s: %s", src_mac, e)

    def _deliver_gateway_telemetry(self, datapath, in_port, src_mac, msg):
        """Telemetria guest->gateway ya validada (llego via el divert del guard):
        la entrega al host por LOCAL e instala un flow de allow por fuente
        (prioridad sobre el divert) para que las siguientes lecturas del meter
        legitimo no vuelvan a pasar por el controlador. idle_timeout re-valida si
        el meter cambia de identidad/ubicacion."""
        try:
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(
                in_port=int(in_port), eth_src=str(src_mac), eth_type=0x0800,
                ip_proto=17, ipv4_dst=GUEST_GATEWAY_IP, udp_dst=TELEMETRY_UDP_PORT,
            )
            actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
            self.add_flow(datapath, SECURITY_DROP_PRIORITY, match, actions,
                          idle_timeout=SECURITY_TELEMETRY_ALLOW_IDLE, hard_timeout=0)
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=int(in_port),
                actions=actions, data=msg.data,
            )
            datapath.send_msg(out)
        except Exception as e:
            self.logger.warning("Failed to deliver gateway telemetry from %s: %s", src_mac, e)

    def _is_policy_block_reason(self, reason):
        return False

    def _record_policy_block(self, *args, **kwargs):
        pass

    def _guest_mac_for_ip(self, ip_addr):
        try:
            return self.redis.hget("topology:guest_ips", ip_addr)
        except redis.RedisError:
            return None

    def _start_metrics_server(self):
        try:
            from wsgiref.simple_server import make_server
            from wsgiref.simple_server import WSGIRequestHandler
        except ImportError:
            self.logger.warning("wsgiref not available, metrics server disabled")
            return
        if not self._is_metrics_exporter():
            return

        class MetricsRequestHandler(WSGIRequestHandler):
            def log_message(self, format, *args):
                if self.path.startswith("/metrics"):
                    return
                super().log_message(format, *args)

        def app(environ, start_response):
            path = environ.get("PATH_INFO", "")
            if path == "/metrics":
                body = self._generate_metrics().encode("utf-8")
                start_response("200 OK", [("Content-Type", "text/plain; version=0.0.4")])
                return [body]
            start_response("404 Not Found", [])
            return []

        try:
            httpd = make_server("0.0.0.0", METRICS_PORT, app, handler_class=MetricsRequestHandler)
            self.logger.info("Metrics server listening on port %d", METRICS_PORT)
            httpd.serve_forever()
        except Exception as e:
            self.logger.warning("Metrics server failed: %s", e)

    def _generate_metrics(self):
        lines = []
        uptime = datetime.utcnow().timestamp() - self.metrics_started_at
        lines.append(f"# HELP ryu_uptime_seconds Uptime of this Ryu instance")
        lines.append(f"# TYPE ryu_uptime_seconds gauge")
        lines.append(f"ryu_uptime_seconds{{node=\"{NODE_NAME}\"}} {uptime:.0f}")

        lines.append(f"# HELP ryu_packet_in_total Total Packet-In events")
        lines.append(f"# TYPE ryu_packet_in_total counter")
        metric_dpids = self._metric_switch_dpids()
        packet_counts = {str(dpid): count for dpid, count in self.packet_in_total.items()}
        for dpid in sorted(metric_dpids | set(packet_counts)):
            lines.append(f'ryu_packet_in_total{{dpid="{dpid}"}} {packet_counts.get(dpid, 0)}')

        lines.append(f"# HELP ryu_installed_flows Installed forwarding flows per switch")
        lines.append(f"# TYPE ryu_installed_flows gauge")
        flow_counts = {str(dpid): count for dpid, count in self.installed_flows.items()}
        for dpid in sorted(metric_dpids | set(flow_counts)):
            lines.append(f'ryu_installed_flows{{dpid="{dpid}"}} {flow_counts.get(dpid, 0)}')

        active_switches = self._active_switch_count()
        lines.append(f"# HELP ryu_active_nodes Number of active switches")
        lines.append(f"# TYPE ryu_active_nodes gauge")
        lines.append(f"ryu_active_nodes {active_switches}")
        lines.append(f"# HELP ryu_active_switches Number of active switches")
        lines.append(f"# TYPE ryu_active_switches gauge")
        lines.append(f"ryu_active_switches {active_switches}")

        lines.append(f"# HELP ryu_arp_proxy_total Total ARP replies sent by controller proxy")
        lines.append(f"# TYPE ryu_arp_proxy_total counter")
        lines.append(f'ryu_arp_proxy_total{{node="{NODE_NAME}"}} {self.arp_handler.metrics.get("proxy", 0)}')
        lines.append(f"# HELP ryu_arp_flood_total Total ARP requests forwarded via controlled flood")
        lines.append(f"# TYPE ryu_arp_flood_total counter")
        lines.append(f'ryu_arp_flood_total{{node="{NODE_NAME}"}} {self.arp_handler.metrics.get("flood", 0)}')
        lines.append(f"# HELP ryu_arp_dedup_total Total ARP requests dropped as duplicates")
        lines.append(f"# TYPE ryu_arp_dedup_total counter")
        lines.append(f'ryu_arp_dedup_total{{node="{NODE_NAME}"}} {self.arp_handler.metrics.get("dedup", 0)}')
        lines.append(f"# HELP ryu_arp_learn_total Total IP->MAC bindings learned from ARP")
        lines.append(f"# TYPE ryu_arp_learn_total counter")
        lines.append(f'ryu_arp_learn_total{{node="{NODE_NAME}"}} {self.arp_handler.metrics.get("learn", 0)}')
        lines.append(f"# HELP ryu_broadcast_flood_total Total broadcast floods issued by this node")
        lines.append(f"# TYPE ryu_broadcast_flood_total counter")
        lines.append(f'ryu_broadcast_flood_total{{node="{NODE_NAME}"}} {self.broadcast_controller.metrics.get("flood", 0)}')
        lines.append(f"# HELP ryu_broadcast_mst_edges MST edges visible from this node")
        lines.append(f"# TYPE ryu_broadcast_mst_edges gauge")
        lines.append(f'ryu_broadcast_mst_edges{{node="{NODE_NAME}"}} {self.broadcast_controller.metrics.get("mst_edges", 0)}')
        lines.append(f"# HELP ryu_broadcast_ports_blocked Non-MST VXLAN ports skipped during flood")
        lines.append(f"# TYPE ryu_broadcast_ports_blocked counter")
        lines.append(f'ryu_broadcast_ports_blocked{{node="{NODE_NAME}"}} {self.broadcast_controller.metrics.get("ports_blocked", 0)}')

        lines.append(f"# HELP ryu_security_events_total Anti-spoofing blocks/detections (total)")
        lines.append(f"# TYPE ryu_security_events_total counter")
        total_security = sum(self.security_events_total.values())
        lines.append(f'ryu_security_events_total{{node="{NODE_NAME}"}} {total_security}')
        # Nombre/label esperados por el dashboard de Grafana (06-observability.yaml):
        # panel "Eventos de Seguridad (por tipo)" -> ryu_security_events_by_type_total{type=...}
        lines.append(f"# HELP ryu_security_events_by_type_total Anti-spoofing events per type")
        lines.append(f"# TYPE ryu_security_events_by_type_total counter")
        for reason, count in sorted(self.security_events_total.items()):
            lines.append(f'ryu_security_events_by_type_total{{node="{NODE_NAME}",type="{reason}"}} {count}')

        for (dpid, port_no), stats in self.port_stats.items():
            p = stats
            lines.append(f'ryu_port_rx_bytes_total{{dpid="{dpid}",port="{port_no}",name="{p["port_name"]}"}} {p["rx_bytes"]}')
            lines.append(f'ryu_port_tx_bytes_total{{dpid="{dpid}",port="{port_no}",name="{p["port_name"]}"}} {p["tx_bytes"]}')
            lines.append(f'ryu_port_rx_packets_total{{dpid="{dpid}",port="{port_no}",name="{p["port_name"]}"}} {p["rx_packets"]}')
            lines.append(f'ryu_port_tx_packets_total{{dpid="{dpid}",port="{port_no}",name="{p["port_name"]}"}} {p["tx_packets"]}')

        try:
            node_ips = self._get_node_ips()
            topo_version = self.topology_manager.topology_version
            mst_edges = len(self.topology_manager.mst_edges)
            diameter = -1
            if self.topology_manager.graph and self.topology_manager.graph.number_of_nodes() > 0:
                try:
                    diameter = nx.diameter(self.topology_manager.graph)
                except Exception:
                    pass
            lines.append(f"# HELP ryu_topology_version Topology version (increments on MST change)")
            lines.append(f"# TYPE ryu_topology_version counter")
            lines.append(f"ryu_topology_version {topo_version}")
            lines.append(f"# HELP ryu_mst_edges Number of edges in MST")
            lines.append(f"# TYPE ryu_mst_edges gauge")
            lines.append(f"ryu_mst_edges {mst_edges}")
            lines.append(f"# HELP ryu_topology_diameter Graph diameter")
            lines.append(f"# TYPE ryu_topology_diameter gauge")
            lines.append(f"ryu_topology_diameter {diameter}")
            lines.append(f"# HELP ryu_topology_node_info Switch in topology")
            lines.append(f"# TYPE ryu_topology_node_info gauge")
            for raw_dpid, ip in node_ips.items():
                dpid_int = self._raw_dpid_to_decimal(raw_dpid)
                alive = 1 if self._is_switch_alive(dpid_int) else 0
                lines.append(f'ryu_topology_node_info{{dpid="{raw_dpid}",ip="{ip}",alive="{alive}"}} 1')
            lines.append(f"# HELP ryu_topology_edge_info Physical link in topology")
            lines.append(f"# TYPE ryu_topology_edge_info gauge")
            links = self.redis.smembers("topology:links") or set()
            for link in links:
                lines.append(f'ryu_topology_edge_info{{link="{link}"}} 1')
        except Exception as e:
            self.logger.warning("Error generating topology metrics: %s", e)

        return "\n".join(lines) + "\n"
