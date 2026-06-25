# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Cluster Access

All K3s operations go through SSH on Master-1. Never assume local `kubectl` reaches the cluster:

```bash
# Run any kubectl command
python tools/gns3/ssh_k3s.py "kubectl -n sdn-controller get pods -o wide"

# Direct SSH
ssh ubuntu@192.168.122.100   # password: ubuntu
```

The API HA VIP is `10.255.255.1` (kube-vip in **BGP** mode, announced into the L3 fabric). It is reachable from **inside** the fabric (i.e. on the nodes), not from the host — that is why all kubectl goes through `ssh_k3s.py` to run on Master-1. The cluster uses `sudo kubectl` unless `~/.kube/config` is configured for the current user.

## Hot Reload (no image rebuild needed)

Code is mounted via ConfigMaps. Update and restart in one step:

```bash
# Ryu controller
kubectl create configmap ryu-code --from-file=app.py=services/ryu-controller/app.py \
  -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -
kubectl rollout restart ds ryu -n sdn-controller

# meter-collector (web dashboard + telemetry)
# IMPORTANT: the configmap MUST include registry.py — the manifest mounts it
# via subPath (/app/registry.py). Omitting it crashes pods with
# "ModuleNotFoundError: No module named 'registry'".
kubectl create configmap meter-collector-code \
  --from-file=app.py=services/meter-collector/app.py \
  --from-file=registry.py=services/meter-collector/registry.py \
  --from-file=index.html=services/meter-collector/templates/index.html \
  -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -
kubectl rollout restart ds meter-collector -n sdn-controller

# DHCP server
kubectl create configmap dhcp-code --from-file=app.py=services/dhcp-server/app.py \
  -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -
kubectl rollout restart ds sdn-dhcp -n sdn-controller
```

## Build & Push Images

CI (`.github/workflows/`) builds and pushes on every push to `master`. Images are on Docker Hub under `arturoalvarez/`. To build manually:

```bash
docker build -t arturoalvarez/ryu-controller:latest services/ryu-controller
docker build -t arturoalvarez/sdn-meter-collector:latest services/meter-collector
# etc. — context is always services/<service-name>/
```

Import into K3s containerd when not pulling from Docker Hub:
```bash
docker save -o /tmp/img.tar <image>:<tag>
python tools/gns3/ssh_k3s.py "sudo k3s ctr images import /tmp/img.tar"
```

## Apply Manifests

```bash
kubectl apply -k deploy/k8s/        # full stack (kustomize)
kubectl apply -f deploy/k8s/02-ryu-controller.yaml  # single manifest
```

Apply order matters for dependencies: `00 → 01 → 02 → 03 → 05 → 06`.

## Key Debug Commands

```bash
# Pod health
python tools/gns3/ssh_k3s.py "sudo kubectl -n sdn-controller get pods -o wide"

# Ryu logs (all nodes)
python tools/gns3/ssh_k3s.py "sudo kubectl logs -n sdn-controller -l app=ryu --tail=100 --prefix"

# OVS flows on a node
python tools/gns3/ssh_k3s.py "sudo kubectl exec -n sdn-controller <ovs-pod> -- ovs-ofctl -O OpenFlow13 dump-flows br-sdn"

# Redis topology
python tools/gns3/ssh_k3s.py "sudo kubectl exec -n sdn-controller redis-0 -c redis -- redis-cli -p 6379 SMEMBERS topology:switches"

# Meter collector stats
curl -s http://192.168.122.100:8081/api/stats | python3 -m json.tool
curl -s http://192.168.122.100:8081/api/sdn-topology | python3 -m json.tool

# Redis master address (for Sentinel queries)
python tools/gns3/ssh_k3s.py "sudo kubectl exec redis-0 -c sentinel -n sdn-controller -- redis-cli -p 26379 sentinel get-master-addr-by-name mymaster"
```

## Public Endpoints

The dashboards run as `hostNetwork` DaemonSets. The kube-vip BGP VIP (`10.255.255.1`)
fronts **only the API** (`:6443`, fabric-internal), not these NodePorts. From the host,
reach them on a control-plane's management IP (the edge that keeps `192.168.122.x`);
Master-1 (`192.168.122.100`) is the canonical one. Workers have **no** `192.168.122.x`
address (pure fabric loopbacks), so they are not reachable from the host directly.

| Service       | URL (from host, via Master-1)   |
|---------------|---------------------------------|
| Grafana       | `http://192.168.122.100:3000`   |
| Operations UI | `http://192.168.122.100:8081`   |
| Prometheus    | `http://192.168.122.100:9090`   |

Any control-plane edge IP (`192.168.122.100/.106/.130`) also works.

## Architecture

### Physical Layer (GNS3) — L3 routed fabric

QEMU VMs inside GNS3. Management/control traffic (K3s API, etcd, Calico) runs over an
**L3 routed fabric**, not an L2 bridge: every `ensX` cable is an OSPF *unnumbered*
point-to-point link and each node has a stable **loopback `/32`** (`10.255.B1.B2`,
derived from `sha256(/etc/machine-id)`). `tools/gns3/l3-fabric/fabric-bootstrap.sh`
(systemd `fabric-bootstrap.service`, runs before K3s) builds this on every node:
loopback on `lo`+`ensX`, FRR `frr.conf` (OSPF + iBGP listen-range, AS 64512), and it
**eradicates** the legacy `br0` L2 bridge. K3s `--node-ip` is the loopback; OSPF gives
reachability + ECMP, so there is no loop class and no failover daemons (OSPF *is* the
failover). The old `br0` (`192.168.122.0/24`) + `ACTIVE_BR0_PORTS` + STP design is gone
(see `docs/MIGRACION_L3_FABRIC.md`).

SDN guest traffic still runs on the OVS bridge `br-sdn` (`10.0.0.0/24`) — independent of
the fabric. Never bridge `br-sdn` into the fabric interfaces.

Control-planes wired to the GNS3 `Mgmt-Switch`/`NAT1` keep their `192.168.122.x`
**management/edge IP** on that interface (auto-detected by `fabric-bootstrap` via a
direct gateway ping): it provides internet, NATs the fabric (`10.255/16` → MASQUERADE)
and originates the OSPF default. Workers have **no** `192.168.122.x` address. NAT1
bridges the GNS3 L2 to the host's `virbr0` via a TAP interface (`gns3tap0-0`).

Overlay (kube-vip BGP for the API VIP `10.255.255.1`, Calico BGP for pod routes) peers
with the local FRR (`127.0.0.1`). Manifests in `deploy/k8s/l3-fabric/`.

### Control Plane: Ryu (distributed)

`services/ryu-controller/app.py` runs as a **DaemonSet** (`hostNetwork: true`) on every node. Each Ryu instance connects to the local OVS (`tcp:127.0.0.1:6653`). Ryu instances coordinate exclusively through Redis — there is no direct controller-to-controller communication.

Key Redis contracts (do not rename keys without auditing all consumers):
- `topology:switches`, `topology:node_names`, `topology:node_ips` — live node registry
- `topology:vxlan_peers` — LLDP-discovered neighbors (source of truth for VXLAN tunnels)
- `topology:mgmt_switch_links` — management switch adjacency
- `mac_to_port:{dpid}`, `switch_ports:{dpid}` — per-switch forwarding state
- `topology:guest_ips`, `topology:guest_locations`, `topology:guest_names` — smart meter L2 identity
- `security:device:{id}`, `security:mac_to_device:{mac}` — AMI authorization registry
- `meter:devices`, `meter:latest:{device_id}`, `meter:history:{device_id}` — telemetry store
- `lock:flow:{dpid}:{src}:{dst}` — distributed locks for FlowMod serialization

### Data Plane: OVS + VXLAN

`ovs-sdn-initializer` creates `br-sdn` on each node, assigns `10.0.0.1/24`, and creates VXLAN tunnels **only to direct fabric neighbors** — the OSPF *unnumbered* neighbors (1-hop `/32` loopback routes where dst == next-hop), published to `topology:vxlan_peers` in Redis. VTEPs are the node **loopbacks** (`10.255.x`), so each tunnel rides the direct cable via OSPF shortest-path. This is intentionally NOT a full mesh — full mesh defeats multi-hop Dijkstra path stitching. Never change this to full mesh. (The DPID is derived from the node's fabric loopback, not from `br0`.)

Ryu computes MST (Prim) over the discovered neighbor graph, then uses Dijkstra for multi-hop forwarding between nodes. Flow installation is serialized per `(dpid, src_mac, dst_mac)` via Redis locks.

Smart meters (`10.0.0.x`) get IPs from the `sdn-dhcp-server` DaemonSet (Scapy-based). The DHCP server on the master node uses `psrc=10.0.0.1`; worker DHCP pods use `psrc=0.0.0.0` to avoid ARP cache poisoning on non-local nodes.

### Telemetry & Security

`meter-collector` (DaemonSet, `hostNetwork: true`) receives UDP telemetry on port 5555 and exposes a Flask dashboard on port 5000 (NodePort 8081). It is **fail-closed**: packets from unregistered or unauthorized sources are rejected and counted.

Auto-registration runs when a smart meter's UDP packet arrives with `device_id` matching `SDNSmartMeter-*` and the MAC/IP can be correlated via `topology:guest_ips`. This avoids manual registration after GNS3 VM recreation.

`externalTrafficPolicy: Local` is required on the meter-collector Service because it uses `hostNetwork`. Changing to `Cluster` causes asymmetric return path hangs.

### Observability

Prometheus scrapes Ryu pods via annotations (`prometheus.io/port: "8000"`). Grafana uses the native Node Graph panel. Loki/Promtail collect Ryu logs; LogQL selector: `{namespace="sdn-controller", app="ryu"}`.

DPID formatting: Ryu uses decimal internally; Redis topology keys use zero-padded hex (`0000` + 12 hex digits). Preserve existing conversions when touching either.

### GNS3 API

```python
# Pattern for GNS3 API calls — read auth from config, don't hardcode
import configparser, requests
cfg = configparser.ConfigParser()
cfg.read('/home/artulita/.config/GNS3/2.2/gns3_server.conf')
auth = (cfg['Server']['user'], cfg['Server']['password'])
r = requests.get('http://127.0.0.1:3080/v2/projects', auth=auth)
```

Resolve node IDs dynamically (`GET /projects/{id}/nodes`) — they change after topology recreation.

## Node Reference

`--node-ip` is the **fabric loopback** (`10.255.x`, derived from `machine-id`, stable
across reboots). Only control-planes (edges) keep a `192.168.122.x` management IP;
workers have none. Resolve current values with
`ssh_k3s.py "sudo kubectl get nodes -o wide"` — they change if a VM's `machine-id` is
regenerated.

| K3s name       | Fabric loopback (node-ip) | Mgmt/edge IP       | Role           |
|----------------|---------------------------|--------------------|----------------|
| master         | 10.255.227.204            | 192.168.122.100    | control-plane  |
| control-2      | 10.255.3.188              | 192.168.122.106    | control-plane  |
| control-3      | 10.255.114.158            | 192.168.122.130    | control-plane  |
| worker-24cf41  | 10.255.12.224             | —                  | worker         |
| worker-b0ff27  | 10.255.246.32             | —                  | worker         |
| worker-b56b35  | 10.255.221.26             | —                  | worker         |
| worker-ea7e34  | 10.255.224.42             | —                  | worker         |

API VIP: `10.255.255.1` (kube-vip BGP, fabric-internal, `:6443`). Host gateway:
`192.168.122.1` (virbr0). Fabric: supernet `10.255.0.0/16`, OSPF area 0, AS 64512.
