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

The HA VIP is `192.168.122.10` (kube-vip). The cluster uses `sudo kubectl` unless `~/.kube/config` is configured for the current user.

## Hot Reload (no image rebuild needed)

Code is mounted via ConfigMaps. Update and restart in one step:

```bash
# Ryu controller
kubectl create configmap ryu-code --from-file=app.py=services/ryu-controller/app.py \
  -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -
kubectl rollout restart ds ryu -n sdn-controller

# meter-collector (web dashboard + telemetry)
kubectl create configmap meter-collector-code \
  --from-file=app.py=services/meter-collector/app.py \
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

| Service       | VIP URL                          | Direct (Master-1)               |
|---------------|----------------------------------|---------------------------------|
| Grafana       | `http://192.168.122.10:3000`     | `http://192.168.122.100:3000`   |
| Operations UI | `http://192.168.122.10:8081`     | `http://192.168.122.100:8081`   |
| Prometheus    | `http://192.168.122.10:9090`     | `http://192.168.122.100:9090`   |

If the VIP is unreachable, use the direct Master-1 address. The VIP (`192.168.122.10`) depends on kube-vip holding a lease and `arp_accept=1` on the host's `virbr0`.

## Architecture

### Physical Layer (GNS3)

QEMU VMs inside GNS3. All management traffic (K3s API, etcd, flannel) runs on Linux bridge `br0` (`192.168.122.0/24`). SDN guest traffic runs on OVS bridge `br-sdn` (`10.0.0.0/24`). These two bridges must never be merged.

The GNS3 `Mgmt-Switch` (OVS container, STP disabled) connects all 3 control-plane nodes and NAT1. NAT1 bridges the GNS3 L2 to the host's `virbr0` via a TAP interface (`gns3tap0-0`).

Each K3s node's `br0` uses only a deterministic subset of its physical ports (`ACTIVE_BR0_PORTS` defined per hostname in `tools/gns3/configure-br0-tree.sh`) to keep `br0` loop-free without STP.

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

`ovs-sdn-initializer` creates `br-sdn` on each node, assigns `10.0.0.1/24`, and creates VXLAN tunnels **only to LLDP-discovered neighbors** (read from `topology:links` in Redis). This is intentionally NOT a full mesh — full mesh defeats multi-hop Dijkstra path stitching. Never change this to full mesh.

Ryu computes MST (Prim) over the physical LLDP graph, then uses Dijkstra for multi-hop forwarding between nodes. Flow installation is serialized per `(dpid, src_mac, dst_mac)` via Redis locks.

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

| K3s name       | IP                  | br0 MAC              | Role           |
|----------------|---------------------|----------------------|----------------|
| master         | 192.168.122.100     | 86:36:f7:5c:06:d4   | control-plane  |
| control-2      | 192.168.122.106     | 3a:a7:4e:40:47:86   | control-plane  |
| control-3      | 192.168.122.130     | 96:9c:1d:49:e5:84   | control-plane  |
| worker-b0ff27  | 192.168.122.115     | 42:f5:e5:b0:ff:27   | worker         |
| worker-b56b35  | 192.168.122.145     | fe:dc:a2:b5:6b:35   | worker         |
| worker-ea7e34  | 192.168.122.70      | 8e:fc:06:ea:7e:34   | worker         |
| worker-24cf41  | 192.168.122.170     | 62:ce:ca:24:cf:41   | worker         |

VIP: `192.168.122.10` (kube-vip, currently held by control-2). Host gateway: `192.168.122.1` (virbr0, MAC `52:54:00:87:4b:28`).
