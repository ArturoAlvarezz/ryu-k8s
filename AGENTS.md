# AGENTS.md

## Repository Shape
- This repo is a lab fork of upstream Ryu plus a K3s/GNS3 SDN stack. Project-specific services live in `services/`; Kubernetes manifests live in `deploy/k8s/`; GNS3/debug helpers live in `tools/gns3/`; upstream Ryu code lives in `upstream-ryu/`.
- `upstream-ryu/README.rst` documents upstream Ryu. `README.md` and `GuiaDeDespliegue.md` document this K3s SDN lab; if prose conflicts with `deploy/k8s/`, trust the manifests.
- The deployed controller is a DaemonSet named `ryu` using `hostNetwork: true`, not a plain multi-replica Deployment. OVS connects to local Ryu on `127.0.0.1:6653`; Redis Sentinel is the shared state backend.

## System Overview
- This project is a distributed SDN lab on K3s/GNS3. Ryu, OVS, Redis Sentinel, DHCP, topology UI, telemetry, and observability run as Kubernetes workloads.
- The data plane is Open vSwitch on every K3s node. `ovs-sdn-initializer` creates `br-sdn`, assigns `10.0.0.1/24`, connects OVS to local Ryu, adds guest-facing `ens*` ports, and creates VXLAN tunnels to LLDP-discovered physical neighbors.
- The control plane is distributed. Each node runs one local Ryu controller with `hostNetwork: true`; switches connect to `tcp:127.0.0.1:6653`, and controllers coordinate through Redis instead of local-only memory.
- Redis + Sentinel is the runtime state contract for topology, MAC learning, DHCP leases, guest locations, STP state, and meter telemetry.
- Physical management/fabric connectivity is on Linux bridge `br0`; SDN guest traffic is on OVS bridge `br-sdn`. Never merge `br0` into `br-sdn`.

## Services
- `services/ryu-controller/app.py`: Ryu OpenFlow app, Redis-backed MAC learning, gateway ARP handling for `10.0.0.1`, topology/path metrics, Prometheus `/metrics` on `METRICS_PORT` default `8000`.
- `services/dhcp-server/app.py`: distributed Scapy DHCP daemon on `br-sdn`; allocates `10.0.0.x` from Redis and runs L2 ARP healthchecks for guests.
- `services/topology-dashboard/app.py`: Flask topology UI backed by Redis; exposed through service port `8080`.
- `services/meter-collector/app.py`: UDP `5555` Smart Meter collector plus Flask API/dashboard on port `5000`; K8s service exposes dashboard on `8081`.
- `services/smart-meter/`: Alpine-based GNS3 guest image. `entrypoint.sh` obtains DHCP via `udhcpc` before running `app.py`; telemetry goes to `COLLECTOR_IP=10.0.0.1`, `COLLECTOR_PORT=5555` by default.
- `services/security-device-registry/`: web console plus CLI registry for authorized AMI devices backed by Redis. It registers/lists/queries devices and validates observed `mac`/`ip`/`dpid`/`in_port` tuples for future Ryu security enforcement. K8s service exposes the web UI on port `8082`.

## Redis Runtime Contract
- Core keys: `topology:switches`, `topology:node_names`, `topology:node_ips`, `switch_ports:{dpid}`, `mac_to_port:{dpid}`, `topology:guest_ips`, `topology:guest_locations`, `topology:guest_names`, `topology:br0_stp_ports`, `switch:alive:{dpid}`.
- DHCP keys include `dhcp:next_ip` and guest lease/health state written by `services/dhcp-server/app.py`.
- Ryu uses distributed locks like `lock:flow:{dpid}:{src}:{dst}` to avoid conflicting flow installs during broadcasts.
- Smart Meter telemetry keys: `meter:devices`, `meter:history:{device_id}`, `meter:latest:{device_id}`.
- Security registry keys: `security:devices`, `security:device:{device_id}`, `security:mac_to_device:{mac}`, `security:ip_to_device:{ip}`.
- Redis keys are consumed across services. Rename or delete keys only after checking all services that read them.

## Observability
- Ryu exposes Prometheus metrics directly from `services/ryu-controller/app.py`; no sidecar is required.
- Key metrics: `ryu_packet_in_total{dpid}`, `ryu_active_nodes`, `ryu_active_switches`, `ryu_installed_flows{dpid}`, `ryu_port_rx_bytes_total`, `ryu_port_tx_bytes_total`, `ryu_topology_node_info`, `ryu_topology_edge_info`, `ryu_trace_path_edge_info`.
- Grafana uses native Node graph with `src_guest` and `dst_guest` variables to show topology and highlighted paths.
- `topology:br0_stp_ports` is exported to Grafana as `br0_stp` or `br0_stp_blocked`; blocked physical STP links should not be used for path visualization.
- Loki/Promtail collect Ryu logs; LogQL selector is `{namespace="sdn-controller", app="ryu"}`.

## Commands
- Upstream Ryu tests/dependencies are under `upstream-ryu/`: CI installs `python -m pip install --upgrade -r upstream-ryu/pip-requirements.txt` first, where `pip-requirements.txt` pins `pip==20.3.4`.
- Full upstream unit matrix command is `NOSE_VERBOSE=0 tox` from `upstream-ryu/`; local focused Python 3.9 run is `tox -e py39 -- <test path or nose args>`.
- Legacy upstream helper: `upstream-ryu/run_tests.sh -N <test path>` runs tests in the current environment, then pycodestyle unless `-P` is passed.
- Style checks are `tox -e pycodestyle` and `tox -e autopep8` from `upstream-ryu/`; pycodestyle intentionally ignores W503/W504/E116/E402/E501/E722/E731/E741 per `upstream-ryu/tox.ini`.
- Build controller image with `docker build -t arturoalvarez/ryu-controller:latest services/ryu-controller`; the Dockerfile pins Python 3.9 slim and `setuptools<58.0.0` for old Ryu compatibility.
- Build project images with these contexts: `services/ryu-controller`, `services/dhcp-server`, `services/topology-dashboard`, `services/meter-collector`, `services/smart-meter`, and `services/security-device-registry`.

## Cluster Access
- Do not assume local `kubectl` or Docker reaches the lab cluster. The K3s master is reached over SSH at `ubuntu@192.168.122.100` with password `ubuntu`; use `python tools/gns3/ssh_k3s.py "kubectl get pods -n sdn-controller"` for remote commands.
- K3s runs on `br0`; master IP is `192.168.122.100`. K3s install and worker join must use `--flannel-iface=br0`.
- Never commit a K3s join token. `k3s_worker_command.sh` is ignored and should take `K3S_NODE_TOKEN` from the environment.

## Hot Reload / Deploy
- Python app code is mounted into pods via ConfigMaps, so small code changes usually do not require rebuilding images.
- Reload Ryu controller code with `kubectl create configmap ryu-code --from-file=app.py=services/ryu-controller/app.py -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -` then `kubectl rollout restart ds ryu -n sdn-controller`.
- ConfigMaps used by the manifest: `ryu-code` for `services/ryu-controller/app.py`, `ryu-topology-code` for `services/topology-dashboard/app.py` and `services/topology-dashboard/templates/index.html`, `dhcp-code` for `services/dhcp-server/app.py`, and `meter-collector-code` for `services/meter-collector/app.py`. The security registry is a web/CLI image and does not preload seed devices.
- Public lab endpoints from the master network are Prometheus `http://192.168.122.100:9090`, Grafana `http://192.168.122.100:3000`, topology UI service port `8080`, meter collector dashboard service port `8081`, and security registry service port `8082`.
- Apply manifests by layer with `kubectl apply -f deploy/k8s/00-namespace.yaml`, then `01-database`, `02-ryu-controller`, `03-sdn-network`, `04-topology-dashboard`, `05-telemetry`, and `06-observability`; or use `kubectl apply -k deploy/k8s/`.

## Debugging Recipes
- Get Redis master: `kubectl exec redis-0 -c sentinel -n sdn-controller -- redis-cli -p 26379 sentinel get-master-addr-by-name mymaster | head -n 1`.
- Dump OVS flows: `kubectl exec <ovs-pod> -n sdn-controller -- ovs-ofctl -O OpenFlow13 dump-flows br-sdn`.
- Ryu logs: `kubectl logs -n sdn-controller -l app=ryu --tail=200 --prefix`.
- DHCP logs: `kubectl logs -n sdn-controller -l app=sdn-dhcp --tail=200`.
- Topology JSON from master: `curl -s http://localhost:8080/api/topology`.
- Meter collector stats from master/fabric: `curl http://192.168.122.100:8081/api/stats`.

## Architecture Gotchas
- Redis keys are part of the runtime contract: `topology:switches`, `topology:node_names`, `topology:node_ips`, `switch_ports:{dpid}`, `mac_to_port:{dpid}`, `topology:guest_ips`, `topology:guest_locations`, and `meter:*` are consumed across services.
- DPID formatting differs by context: Ryu often uses decimal datapath IDs; topology/node metadata uses raw hex strings like `0000` plus 12 hex digits. Preserve existing conversions.
- DHCP depends on Ryu sending broadcast traffic to `OFPP_LOCAL`; changing FLOOD/local OpenFlow behavior can break Scapy DHCP on `br-sdn` even if packets still traverse OVS.
- `ovs-sdn-initializer` must not add management bridge `br0` to `br-sdn`; doing so risks L2 loops in the GNS3/K3s fabric.
- Ryu metrics are served directly by `services/ryu-controller/app.py` on `METRICS_PORT` default `8000`; Prometheus discovers pods via scrape annotations in the manifest.
- The DHCP ARP healthcheck must avoid poisoning guest ARP caches: only the master DHCP pod should use `psrc=10.0.0.1`; worker DHCP pods should use `psrc=0.0.0.0`.
- `br-sdn` should use the same MAC as `br0`. Ryu derives the gateway MAC for `10.0.0.1` from the node DPID.
- Smart Meters must obtain a DHCP lease before starting telemetry; do not revert `services/smart-meter/entrypoint.sh` to a finite retry loop unless deployment ordering guarantees DHCP availability.
- Guest freshness matters. Avoid reintroducing stale guests into metrics/topology without checking live state such as `active_mac:*`, `health:*`, or current OVS FDB evidence.

## Roadmap Context
- Completed: Smart Meter guest image and telemetry collector.
- Completed: STP visualization for physical `br0` links in Grafana and path filtering around blocked links.
- Completed: Prometheus/Grafana/Loki observability stack.
- Potential future feature: SDN security/microsegmentation in Ryu, including anti-MAC-spoofing, ARP poisoning prevention, and ACLs isolating guests or meters from unauthorized nodes.
