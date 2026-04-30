# AGENTS.md

## Repository Shape
- This repo is a lab fork of upstream Ryu plus a K3s/GNS3 SDN stack. Treat root `app.py`, `k8s-sdn-deployment.yaml`, `dhcp-server/`, `topology/`, `meter-collector/`, and `smart-meter/` as the project-specific code; `ryu/` is mostly upstream framework code.
- `README.rst` documents upstream Ryu. `README.md`, `AI_CONTEXT.md`, and `GuiaDeDespliegue.md` document this K3s SDN lab; if prose conflicts with `k8s-sdn-deployment.yaml`, trust the manifest.
- The deployed controller is a DaemonSet named `ryu` using `hostNetwork: true`, not a plain multi-replica Deployment. OVS connects to local Ryu on `127.0.0.1:6653`; Redis Sentinel is the shared state backend.

## Commands
- Install/test dependencies follow old Ryu constraints: CI installs `python -m pip install --upgrade -r pip-requirements.txt` first, where `pip-requirements.txt` pins `pip==20.3.4`.
- Full unit matrix command is `NOSE_VERBOSE=0 tox`; local focused Python 3.9 run is `tox -e py39 -- <test path or nose args>`.
- Legacy helper: `./run_tests.sh -N <test path>` runs tests in the current environment, then pycodestyle unless `-P` is passed.
- Style checks are `tox -e pycodestyle` and `tox -e autopep8`; pycodestyle intentionally ignores W503/W504/E116/E402/E501/E722/E731/E741 per `tox.ini`.
- Build controller image with `docker build -t arturoalvarez/ryu-controller:latest .`; the Dockerfile pins Python 3.9 slim and `setuptools<58.0.0` for old Ryu compatibility.

## Cluster Access
- Do not assume local `kubectl` or Docker reaches the lab cluster. The K3s master is reached over SSH at `ubuntu@192.168.122.100` with password `ubuntu`; use `python ssh_k3s.py "kubectl get pods -n sdn-controller"` for remote commands.
- K3s runs on `br0`; master IP is `192.168.122.100`. K3s install and worker join must use `--flannel-iface=br0`.
- Never commit a K3s join token. `k3s_worker_command.sh` is ignored and should take `K3S_NODE_TOKEN` from the environment.

## Hot Reload / Deploy
- Python app code is mounted into pods via ConfigMaps, so small code changes usually do not require rebuilding images.
- Reload root Ryu controller code with `kubectl create configmap ryu-code --from-file=app.py=app.py -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -` then `kubectl rollout restart ds ryu -n sdn-controller`.
- ConfigMaps used by the manifest: `ryu-code` for root `app.py`, `ryu-topology-code` for `topology/app.py` and `topology/templates/index.html`, `dhcp-code` for `dhcp-server/app.py`, and `meter-collector-code` for `meter-collector/app.py`.
- Public lab endpoints from the master network are Prometheus `http://192.168.122.100:9090`, Grafana `http://192.168.122.100:3000`, topology UI service port `8080`, and meter collector dashboard service port `8081`.

## Architecture Gotchas
- Redis keys are part of the runtime contract: `topology:switches`, `topology:node_names`, `topology:node_ips`, `switch_ports:{dpid}`, `mac_to_port:{dpid}`, `topology:guest_ips`, `topology:guest_locations`, and `meter:*` are consumed across services.
- DPID formatting differs by context: Ryu often uses decimal datapath IDs; topology/node metadata uses raw hex strings like `0000` plus 12 hex digits. Preserve existing conversions.
- DHCP depends on Ryu sending broadcast traffic to `OFPP_LOCAL`; changing FLOOD/local OpenFlow behavior can break Scapy DHCP on `br-sdn` even if packets still traverse OVS.
- `ovs-sdn-initializer` must not add management bridge `br0` to `br-sdn`; doing so risks L2 loops in the GNS3/K3s fabric.
- Ryu metrics are served directly by root `app.py` on `METRICS_PORT` default `8000`; Prometheus discovers pods via scrape annotations in the manifest.
