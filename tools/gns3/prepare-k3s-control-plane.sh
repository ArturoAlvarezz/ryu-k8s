#!/bin/bash
# Prepare a GNS3 VM to run as a K3s control-plane node on the L3 routed fabric.
#
# El control-plane arranca en el fabric L3 (FRR/OSPF unnumbered + loopback /32
# derivada de /etc/machine-id), igual que el worker, SALVO que CONSERVA su IP de
# gestion 192.168.122.x en la interfaz EDGE hacia el Mgmt-Switch/NAT: por ahi sale
# a internet, hace NAT del fabric (10.255/16) y origina la default en OSPF. La
# interfaz edge la DETECTA fabric-bootstrap.sh en runtime (ping directo al gateway);
# aqui solo se PERSISTE la IP/gw de gestion en /etc/l3-fabric/mgmt.env para que el
# bootstrap la reclame aunque ya no exista br0/netplan.
set -euo pipefail

ROLE="${RYU_K3S_CP_ROLE:-${1:-}}"
NODE_NAME="${RYU_K3S_NODE_NAME:-${K3S_NODE_NAME:-${2:-}}}"
MGMT_IP="${RYU_K3S_MGMT_IP:-${RYU_K3S_NODE_IP:-${K3S_NODE_IP:-${3:-}}}}"
MGMT_PREFIX="${RYU_K3S_MGMT_PREFIX:-24}"
MGMT_GATEWAY="${RYU_K3S_MGMT_GATEWAY:-192.168.122.1}"
REPO_DIR="${RYU_K3S_REPO_DIR:-$PWD}"
SKIP_APT_UPGRADE="${RYU_K3S_SKIP_APT_UPGRADE:-false}"

usage() {
  cat <<'EOF'
Usage:
  sudo ./tools/gns3/prepare-k3s-control-plane.sh first       [node-name] [mgmt-ip]
  sudo ./tools/gns3/prepare-k3s-control-plane.sh additional  <node-name> <mgmt-ip>

mgmt-ip = IP de gestion 192.168.122.x del EDGE hacia el Mgmt-Switch/NAT (da internet
y NAT del fabric). El fabric (loopback /32 + OSPF) se monta solo desde machine-id.

Environment overrides:
  RYU_K3S_CP_ROLE        first | additional
  RYU_K3S_NODE_NAME      Hostname del nodo
  RYU_K3S_MGMT_IP        IP de gestion del edge (192.168.122.x). first default .100
  RYU_K3S_MGMT_GATEWAY   Gateway de gestion, default 192.168.122.1
  RYU_K3S_SKIP_APT_UPGRADE  true para omitir apt upgrade
EOF
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script with sudo" >&2
    exit 1
  fi
}

validate_inputs() {
  case "$ROLE" in
    first)
      NODE_NAME="${NODE_NAME:-master}"
      MGMT_IP="${MGMT_IP:-192.168.122.100}"
      ;;
    additional)
      if [ -z "$NODE_NAME" ] || [ -z "$MGMT_IP" ]; then
        echo "ERROR: additional necesita node-name y mgmt-ip (192.168.122.x del edge)" >&2
        usage >&2
        exit 1
      fi
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
  if [ ! -f "$REPO_DIR/tools/gns3/l3-fabric/fabric-bootstrap.sh" ]; then
    echo "ERROR: no encuentro tools/gns3/l3-fabric/fabric-bootstrap.sh bajo RYU_K3S_REPO_DIR=$REPO_DIR" >&2
    exit 1
  fi
}

resize_root_if_possible() {
  if command -v growpart >/dev/null 2>&1 && [ -b /dev/vda1 ]; then
    growpart /dev/vda 1 || true
  fi
  if command -v resize2fs >/dev/null 2>&1 && [ -b /dev/vda1 ]; then
    resize2fs /dev/vda1 || true
  fi
}

install_base_packages() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl git net-tools cloud-guest-utils \
    frr frr-pythontools iptables
}

upgrade_packages() {
  if [ "$SKIP_APT_UPGRADE" != "true" ]; then
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
  fi
}

install_docker() {
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  . /etc/os-release
  docker_codename="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $docker_codename stable
EOF

  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  usermod -aG docker ubuntu 2>/dev/null || true
}

configure_hostname() {
  hostnamectl set-hostname "$NODE_NAME"
  printf '%s\n' "$NODE_NAME" >/etc/hostname
  sed -i '/127.0.1.1/d' /etc/hosts
  printf '127.0.1.1 %s\n' "$NODE_NAME" >>/etc/hosts
  mkdir -p /etc/cloud/cloud.cfg.d
  printf 'preserve_hostname: true\n' >/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg
  # La red del fabric L3 la gestiona fabric-bootstrap; cloud-init no debe
  # regenerar netplan ni reintroducir br0.
  printf 'network: {config: disabled}\n' >/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
}

write_l3_netplan() {
  # ens* como interfaces L3 sueltas (sin br0, sin DHCP). fabric-bootstrap les
  # asigna la loopback /32 unnumbered y reclama la IP de gestion en el edge.
  rm -f /etc/netplan/50-cloud-init.yaml
  cat >/etc/netplan/50-l3-fabric.yaml <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    fabric-ens:
      match: {name: "ens*"}
      optional: true
EOF
  chmod 600 /etc/netplan/50-l3-fabric.yaml
  netplan generate >/dev/null 2>&1 || true
}

persist_mgmt_env() {
  # fabric-bootstrap deriva MGMT_IP de: br0 (legacy) -> netplan -> este archivo.
  # En un nodo nuevo sin br0 es la unica fuente: sin el, el CP no reclama su edge
  # ni su IP de gestion (se queda sin internet / sin VIP del API).
  mkdir -p /etc/l3-fabric
  cat >/etc/l3-fabric/mgmt.env <<EOF
MGMT_IP=${MGMT_IP}/${MGMT_PREFIX}
MGMT_GW=${MGMT_GATEWAY}
EOF
  chmod 600 /etc/l3-fabric/mgmt.env
}

install_fabric_service() {
  install -m 0755 "$REPO_DIR/tools/gns3/l3-fabric/fabric-bootstrap.sh" \
    /usr/local/bin/fabric-bootstrap.sh
  install -m 0644 "$REPO_DIR/tools/gns3/l3-fabric/fabric-bootstrap.service" \
    /etc/systemd/system/fabric-bootstrap.service

  # Erradicar el plano L2 antiguo si la imagen base lo trae.
  systemctl disable --now gns3-br0-tree.service uplink-failover.service \
    worker-mgmt-failover.service 2>/dev/null || true
  rm -f /etc/systemd/system/gns3-br0-tree.service \
        /etc/systemd/system/uplink-failover.service \
        /etc/systemd/system/worker-mgmt-failover.service \
        /etc/default/gns3-br0-tree /etc/default/uplink-failover \
        /etc/default/worker-mgmt-failover \
        /etc/systemd/network/05-uplink-ens3-unmanaged.network \
        /etc/systemd/system/k3s-iptables.service \
        /usr/local/bin/k3s-br0-forwarding.sh
  if [ -f /usr/local/bin/configure-br0-tree.sh ]; then
    printf '#!/bin/bash\n# L3-FABRIC-NEUTRALIZED.\nexit 0\n' >/usr/local/bin/configure-br0-tree.sh
    chmod +x /usr/local/bin/configure-br0-tree.sh
  fi

  systemctl daemon-reload
  systemctl enable frr.service 2>/dev/null || true
  systemctl enable fabric-bootstrap.service
}

configure_network_wait() {
  mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
  cat >/etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF
  systemctl daemon-reload
}

configure_forwarding() {
  # fabric-bootstrap reafirma rp_filter=0, ip_forward, el ACCEPT de transito y el
  # MASQUERADE del edge en runtime. Aqui solo base de k8s + bridge para docker.
  cat >/etc/sysctl.d/99-sdn.conf <<'EOF'
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF
  modprobe br_netfilter 2>/dev/null || true
  sysctl --system || true
}

require_root
validate_inputs
install_base_packages
resize_root_if_possible
upgrade_packages
install_docker
configure_hostname
write_l3_netplan
persist_mgmt_env
install_fabric_service
configure_network_wait
configure_forwarding

echo "prepare-k3s-control-plane: $NODE_NAME listo (fabric L3, mgmt=$MGMT_IP/$MGMT_PREFIX)."
echo "  Siguiente: reinicia (o arranca fabric-bootstrap) y luego instala K3s server"
echo "  con tools/gns3/k3s-server-ha-install.sh (usa la loopback del fabric)."
