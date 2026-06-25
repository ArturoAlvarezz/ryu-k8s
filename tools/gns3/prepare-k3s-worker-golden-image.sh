#!/bin/bash
# Prepare a GNS3 VM as the reusable K3s worker Golden Image (L3 routed fabric).
#
# El nodo arranca en el fabric L3 (FRR/OSPF unnumbered + loopback /32 derivada de
# /etc/machine-id), SIN br0 ni DHCP de gestion. `fabric-bootstrap.service` monta el
# fabric antes de K3s y `k3s-autojoin.service` une el worker contra el VIP del API
# (10.255.255.1, anunciado por kube-vip BGP). El br0/L2 antiguo queda erradicado.
set -euo pipefail

JOIN_TOKEN="${RYU_K3S_NODE_TOKEN:-${K3S_NODE_TOKEN:-${1:-}}}"
API_ENDPOINT="${RYU_K3S_API_ENDPOINT:-${K3S_API_ENDPOINT:-10.255.255.1}}"
K3S_VERSION="${RYU_K3S_VERSION:-v1.35.5+k3s1}"
REPO_DIR="${RYU_K3S_REPO_DIR:-$PWD}"
SKIP_APT_UPGRADE="${RYU_K3S_SKIP_APT_UPGRADE:-false}"

usage() {
  cat <<'EOF'
Usage:
  sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL>' ./tools/gns3/prepare-k3s-worker-golden-image.sh

Environment overrides:
  RYU_K3S_NODE_TOKEN        Required K3s cluster token for worker auto-join
  RYU_K3S_API_ENDPOINT      API VIP del fabric, default 10.255.255.1
  RYU_K3S_VERSION           Version de K3s a instalar (debe coincidir con el cluster)
  RYU_K3S_SKIP_APT_UPGRADE  true to skip apt upgrade
EOF
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script with sudo" >&2
    exit 1
  fi
}

validate_inputs() {
  if [ -z "$JOIN_TOKEN" ] || echo "$JOIN_TOKEN" | grep -q '^<'; then
    echo "ERROR: define RYU_K3S_NODE_TOKEN with the real cluster token" >&2
    usage >&2
    exit 1
  fi
  if [ ! -f "$REPO_DIR/tools/gns3/l3-fabric/fabric-bootstrap.sh" ]; then
    echo "ERROR: no encuentro tools/gns3/l3-fabric/fabric-bootstrap.sh bajo RYU_K3S_REPO_DIR=$REPO_DIR" >&2
    echo "       Ejecuta el script desde la raiz del repo o define RYU_K3S_REPO_DIR." >&2
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
  # Hostname provisional de la imagen; el clon se renombra a worker-<mac> en el
  # primer arranque (k3s-autojoin). preserve_hostname:false permite ese cambio.
  hostnamectl set-hostname worker-golden
  printf 'worker-golden\n' >/etc/hostname
  sed -i '/127.0.1.1/d' /etc/hosts
  printf '127.0.1.1 worker-golden\n' >>/etc/hosts
  mkdir -p /etc/cloud/cloud.cfg.d
  printf 'preserve_hostname: false\n' >/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg
  # Evitar que cloud-init regenere el netplan en cada boot y reintroduzca br0:
  # la red del fabric L3 la gestiona por completo fabric-bootstrap.service.
  printf 'network: {config: disabled}\n' >/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
}

write_l3_netplan() {
  # Netplan minimo del fabric L3: ens* como interfaces L3 sueltas (sin br0, sin
  # DHCP). fabric-bootstrap les asigna la loopback /32 unnumbered y levanta OSPF.
  # Se elimina cualquier netplan previo con br0/bridges (imagen L2 antigua).
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

install_fabric_service() {
  # Artefactos canonicos del fabric L3 (identicos en CP y worker).
  install -m 0755 "$REPO_DIR/tools/gns3/l3-fabric/fabric-bootstrap.sh" \
    /usr/local/bin/fabric-bootstrap.sh
  install -m 0644 "$REPO_DIR/tools/gns3/l3-fabric/fabric-bootstrap.service" \
    /etc/systemd/system/fabric-bootstrap.service

  # Erradicar el mecanismo L2 antiguo si la imagen base lo trae: el viejo
  # gns3-br0-tree espera DHCP en br0 (inexistente en el fabric) y falla al boot.
  systemctl disable --now gns3-br0-tree.service 2>/dev/null || true
  rm -f /etc/systemd/system/gns3-br0-tree.service
  rm -f /etc/default/gns3-br0-tree
  if [ -f /usr/local/bin/configure-br0-tree.sh ]; then
    printf '#!/bin/bash\n# L3-FABRIC-NEUTRALIZED: br0 L2 ya no se usa en el fabric L3.\nexit 0\n' \
      >/usr/local/bin/configure-br0-tree.sh
    chmod +x /usr/local/bin/configure-br0-tree.sh
  fi
  rm -f /etc/systemd/system/k3s-iptables.service /usr/local/bin/k3s-br0-forwarding.sh

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
  # Base de k8s; fabric-bootstrap reafirma rp_filter=0, ip_forward y el ACCEPT de
  # transito del fabric en runtime. Aqui solo se deja el modulo de bridge para
  # contenedores docker y el forwarding habilitado desde el arranque.
  cat >/etc/sysctl.d/99-sdn.conf <<'EOF'
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF
  modprobe br_netfilter 2>/dev/null || true
  sysctl --system || true
}

install_autojoin_service() {
  install -m 0755 "$REPO_DIR/tools/gns3/k3s-autojoin-ha.sh" /usr/local/bin/k3s-autojoin.sh

  cat >/etc/systemd/system/k3s-autojoin.service <<'EOF'
[Unit]
Description=Instalacion automatica de K3S Worker (fabric L3)
After=fabric-bootstrap.service network-online.target
Requires=fabric-bootstrap.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/k3s-autojoin.sh
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  mkdir -p /etc/systemd/system/k3s-autojoin.service.d
  cat >/etc/systemd/system/k3s-autojoin.service.d/token.conf <<EOF
[Service]
Environment=RYU_K3S_NODE_TOKEN=$JOIN_TOKEN
Environment=RYU_K3S_API_ENDPOINT=$API_ENDPOINT
Environment=RYU_K3S_VERSION=$K3S_VERSION
EOF
  chmod 600 /etc/systemd/system/k3s-autojoin.service.d/token.conf

  systemctl daemon-reload
  systemctl enable k3s-autojoin.service
}

verify_units() {
  systemd-analyze verify \
    /etc/systemd/system/fabric-bootstrap.service \
    /etc/systemd/system/k3s-autojoin.service
}

require_root
validate_inputs
install_base_packages
resize_root_if_possible
upgrade_packages
install_docker
configure_hostname
write_l3_netplan
install_fabric_service
configure_network_wait
configure_forwarding
install_autojoin_service
verify_units

echo "prepare-k3s-worker-golden-image: Golden Image (fabric L3) lista; no arranques k3s-autojoin.service antes de sellar."
