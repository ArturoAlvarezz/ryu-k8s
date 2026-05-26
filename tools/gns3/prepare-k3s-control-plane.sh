#!/bin/bash
# Prepare a GNS3 VM to run as a K3s control-plane node.
set -euo pipefail

ROLE="${RYU_K3S_CP_ROLE:-${1:-}}"
NODE_NAME="${RYU_K3S_NODE_NAME:-${K3S_NODE_NAME:-${2:-}}}"
NODE_IP="${RYU_K3S_NODE_IP:-${K3S_NODE_IP:-${3:-}}}"
NODE_PREFIX="${RYU_K3S_NODE_PREFIX:-24}"
NODE_GATEWAY="${RYU_K3S_NODE_GATEWAY:-192.168.122.1}"
NODE_DNS="${RYU_K3S_NODE_DNS:-8.8.8.8 1.1.1.1}"
ALL_PORTS="${RYU_K3S_BR0_PORTS:-ens3 ens4 ens5 ens6}"
STP_PORTS="${RYU_K3S_STP_PORTS:-$ALL_PORTS}"
PREFERRED_STP_PORTS="${RYU_K3S_PREFERRED_STP_PORTS:-ens3 ens4}"
REPO_DIR="${RYU_K3S_REPO_DIR:-$PWD}"
SKIP_APT_UPGRADE="${RYU_K3S_SKIP_APT_UPGRADE:-false}"

usage() {
  cat <<'EOF'
Usage:
  sudo ./tools/gns3/prepare-k3s-control-plane.sh first [node-name] [node-ip]
  sudo ./tools/gns3/prepare-k3s-control-plane.sh additional <node-name> [node-ip]

Environment overrides:
  RYU_K3S_CP_ROLE              first | additional
  RYU_K3S_NODE_NAME            Hostname to configure
  RYU_K3S_NODE_IP              Static br0 IP. Required for first, optional for additional
  RYU_K3S_SKIP_APT_UPGRADE     true to skip apt upgrade
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
      NODE_IP="${NODE_IP:-192.168.122.100}"
      ;;
    additional)
      if [ -z "$NODE_NAME" ]; then
        echo "ERROR: additional control-plane nodes need RYU_K3S_NODE_NAME or argument 2" >&2
        usage >&2
        exit 1
      fi
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
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
    ca-certificates curl git net-tools cloud-guest-utils
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
}

yaml_list() {
  printf '['
  first_item=true
  for item in $1; do
    if [ "$first_item" = true ]; then
      first_item=false
    else
      printf ', '
    fi
    printf '%s' "$item"
  done
  printf ']'
}

write_netplan() {
  dns_list=$(yaml_list "$NODE_DNS")
  port_list=$(yaml_list "$ALL_PORTS")

  cat >/etc/netplan/50-cloud-init.yaml <<EOF
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      optional: true
    ens4:
      dhcp4: false
      optional: true
    ens5:
      dhcp4: false
      optional: true
    ens6:
      dhcp4: false
      optional: true
    ens7:
      dhcp4: false
      optional: true
    ens8:
      dhcp4: false
      optional: true
  bridges:
    br0:
      interfaces: $port_list
EOF

  if [ -n "$NODE_IP" ]; then
    cat >>/etc/netplan/50-cloud-init.yaml <<EOF
      dhcp4: false
      addresses:
        - $NODE_IP/$NODE_PREFIX
      routes:
        - to: default
          via: $NODE_GATEWAY
      nameservers:
        addresses: $dns_list
EOF
  else
    cat >>/etc/netplan/50-cloud-init.yaml <<'EOF'
      dhcp4: true
      dhcp-identifier: mac
EOF
  fi

  cat >>/etc/netplan/50-cloud-init.yaml <<'EOF'
      parameters:
        stp: true
EOF
  chmod 600 /etc/netplan/50-cloud-init.yaml
  netplan apply
}

install_br0_service() {
  install -m 0755 "$REPO_DIR/tools/gns3/configure-br0-tree.sh" /usr/local/bin/configure-br0-tree.sh

  if [ -n "$NODE_IP" ]; then
    cat >/etc/default/gns3-br0-tree <<EOF
NODE_IP=$NODE_IP
NODE_PREFIX=$NODE_PREFIX
NODE_GATEWAY=$NODE_GATEWAY
NODE_DNS=${NODE_DNS%% *}
ALL_PORTS="$ALL_PORTS"
STP_PORTS="$STP_PORTS"
PREFERRED_STP_PORTS="$PREFERRED_STP_PORTS"
EOF
  else
    rm -f /etc/default/gns3-br0-tree
  fi

  cat >/etc/systemd/system/gns3-br0-tree.service <<'EOF'
[Unit]
Description=Configurar br0 de gestion GNS3 con STP
DefaultDependencies=no
After=systemd-udev-settle.service systemd-networkd.service
Before=network-online.target k3s.service
Wants=systemd-udev-settle.service systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/configure-br0-tree.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now gns3-br0-tree.service
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
  cat >/etc/sysctl.d/99-sdn.conf <<'EOF'
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF
  sysctl --system

  cat >/usr/local/bin/k3s-br0-forwarding.sh <<'EOF'
#!/bin/sh
set -eu

iptables -C FORWARD -i br0 -o br0 -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i br0 -o br0 -j ACCEPT
iptables -C FORWARD -i ens3 -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i ens3 -j ACCEPT
iptables -C FORWARD -o ens3 -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -o ens3 -j ACCEPT
EOF
  chmod +x /usr/local/bin/k3s-br0-forwarding.sh

  cat >/etc/systemd/system/k3s-iptables.service <<'EOF'
[Unit]
Description=Reglas iptables para SDN/K3s
After=network-online.target k3s.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 3
ExecStart=/usr/local/bin/k3s-br0-forwarding.sh

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now k3s-iptables.service
}

require_root
validate_inputs
install_base_packages
resize_root_if_possible
upgrade_packages
install_docker
configure_hostname
write_netplan
install_br0_service
configure_network_wait
configure_forwarding

echo "prepare-k3s-control-plane: $NODE_NAME ready; br0=$(ip -4 addr show br0 | awk '/inet / {print $2}' | head -1)"
