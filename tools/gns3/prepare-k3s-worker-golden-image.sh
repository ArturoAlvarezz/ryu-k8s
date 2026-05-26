#!/bin/bash
# Prepare a GNS3 VM as the reusable K3s worker Golden Image.
set -euo pipefail

JOIN_TOKEN="${RYU_K3S_NODE_TOKEN:-${K3S_NODE_TOKEN:-${1:-}}}"
API_ENDPOINT="${RYU_K3S_API_ENDPOINT:-${K3S_API_ENDPOINT:-192.168.122.10}}"
NODE_PREFIX="${RYU_K3S_NODE_PREFIX:-24}"
NODE_GATEWAY="${RYU_K3S_NODE_GATEWAY:-192.168.122.1}"
NODE_DNS="${RYU_K3S_NODE_DNS:-$NODE_GATEWAY}"
ALL_PORTS="${RYU_K3S_BR0_PORTS:-ens3 ens4 ens5 ens6}"
STP_PORTS="${RYU_K3S_STP_PORTS:-$ALL_PORTS}"
PREFERRED_STP_PORTS="${RYU_K3S_PREFERRED_STP_PORTS:-ens3}"
REPO_DIR="${RYU_K3S_REPO_DIR:-$PWD}"
SKIP_APT_UPGRADE="${RYU_K3S_SKIP_APT_UPGRADE:-false}"

usage() {
  cat <<'EOF'
Usage:
  sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL>' ./tools/gns3/prepare-k3s-worker-golden-image.sh

Environment overrides:
  RYU_K3S_NODE_TOKEN        Required K3s cluster token for worker auto-join
  RYU_K3S_API_ENDPOINT      API VIP, default 192.168.122.10
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

configure_hostname() {
  hostnamectl set-hostname worker-golden
  printf 'worker-golden\n' >/etc/hostname
  sed -i '/127.0.1.1/d' /etc/hosts
  printf '127.0.1.1 worker-golden\n' >>/etc/hosts
  mkdir -p /etc/cloud/cloud.cfg.d
  printf 'preserve_hostname: false\n' >/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg
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
      dhcp4: true
      dhcp-identifier: mac
      nameservers:
        addresses: $dns_list
      parameters:
        stp: true
EOF
  chmod 600 /etc/netplan/50-cloud-init.yaml
  netplan apply
}

install_br0_service() {
  install -m 0755 "$REPO_DIR/tools/gns3/configure-br0-tree.sh" /usr/local/bin/configure-br0-tree.sh
  rm -f /etc/default/gns3-br0-tree

  cat >/etc/systemd/system/gns3-br0-tree.service <<'EOF'
[Unit]
Description=Configurar br0 de gestion GNS3 con STP
DefaultDependencies=no
After=systemd-udev-settle.service systemd-networkd.service
Before=network-online.target k3s-agent.service
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
  systemctl enable gns3-br0-tree.service
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
EOF
  chmod +x /usr/local/bin/k3s-br0-forwarding.sh

  cat >/etc/systemd/system/k3s-iptables.service <<'EOF'
[Unit]
Description=Regla iptables de forwarding para br0
After=network-online.target k3s-agent.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/bin/k3s-br0-forwarding.sh

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now k3s-iptables.service
}

install_autojoin_service() {
  install -m 0755 "$REPO_DIR/tools/gns3/k3s-autojoin-ha.sh" /usr/local/bin/k3s-autojoin.sh

  cat >/etc/systemd/system/k3s-autojoin.service <<'EOF'
[Unit]
Description=Instalacion automatica de K3S Worker
After=gns3-br0-tree.service network-online.target
Requires=gns3-br0-tree.service
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
EOF
  chmod 600 /etc/systemd/system/k3s-autojoin.service.d/token.conf

  systemctl daemon-reload
  systemctl enable k3s-autojoin.service
}

verify_units() {
  systemd-analyze verify \
    /etc/systemd/system/gns3-br0-tree.service \
    /etc/systemd/system/k3s-autojoin.service \
    /etc/systemd/system/k3s-iptables.service
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
install_autojoin_service
verify_units

echo "prepare-k3s-worker-golden-image: Golden Image ready; do not start k3s-autojoin.service before sealing."
