#!/bin/bash
# Auto-join de nodos K3s agent contra el VIP HA del API Server.
set -euo pipefail

JOIN_TOKEN="${RYU_K3S_NODE_TOKEN:-${K3S_NODE_TOKEN:-}}"
API_ENDPOINT="${RYU_K3S_API_ENDPOINT:-${K3S_API_ENDPOINT:-192.168.122.10}}"

if systemctl list-unit-files k3s.service 2>/dev/null | grep -q '^k3s.service'; then
  echo "[autojoin] k3s server detectado; no se instala k3s-agent ni se cambia hostname."
  exit 0
fi

install_br0_dependency() {
  if [ -f /etc/systemd/system/gns3-br0-tree.service ]; then
    mkdir -p /etc/systemd/system/k3s-agent.service.d
    cat >/etc/systemd/system/k3s-agent.service.d/10-gns3-br0-tree.conf <<'EOF'
[Unit]
Requires=gns3-br0-tree.service
After=gns3-br0-tree.service
EOF
    systemctl daemon-reload
  fi
}

install_br0_forwarding_service() {
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
ExecStartPre=/bin/sleep 1
ExecStart=/usr/local/bin/k3s-br0-forwarding.sh

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now k3s-iptables.service
}

if [ -x /usr/local/bin/configure-br0-tree.sh ]; then
  /usr/local/bin/configure-br0-tree.sh || true
fi

if [ -z "$JOIN_TOKEN" ] || echo "$JOIN_TOKEN" | grep -q '^<'; then
  echo "[autojoin] ERROR: define RYU_K3S_NODE_TOKEN con el token real del cluster HA."
  exit 1
fi

echo "[autojoin] Esperando IP de gestion en br0..."
for _ in $(seq 1 90); do
  MY_IP=$(ip -4 addr show br0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  [ -n "${MY_IP:-}" ] && break
  sleep 2
done

if [ -z "${MY_IP:-}" ]; then
  echo "[autojoin] ERROR: no se obtuvo IP en br0 tras 180s."
  exit 1
fi

if systemctl list-unit-files k3s-agent.service 2>/dev/null | grep -q '^k3s-agent.service'; then
  install_br0_dependency
  install_br0_forwarding_service
  if grep -R -q -- "--node-ip=$MY_IP" /etc/systemd/system/k3s-agent.service* /etc/rancher/k3s 2>/dev/null; then
    echo "[autojoin] k3s-agent ya instalado con IP $MY_IP."
    exit 0
  fi
  echo "[autojoin] ERROR: k3s-agent existe con otra IP. Reinstala el agent tras corregir DHCP."
  exit 1
fi

MAC_ADDR=$(ip link show br0 | awk '/ether/ {print $2}' | awk -F: '{print $4$5$6}')
NEW_HOSTNAME="worker-${MAC_ADDR}"
hostnamectl set-hostname "$NEW_HOSTNAME"
sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 $NEW_HOSTNAME" >> /etc/hosts
printf 'preserve_hostname: true\n' >/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg

echo "[autojoin] Esperando API Server HA en ${API_ENDPOINT}:6443..."
for _ in $(seq 1 60); do
  if timeout 2 bash -c "</dev/tcp/${API_ENDPOINT}/6443" >/dev/null 2>&1; then
    API_READY=true
    break
  fi
  sleep 3
done

if [ "${API_READY:-false}" != true ]; then
  echo "[autojoin] ERROR: API Server HA no responde en ${API_ENDPOINT}:6443."
  exit 1
fi

curl -sfL https://get.k3s.io | \
  env -u RYU_K3S_NODE_TOKEN -u K3S_NODE_TOKEN \
    -u RYU_K3S_API_ENDPOINT -u K3S_API_ENDPOINT \
  INSTALL_K3S_EXEC="--node-name=$NEW_HOSTNAME --node-ip=$MY_IP --flannel-iface=br0" \
  K3S_URL="https://${API_ENDPOINT}:6443" \
  K3S_TOKEN="$JOIN_TOKEN" \
  sh -

install_br0_dependency
install_br0_forwarding_service

echo "[autojoin] Nodo $NEW_HOSTNAME unido al cluster HA."
