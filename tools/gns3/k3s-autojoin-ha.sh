#!/bin/bash
# Auto-join de nodos K3s agent contra el VIP HA del API Server.
set -euo pipefail

K3S_NODE_TOKEN="${K3S_NODE_TOKEN:-}"
K3S_API_ENDPOINT="${K3S_API_ENDPOINT:-192.168.122.10}"

if [ -x /usr/local/bin/configure-br0-tree.sh ]; then
  /usr/local/bin/configure-br0-tree.sh || true
fi

if [ -z "$K3S_NODE_TOKEN" ] || echo "$K3S_NODE_TOKEN" | grep -q '^<'; then
  echo "[autojoin] ERROR: define K3S_NODE_TOKEN con el token real del cluster HA."
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

echo "[autojoin] Esperando API Server HA en ${K3S_API_ENDPOINT}:6443..."
for _ in $(seq 1 60); do
  if timeout 2 bash -c "</dev/tcp/${K3S_API_ENDPOINT}/6443" >/dev/null 2>&1; then
    API_READY=true
    break
  fi
  sleep 3
done

if [ "${API_READY:-false}" != true ]; then
  echo "[autojoin] ERROR: API Server HA no responde en ${K3S_API_ENDPOINT}:6443."
  exit 1
fi

curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="--node-ip=$MY_IP --flannel-iface=br0" \
  K3S_URL="https://${K3S_API_ENDPOINT}:6443" \
  K3S_TOKEN="$K3S_NODE_TOKEN" \
  sh -

mkdir -p /etc/systemd/system/k3s-agent.service.d
cat >/etc/systemd/system/k3s-agent.service.d/10-gns3-br0-tree.conf <<'EOF'
[Unit]
Requires=gns3-br0-tree.service
After=gns3-br0-tree.service
EOF
systemctl daemon-reload

echo "[autojoin] Nodo $NEW_HOSTNAME unido al cluster HA."
