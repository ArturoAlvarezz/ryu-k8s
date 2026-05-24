#!/bin/bash
# Instala o une un nodo K3s server HA usando embedded etcd y VIP estable.
set -euo pipefail

JOIN_TOKEN="${RYU_K3S_NODE_TOKEN:-${K3S_NODE_TOKEN:-}}"
API_ENDPOINT="${RYU_K3S_API_ENDPOINT:-${K3S_API_ENDPOINT:-192.168.122.10}}"
FIRST_SERVER_IP="${RYU_K3S_FIRST_SERVER_IP:-${K3S_FIRST_SERVER_IP:-192.168.122.100}}"
NODE_IP="${RYU_K3S_NODE_IP:-${K3S_NODE_IP:-}}"
CLUSTER_INIT="${RYU_K3S_CLUSTER_INIT:-${K3S_CLUSTER_INIT:-false}}"
NODE_NAME="${RYU_K3S_NODE_NAME:-${K3S_NODE_NAME:-$(hostname)}}"

if [ -z "$NODE_IP" ]; then
  NODE_IP=$(ip -4 addr show br0 | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
fi

if [ -z "$NODE_IP" ]; then
  echo "ERROR: no se pudo detectar RYU_K3S_NODE_IP en br0" >&2
  exit 1
fi

if [ "$CLUSTER_INIT" != "true" ] && [ -z "$JOIN_TOKEN" ]; then
  echo "ERROR: define RYU_K3S_NODE_TOKEN para unir servidores adicionales" >&2
  exit 1
fi

COMMON_ARGS="server --node-name=${NODE_NAME} --node-ip=${NODE_IP} --advertise-address=${NODE_IP} --flannel-iface=br0 --tls-san=${API_ENDPOINT} --tls-san=${NODE_IP} --etcd-arg=heartbeat-interval=500 --etcd-arg=election-timeout=5000"

if [ "$CLUSTER_INIT" = "true" ]; then
  curl -sfL https://get.k3s.io | \
    env -u RYU_K3S_NODE_TOKEN -u K3S_NODE_TOKEN \
      -u RYU_K3S_API_ENDPOINT -u K3S_API_ENDPOINT \
      -u RYU_K3S_FIRST_SERVER_IP -u K3S_FIRST_SERVER_IP \
      -u RYU_K3S_NODE_IP -u K3S_NODE_IP \
      -u RYU_K3S_NODE_NAME -u K3S_NODE_NAME \
      -u RYU_K3S_CLUSTER_INIT -u K3S_CLUSTER_INIT \
      INSTALL_K3S_EXEC="${COMMON_ARGS} --cluster-init" \
      sh -
else
  curl -sfL https://get.k3s.io | \
    env -u RYU_K3S_NODE_TOKEN -u K3S_NODE_TOKEN \
      -u RYU_K3S_API_ENDPOINT -u K3S_API_ENDPOINT \
      -u RYU_K3S_FIRST_SERVER_IP -u K3S_FIRST_SERVER_IP \
      -u RYU_K3S_NODE_IP -u K3S_NODE_IP \
      -u RYU_K3S_NODE_NAME -u K3S_NODE_NAME \
      -u RYU_K3S_CLUSTER_INIT -u K3S_CLUSTER_INIT \
    INSTALL_K3S_EXEC="${COMMON_ARGS}" \
    K3S_URL="https://${FIRST_SERVER_IP}:6443" \
    K3S_TOKEN="$JOIN_TOKEN" \
    sh -
fi

cat >/usr/local/bin/k3s-gns3-boot-guard.sh <<'EOF'
#!/bin/sh
set -eu

for _ in $(seq 1 120); do
  NODE_IP=$(ip -4 addr show br0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  [ -n "${NODE_IP:-}" ] && break
  sleep 2
done

if [ -z "${NODE_IP:-}" ]; then
  echo "k3s-gns3-boot-guard: br0 has no IPv4 address" >&2
  exit 1
fi

UPTIME_SECONDS=$(cut -d. -f1 /proc/uptime)
BOOT_DELAY=${K3S_BOOT_DELAY_SECONDS:-120}
if [ "$UPTIME_SECONDS" -lt 600 ] && [ "$BOOT_DELAY" -gt 0 ]; then
  sleep "$BOOT_DELAY"
fi
EOF
chmod +x /usr/local/bin/k3s-gns3-boot-guard.sh

mkdir -p /etc/systemd/system/k3s.service.d

[Service]
ExecStartPre=/usr/local/bin/k3s-gns3-boot-guard.sh
RestartSec=15s
EOF
else
  cat >/etc/systemd/system/k3s.service.d/10-gns3-boot-guard.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/bin/k3s-gns3-boot-guard.sh
RestartSec=15s
EOF
fi
systemctl daemon-reload

mkdir -p /etc/kubernetes
ln -sf /etc/rancher/k3s/k3s.yaml /etc/kubernetes/admin.conf

mkdir -p /root/.kube /home/ubuntu/.kube
cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config
sed -i "s#https://127.0.0.1:6443#https://${API_ENDPOINT}:6443#g; s#https://${NODE_IP}:6443#https://${API_ENDPOINT}:6443#g" /root/.kube/config /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube
