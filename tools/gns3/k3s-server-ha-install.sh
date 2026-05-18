#!/bin/bash
# Instala o une un nodo K3s server HA usando embedded etcd y VIP estable.
set -euo pipefail

K3S_NODE_TOKEN="${K3S_NODE_TOKEN:-}"
K3S_API_ENDPOINT="${K3S_API_ENDPOINT:-192.168.122.10}"
K3S_FIRST_SERVER_IP="${K3S_FIRST_SERVER_IP:-192.168.122.100}"
K3S_NODE_IP="${K3S_NODE_IP:-}"
K3S_CLUSTER_INIT="${K3S_CLUSTER_INIT:-false}"

install_br0_tree_guard() {
  if [ ! -r /etc/default/gns3-br0-tree ]; then
    echo "gns3-br0-tree: /etc/default/gns3-br0-tree not found; skipping optional STP bridge service"
    return 0
  fi

  cat >/usr/local/bin/configure-br0-tree.sh <<'EOF'
#!/bin/sh
# Configure the GNS3 management bridge with STP for automatic failover.
set -eu

CONFIG_FILE=${BR0_CONFIG_FILE:-/etc/default/gns3-br0-tree}
if [ -r "$CONFIG_FILE" ]; then
  . "$CONFIG_FILE"
else
  echo "configure-br0-tree: $CONFIG_FILE not found; skipping br0 reconfiguration"
  exit 0
fi

HOSTNAME=$(hostname)
ALL_PORTS=${ALL_PORTS:-"ens3 ens4 ens5 ens6"}
STP_PORTS=${STP_PORTS:-$ALL_PORTS}
PREFERRED_STP_PORTS=${PREFERRED_STP_PORTS:-$STP_PORTS}
BR_PRIORITY=${BR_PRIORITY:-32768}
STP_LOW_COST=${STP_LOW_COST:-10}
STP_HIGH_COST=${STP_HIGH_COST:-200}
NODE_PREFIX=${NODE_PREFIX:-24}
NODE_GATEWAY=${NODE_GATEWAY:-192.168.122.1}

if [ -z "${NODE_IP:-}" ]; then
  echo "configure-br0-tree: define NODE_IP in $CONFIG_FILE" >&2
  exit 1
fi

case "$NODE_IP:${BR0_MAC:-}" in
  *\<*|*\>*)
    echo "configure-br0-tree: replace placeholder values in $CONFIG_FILE" >&2
    exit 1
    ;;
esac

is_preferred_stp_port() {
  check_iface=$1
  for preferred_iface in $PREFERRED_STP_PORTS; do
    [ "$preferred_iface" = "$check_iface" ] && return 0
  done
  return 1
}

wait_for_stp() {
  for _ in $(seq 1 45); do
    pending=0; forwarding=0
    for iface in $STP_PORTS; do
      [ -e "/sys/class/net/br0/brif/$iface/state" ] || continue
      state=$(cat "/sys/class/net/br0/brif/$iface/state" 2>/dev/null || echo 0)
      case "$state" in 1|2) pending=1 ;; 3) forwarding=1 ;; esac
    done
    [ "$pending" = "0" ] && [ "$forwarding" = "1" ] && return 0
    sleep 1
  done
}
ip link show br0 >/dev/null 2>&1 || ip link add name br0 type bridge
if [ -n "${BR0_MAC:-}" ]; then
  ip link set br0 address "$BR0_MAC" || true
fi
ip link set br0 type bridge stp_state 1 priority "$BR_PRIORITY" || true
for iface in $ALL_PORTS; do
  if ip link show "$iface" >/dev/null 2>&1; then
    ip link set "$iface" master br0 2>/dev/null || true
    ip link set "$iface" down || true
  fi
done
for iface in $STP_PORTS; do
  ip link show "$iface" >/dev/null 2>&1 || continue
  ip link set "$iface" master br0 2>/dev/null || true
  ip link set "$iface" up
  if is_preferred_stp_port "$iface"; then bridge link set dev "$iface" cost "$STP_LOW_COST" 2>/dev/null || true; else bridge link set dev "$iface" cost "$STP_HIGH_COST" 2>/dev/null || true; fi
done
ip link set br0 up
ip addr flush dev br0
ip addr add "$NODE_IP/$NODE_PREFIX" dev br0
if [ -n "$NODE_GATEWAY" ]; then
  ip route replace default via "$NODE_GATEWAY" dev br0
fi
wait_for_stp || true
echo "configure-br0-tree: $HOSTNAME br0=$NODE_IP stp_ports=$STP_PORTS preferred_stp_ports=$PREFERRED_STP_PORTS"
EOF
  chmod +x /usr/local/bin/configure-br0-tree.sh

  cat >/etc/systemd/system/gns3-br0-tree.service <<'EOF'
[Unit]
Description=Configure loop-free br0 tree for GNS3 SDN lab
Before=network-online.target k3s.service k3s-agent.service
After=network-online.target systemd-udev-settle.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/configure-br0-tree.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable gns3-br0-tree.service
  systemctl start gns3-br0-tree.service
}

install_br0_tree_guard

if [ -z "$K3S_NODE_IP" ]; then
  K3S_NODE_IP=$(ip -4 addr show br0 | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
fi

if [ -z "$K3S_NODE_IP" ]; then
  echo "ERROR: no se pudo detectar K3S_NODE_IP en br0" >&2
  exit 1
fi

if [ "$K3S_CLUSTER_INIT" != "true" ] && [ -z "$K3S_NODE_TOKEN" ]; then
  echo "ERROR: define K3S_NODE_TOKEN para unir servidores adicionales" >&2
  exit 1
fi

COMMON_ARGS="server --node-ip=${K3S_NODE_IP} --advertise-address=${K3S_NODE_IP} --flannel-iface=br0 --tls-san=${K3S_API_ENDPOINT} --tls-san=${K3S_NODE_IP} --etcd-arg=heartbeat-interval=500 --etcd-arg=election-timeout=5000"

if [ "$K3S_CLUSTER_INIT" = "true" ]; then
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="${COMMON_ARGS} --cluster-init" sh -
else
  curl -sfL https://get.k3s.io | \
    INSTALL_K3S_EXEC="${COMMON_ARGS}" \
    K3S_URL="https://${K3S_FIRST_SERVER_IP}:6443" \
    K3S_TOKEN="$K3S_NODE_TOKEN" \
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
if [ -f /etc/systemd/system/gns3-br0-tree.service ]; then
  cat >/etc/systemd/system/k3s.service.d/10-gns3-boot-guard.conf <<'EOF'
[Unit]
Requires=gns3-br0-tree.service
After=gns3-br0-tree.service

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
sed -i "s#https://127.0.0.1:6443#https://${K3S_API_ENDPOINT}:6443#g; s#https://${K3S_NODE_IP}:6443#https://${K3S_API_ENDPOINT}:6443#g" /root/.kube/config /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube
