#!/bin/bash
# Instala o une un nodo K3s server HA (embedded etcd) sobre el fabric L3.
#
# El --node-ip/--advertise-address es la LOOPBACK /32 del fabric (la monta antes
# fabric-bootstrap.service). flannel va DESHABILITADO (Calico BGP da la CNI) y el
# VIP del API (10.255.255.1) lo anuncia kube-vip en modo BGP. Requiere que
# fabric-bootstrap.sh ya haya corrido (loopback presente en lo).
set -euo pipefail

JOIN_TOKEN="${RYU_K3S_NODE_TOKEN:-${K3S_NODE_TOKEN:-}}"
API_ENDPOINT="${RYU_K3S_API_ENDPOINT:-${K3S_API_ENDPOINT:-10.255.255.1}}"
# Para CPs adicionales: IP del primer server para el join. Por defecto el VIP
# (ya activo cuando se agrega el 2.o/3.er CP); si el VIP aun no existe, pasar la
# loopback del primer CP en RYU_K3S_FIRST_SERVER_IP.
FIRST_SERVER_IP="${RYU_K3S_FIRST_SERVER_IP:-${K3S_FIRST_SERVER_IP:-$API_ENDPOINT}}"
NODE_IP="${RYU_K3S_NODE_IP:-${K3S_NODE_IP:-}}"
CLUSTER_INIT="${RYU_K3S_CLUSTER_INIT:-${K3S_CLUSTER_INIT:-false}}"
NODE_NAME="${RYU_K3S_NODE_NAME:-${K3S_NODE_NAME:-$(hostname)}}"
FABRIC_SUPERNET="${FABRIC_SUPERNET:-10.255}"

# --- Loopback del fabric como node-ip ----------------------------------------
if [ -z "$NODE_IP" ]; then
  for _ in $(seq 1 60); do
    NODE_IP=$(ip -4 -o addr show dev lo 2>/dev/null \
      | awk '{print $4}' | cut -d/ -f1 | grep "^${FABRIC_SUPERNET}\." \
      | grep -vx "10.255.255.1" | head -1 || true)
    [ -n "$NODE_IP" ] && break
    sleep 2
  done
fi
if [ -z "$NODE_IP" ]; then
  echo "ERROR: no aparece la loopback ${FABRIC_SUPERNET}.x en lo. ¿Corrio fabric-bootstrap.service?" >&2
  exit 1
fi

if [ "$CLUSTER_INIT" != "true" ] && [ -z "$JOIN_TOKEN" ]; then
  echo "ERROR: define RYU_K3S_NODE_TOKEN para unir servidores adicionales" >&2
  exit 1
fi

# Flags identicos al cluster vivo: flannel off (Calico BGP), tls-san al VIP +
# loopback, etcd holgado para 1 vCPU.
COMMON_ARGS="server --node-name=${NODE_NAME} --node-ip=${NODE_IP} --advertise-address=${NODE_IP} --flannel-backend=none --disable-network-policy --tls-san=${API_ENDPOINT} --tls-san=${NODE_IP} --etcd-arg=heartbeat-interval=500 --etcd-arg=election-timeout=5000"

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

# K3s debe arrancar DESPUES de fabric-bootstrap (necesita la loopback como node-ip)
# y darse un margen tras el boot en GNS3 (1 vCPU) para que OSPF converja.
cat >/usr/local/bin/k3s-gns3-boot-guard.sh <<EOF
#!/bin/sh
set -eu
for _ in \$(seq 1 120); do
  NODE_IP=\$(ip -4 -o addr show dev lo 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 \
    | grep "^${FABRIC_SUPERNET}\\." | grep -vx "10.255.255.1" | head -1 || true)
  [ -n "\${NODE_IP:-}" ] && break
  sleep 2
done
if [ -z "\${NODE_IP:-}" ]; then
  echo "k3s-gns3-boot-guard: sin loopback del fabric en lo" >&2
  exit 1
fi
UPTIME_SECONDS=\$(cut -d. -f1 /proc/uptime)
BOOT_DELAY=\${K3S_BOOT_DELAY_SECONDS:-120}
if [ "\$UPTIME_SECONDS" -lt 600 ] && [ "\$BOOT_DELAY" -gt 0 ]; then
  sleep "\$BOOT_DELAY"
fi
EOF
chmod +x /usr/local/bin/k3s-gns3-boot-guard.sh

mkdir -p /etc/systemd/system/k3s.service.d
cat >/etc/systemd/system/k3s.service.d/10-fabric-boot-guard.conf <<'EOF'
[Unit]
Requires=fabric-bootstrap.service
After=fabric-bootstrap.service

[Service]
ExecStartPre=/usr/local/bin/k3s-gns3-boot-guard.sh
RestartSec=15s
EOF
systemctl daemon-reload

mkdir -p /etc/kubernetes
ln -sf /etc/rancher/k3s/k3s.yaml /etc/kubernetes/admin.conf

mkdir -p /root/.kube /home/ubuntu/.kube
cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config
sed -i "s#https://127.0.0.1:6443#https://${API_ENDPOINT}:6443#g; s#https://${NODE_IP}:6443#https://${API_ENDPOINT}:6443#g" /root/.kube/config /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube

echo "k3s-server-ha-install: $NODE_NAME server listo (node-ip=$NODE_IP, VIP=$API_ENDPOINT)."
echo "  Tras el PRIMER server: aplica kube-vip BGP y Calico:"
echo "    sudo ./tools/gns3/deploy-kube-vip.sh all"
echo "    kubectl apply -f deploy/k8s/l3-fabric/calico-bgp.yaml"
