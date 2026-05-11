#!/bin/bash
# Instala o une un nodo K3s server HA usando embedded etcd y VIP estable.
set -euo pipefail

K3S_NODE_TOKEN="${K3S_NODE_TOKEN:-}"
K3S_API_ENDPOINT="${K3S_API_ENDPOINT:-192.168.122.10}"
K3S_FIRST_SERVER_IP="${K3S_FIRST_SERVER_IP:-192.168.122.100}"
K3S_NODE_IP="${K3S_NODE_IP:-}"
K3S_CLUSTER_INIT="${K3S_CLUSTER_INIT:-false}"

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

COMMON_ARGS="server --node-ip=${K3S_NODE_IP} --advertise-address=${K3S_NODE_IP} --flannel-iface=br0 --tls-san=${K3S_API_ENDPOINT} --tls-san=${K3S_NODE_IP}"

if [ "$K3S_CLUSTER_INIT" = "true" ]; then
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="${COMMON_ARGS} --cluster-init" sh -
else
  curl -sfL https://get.k3s.io | \
    INSTALL_K3S_EXEC="${COMMON_ARGS}" \
    K3S_URL="https://${K3S_FIRST_SERVER_IP}:6443" \
    K3S_TOKEN="$K3S_NODE_TOKEN" \
    sh -
fi

mkdir -p /root/.kube /home/ubuntu/.kube
cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config
sed -i "s#https://127.0.0.1:6443#https://${K3S_API_ENDPOINT}:6443#g; s#https://${K3S_NODE_IP}:6443#https://${K3S_API_ENDPOINT}:6443#g" /root/.kube/config /home/ubuntu/.kube/config
chown -R ubuntu:ubuntu /home/ubuntu/.kube
