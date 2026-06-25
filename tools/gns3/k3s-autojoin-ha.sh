#!/bin/bash
# Auto-join de nodos K3s agent contra el VIP HA del API Server, sobre el fabric L3.
#
# Requiere que fabric-bootstrap.service ya haya montado el fabric: la loopback /32
# (10.255.x, derivada de /etc/machine-id) es el --node-ip, y OSPF da alcance al VIP
# del API (10.255.255.1, anunciado por kube-vip BGP) y a internet via el NAT del CP.
set -euo pipefail

JOIN_TOKEN="${RYU_K3S_NODE_TOKEN:-${K3S_NODE_TOKEN:-}}"
API_ENDPOINT="${RYU_K3S_API_ENDPOINT:-${K3S_API_ENDPOINT:-10.255.255.1}}"
K3S_VERSION="${RYU_K3S_VERSION:-v1.35.5+k3s1}"
FABRIC_SUPERNET="${FABRIC_SUPERNET:-10.255}"

if systemctl list-unit-files k3s.service 2>/dev/null | grep -q '^k3s.service'; then
  echo "[autojoin] k3s server detectado; no se instala k3s-agent ni se cambia hostname."
  exit 0
fi

if [ -z "$JOIN_TOKEN" ] || echo "$JOIN_TOKEN" | grep -q '^<'; then
  echo "[autojoin] ERROR: define RYU_K3S_NODE_TOKEN con el token real del cluster HA."
  exit 1
fi

# --- 1. Loopback del fabric (--node-ip) -------------------------------------
# fabric-bootstrap.service la asigna a lo como /32 dentro de la supernet 10.255.
echo "[autojoin] Esperando la loopback del fabric en lo..."
LOOPBACK=""
for _ in $(seq 1 90); do
  LOOPBACK=$(ip -4 -o addr show dev lo 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1 | grep "^${FABRIC_SUPERNET}\." | head -1 || true)
  [ -n "${LOOPBACK:-}" ] && break
  sleep 2
done

if [ -z "${LOOPBACK:-}" ]; then
  echo "[autojoin] ERROR: no aparecio la loopback ${FABRIC_SUPERNET}.x en lo tras 180s."
  echo "[autojoin]        Revisa fabric-bootstrap.service y FRR (vtysh -c 'show ip ospf neighbor')."
  exit 1
fi

# --- 2. Hostname estable y unico (worker-<mac de ens3>) ---------------------
# La MAC de ens3 es estable por VM en GNS3; da un nombre legible y unico. Si no
# existe ens3, se deriva de /etc/machine-id (misma raiz que la loopback).
MAC_SUFFIX=$(ip link show ens3 2>/dev/null | awk '/ether/ {print $2}' | awk -F: '{print $4$5$6}')
if [ -z "${MAC_SUFFIX:-}" ]; then
  MAC_SUFFIX=$(cut -c1-6 /etc/machine-id)
fi
NEW_HOSTNAME="worker-${MAC_SUFFIX}"

# --- 3. Idempotencia: si ya se unio con esta identidad, no reinstalar -------
if systemctl list-unit-files k3s-agent.service 2>/dev/null | grep -q '^k3s-agent.service'; then
  if grep -R -q -- "--node-ip=$LOOPBACK" /etc/systemd/system/k3s-agent.service* /etc/rancher/k3s 2>/dev/null; then
    echo "[autojoin] k3s-agent ya instalado con node-ip $LOOPBACK ($NEW_HOSTNAME)."
    exit 0
  fi
  echo "[autojoin] ERROR: k3s-agent existe con otro node-ip. Reinstala el agent tras corregir el fabric."
  exit 1
fi

hostnamectl set-hostname "$NEW_HOSTNAME"
sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 $NEW_HOSTNAME" >> /etc/hosts
printf 'preserve_hostname: true\n' >/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg

# --- 4. Esperar el VIP del API (kube-vip BGP) -------------------------------
echo "[autojoin] Esperando API Server HA en ${API_ENDPOINT}:6443 (via fabric)..."
API_READY=false
for _ in $(seq 1 90); do
  if timeout 2 bash -c "</dev/tcp/${API_ENDPOINT}/6443" >/dev/null 2>&1; then
    API_READY=true
    break
  fi
  sleep 3
done

if [ "$API_READY" != true ]; then
  echo "[autojoin] ERROR: API Server HA no responde en ${API_ENDPOINT}:6443."
  echo "[autojoin]        Verifica OSPF (ruta al VIP) y kube-vip BGP en los control-planes."
  exit 1
fi

# --- 5. Instalar y unir el agent (node-ip = loopback del fabric) ------------
# Sin --flannel-iface: flannel esta deshabilitado en el server (Calico BGP da CNI).
curl -sfL https://get.k3s.io | \
  env -u RYU_K3S_NODE_TOKEN -u K3S_NODE_TOKEN \
    -u RYU_K3S_API_ENDPOINT -u K3S_API_ENDPOINT -u RYU_K3S_VERSION \
  INSTALL_K3S_VERSION="$K3S_VERSION" \
  INSTALL_K3S_EXEC="--node-name=$NEW_HOSTNAME --node-ip=$LOOPBACK" \
  K3S_URL="https://${API_ENDPOINT}:6443" \
  K3S_TOKEN="$JOIN_TOKEN" \
  sh -

echo "[autojoin] Nodo $NEW_HOSTNAME unido al cluster HA (node-ip=$LOOPBACK)."
