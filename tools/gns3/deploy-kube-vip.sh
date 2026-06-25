#!/bin/bash
# Despliega kube-vip HÍBRIDO para el VIP del API en el fabric L3.
#
# Dos VIPs coexisten (IP/interfaz/lease/puerto distintos):
#   - BGP  10.255.255.1  (DaemonSet kube-vip-bgp): VIP en `lo`, propagado por OSPF
#     fabric-wide. Lo usan agentes/servidores del cluster (HA L3-nativa). Interno al fabric.
#   - ARP  192.168.122.10 (DaemonSet kube-vip): flota entre los 3 CP por el L2 del
#     Mgmt-Switch. Para acceso del HOST (que no alcanza la /32 del fabric) + dashboards.
#
# Manifiestos: deploy/k8s/l3-fabric/kube-vip-{arp,bgp}.yaml (el ARP incluye el RBAC).
set -euo pipefail

MODE="${1:-all}"
REPO_DIR="${RYU_K3S_REPO_DIR:-$PWD}"
ARP_MANIFEST="${RYU_K3S_KUBE_VIP_ARP:-$REPO_DIR/deploy/k8s/l3-fabric/kube-vip-arp.yaml}"
BGP_MANIFEST="${RYU_K3S_KUBE_VIP_BGP:-$REPO_DIR/deploy/k8s/l3-fabric/kube-vip-bgp.yaml}"

usage() {
  cat <<'EOF'
Usage:
  ./tools/gns3/deploy-kube-vip.sh arp     # solo VIP ARP 192.168.122.10 (host) + RBAC
  ./tools/gns3/deploy-kube-vip.sh bgp     # solo VIP BGP 10.255.255.1 (fabric)
  ./tools/gns3/deploy-kube-vip.sh all     # híbrido: ARP + BGP (recomendado)
EOF
}

kubectl_cmd() {
  if command -v kubectl >/dev/null 2>&1; then kubectl "$@"
  elif command -v k3s >/dev/null 2>&1; then k3s kubectl "$@"
  else echo "ERROR: kubectl or k3s is required" >&2; exit 1; fi
}

apply_manifest() {
  f="$1"; ds="$2"; lbl="$3"
  if [ ! -f "$f" ]; then
    echo "ERROR: no encuentro $f (ejecuta desde la raíz del repo o define la ruta)." >&2
    exit 1
  fi
  kubectl_cmd apply -f "$f"
  kubectl_cmd -n kube-system rollout status "daemonset/$ds" --timeout=240s || true
  kubectl_cmd -n kube-system get pods -l "app=$lbl" -o wide || true
}

case "$MODE" in
  arp) apply_manifest "$ARP_MANIFEST" kube-vip kube-vip ;;
  bgp) apply_manifest "$BGP_MANIFEST" kube-vip-bgp kube-vip-bgp ;;
  all)
    apply_manifest "$ARP_MANIFEST" kube-vip kube-vip          # incluye RBAC + VIP host
    apply_manifest "$BGP_MANIFEST" kube-vip-bgp kube-vip-bgp  # VIP fabric
    ;;
  *) usage >&2; exit 1 ;;
esac
