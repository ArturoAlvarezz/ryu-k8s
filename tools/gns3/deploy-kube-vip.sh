#!/bin/bash
# Despliega kube-vip (RBAC + DaemonSet) para el VIP del API en el fabric L3.
#
# En el fabric L3 kube-vip corre en modo BGP (NO ARP/L2): peerea con el FRR local
# de cada control-plane y anuncia el VIP del API 10.255.255.1/32. El DaemonSet vive
# en deploy/k8s/l3-fabric/kube-vip-bgp.yaml; este script solo agrega el RBAC (SA +
# ClusterRole) que ese manifiesto no incluye, y aplica el manifiesto.
set -euo pipefail

MODE="${1:-all}"
REPO_DIR="${RYU_K3S_REPO_DIR:-$PWD}"
BGP_MANIFEST="${RYU_K3S_KUBE_VIP_MANIFEST:-$REPO_DIR/deploy/k8s/l3-fabric/kube-vip-bgp.yaml}"

usage() {
  cat <<'EOF'
Usage:
  ./tools/gns3/deploy-kube-vip.sh rbac        # solo ServiceAccount + ClusterRole
  ./tools/gns3/deploy-kube-vip.sh daemonset    # solo el DaemonSet BGP (manifiesto)
  ./tools/gns3/deploy-kube-vip.sh all          # rbac + daemonset

Environment overrides:
  RYU_K3S_KUBE_VIP_MANIFEST   Ruta al manifiesto BGP (default deploy/k8s/l3-fabric/kube-vip-bgp.yaml)
EOF
}

kubectl_cmd() {
  if command -v kubectl >/dev/null 2>&1; then
    kubectl "$@"
  elif command -v k3s >/dev/null 2>&1; then
    k3s kubectl "$@"
  else
    echo "ERROR: kubectl or k3s is required" >&2
    exit 1
  fi
}

apply_rbac() {
  kubectl_cmd apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-vip
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:kube-vip-role
rules:
  - apiGroups: [""]
    resources: ["nodes", "endpoints", "configmaps"]
    verbs: ["list", "get", "watch", "update", "create", "patch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["list", "get", "watch", "update", "create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-vip-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-vip-role
subjects:
  - kind: ServiceAccount
    name: kube-vip
    namespace: kube-system
EOF
}

apply_daemonset() {
  if [ ! -f "$BGP_MANIFEST" ]; then
    echo "ERROR: no encuentro el manifiesto BGP en $BGP_MANIFEST" >&2
    echo "       Ejecuta desde la raiz del repo o define RYU_K3S_KUBE_VIP_MANIFEST." >&2
    exit 1
  fi
  kubectl_cmd apply -f "$BGP_MANIFEST"
  kubectl_cmd -n kube-system rollout status daemonset/kube-vip-bgp --timeout=240s || true
  kubectl_cmd -n kube-system get pods -l app=kube-vip-bgp -o wide || true
}

case "$MODE" in
  rbac)      apply_rbac ;;
  daemonset) apply_daemonset ;;
  all)       apply_rbac; apply_daemonset ;;
  *)         usage >&2; exit 1 ;;
esac
