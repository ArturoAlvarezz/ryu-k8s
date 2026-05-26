#!/bin/bash
# Install kube-vip RBAC and the control-plane VIP DaemonSet for the GNS3 K3s HA lab.
set -euo pipefail

MODE="${1:-all}"
VIP_ADDRESS="${RYU_K3S_VIP:-192.168.122.10}"
VIP_INTERFACE="${RYU_K3S_VIP_INTERFACE:-br0}"
KUBE_VIP_IMAGE="${RYU_K3S_KUBE_VIP_IMAGE:-ghcr.io/kube-vip/kube-vip:v0.8.7}"

usage() {
  cat <<'EOF'
Usage:
  ./tools/gns3/deploy-kube-vip.sh rbac
  ./tools/gns3/deploy-kube-vip.sh daemonset
  ./tools/gns3/deploy-kube-vip.sh all

Environment overrides:
  RYU_K3S_VIP                 VIP address, default 192.168.122.10
  RYU_K3S_VIP_INTERFACE       Interface, default br0
  RYU_K3S_KUBE_VIP_IMAGE      kube-vip image tag
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
  kubectl_cmd apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-vip-ds
  namespace: kube-system
  labels:
    app.kubernetes.io/name: kube-vip-ds
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kube-vip-ds
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kube-vip-ds
    spec:
      serviceAccountName: kube-vip
      hostNetwork: true
      hostAliases:
        - ip: "127.0.0.1"
          hostnames:
            - kubernetes
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: Exists
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
        - key: node-role.kubernetes.io/master
          operator: Exists
          effect: NoSchedule
      containers:
        - name: kube-vip
          image: $KUBE_VIP_IMAGE
          imagePullPolicy: IfNotPresent
          args:
            - manager
          env:
            - name: vip_arp
              value: "true"
            - name: port
              value: "6443"
            - name: vip_nodename
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: vip_interface
              value: $VIP_INTERFACE
            - name: vip_cidr
              value: "32"
            - name: dns_mode
              value: first
            - name: cp_enable
              value: "true"
            - name: cp_namespace
              value: kube-system
            - name: vip_leaderelection
              value: "true"
            - name: vip_leasename
              value: plndr-cp-lock
            - name: vip_leaseduration
              value: "5"
            - name: vip_renewdeadline
              value: "3"
            - name: vip_retryperiod
              value: "1"
            - name: address
              value: $VIP_ADDRESS
            - name: prometheus_server
              value: :2112
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
                - NET_RAW
          volumeMounts:
            - mountPath: /etc/kubernetes/admin.conf
              name: kubeconfig
      volumes:
        - name: kubeconfig
          hostPath:
            path: /etc/rancher/k3s/k3s.yaml
EOF

  kubectl_cmd -n kube-system rollout status daemonset/kube-vip-ds --timeout=240s
  kubectl_cmd -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide
  kubectl_cmd -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{"\n"}' || true
}

case "$MODE" in
  rbac)
    apply_rbac
    ;;
  daemonset)
    apply_daemonset
    ;;
  all)
    apply_rbac
    apply_daemonset
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
