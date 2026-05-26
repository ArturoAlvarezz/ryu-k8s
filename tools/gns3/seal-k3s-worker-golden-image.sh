#!/bin/bash
# Seal the K3s worker Golden Image before exporting the qcow2 disk.
set -euo pipefail

POWER_OFF="${RYU_K3S_POWER_OFF_AFTER_SEAL:-true}"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script with sudo" >&2
    exit 1
  fi
}

validate_golden_image_state() {
  systemctl is-enabled k3s-autojoin.service >/dev/null
  if systemctl is-active --quiet k3s-autojoin.service; then
    echo "ERROR: k3s-autojoin.service is active; do not seal a worker that already joined" >&2
    exit 1
  fi
  if systemctl list-unit-files k3s-agent.service 2>/dev/null | grep -q '^k3s-agent.service'; then
    echo "ERROR: k3s-agent is installed; this VM is not a clean Golden Image" >&2
    exit 1
  fi
}

clean_identity_and_runtime_state() {
  rm -f /etc/default/gns3-br0-tree
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id
  ln -s /etc/machine-id /var/lib/dbus/machine-id
  rm -rf /var/lib/cloud/instances/* /var/lib/cloud/instance 2>/dev/null || true
  journalctl --vacuum-time=1s || true
  find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
  rm -f /root/.bash_history /home/ubuntu/.bash_history 2>/dev/null || true
}

require_root
validate_golden_image_state
clean_identity_and_runtime_state

echo "seal-k3s-worker-golden-image: Golden Image sealed."
if [ "$POWER_OFF" = "true" ]; then
  poweroff
fi
