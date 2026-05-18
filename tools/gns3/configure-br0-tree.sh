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
    pending=0
    forwarding=0
    for iface in $STP_PORTS; do
      [ -e "/sys/class/net/br0/brif/$iface/state" ] || continue
      state=$(cat "/sys/class/net/br0/brif/$iface/state" 2>/dev/null || echo 0)
      case "$state" in
        1|2) pending=1 ;;
        3) forwarding=1 ;;
      esac
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
  if ip link show "$iface" >/dev/null 2>&1; then
    ip link set "$iface" master br0 2>/dev/null || true
    ip link set "$iface" up
    if is_preferred_stp_port "$iface"; then
      bridge link set dev "$iface" cost "$STP_LOW_COST" 2>/dev/null || true
    else
      bridge link set dev "$iface" cost "$STP_HIGH_COST" 2>/dev/null || true
    fi
  else
    echo "configure-br0-tree: expected interface $iface not found on $HOSTNAME" >&2
  fi
done

ip link set br0 up
ip addr flush dev br0
ip addr add "$NODE_IP/$NODE_PREFIX" dev br0
if [ -n "$NODE_GATEWAY" ]; then
  ip route replace default via "$NODE_GATEWAY" dev br0
fi

wait_for_stp || true

echo "configure-br0-tree: $HOSTNAME br0=$NODE_IP stp_ports=$STP_PORTS preferred_stp_ports=$PREFERRED_STP_PORTS"
