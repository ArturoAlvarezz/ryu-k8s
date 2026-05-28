#!/bin/sh
# Configure the GNS3 management bridge with STP and a deterministic node IP.
set -eu

CONFIG_FILE=${BR0_CONFIG_FILE:-/etc/default/gns3-br0-tree}

HOSTNAME=$(hostname)
ALL_PORTS=${ALL_PORTS:-"ens3 ens4 ens5 ens6"}
STP_PORTS=${STP_PORTS:-$ALL_PORTS}
PREFERRED_STP_PORTS=${PREFERRED_STP_PORTS:-$STP_PORTS}
BR_PRIORITY=${BR_PRIORITY:-32768}
STP_LOW_COST=${STP_LOW_COST:-10}
STP_HIGH_COST=${STP_HIGH_COST:-$STP_LOW_COST}
STP_EXPECTED_ROOT_PREFIX=${STP_EXPECTED_ROOT_PREFIX:-0000.}
STP_STABLE_SECONDS=${STP_STABLE_SECONDS:-20}
NODE_PREFIX=${NODE_PREFIX:-24}
NODE_GATEWAY=${NODE_GATEWAY:-192.168.122.1}
NODE_DNS=${NODE_DNS:-$NODE_GATEWAY}
BOOTSTRAP_DHCP_WAIT_SECONDS=${BOOTSTRAP_DHCP_WAIT_SECONDS:-180}

current_br0_ip() {
  ip -o -4 addr show dev br0 scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}'
}

prepare_bridge_for_bootstrap() {
  ip link show br0 >/dev/null 2>&1 || ip link add name br0 type bridge
  ip link set br0 type bridge stp_state 1 priority "$BR_PRIORITY" || true
  for iface in $ALL_PORTS; do
    if ip link show "$iface" >/dev/null 2>&1; then
      ip link set "$iface" master br0 2>/dev/null || true
      ip link set "$iface" up || true
    fi
  done
  ip link set br0 up
}

bootstrap_config_if_missing() {
  [ ! -r "$CONFIG_FILE" ] || return 0

  prepare_bridge_for_bootstrap
  bootstrap_ip=${NODE_IP:-}
  if [ -z "$bootstrap_ip" ]; then
    elapsed=0
    while [ "$elapsed" -lt "$BOOTSTRAP_DHCP_WAIT_SECONDS" ]; do
      bootstrap_ip=$(current_br0_ip || true)
      [ -n "$bootstrap_ip" ] && break
      sleep 2
      elapsed=$((elapsed + 2))
    done
  fi

  if [ -z "$bootstrap_ip" ]; then
    echo "configure-br0-tree: $CONFIG_FILE not found and br0 did not receive DHCP" >&2
    exit 1
  fi

  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat >"$CONFIG_FILE" <<EOF
NODE_IP=$bootstrap_ip
NODE_PREFIX=$NODE_PREFIX
NODE_GATEWAY=$NODE_GATEWAY
NODE_DNS=$NODE_DNS
ALL_PORTS="$ALL_PORTS"
STP_PORTS="$STP_PORTS"
PREFERRED_STP_PORTS="${BOOTSTRAP_PREFERRED_STP_PORTS:-$STP_PORTS}"
EOF
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true
  echo "configure-br0-tree: bootstrapped $CONFIG_FILE with NODE_IP=$bootstrap_ip"
}

bootstrap_config_if_missing
. "$CONFIG_FILE"

ALL_PORTS=${ALL_PORTS:-"ens3 ens4 ens5 ens6"}
STP_PORTS=${STP_PORTS:-$ALL_PORTS}
PREFERRED_STP_PORTS=${PREFERRED_STP_PORTS:-$STP_PORTS}
BR_PRIORITY=${BR_PRIORITY:-32768}
STP_LOW_COST=${STP_LOW_COST:-10}
STP_HIGH_COST=${STP_HIGH_COST:-$STP_LOW_COST}
STP_EXPECTED_ROOT_PREFIX=${STP_EXPECTED_ROOT_PREFIX:-0000.}
STP_STABLE_SECONDS=${STP_STABLE_SECONDS:-20}
NODE_PREFIX=${NODE_PREFIX:-24}
NODE_GATEWAY=${NODE_GATEWAY:-192.168.122.1}
NODE_DNS=${NODE_DNS:-$NODE_GATEWAY}

install_static_br0_networkd_config() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files systemd-networkd.service >/dev/null 2>&1 || return 0

  mkdir -p /etc/systemd/network
  cat >/etc/systemd/network/00-gns3-br0-static.network <<EOF
[Match]
Name=br0

[Network]
DHCP=no
Address=$NODE_IP/$NODE_PREFIX
LinkLocalAddressing=no
ConfigureWithoutCarrier=yes
KeepConfiguration=static
EOF

  if [ -n "$NODE_GATEWAY" ]; then
    cat >>/etc/systemd/network/00-gns3-br0-static.network <<EOF
Gateway=$NODE_GATEWAY
EOF
  fi

  if [ -n "$NODE_DNS" ]; then
    cat >>/etc/systemd/network/00-gns3-br0-static.network <<EOF
DNS=$NODE_DNS
EOF
  fi

  networkctl reload >/dev/null 2>&1 || true
}

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

install_static_br0_networkd_config

is_preferred_stp_port() {
  check_iface=$1
  for preferred_iface in $PREFERRED_STP_PORTS; do
    [ "$preferred_iface" = "$check_iface" ] && return 0
  done
  return 1
}

wait_for_stp() {
  stable=0
  for _ in $(seq 1 120); do
    pending=0
    forwarding=0
    root_ok=1

    if [ -n "$STP_EXPECTED_ROOT_PREFIX" ]; then
      root_id=$(cat /sys/class/net/br0/bridge/root_id 2>/dev/null || echo "")
      case "$root_id" in
        "$STP_EXPECTED_ROOT_PREFIX"*) ;;
        *) root_ok=0 ;;
      esac
    fi

    for iface in $STP_PORTS; do
      [ -e "/sys/class/net/br0/brif/$iface/state" ] || continue
      state=$(cat "/sys/class/net/br0/brif/$iface/state" 2>/dev/null || echo 0)
      case "$state" in
        1|2) pending=1 ;;
        3) forwarding=1 ;;
      esac
    done
    if [ "$pending" = "0" ] && [ "$forwarding" = "1" ] && [ "$root_ok" = "1" ]; then
      stable=$((stable + 1))
      [ "$stable" -ge "$STP_STABLE_SECONDS" ] && return 0
    else
      stable=0
    fi
    sleep 1
  done
  return 1
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
ip addr add "$NODE_IP/$NODE_PREFIX" dev br0 2>/dev/null || true
ip -o -4 addr show dev br0 scope global | while read -r _ _ _ cidr _; do
  case "$cidr" in
    "$NODE_IP/"*|*/32) continue ;;
  esac
  ip addr del "$cidr" dev br0 2>/dev/null || true
done
networkctl reconfigure br0 >/dev/null 2>&1 || true
ip route del default dev br0 proto dhcp 2>/dev/null || true
ip route del "$NODE_GATEWAY" dev br0 proto dhcp 2>/dev/null || true

if [ -n "$NODE_GATEWAY" ]; then
  ip route del default dev br0 proto static 2>/dev/null || true
  ip route replace default via "$NODE_GATEWAY" dev br0
fi

wait_for_stp || true

echo "configure-br0-tree: $HOSTNAME br0=$NODE_IP stp_ports=$STP_PORTS preferred_stp_ports=$PREFERRED_STP_PORTS"
