#!/bin/sh
# Configure the GNS3 management bridge as a plain Linux bridge (NO STP).
# Jun 2026: STP removed from the architecture. br0 is the management plane
# (K3s/etcd/flannel) and runs as a transparent Linux bridge. The SDN data
# plane (br-sdn) handles loop prevention via MST/Dijkstra in Ryu, not STP.
#
# This script is kept for reference; in the new architecture it is NOT
# enabled by default. The gns3-br0-tree.service is disabled on every node.
# If you need to re-enable STP for an emergency, see the legacy
# configure-br0-tree.stp.sh variant (not in this repo).
set -eu

CONFIG_FILE=${BR0_CONFIG_FILE:-/etc/default/gns3-br0-tree}

HOSTNAME=$(hostname)
ALL_PORTS=${ALL_PORTS:-"ens3 ens4 ens5 ens6"}
NODE_PREFIX=${NODE_PREFIX:-24}
NODE_GATEWAY=${NODE_GATEWAY:-192.168.122.1}
NODE_DNS=${NODE_DNS:-$NODE_GATEWAY}
BOOTSTRAP_DHCP_WAIT_SECONDS=${BOOTSTRAP_DHCP_WAIT_SECONDS:-180}

current_br0_ip() {
    ip -o -4 addr show dev br0 scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}'
}

prepare_bridge_for_bootstrap() {
    ip link show br0 >/dev/null 2>&1 || ip link add name br0 type bridge
    # Explicitly disable STP on br0 (stp_state 0). The new architecture
    # relies on MST/Dijkstra in Ryu for loop prevention, not STP on br0.
    ip link set br0 type bridge stp_state 0 || true
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
EOF
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    echo "configure-br0-tree: bootstrapped $CONFIG_FILE with NODE_IP=$bootstrap_ip"
}

bootstrap_config_if_missing
. "$CONFIG_FILE"

ALL_PORTS=${ALL_PORTS:-"ens3 ens4 ens5 ens6"}
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

[Bridge]
STP=no
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

ip link show br0 >/dev/null 2>&1 || ip link add name br0 type bridge

if [ -n "${BR0_MAC:-}" ]; then
    ip link set br0 address "$BR0_MAC" || true
fi

# Disable STP on br0 (new architecture: no STP anywhere in the SDN path)
ip link set br0 type bridge stp_state 0 || true

for iface in $ALL_PORTS; do
    if ip link show "$iface" >/dev/null 2>&1; then
        ip link set "$iface" master br0 2>/dev/null || true
        ip link set "$iface" up || true
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

echo "configure-br0-tree: $HOSTNAME br0=$NODE_IP ports=$ALL_PORTS (NO STP, new architecture)"
