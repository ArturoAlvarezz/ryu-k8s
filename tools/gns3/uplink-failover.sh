#!/bin/sh
# uplink-failover.sh - Failover activo/standby del uplink de gestion, SIN STP.
#
# Normalmente solo el master enslava su puerto hacia el Mgmt-STP-Switch (ens3)
# a br0; los control planes lo dejan fuera para mantener br0 libre de loops
# (ver configure-br0-tree.sh). Eso hace de master un punto unico de fallo para
# la salida a internet (NAT1 / gateway 192.168.122.1).
#
# Este daemon corre en los control planes de respaldo (control-2 = PRIORITY 1,
# control-3 = PRIORITY 2). Cuando master deja de responder, enslava el uplink
# local a br0 para que el cluster conserve su camino a NAT1. Cuando master
# vuelve (o si se detecta una tormenta de broadcast) libera el puerto.
#
# Seguridad ante loops:
#   - Solo se activa cuando master es INALCANZABLE. Si master no responde es
#     porque su VM esta caida o su enlace directo esta abajo; en ambos casos no
#     existe un segundo camino y enslavar el uplink NO forma loop.
#   - Un guard de tormenta libera el puerto de inmediato si llegara a formarse
#     un loop (p.ej. en la breve ventana de failback cuando master regresa),
#     haciendo el diseno auto-reparable.
#   - El uplink (ens3) es puramente plano de gestion; br-sdn / VXLAN / los smart
#     meters NO lo usan, asi que el failover nunca afecta su trafico.
set -u

CONF=/etc/default/uplink-failover
[ -r "$CONF" ] && . "$CONF"

BRIDGE=${BRIDGE:-br0}
UPLINK_PORT=${UPLINK_PORT:-ens3}
MASTER_IP=${MASTER_IP:-192.168.122.100}
GATEWAY=${GATEWAY:-192.168.122.1}
PRIORITY=${PRIORITY:-1}              # 1 = respaldo primario, 2 = secundario
POLL_INTERVAL=${POLL_INTERVAL:-2}
FAIL_THRESHOLD=${FAIL_THRESHOLD:-2}  # polls fallidos consecutivos antes de actuar
STORM_PPS=${STORM_PPS:-1000}         # multicast/s en br0 que se considera loop
STORM_COOLDOWN=${STORM_COOLDOWN:-20} # s sin re-activar tras detectar tormenta

log() { logger -t uplink-failover "$*" 2>/dev/null; echo "uplink-failover: $*"; }

is_enslaved() { [ -d "/sys/class/net/$BRIDGE/brif/$UPLINK_PORT" ]; }

enslave() {
    is_enslaved && return 0
    ip link set "$UPLINK_PORT" master "$BRIDGE" || return 1
    ip link set "$UPLINK_PORT" up || true
    log "ENSLAVE $UPLINK_PORT -> $BRIDGE (master $MASTER_IP inalcanzable; tomando el uplink)"
}

release() {
    is_enslaved || return 0
    ip link set "$UPLINK_PORT" nomaster || return 1
    log "RELEASE $UPLINK_PORT de $BRIDGE (master presente o tormenta)"
}

ping_ok() { ping -c1 -W1 "$1" >/dev/null 2>&1; }

mcast_delta() {
    f="/sys/class/net/$BRIDGE/statistics/multicast"
    a=$(cat "$f" 2>/dev/null || echo 0)
    sleep 1
    b=$(cat "$f" 2>/dev/null || echo 0)
    echo $((b - a))
}

now() { cut -d. -f1 /proc/uptime; }

fail=0
cooldown_until=0
log "iniciado: priority=$PRIORITY uplink=$UPLINK_PORT master=$MASTER_IP gw=$GATEWAY"

while :; do
    t=$(now)

    # Guard de tormenta: si tenemos el uplink y aparece un storm, soltarlo ya.
    if is_enslaved; then
        rate=$(mcast_delta)
        if [ "${rate:-0}" -gt "$STORM_PPS" ]; then
            log "TORMENTA en $BRIDGE (${rate} mcast/s) -> liberando $UPLINK_PORT para romper el loop"
            release
            fail=0
            cooldown_until=$((t + STORM_COOLDOWN))
            sleep "$POLL_INTERVAL"
            continue
        fi
    fi

    if ping_ok "$MASTER_IP"; then
        fail=0
        release                      # master vivo -> permanecer en standby
    else
        fail=$((fail + 1))
        if [ "$fail" -ge "$FAIL_THRESHOLD" ] && [ "$t" -ge "$cooldown_until" ]; then
            take=0
            if [ "$PRIORITY" = "1" ]; then
                take=1
            elif ! ping_ok "$GATEWAY"; then
                take=1               # secundario: solo si el primario no restauro el gw
            fi
            if [ "$take" = "1" ]; then
                enslave
            else
                release
            fi
        fi
    fi

    sleep "$POLL_INTERVAL"
done
