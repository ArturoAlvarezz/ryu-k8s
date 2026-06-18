#!/bin/sh
# worker-mgmt-failover.sh - Failover de management para workers sin uplink directo.
#
# Normalmente solo ens3 esta en br0 (conecta hacia arriba por la cadena de workers
# hasta master). Si master deja de responder (porque worker-b56b35, el nodo hub,
# se cayo), este daemon enslava BACKUP_PORT a br0. Ese puerto conecta directamente
# a un control plane (control-3 para worker-ea7e34) que tiene su lado siempre
# activo, formando un camino alternativo sin STP.
#
# Seguridad ante loops:
#   - BACKUP_PORT solo se activa cuando master es inalcanzable. Si master esta
#     caido o su cadena esta rota, el otro extremo del loop tambien esta caido,
#     por lo que no se forma un bucle activo.
#   - Un guard de tormenta libera el puerto inmediatamente si el multicast sube
#     (caso de race condition durante el failback cuando b56b35 vuelve).
#   - En cuanto master vuelve a responder, se libera BACKUP_PORT.
set -u

CONF=/etc/default/worker-mgmt-failover
[ -r "$CONF" ] && . "$CONF"

BRIDGE=${BRIDGE:-br0}
BACKUP_PORT=${BACKUP_PORT:-ens4}
MASTER_IP=${MASTER_IP:-192.168.122.100}
# IP del primer salto del camino PRIMARIO. Cuando este nodo responde, el camino
# primario esta restaurado y podemos liberar BACKUP_PORT (evita el ciclo donde
# el propio backup hace que MASTER_IP sea accesible y el daemon se auto-libera).
PRIMARY_GATEWAY=${PRIMARY_GATEWAY:-}
POLL_INTERVAL=${POLL_INTERVAL:-2}
FAIL_THRESHOLD=${FAIL_THRESHOLD:-2}
STORM_PPS=${STORM_PPS:-1000}
STORM_COOLDOWN=${STORM_COOLDOWN:-20}

log() { logger -t worker-mgmt-failover "$*" 2>/dev/null; echo "worker-mgmt-failover: $*"; }

is_enslaved() { [ -d "/sys/class/net/$BRIDGE/brif/$BACKUP_PORT" ]; }

enslave() {
    is_enslaved && return 0
    ip link set "$BACKUP_PORT" master "$BRIDGE" || return 1
    ip link set "$BACKUP_PORT" up || true
    log "ENSLAVE $BACKUP_PORT -> $BRIDGE (master $MASTER_IP inalcanzable; activando backup)"
}

release() {
    is_enslaved || return 0
    ip link set "$BACKUP_PORT" nomaster || return 1
    log "RELEASE $BACKUP_PORT de $BRIDGE (camino primario restaurado)"
}

ping_ok() { ping -c1 -W1 "$1" >/dev/null 2>&1; }

# Retorna 0 si el camino PRIMARIO esta restaurado.
# Si PRIMARY_GATEWAY esta definido, lo usa como indicador (su alcanzabilidad
# implica que el nodo hub primario [b56b35] esta de vuelta). Si no, cae al
# master directamente — pero PRIMARY_GATEWAY deberia estar definido cuando el
# backup path hace que master sea accesible por si solo (ciclo de auto-release).
primary_ok() {
    if [ -n "$PRIMARY_GATEWAY" ]; then
        ping_ok "$PRIMARY_GATEWAY"
    else
        ping_ok "$MASTER_IP"
    fi
}

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
log "iniciado: backup_port=$BACKUP_PORT master=$MASTER_IP primary_gateway=${PRIMARY_GATEWAY:-none}"

while :; do
    t=$(now)

    if is_enslaved; then
        rate=$(mcast_delta)
        if [ "${rate:-0}" -gt "$STORM_PPS" ]; then
            log "TORMENTA en $BRIDGE (${rate} mcast/s) -> liberando $BACKUP_PORT"
            release
            fail=0
            cooldown_until=$((t + STORM_COOLDOWN))
            sleep "$POLL_INTERVAL"
            continue
        fi
        # Solo liberar si el camino primario esta restaurado (no si solo master
        # responde a traves del propio backup, lo que causaria un ciclo).
        if primary_ok; then
            fail=0
            release
        fi
    else
        if ping_ok "$MASTER_IP"; then
            fail=0
        else
            fail=$((fail + 1))
            if [ "$fail" -ge "$FAIL_THRESHOLD" ] && [ "$t" -ge "$cooldown_until" ]; then
                enslave
            fi
        fi
    fi

    sleep "$POLL_INTERVAL"
done
