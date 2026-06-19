#!/bin/sh
# worker-mgmt-failover.sh - Failover de management para workers sin uplink directo.
#
# Normalmente solo ens3 esta en br0 (sube por la cadena de workers hasta el
# worker-hub y de ahi a master). Si master deja de responder porque el hub de la
# cadena se cayo, este daemon enslava BACKUP_PORT (ens4) a br0. Ese puerto
# conecta directo a un control-plane (control-3, cuyo ens4 esta siempre en br0),
# formando un camino alternativo de gestion SIN STP.
#
# Mismo patron y garantias que uplink-failover.sh:
#   - BACKUP_PORT solo se enslava cuando el plano de gestion es INALCANZABLE.
#     La salud se mide contra el VIP HA de K3s (kube-vip, 192.168.122.10): es
#     el endpoint real del API server y flota entre control-planes, asi que un
#     master caido con el cluster sano NO dispara un failover espurio. Mientras
#     el hub de la cadena este caido, el extremo primario del posible loop
#     tambien esta abajo, asi que enslavar NO forma un bucle activo.
#   - FAILBACK por guard de tormenta: cuando el hub vuelve, el camino primario
#     (ens3) y el backup (ens4) quedan activos a la vez -> loop -> el multicast
#     se dispara y el guard libera BACKUP_PORT. Diseno auto-reparable que NO
#     depende de la IP de ningun worker (los workers se recrean y cambian de
#     IP/hostname; hardcodear una seria fragil).
#   - NO se libera por ping al VIP: estando enslavado, el VIP es alcanzable a
#     traves del propio backup, asi que ese ping no distingue "primario vivo".
#     Por eso el failback es exclusivamente por tormenta (igual que el failback
#     de uplink-failover.sh).
#
# Unico valor fijo: MGMT_VIP (el VIP HA de K3s, estable). Que worker corre el
# daemon, su BACKUP_PORT y el cableado al control-plane se definen por config
# (/etc/default/worker-mgmt-failover), nunca por una IP de worker hardcodeada.
set -u

CONF=/etc/default/worker-mgmt-failover
[ -r "$CONF" ] && . "$CONF"

BRIDGE=${BRIDGE:-br0}
BACKUP_PORT=${BACKUP_PORT:-ens4}
MGMT_VIP=${MGMT_VIP:-192.168.122.10}
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
    log "ENSLAVE $BACKUP_PORT -> $BRIDGE (VIP $MGMT_VIP inalcanzable; activando backup)"
}

release() {
    is_enslaved || return 0
    ip link set "$BACKUP_PORT" nomaster || return 1
    log "RELEASE $BACKUP_PORT de $BRIDGE (tormenta de failback: primario de vuelta)"
}

ping_ok() { ping -c1 -W1 "$1" >/dev/null 2>&1; }

# Tasa de "tormenta" para detectar el loop de failback. En un loop L2 las tramas
# inundadas circulan y se reciben en el BACKUP_PORT a miles de pps. Medimos el
# MAXIMO entre el contador multicast del bridge y el rx_packets del backup port:
# un storm de BROADCAST (ARP, tipico al restaurar un ENLACE entre dos nodos vivos)
# NO incrementa el contador 'multicast' del bridge -> el guard original quedaba
# ciego y nunca liberaba el backup, perpetuando el loop. rx_packets del backup
# sube con cualquier tipo de tormenta (broadcast/multicast/flood unicast).
storm_rate() {
    mf="/sys/class/net/$BRIDGE/statistics/multicast"
    rf="/sys/class/net/$BACKUP_PORT/statistics/rx_packets"
    m0=$(cat "$mf" 2>/dev/null || echo 0)
    r0=$(cat "$rf" 2>/dev/null || echo 0)
    sleep 1
    m1=$(cat "$mf" 2>/dev/null || echo 0)
    r1=$(cat "$rf" 2>/dev/null || echo 0)
    dm=$((m1 - m0)); dr=$((r1 - r0))
    [ "$dr" -gt "$dm" ] && echo "$dr" || echo "$dm"
}

now() { cut -d. -f1 /proc/uptime; }

fail=0
cooldown_until=0
log "iniciado: backup_port=$BACKUP_PORT vip=$MGMT_VIP"

while :; do
    t=$(now)

    if is_enslaved; then
        # Failback exclusivamente por tormenta: si el primario volvio, ens3+ens4
        # forman loop y el multicast se dispara. Liberamos y entramos en
        # cooldown. NO liberamos por ping al VIP (alcanzable via el backup).
        rate=$(storm_rate)
        if [ "${rate:-0}" -gt "$STORM_PPS" ]; then
            log "TORMENTA en $BRIDGE (${rate} pps en $BACKUP_PORT/mcast) -> liberando $BACKUP_PORT"
            release
            fail=0
            cooldown_until=$((t + STORM_COOLDOWN))
        fi
        # Sin tormenta: permanecer enslavado. El backup sostiene el plano de
        # gestion durante todo el outage del hub.
    else
        if ping_ok "$MGMT_VIP"; then
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
