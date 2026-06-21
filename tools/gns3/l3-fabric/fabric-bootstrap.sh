#!/bin/sh
# fabric-bootstrap.sh — Configuración de red IDÉNTICA en todos los nodos.
#
# Convierte la red física en un L3 routed fabric, UNIFORME y robusto (sin LLDP):
#   - Loopback /32 ESTABLE derivada de /etc/machine-id (NO depende de DHCP).
#   - Candidatos de fabric: ens3..ens6 (convención del proyecto; ens7+ = guest/SDN,
#     se dejan para OVS). El puerto guest (ens8) NUNCA entra al fabric.
#   - Worker: toda ens3-6 con carrier es enlace de fabric (loopback unnumbered + OSPF).
#   - Control-plane: igual, salvo la interfaz EDGE hacia el Mgmt-Switch/NAT, que
#     se detecta por la FDB de br0 (puerto donde está aprendida la MAC del gateway).
#     Esa edge conserva la IP de gestión 192.168.122.x + default + hace NAT egress
#     y origina default en OSPF -> da internet y acceso al resto del fabric.
#
# Byte-idéntico en todos. El perfil CP/worker es por ROL (hostname), no por identidad.
set -eu

FABRIC_SUPERNET="${FABRIC_SUPERNET:-10.255}"
FABRIC_ASN="${FABRIC_ASN:-64512}"
FRR_CONF="${FRR_CONF:-/etc/frr/frr.conf}"

# --- Rol por hostname (mismo patrón que node_role() del proyecto) -------------
case "$(hostname)" in
    master|master-*|control-*|controlplane-*|control-plane-*) IS_CP=yes ;;
    *) IS_CP=no ;;
esac

# --- 1. Capturar gestión ANTES del teardown (vive en br0, no en la física) ----
MGMT_IP="$(ip -4 -o addr show br0 2>/dev/null | awk '{print $4; exit}')"        # 192.168.122.X/24
MGMT_GW="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
# El edge se detecta abajo por ALCANCE DIRECTO del gateway (1 salto L2): solo la
# interfaz físicamente en el Mgmt-Switch/NAT responde. NO se usa la FDB (daría el
# uplink multi-salto hacia ese nodo) ni LLDP (inservible aquí).

# --- 2. Loopback /32 estable desde machine-id --------------------------------
machine_id="$(cat /etc/machine-id)"
h="$(printf '%s' "$machine_id" | sha256sum | cut -c1-4)"
b1=$(( 0x${h} / 256 )); b2=$(( 0x${h} % 256 ))
LOOPBACK="${FABRIC_SUPERNET}.${b1}.${b2}"
ip addr replace "${LOOPBACK}/32" dev lo
echo "fabric-bootstrap: role=${IS_CP} loopback=${LOOPBACK}/32 edge=${EDGE_IFACE:-none} gw=${MGMT_GW:-none}"

# --- 2-bis. Neutralizar el netplan/cloud-init que recrea br0 -----------------
# CRÍTICO: la imagen base trae un netplan de cloud-init que define el viejo
# bridge L2 'br0' enslavando ens3-6. systemd-networkd lo RECREA en cada arranque
# (y cloud-init regenera el netplan), así que un simple 'ip link del br0' se
# deshace en segundos -> las interfaces fabric quedan esclavas de br0 y NO admiten
# la loopback /32 -> OSPF unnumbered muerto -> el nodo reiniciado sale del fabric.
# Se neutraliza en el origen: deshabilitar la regeneración de red de cloud-init y
# sustituir el netplan por uno mínimo (todas las ens UP, sin direcciones ni br0).
# Idempotente; solo se reaplica si el netplan aún define un bridge.
printf 'network: {config: disabled}\n' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
if grep -qE 'br0|bridges' /etc/netplan/*.yaml 2>/dev/null; then
    rm -f /etc/netplan/*.yaml
    cat > /etc/netplan/50-l3-fabric.yaml <<'NETPLAN'
network:
  version: 2
  renderer: networkd
  ethernets:
    fabric-ens:
      match: {name: "ens*"}
      optional: true
NETPLAN
    chmod 600 /etc/netplan/50-l3-fabric.yaml
    netplan apply 2>/dev/null || true
    ip link del br0 2>/dev/null || true
    echo "fabric-bootstrap: netplan br0 neutralizado (cloud-init net desactivado)"
fi

# --- 3. Clasificar ens3-6 y montar el fabric ---------------------------------
# 3a. Llevar ens3-6 a UP y ESPERAR a que GNS3 establezca el carrier del enlace.
# GNS3/QEMU negocian el carrier varios segundos DESPUÉS de que arranca la VM; si
# clasificamos en el instante exacto del bootstrap, una interfaz aún sin carrier
# quedaba fuera del fabric PARA SIEMPRE (sin loopback /32 -> el OSPF unnumbered de
# FRR nunca se activa en ella) -> al reiniciar, el worker quedaba aislado de OSPF y
# no reingresaba al clúster (kubelet sin ruta al API), y los workers leaf detrás
# cascadeaban a NotReady. Esperar a que el conjunto con carrier se estabilice
# (máx 60s, salida temprana) elimina ese race de orden de arranque.
for i in ens3 ens4 ens5 ens6; do
    [ -e "/sys/class/net/$i" ] || continue
    ip link set "$i" up || true
done
prev=""; stable=0
for _ in $(seq 1 60); do
    cur=""
    for i in ens3 ens4 ens5 ens6; do
        [ "$(cat "/sys/class/net/$i/carrier" 2>/dev/null)" = "1" ] && cur="${cur} ${i}"
    done
    if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then
        stable=$((stable + 1)); [ "$stable" -ge 5 ] && break
    else
        stable=0
    fi
    prev="$cur"; sleep 1
done

# 3a-bis. Candidatos con carrier ya estable; soltar de br0.
candidates=""
for i in ens3 ens4 ens5 ens6; do
    [ -e "/sys/class/net/$i" ] || continue
    [ "$(cat "/sys/class/net/$i/carrier" 2>/dev/null)" = "1" ] || continue
    ip link set "$i" nomaster 2>/dev/null || true
    ip addr flush dev "$i" scope global 2>/dev/null || true
    candidates="${candidates} ${i}"
done
ip link del br0 2>/dev/null || true            # retirar el bridge L2 viejo

# rp_filter=0: imprescindible en un fabric L3 unnumbered. Con rp_filter!=0 el
# kernel descarta los hellos OSPF cuyo origen aún no tiene ruta de vuelta (los
# nodos sin red de respaldo caen en un deadlock: necesitan la ruta para aceptar
# el hello, y el hello para obtener la ruta). Persistir en sysctl.d.
sysctl -wq net.ipv4.conf.all.rp_filter=0 || true
sysctl -wq net.ipv4.conf.default.rp_filter=0 || true
{
    echo "net.ipv4.conf.all.rp_filter=0"
    echo "net.ipv4.conf.default.rp_filter=0"
} > /etc/sysctl.d/99-l3-fabric.conf
for i in ens3 ens4 ens5 ens6; do sysctl -wq "net.ipv4.conf.${i}.rp_filter=0" 2>/dev/null || true; done

# Permitir el FORWARDING de tránsito del fabric (loopback-a-loopback). K3s/Calico
# instalan cadenas en FORWARD que, en los nodos de tránsito, descartan el reenvío
# de paquetes 10.255->10.255 que no son de pods -> rompe la alcanzabilidad
# multi-salto entre loopbacks (y el camino de vuelta). Esta regla ACCEPT lo
# garantiza; cali-FORWARD (pos 1) hace RETURN del tránsito, así que esta la captura.
iptables -C FORWARD -s "${FABRIC_SUPERNET}.0.0/16" -d "${FABRIC_SUPERNET}.0.0/16" -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "${FABRIC_SUPERNET}.0.0/16" -d "${FABRIC_SUPERNET}.0.0/16" -j ACCEPT

# 3b. Edge (solo CP): la interfaz por la que el gateway responde DIRECTO (1 salto).
edge_iface=""
if [ "$IS_CP" = yes ] && [ -n "${MGMT_GW:-}" ] && [ -n "${MGMT_IP:-}" ]; then
    for i in $candidates; do
        ip addr replace "${MGMT_IP}" dev "$i"
        if ping -c1 -W1 -I "$i" "$MGMT_GW" >/dev/null 2>&1; then
            edge_iface="$i"; break
        fi
        ip addr flush dev "$i" scope global 2>/dev/null || true
    done
fi

# 3c. El resto de candidatos -> fabric (loopback /32 unnumbered).
fabric_ifaces=""
for i in $candidates; do
    [ "$i" = "$edge_iface" ] && continue
    fabric_ifaces="${fabric_ifaces} ${i}"
    ip addr flush dev "$i" scope global 2>/dev/null || true
    ip addr replace "${LOOPBACK}/32" dev "$i" 2>/dev/null || true
done

# --- 4. Edge/NAT (solo CP con interfaz al Mgmt-Switch) ------------------------
NAT_EGRESS="no"
if [ -n "$edge_iface" ] && [ -n "${MGMT_IP:-}" ]; then
    ip addr flush dev "$edge_iface" scope global 2>/dev/null || true
    ip addr replace "${MGMT_IP}" dev "$edge_iface"
    ip link set "$edge_iface" up
    [ -n "${MGMT_GW:-}" ] && ip route replace default via "${MGMT_GW}" dev "$edge_iface" || true
    NAT_EGRESS="yes"
    sysctl -wq net.ipv4.ip_forward=1 || true
    iptables -t nat -C POSTROUTING -s "${FABRIC_SUPERNET}.0.0/16" -o "${edge_iface}" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "${FABRIC_SUPERNET}.0.0/16" -o "${edge_iface}" -j MASQUERADE
    echo "fabric-bootstrap: edge=${edge_iface} mgmt=${MGMT_IP} -> NAT egress + default-origination"
fi

# --- 5. FRR (OSPF unnumbered + BGP) ------------------------------------------
{
    echo "frr version 8.4"; echo "frr defaults traditional"; echo "hostname $(hostname)"
    echo "log syslog informational"; echo "service integrated-vtysh-config"; echo "ip forwarding"; echo "!"
    for i in $fabric_ifaces; do
        echo "interface ${i}"; echo " ip ospf network point-to-point"; echo " ip ospf area 0"; echo "!"
    done
    echo "interface lo"; echo " ip ospf area 0"; echo "!"
    echo "router ospf"; echo " ospf router-id ${LOOPBACK}"; echo " maximum-paths 8"; echo " passive-interface lo"
    [ "$NAT_EGRESS" = "yes" ] && echo " default-information originate"
    echo "!"
    echo "router bgp ${FABRIC_ASN}"; echo " bgp router-id ${LOOPBACK}"; echo " no bgp ebgp-requires-policy"
    echo " bgp listen range ${FABRIC_SUPERNET}.0.0/16 peer-group FABRIC"
    echo " neighbor FABRIC peer-group"; echo " neighbor FABRIC remote-as ${FABRIC_ASN}"; echo " neighbor FABRIC update-source lo"
    echo " address-family ipv4 unicast"; echo "  redistribute connected"
    echo "  neighbor FABRIC activate"; echo "  neighbor FABRIC next-hop-self"; echo " exit-address-family"; echo "!"
} > "${FRR_CONF}"

sed -i 's/^ospfd=no/ospfd=yes/; s/^bgpd=no/bgpd=yes/' /etc/frr/daemons 2>/dev/null || true
systemctl enable frr 2>/dev/null || true
systemctl restart frr
echo "fabric-bootstrap: FRR activo. fabric=[${fabric_ifaces} ] edge=${edge_iface:-none} nat=${NAT_EGRESS}"
