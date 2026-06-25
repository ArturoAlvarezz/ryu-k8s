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

# --- 1. Capturar gestión (CP) de forma ROBUSTA y PERSISTENTE ------------------
# La IP de gestión del control-plane (192.168.122.x del Mgmt-Switch) ya NO puede
# leerse solo de br0: erradicamos br0 en cada arranque, así que en boots posteriores
# 'ip addr show br0' está vacío -> sin MGMT_IP la detección de edge se salta y el CP
# pierde su IP de gestión (regresión real observada). Cadena de fuentes:
#   br0 (legacy, si aún existe) -> netplan viejo -> /etc/l3-fabric/mgmt.env persistido.
# Se persiste en la primera captura para los arranques donde br0/netplan ya no estén.
# (Excepción de bootstrap permitida para los planos de control.)
PERSIST=/etc/l3-fabric/mgmt.env
mkdir -p /etc/l3-fabric
MGMT_IP="$(ip -4 -o addr show br0 2>/dev/null | awk '{print $4; exit}')"        # 192.168.122.X/24
[ -z "$MGMT_IP" ] && MGMT_IP="$(grep -hoE '192\.168\.122\.[0-9]+/[0-9]+' /etc/netplan/*.yaml 2>/dev/null | head -1)"
[ -z "$MGMT_IP" ] && [ -f "$PERSIST" ] && MGMT_IP="$(awk -F= '/^MGMT_IP=/{print $2}' "$PERSIST")"
MGMT_GW="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
[ -z "$MGMT_GW" ] && [ -n "$MGMT_IP" ] && MGMT_GW="$(echo "$MGMT_IP" | sed 's#\.[0-9]\{1,3\}/.*#.1#')"
if [ "$IS_CP" = yes ] && [ -n "$MGMT_IP" ]; then
    printf 'MGMT_IP=%s\nMGMT_GW=%s\n' "$MGMT_IP" "$MGMT_GW" > "$PERSIST"
fi
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

# --- 2-bis. Erradicar TODOS los mecanismos que recrean el viejo bridge L2 br0 --
# CRÍTICO: la imagen base (arquitectura L2 previa) trae VARIAS fuentes que crean
# br0 y enslavan ens3-6 en cada arranque -> las interfaces fabric quedan esclavas
# del bridge y NO admiten la loopback /32 -> el OSPF unnumbered de FRR no se activa
# -> el nodo reiniciado sale del fabric (kubelet sin ruta al API; leaf detrás
# cascadean). Un simple 'ip link del br0' se deshace porque el creador vuelve a
# correr. Hay que neutralizar las fuentes EN EL ORIGEN. Detectadas:
#   1) /usr/local/bin/configure-br0-tree.sh — script L2 (lo invoca cloud-init/boot)
#      que hace 'ip link add br0' + enslave. Se reduce a no-op.
#   2) /etc/systemd/network/*br0* — units .network/.netdev de systemd-networkd.
#   3) /etc/netplan/*.yaml con br0 + regeneración de red de cloud-init.
# Todo idempotente.
if [ -f /usr/local/bin/configure-br0-tree.sh ] \
   && ! grep -q 'L3-FABRIC-NEUTRALIZED' /usr/local/bin/configure-br0-tree.sh; then
    printf '#!/bin/bash\n# L3-FABRIC-NEUTRALIZED: br0 L2 ya no se usa en el fabric L3.\nexit 0\n' \
        > /usr/local/bin/configure-br0-tree.sh
    chmod +x /usr/local/bin/configure-br0-tree.sh
fi
rm -f /etc/systemd/network/*br0* 2>/dev/null || true
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
fi
# Aplicar y derribar br0 ya neutralizadas todas sus fuentes.
netplan apply 2>/dev/null || true
for i in ens3 ens4 ens5 ens6; do ip link set "$i" nomaster 2>/dev/null || true; done
ip link del br0 2>/dev/null || true
echo "fabric-bootstrap: br0 erradicado (configure-br0-tree neutralizado, networkd/netplan limpios)"

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
# de paquetes 10.255->10.255 que no son de pods. El anillo del fabric usa rutas
# ASIMÉTRICAS (OSPF: ida y vuelta por caminos distintos); en los nodos de tránsito
# conntrack ve tráfico unidireccional -> marca INVALID -> KUBE-FORWARD lo DROPEA.
# Esta regla ACCEPT, POR ENCIMA de KUBE-FORWARD, lo evita para ICMP/TCP/UDP por igual.
iptables -C FORWARD -s "${FABRIC_SUPERNET}.0.0/16" -d "${FABRIC_SUPERNET}.0.0/16" -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "${FABRIC_SUPERNET}.0.0/16" -d "${FABRIC_SUPERNET}.0.0/16" -j ACCEPT

# be_liberal: que conntrack NO marque INVALID los TCP fuera de ventana del tránsito
# asimétrico (defensa extra para TCP; NO rompe NAT, a diferencia de NOTRACK -que
# romperia el DNAT del ClusterIP del apiserver, cuyos endpoints son loopbacks
# 10.255.x). Persistido en sysctl.d.
sysctl -wq net.netfilter.nf_conntrack_tcp_be_liberal=1 2>/dev/null || true
echo "net.netfilter.nf_conntrack_tcp_be_liberal=1" > /etc/sysctl.d/99-fabric-conntrack.conf

# DURABILIDAD del ACCEPT: el ACCEPT se inserta en FORWARD pos 1, pero kube-proxy y
# Calico reprograman FORWARD DESPUÉS del bootstrap (corren Before=k3s) y empujan la
# regla por DEBAJO de KUBE-FORWARD -> tras reinicio el fabric queda fragmentado
# (pares de loopbacks sin alcanzarse, apiserver->kubelet 502, CNI sin llegar al API).
# Un guard re-asegura la regla por encima de KUBE-FORWARD de forma continua.
cat > /usr/local/bin/fabric-forward-guard.sh <<GUARD
#!/bin/sh
# Mantiene el ACCEPT de tránsito del fabric por ENCIMA de KUBE-FORWARD.
SUPERNET="${FABRIC_SUPERNET}"
while true; do
    a=\$(iptables -L FORWARD --line-numbers -n 2>/dev/null | awk -v s="\${SUPERNET}.0.0/16" '\$0 ~ s && /ACCEPT/ {print \$1; exit}')
    k=\$(iptables -L FORWARD --line-numbers -n 2>/dev/null | awk '/KUBE-FORWARD/ {print \$1; exit}')
    if [ -z "\$a" ] || { [ -n "\$k" ] && [ "\$a" -gt "\$k" ]; }; then
        while iptables -D FORWARD -s "\${SUPERNET}.0.0/16" -d "\${SUPERNET}.0.0/16" -j ACCEPT 2>/dev/null; do :; done
        iptables -I FORWARD 1 -s "\${SUPERNET}.0.0/16" -d "\${SUPERNET}.0.0/16" -j ACCEPT
    fi
    sleep 20
done
GUARD
chmod +x /usr/local/bin/fabric-forward-guard.sh
cat > /etc/systemd/system/fabric-forward-guard.service <<'UNIT'
[Unit]
Description=Mantiene el ACCEPT de transito del fabric por encima de KUBE-FORWARD
# NO poner After=k3s.service: fabric-bootstrap corre Before=k3s y arranca este
# guard -> un After=k3s aquí crea un CICLO de orden (bootstrap espera al guard ->
# guard espera a k3s -> k3s espera a bootstrap) que CUELGA el arranque antes de la
# detección del edge y FRR (los CP se quedan sin IP de gestión -> VIP caída).
[Service]
Restart=always
RestartSec=10
ExecStart=/usr/local/bin/fabric-forward-guard.sh
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload 2>/dev/null || true
systemctl enable fabric-forward-guard.service 2>/dev/null || true
# --no-block: arrancar sin BLOQUEAR el bootstrap (evita cualquier espera circular).
systemctl --no-block start fabric-forward-guard.service 2>/dev/null || true

# --- PLUG-AND-PLAY: watcher de enlaces del fabric --------------------------------
# fabric-bootstrap clasifica las ensX UNA sola vez al boot (las que tienen carrier en
# la ventana inicial). Eso rompe el "cablear un nodo a un fabric YA encendido": el
# puerto del nodo existente estaba sin carrier en SU boot, y el nodo nuevo puede
# arrancar antes de que el cable este listo -> esa ensX nunca entra a OSPF -> sin
# adyacencia. Este watcher RECONCILIA en continuo: cualquier ensX (3-6) que gane
# carrier y NO sea el edge (sin IP de gestion 192.168.122.x) entra al fabric sola
# (loopback /32 unnumbered + OSPF point-to-point area 0 + rp_filter=0), via vtysh en
# caliente (sin reiniciar FRR). Asi agregar nodos es plug-and-play, sin ejecutar nada.
cat > /usr/local/bin/fabric-link-watch.sh <<WATCH
#!/bin/sh
SUPERNET="${FABRIC_SUPERNET}"
loopback() {
    ip -4 -o addr show dev lo 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 \\
        | grep "^\${SUPERNET}\\." | grep -vx 10.255.255.1 | head -1
}
while true; do
    LB="\$(loopback)"
    if [ -n "\$LB" ]; then
        for i in ens3 ens4 ens5 ens6; do
            [ -e "/sys/class/net/\$i" ] || continue
            [ "\$(cat /sys/class/net/\$i/carrier 2>/dev/null)" = "1" ] || continue
            # Edge (IP de gestion 192.168.122.x): no tocar.
            ip -4 -o addr show dev "\$i" 2>/dev/null | grep -q '192\\.168\\.122\\.' && continue
            # Ya reconciliada si tiene la loopback /32 (se anade junto con OSPF).
            ip -4 -o addr show dev "\$i" 2>/dev/null | grep -q "\${LB}/32" && continue
            ip link set "\$i" up 2>/dev/null || true
            ip addr replace "\${LB}/32" dev "\$i" 2>/dev/null || true
            sysctl -wq "net.ipv4.conf.\${i}.rp_filter=0" 2>/dev/null || true
            vtysh -c 'conf t' -c "interface \$i" -c 'ip ospf network point-to-point' -c 'ip ospf area 0' -c 'end' 2>/dev/null || true
            logger -t fabric-link-watch "carrier nuevo en \$i -> al fabric (loopback \${LB}/32 + OSPF)"
        done
    fi
    sleep 4
done
WATCH
chmod +x /usr/local/bin/fabric-link-watch.sh
cat > /etc/systemd/system/fabric-link-watch.service <<'UNIT'
[Unit]
Description=Watcher de enlaces del fabric L3 (plug-and-play OSPF en cables nuevos)
After=frr.service
[Service]
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/fabric-link-watch.sh
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload 2>/dev/null || true
systemctl enable fabric-link-watch.service 2>/dev/null || true
systemctl --no-block start fabric-link-watch.service 2>/dev/null || true

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

# --- 5. FRR (OSPF unnumbered SOLAMENTE; sin bgpd) ----------------------------
# FRR corre SOLO ospfd. NO se habilita bgpd a proposito: Calico usa su propio
# demonio BGP (BIRD) para la malla de rutas de pod y necesita el puerto :179 del
# host. Si FRR tambien levantara bgpd, chocarian en :179 y los calico-node
# quedarian 0/1. Sin bgpd, BIRD toma :179 y la malla BGP de Calico establece.
# El VIP del API (kube-vip-bgp, 10.255.255.1) se propaga por OSPF: kube-vip lo
# anade a `lo` (OSPF-enabled) y OSPF lo inunda fabric-wide; no necesita BGP en FRR.
{
    echo "frr version 8.4"; echo "frr defaults traditional"; echo "hostname $(hostname)"
    echo "log syslog informational"; echo "service integrated-vtysh-config"; echo "ip forwarding"; echo "!"
    # Nota: la deteccion RAPIDA de caida de nodo NO se hace bajando los timers de
    # OSPF (hello/dead): en GNS3 sobre 1 vCPU, timers agresivos hacen flapear el hub
    # y un cambio incremental rompe adyacencias por mismatch de intervalos. En su
    # lugar, el ovs-configurator corre un probe activo de liveness (ping a los peers)
    # que publica switch:dead en ~2-3s -> Ryu excluye el nodo del grafo de inmediato.
    # OSPF mantiene sus defaults (estable) y converge el underlay a su ritmo.
    for i in $fabric_ifaces; do
        echo "interface ${i}"; echo " ip ospf network point-to-point"; echo " ip ospf area 0"; echo "!"
    done
    echo "interface lo"; echo " ip ospf area 0"; echo "!"
    echo "router ospf"; echo " ospf router-id ${LOOPBACK}"; echo " maximum-paths 8"; echo " passive-interface lo"
    [ "$NAT_EGRESS" = "yes" ] && echo " default-information originate"
    echo "!"
} > "${FRR_CONF}"

# ospfd=yes, bgpd=NO: Calico (BIRD) es el unico BGP del host y necesita :179.
sed -i 's/^ospfd=no/ospfd=yes/; s/^bgpd=yes/bgpd=no/' /etc/frr/daemons 2>/dev/null || true
systemctl enable frr 2>/dev/null || true
systemctl restart frr
echo "fabric-bootstrap: FRR activo. fabric=[${fabric_ifaces} ] edge=${edge_iface:-none} nat=${NAT_EGRESS}"
