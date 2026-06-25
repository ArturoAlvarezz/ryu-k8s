# Migración a L3 Routed Fabric (FRR/OSPF + BGP)

Reemplaza la red de gestión **L2 plana sin STP** (`br0` + árbol estático
`ACTIVE_BR0_PORTS` + daemons de failover + storm-guards) por un **fabric L3
enrutado**: cada cable es un enlace L3 punto a punto, OSPF da alcanzabilidad y
ECMP, y K3s/etcd/Calico/kube-vip hablan contra **loopbacks estables**.

## Por qué

El enemigo del diseño L2 era la **tormenta de broadcast por loop** (incidentes
`br0-loop-power-cycle`, `failback-storm-broadcast-blind`). Un fabric L3 **elimina
la clase entera de fallo**: no hay dominio de broadcast multi-cable, no hay loops
L2 posibles. Además:

- **Usa todos los cables** (OSPF `maximum-paths` → ECMP) en vez de respaldo en frío.
- **Config uniforme** (golden image): misma lógica en todos, sin `case $HOSTNAME`.
- **Sin nodos especiales:** OSPF *es* el failover; se eliminan los dos daemons.
- **Resuelve el objetivo original** (VXLAN por el cable directo): el túnel viaja
  por *shortest-path* del underlay → si hay cable directo entre vecinos, lo usa.

## Confirmación de hardcodeos (honesta)

| Valor | ¿Hardcode? | Naturaleza |
|---|---|---|
| API VIP `/32` (`10.255.255.1`) | Sí — constante única del cluster | Como el VIP actual `192.168.122.10`. Irreducible. |
| Supernet loopbacks (`10.255.0.0/16`), `area 0`, ASN `64512` | Sí — constantes del fabric | Idénticas en todos. Irreducibles. |
| Loopback `/32` por nodo | **No por hostname** — *derivada* | `sha256(/etc/machine-id)` → 2 bytes → `10.255.B1.B2`. Misma regla en todos, **sin DHCP**. |
| Perfil CP vs worker | Por **rol**, no por nodo | El CP corre kube-vip + etcd; el worker no. 2 plantillas, no por identidad. |
| Interfaces OSPF/BGP | **No** | OSPF unnumbered sobre `ens*` por patrón; BGP por `listen range` (sin enumerar pares). |

**Se elimina** todo el hardcode problemático: `ACTIVE_BR0_PORTS` por hostname,
`uplink-failover.sh`, `worker-mgmt-failover.sh`, `BACKUP_PORT` por nodo,
storm-guards, kube-vip ARP/L2. **Cero casos por hostname, cero workers especiales.**

## Arquitectura

```
  loopback /32 estable por nodo (derivada de machine-id), anunciada por OSPF
  cada cable ensX = enlace L3 P2P unnumbered (OSPF point-to-point, ECMP)

  underlay : OSPF (FRR)      -> alcanzabilidad loopback-a-loopback + ECMP
  overlay  : BGP (FRR, AS 64512, iBGP por listen-range)
             ├─ Calico  -> rutas de pods (peer = FRR local 127.0.0.1)
             └─ kube-vip-> VIP del API 10.255.255.1/32 (peer = FRR local)
  K3s/etcd : --node-ip/--advertise-address/--tls-san = loopback del nodo
  API HA   : kube-vip BGP anuncia el VIP; si el CP cae, BGP lo retira
```

### Componentes (en el repo)

- `tools/gns3/l3-fabric/fabric-bootstrap.sh` — **idéntico en todos los nodos**.
  Deriva la loopback, monta unnumbered en `lo`+`ens*`, genera `frr.conf`
  (OSPF unnumbered + BGP listen-range), arranca FRR.
- `tools/gns3/l3-fabric/fabric-bootstrap.service` — oneshot, corre **antes** de K3s.
- `deploy/k8s/l3-fabric/kube-vip-bgp.yaml` — kube-vip BGP (solo control-planes).
- `deploy/k8s/l3-fabric/calico-fabric.yaml` — Calico (operador): Installation VXLAN + APIServer. (El `calico-bgp.yaml` planeado, peer a FRR, se descartó — ver ACTUALIZACIÓN abajo.)

## Runbook de reconstrucción (corte por reconstrucción, sin proyecto paralelo)

> El cluster actual no se toca hasta el paso de corte. **Snapshot GNS3 de todas
> las VMs antes de empezar** = rollback. Reconstruimos sobre las MISMAS VMs.

### Fase A — Preparar la golden image (offline, sobre la plantilla worker/CP)
1. Instalar FRR: `apt-get install -y frr frr-pythontools`.
2. Copiar artefactos:
   - `install -m0755 tools/gns3/l3-fabric/fabric-bootstrap.sh /usr/local/bin/`
   - `install -m0644 tools/gns3/l3-fabric/fabric-bootstrap.service /etc/systemd/system/`
   - `systemctl enable fabric-bootstrap.service`
3. **Quitar lo viejo:** `systemctl disable --now configure-br0-tree uplink-failover worker-mgmt-failover 2>/dev/null; ip link del br0`. Borrar netplan de `br0`.
4. K3s drop-in (idéntico, la loopback se resuelve en runtime):
   - server: `--flannel-backend=none --disable-network-policy --node-ip=$(ip -4 -o addr show lo | awk '$2!="lo"{next} /10.255/{print $4}' | cut -d/ -f1) --advertise-address=<loopback> --tls-san=10.255.255.1 --tls-san=<loopback>`
   - agent: `--node-ip=<loopback>`
   (Un wrapper lee la loopback de `lo` tras `fabric-bootstrap`.)
5. Sellar imagen (worker y CP comparten todo salvo kube-vip + rol K3s server/agent).

### Fase B — Validar el fabric SIN K8s (1 par de nodos primero)
1. Arrancar 2 nodos con la imagen nueva. `vtysh -c 'show ip ospf neighbor'` → adyacencia full en cada cable.
2. `ping <loopback-remota>` OK; con cable redundante, `ip route get <loopback>` muestra **multipath (ECMP)**.
3. Tirar un cable (GNS3 suspend) → reconvergencia OSPF; loopback sigue alcanzable. **Sin tormenta** (verificar `ip -s link` sin explosión de pps).

### Fase C — Reconstruir el cluster
1. **Snapshot** de todas las VMs.
2. Re-desplegar la imagen nueva en cada VM (control-planes primero).
3. Reinstalar K3s HA con los flags de loopback (Fase A.4).
4. `kubectl apply -f deploy/k8s/l3-fabric/kube-vip-bgp.yaml`.
5. Instalar Calico: `tigera-operator.yaml` + `kubectl apply -f deploy/k8s/l3-fabric/calico-fabric.yaml`.
6. Join de workers (la golden image ya auto-join contra `10.255.255.1`).

### Fase D — Validar K8s + datos
1. `kubectl get nodes` → todos Ready. API por `10.255.255.1` (kube-vip BGP).
2. `vtysh -c 'show bgp ipv4 summary'` → Calico y kube-vip establecidos.
3. Pod-a-pod entre nodos OK (rutas Calico por BGP).
4. **Caer un control-plane** → el VIP se retira por BGP y la API sigue por otro.
5. **Tirar un cable** → cluster estable (ECMP/reconvergencia), sin storm.

### Fase E — SDN/Ryu sobre el fabric
1. Re-desplegar `deploy/k8s/03-sdn-network.yaml` (los túneles VXLAN ahora usan
   las loopbacks como outer IP → shortest-path → cable directo entre vecinos).
2. Correr las pruebas de resiliencia existentes (enlace/nodo); confirmar
   reconvergencia y **cero broadcast storm**.

### Fase F — Limpieza
- Borrar `configure-br0-tree.sh`, `uplink-failover.*`, `worker-mgmt-failover.*`.
- Reescribir `CLAUDE.md` (sección Architecture) y `docs/GuiaDeDespliegue.md §20`.

## Rollback
- Hasta Fase C el cluster vivo no se toca → rollback = no cortar.
- Tras empezar la reconstrucción: **restaurar el snapshot GNS3** de todas las VMs
  vuelve al estado L2 funcional (7/7 Ready).

## Puntos abiertos a afinar durante la reconstrucción
- Tiempo de reconvergencia OSPF objetivo (ajustar `hello/dead` o usar BFD).
- `etcd` peer-urls sobre loopback (K3s lo deriva de `--node-ip`; verificar).

## ACTUALIZACIÓN — estado REAL desplegado (2026-06-25)

El plano L3 (loopbacks/OSPF, `--node-ip`, flannel off) se aplicó. Pero la **capa BGP
divergió del plan de arriba**; lo realmente desplegado y validado es:

- **kube-vip ↔ FRR: NO.** FRR corre **solo `ospfd`** (`bgpd=no`). El VIP `10.255.255.1`
  se propaga por **OSPF** (kube-vip lo añade a `lo`, que es OSPF-enabled), no por BGP.
- **VIP HÍBRIDO:** además del BGP `10.255.255.1` (interno al fabric), se mantiene un
  kube-vip **ARP** `192.168.122.10` para acceso del host. `deploy/k8s/l3-fabric/kube-vip-arp.yaml`
  + `kube-vip-bgp.yaml`; `deploy-kube-vip.sh all` despliega ambos.
- **Calico ↔ FRR: NO (inviable).** El routing nativo de Calico **no funciona** en este
  fabric multi-salto (sin encap, el kernel no instala rutas de pod a nodos no
  L2-adyacentes). Se usa **VXLAN** + la **malla BGP propia de Calico (BIRD)** sobre las
  loopbacks → `calico-node` 1/1. Por eso FRR va sin `bgpd` (BIRD necesita el `:179`).
  El `calico-bgp.yaml` (peer a FRR, sin VXLAN) se **eliminó**; usar
  `deploy/k8s/l3-fabric/calico-fabric.yaml` (Installation VXLAN + **APIServer**, este
  último imprescindible para que el operador gestione IPPools).

Ver memoria `vip-hibrido-bgp-arp` para el detalle operativo.
