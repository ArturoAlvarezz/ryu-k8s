# Arquitectura del Lab SDN sobre K3s/GNS3

> Documento canónico de referencia. Si algo en el código contradice este
> documento, **este documento gana**. Actualizarlo cuando cambie la topología.

## 1. Topología física (GNS3)

El lab se compone de **3 Master planes + 4 Worker planes + 7 Smart Meters
+ 1 NAT + 1 switch de gestión**, todos como VMs QEMU en GNS3.

### 1.1 Mapeo GNS3 ↔ Kubernetes

| GNS3 name      | GNS3 node_id (8 chars) | K3s name        | Loopback (`--node-ip`) | Mgmt/edge IP       | ens0 MAC (GNS3)    |
| -------------- | ---------------------- | --------------- | ---------------------- | ------------------ | ------------------ |
| `Master-1`     | `849e7cb2`             | `master`        | `10.255.227.204`       | `192.168.122.100`  | `0c:9e:7c:b2:00:00` |
| `Master-2`     | `66d2fcb6`             | `control-2`     | `10.255.3.188`         | `192.168.122.106`  | `0c:d2:fc:b6:00:00` |
| `Master-3`     | `9f82a989`             | `control-3`     | `10.255.114.158`       | `192.168.122.130`  | `0c:82:a9:89:00:00` |
| `SDN-Worker-1` | `b98a6707`             | `worker-b0ff27` | `10.255.246.32`        | — | `0c:8a:67:07:00:00` |
| `SDN-Worker-2` | `7584cc37`             | `worker-b56b35` | `10.255.221.26`        | — | `0c:84:cc:37:00:00` |
| `SDN-Worker-3` | `659a7cfe`             | `worker-ea7e34` | `10.255.224.42`        | — | `0c:9a:7c:fe:00:00` |
| `SDN-Worker-4` | `1bcaac31`             | `worker-24cf41` | `10.255.12.224`        | — | `0c:ca:ac:31:00:00` |

La **loopback** (`--node-ip`) se deriva de `machine-id`; cámbiala aquí si se
regenera (resuelve con `kubectl get nodes -o wide`). Solo los control-planes
*edge* tienen IP de gestión `192.168.122.x`; los workers no. **Cómo verificar el
mapeo GNS3↔VM**: `dmidecode -s system-uuid` dentro de la VM debe coincidir con el
`node_id` de GNS3.

### 1.2 Cables físicos (GNS3 links)

| Desde                | Hacia              | Comentario                           |
| -------------------- | ------------------ | ------------------------------------ |
| `Master-1`           | `Mgmt-Switch`      | uplink de management                 |
| `Master-1`           | `Master-2`         | enlace inter-master                  |
| `Master-1`           | `SDN-Worker-2`     | `worker-b56b35` — enlace SDN        |
| `Master-1`           | `SDNSmartMeter-1`  | smart meter en port 0 (ens0)        |
| `Master-2`           | `Mgmt-Switch`      | uplink                               |
| `Master-2`           | `Master-3`         | inter-master                         |
| `Master-2`           | `SDN-Worker-1`     | `worker-b0ff27` — SDN               |
| `Master-2`           | `SDNSmartMeter-7`  | smart meter en port 0                |
| `Master-3`           | `Mgmt-Switch`      | uplink                               |
| `Master-3`           | `SDN-Worker-3`     | `worker-ea7e34` — SDN               |
| `Master-3`           | `SDNSmartMeter-2`  | smart meter en port 0                |
| `SDN-Worker-1`       | `SDN-Worker-4`     | `worker-b0ff27` ↔ `worker-24cf41`  |
| `SDN-Worker-1`       | `SDNSmartMeter-6`  | smart meter en port 0                |
| `SDN-Worker-2`       | `SDN-Worker-4`     | `worker-b56b35` ↔ `worker-24cf41`  |
| `SDN-Worker-2`       | `SDNSmartMeter-3`  | smart meter en port 0                |
| `SDN-Worker-3`       | `SDN-Worker-4`     | `worker-ea7e34` ↔ `worker-24cf41`  |
| `SDN-Worker-3`       | `SDNSmartMeter-4`  | smart meter en port 0 (ens0/ens5)   |
| `SDN-Worker-4`       | `SDNSmartMeter-5`  | smart meter en port 0                |
| `Mgmt-Switch`        | `NAT1`             | uplink a internet                   |

**Cada nodo K3s tiene 6 NICs**: `ens0..ens5`. El host usa `ens0` como uplink
al switch de gestión, y `ens1..ens5` quedan disponibles para guest ports
de `br-sdn` (los smart meters se conectan a un subconjunto).

**Confirmación en runtime** (comando para listar los puertos guest de
`br-sdn` de un nodo):

```bash
sudo kubectl exec -n sdn-controller ovs-sdn-initializer-<X> -- ovs-vsctl list-ports br-sdn
```

### 1.3 Smart Meters

| GNS3 name        | K3s guest MAC        | IP DHCP         | Puerto físico en nodo K3s |
| ---------------- | -------------------- | --------------- | -------------------------- |
| `SDNSmartMeter-1` | `02:42:60:8e:f5:00` | `10.0.0.14`      | `master` (192.168.122.100) |
| `SDNSmartMeter-2` | `02:42:9f:25:df:00` | `10.0.0.11`      | `control-3` (192.168.122.130) |
| `SDNSmartMeter-3` | `02:42:7b:15:75:00` | `10.0.0.12`      | `control-2` (192.168.122.106) |
| `SDNSmartMeter-4` | `02:42:74:bd:11:00` | `10.0.0.16`      | `worker-ea7e34` (192.168.122.70) |
| `SDNSmartMeter-5` | `02:42:6b:dc:ef:00` | `10.0.0.20`      | `worker-24cf41` (192.168.122.170) |
| `SDNSmartMeter-6` | `02:42:11:8c:52:00` | `10.0.0.19`      | `worker-b0ff27` (192.168.122.115) |
| `SDNSmartMeter-7` | `02:42:d2:b8:f1:00` | `10.0.0.22`      | `control-2` (192.168.122.106) |

**Nota**: las MACs `02:42:*` son las MACs Docker de los guest containers
dentro de las VMs GNS3. Las IPs `10.0.0.x` son asignadas por DHCP desde el
servidor DHCP de SDN.

## 2. Plano de management: fabric L3 (FRR/OSPF + BGP)

El plano de gestión es la red **sobre la que vive Kubernetes** (API server de
K3s, etcd, kubelet, CNI de pods y todo el tráfico de control). Ya **no** es un
bridge L2 plano (`br0`): es un **fabric L3 enrutado**. Cada cable `ensX` es un
enlace OSPF *unnumbered* punto a punto y cada nodo se identifica por una
**loopback `/32` estable**. Lo monta `fabric-bootstrap.service`
(`tools/gns3/l3-fabric/fabric-bootstrap.sh`, idéntico en todos los nodos) antes
de K3s. Motivación e historia: [`MIGRACION_L3_FABRIC.md`](MIGRACION_L3_FABRIC.md).

### 2.1 Qué es y qué transporta

- **Loopback `/32` por nodo** = `10.255.B1.B2`, derivada de
  `sha256(/etc/machine-id)` (sin DHCP, sin caso por hostname). Es el `--node-ip`
  de K3s y el router-id de OSPF/BGP.
- **OSPF unnumbered** (FRR, área 0) sobre cada `ens3`-`ens6` con carrier →
  alcanzabilidad loopback-a-loopback + **ECMP** (`maximum-paths 8`).
- **BGP** (FRR, AS 64512, iBGP por `listen range`): kube-vip anuncia el VIP del
  API `10.255.255.1/32` y Calico las rutas de pods; ambos peeran con el FRR
  local (`127.0.0.1`).
- **cloud-init de red deshabilitado** (`99-disable-network-config.cfg`) y netplan
  reducido a `ens*` sueltas; `fabric-bootstrap` erradica cualquier `br0` heredado.
- Dependencia circular resuelta por diseño: Ryu/K3s viven sobre el fabric, pero el
  fabric **no** depende de ningún controlador para su control de caminos — OSPF es
  autosuficiente y converge solo.

### 2.2 Control de loops y failover: OSPF (no hay STP ni daemons)

El fabric L3 **elimina la clase entera de fallo** del modelo L2 anterior: no hay
dominio de broadcast multi-cable, así que **no hay loops L2 posibles** y no hace
falta STP, ni árbol estático de puertos (`ACTIVE_BR0_PORTS`), ni storm-guards.

- **OSPF es el failover.** Si un cable cae, OSPF reconverge por otro camino; con
  ECMP varios cables se usan a la vez (no respaldo en frío). Se eliminan los
  daemons `gns3-br0-tree`, `uplink-failover` y `worker-mgmt-failover`.
- `rp_filter=0` en las interfaces del fabric (imprescindible para OSPF unnumbered:
  evita el deadlock hello↔ruta en nodos sin red de respaldo).
- Una regla `ACCEPT` de tránsito `10.255/16→10.255/16` por encima de
  `KUBE-FORWARD` (con un guard que la re-asegura) evita que kube-proxy/Calico
  dropeen el tránsito asimétrico del anillo como conntrack `INVALID`.

### 2.3 Borde a internet (NAT + default-origination)

No hay un único uplink ni daemon de failover de uplink. Cualquier control-plane
conectado al `Mgmt-Switch`/`NAT1` se **autodetecta como *edge*** en
`fabric-bootstrap` (ping directo al gateway por esa interfaz):

- Conserva su IP de gestión `192.168.122.x` en la interfaz edge.
- Hace **NAT** (`MASQUERADE`) del fabric `10.255/16` hacia esa interfaz.
- **Origina la default en OSPF** (`default-information originate`), dando internet
  a todo el cluster.

Si hay varios CP edge, hay varias salidas redundantes (ECMP), sin lógica activa/
standby. Los workers no tienen IP de gestión ni salen por sí mismos: usan la
default del fabric.

## 3. Plano de datos SDN: `br-sdn` (OVS bridge)

`br-sdn` es la red **de los smart meters y la telemetría**, totalmente
separada del plano de gestión (el fabric L3). Es un OVS controlado por Ryu, sobre
la red `10.0.0.0/24`, con un overlay VXLAN que la hace continua entre nodos. **El
fabric L3 y `br-sdn` nunca se fusionan** (las interfaces del fabric no se enslavan
a `br-sdn`).

### 3.0 Qué es y qué transporta

- Cada nodo K3s tiene `br-sdn` como **OVS bridge** controlado por el Ryu
  local (`tcp:127.0.0.1:6653`).
- IP del bridge: `10.0.0.1/24` (gateway SDN del nodo, anycast — todos los
  nodos comparten `10.0.0.1`).
- Los smart meters (`10.0.0.x`) reciben IP por DHCP (pod `sdn-dhcp-server`) y
  usan `10.0.0.1` para alcanzar el colector de telemetría (UDP/5555).
- A diferencia del fabric L3 de gestión, este plano **sí tiene un controlador**
  (Ryu), así que su control de loops es dinámico e inteligente.

### 3.1 Control de loops: Ryu (MST + Dijkstra + ARP proxy)

`br-sdn` evita loops combinando cuatro técnicas en el controlador:

- **MST (Prim)**: Ryu calcula un árbol de expansión mínima sobre el grafo de
  vecinos del fabric (rutas OSPF / `topology:vxlan_peers`). Sirve de **árbol
  lógico de broadcast**: todo flood (ARP, broadcast) se reenvía solo por aristas
  del MST (`_do_controlled_flood`), nunca por la malla completa.
- **ARP proxy**: el `ArpHandler` responde directamente las ARP request cuyo
  destino ya conoce, evitando floods innecesarios.
- **Caché de ARP vistos** (`topology:arp_dedup`): deduplica ARPs ya vistos
  para cortar la amplificación de un mismo broadcast.
- **Dijkstra multi-hop**: para tráfico unicast guest-a-guest, Ryu instala
  flujos por el **camino más corto** (Dijkstra con pesos) entre el nodo origen
  y el destino, no por el árbol de flood. La instalación se serializa por
  `(dpid, src_mac, dst_mac)` con locks en Redis.

Esto es lo que el fabric de gestión **no** puede usar: requiere un controlador, y
el controlador (Ryu) vive sobre la red de gestión. Por eso la gestión usa OSPF
(autosuficiente) y solo `br-sdn` usa Ryu.

### 3.2 Topología de túneles VXLAN: vecinos del fabric (NO full mesh)

Ver `AGENTS.md` "VXLAN topology is neighbor-only, NOT full mesh".

- Cada nodo crea túneles VXLAN solo a sus **vecinos directos del fabric** (los
  vecinos OSPF de 1 salto: rutas `/32` cuyo destino == next-hop).
- El **VTEP es la loopback** del nodo (`10.255.x`), así que el túnel a un vecino
  viaja por el cable directo (shortest-path del underlay).
- Los vecinos se publican en `topology:vxlan_peers` en Redis (los calcula el
  `ovs-sdn-initializer` desde la tabla de rutas OSPF, no por LLDP).
- En el lab actual, los túneles son ~4 por nodo (topología anillo/cadena).

### 3.3 Servicios que corren en cada nodo

| Pod                     | Función                                              |
| ----------------------- | ---------------------------------------------------- |
| `ryu-<hash>`            | Ryu controller local, escucha OpenFlow en 6653      |
| `ovs-sdn-initializer-<hash>` | Crea `br-sdn`, asigna 10.0.0.1/24, configura VXLAN a vecinos |
| `sdn-dhcp-server-<hash>` | Sirve DHCP a los smart meters en 10.0.0.0/24       |
| `meter-collector-<hash>` | Recibe telemetría UDP en 5555, expone API en 5000   |

## 4. Servicios compartidos (en cualquier nodo)

| Pod                | Función                                            |
| ------------------ | -------------------------------------------------- |
| `redis-0`         | Redis con Sentinel (compartido entre Ryu, DHCP, meter-collector) |
| `prometheus`      | Scraping de métricas Ryu + meter-collector         |
| `grafana`          | Dashboards                                        |
| `loki`            | Agregación de logs                                |
| `promtail`        | Recolección de logs desde pods                    |

## 5. HA / VIP

- **VIP API server**: `https://10.255.255.1:6443`, anunciado por **kube-vip en
  modo BGP** desde los 3 control planes (peer = FRR local). Es interno al fabric;
  con ECMP no hay "líder" ni failover ARP. Si un CP cae, los demás lo siguen
  anunciando.
- Configurar `kubeconfig` con `server: https://10.255.255.1:6443`.

## 6. Telemetría Smart Meter

Flujo de un paquete de telemetría:

```
1. SDNSmartMeter-X (GNS3 container) publica UDP a 10.0.0.1:5555
2. Switch OVS del nodo (SDN-Worker-X GNS3) reenvía por SDN
3. Túneles VXLAN (vecinos LLDP) llevan el paquete a un nodo con 10.0.0.1
4. meter-collector-<hash> en ese nodo recibe en 0.0.0.0:5555
5. Valida con telemetry_source_authorization(source_ip, device_id):
   - source_ip → topología:guest_ips → MAC → topología:guest_locations
   - MAC → security:mac_to_device → device
   - Si device.in_port != observado, antes rechazaba con port_mismatch
6. AHORA: auto-registra o sincroniza identidad si la MAC/IP coinciden
   pero el puerto/dpid cambiaron
7. Si pasa, store_reading → Redis (meter:latest:<device_id>, meter:devices)
8. /api/stats, /api/meters, /api/devices/<id>/history exponen los datos
```

### 6.1 Auto-registro de smart meters (Jun 2026)

`/app/app.py` (en `services/meter-collector/app.py`) auto-registra smart
meters en el security registry cuando:

- El paquete UDP llega con un `device_id` que empieza con `SDNSmartMeter-`
- La MAC se puede inferir vía `topology:guest_ips` (HASH) y
  `topology:guest_locations` (HASH).
- El device no existe o tiene un `in_port`/`dpid` stale (mismatch con la
  observación actual).

Esto evita tener que registrar manualmente cada smart meter en el
security registry, especialmente cuando se recrean las VMs GNS3.

## 7. Verificación rápida del estado del lab

```bash
# K3s: 7 nodos Ready
sudo kubectl --server=https://10.255.255.1:6443 get nodes -o wide

# SDN: 7 pods ryu, 7 pods ovs-sdn-initializer, 7 pods meter-collector
sudo kubectl --server=https://10.255.255.1:6443 -n sdn-controller get pods -o wide

# MST: 6 edges (n-1 para 7 nodos)
sudo kubectl --server=https://10.255.255.1:6443 exec -n sdn-controller redis-0 -c redis -- \
  redis-cli -p 6379 SMEMBERS topology:mst_edges

# VXLAN neighbors: cada nodo tiene ~4 túneles
sudo kubectl --server=https://10.255.255.1:6443 exec -n sdn-controller \
  ovs-sdn-initializer-<X> -- ovs-vsctl list-ports br-sdn | grep ^vx

# Telemetría: 6-7 devices online
curl -s http://192.168.122.100:8081/api/stats | jq
```

## 8. Cambios recientes

- **Migración a fabric L3 (actual):** el plano de gestión pasó de `br0`/L2 (árbol
  estático + daemons de failover) a un **fabric L3 enrutado** (FRR/OSPF unnumbered +
  loopbacks `10.255.x` por `machine-id`, kube-vip BGP `10.255.255.1`, Calico BGP).
  Ver §2 y [`MIGRACION_L3_FABRIC.md`](MIGRACION_L3_FABRIC.md). **Eliminados**:
  `configure-br0-tree.sh`/`gns3-br0-tree`, `uplink-failover.*`,
  `worker-mgmt-failover.*`, `ACTIVE_BR0_PORTS`, STP y storm-guards.
- Plano SDN (`br-sdn`): sin protocolos distribuidos de bloqueo de puertos; usa
  MST + Dijkstra multi-hop + ARP proxy.
- Topología VXLAN de vecinos del fabric (no full mesh) — ver `AGENTS.md`
  "VXLAN topology is neighbor-only, NOT full mesh". VTEPs = loopbacks.
- Auto-registro de smart meters en el security registry vía
  `sync_security_identity` y `_register_observed_meter` cuando hay port/dpid
  mismatch (con ancla MAC anti-spoofing).
- DPID de `br-sdn` derivado de la loopback del fabric (no de `br0`).
- **Resumen de diseño**: la gestión evita loops por ser **L3 enrutada** (OSPF, sin
  dominio de broadcast); `br-sdn` evita loops con MST + ARP proxy + Dijkstra en Ryu
  (tiene controlador). "Árbol, no malla" por mecanismos distintos en cada plano.
