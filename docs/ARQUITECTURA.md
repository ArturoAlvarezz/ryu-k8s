# Arquitectura del Lab SDN sobre K3s/GNS3

> Documento canónico de referencia. Si algo en el código contradice este
> documento, **este documento gana**. Actualizarlo cuando cambie la topología.

## 1. Topología física (GNS3)

El lab se compone de **3 Master planes + 4 Worker planes + 7 Smart Meters
+ 1 NAT + 1 switch de gestión**, todos como VMs QEMU en GNS3.

### 1.1 Mapeo GNS3 ↔ Kubernetes

| GNS3 name      | GNS3 node_id (8 chars) | K3s name        | K3s IP              | br0 MAC            | ens0 MAC (GNS3)    |
| -------------- | ---------------------- | --------------- | ------------------- | ------------------ | ------------------ |
| `Master-1`     | `849e7cb2`             | `master`        | `192.168.122.100`   | `86:36:f7:5c:06:d4` (corregir) | `0c:9e:7c:b2:00:00` |
| `Master-2`     | `66d2fcb6`             | `control-2`     | `192.168.122.106`   | `3a:a7:4e:40:47:86` | `0c:d2:fc:b6:00:00` |
| `Master-3`     | `9f82a989`             | `control-3`     | `192.168.122.130`   | `96:9c:1d:49:e5:84` | `0c:82:a9:89:00:00` |
| `SDN-Worker-1` | `b98a6707`             | `worker-b0ff27` | `192.168.122.115`   | `42:f5:e5:b0:ff:27` | `0c:8a:67:07:00:00` |
| `SDN-Worker-2` | `7584cc37`             | `worker-b56b35` | `192.168.122.145`   | `fe:dc:a2:b5:6b:35` | `0c:84:cc:37:00:00` |
| `SDN-Worker-3` | `659a7cfe`             | `worker-ea7e34` | `192.168.122.70`    | `8e:fc:06:ea:7e:34` | `0c:9a:7c:fe:00:00` |
| `SDN-Worker-4` | `1bcaac31`             | `worker-24cf41` | `192.168.122.170`   | `62:ce:ca:24:cf:41` | `0c:ca:ac:31:00:00` |

**Cómo verificarlo** (autoridad: `dmidecode -s system-uuid` dentro de la VM
debe coincidir con el `node_id` de GNS3).

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

## 2. Plano de management: `br0` (Linux bridge)

`br0` es la red **sobre la que vive Kubernetes**: por ella corren el API
server de K3s, etcd, el overlay flannel/VXLAN de pods, kubelet y todo el
tráfico de control. Es la red `192.168.122.0/24` y su salida a internet es
el `Mgmt-Switch` → `NAT1` → gateway `192.168.122.1`.

### 2.1 Qué es y qué transporta

- Cada nodo K3s tiene `br0` como **Linux bridge con árbol de puertos determinístico**.
- Los nodos obtienen IP en `192.168.122.0/24` (estática vía `cloud-init`/
  netplan; el VIP de HA es `192.168.122.10`).
- Servicios de Kubernetes (API server, etcd, flannel VXLAN, kubelet) corren
  **encima** de `br0`. Esto crea una dependencia circular clave: **Ryu es un
  pod de K3s que corre sobre `br0`**, así que `br0` NO puede depender de un
  controlador SDN para su control de loops — debe ser auto-suficiente.

### 2.2 Control de loops: poda determinista de puertos

La topología física GNS3 tiene anillos redundantes (enlaces inter-master y el
switch de gestión común). Si `br0` enslavara todos sus puertos físicos se
formaría un loop L2 → tormenta de broadcast → cluster inalcanzable.

Para evitar decisiones no deterministas en el plano de gestión, `br0` usa
**poda estática de puertos**:

- `br0` solo enslava los puertos definidos en `ACTIVE_BR0_PORTS` por hostname
  (`default_active_ports()` en `configure-br0-tree.sh`):
  `master=ens3 ens4 ens5`, `control-2=ens5 ens6`, `control-3=ens5`,
  workers=`ens3`.
- Este subconjunto se elige a mano para que la unión de todos los `br0` forme
  un **árbol** (sin ciclos) sobre la malla física. Los enlaces sobrantes
  siguen cableados en GNS3 (sirven para LLDP/VXLAN del plano SDN) pero no
  entran a `br0`.
- `gns3-br0-tree.service` ejecuta `tools/gns3/configure-br0-tree.sh` en cada
  boot para reimponer este árbol de puertos.
- **cloud-init queda deshabilitado** para la red
  (`99-disable-network-config.cfg` con `network: {config: disabled}`); si no,
  regenera el netplan a un `br0` por defecto (`interfaces: [ens3]`) que
  reintroduce el loop tras un corte de energía.

### 2.3 Failover activo/standby del uplink a internet

Normalmente **solo `master` enslava su uplink `ens3`** al switch de gestión,
así que master es el único camino del cluster hacia NAT1/internet — un punto
único de fallo. Para cubrirlo sin abrir caminos paralelos se usa un daemon de
failover hand-rolled (`tools/gns3/uplink-failover.sh`, `uplink-failover.service`):

- Corre solo en los control planes de respaldo: `control-2` = PRIORITY 1,
  `control-3` = PRIORITY 2. `master` NO lo corre.
- Hace ping a master (`192.168.122.100`). Si master deja de responder, el
  respaldo enslava su propio `ens3` a `br0` y toma el uplink; cuando master
  vuelve, lo libera (vuelve a standby).
- **Seguridad ante loops**: solo se activa con master *inalcanzable*. Si master
  no responde, su camino no existe, así que tomar el uplink no puede formar un
  segundo camino → no hay loop. Además un *storm guard* libera el puerto al
  instante si detecta >1000 mcast/s en `br0` (rompe cualquier loop en la
  ventana de failback).
- `ens3` se marca `Unmanaged=yes` en networkd para que el enslave/nomaster del
  daemon persista.

## 3. Plano de datos SDN: `br-sdn` (OVS bridge)

`br-sdn` es la red **de los smart meters y la telemetría**, totalmente
separada de `br0`. Es un OVS controlado por Ryu, sobre la red `10.0.0.0/24`,
con un overlay VXLAN que la hace continua entre nodos. **`br0` y `br-sdn`
nunca se fusionan.**

### 3.0 Qué es y qué transporta

- Cada nodo K3s tiene `br-sdn` como **OVS bridge** controlado por el Ryu
  local (`tcp:127.0.0.1:6653`).
- IP del bridge: `10.0.0.1/24` (gateway SDN del nodo, anycast — todos los
  nodos comparten `10.0.0.1`).
- Los smart meters (`10.0.0.x`) reciben IP por DHCP (pod `sdn-dhcp-server`) y
  usan `10.0.0.1` para alcanzar el colector de telemetría (UDP/5555).
- A diferencia de `br0`, este plano **sí tiene un controlador** (Ryu), así que
  su control de loops es dinámico e inteligente.

### 3.1 Control de loops: Ryu (MST + Dijkstra + ARP proxy)

`br-sdn` evita loops combinando cuatro técnicas en el controlador:

- **MST (Prim)**: Ryu calcula un árbol de expansión mínima sobre el grafo
  físico descubierto por LLDP. Sirve de **árbol lógico de broadcast**: todo
  flood (ARP, broadcast) se reenvía solo por aristas del MST
  (`_do_controlled_flood`), nunca por la malla completa.
- **ARP proxy**: el `ArpHandler` responde directamente las ARP request cuyo
  destino ya conoce, evitando floods innecesarios.
- **Caché de ARP vistos** (`topology:arp_dedup`): deduplica ARPs ya vistos
  para cortar la amplificación de un mismo broadcast.
- **Dijkstra multi-hop**: para tráfico unicast guest-a-guest, Ryu instala
  flujos por el **camino más corto** (Dijkstra con pesos) entre el nodo origen
  y el destino, no por el árbol de flood. La instalación se serializa por
  `(dpid, src_mac, dst_mac)` con locks en Redis.

Esto es lo que `br0` **no** puede usar: requiere un controlador, y el
controlador (Ryu) vive sobre `br0`.

### 3.2 Topología de túneles VXLAN: vecinos LLDP (NO full mesh)

Ver `AGENTS.md` "VXLAN topology is neighbor-only (LLDP), NOT full mesh".

- Cada nodo crea túneles VXLAN solo a sus **vecinos LLDP directos**.
- Los vecinos se descubren dinámicamente via LLDP en `br-sdn`.
- En el lab actual (Jun 2026), los túneles son 4 por nodo (topología
  anillo/cadena).
- Ver `topology:links` en Redis para la lista actualizada de enlaces.

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

- **VIP API server**: `https://192.168.122.10:6443` (kube-vip activo en
  los 3 control planes).
- Configurar `kubeconfig` con `server: https://192.168.122.10:6443` para
  usar el VIP.

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
sudo kubectl --server=https://192.168.122.10:6443 get nodes -o wide

# SDN: 7 pods ryu, 7 pods ovs-sdn-initializer, 7 pods meter-collector
sudo kubectl --server=https://192.168.122.10:6443 -n sdn-controller get pods -o wide

# MST: 6 edges (n-1 para 7 nodos)
sudo kubectl --server=https://192.168.122.10:6443 exec -n sdn-controller redis-0 -c redis -- \
  redis-cli -p 6379 SMEMBERS topology:mst_edges

# VXLAN neighbors: cada nodo tiene ~4 túneles
sudo kubectl --server=https://192.168.122.10:6443 exec -n sdn-controller \
  ovs-sdn-initializer-<X> -- ovs-vsctl list-ports br-sdn | grep ^vx

# Telemetría: 6-7 devices online
curl -s http://192.168.122.100:8081/api/stats | jq
```

## 8. Cambios recientes

- **Jun 2026**: Eliminada la dependencia de protocolos distribuidos de bloqueo de puertos en el plano SDN (`br-sdn`).
  La nueva arquitectura usa MST + Dijkstra multi-hop + ARP proxy.
- **Jun 2026**: Topología VXLAN de vecinos LLDP (no full mesh) — ver
  `AGENTS.md` "VXLAN topology is neighbor-only (LLDP), NOT full mesh".
- **Jun 2026**: Auto-registro de smart meters en security registry vía
  `sync_security_identity` y `_register_observed_meter` cuando hay
  port/dpid mismatch.
- **Jun 2026**: `br0` queda controlado por `gns3-br0-tree.service` y
  `ACTIVE_BR0_PORTS`, con un árbol de puertos explícito por nodo.
- **Jun 2026**: cloud-init deshabilitado para la red en los prepare-k3s-*.sh
  (`99-disable-network-config.cfg`) para que no regenere el netplan y
  reintroduzca el loop L2 en `br0` tras un corte de energía.
- **Jun 2026 (commit 323170aa)**: failover activo/standby del uplink de
  gestión (`uplink-failover.sh`/`.service`). control-2 (PRIORITY 1) y
  control-3 (PRIORITY 2) toman el uplink a NAT1 si master cae; storm guard +
  `ens3` Unmanaged en networkd. Ver §2.3.
- **Resumen de diseño**: ambos planos evitan loops con un "árbol, no malla",
  pero por mecanismos distintos: `br0` con poda estática de puertos
  (`ACTIVE_BR0_PORTS`) porque no puede tener controlador (Ryu vive sobre él);
  `br-sdn` con MST + ARP proxy + Dijkstra en Ryu.
