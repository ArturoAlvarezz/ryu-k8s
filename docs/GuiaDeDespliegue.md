# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s HA · Open vSwitch · FRR (OSPF/BGP) · Calico · Redis Sentinel · Docker
> **Entorno:** Ubuntu QEMU/KVM en GNS3 · **Fabric L3 enrutado** (loopbacks `10.255.0.0/16`, OSPF/BGP) · Plano de datos SDN `10.0.0.0/24`

Guía genérica para desplegar el laboratorio desde cero. El cableado y la cantidad de nodos son libres: sirve para cualquier topología siempre que se respeten los roles, el mapa de interfaces y el orden de despliegue.

> **Arquitectura L3 (importante).** La red de gestión ya **no** es un bridge L2 plano
> (`br0` + DHCP + STP). Es un **fabric L3 enrutado**: cada cable `ensX` es un enlace OSPF
> *unnumbered* punto a punto y cada nodo tiene una **loopback `/32`** estable
> (`10.255.B1.B2`, derivada de `sha256(/etc/machine-id)`). Lo monta
> `fabric-bootstrap.service` (`tools/gns3/l3-fabric/`) antes de K3s. OSPF da
> alcanzabilidad + ECMP (es el failover; no hay daemons), kube-vip anuncia el VIP del
> API (`10.255.255.1` por OSPF en el fabric + `192.168.122.10` por ARP para el host) y
> Calico da la red de pods (CNI, VXLAN). FRR corre **solo `ospfd`** (BGP lo lleva Calico).
> Detalle y motivación en [`docs/MIGRACION_L3_FABRIC.md`](MIGRACION_L3_FABRIC.md).

---

## Índice

**Parte I — Reglas de Despliegue**
1. [Roles de nodos](#1-roles-de-nodos)
2. [Mapa de interfaces y switch de gestión](#2-mapa-de-interfaces-y-switch-de-gestión)

**Parte II — Plano de Control HA**
3. [Preparar el primer servidor control-plane](#3-preparar-el-primer-servidor-control-plane)
4. [Instalar K3s en el primer servidor](#4-instalar-k3s-en-el-primer-servidor)
5. [Preparar permisos de kube-vip](#5-preparar-permisos-de-kube-vip)
6. [Preparar los control-plane adicionales](#6-preparar-los-control-plane-adicionales)
7. [Unir los control-plane y desplegar kube-vip](#7-unir-los-control-plane-y-desplegar-kube-vip)
8. [Configurar kubeconfig](#8-configurar-kubeconfig)

**Parte III — Workers**
9. [Preparar la Golden Image de workers](#9-preparar-la-golden-image-de-workers)
10. [Configurar auto-join del worker (fabric L3)](#10-configurar-auto-join-del-worker-fabric-l3)
11. [Sellar la Golden Image](#11-sellar-la-golden-image)
12. [Importar y arrancar workers en GNS3](#12-importar-y-arrancar-workers-en-gns3)

**Parte IV — Despliegue SDN y Smart Meters**
13. [Desplegar servicios SDN en Kubernetes](#13-desplegar-servicios-sdn-en-kubernetes)
14. [Incorporar Smart Meters](#14-incorporar-smart-meters)

**Parte V — Verificación, Monitoreo y Debugging**
15. [Verificación del cluster](#15-verificación-del-cluster)
16. [Verificación de servicios SDN](#16-verificación-de-servicios-sdn)
17. [Monitoreo y endpoints](#17-monitoreo-y-endpoints)
18. [Debugging post-despliegue](#18-debugging-post-despliegue)
19. [Operaciones de mantenimiento](#19-operaciones-de-mantenimiento)
20. [Resiliencia del fabric L3](#20-resiliencia-del-fabric-l3)

---

# Parte I — Reglas de Despliegue

## 1. Roles de nodos

| Rol | Cantidad | `--node-ip` | IP de gestión (edge) | Instalación K3s |
| --- | --- | --- | --- | --- |
| Primer control-plane | 1 | loopback `10.255.x` | `192.168.122.100` fija | `server --cluster-init` |
| Control-plane adicional | 2 | loopback `10.255.x` | `192.168.122.x` fija | `server` unido al primero |
| Worker | Según topología | loopback `10.255.x` | — (sin IP de gestión) | `agent` con auto-join |
| Smart Meter (guest) | Según topología | DHCP en `br-sdn` (`10.0.0.0/24`) | — | No es nodo del cluster |
| VIP API (fabric) | 1 | `10.255.255.1` | — | kube-vip **BGP** (interno al fabric, lo usan los agentes) |
| VIP API (host) | 1 | — | `192.168.122.10` | kube-vip **ARP** (acceso del host + dashboards) |

El endpoint final del cluster es siempre el VIP del API (interno al fabric):

```text
https://10.255.255.1:6443
```

La **loopback `/32`** de cada nodo (`--node-ip`) se deriva sola de `/etc/machine-id`; no se
asigna a mano ni por DHCP. Solo los control-planes conectados al `Mgmt-Switch`/`NAT1`
conservan una **IP de gestión `192.168.122.x`** en su interfaz *edge* (da internet, NAT del
fabric y origina la default en OSPF); los workers no tienen ninguna. El primer servidor
inicializa etcd; los CP adicionales se unen vía el VIP (o la loopback del primero).

Recursos mínimos validados para las VMs control-plane:

| Recurso | Valor |
| --- | --- |
| RAM | 3 GB o más |
| CPU | 2 hilos recomendados |
| Disco | 20 GB o más |
| Adaptadores | 6 tipo `virtio` |

## 2. Mapa de interfaces y switch de gestión

| Interfaz | Uso |
| --- | --- |
| `ens3`-`ens6` | Enlaces del **fabric L3** (OSPF *unnumbered* P2P). Todo cable con carrier entra al fabric |
| `ens7`-`ens8` | Puertos de guests SDN (Smart Meters), fuera del fabric (los toma OVS) |
| `lo` | Loopback `/32` del fabric (`10.255.x`, `--node-ip`); en CPs *edge* además la IP de gestión |
| `br-sdn` | Bridge Open vSwitch del plano de datos `10.0.0.0/24` (lo crea el DaemonSet SDN) |

No hay `br0`: el fabric es L3 enrutado. Las interfaces del fabric (`ens3`-`ens6`) y el plano
de datos SDN (`br-sdn`, `ens7`-`ens8`) nunca se mezclan. Un cable del fabric **no** debe
enslavarse a ningún bridge: debe quedar como interfaz L3 suelta para que OSPF *unnumbered*
levante en ella.

### 2.1 Switch de gestión / NAT (solo borde a internet)

En el fabric L3 **no** existe un switch L2 de gestión que una a todos los nodos. La función
del antiguo `Mgmt-Switch` se reduce a dar **acceso a internet** al laboratorio: un
`Mgmt-Switch` (OVS) + `NAT1` conectan a la(s) interfaz(es) *edge* de los control-planes con
el `virbr0` del host (`192.168.122.0/24`). El control-plane que reciba el gateway por esa
interfaz la detecta como *edge* (`fabric-bootstrap`), conserva su IP `192.168.122.x`, hace
NAT del fabric (`10.255/16`) y origina la default en OSPF, dando internet a todo el cluster.

Los workers y los enlaces internos del fabric **no** se conectan a este switch: van
directo nodo-a-nodo por `ens3`-`ens6`. No hay loops L2 que controlar (cada cable es un
enlace L3); por eso desaparecen STP, el árbol `ACTIVE_BR0_PORTS` y los daemons de failover.

---

# Parte II — Plano de Control HA

## 3. Preparar el primer servidor control-plane

Ejecuta esta sección en la VM que será el primer control-plane. Conserva la IP fija `192.168.122.100`.

### 3.1 Preparar disco y clonar el repositorio

Si la VM viene de un template QEMU con disco pequeño o linked clone, redimensiona el disco a 20 GB con la VM apagada desde el host GNS3:

```bash
DISK=/home/artulita/GNS3/projects/ProyectoMemoria/project-files/qemu/NODE_ID/hda_disk.qcow2
qemu-img info "$DISK"
qemu-img resize "$DISK" 20G
qemu-img info "$DISK"
```

Después arranca la VM e instala lo mínimo para clonar el repositorio:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 3.2 Ejecutar preparación automática

`tools/gns3/prepare-k3s-control-plane.sh` expande `/dev/vda1` si puede, instala utilidades,
Docker y **FRR**, fija hostname, escribe un netplan L3 (sin `br0`), instala y habilita
`fabric-bootstrap.service` (+ `frr.service`), y **persiste la IP de gestión del edge** en
`/etc/l3-fabric/mgmt.env` (para NAT + default-origination). Elimina cualquier resto L2
(`gns3-br0-tree`, `uplink-failover`, etc.).

```bash
cd ~/ryu-k8s
# arg2 = hostname, arg3 = IP de gestion del EDGE (192.168.122.x hacia el Mgmt-Switch/NAT)
sudo ./tools/gns3/prepare-k3s-control-plane.sh first master 192.168.122.100
```

Para evitar `apt upgrade` en una reinstalación rápida: `RYU_K3S_SKIP_APT_UPGRADE=true`.

**Reinicia la VM** (o `sudo systemctl start fabric-bootstrap.service`) para que el fabric se
monte. La sesión por consola puede parpadear mientras se reorganiza la red. Reconecta y valida:

```bash
hostname
ip -br -4 addr show lo            # debe mostrar la loopback 10.255.x/32
ip -br -4 addr show              # la interfaz edge conserva 192.168.122.100/24
systemctl is-active fabric-bootstrap.service frr.service
sudo vtysh -c 'show ip ospf neighbor'   # adyacencias FULL en cada cable con vecino
df -h /
```

## 4. Instalar K3s en el primer servidor

Solo en `master`, **después** de que `fabric-bootstrap` haya asignado la loopback (paso 3.2).
El `--node-ip` se toma solo de la loopback del fabric; no se pasa IP de gestión.

```bash
cd ~/ryu-k8s

sudo RYU_K3S_CLUSTER_INIT=true \
  RYU_K3S_API_ENDPOINT=10.255.255.1 \
  ./tools/gns3/k3s-server-ha-install.sh
```

El script instala K3s con `--flannel-backend=none --disable-network-policy` (la CNI la dará
Calico) y `--tls-san=10.255.255.1`. Espera a que el nodo quede estable y guarda el token:

```bash
for i in $(seq 1 30); do
  sudo kubectl get nodes -o wide
  sudo kubectl get node master -o jsonpath='{.metadata.labels.node-role\.kubernetes\.io/control-plane}{"\n"}' 2>/dev/null | grep -q true && break
  sleep 5
done
sudo cat /var/lib/rancher/k3s/server/node-token
```

> Con `--flannel-backend=none` los nodos quedan `NotReady` hasta instalar la CNI (Calico,
> paso 7). Es esperado.

## 5. Preparar permisos de kube-vip

En `master`, después de instalar K3s y antes de unir servidores adicionales. Aquí solo se crean los permisos; el VIP se despliega después de unir los 3 control-plane.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/deploy-kube-vip.sh rbac
```

## 6. Preparar los control-plane adicionales

Repite en las dos VMs que serán control-plane adicionales.

### 6.1 Preparar disco y clonar el repositorio

Confirma que el disco ya fue redimensionado a 20 GB (procedimiento de la sección 3.1). Luego:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 6.2 Ejecutar preparación automática

Usa `control-2` en el segundo y `control-3` en el tercero. Cada CP adicional necesita su
**hostname** y su **IP de gestión del edge** (la `192.168.122.x` reservada de esa VM hacia el
`Mgmt-Switch`/`NAT`):

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-2 192.168.122.106
```

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-3 192.168.122.130
```

**Reinicia** cada VM (o arranca `fabric-bootstrap.service`) y valida el fabric antes de unir:

```bash
hostname
ip -br -4 addr show lo            # loopback 10.255.x/32
systemctl is-active fabric-bootstrap.service frr.service
sudo vtysh -c 'show ip ospf neighbor'
df -h /
```

## 7. Unir los control-plane y desplegar kube-vip

Ejecuta el join en cada uno de los dos servidores adicionales con el token real (no el placeholder). Obtén el token en `master`:

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

El primer servidor aún no anuncia el VIP (kube-vip se despliega abajo), así que los CP
adicionales se unen vía la **loopback del primer server** (`RYU_K3S_FIRST_SERVER_IP`). Obtén
la loopback de `master` con `ip -br -4 addr show lo` (p.ej. `10.255.227.204`):

```bash
cd ~/ryu-k8s

sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  RYU_K3S_API_ENDPOINT=10.255.255.1 \
  RYU_K3S_FIRST_SERVER_IP=<LOOPBACK_DE_MASTER> \
  ./tools/gns3/k3s-server-ha-install.sh
```

Valida que los 3 nodos aparezcan con rol `control-plane,etcd` (aún `NotReady`, sin CNI):

```bash
sudo kubectl get nodes -o wide
sudo kubectl get nodes -l node-role.kubernetes.io/control-plane -o wide
```

Con los 3 control-plane como miembros etcd, despliega **kube-vip híbrido** (VIP BGP
`10.255.255.1` interno al fabric + VIP ARP `192.168.122.10` para el host) e instala **Calico**:

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/deploy-kube-vip.sh all   # kube-vip-arp (host) + kube-vip-bgp (fabric)

# Calico (operador Tigera) + Installation (VXLAN) + APIServer:
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml
kubectl apply -f deploy/k8s/l3-fabric/calico-fabric.yaml

# Tras unos segundos los nodos pasan a Ready y el VIP responde:
sudo kubectl get nodes -o wide
sudo kubectl -n calico-system get pods -l k8s-app=calico-node   # deben quedar 1/1
curl -k https://192.168.122.10:6443/readyz                       # VIP ARP, desde el host
```

`401 Unauthorized` = el VIP funciona (el API respondió sin credenciales). Lo que NO debe ocurrir
es timeout, conexión rechazada o ruta inalcanzable. El VIP BGP (`10.255.255.1`) se prueba **desde
un nodo** (es interno al fabric): `curl -k https://10.255.255.1:6443/readyz`.

> **Calico en este fabric (importante).** El dataplane es **VXLAN** (`encapsulation: VXLAN` en
> `calico-fabric.yaml`). El routing **nativo** sin encap **NO funciona** en esta topología L3
> multi-salto (Calico sin encap exige nodos L2-adyacentes; aquí el kernel no instala las rutas de
> pod a nodos no adyacentes). Calico corre su **malla BGP** (BIRD) sobre las loopbacks → los
> `calico-node` quedan `1/1`; para ello **FRR debe correr solo `ospfd`** (`bgpd=no`, lo fija
> `fabric-bootstrap.sh`) y así el BIRD de Calico toma el `:179`. El `calico-apiserver` (CR
> `APIServer` en `calico-fabric.yaml`) es **imprescindible**: sin él el operador no puede
> gestionar los IPPools. Ajusta la versión del operador (`v3.28.0`) a la del cluster si difiere.

## 8. Configurar kubeconfig

En cada control-plane desde donde operes `kubectl`. Sin esto, `kubectl` como usuario normal puede fallar con `permission denied`; hasta entonces usa `sudo kubectl`.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config
# En un nodo (alcanza el fabric): apunta al VIP BGP. Desde el HOST, usa el VIP ARP
# 192.168.122.10 (el host no alcanza la /32 del fabric) o ejecuta kubectl vía ssh_k3s.py.
sed -i 's#https://127.0.0.1:6443#https://10.255.255.1:6443#g' ~/.kube/config
grep -qxF 'export KUBECONFIG=$HOME/.kube/config' ~/.bashrc || echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
grep -qxF 'export KUBECONFIG=$HOME/.kube/config' ~/.profile || echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.profile
export KUBECONFIG=$HOME/.kube/config
kubectl get nodes -o wide
```

---

# Parte III — Workers

## 9. Preparar la Golden Image de workers

Configura una sola VM base, expórtala como `.qcow2` y clónala en GNS3.

Recursos recomendados:

| Recurso | Valor |
| --- | --- |
| RAM | 1 GB (2 GB recomendado para tráfico SDN sostenido) |
| CPU | 1 hilo (2 recomendado) |
| Disco | 10 GB |
| Adaptadores | 6 tipo `virtio` |

Si el disco aún no existe (linked clone), arranca la VM una vez, apágala y redimensiona con la VM apagada:

```bash
DISK=/home/artulita/GNS3/projects/ProyectoMemoria/project-files/qemu/NODE_ID/hda_disk.qcow2
qemu-img info "$DISK"
qemu-img resize "$DISK" 10G
qemu-img info "$DISK"
```

Reemplaza `NODE_ID` por el directorio real del nodo QEMU. Luego clona el repo y valida el espacio:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
df -h /
```

No continúes si `/` sigue por debajo de 10 GB.

## 10. Configurar auto-join del worker (fabric L3)

> **Arquitectura L3.** El worker ya **no** usa `br0` ni DHCP de gestión. Arranca en
> el **fabric L3** (FRR/OSPF *unnumbered* + loopback `/32` derivada de
> `/etc/machine-id`) que monta `fabric-bootstrap.service` **antes** de K3s; el
> auto-join se hace contra el VIP del API `10.255.255.1` (anunciado por kube-vip
> BGP). El viejo `gns3-br0-tree.service` queda **erradicado** por el script.

El script `prepare-k3s-worker-golden-image.sh` deja la VM base lista:

- Instala utilidades, Docker y **FRR** (`frr frr-pythontools`).
- Escribe un netplan L3 mínimo (`ens*` sueltas, sin `br0` ni DHCP) y desactiva la
  regeneración de red de cloud-init.
- Instala y habilita `fabric-bootstrap.service` (y `frr.service`); **elimina** el
  `gns3-br0-tree.service`/`configure-br0-tree.sh` heredados de la imagen L2.
- Crea `k3s-autojoin.service` **habilitado pero sin arrancar**, con el token, el VIP
  y la versión de K3s embebidos.

Confirma primero que el VIP del API responde (desde un control-plane del fabric):

```bash
curl -k https://10.255.255.1:6443/readyz
```

Obtén el token real en un control-plane (normalmente `master`):

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

Ejecuta la preparación en la VM base del worker, **desde la raíz del repo** (no
guardes el token en archivos del repo):

```bash
cd ~/ryu-k8s
sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  ./tools/gns3/prepare-k3s-worker-golden-image.sh
```

Overrides útiles:

- `RYU_K3S_API_ENDPOINT=10.255.255.1` — VIP del API (default del fabric L3).
- `RYU_K3S_VERSION=v1.35.5+k3s1` — versión de K3s; **debe coincidir con el cluster**
  (verifícala con `kubectl get nodes`).
- `RYU_K3S_SKIP_APT_UPGRADE=true` — omitir `apt upgrade`.

Valida que la imagen quedó en modo fabric (todavía **sin** loopback ni unión: eso
ocurre en cada clon tras el sellado):

```bash
df -h /
ls -l /usr/local/bin/fabric-bootstrap.sh        # instalado
systemctl is-enabled fabric-bootstrap.service   # enabled
systemctl is-enabled frr.service                # enabled
systemctl is-enabled k3s-autojoin.service       # enabled
systemctl is-active  k3s-autojoin.service || true  # debe estar inactive
test ! -e /etc/systemd/system/gns3-br0-tree.service && echo "br0-tree eliminado OK"
```

No arranques `k3s-autojoin.service` en la Golden Image: debe quedar habilitado para
correr en cada clon tras el sellado. En el primer arranque de cada clon,
`fabric-bootstrap` deriva la loopback única y `k3s-autojoin` renombra el nodo a
`worker-<mac de ens3>` y lo une al cluster con `--node-ip=<loopback>`.

## 11. Sellar la Golden Image

Al final, antes de apagar y exportar:

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/seal-k3s-worker-golden-image.sh
```

El sellado **vacía `/etc/machine-id`** (entre otra limpieza de identidad): es lo que
garantiza que cada clon regenere un `machine-id` único en su primer arranque y, por
tanto, una **loopback `/32` distinta** en el fabric (sin colisión de OSPF). Si no se
sella, todos los clones compartirían loopback y romperían el fabric.

Exporta el `.qcow2` sellado y úsalo como appliance de worker en GNS3.

## 12. Importar y arrancar workers en GNS3

### 12.1 Crear appliance QEMU

1. GNS3 → `Edit` → `Preferences` → `QEMU VMs` → `New`.
2. Nombre: `SDN-Worker`. Tipo: `Linux`.
3. Selecciona el `.qcow2` sellado como disco principal.
4. Configura 6 adaptadores tipo `virtio`.
5. En `Advanced`, `On close` = `Power off`.

### 12.2 Arrancar workers

1. Mantén encendidos los 3 control-plane y activo el VIP del API `10.255.255.1`.
2. Arrastra la appliance `SDN-Worker` tantas veces como necesites.
3. Conecta los workers solo a puertos `ens3`-`ens6` de control-planes (o de otros workers como hub). Cada cable es un **enlace L3 punto a punto** del fabric (OSPF *unnumbered*). **No** conectes workers al switch de gestión, al switch básico de GNS3 ni a `NAT1`.
4. Reserva `ens7`-`ens8` para Smart Meters u otros guests SDN (fuera del fabric).
5. Enciende los workers. No asignes IP manualmente: `fabric-bootstrap.service` deriva la loopback `/32` única (de `machine-id`), levanta OSPF en cada cable con carrier, y luego `k3s-autojoin.service` une el worker con `--node-ip=<loopback>`.

Cableado válido mínimo (un worker con un solo enlace de fabric):

| Worker | Control-plane |
| --- | --- |
| `SDN-Worker-1:e0` (`ens3`) | `Master:e1` (`ens4`) |
| `SDN-Worker-2:e0` (`ens3`) | `Master2:e1` (`ens4`) |
| `SDN-Worker-3:e0` (`ens3`) | `Master3:e1` (`ens4`) |

Para redundancia, conecta varios `ens3`-`ens6` del worker a control-planes/workers distintos: **todos** los cables con carrier entran al fabric y OSPF usa ECMP entre ellos. No hay árbol activo ni daemons de failover (OSPF *es* el failover); ya no aplican `ACTIVE_BR0_PORTS`, `worker-mgmt-failover` ni STP.

Valida desde un control-plane:

```bash
kubectl get nodes -o wide
kubectl get node <worker-name> -o jsonpath='{.metadata.annotations.k3s\.io/node-args}{"\n"}'
kubectl get node <worker-name> -o jsonpath='{.metadata.annotations.k3s\.io/node-env}{"\n"}' | grep -q 'K3S_NODE_TOKEN' && echo ERROR_TOKEN_EXPOSED || echo TOKEN_NOT_EXPOSED
```

---

# Parte IV — Despliegue SDN y Smart Meters

## 13. Desplegar servicios SDN en Kubernetes

Ejecuta desde un control-plane con `kubectl` apuntando a `https://10.255.255.1:6443`. Idealmente con los workers esperados ya en `Ready` (los DaemonSets solo corren en nodos existentes; los nuevos se cubren al unirse).

```bash
cd ~
test -d ryu-k8s || git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s
```

Namespace:

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
```

ConfigMaps de código montados por los pods (el de `meter-collector` **debe** incluir `registry.py` e `index.html`, montados por `subPath`):

```bash
kubectl create configmap ryu-code \
  --from-file=app.py=services/ryu-controller/app.py \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap dhcp-code \
  --from-file=app.py=services/dhcp-server/app.py \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap meter-collector-code \
  --from-file=app.py=services/meter-collector/app.py \
  --from-file=registry.py=services/meter-collector/registry.py \
  --from-file=index.html=services/meter-collector/templates/index.html \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -
```

Aplica los manifiestos por capa, esperando dependencias:

```bash
kubectl apply -f deploy/k8s/01-database.yaml
kubectl rollout status statefulset/redis -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/02-ryu-controller.yaml
kubectl apply -f deploy/k8s/03-sdn-network.yaml
kubectl rollout status daemonset/ovs-sdn-initializer -n sdn-controller --timeout=300s
kubectl rollout status daemonset/sdn-dhcp-server -n sdn-controller --timeout=300s
kubectl rollout status daemonset/ryu -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/05-telemetry.yaml
kubectl rollout status daemonset/meter-collector -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/06-observability.yaml
kubectl rollout status deployment/prometheus -n sdn-controller --timeout=300s
kubectl rollout status deployment/grafana -n sdn-controller --timeout=300s
```

El orden evita errores transitorios: Ryu, DHCP y meter-collector dependen de Redis; Ryu se aplica antes de OVS para que OVS apunte al controlador local, pero `ovs-sdn-initializer` debe crear `br-sdn` antes de esperar el rollout de Ryu. Prometheus/Grafana al final, para descubrir servicios ya creados.

Manifiestos aplicados:

| Archivo | Función |
| --- | --- |
| `00-namespace.yaml` | Namespace `sdn-controller` |
| `01-database.yaml` | Redis + Sentinel |
| `02-ryu-controller.yaml` | Ryu distribuido con `hostNetwork` |
| `03-sdn-network.yaml` | OVS initializer y DHCP distribuido |
| `05-telemetry.yaml` | Meter collector y consola AMI |
| `06-observability.yaml` | Prometheus, Grafana, Loki y exporters |

## 14. Incorporar Smart Meters

Los Smart Meters son **guests del plano de datos SDN** (`10.0.0.0/24`), no nodos del cluster. Se incorporan como contenedores Docker en GNS3 conectados a un puerto de guest de un worker (fuera del fabric). Obtienen IP del DaemonSet `sdn-dhcp-server`, publican telemetría UDP firmada con HMAC hacia el colector local `10.0.0.1:5555`, y deben autorizarse en la consola AMI (deny-default).

### 14.1 Importar el appliance en GNS3 (si no está presente)

Si el appliance "SDN Smart Meter" no aparece en GNS3, impórtalo desde la plantilla del repo:

1. GNS3 → `File` → `Import appliance`.
2. Selecciona `services/smart-meter/smart-meter.gns3a`.
3. Server: Main server (local).
4. GNS3 usará la imagen Docker `arturoalvarez/sdn-smart-meter:latest` (la baja de Docker Hub). Si trabajas sin internet, primero en el host GNS3: `docker pull arturoalvarez/sdn-smart-meter:latest`.

La plantilla ya define todo lo necesario:

| Campo | Valor |
| --- | --- |
| Imagen | `arturoalvarez/sdn-smart-meter:latest` |
| Categoría | guest |
| Adaptadores | 1 (`eth0`) |
| Consola | telnet |
| `COLLECTOR_IP` / `COLLECTOR_PORT` | `10.0.0.1` / `5555` |
| `HMAC_SECRET` | `sdn-ami-hmac-lab-secret-v1` |

> El `HMAC_SECRET` del medidor **debe coincidir** con el Secret `meter-hmac-secret` de `deploy/k8s/05-telemetry.yaml`. Si cambias uno, cambia el otro o la telemetría se rechazará por HMAC.

Sin la plantilla, crea un Docker container manual con esa imagen, 1 adaptador, consola telnet y las variables del bloque `environment` del `.gns3a`. Para reconstruir la imagen localmente:

```bash
docker build -t arturoalvarez/sdn-smart-meter:latest services/smart-meter
```

### 14.2 Nomenclatura para IP determinista

El `entrypoint.sh` del medidor fija una MAC estable derivada del hostname, y el DHCP asigna IP determinista a partir de ella. Nombra cada nodo Smart Meter en GNS3 como:

```text
SDNSmartMeter-N        # N entre 1 y 250
```

El medidor fija la MAC `02:42:53:4d:00:<NN>` (`NN` = `N` en hexadecimal) y el DHCP le asigna `10.0.0.(10+N)`:

| Hostname | MAC | IP |
| --- | --- | --- |
| `SDNSmartMeter-3` | `02:42:53:4d:00:03` | `10.0.0.13` |
| `SDNSmartMeter-6` | `02:42:53:4d:00:06` | `10.0.0.16` |

Esto garantiza la **misma IP tras recrear o reiniciar la VM**, lo que evita re-registrar el medidor en seguridad. Con el hostname por defecto el medidor funciona, pero su IP no será determinista.

### 14.3 Conexión en la topología

1. Arrastra el nodo Smart Meter al canvas.
2. Conecta su `eth0` a un **puerto de guest de un worker** (`ens7`/`ens8`, fuera del fabric). **No** lo conectes a un cable del fabric, al switch de gestión ni a `NAT1`.
3. El worker debe estar `Ready` y con `br-sdn` creado (`ovs-sdn-initializer`). OVS aprende el puerto del guest y el DHCP responde.
4. Enciende el Smart Meter.

El medidor pertenece al worker al que está cableado; `10.0.0.1` es la IP de `br-sdn` en ese nodo, así que su telemetría va al colector local.

### 14.4 Autorizar el medidor (deny-default)

La telemetría es deny-default: un medidor nuevo queda en `pending` y su telemetría se descarta hasta autorizarlo.

1. Abre la consola AMI: `http://192.168.122.100:8081` → sección **Seguridad**.
2. El medidor aparece como guest observado (correlación por `topology:guest_ips`). Pulsa **Registrar** o cambia su estado a `authorized`.
3. Verifica que la telemetría fluye:

```bash
curl http://192.168.122.100:8081/api/stats
```

Las VMs recreadas que ya estaban `authorized` conservan el estado si mantienen su MAC/IP determinista (sección 14.2).

### 14.5 Pruebas desde la consola del medidor

Abre la consola telnet del nodo en GNS3:

```bash
meter-test status
meter-test ping 10.0.0.13 --count 20
meter-test udp 10.0.0.13 --count 50 --interval 0.1 --size 128
tail -f /var/log/smart-meter.log
```

> Un `ping --count 1` o `2` puede mostrar un "50% loss" falso por la instalación de flujos del primer paquete. Mide siempre con `--count 5` o más para ver el estado estable (típicamente 0% de pérdida).

---

# Parte V — Verificación, Monitoreo y Debugging

## 15. Verificación del cluster

```bash
kubectl get nodes -o wide
```

Debe haber 3 nodos `control-plane,etcd` y el resto workers.

La `InternalIP` de cada nodo debe ser su **loopback del fabric** (`10.255.x`):

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" node-ip="}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'
```

CNI (Calico) y BGP sanos:

```bash
kubectl -n calico-system get pods -l k8s-app=calico-node -o wide   # 1/1
kubectl -n kube-system get pods -l app=kube-vip-bgp -o wide        # VIP fabric
kubectl -n kube-system get pods -l app=kube-vip -o wide            # VIP host (ARP)
# La malla BGP de Calico (BIRD) la ves dentro de calico-node, no en FRR (que es solo OSPF):
sudo vtysh -c 'show ip route 10.255.255.1'   # /32 del VIP, aprendida por OSPF
```

El VIP `10.255.255.1` se propaga por **OSPF**: kube-vip-bgp lo añade a `lo` (que está
OSPF-enabled) y OSPF lo inunda fabric-wide. El líder (lease `plndr-cp-lock-bgp`) lo sostiene;
si cae, otro CP lo toma y reanuncia. Para ver kube-vip:

```bash
kubectl -n kube-system logs -l app=kube-vip --tail=50 --prefix
```

## 16. Verificación de servicios SDN

```bash
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc
```

Rollouts principales:

```bash
kubectl rollout status statefulset/redis -n sdn-controller
kubectl rollout status daemonset/ryu -n sdn-controller
kubectl rollout status daemonset/ovs-sdn-initializer -n sdn-controller
kubectl rollout status daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout status daemonset/meter-collector -n sdn-controller
kubectl rollout status deployment/prometheus -n sdn-controller
kubectl rollout status deployment/grafana -n sdn-controller
```

`br-sdn` en cada nodo:

```bash
kubectl -n sdn-controller get pods -l app=ovs-sdn-initializer -o wide
kubectl -n sdn-controller exec <ovs-sdn-initializer-pod> -- ovs-vsctl show
```

## 17. Monitoreo y endpoints

| Servicio | URL (desde el host, vía un control-plane edge) |
| --- | --- |
| API Server K3s | `https://10.255.255.1:6443` (interno al fabric; desde el host usa `ssh_k3s.py`) |
| Operaciones / Seguridad AMI / Topología | `http://192.168.122.100:8081` |
| Prometheus | `http://192.168.122.100:9090` |
| Grafana | `http://192.168.122.100:3000` |

El VIP `10.255.255.1` (kube-vip BGP) front-ea **solo el API** (`:6443`) y es interno al
fabric. Los dashboards corren en pods `hostNetwork` y **sirven directamente en el puerto de
cada nodo**; desde el host se alcanzan en la IP de gestión de **cualquier control-plane edge**
(`192.168.122.100/.106/.130`). Los workers no tienen IP de gestión, así que no se acceden
directamente desde el host. Su Service es `ClusterIP`: no uses `LoadBalancer`.

La telemetría AMI es deny-default. `/api/stats` muestra solo medidores autorizados con telemetría aceptada; `/api/telemetry-security` muestra los contadores de rechazo por fuente no registrada, cuarentena, bloqueo o errores de HMAC/replay.

Consultas rápidas:

```bash
curl http://192.168.122.100:8081/api/sdn-topology
curl http://192.168.122.100:8081/api/stats
curl http://192.168.122.100:8081/api/guests
curl http://192.168.122.100:8081/api/telemetry-security
curl http://192.168.122.100:9090/api/v1/targets
curl -s 'http://192.168.122.100:9090/api/v1/query?query=ryu_topology_edge_info'
```

Grafana usuario/contraseña inicial: `admin / admin`.

## 18. Debugging post-despliegue

### 18.1 Workers no aparecen en el cluster

En el worker afectado:

```bash
systemctl status k3s-autojoin.service --no-pager -l
journalctl -u k3s-autojoin.service -n 120 --no-pager
systemctl status k3s-agent --no-pager -l
journalctl -u k3s-agent -n 120 --no-pager
```

Primero, ¿montó el fabric? Sin loopback no hay `--node-ip` ni ruta al VIP:

```bash
ip -br -4 addr show lo                     # loopback 10.255.x/32
systemctl status fabric-bootstrap.service --no-pager -l
sudo vtysh -c 'show ip ospf neighbor'      # adyacencias FULL
```

El endpoint configurado debe ser el VIP del fabric, y el archivo no debe contener el token:

```bash
sudo grep RYU_K3S_API_ENDPOINT /etc/systemd/system/k3s-autojoin.service.d/token.conf
sudo grep -q K3S_NODE_TOKEN /etc/systemd/system/k3s-autojoin.service.d/token.conf && echo ERROR_TOKEN_ENV || echo OK
```

Conectividad al API Server (el VIP es interno al fabric; esto se prueba **en el nodo**):

```bash
ping -c 2 10.255.255.1
timeout 2 bash -c '</dev/tcp/10.255.255.1/6443' && echo OK
```

Si el worker se instaló con una IP antigua, bórralo y reinstala el agent:

```bash
kubectl delete node <worker-afectado>
```

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
sudo systemctl restart k3s-autojoin.service
```

### 18.2 VIP del API no responde

```bash
# VIP fabric (10.255.255.1):
kubectl -n kube-system get pods -l app=kube-vip-bgp -o wide
kubectl -n kube-system logs -l app=kube-vip-bgp --tail=120 --prefix
# VIP host (192.168.122.10):
kubectl -n kube-system get pods -l app=kube-vip -o wide
```

El VIP `10.255.255.1/32` se propaga por **OSPF** (no por BGP en FRR): kube-vip-bgp lo añade a
`lo` (OSPF-enabled) y OSPF lo inunda. Verifica la ruta y quién lo sostiene (en un control-plane):

```bash
sudo vtysh -c 'show ip route 10.255.255.1'   # /32 presente (vía OSPF)
ip -br -4 addr show lo | grep 10.255.255.1    # el CP líder lo tiene en lo
kubectl -n kube-system get lease plndr-cp-lock-bgp -o jsonpath='{.spec.holderIdentity}{"\n"}'
```

Si no aparece la ruta: confirma que el pod `kube-vip-bgp` está `1/1` en algún CP y que su `lo`
tiene el VIP. El VIP host `192.168.122.10` (ARP, lease `plndr-cp-lock`) es independiente.

### 18.3 InternalIP no es la loopback del fabric

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" node-ip="}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'
```

La `InternalIP` debe ser la loopback `10.255.x` del nodo. Si un nodo se registró con otra IP
(p.ej. tras regenerar `machine-id`): `kubectl delete node <nodo>`, y en el nodo
`sudo /usr/local/bin/k3s-agent-uninstall.sh` (worker) y `sudo systemctl restart k3s-autojoin.service`.

### 18.4 Redis Sentinel

```bash
kubectl get pods -l app=redis -n sdn-controller -o wide
kubectl exec redis-0 -c sentinel -n sdn-controller -- redis-cli -p 26379 sentinel master mymaster
```

Conectarse al Redis master actual:

```bash
MASTER_IP=$(kubectl exec redis-0 -c sentinel -n sdn-controller -- \
  redis-cli -p 26379 sentinel get-master-addr-by-name mymaster | head -n 1)
kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli -h "$MASTER_IP" PING
```

### 18.5 Logs de Ryu y DHCP

```bash
kubectl logs -n sdn-controller -l app=ryu --tail=200 --prefix
kubectl logs -n sdn-controller -l app=sdn-dhcp --tail=200 --prefix
```

### 18.6 Smart Meter no reporta telemetría

```bash
curl http://192.168.122.100:8081/api/stats
curl http://192.168.122.100:8081/api/guests
curl http://192.168.122.100:8081/api/telemetry-security
```

Un medidor nuevo NO se autoriza solo: al observarse queda en `pending` (rechazo `status_pending`) y su telemetría se descarta hasta aprobarlo con **Registrar** en la consola AMI (o estado `authorized`). Si `/api/telemetry-security` muestra `unregistered_source`, registra el medidor con la IP/MAC/DPID observados en `/api/guests`. Si muestra `status_quarantine` o `security_status_blocked`, cambia el estado a `authorized`. Los registros sin telemetría reciente se marcan `stale` en `/api/guests` (`offline_registered`).

En el nodo donde corre el guest o el collector:

```bash
ip -br addr show br-sdn
ss -lunp | grep ':5555'
sudo timeout 20 tcpdump -ni br-sdn 'arp or udp port 5555'
```

El Smart Meter debe enviar a `COLLECTOR_IP=10.0.0.1`, `COLLECTOR_PORT=5555`.

### 18.7 OVS y flujos OpenFlow

```bash
kubectl -n sdn-controller exec <ovs-sdn-initializer-pod> -- ovs-vsctl show
kubectl -n sdn-controller exec <ovs-sdn-initializer-pod> -- ovs-ofctl -O OpenFlow13 dump-flows br-sdn
```

Trazar un flujo desde el nodo del guest de origen:

```bash
sudo ovs-appctl ofproto/trace br-sdn in_port=<PUERTO>,dl_src=<MAC_SRC>,dl_dst=<MAC_DST>
```

## 19. Operaciones de mantenimiento

### 19.1 Recarga en caliente de código (sin reconstruir imagen)

El código va montado por ConfigMap. Actualiza y reinicia en un paso (ejemplo con Ryu):

```bash
kubectl create configmap ryu-code --from-file=app.py=services/ryu-controller/app.py \
  -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -
kubectl rollout restart ds ryu -n sdn-controller
```

Para `meter-collector`, el ConfigMap **debe** incluir `registry.py` e `index.html` además de `app.py` (se montan por `subPath`); omitirlos rompe el pod con `ModuleNotFoundError: registry`.

### 19.2 Reiniciar servicios

```bash
kubectl rollout restart daemonset/ovs-sdn-initializer -n sdn-controller
kubectl rollout restart daemonset/ryu -n sdn-controller
kubectl rollout restart daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout restart daemonset/meter-collector -n sdn-controller
kubectl rollout restart deployment/prometheus -n sdn-controller
kubectl rollout restart deployment/grafana -n sdn-controller
kubectl rollout restart deployment/loki -n sdn-controller
kubectl rollout restart statefulset/redis -n sdn-controller
```

### 19.3 Reset completo de Redis para repetir pruebas

Borra estado runtime: topología, aprendizaje MAC, DHCP leases, telemetría y registro de seguridad.

```bash
kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli FLUSHALL

kubectl rollout restart statefulset/redis -n sdn-controller
kubectl rollout restart daemonset/ryu -n sdn-controller
kubectl rollout restart daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout restart daemonset/meter-collector -n sdn-controller
```

Después del reset, reinicia o recrea los Smart Meters para que pidan DHCP otra vez y vuelve a autorizarlos (el reset borra el registro de seguridad).

### 19.4 Prueba de fallo del primer master

Solo con 3 control-plane `Ready`. Apaga `master` en GNS3 y, **desde otro control-plane**:

```bash
for i in $(seq 1 30); do
  curl -k --max-time 3 https://10.255.255.1:6443/readyz && break
  sleep 2
done
kubectl get nodes
sudo vtysh -c 'show ip route 10.255.255.1'   # el VIP sigue anunciado por los CP vivos
# El dashboard sigue en la IP edge de un control-plane VIVO (p.ej. control-2):
curl http://192.168.122.106:8081/api/sdn-topology
```

Resultado esperado:

- `kubectl` sigue funcionando contra `10.255.255.1` (kube-vip BGP lo anuncia desde los CP vivos; con ECMP no hay "líder" ni espera de failover ARP).
- Redis Sentinel mantiene o elige un master.
- Los DaemonSets críticos siguen activos en los nodos vivos.

---

## 20. Resiliencia del fabric L3

El fabric L3 **elimina la clase entera de fallo** del diseño L2 anterior (tormenta de
broadcast por loop): no hay dominio de broadcast multi-cable ni STP, y **OSPF es el
failover**. Cada cable es un enlace L3; si uno cae, OSPF reconverge por otro camino (ECMP
usa todos los cables a la vez, no respaldo en frío). Por eso desaparecen los tres daemons
del modelo viejo (`gns3-br0-tree`, `uplink-failover`, `worker-mgmt-failover`) y sus
guards de tormenta: ya no hacen falta.

### 20.1 Cómo da tolerancia el fabric

- **Reachability + ECMP:** OSPF *unnumbered* sobre cada `ensX` con carrier. `maximum-paths 8`
  → varios cables entre dos nodos se usan en paralelo; la caída de uno no corta la loopback.
- **Internet redundante:** cualquier control-plane conectado al `Mgmt-Switch`/`NAT` se
  autodetecta como *edge* (ping directo al gateway), hace NAT del fabric y **origina la
  default en OSPF**. Si hay varios edges, hay varias salidas (sin daemon de uplink).
- **VIP del API por BGP:** kube-vip anuncia `10.255.255.1/32` desde cada control-plane; si
  uno cae, los demás lo siguen anunciando (sin lease ni failover ARP).
- **Sin loops L2:** no hay bridge de gestión que pueda formar bucle, así que no hay
  storm-guards ni árbol de puertos por hostname.

Comprobaciones (en cualquier nodo):

```bash
sudo vtysh -c 'show ip ospf neighbor'        # FULL en cada cable con vecino
sudo vtysh -c 'show ip route 10.255.0.0/16'  # loopbacks alcanzables; multipath = ECMP
# La malla BGP es de Calico (BIRD), no de FRR; se ve dentro de calico-node:
sudo kubectl -n calico-system get pods -l k8s-app=calico-node   # 1/1 = malla BGP OK
```

### 20.2 Prueba de caída de un enlace

```bash
sudo vtysh -c 'show ip route <loopback-remota>'   # antes: ruta (idealmente multipath)
```

Suspende un cable en GNS3 (link → Suspend). OSPF reconverge en pocos segundos:

- La loopback remota sigue alcanzable (`ping <loopback>` continúa) si hay otro camino.
- `ip -s link` **no** muestra explosión de pps (sin tormenta de broadcast).
- Al restaurar el cable, OSPF lo reincorpora y el ECMP se rehace solo.

### 20.3 Prueba de no-cascada de workers

```bash
# Baseline: todos Ready
kubectl get nodes --no-headers | awk '{print $1, $2}'
```

Apaga un worker-hub (uno del que cuelgan otros) en GNS3. A los 45 s, 90 s y 150 s:

```bash
kubectl get nodes --no-headers | grep -c ' Ready'
kubectl get nodes --no-headers | grep ' NotReady'
```

Resultado esperado:

- Solo el worker apagado aparece `NotReady`; los demás reconvergen por OSPF y siguen `Ready`
  (siempre que tengan otro cable de fabric hacia un nodo vivo).
- No hay cascada: la ruta de gestión de los demás no dependía de un enslave L2 a ese hub.
- Al reencender, el nodo rederiva su loopback, OSPF readyace y vuelve a `Ready`.

> Para más matriz de fallos (enlace, worker, master, blackout) ver la nota de pruebas de
> resiliencia del fabric L3 y `docs/RequisitosResiliencia.md`.
