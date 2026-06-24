# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s HA · Open vSwitch · Redis Sentinel · Docker
> **Entorno:** Ubuntu QEMU/KVM en GNS3 · Red de gestión `192.168.122.0/24` · Plano de datos SDN `10.0.0.0/24`

Guía genérica para desplegar el laboratorio desde cero. El cableado y la cantidad de nodos son libres: sirve para cualquier topología siempre que se respeten los roles, el mapa de interfaces y el orden de despliegue.

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
10. [Configurar auto-join del worker](#10-configurar-auto-join-del-worker)
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
20. [Resiliencia de la red de gestión](#20-resiliencia-de-la-red-de-gestión)

---

# Parte I — Reglas de Despliegue

## 1. Roles de nodos

| Rol | Cantidad | IP | Instalación K3s |
| --- | --- | --- | --- |
| Primer control-plane | 1 | `192.168.122.100` fija | `server --cluster-init` |
| Control-plane adicional | 2 | DHCP en `br0` | `server` unido al primero |
| Worker | Según topología | DHCP en `br0` | `agent` con auto-join |
| Smart Meter (guest) | Según topología | DHCP en `br-sdn` (`10.0.0.0/24`) | No es nodo del cluster |
| VIP API Server | 1 | `192.168.122.10` | Anunciado por `kube-vip` |

El endpoint final del cluster es siempre:

```text
https://192.168.122.10:6443
```

El primer servidor `192.168.122.100` se usa solo para inicializar el cluster y para que los servidores adicionales encuentren el primer miembro etcd durante el join. Después, todo apunta al VIP.

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
| `ens3` | Gestión principal hacia Cloud `virbr0` o enlace de gestión |
| `ens4`-`ens6` | Extensión de la red de gestión entre nodos |
| `ens7`-`ens8` | Puertos de guests SDN (Smart Meters), fuera de `br0` |
| `br0` | Bridge Linux de gestión `192.168.122.0/24` |
| `br-sdn` | Bridge Open vSwitch del plano de datos `10.0.0.0/24` (lo crea el DaemonSet SDN) |

`br0` (gestión) y `br-sdn` (datos SDN) nunca se mezclan. Los puertos de guests (`ens7`-`ens8`) quedan fuera de `br0` y los toma OVS.

### 2.1 Configurar el switch de gestión en GNS3

| Campo | Valor |
| --- | --- |
| Template | Docker container / Open vSwitch |
| Imagen | `gns3/openvswitch:latest` |
| Nombre del nodo | `Mgmt-Switch` o equivalente |
| Adaptadores | 16 Ethernet, o al menos tantos como enlaces de gestión vayas a conectar |
| Consola | Telnet o none |

```bash
ovs-vsctl --may-exist add-br br0
for port in $(ls /sys/class/net | grep -E "^eth[0-9]+$"); do
  ovs-vsctl --may-exist add-port br0 "$port"
  ip link set "$port" up
done
ip link set br0 up
```

El control de bucles no se delega al switch de gestión; se mantiene con el árbol determinístico de puertos aplicado en cada nodo K3s (ver [Sección 20](#20-resiliencia-de-la-red-de-gestión)).

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

`tools/gns3/prepare-k3s-control-plane.sh` expande `/dev/vda1` si puede, instala utilidades y Docker, fija hostname, configura `netplan` con `br0`, instala `gns3-br0-tree.service`, habilita forwarding y deja persistentes las reglas necesarias para K3s.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh first master 192.168.122.100
```

Para evitar `apt upgrade` en una reinstalación rápida: `RYU_K3S_SKIP_APT_UPGRADE=true`.

La sesión SSH puede cortarse cuando `ens3` pasa a `br0`. Es esperado. Reconecta a `192.168.122.100` y valida:

```bash
hostname
ip -br addr show br0
systemctl is-active gns3-br0-tree.service
df -h /
```

## 4. Instalar K3s en el primer servidor

Solo en `master` (`192.168.122.100`):

```bash
cd ~/ryu-k8s

sudo RYU_K3S_CLUSTER_INIT=true \
  RYU_K3S_API_ENDPOINT=192.168.122.10 \
  RYU_K3S_NODE_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

Espera a que el nodo quede estable (puede aparecer `Ready` con rol `<none>` unos segundos):

```bash
for i in $(seq 1 30); do
  sudo kubectl get nodes -o wide
  sudo kubectl get node master -o jsonpath='{.metadata.labels.node-role\.kubernetes\.io/control-plane}{"\n"}' 2>/dev/null | grep -q true && break
  sleep 5
done
sudo cat /var/lib/rancher/k3s/server/node-token
```

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

Usa `control-2` en el segundo y `control-3` en el tercero. El script configura DHCP temporal en `br0`; `gns3-br0-tree.service` captura esa IP como `NODE_IP` estática para reinicios.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-2
```

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-3
```

Para fijar una IP reservada explícita, pásala como tercer argumento:

```bash
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-2 192.168.122.X
```

Tras `netplan apply` la IP puede cambiar (pasa de `ens3` a `br0`). Si pierdes SSH, busca la IP nueva en la consola GNS3 o por escaneo de `192.168.122.0/24`, reconecta y valida antes de seguir:

```bash
hostname
ip -br addr show br0
systemctl is-active gns3-br0-tree.service
df -h /
```

## 7. Unir los control-plane y desplegar kube-vip

Ejecuta el join en cada uno de los dos servidores adicionales con el token real (no el placeholder). Obtén el token en `master`:

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

```bash
cd ~/ryu-k8s

sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  RYU_K3S_API_ENDPOINT=192.168.122.10 \
  RYU_K3S_FIRST_SERVER_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

Valida que los 3 nodos estén listos con rol `control-plane,etcd`:

```bash
sudo kubectl get nodes -o wide
sudo kubectl get nodes -l node-role.kubernetes.io/control-plane -o wide
```

Con los 3 control-plane como miembros etcd, despliega `kube-vip` una sola vez como DaemonSet. No habilites `services`; solo se necesita que anuncie `192.168.122.10` para el API Server.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/deploy-kube-vip.sh daemonset
curl -k https://192.168.122.10:6443/readyz
```

`ok` = credenciales locales válidas. `401 Unauthorized` = el VIP funciona (el API respondió sin credenciales). Lo que NO debe ocurrir es timeout, conexión rechazada o ruta inalcanzable.

El bloque `hostAliases` del DaemonSet fuerza a cada pod de `kube-vip` a hablar con el API local en `127.0.0.1`. Sin eso, `control-2`/`control-3` pueden quedarse sin failover cuando cae `master`.

## 8. Configurar kubeconfig

En cada control-plane desde donde operes `kubectl`. Sin esto, `kubectl` como usuario normal puede fallar con `permission denied`; hasta entonces usa `sudo kubectl`.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config
sed -i 's#https://127.0.0.1:6443#https://192.168.122.10:6443#g' ~/.kube/config
sed -i 's#https://192.168.122.100:6443#https://192.168.122.10:6443#g' ~/.kube/config
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

## 10. Configurar auto-join del worker

Prepara la VM base para que cada clon se una solo. El script instala utilidades y Docker, configura `br0` por DHCP temporal, instala `gns3-br0-tree.service`, configura forwarding y crea `k3s-autojoin.service` habilitado pero sin arrancar.

Antes, confirma que el VIP responde:

```bash
curl -k https://192.168.122.10:6443/readyz
```

Obtén el token real en un control-plane (normalmente `master`):

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

Ejecuta la preparación en la VM base del worker (no guardes el token en archivos del repo):

```bash
cd ~/ryu-k8s
sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  ./tools/gns3/prepare-k3s-worker-golden-image.sh
```

Para evitar `apt upgrade`: agrega `RYU_K3S_SKIP_APT_UPGRADE=true`.

La IP DHCP temporal solo sirve para preparar la imagen; en cada clon, `gns3-br0-tree.service` fija la IP propia como `NODE_IP`. Valida:

```bash
ip -br addr show br0
bridge link | grep 'master br0'
df -h /
systemctl is-enabled gns3-br0-tree.service
systemctl is-enabled k3s-autojoin.service
```

No arranques `k3s-autojoin.service` en la Golden Image: debe quedar habilitado para correr en cada clon tras el sellado. El hostname definitivo se genera al primer arranque del clon como `worker-<mac>`.

```bash
systemctl is-enabled k3s-autojoin.service
systemctl is-active k3s-autojoin.service || true
```

## 11. Sellar la Golden Image

Al final, antes de apagar y exportar:

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/seal-k3s-worker-golden-image.sh
```

Exporta el `.qcow2` sellado y úsalo como appliance de worker en GNS3.

## 12. Importar y arrancar workers en GNS3

### 12.1 Crear appliance QEMU

1. GNS3 → `Edit` → `Preferences` → `QEMU VMs` → `New`.
2. Nombre: `SDN-Worker`. Tipo: `Linux`.
3. Selecciona el `.qcow2` sellado como disco principal.
4. Configura 6 adaptadores tipo `virtio`.
5. En `Advanced`, `On close` = `Power off`.

### 12.2 Arrancar workers

1. Mantén encendidos los 3 control-plane y activo el VIP `192.168.122.10`.
2. Arrastra la appliance `SDN-Worker` tantas veces como necesites.
3. Conecta los workers solo a puertos libres de nodos control-plane (o a otros workers como hub). **No** conectes workers al switch de gestión, al switch básico de GNS3 ni a `NAT1`.
4. Reserva `ens7`-`ens8` para Smart Meters u otros guests SDN.
5. Enciende los workers. No asignes IP manualmente: `gns3-br0-tree.service` captura la IP DHCP de `br0` y la fija antes de que `k3s-autojoin.service` una el worker.

Cableado válido mínimo (un worker con un solo enlace de gestión):

| Worker | Control-plane |
| --- | --- |
| `SDN-Worker-1:e0` (`ens3`) | `Master:e1` (`ens4`) |
| `SDN-Worker-2:e0` (`ens3`) | `Master2:e1` (`ens4`) |
| `SDN-Worker-3:e0` (`ens3`) | `Master3:e1` (`ens4`) |

Para redundancia de gestión, conecta `e0`-`e2` del worker a control-plane distintos. El árbol activo de `br0` se define por `ACTIVE_BR0_PORTS` en cada nodo. Para que un cable de respaldo se active solo ante la caída de un worker-hub (sin loop ni STP), instala el daemon `worker-mgmt-failover` (ver [Sección 20](#20-resiliencia-de-la-red-de-gestión)).

Valida desde un control-plane:

```bash
kubectl get nodes -o wide
kubectl get node <worker-name> -o jsonpath='{.metadata.annotations.k3s\.io/node-args}{"\n"}'
kubectl get node <worker-name> -o jsonpath='{.metadata.annotations.k3s\.io/node-env}{"\n"}' | grep -q 'K3S_NODE_TOKEN' && echo ERROR_TOKEN_EXPOSED || echo TOKEN_NOT_EXPOSED
```

---

# Parte IV — Despliegue SDN y Smart Meters

## 13. Desplegar servicios SDN en Kubernetes

Ejecuta desde un control-plane con `kubectl` apuntando a `https://192.168.122.10:6443`. Idealmente con los workers esperados ya en `Ready` (los DaemonSets solo corren en nodos existentes; los nuevos se cubren al unirse).

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

Los Smart Meters son **guests del plano de datos SDN** (`10.0.0.0/24`), no nodos del cluster. Se incorporan como contenedores Docker en GNS3 conectados a un puerto de guest de un worker (fuera de `br0`). Obtienen IP del DaemonSet `sdn-dhcp-server`, publican telemetría UDP firmada con HMAC hacia el colector local `10.0.0.1:5555`, y deben autorizarse en la consola AMI (deny-default).

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
2. Conecta su `eth0` a un **puerto de guest de un worker** (`ens7`/`ens8`, fuera de `br0`). **No** lo conectes a `br0`, al switch de gestión ni a `NAT1`.
3. El worker debe estar `Ready` y con `br-sdn` creado (`ovs-sdn-initializer`). OVS aprende el puerto del guest y el DHCP responde.
4. Enciende el Smart Meter.

El medidor pertenece al worker al que está cableado; `10.0.0.1` es la IP de `br-sdn` en ese nodo, así que su telemetría va al colector local.

### 14.4 Autorizar el medidor (deny-default)

La telemetría es deny-default: un medidor nuevo queda en `pending` y su telemetría se descarta hasta autorizarlo.

1. Abre la consola AMI: `http://192.168.122.10:8081` → sección **Seguridad**.
2. El medidor aparece como guest observado (correlación por `topology:guest_ips`). Pulsa **Registrar** o cambia su estado a `authorized`.
3. Verifica que la telemetría fluye:

```bash
curl http://192.168.122.10:8081/api/stats
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

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" internal="}{.status.addresses[?(@.type=="InternalIP")].address}{" flannel="}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}{end}'
```

La IP `internal` y la IP `flannel` deben coincidir en cada nodo.

```bash
kubectl -n kube-system get pods -o wide
```

Qué control-plane anuncia el VIP:

```bash
kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{"\n"}'
kubectl -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide
kubectl -n kube-system logs -l app.kubernetes.io/name=kube-vip-ds --tail=50 --prefix
```

Desde la máquina local del repositorio puedes consultarlo por SSH contra el master:

```bash
python3 tools/gns3/ssh_k3s.py "kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{\"\n\"}'"
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

| Servicio | URL (VIP) | Directo (cualquier nodo) |
| --- | --- | --- |
| API Server K3s | `https://192.168.122.10:6443` | — |
| Operaciones / Seguridad AMI / Topología | `http://192.168.122.10:8081` | `http://192.168.122.100:8081` |
| Prometheus | `http://192.168.122.10:9090` | `http://192.168.122.100:9090` |
| Grafana | `http://192.168.122.10:3000` | `http://192.168.122.100:3000` |

El servicio `meter-collector` corre con pods `hostNetwork` y **sirve el dashboard/API directamente en el puerto `8081` de cada nodo**. El acceso externo es `VIP:8081 → nodo:8081 → meter-collector local`, sin depender del ServiceLB de K3s. Su Service es `ClusterIP` (solo DNS/ClusterIP interno): no uses `LoadBalancer` ni `externalTrafficPolicy` aquí. Cualquier nodo vivo (y el VIP cuando lo sostiene un control-plane) responde en `:8081`; si el VIP no responde, usa la IP directa de un nodo.

La telemetría AMI es deny-default. `/api/stats` muestra solo medidores autorizados con telemetría aceptada; `/api/telemetry-security` muestra los contadores de rechazo por fuente no registrada, cuarentena, bloqueo o errores de HMAC/replay.

Consultas rápidas:

```bash
curl http://192.168.122.10:8081/api/sdn-topology
curl http://192.168.122.10:8081/api/stats
curl http://192.168.122.10:8081/api/guests
curl http://192.168.122.10:8081/api/telemetry-security
curl http://192.168.122.10:9090/api/v1/targets
curl -s 'http://192.168.122.10:9090/api/v1/query?query=ryu_topology_edge_info'
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

El endpoint configurado debe ser el VIP, y el archivo no debe contener el token:

```bash
sudo grep RYU_K3S_API_ENDPOINT /etc/systemd/system/k3s-autojoin.service.d/token.conf
sudo grep -q K3S_NODE_TOKEN /etc/systemd/system/k3s-autojoin.service.d/token.conf && echo ERROR_TOKEN_ENV || echo OK
```

Conectividad al API Server:

```bash
ping -c 2 192.168.122.10
timeout 2 bash -c '</dev/tcp/192.168.122.10/6443' && echo OK
```

Si el worker se instaló con una IP antigua, bórralo y reinstala el agent:

```bash
kubectl delete node <worker-afectado>
```

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
sudo systemctl restart k3s-autojoin.service
```

### 18.2 VIP no responde

```bash
kubectl -n kube-system get lease plndr-cp-lock -o yaml
kubectl -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide
kubectl -n kube-system logs <kube-vip-pod-name> --tail=120
```

`spec.holderIdentity` indica qué control-plane anuncia el VIP. Verifica que el DaemonSet use `br0`, `192.168.122.10`, el kubeconfig de K3s y el alias local del API:

```bash
kubectl -n kube-system get daemonset kube-vip-ds -o yaml | grep -E 'vip_interface|address:|192.168.122.10|br0|/etc/rancher/k3s/k3s.yaml|hostAliases|127.0.0.1'
```

Si `control-2`/`control-3` muestran `context deadline exceeded` al leer el lease, revisa que exista `hostAliases` con `kubernetes -> 127.0.0.1`. Sin ese alias el failover puede no ocurrir cuando cae `master`.

### 18.3 IP interna y Flannel no coinciden

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" internal="}{.status.addresses[?(@.type=="InternalIP")].address}{" flannel="}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}{end}'
```

Para un worker afectado: `kubectl delete node <worker>`, luego en el worker `sudo /usr/local/bin/k3s-agent-uninstall.sh` y `sudo systemctl restart k3s-autojoin.service`.

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
curl http://192.168.122.10:8081/api/stats
curl http://192.168.122.10:8081/api/guests
curl http://192.168.122.10:8081/api/telemetry-security
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

Solo con 3 control-plane `Ready`. Apaga `master` en GNS3 y, desde otro control-plane:

```bash
for i in $(seq 1 30); do
  curl -k --max-time 3 https://192.168.122.10:6443/readyz && break
  sleep 2
done
kubectl get nodes
kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{"\n"}'
curl http://192.168.122.10:8081/api/sdn-topology
```

Resultado esperado:

- `kubectl` sigue funcionando contra `192.168.122.10`.
- El lease `plndr-cp-lock` cambia a un control-plane vivo (30-60 s mientras convergen ARP, kube-vip y etcd).
- Redis Sentinel mantiene o elige un master.
- Los DaemonSets críticos siguen activos en los nodos vivos.

---

## 20. Resiliencia de la red de gestión

La red de gestión (`br0`, `192.168.122.0/24`) es una sola L2 plana sin STP. Se mantiene libre de loops y tolerante a fallos con tres mecanismos coordinados, todos sin STP y auto-reparables ante tormentas de broadcast. El endpoint que mide "plano de gestión sano" es siempre el VIP HA `192.168.122.10` (kube-vip), no un control-plane concreto: así un master caído con el VIP flotando a otro nodo no se confunde con pérdida de red.

### 20.1 Árbol determinístico de `br0` (`gns3-br0-tree.service`)

`tools/gns3/configure-br0-tree.sh` enslava a `br0` solo un subconjunto de puertos físicos por nodo (`ACTIVE_BR0_PORTS`), dejando el resto de cables conectados pero fuera del bridge. Eso da un árbol sin ciclos con STP deshabilitado; los enlaces redundantes quedan como respaldo en frío que se activa bajo demanda (20.2 y 20.3).

- El subconjunto activo se define por nodo en `/etc/default/gns3-br0-tree` con `ACTIVE_BR0_PORTS`. Sin esa variable, el script aplica un default por hostname. Para un clon nuevo, fija `ACTIVE_BR0_PORTS` en su config en vez de depender del default.
- **Excepción documentada:** un control-plane estable (p.ej. `control-3`) puede llevar `ens4` permanentemente en `br0` como extremo fijo del cable de respaldo hacia un worker (20.3). No forma loop porque el extremo del worker mantiene su `ens4` fuera de `br0` mientras el camino primario está sano.
- Tras editar el árbol, el script regenera `netplan`/`networkd` para que un reinicio no re-enslave un puerto viejo y dispare una tormenta.

```bash
systemctl is-active gns3-br0-tree.service
ip -br link show master br0
```

### 20.2 Failover del uplink a internet (`uplink-failover.service`)

Solo `master` enslava su uplink hacia `NAT1`/gateway (`192.168.122.1`); es un punto único de fallo para salir a internet. El daemon `tools/gns3/uplink-failover.sh` corre en los control-plane de respaldo (`control-2` = prioridad 1, `control-3` = prioridad 2) y enslava su uplink local cuando `master` deja de responder, liberándolo al regresar `master` o ante una tormenta.

- Solo se activa con `master` INALCANZABLE: si master no responde, su enlace está abajo y enslavar no crea un segundo camino activo (no hay loop).
- Un guard de tormenta libera el puerto si se formara un loop en el failback.
- El uplink es puro plano de gestión; `br-sdn`/VXLAN/Smart Meters no lo usan.

Instalación (en `control-2` y `control-3`):

```bash
sudo install -m 0755 tools/gns3/uplink-failover.sh /usr/local/bin/uplink-failover.sh
sudo install -m 0644 tools/gns3/uplink-failover.service /etc/systemd/system/uplink-failover.service
echo 'PRIORITY=1' | sudo tee /etc/default/uplink-failover    # PRIORITY=2 en control-3
sudo systemctl enable --now uplink-failover.service
```

### 20.3 Failover de la ruta de gestión de un worker (`worker-mgmt-failover.service`)

Cuando los workers cuelgan en cadena de un único worker-hub, apagar ese hub deja sin ruta de gestión a todos los workers aguas abajo (cascada: todos `NotReady`). Para romperla, un worker con un segundo cable hacia un control-plane corre `tools/gns3/worker-mgmt-failover.sh`, que enslava su puerto de respaldo (`BACKUP_PORT`, por defecto `ens4`) a `br0` cuando el VIP deja de responder.

- **Disparo por salud del VIP** (`MGMT_VIP=192.168.122.10`): mientras el hub esté caído, el extremo primario del posible loop también está abajo, así que enslavar no forma bucle activo.
- **Failback solo por tormenta:** cuando el hub vuelve, primario (`ens3`) y backup (`ens4`) quedan activos a la vez → loop → el guard libera `ens4`. No se libera por ping al VIP (estando enslavado el VIP es alcanzable por el propio backup).
- **Sin IPs de worker hardcodeadas:** el único valor fijo es el VIP. Qué worker corre el daemon, su `BACKUP_PORT` y el cableado se definen por config.

Requisito de cableado: el worker que corre el daemon debe tener un cable de su `ens4` al `ens4` de un control-plane que lleve ese puerto permanentemente en `br0` (excepción de 20.1).

Instalación (en el worker con cable de respaldo a un control-plane):

```bash
sudo install -m 0755 tools/gns3/worker-mgmt-failover.sh /usr/local/bin/worker-mgmt-failover.sh
sudo install -m 0644 tools/gns3/worker-mgmt-failover.service /etc/systemd/system/worker-mgmt-failover.service
# Opcional: override de BACKUP_PORT/MGMT_VIP en /etc/default/worker-mgmt-failover
sudo systemctl enable --now worker-mgmt-failover.service
```

### 20.4 Prueba de no-cascada de workers

```bash
# Baseline: todos Ready
kubectl get nodes --no-headers | awk '{print $1, $2}'
```

Apaga el worker-hub en GNS3. A los 45 s, 90 s y 150 s:

```bash
kubectl get nodes --no-headers | grep -c ' Ready'
kubectl get nodes --no-headers | grep ' NotReady'
```

Resultado esperado:

- Solo el worker-hub apagado aparece `NotReady`; los demás siguen `Ready`.
- En el worker de respaldo, `journalctl -u worker-mgmt-failover` muestra un único `ENSLAVE` durante el outage y un único `TORMENTA → RELEASE` al reencender el hub.
- Al reencender el hub, el cluster reconverge a todos `Ready` en 30-60 s.
