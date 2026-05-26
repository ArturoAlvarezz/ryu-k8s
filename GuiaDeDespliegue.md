# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s HA · Open vSwitch · Redis Sentinel · Docker
> **Entorno:** Ubuntu QEMU/KVM en GNS3 · Red de gestión `192.168.122.0/24`

---

## Índice

### Parte I — Reglas de Despliegue

1. [Roles de nodos](#1-roles-de-nodos)
2. [Mapa de interfaces](#2-mapa-de-interfaces)

### Parte II — Plano de Control HA

4. [Preparar el primer servidor control-plane](#4-preparar-el-primer-servidor-control-plane)
5. [Instalar K3s en el primer servidor](#5-instalar-k3s-en-el-primer-servidor)
6. [Preparar permisos de kube-vip](#6-preparar-permisos-de-kube-vip)
7. [Preparar los dos servidores control-plane adicionales](#7-preparar-los-dos-servidores-control-plane-adicionales)
8. [Unir los servidores adicionales al cluster](#8-unir-los-servidores-adicionales-al-cluster)
9. [Configurar kubeconfig](#9-configurar-kubeconfig)

### Parte III — Workers

10. [Preparar la Golden Image de workers](#10-preparar-la-golden-image-de-workers)
11. [Configurar auto-join del worker](#11-configurar-auto-join-del-worker)
12. [Sellar la Golden Image](#12-sellar-la-golden-image)
13. [Importar y arrancar workers en GNS3](#13-importar-y-arrancar-workers-en-gns3)

### Parte IV — Despliegue SDN

14. [Desplegar servicios SDN en Kubernetes](#14-desplegar-servicios-sdn-en-kubernetes)

### Parte V — Verificación, Monitoreo y Debugging Post-Despliegue

15. [Verificación del cluster](#15-verificación-del-cluster)
16. [Verificación de servicios SDN](#16-verificación-de-servicios-sdn)
17. [Monitoreo y endpoints](#17-monitoreo-y-endpoints)
18. [Debugging post-despliegue](#18-debugging-post-despliegue)
19. [Operaciones de mantenimiento](#19-operaciones-de-mantenimiento)

---

# Parte I — Reglas de Despliegue

## 1. Roles de nodos

| Rol | Cantidad | IP | Instalación K3s |
| --- | --- | --- | --- |
| Primer control-plane | 1 | `192.168.122.100` fija | `server --cluster-init` |
| Control-plane adicional | 2 | DHCP en `br0` | `server` unido al primero |
| Worker | Según topología | DHCP en `br0` | `agent` con auto-join |
| VIP API Server | 1 | `192.168.122.10` | Anunciado por `kube-vip` |

El endpoint final del cluster es siempre:

```text
https://192.168.122.10:6443
```

El primer servidor `192.168.122.100` se usa solo para inicializar el cluster y para que los servidores adicionales encuentren el primer miembro etcd durante el join.

Recursos mínimos validados para las VMs control-plane:

| Recurso | Valor |
| --- | --- |
| RAM | 3 GB o más |
| CPU | 2 hilos recomendados |
| Disco | 20 GB o más |
| Adaptadores | 6 tipo `virtio` |

## 2. Mapa de interfaces

| Interfaz | Uso |
| --- | --- |
| `ens3` | Gestión principal hacia Cloud `virbr0` o enlace de gestión |
| `ens4`-`ens6` | Extensión de la red de gestión/fabric entre nodos |
| `ens7`-`ens8` | Puertos de guests SDN, fuera de `br0` |
| `br0` | Bridge Linux de gestión/fabric `192.168.122.0/24` |
| `br-sdn` | Bridge Open vSwitch creado por el DaemonSet SDN |

### 2.1 Arranque completo de una topología GNS3 con enlaces redundantes

#### 2.1.1 Configurar el switch STP de gestión

Configuración del nodo en GNS3:

| Campo | Valor |
| --- | --- |
| Template | Docker container / Open vSwitch |
| Imagen | `gns3/openvswitch:latest` |
| Nombre del nodo | `Mgmt-STP-Switch` o un nombre equivalente de switch de gestión |
| Adaptadores | 16 Ethernet adapters, o al menos tantos como enlaces de gestión vayas a conectar |
| Consola | Telnet o none |

```bash

ovs-vsctl --may-exist add-br br0
for port in $(ls /sys/class/net | grep -E "^eth[0-9]+$"); do
  ovs-vsctl --may-exist add-port br0 "$port"
  ip link set "$port" up
done
ip link set br0 up
ovs-vsctl set Bridge br0 stp_enable=true other_config:stp-priority=0

ovs-vsctl get Bridge br0 stp_enable

ovs-vsctl get Bridge br0 other_config:stp-priority

ovs-appctl stp/show br0
```

---

# Parte II — Plano de Control HA

## 4. Preparar el primer servidor control-plane

Ejecuta esta sección en la VM que será el primer control-plane. Esta VM conserva la IP fija `192.168.122.100`.

### 4.1 Preparar disco y clonar el repositorio

Si la VM viene de un template QEMU con disco cloud pequeño o linked clone, redimensiona el disco a 20 GB antes de arrancarla. Hazlo con la VM apagada desde el host GNS3:

```bash
DISK=/home/artulita/GNS3/projects/ProyectoMemoria/project-files/qemu/NODE_ID/hda_disk.qcow2
qemu-img info "$DISK"
qemu-img resize "$DISK" 20G
qemu-img info "$DISK"
```

Después arranca la VM e instala lo mínimo para clonar el repositorio. El script de preparación intentará expandir la partición dentro de Ubuntu, pero valida el espacio antes de instalar K3s:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 4.2 Ejecutar preparación automática del primer control-plane

El script `tools/gns3/prepare-k3s-control-plane.sh` automatiza la configuración inicial del servidor: expande `/dev/vda1` si es posible, instala utilidades y Docker, fija hostname, configura `netplan` con `br0`, instala `gns3-br0-tree.service`, ajusta la espera de red, habilita forwarding y deja persistentes las reglas necesarias para K3s.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh first master 192.168.122.100
```

Si quieres evitar `apt upgrade` en una reinstalación rápida, ejecuta el mismo comando con `RYU_K3S_SKIP_APT_UPGRADE=true`.

La sesión SSH puede cortarse cuando `ens3` pasa a formar parte de `br0`. Eso es esperado. Reconecta a `192.168.122.100` y valida antes de seguir:

```bash
hostname
ip -br addr show br0
systemctl is-active gns3-br0-tree.service
df -h /
```

## 5. Instalar K3s en el primer servidor

Ejecuta esto solo en `master` (`192.168.122.100`).

```bash
cd ~/ryu-k8s

sudo RYU_K3S_CLUSTER_INIT=true \
  RYU_K3S_API_ENDPOINT=192.168.122.10 \
  RYU_K3S_NODE_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

Espera a que el nodo aparezca estable antes de seguir. Justo después de instalar K3s puede aparecer `Ready` con rol `<none>` durante unos segundos.

```bash
for i in $(seq 1 30); do
  sudo kubectl get nodes -o wide
  sudo kubectl get node master -o jsonpath='{.metadata.labels.node-role\.kubernetes\.io/control-plane}{"\n"}' 2>/dev/null | grep -q true && break
  sleep 5
done
sudo cat /var/lib/rancher/k3s/server/node-token
```

## 6. Preparar permisos de kube-vip

Ejecuta esto en `master` después de instalar K3s y antes de unir servidores adicionales. En esta sección solo se crean los permisos. El VIP se desplegará como DaemonSet después de unir los 3 servidores control-plane.

En K3s, `/etc/rancher/k3s/k3s.yaml` suele quedar legible solo por `root`, por lo que este primer paso debe ejecutarse con `sudo` si todavía no configuraste kubeconfig para el usuario `ubuntu`:

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/deploy-kube-vip.sh rbac
```

## 7. Preparar los dos servidores control-plane adicionales

Repite esta sección en dos VMs separadas que serán control-plane adicionales.

### 7.1 Preparar disco y clonar el repositorio

Antes de instalar paquetes, confirma que el disco del servidor adicional ya fue redimensionado a 20 GB. Si viene de un linked clone pequeño, haz el mismo procedimiento de redimensionado descrito en la sección 4.1 desde el host GNS3.

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 7.2 Ejecutar preparación automática del control-plane adicional

En el segundo servidor usa `control-2`. En el tercer servidor usa `control-3`. El script configura la red con DHCP temporal en `br0` y `gns3-br0-tree.service` captura esa IP como `NODE_IP` estática para reinicios posteriores, igual que en los workers clonables.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-2
```

Para el tercer servidor:

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-3
```

Si tienes una IP ya reservada y quieres fijarla explícitamente, pásala como tercer argumento:

```bash
sudo ./tools/gns3/prepare-k3s-control-plane.sh additional control-2 192.168.122.X
```

Después de aplicar `netplan`, la IP de la VM puede cambiar porque la dirección pasa de `ens3` a `br0`. Si pierdes la sesión SSH, busca la nueva IP en la consola de GNS3, en la tabla DHCP/NAT o con un escaneo de `192.168.122.0/24`, y continúa desde esa IP. No ejecutes la sección 8 hasta haber reconectado a la IP nueva y validado `br0`:

```bash
hostname
ip -br addr show br0
systemctl is-active gns3-br0-tree.service
df -h /
```

## 8. Unir los servidores adicionales al cluster

Ejecuta esta sección en cada uno de los dos servidores adicionales.

Usa el token obtenido en el primer servidor. No uses el placeholder literalmente.

En `master`, obtén el token y guárdalo solo en tu sesión de terminal o gestor seguro. No lo escribas en archivos del repositorio:

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

Después de unir los dos servidores adicionales, valida desde cualquier control-plane que los 3 nodos estén listos:

```bash
sudo kubectl get nodes -o wide
```

Los tres servidores deben quedar como miembros etcd/control-plane antes de desplegar `kube-vip` y antes de arrancar workers.

Valida también que los 3 servidores tengan rol `control-plane,etcd`:

```bash
sudo kubectl get nodes -l node-role.kubernetes.io/control-plane -o wide
```

Ahora sí, despliega `kube-vip` una sola vez como DaemonSet. No habilites `services`; este laboratorio solo necesita que `kube-vip` anuncie `192.168.122.10` para el API Server.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/deploy-kube-vip.sh daemonset
curl -k https://192.168.122.10:6443/readyz
```

Si `curl` devuelve `ok`, estás consultando con credenciales locales válidas. Si devuelve `401 Unauthorized`, el VIP también está funcionando: el API Server respondió, pero la petición no llevaba credenciales. Lo que no debe ocurrir es timeout, conexión rechazada o ruta inalcanzable.

El bloque `hostAliases` es intencional: fuerza a cada pod de `kube-vip` a hablar con el API local en `127.0.0.1`. Sin eso, los pods de `control-2` y `control-3` pueden intentar renovar o adquirir el lease a través del Service `kubernetes` y quedarse sin failover cuando cae `master`.

## 9. Configurar kubeconfig

Ejecuta esto en cada servidor control-plane desde donde vayas a operar `kubectl`.

Sin este paso, `kubectl` como usuario normal puede fallar con `error loading config file "/etc/rancher/k3s/k3s.yaml": permission denied`. Hasta configurar `~/.kube/config`, usa `sudo kubectl ...` para comandos administrativos.

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

## 10. Preparar la Golden Image de workers

Configura una sola VM base. Esa VM se exporta como `.qcow2` y luego se clona en GNS3.

Recursos recomendados:

| Recurso | Valor |
| --- | --- |
| RAM | 1 GB |
| CPU | 1 hilo |
| Disco | 10 GB |
| Adaptadores | 6 tipo `virtio` |

Si usas un template QEMU con linked clones, GNS3 puede crear el archivo `hda_disk.qcow2` recién al primer arranque del nodo. Si el archivo aún no existe, arranca la VM una vez, apágala inmediatamente desde GNS3 o con `sudo poweroff`, y redimensiona el disco con la VM apagada antes de instalar paquetes:

```bash
DISK=/home/artulita/GNS3/projects/ProyectoMemoria/project-files/qemu/NODE_ID/hda_disk.qcow2
qemu-img info "$DISK"
qemu-img resize "$DISK" 10G
qemu-img info "$DISK"
```

Reemplaza `NODE_ID` por el directorio real del nodo QEMU. No copies el comando con `NODE_ID` sin cambiarlo.

Después arranca la VM base e instala lo mínimo para clonar el repositorio. El script de preparación intentará expandir `/dev/vda1`, pero valida el espacio antes de sellar:

```bash
sudo apt update
sudo apt install -y git ca-certificates
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
df -h /
```

No continúes si `/` sigue por debajo de 10 GB.

## 11. Configurar auto-join del worker

Esta sección deja preparada la VM base para que cada clon se una automáticamente al cluster. El script instala utilidades y Docker, configura `br0` por DHCP temporal, instala `gns3-br0-tree.service`, configura forwarding, crea `k3s-autojoin.service` y lo deja habilitado pero sin arrancarlo.

Antes de tocar la Golden Image, asegúrate de que el VIP ya esté desplegado y responda desde la red de gestión:

```bash
curl -k https://192.168.122.10:6443/readyz
```

Un `401 Unauthorized` sin credenciales es válido porque confirma conectividad al API Server. Un timeout o conexión rechazada no es válido.

Usa el token real del cluster HA obtenido en un servidor control-plane, normalmente `master`. No ejecutes este comando en la VM base del worker porque ahí no existe el token de servidor:

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

Ejecuta la preparación automática en la VM base del worker. No guardes el token en archivos del repositorio:

```bash
cd ~/ryu-k8s
sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  ./tools/gns3/prepare-k3s-worker-golden-image.sh
```

Si quieres evitar `apt upgrade` en una reinstalación rápida, agrega `RYU_K3S_SKIP_APT_UPGRADE=true` al comando anterior.

Durante `netplan apply`, la IP DHCP temporal puede cambiar porque la dirección pasa de `ens3` a `br0`. Esa IP solo sirve para preparar la imagen; en los clones, `gns3-br0-tree.service` creará `/etc/default/gns3-br0-tree` con la IP propia de cada clon como `NODE_IP`. Si pierdes la sesión SSH, reconecta a la IP nueva y valida:

```bash
ip -br addr show br0
bridge link | grep 'master br0'
df -h /
systemctl is-enabled gns3-br0-tree.service
systemctl is-enabled k3s-autojoin.service
```

No arranques `k3s-autojoin.service` en la Golden Image. Debe quedar habilitado para ejecutarse en cada clon después del sellado y arranque en GNS3. El hostname definitivo del worker se generará automáticamente al primer arranque del clon con formato `worker-<mac>`.

Verifica que el servicio esté habilitado y no activo:

```bash
systemctl is-enabled k3s-autojoin.service
systemctl is-active k3s-autojoin.service || true
```

## 12. Sellar la Golden Image

Ejecuta esto al final, antes de apagar y exportar el disco.

```bash
cd ~/ryu-k8s
sudo ./tools/gns3/seal-k3s-worker-golden-image.sh
```

Exporta el disco `.qcow2` desde el hipervisor y úsalo como appliance de worker en GNS3.

## 13. Importar y arrancar workers en GNS3

### 13.1 Crear appliance QEMU

1. Abre GNS3.
2. Entra a `Edit` → `Preferences` → `QEMU VMs` → `New`.
3. Nombre: `SDN-Worker`.
4. Tipo: `Linux`.
5. Selecciona el `.qcow2` sellado como disco principal.
6. Configura 6 adaptadores tipo `virtio`.
7. En `Advanced`, deja `On close` en `Power off`.
8. Termina el asistente.

### 13.2 Arrancar workers

1. Mantén encendidos los 3 servidores control-plane.
2. Mantén activo el VIP `192.168.122.10`.
3. Arrastra la appliance `SDN-Worker` al canvas tantas veces como necesites.
4. Conecta los workers solo a puertos libres de nodos control-plane. No conectes ningún worker al `Mgmt-STP-Switch`, al switch básico de GNS3 ni a `NAT1`.
5. Reserva `ens7`-`ens8` para Smart Meters u otros guests SDN.
6. Enciende los workers.
7. No asignes IP manualmente a cada clon: `gns3-br0-tree.service` capturará la IP DHCP inicial de `br0` y la convertirá en perfil estático antes de que `k3s-autojoin.service` una el worker al cluster.

Cableado válido mínimo para un worker con un solo enlace:

| Worker | Control-plane |
| --- | --- |
| `SDN-Worker-1:e0` (`ens3`) | `Master:e1` (`ens4`) |
| `SDN-Worker-2:e0` (`ens3`) | `Master2:e1` (`ens4`) |
| `SDN-Worker-3:e0` (`ens3`) | `Master3:e1` (`ens4`) |

Si quieres redundancia de gestión para un worker, conecta `e0`-`e2` del worker a control-plane distintos, por ejemplo `Master:e1`, `Master2:e1` y `Master3:e1`, y crea un perfil `gns3-br0-tree` específico para ese clon antes de unirlo. No uses el switch de gestión como punto de conexión de workers.

Cada worker usa una IP persistente en `br0`, genera hostname `worker-<mac>`, instala `k3s-agent` y se une al cluster usando `https://192.168.122.10:6443`.

Valida desde un control-plane:

```bash
kubectl get nodes -o wide
kubectl get node <worker-name> -o jsonpath='{.metadata.annotations.k3s\.io/node-args}{"\n"}'
kubectl get node <worker-name> -o jsonpath='{.metadata.annotations.k3s\.io/node-env}{"\n"}' | grep -q 'K3S_NODE_TOKEN' && echo ERROR_TOKEN_EXPOSED || echo TOKEN_NOT_EXPOSED
```

---

# Parte IV — Despliegue SDN

## 14. Desplegar servicios SDN en Kubernetes

Ejecuta esta sección desde un control-plane con `kubectl` configurado contra `https://192.168.122.10:6443`.

No despliegues servicios SDN hasta que `kubectl get nodes -o wide` muestre los 3 control-plane y los workers esperados en `Ready`. Si faltan workers, puedes desplegar el plano SDN igualmente, pero los DaemonSets solo correrán en los nodos existentes y tendrás que verificar los nuevos nodos cuando se unan.

```bash
cd ~
test -d ryu-k8s || git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s
```

Aplica el namespace:

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
```

Crea los ConfigMaps de código montados por los pods:

```bash
kubectl create configmap ryu-code \
  --from-file=app.py=services/ryu-controller/app.py \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap ryu-topology-code \
  --from-file=app.py=services/topology-dashboard/app.py \
  --from-file=index.html=services/topology-dashboard/templates/index.html \
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

Aplica los manifiestos por capa y espera las dependencias principales antes de pasar a la siguiente capa:

```bash
kubectl apply -f deploy/k8s/01-database.yaml
kubectl rollout status statefulset/redis -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/02-ryu-controller.yaml
kubectl apply -f deploy/k8s/03-sdn-network.yaml
kubectl rollout status daemonset/ovs-sdn-initializer -n sdn-controller --timeout=300s
kubectl rollout status daemonset/sdn-dhcp-server -n sdn-controller --timeout=300s
kubectl rollout status daemonset/ryu -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/04-topology-dashboard.yaml
kubectl rollout status deployment/ryu-topology -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/05-telemetry.yaml
kubectl rollout status daemonset/meter-collector -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/06-observability.yaml
kubectl rollout status deployment/prometheus -n sdn-controller --timeout=300s
kubectl rollout status deployment/grafana -n sdn-controller --timeout=300s
```

Este orden evita errores transitorios difíciles de diagnosticar: Ryu, DHCP, topology-dashboard y meter-collector dependen de Redis; Ryu debe aplicarse antes de OVS para que OVS pueda apuntar al controlador local, pero no debes esperar el rollout de Ryu hasta que `ovs-sdn-initializer` haya creado `br-sdn`. Prometheus/Grafana deben desplegarse al final para descubrir servicios ya creados.

Los manifiestos aplicados son:

| Archivo | Función |
| --- | --- |
| `00-namespace.yaml` | Namespace `sdn-controller` |
| `01-database.yaml` | Redis + Sentinel |
| `02-ryu-controller.yaml` | Ryu distribuido con `hostNetwork` |
| `03-sdn-network.yaml` | OVS initializer y DHCP distribuido |
| `04-topology-dashboard.yaml` | Dashboard de topología |
| `05-telemetry.yaml` | Meter collector y consola AMI |
| `06-observability.yaml` | Prometheus, Grafana, Loki y exporters |

---

# Parte V — Verificación, Monitoreo y Debugging Post-Despliegue

## 15. Verificación del cluster

Ejecuta estos comandos después de terminar la configuración completa.

```bash
kubectl get nodes -o wide
```

Debe haber 3 nodos con rol `control-plane,etcd` y el resto como workers.

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" internal="}{.status.addresses[?(@.type=="InternalIP")].address}{" flannel="}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}{end}'
```

La IP `internal` y la IP `flannel` deben coincidir en cada nodo.

```bash
kubectl -n kube-system get pods -o wide
```

Los pods base de K3s deben estar `Running` o `Completed`.

Comprueba qué nodo control-plane está anunciando el VIP HA `192.168.122.10`:

```bash
kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{"\n"}'
```

El valor devuelto es el nodo que tiene el mando actual del VIP. Para ver los pods de `kube-vip` y su ubicación:

```bash
kubectl -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide
```

Para revisar los cambios de liderazgo o errores recientes de `kube-vip`:

```bash
kubectl -n kube-system logs -l app.kubernetes.io/name=kube-vip-ds --tail=50 --prefix
```

Desde la máquina local del repositorio también puedes consultarlo por SSH contra el master:

```bash
python3 tools/gns3/ssh_k3s.py "kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{\"\n\"}'"
python3 tools/gns3/ssh_k3s.py "kubectl -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide"
python3 tools/gns3/ssh_k3s.py "kubectl -n kube-system logs -l app.kubernetes.io/name=kube-vip-ds --tail=50 --prefix"
```

## 16. Verificación de servicios SDN

```bash
kubectl get configmap -n sdn-controller
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc
```

Verifica rollouts principales:

```bash
kubectl rollout status statefulset/redis -n sdn-controller
kubectl rollout status daemonset/ryu -n sdn-controller
kubectl rollout status daemonset/ovs-sdn-initializer -n sdn-controller
kubectl rollout status daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout status daemonset/meter-collector -n sdn-controller
kubectl rollout status deployment/ryu-topology -n sdn-controller
kubectl rollout status deployment/prometheus -n sdn-controller
kubectl rollout status deployment/grafana -n sdn-controller
```

Verifica que OVS tenga `br-sdn` en cada nodo:

```bash
kubectl -n sdn-controller get pods -l app=ovs-sdn-initializer -o wide
kubectl -n sdn-controller exec <ovs-sdn-initializer-pod> -- ovs-vsctl show
```

## 17. Monitoreo y endpoints

Endpoints principales del laboratorio:

| Servicio | URL |
| --- | --- |
| API Server K3s | `https://192.168.122.10:6443` |
| Topología | `http://192.168.122.10:8080` |
| Meter collector / Seguridad AMI | `http://192.168.122.10:8081` |
| Prometheus | `http://192.168.122.10:9090` |
| Grafana | `http://192.168.122.10:3000` |

El servicio `meter-collector` usa pods `hostNetwork`; por eso su Service debe mantener `externalTrafficPolicy: Local`. Si queda en `Cluster`, el balanceo externo puede enviar `8081` hacia otro nodo `192.168.122.x:5000` y el navegador queda esperando respuesta por retorno asimetrico. El sintoma es que `curl http://192.168.122.100:5000/api/stats` funciona, pero `curl http://192.168.122.100:8081/api/stats` se queda en timeout.

La telemetria AMI es deny-default. `/api/stats` muestra solo medidores autorizados con telemetria aceptada; `/api/telemetry-security` muestra los contadores de rechazo por fuente no registrada, cuarentena, bloqueo o errores de HMAC/replay.

Consultas rápidas:

```bash
curl http://192.168.122.10:8080/api/topology
curl http://192.168.122.10:8081/api/stats
curl http://192.168.122.10:8081/api/guests
curl http://192.168.122.10:8081/api/telemetry-security
curl http://192.168.122.10:9090/api/v1/targets
```

Consulta directa del grafo STP usado por Grafana:

```bash
curl -s 'http://192.168.122.10:9090/api/v1/query?query=ryu_topology_edge_info'
```

Grafana usa usuario y contraseña inicial:

```text
admin / admin
```

## 18. Debugging post-despliegue

Usa esta sección solo después de completar el despliegue.

### 18.1 Workers no aparecen en el cluster

En el worker afectado:

```bash
systemctl status k3s-autojoin.service --no-pager -l
journalctl -u k3s-autojoin.service -n 120 --no-pager
systemctl status k3s-agent --no-pager -l
journalctl -u k3s-agent -n 120 --no-pager
```

Comprueba que el endpoint configurado sea el VIP:

```bash
sudo grep RYU_K3S_API_ENDPOINT /etc/systemd/system/k3s-autojoin.service.d/token.conf
```

Debe ser:

```text
Environment=RYU_K3S_API_ENDPOINT=192.168.122.10
```

El archivo no debe contener `K3S_NODE_TOKEN`:

```bash
sudo grep -q K3S_NODE_TOKEN /etc/systemd/system/k3s-autojoin.service.d/token.conf && echo ERROR_TOKEN_ENV || echo OK
```

Comprueba conectividad al API Server:

```bash
ping -c 2 192.168.122.10
timeout 2 bash -c '</dev/tcp/192.168.122.10/6443' && echo OK
```

Si el worker se instaló con una IP antigua, elimina el Node desde Kubernetes y reinstala el agent en el worker:

```bash
kubectl delete node <worker-afectado>
```

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
sudo systemctl restart k3s-autojoin.service
```

### 18.2 VIP no responde

En cada control-plane:

```bash
kubectl -n kube-system get lease plndr-cp-lock -o yaml
kubectl -n kube-system get daemonset kube-vip-ds -o wide
kubectl -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide
kubectl -n kube-system logs <kube-vip-pod-name> --tail=120
```

En el lease, `spec.holderIdentity` indica qué control-plane está anunciando el VIP.

Comprueba que el DaemonSet use `br0`, `192.168.122.10`, el kubeconfig de K3s y el alias local del API:

```bash
kubectl -n kube-system get daemonset kube-vip-ds -o yaml | grep -E 'vip_interface|address:|192.168.122.10|br0|/etc/rancher/k3s/k3s.yaml|hostAliases|127.0.0.1'
```

Si `control-2` o `control-3` muestran `context deadline exceeded` al intentar leer el lease, revisa que exista `hostAliases` con `kubernetes -> 127.0.0.1` en el DaemonSet. Sin ese alias, el failover puede no ocurrir cuando cae `master`.

### 18.3 IP interna y Flannel no coinciden

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" internal="}{.status.addresses[?(@.type=="InternalIP")].address}{" flannel="}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}{end}'
```

Para un worker afectado:

```bash
kubectl delete node <worker-afectado>
```

En el worker:

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
sudo systemctl restart k3s-autojoin.service
```

### 18.4 Redis Sentinel

```bash
kubectl get statefulset redis -n sdn-controller
kubectl get pods -l app=redis -n sdn-controller -o wide
kubectl exec redis-0 -c sentinel -n sdn-controller -- \
  redis-cli -p 26379 sentinel master mymaster
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
curl http://192.168.122.10:8081/api/meters
curl http://192.168.122.10:8081/api/stats
curl http://192.168.122.10:8081/api/guests
curl http://192.168.122.10:8081/api/telemetry-security
```

Si `/api/telemetry-security` muestra `unregistered_source`, registra el medidor con la IP/MAC/DPID/puerto observados en `/api/guests`. Si muestra `status_quarantine` o `security_status_blocked`, cambia el estado del dispositivo a `authorized` desde la consola AMI antes de esperar que aparezca en `/api/stats`.

En el nodo donde corre el guest o el collector:

```bash
ip -br addr show br-sdn
ss -lunp | grep ':5555'
sudo timeout 20 tcpdump -ni br-sdn 'arp or udp port 5555'
```

El Smart Meter debe enviar a:

```text
COLLECTOR_IP=10.0.0.1
COLLECTOR_PORT=5555
```

### 18.7 OVS y flujos OpenFlow

```bash
kubectl -n sdn-controller exec <ovs-sdn-initializer-pod> -- ovs-vsctl show
kubectl -n sdn-controller exec <ovs-sdn-initializer-pod> -- ovs-ofctl -O OpenFlow13 dump-flows br-sdn
```

Trazar un flujo desde el nodo donde está el guest de origen:

```bash
sudo ovs-appctl ofproto/trace br-sdn in_port=<PUERTO>,dl_src=<MAC_SRC>,dl_dst=<MAC_DST>
```

## 19. Operaciones de mantenimiento

### 19.1 Reiniciar servicios

```bash
kubectl rollout restart daemonset/ovs-sdn-initializer -n sdn-controller
kubectl rollout restart daemonset/ryu -n sdn-controller
kubectl rollout restart daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout restart daemonset/meter-collector -n sdn-controller
kubectl rollout restart deployment/ryu-topology -n sdn-controller
kubectl rollout restart deployment/prometheus -n sdn-controller
kubectl rollout restart deployment/grafana -n sdn-controller
kubectl rollout restart deployment/loki -n sdn-controller
kubectl rollout restart statefulset/redis -n sdn-controller
```

### 19.2 Reset completo de Redis para repetir pruebas

Este procedimiento borra estado runtime: topología, aprendizaje MAC, DHCP leases, telemetría y registro de seguridad.

```bash
kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli FLUSHALL

kubectl rollout restart statefulset/redis -n sdn-controller
kubectl rollout restart daemonset/ryu -n sdn-controller
kubectl rollout restart daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout restart daemonset/meter-collector -n sdn-controller
kubectl rollout restart deployment/ryu-topology -n sdn-controller
```

Después del reset, reinicia o recrea los guests Smart Meter para que pidan DHCP otra vez. El reset también borra el registro de seguridad, por lo que la telemetria quedará rechazada hasta volver a registrar o autorizar los medidores esperados.

### 19.3 Prueba de fallo del primer master

Ejecuta esta prueba solo después de verificar que existen 3 control-plane `Ready`.

```bash
kubectl get nodes -o wide
kubectl get pods -A -o wide
```

Apaga el nodo `master` en GNS3.

Desde otro control-plane:

```bash
for i in $(seq 1 30); do
  curl -k --max-time 3 https://192.168.122.10:6443/readyz && break
  sleep 2
done
KUBECONFIG=$HOME/.kube/config kubectl get nodes
KUBECONFIG=$HOME/.kube/config kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{"\n"}'
curl http://192.168.122.10:8080/api/topology
curl http://192.168.122.10:8081/api/health
```

Resultado esperado:

- `kubectl` sigue funcionando contra `192.168.122.10`.
- El lease `plndr-cp-lock` cambia a un control-plane vivo. En GNS3 puede tardar 30-60 segundos mientras convergen ARP, kube-vip y etcd.
- Redis Sentinel mantiene o elige un master.
- Los DaemonSets críticos siguen activos en los nodos vivos.
- Los Deployments se recrean fuera del nodo apagado si tenían réplicas allí.
