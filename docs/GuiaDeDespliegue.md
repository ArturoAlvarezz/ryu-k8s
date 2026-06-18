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
20. [Resiliencia de la red de gestión](#20-resiliencia-de-la-red-de-gestión)

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

#### 2.1.1 Configurar el switch de gestión

Configuración del nodo en GNS3:

| Campo | Valor |
| --- | --- |
| Template | Docker container / Open vSwitch |
| Imagen | `gns3/openvswitch:latest` |
| Nombre del nodo | `Mgmt-Switch` o un nombre equivalente de switch de gestión |
| Adaptadores | 16 Ethernet adapters, o al menos tantos como enlaces de gestión vayas a conectar |
| Consola | Telnet o none |

```bash

ovs-vsctl --may-exist add-br br0
for port in $(ls /sys/class/net | grep -E "^eth[0-9]+$"); do
  ovs-vsctl --may-exist add-port br0 "$port"
  ip link set "$port" up
done
ip link set br0 up
```

El control de bucles no se delega al switch de gestión; se mantiene mediante el árbol determinístico de puertos aplicado en cada nodo K3s.

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
4. Conecta los workers solo a puertos libres de nodos control-plane. No conectes ningún worker al switch de gestión, al switch básico de GNS3 ni a `NAT1`.
5. Reserva `ens7`-`ens8` para Smart Meters u otros guests SDN.
6. Enciende los workers.
7. No asignes IP manualmente a cada clon: `gns3-br0-tree.service` capturará la IP DHCP inicial de `br0` y la convertirá en perfil estático antes de que `k3s-autojoin.service` una el worker al cluster.

Cableado válido mínimo para un worker con un solo enlace:

| Worker | Control-plane |
| --- | --- |
| `SDN-Worker-1:e0` (`ens3`) | `Master:e1` (`ens4`) |
| `SDN-Worker-2:e0` (`ens3`) | `Master2:e1` (`ens4`) |
| `SDN-Worker-3:e0` (`ens3`) | `Master3:e1` (`ens4`) |

Si quieres redundancia de gestión para un worker, conecta `e0`-`e2` del worker a control-plane distintos, por ejemplo `Master:e1`, `Master2:e1` y `Master3:e1`. El árbol activo de `br0` se define por `ACTIVE_BR0_PORTS` en cada nodo; ajusta esa variable si necesitas forzar un camino específico para un clon. No uses el switch de gestión como punto de conexión de workers. Para que ese cable de respaldo se active automáticamente ante la caída de un worker-hub (sin formar loop ni STP), instala el daemon `worker-mgmt-failover` en el worker correspondiente: ver [Sección 20 — Resiliencia de la red de gestión](#20-resiliencia-de-la-red-de-gestión).

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

kubectl apply -f deploy/k8s/05-telemetry.yaml
kubectl rollout status daemonset/meter-collector -n sdn-controller --timeout=300s

kubectl apply -f deploy/k8s/06-observability.yaml
kubectl rollout status deployment/prometheus -n sdn-controller --timeout=300s
kubectl rollout status deployment/grafana -n sdn-controller --timeout=300s
```

Este orden evita errores transitorios difíciles de diagnosticar: Ryu, DHCP y meter-collector dependen de Redis; Ryu debe aplicarse antes de OVS para que OVS pueda apuntar al controlador local, pero no debes esperar el rollout de Ryu hasta que `ovs-sdn-initializer` haya creado `br-sdn`. Prometheus/Grafana deben desplegarse al final para descubrir servicios ya creados.

Los manifiestos aplicados son:

| Archivo | Función |
| --- | --- |
| `00-namespace.yaml` | Namespace `sdn-controller` |
| `01-database.yaml` | Redis + Sentinel |
| `02-ryu-controller.yaml` | Ryu distribuido con `hostNetwork` |
| `03-sdn-network.yaml` | OVS initializer y DHCP distribuido |
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
| Meter collector / Seguridad AMI / Topología | `http://192.168.122.10:8081` |
| Prometheus | `http://192.168.122.10:9090` |
| Grafana | `http://192.168.122.10:3000` |

El servicio `meter-collector` usa pods `hostNetwork`; por eso su Service debe mantener `externalTrafficPolicy: Local`. Si queda en `Cluster`, el balanceo externo puede enviar `8081` hacia otro nodo `192.168.122.x:5000` y el navegador queda esperando respuesta por retorno asimetrico. El sintoma es que `curl http://192.168.122.100:5000/api/stats` funciona, pero `curl http://192.168.122.100:8081/api/stats` se queda en timeout.

La telemetria AMI es deny-default. `/api/stats` muestra solo medidores autorizados con telemetria aceptada; `/api/telemetry-security` muestra los contadores de rechazo por fuente no registrada, cuarentena, bloqueo o errores de HMAC/replay.

Consultas rápidas:

```bash
curl http://192.168.122.10:8081/api/sdn-topology
curl http://192.168.122.10:8081/api/stats
curl http://192.168.122.10:8081/api/guests
curl http://192.168.122.10:8081/api/telemetry-security
curl http://192.168.122.10:9090/api/v1/targets
```

Consulta directa de enlaces SDN publicados por Prometheus:

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

Un medidor nuevo NO se autoriza solo: al observarse por primera vez queda en estado `pending` (rechazo de política `status_pending`) y su telemetría se descarta hasta que el operador lo aprueba con el botón **Registrar** en la consola AMI (o cambiando su estado a `authorized`). Las VMs recreadas que ya estaban `authorized` conservan ese estado. Los registros sin telemetría reciente se marcan `stale` en `/api/guests` (`offline_registered`) para distinguir bajas reales de medidores que sólo no han reportado aún.

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
curl http://192.168.122.10:8081/api/sdn-topology
curl http://192.168.122.10:8081/api/health
```

Resultado esperado:

- `kubectl` sigue funcionando contra `192.168.122.10`.
- El lease `plndr-cp-lock` cambia a un control-plane vivo. En GNS3 puede tardar 30-60 segundos mientras convergen ARP, kube-vip y etcd.
- Redis Sentinel mantiene o elige un master.
- Los DaemonSets críticos siguen activos en los nodos vivos.
- Los Deployments se recrean fuera del nodo apagado si tenían réplicas allí.

---

## 20. Resiliencia de la red de gestión

La red de gestión (`br0`, `192.168.122.0/24`) es una sola L2 plana sin STP. Mantener `br0` libre de loops y, a la vez, tolerante a fallos de nodo se logra con tres mecanismos coordinados, todos sin STP y todos auto-reparables ante tormentas de broadcast. El endpoint que mide "plano de gestión sano" es siempre el VIP HA de K3s `192.168.122.10` (kube-vip), no un control-plane concreto: así un master caído con el VIP flotando a otro control-plane no se confunde con una pérdida de red.

### 20.1 Árbol determinístico de `br0` (`gns3-br0-tree.service`)

`tools/gns3/configure-br0-tree.sh` enslava a `br0` únicamente un subconjunto de puertos físicos por nodo (`ACTIVE_BR0_PORTS`), dejando el resto de cables conectados pero fuera del bridge. Eso da un árbol sin ciclos con STP deshabilitado; los enlaces redundantes quedan como respaldo en frío que sólo se activa bajo demanda (ver 20.2 y 20.3).

- El subconjunto activo se define por nodo en `/etc/default/gns3-br0-tree` con `ACTIVE_BR0_PORTS`. Si esa variable no existe, el script aplica un default por hostname (función `default_active_ports`). Para un clon nuevo, fija `ACTIVE_BR0_PORTS` en su archivo de config en vez de depender del default.
- **Excepción documentada (control-plane estable):** `control-3` lleva `ens4` permanentemente en `br0`. Ese `ens4` es el extremo fijo del cable de respaldo hacia un worker (ver 20.3). No forma loop porque el extremo del worker mantiene su propio `ens4` fuera de `br0` mientras el camino primario está sano.
- Tras editar el árbol, el script regenera la config de `netplan`/`networkd` para que un reinicio (o un corte de energía) no re-enslave un puerto viejo y dispare una tormenta.

Verifica el árbol activo de un nodo:

```bash
systemctl is-active gns3-br0-tree.service
ip -br link show master br0
```

### 20.2 Failover del uplink a internet (`uplink-failover.service`)

Sólo `master` enslava su uplink hacia `NAT1`/gateway (`192.168.122.1`); los control-plane lo dejan fuera de `br0`. Eso hace de `master` un punto único de fallo para la salida a internet. El daemon `tools/gns3/uplink-failover.sh` corre en los control-plane de respaldo (`control-2` = prioridad 1, `control-3` = prioridad 2) y enslava su uplink local cuando `master` deja de responder, devolviéndolo al liberarse cuando `master` regresa o si detecta una tormenta.

- Sólo se activa con `master` INALCANZABLE: si master no responde, su enlace está abajo y enslavar no crea un segundo camino activo (no hay loop).
- Un guard de tormenta libera el puerto de inmediato si se formara un loop en la ventana de failback.
- El uplink es puro plano de gestión; `br-sdn`/VXLAN/Smart Meters no lo usan, así que el failover nunca afecta el tráfico SDN.

Instalación (en `control-2` y `control-3`):

```bash
sudo install -m 0755 tools/gns3/uplink-failover.sh /usr/local/bin/uplink-failover.sh
sudo install -m 0644 tools/gns3/uplink-failover.service /etc/systemd/system/uplink-failover.service
# control-2 -> prioridad 1, control-3 -> prioridad 2
echo 'PRIORITY=1' | sudo tee /etc/default/uplink-failover    # PRIORITY=2 en control-3
sudo systemctl enable --now uplink-failover.service
```

### 20.3 Failover de la ruta de gestión de un worker (`worker-mgmt-failover.service`)

Cuando los workers cuelgan en cadena de un único worker-hub, apagar ese hub deja sin ruta de gestión a todos los workers aguas abajo y se produce una **cascada**: todos pasan a `NotReady`. Para romperla, un worker con un segundo cable hacia un control-plane corre `tools/gns3/worker-mgmt-failover.sh`, que enslava su puerto de respaldo (`BACKUP_PORT`, por defecto `ens4`) a `br0` cuando el VIP de K3s deja de responder, abriendo un camino alternativo hacia el control-plane (su `ens4` siempre activo, ver 20.1).

Garantías (mismo patrón que 20.2):

- **Disparo por salud del VIP** (`MGMT_VIP=192.168.122.10`): se mide contra el VIP HA, no contra un master concreto. Mientras el hub esté caído, el extremo primario del posible loop también está abajo, así que enslavar no forma un bucle activo.
- **Failback exclusivamente por tormenta:** cuando el hub vuelve, el camino primario (`ens3`) y el backup (`ens4`) quedan activos a la vez → loop → el multicast se dispara → el guard libera `ens4`. No se libera por ping al VIP, porque estando enslavado el VIP es alcanzable a través del propio backup y ese ping no distinguiría "primario vivo".
- **Sin IPs de worker hardcodeadas:** el único valor fijo es el VIP (estable). Qué worker corre el daemon, su `BACKUP_PORT` y el cableado al control-plane se definen por config, nunca por la IP de otro worker (que cambia al recrear la VM).

Requisitos de cableado: el worker que corre el daemon debe tener un cable de su `ens4` al `ens4` de un control-plane que lleve ese puerto permanentemente en `br0` (ver excepción de `control-3` en 20.1). Ese worker reparte el respaldo para toda la cadena aguas abajo.

Instalación (en el worker con cable de respaldo a un control-plane):

```bash
sudo install -m 0755 tools/gns3/worker-mgmt-failover.sh /usr/local/bin/worker-mgmt-failover.sh
sudo install -m 0644 tools/gns3/worker-mgmt-failover.service /etc/systemd/system/worker-mgmt-failover.service
# Opcional: override de BACKUP_PORT/MGMT_VIP en /etc/default/worker-mgmt-failover
sudo systemctl enable --now worker-mgmt-failover.service
```

### 20.4 Prueba de no-cascada de workers

Verifica que apagar el worker-hub sólo afecta a ese worker y no colapsa la cadena.

```bash
# Baseline: todos Ready
kubectl get nodes --no-headers | awk '{print $1, $2}'
```

Apaga el worker-hub en GNS3. A los 45 s, 90 s y 150 s vuelve a consultar:

```bash
kubectl get nodes --no-headers | grep -c ' Ready'
kubectl get nodes --no-headers | grep ' NotReady'
```

Resultado esperado:

- Sólo el worker-hub apagado aparece `NotReady`; los demás workers siguen `Ready` en todas las mediciones.
- En el worker de respaldo, `journalctl -u worker-mgmt-failover` muestra un único `ENSLAVE` durante el outage y un único `TORMENTA → RELEASE` al reencender el hub (failback limpio, sin oscilación).
- Al reencender el hub, el cluster reconverge a todos `Ready` en bajo 30-60 s.
