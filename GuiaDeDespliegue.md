# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s HA · Open vSwitch · Redis Sentinel · Docker
> **Entorno:** Ubuntu QEMU/KVM en GNS3 · Red de gestión `192.168.122.0/24`

---

## Índice

### Parte I — Reglas de Despliegue

1. [Orden obligatorio](#1-orden-obligatorio)
2. [Roles de nodos](#2-roles-de-nodos)
3. [Mapa de interfaces](#3-mapa-de-interfaces)

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

## 1. Orden obligatorio

Sigue este orden sin saltarte pasos:

1. Configura el primer servidor control-plane con IP fija `192.168.122.100`.
2. Instala K3s server en el primer servidor con `--cluster-init`.
3. Crea los permisos de `kube-vip`, pero no arranques workers todavía.
4. Prepara dos nodos adicionales como K3s `server`, no como workers.
5. Une esos dos nodos adicionales al cluster como `control-plane,etcd` usando `192.168.122.100` como primer miembro etcd.
6. Despliega `kube-vip` como DaemonSet para crear el VIP `192.168.122.10` en los 3 control-plane.
7. Solo después de tener 3 control-plane y el VIP activo, arranca workers/agents.
8. Despliega los manifiestos SDN en Kubernetes.
9. Ejecuta verificación y debugging únicamente después de terminar el despliegue.

No arranques workers apuntando a `192.168.122.10` antes de configurar y verificar `kube-vip`. Si el VIP no existe, los workers se quedarán esperando el API Server.

No conviertas un worker que ya se unió como `agent` en control-plane. Para usar una VM como control-plane, prepárala como servidor antes de instalar `k3s-agent`. Si un nodo ya se unió como worker, recrea la VM o desinstala el agent antes de instalarlo como server.

## 2. Roles de nodos

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
| Adaptadores | 8 tipo `virtio` |

Un disco de 2-3 GB no alcanza para Ubuntu, Docker y K3s. Si importas un template cloud pequeño, redimensiona el disco antes de instalar K3s.

En GNS3, cambiar RAM/CPU/adaptadores del nodo no redimensiona automáticamente el disco del clon. Antes de arrancar cada control-plane, verifica el `hda_disk.qcow2` del nodo y redimensiónalo si sigue pequeño:

```bash
DISK=/home/artulita/GNS3/projects/ProyectoMemoria/project-files/qemu/NODE_ID/hda_disk.qcow2
qemu-img info "$DISK"
qemu-img resize "$DISK" 20G
```

Reemplaza `NODE_ID` por el directorio real del nodo QEMU. No copies el comando con `NODE_ID` sin cambiarlo.

Ejecuta `qemu-img resize` con la VM apagada. Después de arrancar, valida dentro de Ubuntu que la partición raíz creció:

```bash
lsblk
df -h /
```

## 3. Mapa de interfaces

| Interfaz | Uso |
| --- | --- |
| `ens3` | Gestión principal hacia Cloud `virbr0` o enlace de gestión |
| `ens4`-`ens6` | Extensión de la red de gestión/fabric entre nodos |
| `ens7`-`ens8` | Puertos de guests SDN, fuera de `br0` |
| `br0` | Bridge Linux de gestión/fabric `192.168.122.0/24` |
| `br-sdn` | Bridge Open vSwitch creado por el DaemonSet SDN |

No agregues `br0` dentro de `br-sdn`. `br0` es gestión/fabric; `br-sdn` es dataplane SDN.

Para validar solo Parte I/II con una topología simple, conecta un único cable de gestión por control-plane: `ens3` de cada servidor hacia `Mgmt-STP-Switch`. Mantén `ens4`-`ens6` sin cable o como puertos opcionales en `br0`; no instales `gns3-br0-tree.service` salvo que agregues enlaces redundantes. `ens7` y `ens8` quedan reservadas para guests SDN y no deben entrar a `br0`.

Con nombres GNS3 típicos, la topología mínima para Parte I/II queda así:

| Enlace | Uso |
| --- | --- |
| `NAT1:nat0` ↔ `Mgmt-STP-Switch:eth0` | Salida de gestión a `virbr0` |
| `Master:e0` ↔ `Mgmt-STP-Switch:eth1` | Primer control-plane |
| `Master2:e0` ↔ `Mgmt-STP-Switch:eth2` | Segundo control-plane |
| `Master3:e0` ↔ `Mgmt-STP-Switch:eth3` | Tercer control-plane |

No conectes más cables para esta validación simple. Si hay enlaces antiguos o VMs sobrantes de una prueba anterior, elimínalos antes de empezar para no mezclar direcciones DHCP ni estados K3s viejos.

K3s y Flannel deben usar siempre `br0`:

```text
--flannel-iface=br0
```

### 3.1 Arranque completo de una topología GNS3 con enlaces redundantes

Si tu topología GNS3 tiene enlaces redundantes en la red de gestión/fabric, el segmento compartido debe usar STP. El `Ethernet switch` básico de GNS3 no es suficiente porque no participa en STP real; reemplázalo por un nodo Docker Open vSwitch y úsalo como raíz del árbol.

`configure-br0-tree.sh` sigue siendo necesario cuando quieres que cada nodo reconstruya `br0` de forma repetible después de apagar/encender la topología completa. No es obligatorio para una topología simple sin enlaces redundantes, pero sí es la forma recomendada para un fabric HA: evita depender de cambios manuales de `ip link`, fija la IP de `br0` y activa STP antes de K3s.

#### 3.1.1 Configurar el switch STP de gestión

Si la topología todavía usa el `Ethernet switch` básico de GNS3 para la red de gestión, elimínalo o déjalo apagado y reemplázalo por un nodo Docker Open vSwitch.

Configuración del nodo nuevo en GNS3:

| Campo | Valor |
| --- | --- |
| Template | Docker container / Open vSwitch |
| Imagen | `gns3/openvswitch:latest` |
| Nombre del nodo | `Mgmt-STP-Switch` o un nombre equivalente de switch de gestión |
| Adaptadores | 16 Ethernet adapters, o al menos tantos como enlaces de gestión vayas a conectar |
| Consola | Telnet o none |

Conecta al switch OVS todos los enlaces del segmento de gestión/fabric que antes llegaban al switch básico. Como mínimo debe conectar la salida NAT o uplink de gestión y los nodos que necesitan acceso inicial al API. Los enlaces redundantes directos entre nodos K3s también pueden quedar conectados; STP bloqueará o habilitará cada enlace según corresponda.

Ejemplo de asignación de puertos del switch OVS:

| Puerto del switch OVS | Conecta a |
| --- | --- |
| `eth0` | NAT/uplink de gestión |
| `eth1` | Primer control-plane |
| `eth2` | Segundo control-plane, si existe |
| `eth3` | Tercer control-plane, si existe |
| `eth4`-`ethN` | Otros enlaces de gestión/fabric según tu diseño |

Arranca el nodo y activa STP en su bridge `br0`. El ID del contenedor cambia si recreas el nodo, así que resuélvelo antes de ejecutar `ovs-vsctl`:

```bash
docker ps --filter ancestor=gns3/openvswitch:latest --format '{{.ID}} {{.Names}}'
```

Usa el contenedor que corresponda a tu switch de gestión:

```bash
docker exec <contenedor-mgmt-stp-switch> sh -lc '
  ovs-vsctl --may-exist add-br br0
  for port in $(ls /sys/class/net | grep -E "^eth[0-9]+$"); do
    ovs-vsctl --may-exist add-port br0 "$port"
    ip link set "$port" up
  done
  ip link set br0 up
  ovs-vsctl set Bridge br0 stp_enable=true other_config:stp-priority=0
'

docker exec <contenedor-mgmt-stp-switch> \
  ovs-vsctl get Bridge br0 stp_enable

docker exec <contenedor-mgmt-stp-switch> \
  ovs-vsctl get Bridge br0 other_config:stp-priority

docker exec <contenedor-mgmt-stp-switch> \
  ovs-appctl stp/show br0
```

El resultado esperado en `ovs-appctl stp/show br0` es `This bridge is the root`.

Si reinicias o recreas el nodo Docker y pierde la configuración, repite el bloque anterior. No guardes el ID del contenedor en el repositorio: resuélvelo siempre con `docker ps`.

#### 3.1.2 Planificar el perfil `br0` de cada nodo

Antes de instalar el servicio, define estos valores para cada nodo. No copies perfiles de otra topología: cada VM debe declarar solo las interfaces que realmente pertenecen a su red de gestión.

| Campo | Significado |
| --- | --- |
| `NODE_IP` | IP fija que tendrá `br0` en ese nodo |
| `NODE_PREFIX` | Prefijo de red, normalmente `24` en `192.168.122.0/24` |
| `NODE_GATEWAY` | Gateway de gestión, o vacío si ese nodo no debe instalar ruta por defecto |
| `BR0_MAC` | MAC estable para `br0`; recomendable si quieres DPID estable en `br-sdn` |
| `ALL_PORTS` | Interfaces físicas que el script puede administrar en `br0` |
| `STP_PORTS` | Subconjunto de `ALL_PORTS` que queda activo en modo `stp` |
| `PREFERRED_STP_PORTS` | Puertos preferidos con coste bajo |
| `BR_PRIORITY` | Prioridad STP del bridge Linux; menor valor significa mayor prioridad |
| `STP_LOW_COST` | Coste para puertos preferidos, por ejemplo `10` |
| `STP_HIGH_COST` | Coste para puertos de respaldo, por ejemplo `200` |

Reglas prácticas:

- Incluye en `STP_PORTS` todos los enlaces de gestión que quieras mantener conectados y disponibles para failover.
- Incluye en `PREFERRED_STP_PORTS` solo los enlaces que quieres favorecer como camino normal.
- Usa coste alto para enlaces de respaldo que solo deben activarse si falla la ruta principal.
- No incluyas `ens7` ni `ens8` si esos puertos estarán conectados a Smart Meters u otros guests SDN; deben quedar disponibles para `br-sdn`/OVS.

Los enlaces bloqueados por STP siguen levantados y deben mostrar BPDUs 802.1d en Wireshark.

La instalación de `configure-br0-tree.sh` no se hace en esta sección porque aquí todavía estás diseñando la topología. Crea el perfil y habilita el servicio más adelante, cuando cada VM ya exista, tenga hostname definitivo, interfaces conectadas y el repositorio clonado. En esta guía se hace en las secciones de preparación de control-plane y workers.

---

# Parte II — Plano de Control HA

## 4. Preparar el primer servidor control-plane

Ejecuta esta sección en la VM que será el primer control-plane. Esta VM conserva la IP fija `192.168.122.100`.

### 4.1 Instalar utilidades

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl git ca-certificates
```

### 4.2 Clonar el repositorio

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 4.3 Instalar Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
```

### 4.4 Configurar hostname e IP fija

```bash
sudo hostnamectl set-hostname master
echo "master" | sudo tee /etc/hostname
sudo sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 master" | sudo tee -a /etc/hosts

sudo bash -c 'cat > /etc/netplan/50-cloud-init.yaml << EOF
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      optional: false
    ens4:
      dhcp4: false
      optional: true
    ens5:
      dhcp4: false
      optional: true
    ens6:
      dhcp4: false
      optional: true
    ens7:
      dhcp4: false
      optional: true
    ens8:
      dhcp4: false
      optional: true
  bridges:
    br0:
      interfaces: [ens3, ens4, ens5, ens6]
      dhcp4: false
      addresses:
        - 192.168.122.100/24
      routes:
        - to: default
          via: 192.168.122.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      parameters:
        stp: true
EOF'
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply
```

La sesión SSH puede cortarse cuando `ens3` pasa a formar parte de `br0`. Eso es esperado. Reconecta a `192.168.122.100` y valida antes de seguir:

```bash
hostname
ip -br addr show br0
df -h /
```


### 4.5 Configurar espera de red

```bash
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
sudo bash -c 'cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF'
sudo systemctl daemon-reload
```

### 4.6 Configurar forwarding

```bash
sudo bash -c 'cat > /etc/sysctl.d/99-sdn.conf << EOF
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF'
sudo sysctl --system

sudo bash -c 'cat > /etc/systemd/system/k3s-iptables.service << EOF
[Unit]
Description=Reglas iptables para SDN/K3s
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 3
ExecStart=/bin/bash -c "iptables -I FORWARD -i br0 -o br0 -j ACCEPT; iptables -I FORWARD -i ens3 -j ACCEPT; iptables -I FORWARD -o ens3 -j ACCEPT"

[Install]
WantedBy=multi-user.target
EOF'
sudo systemctl daemon-reload
sudo systemctl enable --now k3s-iptables.service
```

### 4.7 Configurar `gns3-br0-tree.service` si usarás enlaces redundantes

Ejecuta esta subsección solo si tu topología de gestión tiene enlaces redundantes y quieres que `br0` se reconstruya automáticamente con STP tras cada arranque. En una topología simple sin redundancia puedes omitirla.

Crea el perfil local de esta VM. Este bloque es para el primer control-plane `master` con IP `192.168.122.100`; en otros nodos debes cambiar `NODE_IP`, `STP_PORTS`, `PREFERRED_STP_PORTS` y `BR_PRIORITY` antes de pegarlo.

```bash
set -euo pipefail

sudo tee /etc/default/gns3-br0-tree > /dev/null <<'EOF'
NODE_IP=192.168.122.100
NODE_PREFIX=24
NODE_GATEWAY=192.168.122.1
ALL_PORTS="ens3 ens4 ens5 ens6"
STP_PORTS="ens3 ens4 ens5 ens6"
PREFERRED_STP_PORTS="ens3"
BR_PRIORITY=32768
STP_LOW_COST=10
STP_HIGH_COST=200
EOF

sudo test -r /etc/default/gns3-br0-tree
sudo grep -q '^NODE_IP=192\.168\.122\.100$' /etc/default/gns3-br0-tree
```

Instala el script y el servicio systemd:

```bash
set -euo pipefail

cd ~/ryu-k8s
test -f tools/gns3/configure-br0-tree.sh
sudo test -r /etc/default/gns3-br0-tree

sudo install -m 0755 tools/gns3/configure-br0-tree.sh /usr/local/bin/configure-br0-tree.sh
sudo /usr/local/bin/configure-br0-tree.sh

sudo tee /etc/systemd/system/gns3-br0-tree.service > /dev/null <<'EOF'
[Unit]
Description=Configure GNS3 br0 management bridge
Before=network-online.target k3s.service k3s-agent.service
After=systemd-udev-settle.service
Wants=systemd-udev-settle.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/configure-br0-tree.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable gns3-br0-tree.service
```

Si `test -f tools/gns3/configure-br0-tree.sh` falla, la VM no tiene una versión del repositorio que incluya ese script. Actualiza el repositorio antes de crear el servicio.

Si ya ejecutaste una versión anterior de la guía y quedó un servicio roto con `status=203/EXEC`, elimínalo antes de repetir el bloque corregido:

```bash
sudo systemctl disable --now gns3-br0-tree.service || true
sudo rm -f /etc/systemd/system/gns3-br0-tree.service
sudo systemctl daemon-reload
```

Verifica el resultado en esta VM:

```bash
systemctl status gns3-br0-tree.service --no-pager
ip -br addr show br0
bridge link | grep 'master br0'
cat /sys/class/net/br0/bridge/stp_state
```

## 5. Instalar K3s en el primer servidor

Ejecuta esto solo en `master` (`192.168.122.100`).

Si estás usando la topología redundante con STP, antes de ejecutar el instalador asegúrate de haber completado la sección 4.7 en este nodo.

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
```

Guarda el token del cluster. Lo usarás en los dos servidores adicionales y en la Golden Image de workers.

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

No subas este token al repositorio.

## 6. Preparar permisos de kube-vip

Ejecuta esto en `master` después de instalar K3s. En esta sección solo se crean los permisos. El VIP se desplegará como DaemonSet después de unir los 3 servidores control-plane.

Crea el ServiceAccount y permisos de leader election para `kube-vip`. En K3s, `/etc/rancher/k3s/k3s.yaml` suele quedar legible solo por `root`, por lo que este primer `kubectl apply` debe ejecutarse con `sudo` si todavía no configuraste kubeconfig para el usuario `ubuntu`:

```bash
sudo kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-vip
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:kube-vip-role
rules:
  - apiGroups: [""]
    resources: ["nodes", "endpoints", "configmaps"]
    verbs: ["list", "get", "watch", "update", "create", "patch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["list", "get", "watch", "update", "create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-vip-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-vip-role
subjects:
  - kind: ServiceAccount
    name: kube-vip
    namespace: kube-system
EOF
```

No escribas todavía `/var/lib/rancher/k3s/server/manifests/kube-vip.yaml`: si K3s aplica un YAML incompleto mientras lo estás parcheando, `kube-vip` puede quedar con `serviceAccountName: default` o con el kubeconfig equivocado. En esta guía se usa un DaemonSet aplicado una vez cuando ya existen los 3 control-plane.

## 7. Preparar los dos servidores control-plane adicionales

Repite esta sección en dos VMs separadas que serán control-plane adicionales.

Estas VMs pueden tener la misma forma de red que un worker, pero no deben tener `k3s-autojoin.service` habilitado ni deben instalarse como `agent`.

### 7.1 Instalar utilidades

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl git ca-certificates
```

### 7.2 Clonar el repositorio

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 7.3 Instalar Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
```

### 7.4 Configurar red DHCP sobre `br0`

```bash
sudo bash -c 'cat > /etc/netplan/50-cloud-init.yaml << EOF
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      optional: true
    ens4:
      dhcp4: false
      optional: true
    ens5:
      dhcp4: false
      optional: true
    ens6:
      dhcp4: false
      optional: true
    ens7:
      dhcp4: false
      optional: true
    ens8:
      dhcp4: false
      optional: true
  bridges:
    br0:
      interfaces: [ens3, ens4, ens5, ens6]
      dhcp4: true
      dhcp-identifier: mac
      parameters:
        stp: true
EOF'
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply
```

Después de `netplan apply`, la IP DHCP de la VM puede cambiar porque la dirección pasa de `ens3` a `br0`. Si pierdes la sesión SSH, busca la nueva IP en la consola de GNS3, en la tabla DHCP/NAT o con un escaneo de `192.168.122.0/24`, y continúa desde esa IP.

No ejecutes la sección 7.5 hasta haber reconectado a la IP nueva y validado `br0`:

```bash
hostname
ip -br addr show br0
df -h /
```

### 7.5 Configurar hostname único

En el segundo servidor usa `control-2`. En el tercer servidor usa `control-3`.

```bash
export NODE_NAME=control-2
sudo hostnamectl set-hostname "$NODE_NAME"
echo "$NODE_NAME" | sudo tee /etc/hostname
sudo sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 $NODE_NAME" | sudo tee -a /etc/hosts
```

No reutilices el mismo hostname en dos servidores K3s.

### 7.6 Configurar espera de red y forwarding

```bash
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
sudo bash -c 'cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF'
sudo systemctl daemon-reload

sudo bash -c 'cat > /etc/systemd/system/k3s-iptables.service << EOF
[Unit]
Description=Regla iptables de forwarding para br0
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/sbin/iptables -I FORWARD -i br0 -o br0 -j ACCEPT

[Install]
WantedBy=multi-user.target
EOF'
sudo systemctl daemon-reload
sudo systemctl enable --now k3s-iptables.service
```

### 7.7 Configurar `gns3-br0-tree.service` si usarás enlaces redundantes

Si este servidor adicional participa en una topología de gestión redundante, repite la sección 4.7 en esta VM antes de unirla al cluster, pero cambia `NODE_IP`, `STP_PORTS`, `PREFERRED_STP_PORTS` y `BR_PRIORITY` según el cableado de este nodo. No reutilices literalmente el perfil del primer servidor.

## 8. Unir los servidores adicionales al cluster

Ejecuta esta sección en cada uno de los dos servidores adicionales.

Usa el token obtenido en el primer servidor. No uses el placeholder literalmente.

Si el servidor adicional forma parte de una topología redundante, completa primero la sección 7.7.

```bash
cd ~/ryu-k8s

sudo RYU_K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  RYU_K3S_API_ENDPOINT=192.168.122.10 \
  RYU_K3S_FIRST_SERVER_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

No uses `K3S_NODE_TOKEN` como variable de entorno directa al unir servidores. K3s persiste variables `K3S_*` en anotaciones internas del Node; el script acepta `RYU_K3S_NODE_TOKEN` y limpia el entorno antes de llamar al instalador.

Después de unir los dos servidores adicionales, valida desde cualquier control-plane que los 3 nodos estén listos:

```bash
sudo kubectl get nodes -o wide
```

Los tres servidores deben quedar como miembros etcd/control-plane antes de arrancar workers.

Despliega `kube-vip` una sola vez como DaemonSet. No habilites `services`; este laboratorio solo necesita que `kube-vip` anuncie `192.168.122.10` para el API Server.

```bash
sudo kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-vip-ds
  namespace: kube-system
  labels:
    app.kubernetes.io/name: kube-vip-ds
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kube-vip-ds
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kube-vip-ds
    spec:
      serviceAccountName: kube-vip
      hostNetwork: true
      hostAliases:
        - ip: "127.0.0.1"
          hostnames:
            - kubernetes
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: Exists
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
        - key: node-role.kubernetes.io/master
          operator: Exists
          effect: NoSchedule
      containers:
        - name: kube-vip
          image: ghcr.io/kube-vip/kube-vip:v0.8.7
          imagePullPolicy: IfNotPresent
          args:
            - manager
          env:
            - name: vip_arp
              value: "true"
            - name: port
              value: "6443"
            - name: vip_nodename
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: vip_interface
              value: br0
            - name: vip_cidr
              value: "32"
            - name: dns_mode
              value: first
            - name: cp_enable
              value: "true"
            - name: cp_namespace
              value: kube-system
            - name: vip_leaderelection
              value: "true"
            - name: vip_leasename
              value: plndr-cp-lock
            - name: vip_leaseduration
              value: "5"
            - name: vip_renewdeadline
              value: "3"
            - name: vip_retryperiod
              value: "1"
            - name: address
              value: 192.168.122.10
            - name: prometheus_server
              value: :2112
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
                - NET_RAW
          volumeMounts:
            - mountPath: /etc/kubernetes/admin.conf
              name: kubeconfig
      volumes:
        - name: kubeconfig
          hostPath:
            path: /etc/rancher/k3s/k3s.yaml
EOF

sudo kubectl -n kube-system rollout status daemonset/kube-vip-ds --timeout=240s
sudo kubectl -n kube-system get pods -l app.kubernetes.io/name=kube-vip-ds -o wide
sudo kubectl -n kube-system get lease plndr-cp-lock -o jsonpath='{.spec.holderIdentity}{"\n"}'
curl -k https://192.168.122.10:6443/readyz
```

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

Si abres una sesión no interactiva o ejecutas comandos remotos que no cargan `~/.bashrc`, antepone `KUBECONFIG=$HOME/.kube/config` o usa `sudo kubectl`. Sin esa variable, el wrapper de K3s puede intentar leer `/etc/rancher/k3s/k3s.yaml` y fallar por permisos.

Si ves este error, el cluster puede estar sano; solo falta configurar permisos para el usuario actual:

```text
WARN[0000] Unable to read /etc/rancher/k3s/k3s.yaml, please start server with --write-kubeconfig-mode or --write-kubeconfig-group to modify kube config permissions
error: error loading config file "/etc/rancher/k3s/k3s.yaml": open /etc/rancher/k3s/k3s.yaml: permission denied
```

Solución rápida para validar mientras configuras `~/.kube/config`:

```bash
sudo kubectl get nodes
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

Ejecuta las siguientes secciones solo en la VM base del worker.

### 10.1 Instalar utilidades

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl git ca-certificates
```

### 10.2 Clonar el repositorio

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s
```

### 10.3 Instalar Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
```

### 10.4 Configurar red DHCP Zero-Touch

```bash
sudo bash -c 'cat > /etc/netplan/50-cloud-init.yaml << EOF
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      optional: true
    ens4:
      dhcp4: false
      optional: true
    ens5:
      dhcp4: false
      optional: true
    ens6:
      dhcp4: false
      optional: true
    ens7:
      dhcp4: false
      optional: true
    ens8:
      dhcp4: false
      optional: true
  bridges:
    br0:
      interfaces: [ens3, ens4, ens5, ens6]
      dhcp4: true
      dhcp-identifier: mac
      parameters:
        stp: true
EOF'
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply
```

Después de `netplan apply`, la IP DHCP puede cambiar porque la dirección pasa de `ens3` a `br0`. Si se corta SSH, busca la nueva IP en la tabla DHCP/NAT o en la consola de GNS3 y continúa desde esa IP. Valida antes de seguir:

```bash
ip -br addr show br0
bridge link | grep 'master br0'
df -h /
```

### 10.5 Configurar espera de red y forwarding

```bash
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
sudo bash -c 'cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF'
sudo systemctl daemon-reload

sudo bash -c 'cat > /etc/systemd/system/k3s-iptables.service << EOF
[Unit]
Description=Regla iptables de forwarding para br0
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/sbin/iptables -I FORWARD -i br0 -o br0 -j ACCEPT

[Install]
WantedBy=multi-user.target
EOF'
sudo systemctl daemon-reload
sudo systemctl enable --now k3s-iptables.service
```

### 10.6 Preparar `configure-br0-tree.sh` para workers redundantes

Si los workers usarán una red de gestión redundante, instala el script en la Golden Image, pero no crees un perfil definitivo en `/etc/default/gns3-br0-tree` dentro de la imagen base salvo que todos los clones vayan a compartir exactamente el mismo diseño, cosa que normalmente no ocurre. Cada clon debe tener su propio `NODE_IP`, `BR0_MAC`, puertos y prioridad.

```bash
set -euo pipefail

cd ~/ryu-k8s
test -f tools/gns3/configure-br0-tree.sh
sudo install -m 0755 tools/gns3/configure-br0-tree.sh /usr/local/bin/configure-br0-tree.sh

sudo tee /etc/systemd/system/gns3-br0-tree.service > /dev/null <<'EOF'
[Unit]
Description=Configure GNS3 br0 management bridge
Before=network-online.target k3s-agent.service
After=systemd-udev-settle.service
Wants=systemd-udev-settle.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/configure-br0-tree.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable gns3-br0-tree.service
```

El servicio no reconfigura `br0` si `/etc/default/gns3-br0-tree` no existe. Después de crear cada clon en GNS3, si ese worker necesita STP gestionado por este script, entra en la VM, crea su perfil propio siguiendo la sección 4.7 y arranca el servicio antes de unirlo al cluster:

```bash
sudo systemctl start gns3-br0-tree.service
```

## 11. Configurar auto-join del worker

Esta sección deja preparado el servicio que se ejecutará automáticamente en cada clon.

Usa el token real del cluster HA obtenido en el primer servidor:

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

Copia el script de auto-join:

```bash
sudo cp ~/ryu-k8s/tools/gns3/k3s-autojoin-ha.sh /usr/local/bin/k3s-autojoin.sh
sudo chmod +x /usr/local/bin/k3s-autojoin.sh
```

Crea el servicio systemd:

```bash
sudo bash -c 'cat > /etc/systemd/system/k3s-autojoin.service << EOF
[Unit]
Description=Instalacion automatica de K3S Worker
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/k3s-autojoin.sh
Restart=on-failure
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF'
```

Crea el drop-in con el token real y el VIP del API Server:

```bash
sudo mkdir -p /etc/systemd/system/k3s-autojoin.service.d
sudo bash -c 'cat > /etc/systemd/system/k3s-autojoin.service.d/token.conf << EOF
[Service]
Environment=RYU_K3S_NODE_TOKEN=<TOKEN_REAL_DEL_CLUSTER_HA>
Environment=RYU_K3S_API_ENDPOINT=192.168.122.10
EOF'
sudo chmod 600 /etc/systemd/system/k3s-autojoin.service.d/token.conf

sudo systemctl daemon-reload
sudo systemctl enable k3s-autojoin.service
sudo systemd-analyze verify \
  /etc/systemd/system/k3s-autojoin.service \
  /etc/systemd/system/gns3-br0-tree.service \
  /etc/systemd/system/k3s-iptables.service
```

No uses `K3S_NODE_TOKEN` como variable del drop-in del worker. K3s persiste variables `K3S_*` en la anotación `k3s.io/node-env` del objeto Node; `RYU_K3S_NODE_TOKEN` evita exponer el token en Kubernetes y el script limpia el entorno antes de invocar el instalador.

No ejecutes `systemctl start k3s-autojoin.service` en la VM base. El servicio debe quedar solo habilitado para que corra en cada clon al primer arranque.

## 12. Sellar la Golden Image

Ejecuta esto al final, antes de apagar y exportar el disco.

```bash
sudo truncate -s 0 /etc/machine-id
sudo rm -f /var/lib/dbus/machine-id
sudo ln -s /etc/machine-id /var/lib/dbus/machine-id

sudo journalctl --vacuum-time=1s
cat /dev/null > ~/.bash_history

sudo poweroff
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

Cableado válido mínimo para un worker con un solo enlace:

| Worker | Control-plane |
| --- | --- |
| `SDN-Worker-1:e0` (`ens3`) | `Master-1:e1` (`ens4`) |
| `SDN-Worker-2:e0` (`ens3`) | `Master-2:e1` (`ens4`) |
| `SDN-Worker-3:e0` (`ens3`) | `Master-3:e1` (`ens4`) |

Si quieres redundancia de gestión para un worker, conecta `e0`-`e2` del worker a control-plane distintos, por ejemplo `Master-1:e1`, `Master-2:e1` y `Master-3:e1`, y crea un perfil `gns3-br0-tree` específico para ese clon antes de unirlo. No uses el switch de gestión como punto de conexión de workers.

Cada worker obtiene IP por DHCP en `br0`, genera hostname `worker-<mac>`, instala `k3s-agent` y se une al cluster usando `https://192.168.122.10:6443`.

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

Aplica los manifiestos por capa:

```bash
kubectl apply -f deploy/k8s/01-database.yaml
kubectl apply -f deploy/k8s/02-ryu-controller.yaml
kubectl apply -f deploy/k8s/03-sdn-network.yaml
kubectl apply -f deploy/k8s/04-topology-dashboard.yaml
kubectl apply -f deploy/k8s/05-telemetry.yaml
kubectl apply -f deploy/k8s/06-observability.yaml
```

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
