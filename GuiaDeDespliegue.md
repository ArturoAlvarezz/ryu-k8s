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
6. [Configurar kube-vip en el primer servidor](#6-configurar-kube-vip-en-el-primer-servidor)
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
3. Configura `kube-vip` para crear el VIP `192.168.122.10`.
4. Prepara dos nodos adicionales como K3s `server`, no como workers.
5. Une esos dos nodos adicionales al cluster como `control-plane,etcd`.
6. Configura `kube-vip` también en los dos servidores adicionales.
7. Solo después de tener 3 control-plane y el VIP activo, arranca workers/agents.
8. Despliega los manifiestos SDN en Kubernetes.
9. Ejecuta verificación y debugging únicamente después de terminar el despliegue.

No arranques workers apuntando a `192.168.122.10` antes de configurar `kube-vip`. Si el VIP no existe, los workers se quedarán esperando el API Server.

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

## 3. Mapa de interfaces

| Interfaz | Uso |
| --- | --- |
| `ens3` | Gestión principal hacia Cloud `virbr0` o enlace de gestión |
| `ens4`-`ens6` | Extensión de la red de gestión/fabric entre nodos |
| `ens7`-`ens8` | Puertos de guests SDN, fuera de `br0` |
| `br0` | Bridge Linux de gestión/fabric `192.168.122.0/24` |
| `br-sdn` | Bridge Open vSwitch creado por el DaemonSet SDN |

No agregues `br0` dentro de `br-sdn`. `br0` es gestión/fabric; `br-sdn` es dataplane SDN.

K3s y Flannel deben usar siempre `br0`:

```text
--flannel-iface=br0
```

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

## 5. Instalar K3s en el primer servidor

Ejecuta esto solo en `master` (`192.168.122.100`).

```bash
cd ~/ryu-k8s

sudo K3S_CLUSTER_INIT=true \
  K3S_API_ENDPOINT=192.168.122.10 \
  K3S_NODE_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

Guarda el token del cluster. Lo usarás en los dos servidores adicionales y en la Golden Image de workers.

```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```

No subas este token al repositorio.

## 6. Configurar kube-vip en el primer servidor

Ejecuta esto en `master` después de instalar K3s.

```bash
export VIP=192.168.122.10
export INTERFACE=br0
export KVVERSION=v0.8.7

sudo mkdir -p /var/lib/rancher/k3s/server/manifests
sudo ctr image pull ghcr.io/kube-vip/kube-vip:${KVVERSION}
sudo ctr run --rm --net-host ghcr.io/kube-vip/kube-vip:${KVVERSION} vip /kube-vip manifest pod \
  --interface ${INTERFACE} \
  --address ${VIP} \
  --controlplane \
  --services \
  --arp \
  --leaderElection \
  | sudo tee /var/lib/rancher/k3s/server/manifests/kube-vip.yaml
```

`kube-vip` crea el endpoint estable `192.168.122.10:6443`. Los workers deben usar ese endpoint, no la IP fija del primer servidor.

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

## 8. Unir los servidores adicionales al cluster

Ejecuta esta sección en cada uno de los dos servidores adicionales.

Usa el token obtenido en el primer servidor. No uses el placeholder literalmente.

```bash
cd ~/ryu-k8s

sudo K3S_NODE_TOKEN='<TOKEN_REAL_DEL_CLUSTER_HA>' \
  K3S_API_ENDPOINT=192.168.122.10 \
  K3S_FIRST_SERVER_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

Después de unir cada servidor adicional, instala `kube-vip` también en ese servidor:

```bash
export VIP=192.168.122.10
export INTERFACE=br0
export KVVERSION=v0.8.7

sudo mkdir -p /var/lib/rancher/k3s/server/manifests
sudo ctr image pull ghcr.io/kube-vip/kube-vip:${KVVERSION}
sudo ctr run --rm --net-host ghcr.io/kube-vip/kube-vip:${KVVERSION} vip /kube-vip manifest pod \
  --interface ${INTERFACE} \
  --address ${VIP} \
  --controlplane \
  --services \
  --arp \
  --leaderElection \
  | sudo tee /var/lib/rancher/k3s/server/manifests/kube-vip.yaml
```

Los tres servidores deben quedar como miembros etcd/control-plane antes de arrancar workers.

## 9. Configurar kubeconfig

Ejecuta esto en cada servidor control-plane desde donde vayas a operar `kubectl`.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
sed -i 's#https://127.0.0.1:6443#https://192.168.122.10:6443#g' ~/.kube/config
sed -i 's#https://192.168.122.100:6443#https://192.168.122.10:6443#g' ~/.kube/config
grep -qxF 'export KUBECONFIG=$HOME/.kube/config' ~/.bashrc || echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
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
Environment=K3S_NODE_TOKEN=<TOKEN_REAL_DEL_CLUSTER_HA>
Environment=K3S_API_ENDPOINT=192.168.122.10
EOF'
sudo chmod 600 /etc/systemd/system/k3s-autojoin.service.d/token.conf

sudo systemctl daemon-reload
sudo systemctl enable k3s-autojoin.service
```

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
4. Conecta `ens3`-`ens6` a la red de gestión/fabric.
5. Reserva `ens7`-`ens8` para Smart Meters u otros guests SDN.
6. Enciende los workers.

Cada worker obtiene IP por DHCP en `br0`, genera hostname `worker-<mac>`, instala `k3s-agent` y se une al cluster usando `https://192.168.122.10:6443`.

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

Consultas rápidas:

```bash
curl http://192.168.122.10:8080/api/topology
curl http://192.168.122.10:8081/api/stats
curl http://192.168.122.10:9090/api/v1/targets
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
sudo grep K3S_API_ENDPOINT /etc/systemd/system/k3s-autojoin.service.d/token.conf
```

Debe ser:

```text
Environment=K3S_API_ENDPOINT=192.168.122.10
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
sudo ls -l /var/lib/rancher/k3s/server/manifests/kube-vip.yaml
kubectl -n kube-system get pods -o wide | grep kube-vip
kubectl -n kube-system logs <kube-vip-pod-name> --tail=120
```

Comprueba que el manifiesto use `br0` y `192.168.122.10`:

```bash
sudo grep -E 'vip_interface|address|192.168.122.10|br0' /var/lib/rancher/k3s/server/manifests/kube-vip.yaml
```

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
```

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

Después del reset, reinicia o recrea los guests Smart Meter para que pidan DHCP otra vez.

### 19.3 Prueba de fallo del primer master

Ejecuta esta prueba solo después de verificar que existen 3 control-plane `Ready`.

```bash
kubectl get nodes -o wide
kubectl get pods -A -o wide
```

Apaga el nodo `master` en GNS3.

Desde otro control-plane:

```bash
kubectl get nodes
curl -k https://192.168.122.10:6443/readyz
curl http://192.168.122.10:8080/api/topology
curl http://192.168.122.10:8081/api/health
```

Resultado esperado:

- `kubectl` sigue funcionando contra `192.168.122.10`.
- Redis Sentinel mantiene o elige un master.
- Los DaemonSets críticos siguen activos en los nodos vivos.
- Los Deployments se recrean fuera del nodo apagado si tenían réplicas allí.
