# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s · Open vSwitch · Redis · Docker  
> **Entorno:** Ubuntu (KVM/QEMU) · Red interna `192.168.122.0/24`

---

## Índice

### Parte I — Plano de control HA

1. [Requisitos del plano de control HA](#1-requisitos-del-plano-de-control-ha)
2. [Actualizar sistema e instalar utilidades](#2-actualizar-sistema-e-instalar-utilidades)
3. [Instalación de Docker](#3-instalación-de-docker)
4. [Configuración de red del primer servidor](#4-configuración-de-red-del-primer-servidor-ip-fija)
5. [Instalación de K3s HA](#5-instalación-de-k3s-ha)

### Parte II — Workers (Golden Image)

6. [Preparación de la Golden Image](#6-preparación-de-la-golden-image-plantilla-base)
7. [Actualizar sistema e instalar utilidades (Worker)](#7-actualizar-sistema-e-instalar-utilidades-worker)
8. [Instalación de Docker (Worker)](#8-instalación-de-docker-worker)
9. [Configuración de red del Worker (DHCP Zero-Touch)](#9-configuración-de-red-del-worker-dhcp-zero-touch)
10. [Instalación de K3s Agent (Auto-Join)](#10-instalación-de-k3s-agent-auto-join)
11. [Sellado de la Golden Image (Sysprep)](#11-sellado-de-la-golden-image-sysprep)

### Parte III — GNS3 y Despliegue SDN

12. [Importar la Golden Image en GNS3](#12-importar-la-golden-image-en-gns3-one-click)
13. [Despliegue de RYU en K3s](#13-despliegue-de-ryu-en-k3s)
14. [Verificación y monitoreo](#14-verificación-y-monitoreo)

---

# Parte I — Plano de control HA

> ℹ️ **El cluster debe desplegarse en modo HA** — usa 3 nodos K3s `server` con embedded etcd y un VIP estable para el API Server. El primer servidor conserva la IP fija `192.168.122.100`, pero `kubectl` y los workers deben apuntar al VIP `192.168.122.10`.

---

## 1. Requisitos del plano de control HA

| Recurso            | Mínimo                        |
| ------------------ | ----------------------------- |
| RAM                | 2 GB por server               |
| CPU                | 2 hilos por server            |
| Almacenamiento     | 20 GB                         |
| Adaptadores de red | 6 (1 gestión + 5 puertos OVS) |

**Arquitectura de red del primer servidor:**

- `br0` → Bridge de gestión/fabric con **IP fija `192.168.122.100`** en el primer server.
- `192.168.122.10` → VIP del API Server K3s HA, anunciado por `kube-vip` sobre `br0`.
- `ens3` → Puerto del bridge `br0`, conectado al Cloud `virbr0` en GNS3.
- `ens4`–`ens6` → Puertos del bridge `br0` para extender la red `192.168.122.0/24` hacia Workers y permitir DHCP en cadena.
- `ens7`–`ens8` / `Ethernet4`–`Ethernet5` → Puertos reservados para Guests SDN, fuera de `br0`; el `ovs-sdn-initializer` los agrega a `br-sdn`.

> ⚠️ **Importante:** En este modo, K3s debe instalarse con `--flannel-iface=br0`, no con `ens3`. La IP vive en el bridge, por lo que `ens3` no tendrá IPv4 propia.

> ⚠️ **Alta disponibilidad:** no uses `192.168.122.100` como endpoint permanente del cluster. Esa IP pertenece a un nodo. El endpoint estable debe ser `https://192.168.122.10:6443`.

---

## 2. Actualizar sistema e instalar utilidades

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl
```

---

## 3. Instalación de Docker

```bash
# Dependencias y repositorio oficial de Docker
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Instalar Docker Engine
sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
```

---

## 4. Configuración de red del primer servidor (IP fija)

### 4.1 Asignar hostname e IP estática

```bash
# 1. Hostname
sudo hostnamectl set-hostname master
echo "master" | sudo tee /etc/hostname
sudo sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 master" | sudo tee -a /etc/hosts

# 2. IP estática 192.168.122.100 en br0.
#    br0 incluye ens3-ens6 para extender la red 192.168.122.0/24.
#    ens7-ens8 quedan libres para Guests SDN y serán tomados por br-sdn.
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

# Verificar: br0 debe tener 192.168.122.100/24 y ruta por defecto
ip -br addr
ip route
```

La salida esperada debe verse así en lo importante:

```text
ens3    UP
br0     UP    192.168.122.100/24
```

Si `ens3` queda sin IPv4, está correcto. Lo importante es que `br0` tenga `192.168.122.100/24` y una ruta por defecto vía `192.168.122.1`.

### 4.2 Fix de systemd-networkd-wait-online

> ⚠️ **Problema conocido:** El Maestro puede arrancar con algunos puertos del bridge sin cable. `systemd-networkd-wait-online` espera que todos los enlaces estén configurados, bloqueando el arranque de K3s.

```bash
# Pasar con --any: basta con que br0 o algún enlace de gestión esté activo
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
sudo bash -c 'printf "[Service]\nExecStart=\nExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30\n" \
  > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf'
sudo systemctl daemon-reload
```

### 4.3 Habilitar IP Forwarding y reglas iptables

```bash
# Forwarding permanente
sudo bash -c 'cat > /etc/sysctl.d/99-sdn.conf << EOF
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF'
sudo sysctl --system

# Reglas iptables inmediatas
sudo iptables -I FORWARD -i br0 -o br0 -j ACCEPT
sudo iptables -I FORWARD -i ens3 -j ACCEPT
sudo iptables -I FORWARD -o ens3 -j ACCEPT

# Persistir reglas con servicio systemd
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

---

## 5. Instalación de K3s HA

El despliegue recomendado usa embedded etcd con 3 servidores K3s y un VIP (`192.168.122.10`) para que el API Server siga disponible si cae el nodo `master`.

Topología recomendada:

| Rol | Cantidad | Ejemplo |
| --- | --- | --- |
| K3s server / control-plane / etcd | 3 | `master`, `worker-5540b0`, `worker-6a4a6d` |
| K3s agent | 3 | resto de workers |
| VIP API Server | 1 | `192.168.122.10` |

Usa siempre un número impar de servidores etcd. Con 3 servidores, el cluster tolera la caída de 1 servidor. Con 5 servidores tolera 2, pero consume más CPU/RAM y complica el laboratorio.

Variables estándar usadas en esta guía:

```bash
export K3S_API_ENDPOINT=192.168.122.10
export K3S_FIRST_SERVER_IP=192.168.122.100
```

`K3S_API_ENDPOINT` debe ser una IP libre en `br0`. No debe pertenecer permanentemente a ningún nodo.

### 5.1 Instalar el primer servidor con cluster-init

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git ~/ryu-k8s
cd ~/ryu-k8s

sudo K3S_CLUSTER_INIT=true \
  K3S_API_ENDPOINT=192.168.122.10 \
  K3S_NODE_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh

# Guarda este token: se usará en servidores adicionales y agents.
sudo cat /var/lib/rancher/k3s/server/node-token
```

### 5.2 Configurar kube-vip para el VIP del API Server

Ejecuta este bloque en cada nodo que actúe como K3s `server`:

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

`kube-vip` anuncia `192.168.122.10` en la red L2 de `br0`. Si el server que posee el VIP cae, otro server toma el VIP mediante leader election.

### 5.3 Unir dos servidores adicionales

En dos nodos elegidos como control-plane adicionales, ejecuta:

```bash
cd ~/ryu-k8s
sudo K3S_NODE_TOKEN='<token-real>' \
  K3S_API_ENDPOINT=192.168.122.10 \
  K3S_FIRST_SERVER_IP=192.168.122.100 \
  ./tools/gns3/k3s-server-ha-install.sh
```

Cuando termines debe haber 3 nodos con rol `control-plane`:

```bash
kubectl get nodes -o wide
```

Después de que cada server adicional se una al cluster, instala `kube-vip` en ese nodo con el mismo bloque de la sección 5.2.

### 5.4 Configurar kubectl

```bash
# Configurar kubectl para el usuario actual
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
source ~/.bashrc

# Confirmar que kubectl apunta al VIP HA del API Server
grep 'server:' ~/.kube/config
# Debe mostrar: server: https://192.168.122.10:6443

# Persistir kubeconfig automáticamente en cada reinicio
sudo bash -c 'cat > /etc/systemd/system/k3s-kubeconfig.service << EOF
[Unit]
Description=Copiar kubeconfig de K3s al usuario ubuntu
After=k3s.service
Wants=k3s.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "mkdir -p /home/ubuntu/.kube && cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config && chown ubuntu:ubuntu /home/ubuntu/.kube/config"

[Install]
WantedBy=multi-user.target
EOF'
sudo systemctl daemon-reload
sudo systemctl enable --now k3s-kubeconfig.service

# Verificar que el plano de control HA está activo
kubectl get nodes -o wide
```

> Si `kubectl get nodes` devuelve `connection refused`, primero revisa `sudo systemctl status k3s`, `journalctl -u k3s -n 80` y que `kube-vip` esté anunciando `192.168.122.10`. En este modo K3s debe decir `--flannel-iface=br0` y `--tls-san=192.168.122.10`.

### 5.5 Distribuir componentes base de kube-system

Después de crear los 3 servers, distribuye componentes base para que no queden todos en el primer nodo:

```bash
kubectl -n kube-system scale deployment/coredns --replicas=2
kubectl -n kube-system rollout restart deployment/coredns deployment/metrics-server deployment/traefik
kubectl -n kube-system get pods -o wide
```

`local-path-provisioner` puede seguir con una réplica en este laboratorio porque Redis, Prometheus y Loki usan `emptyDir`. Si más adelante introduces PVCs persistentes, debes rediseñar almacenamiento antes de exigir HA real de datos.

### 5.6 Comportamiento esperado de administración HA

Los manifiestos del proyecto no deben fijar servicios de administración al hostname `master`:

- `ryu-topology` corre con 2 réplicas y anti-affinity.
- `grafana` corre con 2 réplicas y anti-affinity.
- `prometheus` y `loki` son movibles y mantienen 1 réplica porque usan `emptyDir`; Kubernetes puede recrearlos en otro nodo, pero sus datos locales se reinician.

Para HA real de métricas/logs en producción se necesitaría Thanos/Mimir/Loki distributed o almacenamiento replicado. En este laboratorio, el objetivo es que la administración, `kubectl` y los DaemonSets críticos sigan operativos cuando cae un server.

---

# Parte II — Workers (Golden Image)

> ℹ️ **La Golden Image es una única VM base** que se clonará en GNS3 para crear infinitos Workers con un solo clic. Configura esta VM una sola vez y expórtala como `.qcow2`.

---

## 6. Preparación de la Golden Image (Plantilla Base)

Crea una VM nueva en tu hipervisor (QEMU/KVM) con los siguientes recursos:

| Recurso            | Recomendado                        |
| ------------------ | ---------------------------------- |
| RAM                | 1 GB                               |
| CPU                | 1 hilo                             |
| Almacenamiento     | 10 GB                              |
| Adaptadores de red | 6 (1 gestión DHCP + 5 puertos OVS) |

**Arquitectura de red del Worker:**

- `br0` → Bridge de gestión/fabric con **IP dinámica DHCP** (`192.168.122.x`).
- `ens3`–`ens6` → Puertos del bridge `br0`, para poder conectarse al Maestro o a otros Workers y propagar DHCP.
- `ens7`–`ens8` / `Ethernet4`–`Ethernet5` → Puertos reservados para conectar Smart Meters u otros Guests SDN; no pertenecen a `br0`.

> En este modo, el Cloud `virbr0` solo necesita llegar al Maestro. Los Workers pueden conectarse al Maestro o entre sí usando `ens3`–`ens6`. Usa `Ethernet4`/`Ethernet5` (`ens7`/`ens8`) para Smart Meters y Guests SDN.

---

## 7. Actualizar sistema e instalar utilidades (Worker)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl
```

---

## 8. Instalación de Docker (Worker)

```bash
# Dependencias y repositorio oficial de Docker
sudo apt-get update
sudo apt-get install -y ca-certificates curl
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

---

## 9. Configuración de red del Worker (DHCP Zero-Touch)

### 9.1 Netplan con bridge DHCP Zero-Touch

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

# Verificar: br0 debe recibir una IP 192.168.122.x y una ruta por defecto
ip -br addr
ip route
ping -c 3 1.1.1.1
```

> **Importante:** `dhcp-identifier: mac` mantiene el flujo zero-touch sin hardcodear IPs. Cada worker sigue obteniendo una dirección automáticamente, pero el servidor DHCP identifica al clon por la MAC estable de su interfaz/bridge en vez de por un identificador DHCP generado por el sistema. Así, al reiniciar el proyecto en GNS3, el mismo worker vuelve a pedir la misma IP y K3s/Flannel no queda con `InternalIP` y `flannel public-ip` cruzadas.

Si `br0` aparece sin IPv4 y `ping` muestra `Network is unreachable`, revisa que exista un camino L2 hacia el Maestro y que el Maestro tenga `br0` conectado al Cloud `virbr0`.

Para validar que el puerto de Guest quedó libre para la SDN:

```bash
bridge link | grep -E 'ens7|ens8' || echo "ens7 y ens8 libres para br-sdn"
```

Cuando el DaemonSet `ovs-sdn-initializer` esté corriendo y haya Guests conectados, `ens7` y/o `ens8` deben aparecer dentro de `br-sdn`:

```bash
kubectl -n sdn-controller exec <ovs-sdn-initializer-del-worker> -- ovs-vsctl list-ports br-sdn
```

### 9.2 Forwarding de tráfico entre interfaces

```bash
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

### 9.3 Fix de systemd-networkd-wait-online

> ⚠️ **Problema conocido:** `systemd-networkd-wait-online` espera que todos los enlaces estén configurados. Como algunos puertos pueden no tener cable, esto puede bloquear `k3s-agent`.

```bash
# Pasar con --any: basta con que UNA interfaz esté activa
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
sudo bash -c 'cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF'
sudo systemctl daemon-reload
```

---

## 10. Instalación de K3s Agent (Auto-Join HA)

Ejecuta esta sección en la **VM base del Worker**, antes del sellado de la Golden Image. Así cada clon que arrastres en GNS3 ya tendrá el servicio habilitado y se unirá automáticamente al cluster al arrancar, sin entrar a la consola del worker.

### 10.1 Script de auto-configuración

Al arrancar un clon, este script obtiene IP DHCP, genera hostname único, espera al VIP del API Server y se une al cluster automáticamente.

Antes de crear el script, copia el token real desde cualquier servidor K3s:

```bash
# Ejecutar en cualquier server K3s
sudo cat /var/lib/rancher/k3s/server/node-token
```

Guarda ese valor para el servicio systemd de la VM base del Worker. No lo pegues dentro del script ni lo subas a git; el script debe leerlo desde `K3S_NODE_TOKEN`. Los workers deben unirse al VIP `192.168.122.10`, no a la IP del primer server.

```bash
sudo cp ~/ryu-k8s/tools/gns3/k3s-autojoin-ha.sh /usr/local/bin/k3s-autojoin.sh
sudo chmod +x /usr/local/bin/k3s-autojoin.sh
```

### 10.2 Servicio systemd del Worker

En la VM base del Worker, crea el servicio y el drop-in con el token real. El archivo `token.conf` queda dentro de la Golden Image para que los clones GNS3 se conecten solos al cluster.

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

# Crear el drop-in con el token real obtenido desde el cluster HA.
# Este archivo es local del Worker y no debe versionarse.
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

No ejecutes todavía `systemctl start k3s-autojoin.service` en la VM base si la vas a sellar como appliance. Solo debe quedar `enabled`; el join ocurrirá automáticamente en cada clon al primer arranque.

Si el servicio falla con `ERROR: Define K3S_NODE_TOKEN`, el script está correcto pero falta el drop-in `/etc/systemd/system/k3s-autojoin.service.d/token.conf` o contiene el token equivocado. Corrige el drop-in, ejecuta `sudo systemctl daemon-reload` y reinicia con `sudo systemctl restart k3s-autojoin.service`.

Si reconstruyes el cluster HA, el `node-token` cambia. En ese caso actualiza `token.conf` en la VM base del Worker y vuelve a exportar la appliance; los clones creados con una Golden Image vieja seguirán usando el token anterior y no podrán unirse.

---

## 11. Sellado de la Golden Image (Sysprep)

Antes de apagar la VM y exportarla, límpiala para que los clones generen identificadores únicos:

```bash
# Limpiar Machine-ID (fuerza DHCP leases únicos por clon)
sudo truncate -s 0 /etc/machine-id
sudo rm /var/lib/dbus/machine-id
sudo ln -s /etc/machine-id /var/lib/dbus/machine-id

# Limpiar logs y bash history
sudo journalctl --vacuum-time=1s
cat /dev/null > ~/.bash_history

# Apagar la VM
sudo poweroff
```

> ✅ **¡Listo!** Exporta el disco `.qcow2` desde tu hipervisor. Al importarlo en GNS3 y encender el nodo, en ~60 segundos se convierte en un Worker K3s operativo sin intervención manual.

---

# Parte III — GNS3 y Despliegue SDN

---

## 12. Importar la Golden Image en GNS3 (One-Click)

### 12.1 Crear la Appliance QEMU en GNS3

1. Abre **GNS3** → `Edit` → `Preferences` → `QEMU VMs` → **New**.
2. Nombre: `SDN-Worker`, Tipo: `Linux`.
3. Selecciona tu archivo `.qcow2` sellado como **disco principal**.
4. Configura **6 adaptadores** tipo `virtio`.
5. En **Advanced**, deja `On close` en `Power off` (no guardar estado).
6. Termina el asistente — verás `SDN-Worker` en tu panel de dispositivos.

### 12.2 Flujo de trabajo One-Click

```bash
┌─────────────────────────────────────────────────────────┐
│  GNS3 Canvas                                            │
│                                                         │
│  [SDN-Worker] ──── [SDN-Worker] ──── [SDN-Maestro]      │
│       ↑                  ↑                ↑             │
│  Arrastra y conecta cables (GNS3)    IP Fija            │
│                                  192.168.122.100        │
└─────────────────────────────────────────────────────────┘
```

1. **Arrastra** la Appliance `SDN-Worker` al canvas tantas veces como Workers necesites.
2. **Conecta los cables** según tu topología. Recuerda que el Cloud `virbr0` debe llegar al Maestro, y desde ahí puedes encadenar Workers usando `ens3`–`ens6` porque forman parte de `br0`. Reserva `ens7`–`ens8` / `Ethernet4`–`Ethernet5` para Smart Meters u otros Guests SDN.
3. **Inicia primero los 3 nodos control-plane** y espera a que `kubectl get nodes` muestre quorum.
4. Presiona **"Start All"** para los Workers.
5. En ~60 segundos cada Worker obtiene IP, genera hostname y se une al cluster.
6. Verifica desde cualquier nodo con kubeconfig apuntando al VIP:

```bash
kubectl get nodes
# Verás 3 control-plane y el resto de workers con STATUS Ready
```

> ⚠️ **Requisito:** El VIP `192.168.122.10` debe responder en `:6443` antes de iniciar los agents.

---

## 13. Despliegue de RYU en K3s

Ejecuta esta sección desde cualquier nodo control-plane o estación con kubeconfig apuntando a `https://192.168.122.10:6443`, después de confirmar que `kubectl get nodes -o wide` responde correctamente.

```bash
cd ~
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s

# Crear namespace antes de crear ConfigMaps y servicios
kubectl apply -f deploy/k8s/00-namespace.yaml

# Crear/actualizar ConfigMaps requeridos por el manifiesto
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

# Aplicar los manifiestos por capa, en orden de dependencias
kubectl apply -f deploy/k8s/01-database.yaml
kubectl apply -f deploy/k8s/02-ryu-controller.yaml
kubectl apply -f deploy/k8s/03-sdn-network.yaml
kubectl apply -f deploy/k8s/04-topology-dashboard.yaml
kubectl apply -f deploy/k8s/05-telemetry.yaml
kubectl apply -f deploy/k8s/06-observability.yaml

# Alternativa equivalente si prefieres aplicar todo el stack junto:
# kubectl apply -k deploy/k8s/

# Verificar el estado de todos los recursos
kubectl get configmap -n sdn-controller
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc
```

Los ConfigMaps son obligatorios porque los manifiestos montan el código de Ryu, Topología, DHCP y Meter Collector desde Kubernetes. Si se omiten, los Pods pueden quedar en `CreateContainerConfigError` o no arrancar correctamente.

Los manifiestos Kubernetes están separados por responsabilidad:

- `deploy/k8s/00-namespace.yaml`: namespace `sdn-controller`.
- `deploy/k8s/01-database.yaml`: Redis + Sentinel para estado compartido.
- `deploy/k8s/02-ryu-controller.yaml`: controlador Ryu/OpenFlow y servicio OpenFlow.
- `deploy/k8s/03-sdn-network.yaml`: `ovs-sdn-initializer` y DHCP distribuido.
- `deploy/k8s/04-topology-dashboard.yaml`: dashboard web propio de topología.
- `deploy/k8s/05-telemetry.yaml`: colector, dashboard Smart Meter y consola unificada de seguridad AMI.
- `deploy/k8s/06-observability.yaml`: Prometheus, Grafana, Loki, Promtail y Node Exporter.

> El `meter-collector` corre como DaemonSet con `hostNetwork` en todos los nodos y escucha UDP `5555` directamente sobre la SDN. El `ovs-sdn-initializer` asigna `10.0.0.1/24` a `br-sdn` en cada nodo; los Smart Meters deben enviar telemetría a `COLLECTOR_IP=10.0.0.1`.
>
> Importante: los healthchecks ARP del DHCP usan `psrc=0.0.0.0` para no envenenar la caché ARP de los Guests. Ryu responde localmente las solicitudes ARP por `10.0.0.1`, de modo que cada Guest use el collector de su propio nodo.
>
> `br-sdn` debe usar la misma MAC que `br0`. Ryu deriva la MAC gateway de `10.0.0.1` desde el DPID físico del nodo; si `br-sdn` usa otra MAC, los paquetes UDP destinados al collector local pueden llegar al puerto local de OVS con una MAC que el kernel no acepta.

### 13.1 Registro de dispositivos autorizados SDN AMI

La consola unificada `SDN AMI Operations`, servida por `meter-collector` en el puerto `8081`, crea la fuente de identidad de los medidores autorizados en Redis. Usa estas claves sin modificar el contrato existente de topología, DHCP ni telemetría:

- `security:devices`: set de `device_id` registrados.
- `security:device:{device_id}`: JSON completo del dispositivo.
- `security:mac_to_device:{mac}`: índice MAC a `device_id`.
- `security:ip_to_device:{ip}`: índice IP a `device_id`.

Modelo persistido por dispositivo:

```json
{
  "device_id": "meter-01",
  "mac": "02:42:0a:00:00:01",
  "ip": "10.0.0.10",
  "role": "smart_meter",
  "allowed_dst_ip": "10.0.0.1",
  "allowed_udp_port": 5555,
  "status": "authorized",
  "registered_at": "2026-05-02T00:00:00+00:00",
  "last_seen": "",
  "dpid": "",
  "in_port": ""
}
```

Para construir y publicar la imagen de la consola unificada:

```bash
docker build -t arturoalvarez/sdn-meter-collector:latest services/meter-collector
docker push arturoalvarez/sdn-meter-collector:latest
```

Para actualizar la consola web:

```bash
kubectl rollout restart daemonset/meter-collector -n sdn-controller
kubectl get svc meter-collector -n sdn-controller
```

La interfaz queda expuesta por el servicio `meter-collector` en el puerto `8081`. Desde la red del laboratorio, abre `http://192.168.122.10:8081` o la IP LoadBalancer de cualquier nodo disponible. La pestaña `Seguridad AMI` permite autorizar guests detectados por DHCP/Ryu, cambiar su estado o eliminarlos sin ejecutar `kubectl run` manualmente.

La consola muestra los guests observados desde Redis (`topology:guest_ips`, `mac_to_port:*`, `switch_ports:*`, `health:*`). Las MACs que corresponden a la MAC derivada del DPID de un nodo K3s se muestran como `worker` y se consideran permitidas automáticamente para no bloquear el plano de la arquitectura.

Si prefieres operar por terminal, puedes registrar tus propios guests autorizados con el CLI. Sustituye MAC, IP, DPID e `in_port` por los valores reales observados en tu laboratorio:

```bash
kubectl run security-registry-register -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py register \
  --device-id meter-lab-01 \
  --mac 02:42:0a:00:00:01 \
  --ip 10.0.0.10 \
  --role smart_meter \
  --allowed-dst-ip 10.0.0.1 \
  --allowed-udp-port 5555 \
  --status authorized \
  --dpid 1234 \
  --in-port 5
```

Comandos de prueba desde Kubernetes:

```bash
# Listar dispositivos registrados
kubectl run security-registry-list -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py list

# Consultar por MAC
kubectl run security-registry-mac -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py get-mac 02:42:0a:00:00:01

# Consultar por IP
kubectl run security-registry-ip -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py get-ip 10.0.0.10

# Cambiar un dispositivo a quarantined
kubectl run security-registry-quarantine -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py set-status meter-lab-01 quarantined

# Eliminar un dispositivo que no pertenece a la arquitectura
kubectl run security-registry-delete -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py delete meter-lab-01

# Validar la combinación observada por Ryu antes de instalar flujos
kubectl run security-registry-validate -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py validate \
  --mac 02:42:0a:00:00:01 --ip 10.0.0.10 --dpid 1234 --in-port 5
```

Ejemplo de salida esperada al listar:

```json
{
  "count": 1,
  "devices": [
    {
      "device_id": "meter-lab-01",
      "mac": "02:42:0a:00:00:01",
      "ip": "10.0.0.10",
      "status": "authorized"
    }
  ]
}
```

El subcomando `validate` ya prepara la integración con Ryu: recibe `mac`, `ip`, `dpid` e `in_port`, permite automáticamente workers cuya MAC coincide con la MAC derivada del DPID, comprueba que los guests existan, que su estado sea `authorized`, que la IP coincida y que `dpid`/`in_port` coincidan cuando estén fijados en el registro. Si `dpid` o `in_port` están vacíos en un guest registrado, se consideran no anclados todavía y no bloquean la validación.

### 13.2 Operaciones de mantenimiento

```bash
# Reiniciar el controlador RYU
kubectl rollout restart ds ryu -n sdn-controller

# Reiniciar Redis StatefulSet (⚠️ borra los datos en memoria)
kubectl rollout restart statefulset redis -n sdn-controller

# Seguir los logs en tiempo real
kubectl logs -f -l app=ryu -n sdn-controller --prefix

# Reiniciar el servidor DHCP
kubectl rollout restart ds sdn-dhcp-server -n sdn-controller

# Reiniciar observabilidad
kubectl rollout restart deploy/prometheus deploy/grafana -n sdn-controller
```

> Redis usa `emptyDir` en este entorno GNS3. Es intencional: evita que PVC/PV `local-path` queden pegados a nodos antiguos cuando se recrean Workers. Si ves `redis-0 Pending` con `didn't match PersistentVolume's node affinity`, recrea Redis y limpia PVCs antiguos.

### 13.2.1 Reset completo de la base de datos para pruebas

Usa este procedimiento cuando quieras limpiar completamente el estado runtime del laboratorio antes de repetir pruebas. Borra topología, aprendizaje MAC, leases DHCP, telemetría Smart Meter, estado HMAC, registro de seguridad, contadores y eventos. No borra manifiestos ni imágenes.

```bash
# Confirmar el master Redis actual vía Sentinel
kubectl exec redis-0 -c sentinel -n sdn-controller -- \
  redis-cli -p 26379 sentinel get-master-addr-by-name mymaster

# Reset completo de Redis. ⚠️ Borra todo el estado runtime del laboratorio.
kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli FLUSHALL

# Reiniciar servicios que reconstruyen estado desde OVS, DHCP, guests y Redis
kubectl rollout restart statefulset/redis -n sdn-controller
kubectl rollout restart daemonset/ryu -n sdn-controller
kubectl rollout restart daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout restart daemonset/meter-collector -n sdn-controller
kubectl rollout restart deployment/ryu-topology -n sdn-controller
kubectl rollout restart deployment/prometheus -n sdn-controller
kubectl rollout restart deployment/grafana -n sdn-controller

# Esperar convergencia
kubectl rollout status statefulset/redis -n sdn-controller
kubectl rollout status daemonset/ryu -n sdn-controller
kubectl rollout status daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout status daemonset/meter-collector -n sdn-controller
kubectl rollout status deployment/ryu-topology -n sdn-controller
kubectl rollout status deployment/prometheus -n sdn-controller
kubectl rollout status deployment/grafana -n sdn-controller
```

Después del reset, reinicia o recrea los guests Smart Meter en GNS3 para que pidan DHCP otra vez y vuelvan a poblar Redis. Si usas el registro de seguridad, vuelve a autorizar los guests desde `http://192.168.122.10:8081` antes de ejecutar pruebas de cuarentena/bloqueo.

### 13.3 Reinicio de todos los pods por servicio

Usa estos comandos para reiniciar cada servicio completo en el namespace `sdn-controller`.

```bash
# Controlador SDN y red de datos
kubectl rollout restart daemonset/ovs-sdn-initializer -n sdn-controller
kubectl rollout restart daemonset/ryu -n sdn-controller
kubectl rollout restart daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout restart deployment/ryu-topology -n sdn-controller

# Telemetría y observabilidad
kubectl rollout restart daemonset/meter-collector -n sdn-controller
kubectl rollout restart daemonset/node-exporter -n sdn-controller
kubectl rollout restart daemonset/promtail -n sdn-controller
kubectl rollout restart deployment/prometheus -n sdn-controller
kubectl rollout restart deployment/grafana -n sdn-controller
kubectl rollout restart deployment/loki -n sdn-controller

# Base de datos
kubectl rollout restart statefulset/redis -n sdn-controller

# Validar estado tras reinicios
kubectl get pods -n sdn-controller -o wide
```

Si quieres esperar a que cada servicio termine su rollout antes de pasar al siguiente, usa:

```bash
kubectl rollout status daemonset/ovs-sdn-initializer -n sdn-controller
kubectl rollout status daemonset/ryu -n sdn-controller
kubectl rollout status daemonset/sdn-dhcp-server -n sdn-controller
kubectl rollout status deployment/ryu-topology -n sdn-controller
kubectl rollout status daemonset/meter-collector -n sdn-controller
kubectl rollout status daemonset/node-exporter -n sdn-controller
kubectl rollout status daemonset/promtail -n sdn-controller
kubectl rollout status deployment/prometheus -n sdn-controller
kubectl rollout status deployment/grafana -n sdn-controller
kubectl rollout status deployment/loki -n sdn-controller
kubectl rollout status statefulset/redis -n sdn-controller
```

---

## 14. Verificación y monitoreo

### 14.1 Verificar nodos del cluster

```bash
kubectl get nodes -o wide
```

Comprueba que la IP interna de Kubernetes y la IP pública de Flannel coincidan en todos los nodos:

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" internal="}{.status.addresses[?(@.type=="InternalIP")].address}{" flannel="}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}{end}'
```

La salida correcta debe tener la misma IP en `internal=` y `flannel=` para cada nodo. Si un worker muestra valores distintos después de reiniciar GNS3, ese nodo fue registrado con una IP DHCP anterior y debe reunirse al cluster.

### 14.1.1 Prueba obligatoria de fallo del master

Esta prueba confirma que el cluster no depende del nodo `master` para operar.

1. Verifica quorum y distribución antes del fallo:

```bash
kubectl get nodes -o wide
kubectl -n kube-system get pods -o wide
kubectl get pods -n sdn-controller -o wide
```

2. Apaga el nodo `master` en GNS3.

3. Desde otro server control-plane, verifica que el API sigue respondiendo por el VIP:

```bash
kubectl get nodes
curl -k https://192.168.122.10:6443/readyz
```

4. Confirma servicios del proyecto:

```bash
kubectl get pods -n sdn-controller -o wide
curl http://192.168.122.10:8080/api/topology
curl http://192.168.122.10:8081/api/health
curl http://192.168.122.10:3000/api/health
```

Resultado esperado:

- `kubectl` sigue funcionando por `192.168.122.10`.
- Redis Sentinel mantiene o elige master.
- `ryu`, `sdn-dhcp-server`, `meter-collector` y `ovs-sdn-initializer` siguen activos en los nodos vivos.
- Los dashboards movibles se recrean en otro nodo si estaban en el nodo caído.

### 14.1.2 Recuperar workers con IP de Flannel cruzada

Si ya existen pods en `Unknown` por un reinicio anterior, primero corrige la Golden Image o cada worker con `dhcp-identifier: mac`. Luego recrea los workers afectados para que K3s y Flannel tomen la IP estable:

```bash
# Desde cualquier nodo con kubectl: identificar workers con IP cruzada
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" internal="}{.status.addresses[?(@.type=="InternalIP")].address}{" flannel="}{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}{end}'

# Por cada worker afectado, borrar el objeto Node.
# El worker se volverá a registrar al arrancar con DHCP estable.
kubectl delete node <worker-afectado>

# Limpiar pods huérfanos que quedaron en estado Unknown
kubectl delete pod -A --field-selector=status.phase=Unknown
```

En el worker afectado, si `k3s-agent` quedó instalado con una IP antigua, reinstala el agent después de corregir Netplan:

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
sudo systemctl enable --now k3s-autojoin.service
```

No borres ni cambies el `node-token` del cluster para esta recuperación. El punto crítico es que el worker vuelva a pedir la misma IP por DHCP en cada arranque.

### 14.2 Consultar Redis (Sentinel HA)

```bash
# Identificar el Master actual
kubectl exec redis-0 -c sentinel -n sdn-controller -- \
  redis-cli -p 26379 sentinel master mymaster | head -n 4

# Conectarse al Master para inspeccionar datos
POD_REDIS=$(kubectl get pods -l app=redis -n sdn-controller -o name | head -n 1)
kubectl exec -it $POD_REDIS -c redis -n sdn-controller -- redis-cli HGETALL topology:guest_ips
```

Comandos útiles dentro de `redis-cli`:

```redis
# Listar todas las claves almacenadas
KEYS *

# Ver los nodos registrados en la topología
HGETALL topology:node_names
HGETALL topology:node_ips

# Ver los switches conectados
SMEMBERS topology:switches

# Inspeccionar la tabla MAC de un switch (reemplaza el DPID)
HGETALL mac_to_port:77356373094209

# Ver últimas lecturas de medidores IoT
SMEMBERS meter:devices
HGETALL meter:latest:<device_id>
```

### 14.3 Verificar Alta Disponibilidad Redis

```bash
# Ver estado del StatefulSet (deben estar 3/3 Running)
kubectl get statefulset redis -n sdn-controller
kubectl get pods -l app=redis -n sdn-controller -o wide

# No deben existir PVCs Redis en esta guía basada en emptyDir
kubectl get pvc -n sdn-controller

# Simular caída del Master y verificar failover
kubectl delete pod redis-0 -n sdn-controller
# Esperar ~5s y consultar el nuevo master:
kubectl exec redis-1 -c sentinel -n sdn-controller -- \
  redis-cli -p 26379 sentinel master mymaster | grep -A1 'ip'
```

Si Redis queda bloqueado por PVCs de una instalación anterior:

```bash
kubectl delete statefulset redis -n sdn-controller
kubectl delete pod -l app=redis -n sdn-controller --ignore-not-found
kubectl delete pvc data-redis-0 data-redis-1 data-redis-2 -n sdn-controller --ignore-not-found
kubectl apply -f deploy/k8s/01-database.yaml
kubectl rollout status statefulset/redis -n sdn-controller
kubectl rollout restart ds/ovs-sdn-initializer ds/sdn-dhcp-server ds/ryu ds/ryu-topology -n sdn-controller
```

### 14.4 Logs del controlador RYU

```bash
kubectl logs -f -l app=ryu -n sdn-controller --prefix
```

### 14.5 Logs del servidor DHCP

```bash
kubectl logs -f -l app=sdn-dhcp -n sdn-controller
```

### 14.6 Dashboard de Telemetría (Smart Meters)

```bash
# Acceder al dashboard del colector de telemetría
curl http://192.168.122.10:8081/api/stats

# Ver lecturas en tiempo real desde el navegador
# http://192.168.122.10:8081
```

### 14.7 Observabilidad con Prometheus y Grafana

El stack de observabilidad queda incluido en `deploy/k8s/06-observability.yaml`:

- `node-exporter`: DaemonSet, un pod por nodo para CPU, memoria, filesystem y tráfico del host.
- `prometheus`: Deployment con 2 réplicas y retención local corta de 6h.
- `grafana`: Deployment con 2 réplicas, datasource Prometheus y dashboard SDN provisionados por ConfigMap.

```bash
# Verificar componentes
kubectl get pods -n sdn-controller -l app=node-exporter -o wide
kubectl get deploy prometheus grafana -n sdn-controller
kubectl get svc prometheus grafana -n sdn-controller

# Verificar que Ryu expone métricas desde cada nodo
curl http://localhost:8000/metrics | head

# Ver targets descubiertos por Prometheus
curl http://192.168.122.10:9090/api/v1/targets

# Acceso web
# Prometheus: http://192.168.122.10:9090
# Grafana:    http://192.168.122.10:3000
# Login:      admin / admin
```

Consultas útiles en Prometheus/Grafana:

```promql
# Packet-In por segundo por switch
sum by (dpid) (rate(ryu_packet_in_total[1m]))

# Cantidad de nodos activos reportados por Redis/Ryu
max(ryu_active_nodes)

# Flujos instalados por switch
max by (dpid) (ryu_installed_flows)

# Top 5 nodos con mas trafico de red
topk(5, sum by (node) (
  rate(node_network_receive_bytes_total{device!~"lo|cni.*|flannel.*|veth.*"}[1m]) +
  rate(node_network_transmit_bytes_total{device!~"lo|cni.*|flannel.*|veth.*"}[1m])
))

# CPU usada por nodo
100 - (avg by (node) (rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)

# Memoria usada por nodo
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100
```

El dashboard `SDN Observabilidad` también incluye un panel `Mapa SDN y camino entre guests` basado en el panel nativo `Node graph` de Grafana. Usa las variables superiores `Guest origen` y `Guest destino` para seleccionar dos guests; los enlaces del camino calculado por Ryu aparecen como enlaces adicionales de tipo `path`.

Los enlaces bloqueados por STP físico en `br0` se destacan en el mismo mapa como `br0 STP blocked`, en rojo y con mayor grosor. Para verificar el estado desde Prometheus:

```promql
count(max by (id, source, target, mainstat, secondarystat, color, strokeDasharray, thickness, type) (
  ryu_topology_edge_info{type="br0_stp_blocked"}
))
```

### 14.8 Verificar camino Smart Meter → Collector

Si el DHCP entrega IP pero no aparecen lecturas:

```bash
# En el Maestro: br-sdn debe tener la IP virtual del collector
ip -br addr show br-sdn
# Esperado: br-sdn UNKNOWN 10.0.0.1/24 ...

# El collector debe escuchar UDP 5555 en hostNetwork
ss -lunp | grep ':5555'

# Capturar tráfico real desde un nodo donde corra el guest o collector
sudo timeout 20 tcpdump -ni br-sdn 'arp or udp port 5555'

# Prueba sintética de telemetría hacia el collector
printf '{"device_id":"test-meter","timestamp":"2026-04-24T00:00:00Z","voltage_v":220,"current_a":1,"active_power_kw":0.22,"reactive_power_kvar":0.1,"power_factor":0.92,"energy_kwh":0.01,"seq":1}' \
  > /tmp/meter-test.json
bash -lc 'cat /tmp/meter-test.json > /dev/udp/10.0.0.1/5555'
curl http://192.168.122.10:8081/api/meters

# Limpiar dato de prueba
kubectl -n sdn-controller exec redis-0 -c redis -- redis-cli SREM meter:devices test-meter
kubectl -n sdn-controller exec redis-0 -c redis -- redis-cli DEL meter:latest:test-meter meter:history:test-meter
```

Para Smart Meters nuevos, usa la imagen/appliance actualizado o configura en GNS3:

```text
COLLECTOR_IP=10.0.0.1
COLLECTOR_PORT=5555
```

Si en `tcpdump` solo ves ARP pero no UDP `5555`, revisa que el DHCP tenga el fix anti-ARP-poisoning:

```bash
kubectl -n sdn-controller logs -l app=sdn-dhcp --tail=30 | grep 'Healthcheck ARP'
```

El pod DHCP del Maestro debe mostrar `psrc=10.0.0.1 en nodo=master`; los pods en Workers deben mostrar `psrc=0.0.0.0`. Si un Worker anuncia `psrc=10.0.0.1`, recrea el ConfigMap `dhcp-code` desde `services/dhcp-server/app.py` y reinicia `ds/sdn-dhcp-server`.

### 14.9 Trazar rutas en OVS (verificar caminos reales)

```bash
# Ejecutar en el worker de origen (reemplaza las MACs y puerto)
sudo ovs-appctl ofproto/trace br-sdn in_port=2,dl_src=<MAC_SRC>,dl_dst=<MAC_DST>

# Entrar al pod de OVS en un nodo específico
kubectl exec -it <ovs-pod-name> -n sdn-controller -- /bin/sh
```
