# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s · Open vSwitch · Redis · Docker  
> **Entorno:** Ubuntu (KVM/QEMU) · Red interna `192.168.122.0/24`

---

## Índice

### Parte I — Nodo Maestro
1. [Requisitos del Maestro](#1-requisitos-del-maestro)
2. [Actualizar sistema e instalar utilidades](#2-actualizar-sistema-e-instalar-utilidades)
3. [Instalación de Docker](#3-instalación-de-docker)
4. [Configuración de red del Maestro (IP fija)](#4-configuración-de-red-del-maestro-ip-fija)
5. [Instalación de K3s Servidor](#5-instalación-de-k3s-servidor)

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

# Parte I — Nodo Maestro

> ℹ️ **El Maestro se configura manualmente** — tiene IP fija y no es un clon. Ejecuta todos estos pasos directamente en su consola antes de arrancar ningún Worker.

---

## 1. Requisitos del Maestro

| Recurso | Mínimo |
|---|---|
| RAM | 2 GB |
| CPU | 2 hilos |
| Almacenamiento | 20 GB |
| Adaptadores de red | 6 (1 gestión + 5 puertos OVS) |

**Arquitectura de red del Maestro:**
- `ens3` → Gestión K3s con **IP fija `192.168.122.100`**, conectado al Cloud `virbr0` en GNS3.
- `ens4`–`ens8` → Puertos OVS para la topología SDN (sin IP, agrupados en `br0`).

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

## 4. Configuración de red del Maestro (IP fija)

### 4.1 Asignar hostname e IP estática

```bash
# 1. Hostname
sudo hostnamectl set-hostname master
echo "master" | sudo tee /etc/hostname
sudo sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 master" | sudo tee -a /etc/hosts

# 2. IP estática 192.168.122.100 en ens3
sudo bash -c 'cat > /etc/netplan/50-cloud-init.yaml << EOF
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      addresses:
        - 192.168.122.100/24
      routes:
        - to: default
          via: 192.168.122.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
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
      interfaces: [ens4, ens5, ens6, ens7, ens8]
      dhcp4: false
      parameters:
        stp: true
EOF'
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply

# Verificar
ip addr show ens3
```

### 4.2 Fix de systemd-networkd-wait-online

> ⚠️ **Problema conocido:** El Maestro también tiene `ens4`–`ens8` sin IP al boot (los gestiona OVS). `systemd-networkd-wait-online` espera que **todos** los interfaces estén configurados, bloqueando el arranque de K3s.

```bash
# Pasar con --any: basta con que UNA interfaz esté activa (ens3)
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

## 5. Instalación de K3s Servidor

### 5.1 Instalar K3s con token fijo

Usamos un token fijo para que coincida exactamente con el preconfigurado en los Workers:

```bash
K3S_TOKEN="K1001663fe573cc145f25d326dcb92f5f0f718e4a116e3719ca9cffc2167e2d95c6::server:ecce388f9096c175ca554b5cd38de3f9"

curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="--node-ip=192.168.122.100 --advertise-address=192.168.122.100 --bind-address=192.168.122.100 --flannel-iface=ens3" \
  K3S_TOKEN="${K3S_TOKEN}" \
  sh -
```

> ⚠️ **Nota sobre el token:** K3s valida el secreto completo. El token preconfigurado en los Workers debe coincidir exactamente con este valor.

### 5.2 Configurar kubectl

```bash
# Configurar kubectl para el usuario actual
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
source ~/.bashrc

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

# Verificar que el Maestro está activo
kubectl get nodes
```

---

# Parte II — Workers (Golden Image)

> ℹ️ **La Golden Image es una única VM base** que se clonará en GNS3 para crear infinitos Workers con un solo clic. Configura esta VM una sola vez, sélala y expórtala como `.qcow2`.

---

## 6. Preparación de la Golden Image (Plantilla Base)

Crea una VM nueva en tu hipervisor (QEMU/KVM) con los siguientes recursos:

| Recurso | Recomendado |
|---|---|
| RAM | 1 GB |
| CPU | 1 hilo |
| Almacenamiento | 10 GB |
| Adaptadores de red | 6 (1 gestión DHCP + 5 puertos OVS) |

**Arquitectura de red del Worker:**
- `ens3` → Gestión K3s con **IP dinámica DHCP** (`192.168.122.x`), conectado al Cloud `virbr0` en GNS3.
- `ens4`–`ens8` → Puertos OVS para la topología SDN (sin IP, gestionados por OVS).

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

### 9.1 Netplan con gestión DHCP y puertos OVS opcionales

```bash
sudo bash -c 'cat > /etc/netplan/50-cloud-init.yaml << EOF
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
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
      interfaces: [ens4, ens5, ens6, ens7, ens8]
      dhcp4: false
      parameters:
        stp: true
EOF'
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply
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

> ⚠️ **Problema conocido:** `systemd-networkd-wait-online` espera que **todos** los interfaces estén configurados. Los interfaces SDN (`ens4`+) no tienen IP al arrancar, lo que bloquea `k3s-agent`.

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

## 10. Instalación de K3s Agent (Auto-Join)

### 10.1 Script de autoconfiguración

Al arrancar un clon, este script: obtiene IP DHCP, genera hostname único, espera al Maestro y se une al cluster automáticamente.

```bash
sudo tee /usr/local/bin/k3s-autojoin.sh > /dev/null << 'SCRIPT'
#!/bin/bash
# k3s-autojoin.sh — Autoconfiguración de Worker K3s

# 1. Esperar IP de gestión en ens3 (192.168.122.x)
echo "[autojoin] Esperando IP de gestión en ens3..."
for i in $(seq 1 30); do
  MY_IP=$(ip addr show ens3 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  [ -n "$MY_IP" ] && break
  sleep 2
done

if [ -z "$MY_IP" ]; then
  echo "[autojoin] ERROR: No se obtuvo IP en ens3 tras 60s. Abortando."
  exit 1
fi
echo "[autojoin] IP obtenida: $MY_IP"

# 2. Generar hostname único basado en la MAC de ens3
MAC_ADDR=$(ip link show ens3 | awk '/ether/ {print $2}' | tr -d ':' | tail -c 5)
NEW_HOSTNAME="worker-${MAC_ADDR}"
hostnamectl set-hostname "$NEW_HOSTNAME"
echo "127.0.1.1 $NEW_HOSTNAME" >> /etc/hosts
echo "[autojoin] Hostname asignado: $NEW_HOSTNAME"

# 3. Esperar que el Maestro sea alcanzable
echo "[autojoin] Esperando al Maestro en 192.168.122.100..."
for i in $(seq 1 30); do
  ping -c1 -W2 192.168.122.100 > /dev/null 2>&1 && break
  sleep 3
done

# 4. Unirse al cluster K3s
curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="--node-ip=$MY_IP --flannel-iface=ens3" \
  K3S_URL=https://192.168.122.100:6443 \
  K3S_TOKEN=K1001663fe573cc145f25d326dcb92f5f0f718e4a116e3719ca9cffc2167e2d95c6::server:ecce388f9096c175ca554b5cd38de3f9 \
  sh -

# 5. Deshabilitar este servicio (solo corre una vez)
systemctl disable k3s-autojoin.service
echo "[autojoin] ¡Nodo $NEW_HOSTNAME unido exitosamente al cluster!"
SCRIPT

sudo chmod +x /usr/local/bin/k3s-autojoin.sh
```

### 10.2 Servicio systemd del Worker

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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable k3s-autojoin.service
```

### 10.3 Fix en caliente para Workers ya desplegados

Si `k3s-agent` falla en un Worker que ya está corriendo:

```bash
# Conectarse al worker
ssh ubuntu@<IP_DEL_WORKER>

# Aplicar override y reiniciar k3s-agent
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
sudo bash -c 'cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30
EOF'
sudo systemctl daemon-reload
sudo systemctl reset-failed systemd-networkd-wait-online.service
sudo systemctl restart k3s-agent.service

# Verificar estado
sudo systemctl status k3s-agent.service
```

Aplicar en **todos los workers en paralelo** desde el Maestro:

```bash
# Obtener IPs de workers
kubectl get nodes -o wide | grep -v master

# Aplicar fix masivo
for IP in <IP1> <IP2> <IP3>; do
  ssh ubuntu@$IP "sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/ && \
    echo -e '[Service]\nExecStart=\nExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=30' | \
    sudo tee /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf && \
    sudo systemctl daemon-reload && \
    sudo systemctl restart k3s-agent" &
done
wait && echo 'Fix aplicado en todos los workers'
```

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

```
┌─────────────────────────────────────────────────────────┐
│  GNS3 Canvas                                            │
│                                                         │
│  [SDN-Worker] ──── [SDN-Worker] ──── [SDN-Maestro]     │
│       ↑                  ↑                ↑             │
│  Arrastra y conecta cables (GNS3)    IP Fija            │
│                                  192.168.122.100        │
└─────────────────────────────────────────────────────────┘
```

1. **Arrastra** la Appliance `SDN-Worker` al canvas tantas veces como Workers necesites.
2. **Conecta los cables** según tu topología. Recuerda que `ens3` va al Cloud `virbr0`.
3. **Inicia primero el Maestro** y espera a que K3s esté activo.
4. Presiona **"Start All"** para los Workers.
5. En ~60 segundos cada Worker obtiene IP, genera hostname y se une al cluster.
6. Verifica en el Maestro:

```bash
kubectl get nodes
# Verás todos los workers con STATUS Ready
```

> ⚠️ **Requisito:** El Maestro debe estar operativo **antes** de iniciar los Workers.

---

## 13. Despliegue de RYU en K3s

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s

# Aplicar el manifiesto completo
kubectl apply -f k8s-sdn-deployment.yaml

# Verificar el estado de todos los recursos
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc
```

### 13.1 Operaciones de mantenimiento

```bash
# Reiniciar el controlador RYU
kubectl rollout restart ds ryu -n sdn-controller

# Reiniciar Redis StatefulSet (⚠️ borra los datos en memoria)
kubectl rollout restart statefulset redis -n sdn-controller

# Seguir los logs en tiempo real
kubectl logs -f -l app=ryu -n sdn-controller --prefix

# Reiniciar el servidor DHCP
kubectl rollout restart ds sdn-dhcp-server -n sdn-controller
```

---

## 14. Verificación y monitoreo

### 14.1 Verificar nodos del cluster

```bash
kubectl get nodes -o wide
```

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

# Simular caída del Master y verificar failover
kubectl delete pod redis-0 -n sdn-controller
# Esperar ~5s y consultar el nuevo master:
kubectl exec redis-1 -c sentinel -n sdn-controller -- \
  redis-cli -p 26379 sentinel master mymaster | grep -A1 'ip'
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
curl http://192.168.122.100:8081/api/stats

# Ver lecturas en tiempo real desde el navegador
# http://192.168.122.100:8081
```

### 14.7 Trazar rutas en OVS (verificar caminos reales)

```bash
# Ejecutar en el worker de origen (reemplaza las MACs y puerto)
sudo ovs-appctl ofproto/trace br-sdn in_port=2,dl_src=<MAC_SRC>,dl_dst=<MAC_DST>

# Entrar al pod de OVS en un nodo específico
kubectl exec -it <ovs-pod-name> -n sdn-controller -- /bin/sh
```