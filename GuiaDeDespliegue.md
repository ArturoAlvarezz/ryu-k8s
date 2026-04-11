# Guía de Despliegue: RYU SDN Framework sobre K3s

> **Stack:** RYU Controller · K3s · Open vSwitch · Redis · Docker  
> **Entorno:** Ubuntu (KVM/QEMU) · Red interna `192.168.122.0/24`

---

## Índice

1. [Preparación de nodos](#1-preparación-de-nodos)
2. [Configuración de red (IP fija + bridge)](#2-configuración-de-red-ip-fija--bridge)
3. [Actualizar sistema e instalar utilidades](#3-actualizar-sistema-e-instalar-utilidades)
4. [Instalación de Docker](#4-instalación-de-docker)
4. [Instalación de Docker](#4-instalación-de-docker)
5. [Instalación de K3s](#5-instalación-de-k3s)
6. [Despliegue de RYU en K3s](#6-despliegue-de-ryu-en-k3s)
7. [Configuración de Open vSwitch (OVS)](#7-configuración-de-open-vswitch-ovs)
8. [Verificación y monitoreo](#8-verificación-y-monitoreo)

---

## 1. Preparación de nodos

Antes de comenzar, ajusta los recursos de cada VM desde el hipervisor (virt-manager, Proxmox, etc.) **antes de encender las máquinas**:

| Nodo               | RAM recomendada | CPU (hilos) | Almacenamiento | Adaptadores de red |
|--------------------|-----------------|-------------|----------------|--------------------|
| `nodo-k3s-maestro` | ≥ 2 GB          | ≥ 2         | ≥ 20 GB        | **5**              |
| `nodo-k3s-worker1` | ≥ 1 GB          | ≥ 1         | ≥ 10 GB        | **5**              |

> ℹ️ Los 5 adaptadores son necesarios para que el bridge `br0` tenga interfaces físicas suficientes. `ens3`–`ens5` se asignan al bridge; las restantes quedan disponibles para tráfico de gestión y K3s.

---

## 2. Configuración de red (IP fija + bridge)

> ⚠️ **Este paso debe realizarse antes de instalar cualquier paquete.** Sin la red configurada correctamente, las VMs no tendrán acceso a internet.  
> Asegúrate de que `ens3`, `ens4` y `ens5` sean las interfaces correctas en tu VM.  
> Los nodos de control SDN **no deben** estar sobre la red SDN gestionada.

### 2.1 Configurar Netplan con bridge `br0`

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

```yaml
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
  bridges:
    br0:
      interfaces: [ens3, ens4, ens5]
      parameters:
        stp: true
      addresses:
        - 192.168.122.103/24       # ← Ajusta la IP según el nodo
      routes:
        - to: default
          via: 192.168.122.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
```

### 2.2 Servicio systemd para regla de forwarding en `br0`

Crea el servicio para que la regla `iptables` persista entre reinicios:

```bash
sudo nano /etc/systemd/system/k3s-iptables.service
```

```ini
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
```

### 2.3 Aplicar la configuración

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now k3s-iptables.service
sudo netplan apply

# En el nodo maestro:
sudo hostnamectl set-hostname nodo-k3s-maestro

# En el nodo worker:
sudo hostnamectl set-hostname nodo-k3s-worker1

sudo reboot
```

---

## 3. Actualizar sistema e instalar utilidades

Con la red ya configurada y el sistema reiniciado, actualiza los paquetes y configura el hostname en **cada nodo**:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools
```

---

## 4. Instalación de Docker

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

# Agregar usuario al grupo docker (requiere cerrar sesión para aplicar)
sudo usermod -aG docker $USER

# Verificar instalación
sudo docker run hello-world
```

---

## 5. Instalación de K3s

### 5.1 Nodo maestro

```bash
curl -sfL https://get.k3s.io | sh -

# Obtener el token para unir workers
sudo cat /var/lib/rancher/k3s/server/node-token

# Configurar kubectl para el usuario actual
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
source ~/.bashrc

# Persistir kubeconfig en cada reinicio
sudo crontab -e
# Agrega esta línea:
# @reboot mkdir -p /home/ubuntu/.kube && cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config && chown ubuntu:ubuntu /home/ubuntu/.kube/config

# Verificar que el nodo esté activo
kubectl get nodes
```

### 5.2 Nodo worker

Reemplaza `<TOKEN>` con el token obtenido en el paso anterior:

```bash
curl -sfL https://get.k3s.io | \
  K3S_URL=https://192.168.122.100:6443 \
  K3S_TOKEN=<TOKEN> \
  sh -
```

---

## 6. Despliegue de RYU en K3s

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s

# Aplicar el manifiesto completo
kubectl apply -f k8s-sdn-deployment.yaml

# Verificar el estado de todos los recursos en el namespace
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc
```

### 6.1 Operaciones de mantenimiento

```bash
# Reiniciar el controlador RYU
kubectl rollout restart deployment ryu -n sdn-controller

# Reiniciar Redis (limpia el estado de la base de datos)
kubectl rollout restart deployment redis -n sdn-controller

# Seguir los logs en tiempo real
kubectl logs -f -l app=ryu -n sdn-controller --prefix

kubectl rollout restart ds sdn-dhcp-server -n sdn-controller

```

---

## 7. Verificación y monitoreo

### 7.1 Consultar Redis

```bash
kubectl exec -it deployment/redis -n sdn-controller -- redis-cli
# Detectamos el pod de base de datos y le consultamos la tabla completa:
POD_REDIS=$(kubectl get pods -l app=redis -n sdn-controller -o name | head -n 1)
kubectl exec -it $POD_REDIS -n sdn-controller -- redis-cli HGETALL topology:guest_ips

```

Comandos útiles dentro de `redis-cli`:

```redis
# Listar todas las claves almacenadas
KEYS *

# Ver los switches conectados a la topología
SMEMBERS topology:switches

# Inspeccionar la tabla MAC de un switch específico (reemplaza el DPID)
HGETALL mac_to_port:77356373094209
```

### 7.2 Logs del controlador RYU

```bash
kubectl logs -f -l app=ryu -n sdn-controller --prefix
```

### 7.3 Asignarle ip a un guest

```bash
ip addr add 10.0.0.5/24 dev eth0
```

---
