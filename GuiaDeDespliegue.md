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

| Recurso            | Mínimo                        |
| ------------------ | ----------------------------- |
| RAM                | 2 GB                          |
| CPU                | 2 hilos                       |
| Almacenamiento     | 20 GB                         |
| Adaptadores de red | 6 (1 gestión + 5 puertos OVS) |

**Arquitectura de red del Maestro:**

- `br0` → Bridge de gestión/fabric con **IP fija `192.168.122.100`**.
- `ens3` → Puerto del bridge `br0`, conectado al Cloud `virbr0` en GNS3.
- `ens4`–`ens6` → Puertos del bridge `br0` para extender la red `192.168.122.0/24` hacia Workers y permitir DHCP en cadena.
- `ens7`–`ens8` / `Ethernet4`–`Ethernet5` → Puertos reservados para Guests SDN, fuera de `br0`; el `ovs-sdn-initializer` los agrega a `br-sdn`.

> ⚠️ **Importante:** En este modo, K3s debe instalarse con `--flannel-iface=br0`, no con `ens3`. La IP vive en el bridge, por lo que `ens3` no tendrá IPv4 propia.

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

## 5. Instalación de K3s Servidor

### 5.1 Instalar K3s Servidor y guardar token real

```bash
curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="--node-ip=192.168.122.100 --advertise-address=192.168.122.100 --bind-address=192.168.122.100 --flannel-iface=br0" \
  sh -

# Guarda este token: se usará en el script de Auto-Join de los Workers
sudo cat /var/lib/rancher/k3s/server/node-token
```

### 5.2 Configurar kubectl

```bash
# Configurar kubectl para el usuario actual
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
source ~/.bashrc

# Confirmar que kubectl apunta al API Server del Maestro
grep 'server:' ~/.kube/config
# Debe mostrar: server: https://192.168.122.100:6443

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
kubectl get nodes -o wide
```

> Si `kubectl get nodes` devuelve `connection refused`, primero revisa `sudo systemctl status k3s` y `journalctl -u k3s -n 80`. En esta guía, ese error normalmente significa que el API Server está reiniciándose o que K3s fue instalado apuntando a la interfaz equivocada. En este modo debe decir `--flannel-iface=br0`.

---

# Parte II — Workers (Golden Image)

> ℹ️ **La Golden Image es una única VM base** que se clonará en GNS3 para crear infinitos Workers con un solo clic. Configura esta VM una sola vez, sélala y expórtala como `.qcow2`.

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

## 10. Instalación de K3s Agent (Auto-Join)

### 10.1 Script de autoconfiguración

Al arrancar un clon, este script: obtiene IP DHCP, genera hostname único, espera al Maestro y se une al cluster automáticamente.

Antes de crear el script, copia el token real desde el Maestro:

```bash
# Ejecutar en el Maestro
sudo cat /var/lib/rancher/k3s/server/node-token
```

Luego reemplaza `<TOKEN_REAL_DEL_MAESTRO>` en el script por ese valor. No reutilices tokens antiguos ni tokens de otra instalación de K3s.

```bash
sudo tee /usr/local/bin/k3s-autojoin.sh > /dev/null << 'SCRIPT'
#!/bin/bash
# k3s-autojoin.sh — Autoconfiguración de Worker K3s

K3S_NODE_TOKEN="K1008fc21ab5b1e9fb8b276fc97d9538b61b971389b23008986dc37c27efc1847bc::server:36d6a324fc1204f78e50a90cb295c193"
if [ -z "$K3S_NODE_TOKEN" ] || echo "$K3S_NODE_TOKEN" | grep -q '^<'; then
  echo "[autojoin] ERROR: Reemplaza el placeholder por el token real del Maestro."
  exit 1
fi

# 1. Esperar IP de gestión en br0 (192.168.122.x)
echo "[autojoin] Esperando IP de gestión en br0..."
for i in $(seq 1 30); do
  MY_IP=$(ip addr show br0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  [ -n "$MY_IP" ] && break
  sleep 2
done

if [ -z "$MY_IP" ]; then
  echo "[autojoin] ERROR: No se obtuvo IP en br0 tras 60s. Abortando."
  exit 1
fi
echo "[autojoin] IP obtenida: $MY_IP"

# 2. Generar hostname único basado en la MAC de br0
MAC_ADDR=$(ip link show br0 | awk '/ether/ {print $2}' | awk -F: '{print $4$5$6}')
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
  INSTALL_K3S_EXEC="--node-ip=$MY_IP --flannel-iface=br0" \
  K3S_URL=https://192.168.122.100:6443 \
  K3S_TOKEN="$K3S_NODE_TOKEN" \
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
2. **Conecta los cables** según tu topología. Recuerda que el Cloud `virbr0` debe llegar al Maestro, y desde ahí puedes encadenar Workers usando `ens3`–`ens6` porque forman parte de `br0`. Reserva `ens7`–`ens8` / `Ethernet4`–`Ethernet5` para Smart Meters u otros Guests SDN.
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

Ejecuta esta sección dentro del nodo `master`, después de confirmar que `kubectl get nodes -o wide` responde correctamente.

```bash
cd ~
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s

# Crear namespace antes de crear ConfigMaps
kubectl create namespace sdn-controller --dry-run=client -o yaml | kubectl apply -f -

# Crear/actualizar ConfigMaps requeridos por el manifiesto
kubectl create configmap ryu-code \
  --from-file=app.py=app.py \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap ryu-topology-code \
  --from-file=app.py=topology/app.py \
  --from-file=index.html=topology/templates/index.html \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap dhcp-code \
  --from-file=app.py=dhcp-server/app.py \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap meter-collector-code \
  --from-file=app.py=meter-collector/app.py \
  -n sdn-controller \
  --dry-run=client -o yaml | kubectl apply -f -

# Aplicar el manifiesto completo después de tener los ConfigMaps listos
kubectl apply -f k8s-sdn-deployment.yaml

# Verificar el estado de todos los recursos
kubectl get configmap -n sdn-controller
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc
```

Los ConfigMaps son obligatorios porque el manifiesto monta el código de Ryu, Topología, DHCP y Meter Collector desde Kubernetes. Si se omiten, los Pods pueden quedar en `CreateContainerConfigError` o no arrancar correctamente.

> El `meter-collector` corre con `hostNetwork` en el Maestro y escucha UDP `5555` directamente sobre la SDN. El `ovs-sdn-initializer` asigna `10.0.0.1/24` a `br-sdn` en el Maestro; los Smart Meters deben enviar telemetría a `COLLECTOR_IP=10.0.0.1`.
>
> Importante: `10.0.0.1` pertenece solo al Maestro. Los healthchecks ARP del DHCP usan `psrc=10.0.0.1` únicamente en el pod que corre sobre `master`; en Workers usan `psrc=0.0.0.0` para no envenenar la caché ARP de los Guests y desviar telemetría hacia otro nodo.

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

# Reiniciar observabilidad
kubectl rollout restart deploy/prometheus deploy/grafana -n sdn-controller
```

> Redis usa `emptyDir` en este entorno GNS3. Es intencional: evita que PVC/PV `local-path` queden pegados a nodos antiguos cuando se recrean Workers. Si ves `redis-0 Pending` con `didn't match PersistentVolume's node affinity`, recrea Redis y limpia PVCs antiguos.

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
kubectl apply -f k8s-sdn-deployment.yaml
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
curl http://192.168.122.100:8081/api/stats

# Ver lecturas en tiempo real desde el navegador
# http://192.168.122.100:8081
```

### 14.7 Observabilidad con Prometheus y Grafana

El stack de observabilidad queda incluido en `k8s-sdn-deployment.yaml`:

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
curl http://192.168.122.100:9090/api/v1/targets

# Acceso web
# Prometheus: http://192.168.122.100:9090
# Grafana:    http://192.168.122.100:3000
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

El dashboard `SDN Observabilidad` tambien incluye un panel `Mapa SDN y camino entre guests` basado en el panel nativo `Node graph` de Grafana. Usa las variables superiores `Guest origen` y `Guest destino` para seleccionar dos guests; los enlaces del camino calculado por Ryu aparecen como enlaces adicionales de tipo `path`.

### 14.8 Verificar camino Smart Meter → Collector

Si el DHCP entrega IP pero no aparecen lecturas:

```bash
# En el Maestro: br-sdn debe tener la IP virtual del collector
ip -br addr show br-sdn
# Esperado: br-sdn UNKNOWN 10.0.0.1/24 ...

# El collector debe escuchar UDP 5555 en hostNetwork
ss -lunp | grep ':5555'

# Capturar tráfico real desde el Maestro
sudo timeout 20 tcpdump -ni br-sdn 'arp or udp port 5555'

# Prueba sintética de telemetría hacia el collector
printf '{"device_id":"test-meter","timestamp":"2026-04-24T00:00:00Z","voltage_v":220,"current_a":1,"active_power_kw":0.22,"reactive_power_kvar":0.1,"power_factor":0.92,"energy_kwh":0.01,"seq":1}' \
  > /tmp/meter-test.json
bash -lc 'cat /tmp/meter-test.json > /dev/udp/10.0.0.1/5555'
curl http://192.168.122.100:8081/api/meters

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

El pod DHCP del Maestro debe mostrar `psrc=10.0.0.1 en nodo=master`; los pods en Workers deben mostrar `psrc=0.0.0.0`. Si un Worker anuncia `psrc=10.0.0.1`, recrea el ConfigMap `dhcp-code` desde `dhcp-server/app.py` y reinicia `ds/sdn-dhcp-server`.

### 14.9 Trazar rutas en OVS (verificar caminos reales)

```bash
# Ejecutar en el worker de origen (reemplaza las MACs y puerto)
sudo ovs-appctl ofproto/trace br-sdn in_port=2,dl_src=<MAC_SRC>,dl_dst=<MAC_DST>

# Entrar al pod de OVS en un nodo específico
kubectl exec -it <ovs-pod-name> -n sdn-controller -- /bin/sh
```
