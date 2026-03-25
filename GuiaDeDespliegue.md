# Apuntes Configuración RYU SDN Framework

## Preparación de maquinas

### Configuración de maquina

- Aumentar RAM
- Aumentar hilos
- Aumentar almacenamiento

### Actualizar paquetes de las maquinas

sudo apt update && sudo apt upgrade -y
sudo apt install net-tools

### Cambiar hostname

sudo hostnamectl set-hostname nodo-k3s-maestro

Nodo-K3S-Maestro

### Configurar ip fija

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

Cambiar el archivo por:

```yaml
network:
  version: 2
  ethernets:
    ens3:
      match:
        macaddress: "0c:da:c3:c2:00:00"
      set-name: "ens3"
      dhcp4: false
      dhcp6: false
      addresses:
        - 192.168.122.100/24
      routes:
        - to: default
          via: 192.168.122.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
```

```bash
sudo netplan apply
sudo reboot
```

### Instalar paquetes Docker

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

sudo usermod -aG docker $USER

sudo docker run hello-world
```

### Instalar k3s

```bash
curl -sfL https://get.k3s.io | sh -
sudo cat /var/lib/rancher/k3s/server/node-token
hostname -I
sudo mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
export KUBECONFIG=~/.kube/config
kubectl get nodes
```

Para nodos agentes:

```bash
curl -sfL https://get.k3s.io | K3S_URL=https://192.168.122.100:6443 K3S_TOKEN=K10f828ee4224c68629b733e11867e91fc8edbb476ba75e1196880d373c149ed8d2::server:61732bf588da1d6c5c3d7e87e6c147e3 sh -
```

### Desplegar Ryu en K3S

```bash
git clone https://github.com/ArturoAlvarezz/ryu-k8s.git
cd ryu-k8s
kubectl apply -f k8s-sdn-deployment.yaml
kubectl get all -n sdn-controller
kubectl -n sdn-controller get pods -o wide
kubectl -n sdn-controller get svc

# Forzar el reinicio (limpieza) del motor de base de datos
kubectl rollout restart deployment redis -n sdn-controller

# Forzar el reinicio de las réplicas de Ryu
kubectl rollout restart deployment ryu -n sdn-controller

kubectl logs -f -l app=ryu -n sdn-controller

```

### Configurar OVS

La nodos de control sdn no pueden estar sobre una red sdn

```bash
ovs-vsctl show
ip addr flush dev eth0
ip addr add 192.168.122.53/24 dev br0
ip link set br0 up
ovs-vsctl set bridge br0 protocols=OpenFlow13
ovs-vsctl set-controller br0 tcp:192.168.122.100:6653
ovs-vsctl show
ovs-vsctl list controller
```

### Entrar en redis

```bash
kubectl exec -it deployment/redis -n sdn-controller -- redis-cli

# Ver los Switches Conectados
SMEMBERS topology:switches

# Ver las Tablas MAC (mac_to_port)

HGETALL mac_to_port:77356373094209

#Ver todo lo que hay guardado en Redis
KEYS *
```

### Probar Ryu

```bash
kubectl logs -f -l app=ryu -n sdn-controller --prefix
```
