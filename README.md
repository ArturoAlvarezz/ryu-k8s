# Controlador SDN Distribuido con Ryu y Redis en Kubernetes

Este repositorio contiene la implementación y los manifiestos de despliegue para una arquitectura de plano de control SDN (Software Defined Networking) resiliente y altamente disponible construida sobre **Ryu**, externalizando su estado en **Redis** y orquestada con **Kubernetes (K3s)**.

## 1. Explicación del Código (`services/ryu-controller/app.py`)

El diseño tradicional de controladores SDN monolíticos almacena el estado de la red (por ejemplo, el mapeo de MAC a puerto y los switches conectados) en la memoria RAM del proceso en ejecución. Para que el controlador pueda escalar horizontalmente (aumentar el número de réplicas en Kubernetes) sin perder consistencia, se ha refactorizado la aplicación Ryu para usar una base de datos externa compartida (Redis).

### Externalización de Estado
- **Conexiones de Switches (`EventOFPSwitchFeatures`)**: Cuando un nuevo switch se conecta a una instancia (réplica) del controlador, su identificador (`dpid`) se registra directamente en un Set global de Redis usando `self.redis.sadd('topology:switches', dpid)`. Esto permite que cualquier réplica pueda consultar en cualquier momento la lista global de switches activos.
- **Tabla de Aprendizaje MAC (`mac_to_port`)**: En lugar de usar un diccionario nativo de Python (`self.mac_to_port = {}`), se ha instanciado un HashMap de Redis por cada switch (por ejemplo, `mac_to_port:<dpid>`). Cuando un switch recibe un paquete y el controlador debe aprender la dirección MAC de origen, se guarda en la base compartida usando `self.redis.hset(mac_table_key, src, in_port)`. Las validaciones de despacho leen de esta clave mediante `hget`.

### Manejo de Concurrencia (Redis Locks)
En escenarios donde hay cientos de flujos y múltiples switches intentan validar una ruta, o un paquete de inundación (FLOOD) genera ráfagas de mensajes OpenFlow `Packet-In` en switches vecinos, diferentes réplicas del controlador podrían procesar el mismo evento y tratar de instalar reglas de red (`FlowMod`) en el mismo switch casi simultáneamente.
- **Bloqueo Distribuido (Lock)**: Para prevenir reglas contradictorias o duplicadas y el desperdicio de recursos, se ha implementado un sistema de Lock vía Redis antes de instalar una regla OpenFlow: `lock = self.redis.lock(lock_name)`.
- **Atomicidad**: La llave del bloqueo se compone de `lock:flow:<dpid>:<src_mac>:<dst_mac>`. Esto asegura que de múltiples réplicas que reciben solicitudes de rutas para el mismo par de origen-destino en el mismo switch, solo una adquiere el bloqueo y programa la regla de red, mientras que las demás descartarán o encolarán la petición (manejado por `lock.acquire()`).

---

## 2. Funcionamiento de la Arquitectura en Kubernetes

La aplicación dejó de ser un simple script sobre una terminal para convertirse en un clúster microservicios.

- **Despliegues (Deployments)**: 
  - Ryu cuenta con una configuración `replicas: 3`. K3s programará 3 Pods distintos (contenedores que corren la imagen Docker de Ryu).
  - Un Pod independiente de Redis almacena el estado global con persistencia ágil en memoria ram.
- **Resolución DNS Interna**: Las 3 réplicas descubren la base de datos automáticamente pidiendo conectarse al `REDIS_HOST` llamado `redis.sdn-controller.svc.cluster.local`, un alias inyectado por el Service de Kubernetes de Redis.
- **Balanceo y Conexión de Dataplane (OpenFlow)**: 
  - K3s utiliza un Service del tipo `LoadBalancer`. Expone dinámicamente el puerto OpenFlow estándar de capa inferior (`6633` y `6653`).
  - Cuando la capa inferior física (o Mininet/Open vSwitch) configura como controlador la IP del clúster K3s, los paquetes entrantes se distribuyen **equitativamente** entre cualquiera de los 3 Pods de Ryu operativos.
  - Al caerse un Pod accidentalmente, K3s recreará instantáneamente otro. Los switches que estaban conectados al controlador caído se reconectarán automáticamente al `LoadBalancer` cayendo en uno de los otros Pods vivos. Como los demás Pods ya ven el estado centralizado en Redis, los switches no notarán ninguna pérdida de metadatos o estado a nivel controlador global.

---

## 3. Cómo Desplegar en K3s

Sigue estos pasos desde cualquier nodo control-plane o estación con kubeconfig apuntando al VIP HA `https://10.255.255.1:6443`. Para reconstruir el cluster completo usa [docs/GuiaDeDespliegue.md](docs/GuiaDeDespliegue.md); esa guía es la fuente única para desplegar K3s HA y el stack SDN.

### Paso A: Compilar la Imagen Docker

Construye la imagen optimizada (definida en el `Dockerfile` de Python 3.9) utilizando la etiqueta que especificamos en el manifiesto (`arturoalvarez/ryu-controller:latest`).

```bash
cd /home/artulita/Documents/Memoria/ryu-k8s
docker build -t arturoalvarez/ryu-controller:latest services/ryu-controller
```

### Paso B: Importar la Imagen al Containerd de K3s

K3s no utiliza Docker daemon por defecto como runtime, sino `containerd`. Debes asegurarte de que K3s tenga acceso local a la imagen recién programada importándola (o empujándola a un Docker Hub y permitiendo que se descargue):

```bash
# Guardamos la imagen en un archivo temporal (.tar)
docker save -o ryu-controller.tar arturoalvarez/ryu-controller:latest

# Importamos a K3s Containerd (ctr)
sudo k3s ctr images import ryu-controller.tar
```
*(O simplemente deja que K3s la descargue de Docker Hub si ya la has subido).*

### Paso C: Aplicar los Manifiestos de Kubernetes

Inyecta toda la arquitectura SDN en tu clúster emitiendo el mandato sobre el archivo yaml:

```bash
kubectl apply -k deploy/k8s/
```

### Paso D: Validar el Despliegue

Verifica que el Namespace y los Pods se encuentren en estado `Running`:

```bash
kubectl get pods -n sdn-controller
```

Verifica tu balanceador de carga para comprobar la IP Externa (External-IP) por la que deberán conectarse los switches (tus topologías de Mininet/OVS deberán apuntar a esta IP para el Controller):

```bash
kubectl get svc -n sdn-controller
```

Para ver en tiempo real cómo tu controlador Ryu maneja las solicitudes OpenFlow, puedes revisar los logs combinados en cualquiera de las réplicas:

```bash
kubectl logs -f -l app=ryu -n sdn-controller
```

---

## 4. Registro de Dispositivos Autorizados SDN AMI

El registro mantiene en Redis la identidad de los medidores autorizados. La consola web ahora vive dentro de `services/meter-collector/` como parte del dashboard unificado `SDN AMI Operations`; el CLI Python se conserva en `services/security-device-registry/` para registrar, listar, consultar por MAC/IP, cambiar estado y validar la combinación observada por Ryu (`mac`, `ip`, `dpid`, `in_port`) antes de permitir flujos.

Claves Redis usadas:

- `security:devices`
- `security:device:{device_id}`
- `security:mac_to_device:{mac}`
- `security:ip_to_device:{ip}`

Construye y publica la imagen del dashboard unificado:

```bash
docker build -t arturoalvarez/sdn-meter-collector:latest services/meter-collector
docker push arturoalvarez/sdn-meter-collector:latest
kubectl apply -f deploy/k8s/05-telemetry.yaml
```

El registro queda vacío por defecto. La consola web se expone en el servicio `meter-collector` puerto `8081`, por ejemplo `http://192.168.122.100:8081` en el despliegue HA. Desde la pestaña `Seguridad AMI` puedes autorizar guests detectados por DHCP/Ryu, cambiar su estado o eliminarlos sin ejecutar `kubectl` manualmente. Los workers se destacan aparte y se permiten automáticamente porque pertenecen a la arquitectura.

Pruebas rápidas:

```bash
kubectl run security-registry-list -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py list

kubectl run security-registry-register -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py register \
  --device-id meter-lab-01 --mac 02:42:0a:00:00:01 --ip 10.0.0.10 \
  --role smart_meter --allowed-dst-ip 10.0.0.1 --allowed-udp-port 5555 \
  --status authorized --dpid 1234 --in-port 5

kubectl run security-registry-mac -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py get-mac 02:42:0a:00:00:01

kubectl run security-registry-ip -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py get-ip 10.0.0.10

kubectl run security-registry-quarantine -n sdn-controller --rm -i --restart=Never \
  --image=arturoalvarez/security-device-registry:latest --command -- python /app/registry.py set-status meter-lab-01 quarantined
```
