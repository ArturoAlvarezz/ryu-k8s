# Proyecto: Orchestrador SDN Distribuido sobre Kubernetes (K3s) con Ryu y OVS

> **Nota para el Agente de IA:** Este documento sirve como "Memoria Central" del proyecto. Contiene la arquitectura, flujos de datos, peculiaridades de diseño y lecciones aprendidas. Úsalo como contexto principal antes de agregar nuevas funcionalidades, modificar la red SDN o depurar código.

## 1. Visión General
El proyecto es una **Red Definida por Software (SDN) completamente distribuida**, diseñada para correr como microservicios dentro de un clúster de Kubernetes (K3s) virtualizado sobre GNS3.
Su objetivo es interceptar dinámicamente el tráfico de la red subyacente (física o de túneles VXLAN), aprender las direcciones MAC, instalar reglas de OpenFlow en los switches, y proveer servicios de red (como DHCP y Topología) de forma automática y resiliente, evitando puntos únicos de falla (SPOF).

## 2. Pila Tecnológica (Tech Stack)
- **Controlador SDN:** Ryu Framework (Python 3.9).
- **Data Plane (Switches):** Open vSwitch (OVS).
- **Orquestación y Despliegue:** Kubernetes (K3s ligero).
- **Almacenamiento de Estado (Base de Datos):** Redis + Redis Sentinel (Alta Disponibilidad).
- **Microservicios Python:** Flask (Web UI de Topología), Scapy (Servidor DHCP Nativo).
- **Protocolos Clave:** OpenFlow 1.3, VXLAN, LLDP, RSTP.

## 3. Arquitectura del Sistema
El sistema rompe el paradigma del "Controlador Centralizado". Aquí, el "Cerebro" está dividido en múltiples réplicas que comparten memoria.

### 3.1. Data Plane: OVS & `ovs-sdn-initializer` (DaemonSet)
- Corre en todos los nodos (Workers y Maestro).
- Un script de Bash continuo monitorea interfaces de red (`ens4` en adelante).
- Evita explícitamente añadir interfaces maestras (`br0`) al bridge SDN para **prevenir bucles de Capa 2** con la red de gestión de K3s.
- Establece túneles **VXLAN** dinámicamente detectando vecinos mediante LLDP.
- **Heartbeat:** Cada 10s envía un latido a Redis (`switch:alive:{DPID}`) con TTL de 30s.

### 3.2. Control Plane: Ryu Controller (DaemonSet)
- Corre en todos los nodos con `hostNetwork: true`. Escucha en `0.0.0.0:6653`.
- **Estrategia Localhost:** Cada switch OVS se conecta **solo a su Ryu local** (`127.0.0.1:6653`).
- Si un switch no sabe qué hacer con un paquete, hace `Packet-In` hacia su Ryu local.
- **Estado Distribuido:** Los Ryu no guardan variables en memoria RAM. Toda la tabla de aprendizaje (`mac_to_port`) se almacena en **Redis Sentinel**.
- **Bloqueos (Redis Locks):** Para evitar que dos controladores instalen reglas contradictorias al mismo tiempo cuando un Broadcast inunda la red, se usa un candado: `lock:flow:{dpid}:{src}:{dst}`.

### 3.3. Base de Datos: Redis StatefulSet
- Clúster Maestro/Esclavo manejado por Redis Sentinel (Puerto 26379).
- Claves principales:
  - `topology:switches`: Set con los DPIDs de switches activos (Decimal).
  - `topology:node_names`: Hash mapeando DPID Hexadecimal -> Nombre de Nodo.
  - `mac_to_port:{dpid}`: Hash con el ruteo local del switch.
  - `topology:guest_ips`: Hash mapeando MAC -> IP asignada por DHCP.

## 4. Microservicios Críticos

### 4.1. DHCP Server Distribuido (`dhcp-server/app.py`)
- Un DaemonSet que usa `scapy` para hacer *sniffing* en la interfaz `br-sdn` de cada host.
- **Peculiaridad de OpenFlow (¡Importante!):** Para que `scapy` pueda leer los Broadcasts (DHCPDISCOVER), Ryu debe inyectar una regla de OpenFlow explícita que envíe el tráfico `FLOOD` + `LOCAL` (`OFPP_LOCAL`). De lo contrario, los paquetes viajan por cables físicos pero no entran al Stack TCP/IP de Linux local.
- Asigna IPs en el rango `10.0.0.X` mediante un contador atómico en Redis (`dhcp:next_ip`).
- Realiza **Healthchecks L2** enviando paquetes ARP para validar que los Guests sigan vivos y elimina IPs obsoletas. Anti-ARP-poisoning: solo el pod DHCP del Maestro puede usar `psrc=10.0.0.1`; los Workers usan `psrc=0.0.0.0` para no desviar la telemetría destinada al collector del Maestro.

### 4.2. Smart Meter IoT (`smart-meter/app.py`) — **IMAGEN GUEST GNS3**
- Contenedor Alpine ligero (~80MB) que simula un Medidor Eléctrico Inteligente.
- Al arrancar, `entrypoint.sh` ejecuta `udhcpc -i eth0` para obtener IP via DHCP de la SDN.
- Genera telemetría sintética (voltaje, corriente, potencia activa/reactiva, energía acumulada) con ruido senoidal realista.
- Publica paquetes JSON via **UDP** cada N segundos (configurable con `REPORT_INTERVAL`, default 5s).
- Destino configurable: `COLLECTOR_IP` (default `10.0.0.1`, gateway/colector SDN en `br-sdn` del Maestro) + `COLLECTOR_PORT` (default 5555).
- **Appliance GNS3:** `smart-meter/smart-meter.gns3a` — importable directamente con DHCP activado.
- **Imagen Docker:** `arturoalvarez/sdn-smart-meter:latest`.

### 4.3. Colector de Telemetría (`meter-collector/app.py`) — **K8s Deployment**
- Microservicio doble: servidor UDP + API Flask + Web Dashboard.
- **UDP listener** en `:5555` — recibe lecturas JSON de todos los medidores de la VXLAN.
- **Persistencia:** almacena historial por dispositivo en Redis (`meter:history:{id}`, `meter:latest:{id}`, `meter:devices`).
- **Fallback:** si Redis no está disponible, opera en caché en memoria.
- **API REST:**
  - `GET /api/meters` — última lectura de todos los medidores.
  - `GET /api/meters/<id>/history?limit=N` — historial de un medidor.
  - `GET /api/stats` — estadísticas globales (potencia total, energía acumulada, dispositivos en línea).
  - `GET /api/health` — estado del servicio (usado por K8s livenessProbe).
- **Dashboard Web:** accesible en `http://localhost:8081` (puerto LoadBalancer K8s), actualización cada 5s.
- **Imagen Docker:** `arturoalvarez/sdn-meter-collector:latest`.
- **Claves Redis nuevas:**
  - `meter:devices`: Set con device_ids registrados.
  - `meter:history:{device_id}`: Lista de las últimas 100 lecturas JSON.
  - `meter:latest:{device_id}`: Hash con la lectura más reciente (TTL 5min).

### 4.4. Topología Web (`topology/app.py`)
- Aplicación Flask montada en K3s, con Frontend en `Vis.js`.
- Renderiza el grafo de la red leyendo de Redis.
- **Filtro de Fantasmas:** Valida que el DPID (formateado en Hexadecimal) posea un `switch:alive:{raw_dpid}` en Redis. Si no, purga el switch asumiendo que el nodo fue destruido abruptamente.

### 4.5. Observabilidad (`Prometheus`, `Grafana`, `node-exporter`)
- **Ryu expone `/metrics` en `:8000`:** no depende de librerías externas; sirve formato Prometheus desde el propio proceso del controlador.
- **Métricas SDN principales:**
  - `ryu_packet_in_total{dpid}`: contador de eventos Packet-In por switch. Grafana usa `rate(...[1m])` para mostrar Packet-In por segundo.
  - `ryu_active_nodes`: cantidad de nodos registrados en Redis (`topology:node_names`).
  - `ryu_active_switches`: cantidad de switches registrados en Redis (`topology:switches`).
  - `ryu_installed_flows{dpid}`: flujos OpenFlow instalados por switch, medidos con `OFPFlowStatsRequest`.
  - `ryu_port_rx_bytes_total` / `ryu_port_tx_bytes_total`: tráfico SDN por puerto OpenFlow.
- **node-exporter corre como DaemonSet:** hay un pod en cada nodo para CPU, memoria, filesystem y tráfico de interfaces del host.
- **Prometheus corre con 2 réplicas:** scrapes duplicados e independientes con `emptyDir` y retención corta de 6h. Esto evita SPOF en el laboratorio sin requerir storage distribuido.
- **Grafana corre con 2 réplicas:** dashboard y datasource provisionados por ConfigMap; si un pod cae, el Service balancea hacia el otro.
- **Mapa nativo en Grafana:** Ryu exporta `ryu_topology_node_info`, `ryu_topology_edge_info` y `ryu_trace_path_edge_info` para alimentar un panel nativo `Node graph`. El dashboard usa variables `src_guest` y `dst_guest` para resaltar el camino entre dos guests sin usar iframe ni la UI anterior de topología.
- **Servicios expuestos:**
  - Prometheus: `http://192.168.122.100:9090`
  - Grafana: `http://192.168.122.100:3000`
  - Dashboard preprovisionado: carpeta `SDN`, panel `SDN Observabilidad`.

## 5. Flujo de Trabajo y Operaciones (Comandos Útiles)

> **¡INSTRUCCIÓN CRÍTICA PARA EL AGENTE DE IA!**
> No puedes ejecutar comandos de `kubectl` o `docker` directamente en la terminal local, ya que el clúster corre dentro de una topología aislada de GNS3.
> Para interactuar con el clúster, **DEBES establecer una conexión SSH hacia el Nodo Maestro**.
> - **IP del Maestro:** `192.168.122.100`
> - **Usuario:** `ubuntu`
> - **Contraseña:** `ubuntu`
> 
> Puedes usar la librería `paramiko` en un script rápido de Python para inyectar comandos remotos (ej: `echo 'ubuntu' | sudo -S kubectl get pods -n sdn-controller`), o usar el script `ssh_k3s.py` que ya está en el directorio.

### 5.1. Hot Reloading (Modificando Código sin compilar Docker)
Los archivos de código `.py` no están quemados en las imágenes Docker. Se inyectan en vivo mediante **ConfigMaps**.
Para aplicar un cambio en `app.py` (Ryu) o en el Dashboard:
```bash
# 1. Recrear el ConfigMap desde los archivos fuente locales
kubectl create configmap ryu-code --from-file=app.py=app.py -n sdn-controller -o yaml --dry-run=client | kubectl replace -f -

# 2. Reiniciar el DaemonSet para absorber el nuevo código
kubectl rollout restart ds ryu -n sdn-controller
```

### 5.2. Herramientas de Depuración en el Clúster
- **Obtener IP del Redis Master:**
  ```bash
  MASTER_IP=$(kubectl exec redis-0 -c sentinel -n sdn-controller -- redis-cli -p 26379 sentinel get-master-addr-by-name mymaster | head -n 1)
  ```
- **Volcar Flujos (Flows) de OVS en un nodo específico:**
  ```bash
  # Requiere OpenFlow 1.3
  kubectl exec <ovs-pod> -n sdn-controller -- ovs-ofctl -O OpenFlow13 dump-flows br-sdn
  ```
- **Leer logs de paquetes de Ryu:**
  ```bash
  kubectl logs -n sdn-controller -l app=ryu --tail=200 | grep 'packet in'
  ```
- **Consultar la API de la App Web de Topología (vía cURL):**
  Como la app web de topología está expuesta como un `LoadBalancer` en K3s, puedes acceder a sus endpoints directamente desde el localhost del Nodo Maestro:
  ```bash
  # Obtener el JSON completo con los Nodos y Enlaces L2 activos de la SDN
  curl -s http://localhost:8080/api/topology
  ```

## 6. Siguientes Pasos Potenciales / Roadmap (Tareas Pendientes)

El siguiente listado de tareas representa las funcionalidades clave que restan para completar la memoria de título. Los agentes de IA deben usar este contexto para saber exactamente qué construir:

- [x] **Crear servicio para los Guests que simule un medidor IoT:**
  - *Completado:* `smart-meter/` — imagen Docker Alpine con DHCP (`udhcpc`) + publicador UDP de telemetría eléctrica sintética. Appliance GNS3 en `smart-meter/smart-meter.gns3a`. Colector K8s en `meter-collector/` con dashboard web en puerto 8081.

- [x] **Visualización del estado del Spanning Tree (RSTP) en el Dashboard:**
  - *Completado:* `ovs-sdn-initializer` lee `rstp_status` de OVS por puerto VXLAN y publica `topology:rstp_ports` en Redis. Ryu exporta esos estados en `ryu_topology_edge_info`; los enlaces con `Discarding:Alternate` aparecen en el panel nativo `Node graph` de Grafana como `RSTP blocked`, en rojo y punteado.

- [ ] **Visualización animada del flujo correcto de los datos:**
  - *Contexto:* La topología actual es estática. Se requiere consumir estadísticas de puertos (OpenFlow PortStats) o capturar los flujos desde el Controlador Ryu para animar los enlaces en la interfaz web (Vis.js). Esto permitirá demostrar visualmente el camino exacto que toman los paquetes (por ejemplo, los del medidor simulado) al viajar desde el origen hasta el destino a través de los túneles VXLAN.

- [ ] **Integrar capa de seguridad en la SDN (Microsegmentación/Firewalling):**
  - *Contexto:* Aprovechar el paradigma SDN para inyectar reglas de seguridad en los switches OVS vía el Controlador Ryu. Esto puede incluir protección contra MAC Spoofing, prevención de ARP Poisoning, o la creación de listas de control de acceso (ACLs) que aíslen el tráfico de ciertos Guests (medidores) de nodos no autorizados.

- [x] **Integración de Prometheus y Grafana (Observabilidad):**
  - *Completado:* `app.py` expone `/metrics` en puerto 8000 con métricas de Packet-In, nodos activos, switches activos, flujos instalados por switch y tráfico por puerto OpenFlow. `k8s-sdn-deployment.yaml` despliega Prometheus con 2 réplicas, Grafana con 2 réplicas y `node-exporter` como DaemonSet en todos los nodos. Grafana incluye un dashboard provisionado para tasas de Packet-In por segundo, nodos activos, flujos por switch, nodos con más tráfico, CPU y memoria por nodo.
