# Objetivos del Proyecto SDN-K8s (AMI)

Este documento define formalmente los objetivos, requisitos funcionales, limitaciones de diseño y escenarios de pruebas de caída que debe cumplir la arquitectura de red SDN distribuida sobre K3s y GNS3.

---

## 1. Filosofía del Proyecto

La filosofía central de este proyecto es la **automatización completa y la inteligencia de red**, garantizando en todo momento la **alta disponibilidad (HA)** y la **autorreparabilidad (self-healing)**. El sistema debe ser capaz de reaccionar de forma autónoma ante cambios físicos y lógicos en la topología, manteniendo los servicios operativos sin requerir intervención manual.

---

## 2. Observabilidad y Visualización

### 2.1 Mapeo de Métricas en Grafana
* **Objetivo**: Representar correctamente todas las métricas expuestas por los servicios del controlador SDN y los medidores inteligentes.
* **Métricas Clave**:
  * `ryu_packet_in_total` (filtrado por Datapath ID).
  * `ryu_active_nodes` y `ryu_active_switches`.
  * `ryu_installed_flows` por switch.
  * Tráfico de red: `ryu_port_rx_bytes_total` y `ryu_port_tx_bytes_total`.
  * Grafo de topología y caminos calculados expuestos mediante variables de Grafana (`src_guest`, `dst_guest`).

### 2.2 Web de Operaciones SDN AMI
La interfaz web de operaciones debe actuar como el centro de control del estado y la seguridad de la infraestructura AMI.
* **Telemetría AMI**: 
  * Mostrar exclusivamente los Smart Meters **activos y autorizados**.
  * Si un Smart Meter no está autorizado, no debe aparecer en la sección de telemetría activa.
* **Seguridad AMI**:
  * Mostrar todos los nodos worker activos en tiempo real.
  * Eliminar automáticamente los nodos worker de la sección de seguridad si desaparecen de la topología de red (limpieza de estado dinámico).
* **Gestión de Guest SDN**:
  * Mostrar de forma precisa el estado de todos los Smart Meters registrados en la base de datos.
  * Si un Smart Meter deja de tener presencia activa (no envía heartbeats o no está visible en el forwarding database de OVS/Ryu), su estado debe cambiar automáticamente a **"Registrados sin presencia activa"**.
* **Políticas de Acceso y Control de Telemetría**:
  * **Smart Meters en Cuarentena o Bloqueados**: No deben tener permitido enviar telemetría al sistema. El colector debe denegar sus paquetes de forma fail-closed.
  * **Nuevos Smart Meters**: Deben ingresar en un estado de espera de autorización. No podrán enviar telemetría ni ser considerados activos hasta que un operador los autorice en el registro de seguridad.
  * **Validación Criptográfica (Firma HMAC-SHA256)**: Cada lectura enviada por los Smart Meters debe validarse mediante una firma HMAC. Las lecturas con firmas inválidas o ausentes deben ser rechazadas y registradas para auditoría.
  * **Prevención de Ataques de Replay (Nonce)**: El colector de telemetría debe validar que el `nonce` enviado en cada lectura sea único, registrándolo en Redis (`meter:nonce:{device_id}:{nonce}`) para evitar que datos antiguos sean retransmitidos.

---

## 3. Topología SDN y Visualización de Caminos

El mapa de topología SDN es una representación gráfica fiel y dinámica del estado físico y lógico de la red.
* **Representación Fiel**:
  * Mostrar con precisión las conexiones de gestión de la infraestructura (`br0`) y de transporte de datos SDN (`br-sdn`) entre todos los nodos del clúster.
  * Los Smart Meters deben mostrarse conectados gráficamente a su respectivo nodo físico de origen (el nodo K3s donde está corriendo el switch OVS al que está conectado el dispositivo).
* **Visualización de Caminos Reales**:
  * Al seleccionar dos Smart Meters, la interfaz debe mostrar el **camino de red real** que toman los paquetes de datos.
  * Dicho camino debe ser el designado activamente por las reglas de flujo de Ryu y debe **iluminarse** en el mapa para facilitar el diagnóstico.
  * **Cálculo Basado en Dijkstra sobre Enlaces VXLAN**: El camino trazado e iluminado en la interfaz debe calcularse usando Dijkstra sobre el grafo de enlaces VXLAN y costos dinámicos en Redis (`topology:link_cost`), coincidiendo con Ryu. **No debe depender de la tabla de aprendizaje MAC local (`mac_to_port`)**, ya que el flood de L2 genera registros subóptimos o transitorios en la FDB.
* **Actualización Dinámica**:
  * El mapa de topología debe actualizarse de manera automática e instantánea ante cualquier cambio en el estado de los enlaces, switches o dispositivos.

---

## 4. Limitaciones y Diseño de la Arquitectura

Para asegurar la coherencia científica y práctica del laboratorio, la red debe ceñirse a las siguientes limitaciones de diseño:

1. **Túneles VXLAN Vecino a Vecino**:
   * Los túneles VXLAN en `br-sdn` deben establecerse **únicamente** entre vecinos físicos directos (descubiertos dinámicamente vía LLDP). No se permite un diseño de malla completa (full-mesh) VXLAN que conecte directamente nodos no adyacentes.
2. **Descubrimiento y Limpieza Dinámica OVS**:
   * El inicializador de Open vSwitch (`ovs-sdn-initializer`) debe descubrir los vecinos físicos dinámicamente mediante `lldpd` y la API de Kubernetes. Si un enlace con un vecino físico cae o desaparece, el inicializador debe eliminar de forma limpia la interfaz VXLAN correspondiente y purgar sus flujos asociados en OpenFlow (`ovs-ofctl del-flows ... out_port=...`) para evitar flujos huérfanos.
3. **Cálculo de Rutas vía Dijkstra**:
   * El controlador distribuido Ryu debe utilizar el algoritmo de **Dijkstra** para calcular el mejor camino (ruta con menor costo o saltos) entre dos Smart Meters en el plano de datos SDN.
4. **Control de Concurrencia en Ryu (Redis Locks)**:
   * Para evitar la instalación de flujos contradictorios o duplicados debido a ráfagas concurrentes de `Packet-In` (generadas por inundaciones de broadcast), Ryu debe utilizar bloqueos distribuidos en Redis (`lock:flow:{dpid}:{src}:{dst}`) al programar las reglas en los switches.
5. **Sin Spanning Tree Protocol (STP) en el Dataplane SDN**:
   * No se debe activar ni utilizar STP dentro de la red SDN (`br-sdn`) para evitar el bloqueo innecesario de caminos físicos en la topología (especialmente en topologías con anillos físicos redundantes).
6. **Control Inteligente de Bucles (L2 Loops)**:
   * En su lugar, el control de bucles a nivel de capa 2 (L2) se realizará de forma inteligente mediante la programación dinámica de flujos específicos (OpenFlow) y el cálculo de caminos de forwarding sin bucles por parte del controlador Ryu.
7. **Servicio DHCP Distribuido con Exclusión Mutua**:
   * El servidor DHCP basado en Scapy debe desplegarse como un DaemonSet escuchando en `br-sdn`. Para evitar que múltiples réplicas DHCP respondan a un mismo broadcast de cliente, deben coordinarse mediante un **bloqueo distribuido atómico** en Redis (`dhcp:lock:{mac}:{xid}:{type}`). Solo el servidor que adquiera el candado responderá al cliente.
8. **Healthchecks ARP No Contaminantes**:
   * El radar DHCP realiza pings ARP periódicos para actualizar la presencia de los medidores en Redis (`health:{mac}`). Para evitar contaminar las tablas ARP de los Smart Meters (ARP poisoning), el radar DHCP en los nodos worker debe realizar las peticiones con IP origen `psrc=0.0.0.0`; únicamente el pod maestro de DHCP (o el dueño de la IP virtual `10.0.0.1`) debe utilizar `psrc=10.0.0.1`.
9. **Conectividad de Prueba (Ping)**:
   * Los Smart Meters deben poder comunicarse directamente entre sí mediante protocolo ICMP (ping) para validar la correcta configuración del plano de datos.
10. **Cero Hardcoding (Diseño Dinámico)**:
    * No se permite hardcodear direcciones IP, nombres de nodos, identificadores GNS3 o relaciones de vecindad en los servicios. El sistema debe descubrir de forma totalmente dinámica el entorno a medida que los nodos se crean, destruyen o reconectan. Se permiten pequeñas excepciones configurables de bootstrapping en los planos de control si es estrictamente necesario para el clúster Kubernetes.

---

## 5. Matriz de Pruebas de Resiliencia y Caídas

El sistema debe superar satisfactoriamente las siguientes pruebas de interrupción de servicio, demostrando su capacidad de reconvergencia automática. Cada prueba de caída de enlace o nodo debe seleccionar previamente dos Smart Meters cuyo camino activo, confirmado por la Web de Operaciones SDN AMI o `/api/sdn-trace`, atraviese el enlace o nodo que se va a interrumpir. El criterio mínimo es que un ping continuo entre esos Smart Meters se detenga al producirse la caída y vuelva a funcionar automáticamente cuando Ryu recalcule e instale un camino alternativo; tras restaurar el elemento caído, el ping debe mantenerse operativo y la topología debe estabilizarse sin duplicados ni estado obsoleto.

| Escenario de Fallo | Comportamiento Esperado | Criterio de Aceptación |
| :--- | :--- | :--- |
| **Caída de enlace físico (cable)** | El tráfico se interrumpe momentáneamente. Ryu detecta la pérdida del enlace, recalcula la ruta óptima vía Dijkstra con los enlaces restantes y reinstala las reglas de flujo. | El ping continuo entre Smart Meters se restablece de forma automática por un camino alternativo. |
| **Recuperación de enlace físico** | Ryu detecta la reactivación del enlace físico a través de eventos OpenFlow/LLDP, recalcula el camino óptimo y actualiza los flujos si el nuevo enlace ofrece una ruta mejor. | Los flujos vuelven a la ruta preferencial sin pérdida de conectividad permanente. |
| **Apagado de un nodo Worker** | Ryu detecta la desconexión del switch. El estado del worker se limpia de la sección de seguridad. Los flujos se recalculan omitiendo el nodo caído. | Los Smart Meters en los nodos restantes siguen comunicándose normalmente. |
| **Encendido de un nodo Worker** | El worker se inicia, se une al cluster, arranca OVS y Ryu local, se auto-descubren sus vecinos y se establecen los túneles VXLAN. | El switch se integra a la topología y puede ser utilizado para encaminar tráfico nuevamente. |
| **Apagado de un Control Plane secundario** | Kubernetes reprograma los servicios que residían en él (DHCP, base de datos si aplica). Los Ryu controllers supervivientes asumen el control total de la red. | El clúster mantiene el quorum y el plano de datos sigue operativo de manera transparente. |
| **Encendido de un Control Plane secundario** | El nodo vuelve a unirse al cluster, recupera su rol de control y sincroniza el estado de la base de datos distribuida (Redis/Sentinel/etcd). | Los servicios vuelven a un estado balanceado de forma automática. |
| **Apagado del Master Principal** | Se pierde el nodo master primario. La infraestructura debe elegir un nuevo líder de clúster (Kubernetes/etcd) y promover una nueva réplica a Master en Redis Sentinel de forma automática. | Los servicios de control y telemetría siguen operando desde los otros control planes. |
| **Encendido del Master Principal** | El nodo Master se reincorporará al clúster, retoma sus funciones y se sincroniza con el estado actual de la red. | El clúster se estabiliza por completo sin duplicación de servicios ni conflictos de red. |
| **Apagado Completo (Blackout General)** | Simulación de corte de energía masivo. Todos los nodos se apagan. Al encenderse el laboratorio, los servicios deben arrancar de forma ordenada gracias a las dependencias de Kubernetes. | La red SDN se auto-construye desde cero, Redis Sentinel elige master, los medidores obtienen IP por DHCP y reanudan la telemetría automáticamente en un tiempo prudente. |
