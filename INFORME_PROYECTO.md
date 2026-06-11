# Informe del Proyecto: SDN Distribuida, Alta Disponibilidad y Recuperación Rápida

## 1. Propósito General del Proyecto

Este proyecto implementa una red SDN distribuida sobre un laboratorio virtualizado en GNS3, orquestada con K3s y diseñada con tres objetivos principales: distribución del plano de control, alta disponibilidad de los servicios críticos y recuperación rápida ante fallos de nodos, pods, enlaces o servicios auxiliares.

La solución no se limita a ejecutar un controlador SDN aislado. El resultado es una plataforma completa compuesta por controlador Ryu, Open vSwitch, Redis Sentinel, DHCP distribuido, descubrimiento de topología, telemetría de medidores inteligentes, observabilidad con Prometheus/Grafana/Loki y un módulo de seguridad para validar dispositivos AMI autorizados.

La arquitectura final se organiza en capas:

| Capa | Implementación |
| --- | --- |
| Laboratorio físico/virtual | GNS3 con máquinas QEMU/KVM y guests Docker |
| Orquestación | K3s sobre nodos Ubuntu |
| Plano de gestión | Bridge Linux `br0`, red `192.168.122.0/24`, Flannel sobre `br0` |
| Plano SDN | Open vSwitch `br-sdn`, red `10.0.0.0/24`, túneles VXLAN |
| Controlador SDN | Ryu en `DaemonSet`, un controlador local por nodo |
| Estado distribuido | Redis + Sentinel como backend compartido |
| Servicios SDN | DHCP, topología, telemetría, seguridad y observabilidad |
| Guests de prueba | Smart Meters y máquina atacante en GNS3 |

La decisión más importante del diseño fue evitar depender de un único controlador remoto. Cada nodo K3s ejecuta su propio controlador Ryu con `hostNetwork: true`, y el OVS local se conecta a `127.0.0.1:6653`. De esta forma, si un nodo pierde conectividad temporal con otros nodos, su dataplane local mantiene un controlador disponible. La coordinación global se resuelve mediante Redis Sentinel.

## 2. Selección del Controlador SDN

Para el controlador SDN se eligió Ryu. La elección se fundamenta en el tipo de proyecto: un laboratorio académico y experimental donde era necesario modificar el comportamiento del controlador, integrar estado externo en Redis, exponer métricas propias, implementar reglas de seguridad y desplegar todo dentro de Kubernetes con recursos reducidos.

Ryu es un framework SDN escrito en Python, orientado a OpenFlow y muy adecuado para prototipado avanzado. Permite intervenir directamente en eventos OpenFlow como `EventOFPSwitchFeatures`, `EventOFPPacketIn`, estadísticas de puertos, estadísticas de flujos y eventos de topología. Esa flexibilidad fue clave para implementar aprendizaje MAC distribuido, bloqueo de tráfico malicioso, respuesta ARP del gateway virtual, métricas Prometheus y cálculo de caminos.

Comparación de alternativas evaluadas:

| Controlador | Ventajas | Motivo para no elegirlo |
| --- | --- | --- |
| Ryu | Ligero, Python, fácil de modificar, integración directa con OpenFlow 1.3, simple de contenerizar | Fue elegido porque permite implementar rápido lógica propia y adaptarla a Redis/K3s/GNS3 |
| OpenDaylight | Plataforma SDN muy completa, modular, madura para entornos empresariales | Es más pesado, basado en Java/Karaf/OSGi, con mayor complejidad operativa para un laboratorio con K3s y VMs pequeñas |
| ONOS | Diseñado para control distribuido y alta disponibilidad a gran escala | Su modelo de cluster nativo era más complejo de operar que externalizar el estado en Redis para este caso de uso |
| Floodlight | Controlador OpenFlow clásico y relativamente simple | Está basado en Java y ofrece menos flexibilidad práctica para integrar rápidamente lógica Python, Scapy, Redis y métricas propias |

La decisión de usar Ryu no significa ignorar la alta disponibilidad. En lugar de depender de un cluster interno del controlador, se implementó una arquitectura distribuida alrededor de Ryu: un Ryu por nodo, estado compartido en Redis Sentinel y mecanismos de expiración, locks y reconstrucción de estado.

Esta estrategia encaja mejor con el objetivo del proyecto porque separa claramente responsabilidades. Ryu toma decisiones OpenFlow locales, Redis mantiene el contrato de estado global y Kubernetes se encarga de reiniciar o reubicar workloads cuando hay fallos.

## 3. Enfoque Distribuido y de Alta Disponibilidad

El diseño final prioriza la disponibilidad local del plano de control. En una arquitectura centralizada clásica, todos los switches OpenFlow dependen de una IP remota del controlador. Si esa instancia cae o si un enlace de gestión falla, el switch queda sin plano de control. En este proyecto, cada OVS se conecta al Ryu que corre en el mismo nodo mediante `tcp:127.0.0.1:6653`.

La arquitectura distribuida se apoya en las siguientes decisiones:

| Decisión | Justificación |
| --- | --- |
| Ryu como `DaemonSet` | Garantiza una instancia del controlador en cada nodo K3s |
| `hostNetwork: true` | Permite que Ryu escuche en la red del host y que OVS acceda a `127.0.0.1` |
| OVS local por nodo | Cada nodo controla su propio bridge SDN `br-sdn` |
| Redis Sentinel | Evita depender de un Redis único sin failover |
| Locks distribuidos | Previenen que varias instancias programen reglas contradictorias |
| TTLs y heartbeats | Eliminan nodos, guests y enlaces obsoletos sin intervención manual |
| Probes de Kubernetes | Detectan procesos colgados y fuerzan reinicio controlado |
| ConfigMaps para código | Permiten hot reload de servicios Python sin reconstruir imágenes completas |

Esta decisión reemplazó una etapa anterior del proyecto donde Ryu se planteaba como `Deployment` con varias réplicas detrás de un `LoadBalancer`. El historial de commits muestra la evolución hacia el diseño actual, especialmente en el cambio a `DaemonSet`, la eliminación de `hostPorts`, la conexión local de OVS a `127.0.0.1` y la migración de Redis simple a Redis Sentinel.

## 4. Virtualización en GNS3

GNS3 se utiliza como plataforma de laboratorio para emular una red física distribuida. La decisión de usar GNS3 permite crear, destruir y reconectar nodos de red de forma visual, simulando fallos de enlaces, apagado de nodos, incorporación de workers y conexión de dispositivos IoT a puertos concretos.

El entorno virtual se construye con máquinas QEMU/KVM para los nodos K3s y appliances Docker para los Smart Meters. Esto permite combinar dos niveles de virtualización: VMs completas para los nodos de infraestructura y contenedores ligeros para los dispositivos finales.

GNS3 aporta ventajas importantes para este proyecto:

| Necesidad del proyecto | Aporte de GNS3 |
| --- | --- |
| Probar topologías variables | Permite conectar workers en línea, estrella, anillo o combinaciones manuales |
| Simular fallos físicos | Basta con apagar nodos o desconectar enlaces del canvas |
| Separar puertos de gestión y puertos SDN | Cada VM puede tener varios adaptadores `virtio` |
| Probar guests reales | Los Smart Meters se conectan a puertos concretos de OVS |
| Validar seguridad | Se puede conectar una máquina atacante al segmento SDN |

El laboratorio utiliza una red de gestión `192.168.122.0/24`, conectada al cloud `virbr0`, y una red SDN independiente `10.0.0.0/24` construida sobre `br-sdn`. Esta separación es fundamental: `br0` pertenece al plano de gestión y fabric de K3s, mientras que `br-sdn` pertenece al plano de datos SDN. El proyecto evita mezclar ambos bridges para no crear bucles ni contaminar el tráfico de control con el tráfico de guests.

## 5. Tipos de Máquinas Virtuales y Guests

El proyecto usa varios tipos de nodos, cada uno con un rol específico dentro de la arquitectura.

| Tipo | Tecnología | Rol |
| --- | --- | --- |
| Nodo maestro | Ubuntu QEMU/KVM | Ejecuta K3s server, servicios anclados al master y acceso principal al laboratorio |
| Nodo worker | Ubuntu QEMU/KVM clonado desde Golden Image | Ejecuta K3s agent, OVS, Ryu local, DHCP, collector y dataplane SDN |
| Smart Meter | Appliance Docker en GNS3 | Simula un medidor eléctrico que pide DHCP y envía telemetría UDP firmada |
| Máquina atacante | Ubuntu QEMU | Genera tráfico malicioso para validar detección de MAC spoofing, IP spoofing y ARP poisoning |

El nodo maestro tiene IP fija `192.168.122.100` en `br0`. Esta IP actúa como punto estable para el API Server de K3s, para los servicios expuestos y para la conexión inicial de los workers.

Los workers se preparan mediante una Golden Image. La decisión de usar una Golden Image reduce el esfuerzo operativo: se configura una única VM base y luego se clona en GNS3 tantas veces como sea necesario. Cada clon obtiene IP por DHCP, genera un hostname único basado en la MAC de `br0` y se une automáticamente al cluster K3s mediante un servicio `systemd` de auto-join.

Los Smart Meters son contenedores Alpine/BusyBox en GNS3. Esta elección reduce consumo de CPU y memoria, y permite crear muchos medidores sin levantar VMs completas. Cada Smart Meter ejecuta `udhcpc` hasta obtener una dirección en la red SDN y luego inicia el simulador Python de telemetría.

La máquina atacante se implementa como Ubuntu QEMU porque Scapy y las pruebas de paquetes crudos requieren privilegios, paquetes de desarrollo y herramientas como `tcpdump`. Se usa para validar la seguridad del controlador en condiciones similares a una máquina real conectada a la red de acceso.

## 6. Diseño de Red: `br0` y `br-sdn`

El diseño separa estrictamente el plano de gestión del plano SDN.

| Bridge | Red | Uso |
| --- | --- | --- |
| `br0` | `192.168.122.0/24` | Gestión, K3s, Flannel, comunicación entre nodos, LLDP físico |
| `br-sdn` | `10.0.0.0/24` | Tráfico de guests, Smart Meters, DHCP SDN, telemetría AMI |

En el maestro, `br0` usa IP fija `192.168.122.100`. En los workers, `br0` usa DHCP y `dhcp-identifier: mac` para que cada clon mantenga una IP estable tras reinicios de GNS3. Esta decisión evita que K3s y Flannel queden con IPs cruzadas después de recrear nodos.

Los puertos `ens3` a `ens6` pertenecen al bridge `br0` y forman el fabric físico/virtual entre nodos. Los puertos `ens7`, `ens8` o equivalentes quedan libres para guests SDN y son agregados dinámicamente a `br-sdn` por el inicializador de OVS.

La red SDN usa `10.0.0.1/24` como gateway y punto local de colección. Un detalle importante es que `10.0.0.1` existe localmente en cada nodo sobre `br-sdn`. Ryu responde ARP por `10.0.0.1` usando una MAC derivada del DPID del nodo, lo que permite que un Smart Meter envíe telemetría al collector local de su mismo nodo sin depender de un collector remoto.

`br-sdn` usa la misma MAC que `br0`. Esta decisión evita inconsistencias entre el DPID, la MAC esperada por Ryu y la MAC aceptada por el kernel cuando se entrega tráfico al puerto local de OVS.

## 7. Orquestación con K3s

K3s fue elegido como distribución Kubernetes por ser ligera, simple de instalar y suficiente para orquestar un laboratorio distribuido con VMs pequeñas. Frente a Kubernetes completo, K3s reduce consumo de recursos y complejidad operacional, lo que es importante cuando los nodos corren dentro de GNS3/QEMU.

El cluster se instala con `--flannel-iface=br0`. Esta decisión es crítica porque la IP de gestión vive en `br0`, no en una interfaz física individual. Si K3s se enlazara a `ens3`, el API Server, Flannel o los workers podrían quedar usando una interfaz sin IP.

Los manifiestos se organizan por capas:

| Archivo | Responsabilidad |
| --- | --- |
| `00-namespace.yaml` | Namespace `sdn-controller` |
| `01-database.yaml` | Redis + Sentinel |
| `02-ryu-controller.yaml` | Ryu/OpenFlow |
| `03-sdn-network.yaml` | OVS, VXLAN y DHCP distribuido |
| `04-topology-dashboard.yaml` | Dashboard propio de topología |
| `05-telemetry.yaml` | Collector de Smart Meters |
| `06-observability.yaml` | Prometheus, Grafana, Loki, Promtail, Node Exporter |
| `07-security-registry.yaml` | Registro web/API de dispositivos autorizados |

Los servicios críticos por nodo se despliegan como `DaemonSet`: Ryu, OVS initializer, DHCP, meter collector, Promtail y Node Exporter. Esta decisión asegura presencia local en cada nodo y evita que un único pod central sea cuello de botella.

Los servicios de visualización y administración se fijan al master con `nodeSelector`. Esto simplifica el acceso desde la red del laboratorio y evita inconsistencias de provisión en dashboards como Grafana. No forman parte del dataplane crítico, por lo que pueden centralizarse sin comprometer el objetivo principal de control distribuido.

## 8. Controlador Ryu Implementado

El controlador principal está en `services/ryu-controller/app.py`. Implementa una aplicación Ryu llamada `DistributedL2Switch` con soporte OpenFlow 1.3.

Sus funciones principales son:

| Función | Implementación |
| --- | --- |
| Registro de switches | Guarda DPIDs en `topology:switches` |
| Aprendizaje MAC | Guarda `mac_to_port:{dpid}` en Redis |
| Instalación de flujos | Usa `OFPFlowMod` con locks distribuidos |
| Entrega local | Envía tráfico a `OFPP_LOCAL` cuando el destino es `10.0.0.1` |
| ARP gateway | Responde ARP por `10.0.0.1` desde Ryu |
| Seguridad | Detecta spoofing y poisoning, instala drops de cuarentena |
| Métricas | Expone `/metrics` en el puerto `8000` |
| Topología | Exporta nodos, enlaces y caminos a Prometheus |

El aprendizaje MAC no queda en memoria local del proceso. Cada entrada se guarda en Redis con claves como `mac_to_port:{dpid}`. Esto permite que el estado sobreviva a reinicios de una instancia Ryu y pueda ser consultado por otros servicios, como el dashboard de topología, el DHCP y el registro de seguridad.

Para evitar conflictos en entornos distribuidos, el controlador usa locks Redis antes de instalar reglas OpenFlow. La llave tiene el formato `lock:flow:{dpid}:{src}:{dst}`. Con esto, si varios eventos derivados del mismo flujo llegan casi al mismo tiempo, solo una instancia programa la regla y las demás evitan duplicar o contradecir la acción.

Los flujos reactivos de forwarding usan `FORWARDING_FLOW_IDLE_TIMEOUT=120`. Este valor reduce la latencia fria observada durante pruebas todos-contra-todos, porque evita que los flows expiren mientras se recorren varios pares de Smart Meters. La recuperación ante fallos no depende de esperar ese timeout: Ryu elimina activamente flows que apuntan a puertos VXLAN marcados como inactivos por los probes del inicializador.

Ryu también implementa medidas específicas para el laboratorio:

| Problema | Solución implementada |
| --- | --- |
| DHCP necesita ver broadcasts | El controlador inyecta una copia a `OFPP_LOCAL` |
| Tráfico al collector debe ser local | Paquetes IP con destino `10.0.0.1` salen por `OFPP_LOCAL` |
| VXLAN puede generar loops de flood | No se reenvía flood de un puerto VXLAN a otro puerto VXLAN |
| Guests obsoletos ensucian la topología | Se usan TTLs `active_mac:*`, `health:*` y limpieza de Redis |
| Workers pueden parecer guests | Se detectan MACs derivadas de DPIDs y se auto-permiten |

La elección de implementar estas funciones en Ryu se justifica porque el proyecto necesitaba comportamiento a medida, especialmente alrededor de DHCP distribuido, local gateway, métricas y seguridad. Un controlador más pesado habría requerido adaptar plugins o módulos complejos, mientras que en Ryu la lógica se implementa directamente en Python.

## 9. Open vSwitch y VXLAN Dinámico

Cada nodo K3s ejecuta Open vSwitch y mantiene un bridge `br-sdn`. Este bridge representa el switch SDN local del nodo y es controlado por Ryu mediante OpenFlow 1.3.

El componente `ovs-sdn-initializer`, definido en `deploy/k8s/03-sdn-network.yaml`, corre como `DaemonSet` privilegiado con `hostNetwork` y `hostPID`. Su función es preparar el dataplane del host.

Acciones principales del inicializador:

| Acción | Detalle |
| --- | --- |
| Instalar dependencias | Instala OVS, `lldpd`, herramientas IP y Redis CLI |
| Crear `br-sdn` | Borra estado anterior y recrea el bridge SDN |
| Fijar DPID | Deriva el DPID desde la MAC de `br0` |
| Fijar MAC | Hace que `br-sdn` use la misma MAC que `br0` |
| Asignar gateway | Configura `10.0.0.1/24` en `br-sdn` |
| Conectar controlador | Configura `tcp:127.0.0.1:6653` |
| Crear túneles | Usa LLDP para descubrir vecinos y crear VXLAN |
| Agregar guests | Añade interfaces `ens*` libres a `br-sdn` |
| Publicar heartbeats | Escribe `switch:alive:{dpid}` con TTL |

La creación de VXLAN es dinámica. El inicializador observa vecinos LLDP en la red de gestión y crea puertos VXLAN con nombres derivados de la IP remota, por ejemplo `vx192168122101`. Si un vecino desaparece, el sistema acumula misses y elimina el túnel obsoleto después de varios ciclos.

Esta decisión evita hardcodear la topología. El usuario puede modificar cables en GNS3, y el sistema reconstruye los túneles según los vecinos observados. Es una decisión coherente con el objetivo de recuperación rápida, porque reduce la intervención manual tras cambios físicos o reinicios.

El historial de commits muestra que el diseño pasó por varias etapas: VXLAN fijo, topología en anillo, RSTP experimental, inferencia por MAC learning y finalmente VXLAN dinámico vía Redis/LLDP sin mover las interfaces de gestión. Esa evolución llevó a la separación actual entre `br0` y `br-sdn`, que es más estable para K3s.

## 10. Redis Sentinel como Estado Compartido

Redis es el contrato runtime del sistema. Se utiliza para almacenar topología, aprendizaje MAC, leases DHCP, ubicación de guests, estado de seguridad, telemetría y métricas derivadas.

El despliegue actual usa un `StatefulSet` con tres réplicas Redis y Sentinel. Sentinel monitoriza el master `mymaster`, detecta caída con `down-after-milliseconds` bajo y ejecuta failover. Los pods tienen anti-affinity para distribuirse por nodos cuando el cluster lo permite.

Claves relevantes:

| Grupo | Claves principales |
| --- | --- |
| Topología | `topology:switches`, `topology:node_names`, `topology:node_ips`, `topology:links` |
| Puertos | `switch_ports:{dpid}` |
| Aprendizaje MAC | `mac_to_port:{dpid}`, `active_mac:{dpid}:{mac}` |
| Guests | `topology:guest_ips`, `topology:guest_locations`, `health:{mac}` |
| DHCP | `dhcp:next_ip`, `dhcp:bind:{mac}`, `dhcp:lock:{mac}:{xid}:{msg_type}` |
| Seguridad | `security:devices`, `security:device:{device_id}`, `security:mac_to_device:{mac}`, `security:ip_to_device:{ip}` |
| Telemetría | `meter:devices`, `meter:history:{device_id}`, `meter:latest:{device_id}` |
| HMAC | `meter:hmac:*`, `meter:nonce:{device_id}:{nonce}` |

Se eligió Redis porque ofrece estructuras simples y eficientes para este caso: sets, hashes, contadores, listas, TTLs y locks. Además, la integración desde Python es directa para Ryu, Flask y Scapy.

En el despliegue actual Redis usa PVCs persistentes `data-redis-0`, `data-redis-1` y `data-redis-2` con `local-path`. Esta decisión evita perder estado por reinicios de pod y permite validar failover de Sentinel sin vaciar la base de datos runtime. Para producción, el equivalente debería usar almacenamiento persistente con política clara de backup, anti-affinity reforzada y recuperación documentada ante pérdida de nodo físico.

## 11. DHCP Distribuido

El servicio DHCP está en `services/dhcp-server/app.py` y se despliega como `DaemonSet`. Cada nodo ejecuta una instancia local que escucha en interfaces de guests o en `br-sdn` usando Scapy.

El reto principal es que, por VXLAN, varios pods DHCP pueden recibir el mismo broadcast. Para evitar respuestas duplicadas, el servicio usa locks atómicos en Redis con `SET NX EX`. La llave incluye MAC, transaction ID y tipo de mensaje DHCP. El primer pod que adquiere el lock responde, y los demás descartan el evento.

El DHCP asigna direcciones en `10.0.0.x` y registra el resultado en Redis:

| Dato | Clave |
| --- | --- |
| Lease por MAC | `dhcp:bind:{mac}` |
| Siguiente IP | `dhcp:next_ip` |
| IP visible en topología | `topology:guest_ips` |
| Ubicación del guest | `topology:guest_locations` |

El servicio responde de tres maneras para mejorar compatibilidad con guests GNS3: broadcast por `br-sdn`, copia unicast L2 dirigida a la MAC cliente y copia directa por la interfaz física local cuando se identifica el puerto del guest. Esta mejora aparece en commits relacionados con respuestas unicast y respuestas por puertos locales.

También ejecuta healthchecks ARP periódicos para determinar si un guest sigue vivo. Para evitar envenenar caches ARP, los workers usan `psrc=0.0.0.0` en lugar de anunciarse como `10.0.0.1`. Ryu es el único responsable de responder ARP por el gateway virtual.

Esta decisión mejora la frescura de la topología: si un guest deja de responder, se elimina de `mac_to_port` y `topology:guest_ips`, evitando que dashboards y métricas muestren nodos fantasmas.

## 12. Visualización de Topología

La visualización de topología se implementa en dos niveles: un dashboard web propio y un dashboard Grafana basado en métricas Prometheus.

El dashboard propio está en `services/topology-dashboard/app.py`. Expone `/api/topology` y `/api/trace/<src_guest>/<dst_guest>`. Lee Redis para construir nodos, enlaces, guests e información de caminos.

La API construye la vista a partir de:

| Información | Fuente Redis |
| --- | --- |
| Switches activos | `topology:switches` y `switch:alive:*` |
| Nombres de nodos | `topology:node_names` |
| IPs de nodos | `topology:node_ips` |
| Puertos OVS | `switch_ports:{dpid}` |
| Guests | `mac_to_port:{dpid}`, `topology:guest_ips`, `health:{mac}` |
| Enlaces VXLAN | Nombres de puertos `vx*` cruzados con IPs de nodos |

El dashboard evita mostrar nodos desconectados mediante heartbeats. Si un switch no tiene `switch:alive:{dpid}`, se limpia su estado asociado. Esto mantiene la visualización coherente tras fallos y reinicios.

Grafana complementa esta vista con un panel Node graph nativo. Ryu exporta métricas `ryu_topology_node_info`, `ryu_topology_edge_info` y `ryu_trace_path_edge_info`, que Grafana consulta para mostrar el mapa SDN y resaltar caminos entre dos guests seleccionados.

La decisión de usar Grafana para la vista operacional se fundamenta en que permite unir topología, métricas, logs y eventos de seguridad en un mismo lugar. El dashboard propio queda como herramienta directa de depuración basada en Redis, mientras Grafana queda como observabilidad integrada.

## 13. Smart Meters y Telemetría AMI

El proyecto incluye una simulación de medidores inteligentes. El servicio `services/smart-meter/app.py` genera lecturas sintéticas de voltaje, corriente, potencia activa, potencia reactiva, factor de potencia y energía acumulada.

Cada Smart Meter:

| Característica | Implementación |
| --- | --- |
| Obtención de IP | `udhcpc` en `entrypoint.sh` |
| Reintento de DHCP | Bucle infinito hasta obtener lease |
| Destino por defecto | `10.0.0.1:5555` |
| Protocolo | UDP |
| Seguridad | Firma HMAC-SHA256 |
| Anti-replay | Campo `nonce` único por lectura |
| Identidad | `DEVICE_ID` o hostname |

El appliance `smart-meter.gns3a` permite arrastrar el medidor al canvas de GNS3 y conectarlo al puerto SDN de un nodo. Al iniciar, el contenedor levanta `eth0`, pide DHCP y luego comienza a enviar telemetría.

La elección de enviar a `10.0.0.1` es deliberada. Cada nodo tiene un collector local escuchando en esa IP sobre `br-sdn`. Esto evita que todos los medidores dependan de un único collector central y reduce la latencia y el tráfico entre nodos.

## 14. Meter Collector Distribuido

El collector está en `services/meter-collector/app.py` y se despliega como `DaemonSet` con `hostNetwork`. Escucha UDP `5555` para telemetría y HTTP `5000` para API, dashboard y métricas.

Funciones principales:

| Función | Detalle |
| --- | --- |
| Recepción UDP | Escucha en `0.0.0.0:5555` |
| Validación HMAC | Verifica firma con secreto global, secretos por dispositivo o Redis |
| Anti-replay | Usa nonces con TTL en Redis |
| Tolerancia a Redis | Mantiene caché en memoria si Redis no está disponible |
| Persistencia runtime | Guarda última lectura e historial en Redis |
| API | Expone `/api/meters`, `/api/stats`, `/api/meters/<id>/history` |
| Métricas | Expone `/metrics` para Prometheus |

Las lecturas se almacenan en `meter:latest:{device_id}` y `meter:history:{device_id}`. La última lectura tiene TTL, por lo que un medidor que deja de reportar desaparece automáticamente de la vista de activos.

El collector también consulta el registro de seguridad. Si la IP de origen pertenece a un dispositivo bloqueado o en cuarentena, oculta o descarta su telemetría. Esto conecta la seguridad del plano SDN con la seguridad de la capa de aplicación AMI.

## 15. Registro de Dispositivos y Seguridad SDN

El módulo `services/security-device-registry/` implementa una fuente de identidad para dispositivos AMI autorizados. Tiene dos interfaces: un CLI (`registry.py`) y una consola web/API (`web.py`).

El registro guarda cada dispositivo con campos como `device_id`, `mac`, `ip`, `role`, `allowed_dst_ip`, `allowed_udp_port`, `status`, `dpid` e `in_port`.

Estados soportados:

| Estado | Significado |
| --- | --- |
| `authorized` | El dispositivo está permitido |
| `blocked` | El dispositivo está bloqueado administrativamente |
| `quarantined` | El dispositivo fue aislado por seguridad |

El controlador Ryu usa este registro para validar tráfico observado. Detecta:

| Amenaza | Condición detectada |
| --- | --- |
| MAC spoofing | MAC no registrada enviando telemetría o MAC observada en DPID/puerto incorrecto |
| IP spoofing | IP de origen distinta a la registrada, IP usada por otro dispositivo o uso de `10.0.0.1` |
| ARP poisoning | ARP anunciando `10.0.0.1`, mismatch entre MAC Ethernet y ARP, o IP ARP distinta a la registrada |

Cuando detecta una amenaza, Ryu registra un evento en Redis, incrementa contadores y, si no está en modo aprendizaje, instala un drop flow de prioridad alta para bloquear el tráfico del guest. Un hilo de sincronización revisa periódicamente dispositivos en cuarentena, bloqueados o reautorizados para instalar o eliminar reglas de drop.

Los workers se auto-permiten si su MAC corresponde a una MAC derivada de DPID. Esta excepción es necesaria porque los nodos de infraestructura generan tráfico legítimo que no debe tratarse como dispositivo AMI.

El proyecto incluye una guía y un script de pruebas con Scapy para simular MAC spoofing, IP spoofing y ARP poisoning desde una máquina atacante Ubuntu conectada a la red SDN. Esto permite validar que los eventos aparecen en logs, Grafana y el registro de seguridad.

## 16. Observabilidad

La observabilidad se implementa con Prometheus, Grafana, Loki, Promtail y Node Exporter.

Prometheus scrapea directamente Ryu mediante anotaciones de pod. Ryu expone `/metrics` sin sidecar, lo que simplifica el despliegue y reduce consumo. También scrapea Node Exporter para métricas del host y el collector para métricas de telemetría/HMAC.

Métricas principales:

| Métrica | Uso |
| --- | --- |
| `ryu_packet_in_total` | Volumen de eventos Packet-In por switch |
| `ryu_active_nodes` | Cantidad de nodos activos según heartbeats |
| `ryu_active_switches` | Cantidad de switches activos |
| `ryu_installed_flows` | Flujos instalados por switch |
| `ryu_port_rx_bytes_total` | Tráfico recibido por puerto OpenFlow |
| `ryu_port_tx_bytes_total` | Tráfico transmitido por puerto OpenFlow |
| `ryu_topology_node_info` | Nodos para el Node graph de Grafana |
| `ryu_topology_edge_info` | Enlaces para el Node graph de Grafana |
| `ryu_security_events_total` | Eventos de seguridad detectados |
| `meter_hmac_accepted_total` | Paquetes AMI válidos |
| `meter_hmac_invalid_total` | Paquetes AMI rechazados |

Grafana incluye un dashboard `SDN Observabilidad` con mapa de red, camino entre guests, Packet-In por segundo, nodos activos, switches activos, flujos instalados, tráfico por puerto, CPU, memoria, logs de Ryu, eventos de seguridad, validación HMAC y potencia reportada por Smart Meters.

Loki y Promtail centralizan logs de Ryu. Esto facilita correlacionar eventos de seguridad con cambios de topología, reconexiones OpenFlow o fallos de servicios.

## 17. Recuperación Rápida ante Fallos

El proyecto incorpora varios mecanismos de recuperación automática.

| Fallo | Mecanismo de recuperación |
| --- | --- |
| Caída de un pod Ryu | Kubernetes reinicia el pod del `DaemonSet`; OVS reconecta al Ryu local |
| Reinicio de nodo | `ovs-sdn-initializer` reconstruye `br-sdn`, VXLAN, controller y heartbeats |
| Cambio de enlaces GNS3 | LLDP detecta vecinos y crea/elimina túneles VXLAN |
| Redis master caído | Sentinel elige nuevo master y los servicios consultan Sentinel |
| DHCP todavía no disponible | Smart Meter reintenta `udhcpc` indefinidamente |
| Guest desconectado | Healthcheck ARP expira `health:{mac}` y se limpia la topología |
| Topología stale | TTLs en `active_mac:*`, `switch:alive:*` y `meter:latest:*` eliminan información vieja |
| Dispositivo reautorizado | Ryu elimina reglas de drop asociadas al guest |
| Error temporal del collector con Redis | Collector mantiene caché en memoria y reconecta periódicamente |

La recuperación no depende de intervención manual para los casos normales. La base de datos puede limpiarse completamente con un procedimiento de reset documentado, útil para repetir pruebas desde cero.

## 18. Evolución del Proyecto Según el Historial de Commits

El historial de commits muestra una evolución incremental hacia la arquitectura actual.

| Fase | Cambios principales |
| --- | --- |
| Base distribuida | Se implementó Ryu con Redis para externalizar estado y locks de concurrencia |
| Kubernetes inicial | Se agregaron manifiestos K3s, servicios y despliegue del controlador |
| OVS y VXLAN | Se incorporó un `DaemonSet` de OVS, auto-detección de interfaces y túneles VXLAN |
| Estabilización de red | Se fijó DPID por MAC de `br0`, se separó `br0` de `br-sdn` y se evitó romper K3s |
| Topología | Se agregó dashboard web, formato de DPID como MAC y deduplicación de enlaces |
| DHCP distribuido | Se implementó DHCP con Scapy, locks Redis, leases y healthchecks |
| Arquitectura final de control | Ryu pasó a `DaemonSet` con `hostNetwork` y OVS quedó conectado a `127.0.0.1` |
| Redis HA | Se migró a Redis Sentinel y se consolidó el tracking de puertos |
| Smart Meter | Se agregaron medidores, collector distribuido y entrega local a `10.0.0.1` |
| Observabilidad | Se incorporaron Prometheus, Grafana, Loki, Promtail y Node Exporter |
| Seguridad | Se agregó registro de dispositivos, dashboard de seguridad y enforcement en Ryu |
| AMI seguro | Se añadió HMAC, nonces anti-replay y métricas de telemetría válida/inválida |
| Correcciones finales | Se estabilizó frescura de guests, dashboards, cuarentena y reautorización |

Algunos commits muestran decisiones descartadas. Por ejemplo, se probó visualización o lógica relacionada con RSTP, pero luego se removió del proyecto SDN. El diseño vigente conserva STP en `br0` para proteger el plano físico/de gestión, pero evita mezclarlo con la lógica SDN principal sobre `br-sdn`.

También se observa que la documentación inicial hablaba de un Ryu como `Deployment` balanceado. El estado actual del código y los manifiestos reemplaza esa idea por un `DaemonSet` local por nodo, que es más coherente con el objetivo de recuperación rápida y control distribuido.

## 19. Decisiones de Diseño Más Relevantes

| Decisión | Fundamentación |
| --- | --- |
| Ryu en lugar de OpenDaylight/ONOS | Menor complejidad, Python, integración rápida con Redis, Scapy y Prometheus |
| K3s en lugar de Kubernetes completo | Menor consumo y despliegue más simple en VMs de GNS3 |
| `DaemonSet` para Ryu | Controlador local por nodo y menor dependencia de red externa |
| Redis Sentinel | Estado común con failover y coordinación entre servicios |
| OVS por nodo | Dataplane local programable mediante OpenFlow |
| VXLAN dinámico | Extiende la red SDN entre nodos sin hardcodear enlaces |
| `br0` separado de `br-sdn` | Evita bucles y separa gestión de dataplane |
| DHCP distribuido con locks | Responde localmente sin duplicar leases |
| Collector local en `10.0.0.1` | Reduce dependencia central y mejora continuidad local |
| HMAC en telemetría AMI | Aporta autenticidad, integridad y protección anti-replay |
| Registro de seguridad | Permite autorizar, bloquear y poner en cuarentena dispositivos |
| Observabilidad integrada | Permite diagnosticar fallos y demostrar comportamiento del sistema |

## 20. Limitaciones y Consideraciones

El sistema está diseñado para un laboratorio GNS3, no como despliegue productivo directo. Algunas decisiones son intencionales para facilitar pruebas, reinicios y recreación de nodos.

Limitaciones actuales:

| Limitación | Implicancia |
| --- | --- |
| PVCs Redis locales `local-path` | Mejoran persistencia frente a reinicios de pod, pero siguen atados al nodo donde se creó cada volumen |
| Dashboards fijados al master | Simplifica acceso, pero no da HA completa a la capa visual |
| Secretos HMAC de laboratorio | Deben gestionarse con rotación y secretos robustos en producción |
| Seguridad centrada en AMI | El enforcement está orientado a Smart Meters y amenazas L2/L3 concretas |
| GNS3 como entorno base | Permite experimentación, pero no replica todos los aspectos de hardware físico real |

Estas limitaciones no contradicen el objetivo del proyecto. El objetivo principal es demostrar una SDN distribuida, resiliente y observable en un entorno reproducible, y las decisiones tomadas favorecen ese objetivo.

## 21. Validación Experimental y Resultados Actuales

La validación completa se ejecutó el 2026-06-09 sobre el laboratorio activo. La prueba incluyó estado base del cluster, APIs, métricas Prometheus consumidas por Grafana, conectividad Smart Meter, carga concurrente, caída de topología y recuperación posterior.

Estado base verificado:

| Elemento | Resultado |
| --- | --- |
| Nodos K3s | 7/7 `Ready` |
| DaemonSet Ryu | 7/7 pods disponibles |
| DaemonSet OVS initializer | 7/7 pods disponibles |
| DaemonSet DHCP | 7/7 pods disponibles |
| DaemonSet meter collector | 7/7 pods disponibles |
| Redis Sentinel | Master `redis-0.redis-headless.sdn-controller.svc.cluster.local`, 2 replicas sincronizadas |
| Topología API | 7 switches, 5 guests Smart Meter, 13 enlaces SDN/guest |
| Grafana/Prometheus | 13 nodos totales: 7 switches SDN, 5 guests y `mgmt-stp-switch` para STP físico |
| Telemetría AMI | 5/5 Smart Meters online |

Durante la revisión se detectó una inconsistencia de topología: Prometheus/Grafana mostraban 6 guests mientras la telemetría real tenía 5 Smart Meters. La causa fue una MAC antigua de `SDNSmartMeter-5` retenida en Redis tras recreación del contenedor. Se limpió la entrada runtime de `topology:guest_ips`, `topology:guest_locations`, `topology:guest_names`, `health:*`, `active_mac:*` y `mac_to_port:*`. Tras expirar la ventana `last_over_time`, Grafana volvió a coincidir con la realidad: 5 guests y 5 meters.

Pruebas de conectividad:

| Prueba | Resultado |
| --- | --- |
| Matriz inicial 5 Smart Meters, 20 pares, 5 paquetes | Detectó convergencia lenta en algunos pares por expiración de flows reactivos |
| Corrección aplicada | `FORWARDING_FLOW_IDLE_TIMEOUT` aumentado de 30s a 120s |
| Rollout Ryu | 270s hasta 7/7 pods disponibles |
| Matriz estable posterior, 20 pares, 10 paquetes | 0/20 fallos, 0% pérdida, promedio global 4.964 ms, peor promedio 17.387 ms |
| Matriz final post-fallo, 20 pares, 5 paquetes | 0/20 fallos, 0% pérdida, promedio global 5.442 ms, peor promedio 14.495 ms |

Prueba de carga:

| Carga | Resultado |
| --- | --- |
| Tipo de carga | 20 flujos ICMP concurrentes todos-contra-todos |
| Volumen | 100 paquetes por flujo, 2000 paquetes totales |
| Duración medida | 2.31s |
| Pérdida | 0% |
| Promedio global por par | 12.856 ms |
| Peor promedio por par | 25.633 ms |
| Estado posterior | 5/5 meters online, 7/7 DaemonSets disponibles, 81 flows instalados reportados por Prometheus |

Prueba de caída y recuperación:

| Evento | Resultado medido |
| --- | --- |
| Nodo apagado | `SDN-Worker-2`, correspondiente a `worker-b56b35` |
| Rol en topología | Nodo intermedio VXLAN y host de `SDNSmartMeter-3` |
| Tráfico monitorizado | SM1 `10.0.0.14` hacia SM4 `10.0.0.12` |
| Latencia base previa | Promedio 4.276 ms |
| Recuperación SM1->SM4 tras caída | 87.5s desde orden de apagado |
| Ventana de pérdida observada | 85.8s desde primer fallo hasta 5 éxitos consecutivos |
| Estado durante caída | 6 nodos K3s `Ready`, `worker-b56b35` `NotReady`, topología reducida a 10 nodos, 4 guests y 10 enlaces |
| Reinicio del worker | Nodo `Ready` en 94.1s desde orden de arranque |
| Recuperación completa de topología/telemetría | 2.1s tras el primer chequeo posterior al rollout de DaemonSets |
| Estado final | 7/7 nodos `Ready`, 7/7 DaemonSets disponibles, 12 nodos API, 5 guests, 13 enlaces, 5/5 meters online |

Monitorización final de procesos y recursos:

| Métrica | Resultado |
| --- | --- |
| CPU por nodo tras pruebas | Entre 36.15% y 53.05% según Node Exporter |
| Memoria por nodo tras pruebas | Entre 35.78% y 49.31% |
| Redis | Master operativo y dos replicas `slave` |
| Pods no `Running` | Ninguno en `sdn-controller` |
| Logs Ryu durante caída | Eliminación esperada de flows hacia VXLAN inactivos y breves errores Redis mientras Sentinel/servicios reconvergían |

La arquitectura se recuperó correctamente de la caída de un worker intermedio sin malla completa VXLAN. La recuperación no fue instantánea porque depende de la detección de reachability, expiración/limpieza de estado y recomputo de camino, pero el sistema volvió a operar sin intervención manual. El resultado es suficiente para demostrar resiliencia de laboratorio y deja dos límites claros: el underlay virtualizado en GNS3 domina la latencia, y los flujos reactivos introducen latencia fria cuando no están instalados.

## 22. Comparación con Arquitecturas Alternativas

Para evaluar el valor del proyecto no basta compararlo solo con una SDN centralizada. En una red eléctrica real, especialmente en una red AMI con medidores inteligentes, también existe una alternativa tradicional: una red IP o Ethernet sin OpenFlow, construida con routers, switches gestionables, VLANs, ACLs, OSPF/Static Routing, VRRP/HSRP, firewalls perimetrales y sistemas de monitoreo separados. Esa arquitectura es habitual porque usa tecnologías maduras y conocidas por los equipos de operación, pero ofrece menos capacidad de reacción programable ante eventos de seguridad, cambios topológicos y grandes volúmenes de telemetría distribuida.

Las tres opciones comparadas son:

| Arquitectura | Descripción |
| --- | --- |
| Red tradicional sin OpenFlow | Switches/routers convencionales, VLANs, ACLs, routing estático o dinámico, firewalls y monitoreo externo |
| SDN centralizada | OVS/OpenFlow con uno o varios controladores centrales detrás de una IP o servicio común |
| SDN distribuida del proyecto | OVS/OpenFlow por nodo, Ryu local en `127.0.0.1`, Redis Sentinel como estado compartido, servicios distribuidos y observabilidad integrada |

### 22.1 Respuesta ante Caídas

En una red tradicional sin OpenFlow, la recuperación depende principalmente de protocolos de red clásicos. STP/RSTP protege contra bucles a nivel L2, OSPF o rutas estáticas redundantes pueden recuperar caminos L3, y VRRP/HSRP puede mover una gateway virtual entre routers. Estos mecanismos son robustos y ampliamente probados, pero operan con información limitada: reaccionan a enlaces, interfaces o vecinos de routing, no al estado semántico de los medidores, la seguridad AMI, la validez de la telemetría o la ubicación real de cada dispositivo final.

En una SDN centralizada, el controlador tiene más visibilidad lógica que una red tradicional, pero introduce una dependencia fuerte del punto central. Si el controlador o su conectividad de gestión fallan, los switches pueden seguir reenviando flows ya instalados, pero no pueden resolver correctamente nuevos flujos, cambios de topología, nuevos medidores o eventos de seguridad que requieran nuevas reglas.

En este proyecto, cada nodo mantiene su propio controlador Ryu local. OVS no necesita alcanzar un controlador remoto para procesar eventos OpenFlow, porque se conecta a `tcp:127.0.0.1:6653`. Redis Sentinel mantiene el estado compartido y los TTLs eliminan información obsoleta. En la prueba de caída de `SDN-Worker-2`, el sistema recuperó conectividad SM1->SM4 en 87.5s y volvió a topología completa tras reiniciar el worker sin intervención manual.

| Escenario de caída | Red tradicional sin OpenFlow | SDN centralizada | SDN distribuida del proyecto |
| --- | --- | --- | --- |
| Caída de enlace | STP/RSTP u OSPF reconvergen, pero sin conocimiento de guests AMI | El controlador recalcula si sigue accesible | LLDP/probes actualizan VXLAN, Ryu borra flows hacia peers inactivos |
| Caída de nodo de acceso | Los dispositivos detrás del nodo quedan fuera; la red puede tardar en limpiar MAC/ARP | El controlador central detecta si recibe eventos o métricas | `switch:alive:*`, `health:*` y `active_mac:*` limpian topología y guests obsoletos |
| Caída del controlador | No aplica si no hay controlador | Alto impacto si el endpoint central no está disponible | Impacto local: cada nodo tiene su Ryu local |
| Reinicio de un nodo | Requiere scripts/servicios de host para reconstruir bridges y rutas | Depende de que OVS reconecte al controlador central | `ovs-sdn-initializer` reconstruye `br-sdn`, VXLAN, controller y heartbeats |
| Recuperación observada en la prueba | No medida en este proyecto | No usada como arquitectura final | SM1->SM4 recuperó en 87.5s; worker volvió `Ready` en 94.1s |

La red tradicional puede reconverger más rápido en algunos escenarios puramente L3, sobre todo con hardware físico y protocolos bien ajustados. Sin embargo, no reconstruye por sí sola el estado lógico de una red AMI: qué medidor está autorizado, en qué puerto está, qué MAC/IP le corresponde, si su telemetría es válida o si debe quedar en cuarentena. Esa diferencia es central para el problema abordado.

### 22.2 Seguridad

En una red eléctrica, la seguridad no se limita a impedir acceso IP. Un medidor comprometido puede intentar suplantar otra MAC, usar la IP de otro dispositivo, enviar ARP falsos, repetir telemetría antigua, falsificar lecturas o inundar el segmento con tráfico que degrade la recolección.

Una red tradicional suele resolver esto con VLANs, ACLs, DHCP snooping, Dynamic ARP Inspection, port security, firewalls y eventualmente NAC/802.1X. Estas medidas son útiles, pero normalmente viven repartidas en muchos equipos y no comparten contexto con la aplicación AMI. Por ejemplo, un switch puede limitar MACs por puerto, pero no necesariamente sabe si una lectura UDP firmada pertenece al medidor autorizado para ese `dpid/in_port`, ni puede correlacionar un nonce HMAC inválido con una cuarentena OpenFlow inmediata.

La SDN centralizada mejora la capacidad de enforcement porque el controlador puede instalar drops o redirecciones dinámicas. Su debilidad vuelve a ser la dependencia del controlador central: si hay pérdida de conectividad hacia él, la respuesta ante nuevas amenazas se degrada.

En este proyecto, la seguridad se integra desde el acceso hasta la aplicación:

| Capa | Red tradicional sin OpenFlow | SDN distribuida del proyecto |
| --- | --- | --- |
| Identidad del dispositivo | MAC/IP, DHCP snooping, NAC o inventario externo | Registro Redis con `device_id`, MAC, IP, DPID, puerto, rol y estado |
| MAC spoofing | Port security por switch, configuración equipo por equipo | Ryu compara MAC observada contra registro y ubicación real |
| IP spoofing | ACLs, DHCP snooping o reglas en firewall | Ryu valida IP observada contra dispositivo autorizado |
| ARP poisoning | Dynamic ARP Inspection si está disponible | Ryu bloquea ARP por `10.0.0.1`, mismatches Ethernet/ARP y anuncios inválidos |
| Telemetría falsa | Normalmente se valida en aplicación o firewall | Collector valida HMAC, nonce, timestamp y estado de seguridad |
| Cuarentena | VLAN de cuarentena/NAC, usualmente dependiente de infraestructura externa | Ryu instala drops y el collector rechaza fuentes no autorizadas o en cuarentena |
| Observabilidad de seguridad | Logs distribuidos entre switches/firewalls/NMS | Eventos, métricas Prometheus, Loki y dashboard unificado |

La ventaja de la arquitectura del proyecto es la correlación. La red no solo filtra paquetes; relaciona ubicación física/lógica, estado administrativo, identidad AMI y validez criptográfica de la telemetría. Para una red eléctrica, esto permite responder a ataques de forma más precisa: bloquear un medidor concreto sin afectar a otros, identificar si cambió de puerto, detectar si una IP fue reutilizada y reflejar el evento en Grafana.

### 22.3 Grandes Cantidades de Tráfico

Una red eléctrica con muchos medidores produce tráfico constante y repetitivo: lecturas periódicas, eventos de calidad eléctrica, alarmas, reconexiones, mensajes de control y tráfico de mantenimiento. En una arquitectura tradicional, este tráfico se transporta bien si la red está sobredimensionada y segmentada por VLAN/subredes, pero la gestión fina del flujo suele depender de QoS estática, ACLs y capacidad de los routers/firewalls centrales.

El riesgo de una arquitectura tradicional es que el crecimiento se administra por configuración manual o por plantillas externas. A medida que crece el número de medidores, también crece la necesidad de mantener ACLs, rutas, reglas de firewall, listas de dispositivos y dashboards consistentes. Si se centraliza toda la telemetría en un collector único, aparece además un cuello de botella de aplicación.

En este proyecto, el tráfico AMI se distribuye por diseño. Cada nodo tiene un collector local en `10.0.0.1`, DHCP local coordinado por Redis y Ryu local para instalar flows. Esto reduce dependencia de un collector central y evita que todos los medidores crucen la topología para entregar datos. La prueba de carga ejecutó 20 flujos ICMP concurrentes entre los 5 Smart Meters, con 2000 paquetes totales, 0% de pérdida y todos los servicios críticos disponibles al finalizar.

| Aspecto bajo carga | Red tradicional sin OpenFlow | SDN centralizada | SDN distribuida del proyecto |
| --- | --- | --- | --- |
| Instalación de política | ACL/QoS configuradas por equipo o automatización externa | Controlador central instala reglas | Ryu local instala flows y coordina estado en Redis |
| Telemetría AMI | Puede concentrarse en uno o pocos collectors | Depende del diseño de servicios | Collector local por nodo con `hostNetwork` |
| Escalamiento operativo | Aumenta complejidad de VLANs, ACLs, rutas y firewalls | Aumenta carga del controlador central | Aumentan instancias DaemonSet por nodo y estado compartido |
| Fallo bajo ráfagas | Riesgo de saturar enlaces/firewalls/collectors centrales | Riesgo de saturar controlador si hay muchos Packet-In | Flujos reactivos se instalan localmente; timeout de 120s reduce Packet-In repetidos |
| Visibilidad | NMS/SNMP/NetFlow separados de la aplicación | Métricas SDN centralizadas | Prometheus une topología, flows, CPU, memoria, logs y telemetría |

La arquitectura tradicional puede ofrecer mayor rendimiento bruto si usa switches y routers físicos especializados. Esa es una ventaja real: ASICs dedicados pueden reenviar a línea de cable con latencias muy bajas. Pero el problema de este proyecto no es solo reenviar paquetes; es administrar una red eléctrica distribuida con medidores identificables, telemetría validada, recuperación automática y seguridad contextual. Para ese objetivo, la programabilidad de OpenFlow y la distribución por nodo aportan más valor que una red clásica puramente estática.

### 22.4 Evaluación Final

La arquitectura del proyecto es superior a una SDN centralizada cuando se prioriza continuidad local: la caída del controlador remoto deja de ser un punto único de falla porque cada OVS habla con el Ryu de su propio nodo. También es superior a una red tradicional sin OpenFlow cuando se requiere control dinámico basado en identidad, ubicación y estado de seguridad AMI, porque las decisiones no dependen solo de VLANs o ACLs estáticas.

No obstante, una red tradicional sigue siendo válida para entornos donde los medidores solo deben enviar datos a un backend central, el inventario cambia poco, la seguridad se delega a firewalls/NAC externos y la operación prefiere protocolos conocidos antes que programabilidad. También puede ser mejor en rendimiento puro si se implementa con hardware especializado. La arquitectura propuesta es más adecuada cuando el requisito principal es resiliencia observable y control granular: detectar fallos, reconstruir topología, validar dispositivos, aislar amenazas y mantener telemetría distribuida aun durante cambios o caídas parciales.

## 23. Conclusión

El proyecto implementa una plataforma SDN distribuida completa sobre GNS3 y K3s. La arquitectura final evita un controlador central único, ejecuta Ryu localmente en cada nodo, coordina el estado mediante Redis Sentinel y reconstruye automáticamente dataplane, túneles, leases, topología y métricas tras reinicios o cambios de red.

La selección de Ryu fue adecuada porque permitió modificar directamente la lógica OpenFlow y construir un controlador adaptado al laboratorio: aprendizaje MAC distribuido, locks Redis, respuesta ARP local, integración con DHCP, métricas Prometheus y enforcement de seguridad.

La solución también incorpora elementos de un sistema real: observabilidad completa, dispositivos IoT simulados, telemetría firmada, registro de dispositivos autorizados, cuarentena de guests y pruebas de ataques. Por eso el resultado no es solo una prueba de conectividad SDN, sino una infraestructura experimental de control, monitoreo y seguridad para redes AMI distribuidas.

En síntesis, el proyecto demuestra que es posible construir una SDN resiliente con herramientas ligeras y modificables, usando Ryu como controlador programable, K3s como orquestador, Open vSwitch como dataplane y Redis Sentinel como backend de coordinación distribuida.
