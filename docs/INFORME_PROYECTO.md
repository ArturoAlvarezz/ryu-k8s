# Informe del Proyecto: SDN Distribuida para Infraestructura AMI sobre K3s y GNS3

## Marco Teorico

Una red definida por software, o SDN, separa el plano de control del plano de datos. En una red tradicional, cada switch o router decide por si mismo como reenviar los paquetes. En una arquitectura SDN, los dispositivos de red ejecutan reglas y un controlador externo decide que reglas deben existir. Esta separacion permite programar la red, observar su estado y reaccionar ante fallos o amenazas con mas precision que una configuracion estatica basada solo en VLANs, rutas y ACLs.

El proyecto usa esta idea para construir una red AMI distribuida. AMI significa Advanced Metering Infrastructure y representa una infraestructura de medidores inteligentes. En este contexto, los Smart Meters no son simples hosts de prueba: simulan dispositivos de una red electrica que obtienen direccion IP, envian telemetria periodica, deben estar autorizados y pueden ser bloqueados si su comportamiento no coincide con su identidad registrada.

El controlador elegido fue Ryu. Ryu es un framework SDN escrito en Python que permite crear aplicaciones OpenFlow. Fue adecuado porque el proyecto necesitaba modificar la logica del controlador en profundidad: aprendizaje MAC distribuido, calculo de rutas, respuesta ARP, instalacion de flujos, metricas Prometheus, validacion de seguridad y coordinacion con Redis. Controladores como OpenDaylight, ONOS o Floodlight se consideraron, pero se descartaron para este laboratorio porque agregaban mas complejidad operacional que valor practico. OpenDaylight y ONOS son plataformas mas pesadas y pensadas para entornos empresariales o carrier. Floodlight es mas simple, pero esta basado en Java y no encajaba tan bien con el ecosistema Python usado por Ryu, Scapy, Flask y los servicios propios.

OpenFlow es el protocolo que permite a Ryu programar Open vSwitch. Cuando OVS no sabe como tratar un paquete, envia un evento `Packet-In` al controlador. Ryu responde instalando reglas mediante mensajes `FlowMod`. Esas reglas pueden reenviar a un puerto fisico, a un tunel VXLAN, al puerto local del host o descartar el trafico. El identificador de cada switch se denomina DPID y permite asociar cada datapath con un nodo concreto de la topologia.

Open vSwitch se usa como switch virtual programable en cada nodo K3s. Cada nodo mantiene un bridge OVS llamado `br-sdn`, que representa el plano de datos SDN. A ese bridge se conectan los Smart Meters y los tuneles que enlazan nodos. OVS fue necesario porque permite mezclar OpenFlow, puertos locales, interfaces de GNS3 y tuneles VXLAN. Se probo ejecutar OVS desde una base Alpine, pero se descarto por problemas practicos de compatibilidad con kernel y modulos. El proyecto paso a una base Ubuntu para estabilizar el dataplane.

VXLAN permite extender una red de capa 2 sobre una red IP. En el proyecto se usa para que Smart Meters conectados a nodos distintos pertenezcan al mismo plano SDN `10.0.0.0/24`. La alternativa de crear una malla completa de VXLAN fue descartada. Una malla completa parece sencilla al comienzo, pero escala mal, crea enlaces artificiales entre nodos que no son vecinos reales y elimina el sentido de calcular rutas multi-hop. La arquitectura final mantiene vecinos directos del fabric y deja que Ryu calcule los caminos.

El control de bucles evoluciono de forma importante. STP y RSTP se evaluaron porque son mecanismos clasicos para evitar loops de capa 2, pero se descartaron en el dataplane SDN final. STP bloquea enlaces completos, desperdicia redundancia fisica y no entiende la logica de la aplicacion AMI. La solucion final separa dos problemas: el broadcast se controla con un arbol minimo de expansion, y el trafico unicast se calcula con Dijkstra. El MST evita que los floods formen bucles. Dijkstra permite usar el mejor camino disponible entre Smart Meters sin quedar limitado por el arbol de broadcast.

Redis cumple el rol de estado distribuido. No es solo una cache. Es el contrato runtime que comparten Ryu, DHCP, el colector de telemetria, el dashboard, el registro de seguridad y las pruebas. En Redis viven los switches activos, las ubicaciones de los guests, el aprendizaje MAC, los leases DHCP, los peers VXLAN, los estados de seguridad, las lecturas de medidores, los nonces HMAC y los locks distribuidos. Redis simple fue reemplazado por Redis Sentinel para evitar que la caida de una instancia dejara sin estado al sistema.

K3s aporta la orquestacion. Se eligio K3s en lugar de Kubernetes completo porque el laboratorio corre sobre VMs QEMU dentro de GNS3 y los recursos son limitados. K3s permite ejecutar componentes como DaemonSets, StatefulSets y ConfigMaps sin cargar el entorno con una distribucion Kubernetes mas pesada. Los DaemonSets son clave porque garantizan un componente por nodo: Ryu, OVS initializer, DHCP, meter collector, Promtail y Node Exporter. El cambio mas importante fue abandonar el modelo de Ryu como Deployment con varias replicas detras de un balanceador. La arquitectura final ejecuta un Ryu local por nodo con `hostNetwork`, y cada OVS se conecta a `tcp:127.0.0.1:6653`. Esto elimina la dependencia de un controlador remoto para el dataplane local.

GNS3 permite construir un laboratorio de red con nodos, cables, apagados y fallos reales. Los control planes y workers son VMs Ubuntu sobre QEMU/KVM. Los Smart Meters son contenedores ligeros. La maquina atacante es Ubuntu porque las pruebas con Scapy, paquetes crudos y tcpdump requieren un entorno mas completo. GNS3 fue preferido frente a simulaciones mas simples porque el objetivo no era solo probar un algoritmo SDN, sino validar un cluster K3s real con servicios, reinicios, interfaces, OVS, Redis y fallos de nodos.

El DHCP del plano SDN se implementa con Scapy porque se necesitaba control fino sobre paquetes DHCP y ARP. Cada nodo tiene un servidor DHCP local. Como un broadcast puede atravesar VXLAN y llegar a varias instancias, se usan locks atomicos en Redis para que solo una responda. Esta decision evita leases duplicados y mantiene una unica verdad sobre la IP de cada Smart Meter.

La telemetria AMI usa UDP hacia `10.0.0.1:5555`. Cada nodo expone localmente `10.0.0.1` en `br-sdn` y ejecuta un meter collector. Esta decision evita que todos los medidores dependan de un collector central y reduce trafico innecesario entre nodos. La telemetria se protege con HMAC-SHA256 y nonce. El HMAC valida integridad y autenticidad. El nonce evita replay de lecturas antiguas. El comportamiento es fail-closed: si la firma falta, es invalida, el nonce se repite, el dispositivo no esta autorizado o Redis no permite validar la fuente, la lectura se rechaza.

La observabilidad se implementa con Prometheus, Grafana, Loki, Promtail y Node Exporter. Prometheus recolecta metricas de Ryu, del collector y de los nodos. Grafana permite visualizar salud, trafico, telemetria, seguridad y logs. Loki centraliza logs y Promtail los envia desde los pods. Ryu expone `/metrics` directamente, sin sidecar, porque agregar otro contenedor solo para metricas complicaba el despliegue sin aportar valor real.

El proyecto tambien evoluciono hacia un fabric L3 con FRR, OSPF, BGP, Calico y loopbacks `10.255.x.x`. Esta fase responde a un problema observado en el plano de gestion L2: un dominio broadcast con multiples cables puede generar tormentas si se reintroduce un loop. El fabric L3 elimina esa clase de fallo porque cada cable pasa a ser un enlace enrutado. OSPF entrega alcanzabilidad entre loopbacks, ECMP permite usar multiples caminos, y BGP puede integrar kube-vip y Calico. Esta evolucion reemplaza mecanismos anteriores como arboles estaticos de `br0`, puertos activos por hostname, failover L2 y storm guards.

Las tecnologias usadas de forma efectiva fueron Ryu, OpenFlow, Open vSwitch, VXLAN, K3s, Redis Sentinel, Scapy, Flask, GNS3, QEMU/KVM, Docker, Prometheus, Grafana, Loki, Promtail, Node Exporter, HMAC-SHA256, FRR, OSPF, BGP y Calico. Las tecnologias o enfoques descartados fueron OpenDaylight, ONOS, Floodlight, Kubernetes completo, Ryu centralizado detras de LoadBalancer, Redis simple, OVS Alpine, STP/RSTP en el dataplane SDN, VXLAN full-mesh, BFS como fuente de verdad para caminos, collector central unico y dashboards separados para seguridad.

## Metodologia

### Problema a Resolver

El problema central fue construir una red AMI distribuida capaz de mantener conectividad, telemetria y seguridad ante fallos de enlaces, nodos, pods y servicios auxiliares. Una red de Smart Meters no puede depender de configuracion manual ni de un controlador unico. Tampoco basta con que los paquetes pasen: el sistema debe saber que medidor esta conectado, donde esta, si esta autorizado, si su telemetria es valida y si la topologia mostrada corresponde al estado real.

La metodologia fue incremental. El proyecto comenzo como un fork de Ryu y evoluciono hacia una plataforma completa. Cada decision importante surgio de una limitacion detectada en pruebas. Cuando un enfoque resolvia un problema pero creaba otro, se reemplazaba. Por eso el historial muestra STP y RSTP antes de MST y Dijkstra, Ryu Deployment antes de DaemonSet, Redis simple antes de Sentinel, VXLAN mas amplio antes de vecinos reales, y `br0` L2 antes del fabric L3.

El criterio de avance no fue teorico. Cada etapa se valido en GNS3 con K3s real, OVS real, pods reales y fallos provocados. Si el laboratorio quedaba con estado stale, loops, flows obsoletos, dashboards incorrectos o telemetria falsa aceptada, el diseno se corregia.

La eleccion de K3s fue parte central de la metodologia porque el objetivo no era construir solo una aplicacion SDN, sino una arquitectura distribuida operable. K3s permitio trabajar con primitivas reales de Kubernetes, como DaemonSets, StatefulSets, Services, ConfigMaps y rolling restarts, pero con un consumo compatible con varias maquinas virtuales ejecutandose dentro de GNS3. Esto hizo posible validar el comportamiento del sistema en condiciones cercanas a una instalacion distribuida: un controlador Ryu por nodo, OVS local, servicios replicados, Redis Sentinel, observabilidad y reinicios controlados. En vez de simular la distribucion desde un proceso unico, el laboratorio obligo a resolver problemas propios de un cluster real, como descubrimiento de nodos, estado compartido, failover, pods que reinician, nodos que caen y diferencias entre conectividad local y conectividad remota.

K3s tambien ayudo a separar responsabilidades. Los componentes que debian estar en todos los nodos se modelaron como DaemonSets; los que necesitaban identidad estable y persistencia se desplegaron como StatefulSets; y el codigo de servicios Python se monto mediante ConfigMaps para acelerar iteraciones sin reconstruir imagenes en cada prueba. Esta forma de trabajo permitio que la metodologia fuera experimental y repetible: se introducia un cambio, se desplegaba en el cluster, se provocaba un fallo o ataque, y luego se observaba el efecto en conectividad, Redis, logs, metricas y dashboards.

### Evolucion Tecnica del Proyecto

- La primera fase fue convertir Ryu en un controlador SDN con estado externo en Redis. Esto permitio que el aprendizaje MAC y la topologia dejaran de depender solo de la memoria del proceso.

- La segunda fase fue llevar el controlador a Kubernetes. Se agregaron manifiestos, imagenes Docker y despliegue en K3s.

- La tercera fase incorporo OVS por nodo. Se creo `br-sdn`, se estabilizo el DPID, se agregaron interfaces guest y se empezaron a construir tuneles VXLAN.

- La cuarta fase separo el plano de gestion del plano SDN. Se evito mezclar `br0` con `br-sdn` porque hacerlo podia romper K3s o introducir loops peligrosos.

- La quinta fase cambio el modelo de Ryu. En lugar de un Deployment central o balanceado, se paso a un DaemonSet con un Ryu local por nodo. OVS quedo conectado al controlador local por `127.0.0.1`.

- La sexta fase migro Redis a Sentinel. Esto convirtio el backend de estado en un componente con failover.

- La septima fase agrego DHCP distribuido con Scapy y locks Redis. Esto hizo posible conectar Smart Meters reales de GNS3 al plano SDN.

- La octava fase incorporo Smart Meters, meter collector y telemetria AMI. La red dejo de ser solo conectividad y paso a transportar datos de aplicacion.

- La novena fase agrego observabilidad. Prometheus, Grafana y Loki permitieron medir Packet-In, flows, estado de nodos, trafico, logs y seguridad.

- La decima fase agrego seguridad AMI. Se implemento registro de dispositivos, estados `authorized`, `blocked` y `quarantined`, validacion de MAC, IP, DPID, puerto, HMAC y nonce.

- La undecima fase estabilizo K3s HA, kube-vip, Golden Images, autojoin y recuperacion tras reinicios GNS3.

- La duodecima fase se centro en resiliencia. Se agrego propagacion de switches caidos, limpieza de flows stale, caducidad de presencia y reroute ante cambios de topologia.

- La decimotercera fase elimino STP/RSTP del dataplane SDN y lo reemplazo por MST para broadcast y Dijkstra para unicast.

- La decimocuarta fase rechazo la malla completa VXLAN y consolido tuneles a vecinos reales del fabric.

- La fase final incorporo fabric L3 con FRR/OSPF, loopbacks y deteccion mas rapida de peers caidos.

### Decisiones Tecnologicas

- Ryu fue elegido porque permite implementar logica propia en Python y modificar el comportamiento OpenFlow sin cargar con una plataforma SDN pesada.

- K3s fue elegido porque entrega Kubernetes real con menor consumo, adecuado para VMs dentro de GNS3.

- OVS fue elegido porque permite un dataplane programable con OpenFlow y VXLAN.

- Redis Sentinel fue elegido porque el sistema necesita estado compartido con failover. Sin Redis, los controladores locales serian islas.

- El modelo de Ryu local por nodo fue elegido porque evita que la caida de un controlador remoto afecte a todos los switches.

- El gateway `10.0.0.1` local por nodo fue elegido para mantener telemetria local y reducir dependencia de servicios centrales.

- DHCP distribuido fue elegido porque los Smart Meters pueden estar conectados a cualquier nodo y deben obtener IP aunque otros nodos esten fallando.

- HMAC y nonce fueron incorporados porque en una red AMI no basta con transportar paquetes; las lecturas deben ser autenticas, integras y no repetidas.

- MST y Dijkstra reemplazaron STP/RSTP porque el proyecto necesita evitar loops sin bloquear de forma permanente enlaces utiles.

- VXLAN por vecinos reemplazo full-mesh porque conserva el grafo real y permite validar caminos multi-hop.

- El fabric L3 reemplaza gradualmente el underlay L2 porque elimina la clase completa de fallos por loops broadcast en gestion.

### Enfoques Descartados

- OpenDaylight fue descartado por peso y complejidad operativa.

- ONOS fue descartado porque su cluster nativo era mas complejo que externalizar estado en Redis para este caso.

- Floodlight fue descartado porque no encajaba tan bien con el ecosistema Python del proyecto.

- Kubernetes completo fue descartado porque K3s resuelve el mismo problema con menor consumo.

- Ryu como Deployment balanceado fue descartado porque seguia dependiendo de conectividad hacia un endpoint remoto.

- Redis simple fue descartado porque era un punto unico de fallo.

- OVS Alpine fue descartado por incompatibilidades practicas.

- STP/RSTP en `br-sdn` fue descartado porque bloqueaba enlaces y no resolvia la logica de rutas AMI.

- VXLAN full-mesh fue descartado por escalabilidad y porque falseaba la topologia.

- BFS fue reemplazado por Dijkstra porque no modelaba costes ni coincidia con el forwarding final.

- Un collector central fue descartado porque concentraba trafico y riesgo.

- La UI separada de seguridad fue reemplazada por un dashboard operacional unificado.

## Implementacion

### Arquitectura General

La implementacion final es una plataforma SDN distribuida sobre K3s y GNS3. Incluye un laboratorio virtual, un cluster Kubernetes ligero, un dataplane OpenFlow, un backend de estado compartido, servicios AMI, seguridad y observabilidad.

El laboratorio se ejecuta en GNS3. Los nodos de infraestructura son VMs Ubuntu. Los Smart Meters son contenedores. La maquina atacante es una VM Ubuntu. Esta combinacion permite simular una infraestructura distribuida con fallos reales de enlace y de nodo.

K3s orquesta los servicios. Los componentes que deben existir en cada nodo se despliegan como DaemonSets. Redis se despliega como StatefulSet con Sentinel. El codigo Python de servicios como Ryu, DHCP y meter collector se inyecta mediante ConfigMaps para facilitar hot reload en laboratorio.

El dataplane SDN vive en `br-sdn`. Cada nodo tiene su propio OVS y su propio Ryu. OVS no apunta a un servicio remoto, sino a `tcp:127.0.0.1:6653`. Esta es una de las decisiones mas importantes de la implementacion: el plano de control inmediato de cada switch esta en el mismo nodo.

El estado compartido vive en Redis Sentinel. Ryu escribe switches, MACs, puertos y caminos. DHCP escribe leases y ubicacion de guests. El collector escribe telemetria y consulta seguridad. El dashboard lee topologia y estado de dispositivos. Las pruebas inspeccionan esas mismas claves.

### Controlador Ryu

El controlador principal esta en `services/ryu-controller/app.py`. La aplicacion `DistributedL2Switch` procesa eventos OpenFlow y coordina decisiones con Redis.

Ryu registra switches cuando se conectan. Aprende MACs observadas. Publica presencia con TTL. Instala flows reactivos. Entrega trafico destinado a `10.0.0.1` al puerto local. Fabrica respuestas ARP para el gateway y para destinos conocidos. Calcula flood controlado por MST. Calcula caminos unicast por Dijkstra. Expone metricas Prometheus en el puerto `8000`.

Ryu tambien participa en seguridad. Valida si una MAC o IP observada corresponde a un dispositivo autorizado. Detecta intentos de suplantacion. Bloquea ARP malicioso para `10.0.0.1`. Instala drops de alta prioridad para dispositivos bloqueados o en cuarentena. Esta logica evita que la seguridad quede solo en la aplicacion.

Los locks Redis evitan que varias instancias instalen reglas contradictorias. La llave `lock:flow:{dpid}:{src}:{dst}` serializa la instalacion de flows para un mismo par de comunicacion.

### OVS y VXLAN

El `ovs-sdn-initializer` prepara `br-sdn` en cada nodo. Crea el bridge, fija DPID, asigna `10.0.0.1/24`, conecta el controlador local, agrega puertos guest y crea tuneles VXLAN hacia peers directos.

El inicializador tambien publica heartbeats `switch:alive:{dpid}` y detecta peers caidos. Cuando un peer desaparece, publica eventos `switch:dead` y elimina flows que podrian seguir apuntando a puertos obsoletos. Esto reduce el riesgo de que el dataplane siga usando caminos muertos.

En el modelo mas reciente, los peers VXLAN se derivan de rutas OSPF hacia loopbacks `10.255.x.x`. Esto permite que el overlay use vecinos reales del fabric y evita una malla completa artificial.

### Underlay de Gestion

El proyecto tuvo dos etapas de underlay. La primera uso `br0` como bridge Linux para la red de gestion. Como GNS3 permite topologias con anillos, `br0` debia mantenerse sin loops. Para eso se usaron puertos activos deterministas, failover controlado y guards contra tormentas.

La etapa posterior migra a fabric L3. En vez de construir un dominio L2 grande, cada enlace se trata como ruta IP. FRR anuncia loopbacks por OSPF. La alcanzabilidad entre nodos ya no depende de STP ni de un arbol manual. Esto hace el underlay mas robusto frente a cables redundantes y reinicios.

La regla que se mantiene en ambas etapas es estricta: `br0` o el underlay de gestion no deben mezclarse con `br-sdn`. El plano de gestion sostiene Kubernetes. El plano SDN transporta Smart Meters.

### Redis Sentinel

Redis Sentinel mantiene el estado comun y el failover del backend. Los servicios consultan Sentinel para ubicar el master vigente. Esto evita acoplar el sistema a una instancia fija.

Redis contiene la topologia, los peers VXLAN, el aprendizaje MAC, la presencia de switches, los leases DHCP, la ubicacion de guests, el estado de seguridad, la telemetria, los nonces y los locks. Esa centralizacion controlada permite que varias instancias locales actuen como un sistema distribuido.

### DHCP Distribuido

El DHCP distribuido esta en `services/dhcp-server/app.py`. Cada nodo escucha trafico DHCP del plano SDN. Cuando recibe una solicitud, intenta adquirir un lock en Redis. Si lo consigue, responde. Si no lo consigue, descarta porque otra instancia ya gano.

El DHCP guarda la IP asignada y la asocia a la MAC del Smart Meter. Tambien publica informacion que luego consume la topologia. Sus healthchecks ARP permiten saber si un guest sigue presente. Para no contaminar caches ARP, los workers hacen probes con `psrc=0.0.0.0`.

### Smart Meters

Los Smart Meters estan en `services/smart-meter/`. Al arrancar, levantan la interfaz, ejecutan `udhcpc` hasta obtener direccion y luego empiezan a enviar telemetria. El retry infinito de DHCP es intencional. En un entorno distribuido, el medidor no debe fallar solo porque arranco antes que DHCP.

Cada lectura contiene identidad del dispositivo, valores electricos simulados, timestamp, nonce y HMAC. El destino por defecto es `10.0.0.1:5555`.

### Meter Collector y Dashboard

El meter collector esta en `services/meter-collector/app.py`. Recibe UDP en `5555` y expone HTTP en `8081`. Corre por nodo con `hostNetwork`, lo que permite recibir trafico local y exponer el dashboard operacional sin depender de ServiceLB para el camino critico.

El collector valida HMAC, nonce, estado administrativo y autorizacion de la fuente. Si la lectura es valida, guarda la ultima muestra y el historial en Redis. Si no es valida, incrementa contadores de rechazo y la descarta.

El dashboard unificado muestra telemetria, seguridad, guests, topologia y trazado de caminos. Las APIs mas importantes son `/api/stats`, `/api/guests`, `/api/telemetry-security`, `/api/sdn-topology` y `/api/sdn-trace`.

### Seguridad AMI

El registro de seguridad mantiene la identidad esperada de cada medidor. Para autorizar un dispositivo no basta su `device_id`. Tambien se considera MAC, IP, DPID, puerto, destino permitido, puerto UDP permitido y estado administrativo.

Ryu y el collector aplican seguridad en capas. Ryu protege el borde de red contra spoofing y ARP poisoning. El collector protege la aplicacion contra telemetria falsa, replay y fuentes no autorizadas.

Los estados principales son `authorized`, `blocked` y `quarantined`. Un dispositivo autorizado puede enviar telemetria si coincide con su identidad. Un dispositivo bloqueado o en cuarentena no debe publicar telemetria aceptada.

### Observabilidad

Prometheus recolecta metricas de Ryu, collector y nodos. Ryu publica metricas como `ryu_packet_in_total`, `ryu_active_nodes`, `ryu_active_switches`, `ryu_installed_flows`, `ryu_port_rx_bytes_total`, `ryu_port_tx_bytes_total`, `ryu_topology_node_info` y `ryu_topology_edge_info`.

Grafana visualiza esas metricas junto con logs y estado de seguridad. Loki y Promtail centralizan logs. El objetivo no es solo ver graficos, sino poder explicar por que una ruta cambio, por que un medidor desaparecio, por que una lectura fue rechazada o por que un nodo quedo marcado como caido.

## Pruebas y Validaciones

### Tipo de Pruebas

Las pruebas del proyecto son principalmente de caja gris. Son de caja negra cuando se valida conectividad desde los Smart Meters, APIs del dashboard o disponibilidad de servicios sin mirar la implementacion interna. Son de caja gris porque tambien se inspeccionan Redis, logs de Ryu, flows OVS, pods de Kubernetes, rutas del fabric y metricas Prometheus. No son pruebas puramente de caja blanca porque el criterio final es el comportamiento observable de la red.

Tambien hay pruebas de integracion. Ryu, OVS, Redis, DHCP, meter collector, seguridad, dashboard y Smart Meters se validan juntos. Un ping exitoso no basta si la topologia queda stale. Una lectura aceptada no basta si el dispositivo no estaba autorizado. Una API disponible no basta si los DPIDs caidos siguen apareciendo como camino activo.

Las pruebas de resiliencia son una forma de chaos testing controlado. Se apagan nodos, se suspenden enlaces y se reinician componentes para medir si el sistema detecta el cambio, limpia estado obsoleto y reconstruye conectividad.

Las pruebas de seguridad generan trafico malicioso o invalido. Incluyen MAC spoofing, IP spoofing, ARP poisoning, telemetria sin HMAC, HMAC invalido y replay por nonce repetido.

Las pruebas de carga usan matrices ICMP y flujos concurrentes entre Smart Meters para verificar que los flows reactivos y los timeouts no degraden la conectividad.

### Criterios de Aceptacion

- El baseline debe mostrar nodos Ready, pods criticos Running, Redis operativo, Smart Meters online y topologia sin elementos stale.

- La conectividad debe funcionar entre Smart Meters no aislados.

- Ante caida de enlace, el camino activo debe cambiar y el ping debe recuperarse por una alternativa.

- Ante caida de nodo, el DPID caido no debe seguir siendo usado como camino activo una vez detectada la falla.

- Tras restauracion, el sistema debe estabilizar sin duplicar guests, enlaces ni flows obsoletos.

- La telemetria no autorizada, mal firmada o repetida debe rechazarse fail-closed.

- La red no debe construir VXLAN full-mesh artificial.

### Evidencias Usadas

- Estado de Kubernetes con `kubectl get nodes` y pods del namespace `sdn-controller`.

- Estado de DaemonSets y rollouts de Ryu, OVS, DHCP y meter collector.

- APIs `/api/sdn-topology`, `/api/sdn-trace`, `/api/stats`, `/api/guests` y `/api/telemetry-security`.

- Claves Redis como `switch:alive:*`, `topology:vxlan_peers`, `topology:guest_locations`, `topology:guest_ips`, `mac_to_port:*` y `switch_ports:*`.

- Logs de Ryu, DHCP y meter collector.

- Metricas Prometheus y paneles Grafana.

- Estado de nodos y enlaces en GNS3.

- Pings continuos entre pares de Smart Meters elegidos segun su camino activo.

### Resultados de Conectividad y Carga

En una validacion previa con 5 Smart Meters, el cluster tenia 7 de 7 nodos K3s Ready. Ryu, OVS initializer, DHCP y meter collector estaban disponibles en 7 de 7 nodos. Redis Sentinel tenia master operativo y replicas sincronizadas. La telemetria mostraba 5 de 5 Smart Meters online.

La matriz ICMP estable entre los 5 Smart Meters completo 20 de 20 pares sin perdida persistente. La latencia media global quedo alrededor de 5 ms. La prueba de carga ejecuto 20 flujos concurrentes, 2000 paquetes totales y 0 por ciento de perdida. Este resultado demostro que la arquitectura podia operar como red SDN distribuida funcional con telemetria y observabilidad activas.

### Resultados de Resiliencia Recientes

La bateria destructiva mas reciente se ejecuto con 7 Smart Meters. Antes de cada caida se eligieron pares cuyo `/api/sdn-trace` atravesaba el enlace o nodo que se iba a fallar. El baseline inicial estaba sano: 7 de 7 nodos Kubernetes Ready, sin pods no Running en `sdn-controller`, 7 de 7 Smart Meters online, 7 de 7 workers o nodos SDN online, topologia de 15 nodos y 26 enlaces, matriz ICMP 42 de 42 OK y nodos GNS3 iniciados.

La caida del enlace `Master-1 <-> SDN-Worker-2` fue aprobada. El par probado fue SM2 hacia SM3. Antes de la caida, el camino pasaba por `2388559800552`, `2584416622385`, `2326098758569` y `3195622440816`. Durante la caida, el camino cambio y uso `2433129235981` como alternativa. El ping previo fue 5 de 5, durante la caida fue 45 de 45 y tras restaurar fue 30 de 30. La perdida fue 0 por ciento. Este es el comportamiento objetivo: el camino cambia y el trafico se mantiene.

La caida de `SDN-Worker-1` fue parcial. El par probado fue SM3 hacia SM4. El trace siguio usando el DPID caido durante la ventana de fallo. El ping durante la caida tuvo 37.7778 por ciento de perdida. Tras restaurar, el sistema recupero baseline, pero aparecieron duplicados y una ventana de failback no limpia. Esto demuestra recuperacion final, pero no reconvergencia estricta.

La caida de `Master-3` fue parcial. El par probado fue SM1 hacia SM4. El trace mantuvo el DPID caido durante la caida. El ping durante la caida tuvo 24.4444 por ciento de perdida. No hubo 503 prolongado en esa ejecucion, pero la perdida y el estado stale indican que la exclusion de nodos caidos aun no era suficientemente rapida.

La caida de `Master-1` fue parcial. El par probado fue SM2 hacia SM3. El trace siguio mostrando el master apagado. El ping durante la caida tuvo 80 por ciento de perdida. Tras restaurar, el ping volvio a 0 por ciento de perdida y el sistema recupero baseline.

El estado final de la bateria fue sano. Kubernetes volvio a 7 de 7 Ready, no quedaron pods no Running en `sdn-controller`, los 7 Smart Meters quedaron online, la topologia volvio a 15 nodos y 26 enlaces, la matriz ICMP final fue 42 de 42 OK y los nodos GNS3 quedaron iniciados.

La conclusion de resiliencia es directa. La caida de enlace cumple el objetivo de reroute automatico. Las caidas de worker, control-plane y master muestran recuperacion final, pero todavia no cumplen el criterio estricto de baja perdida y exclusion inmediata de DPIDs caidos. El siguiente trabajo tecnico debe enfocarse en invalidar mas rapido `switch:alive:*`, excluir switches no vivos en `/api/sdn-trace`, limpiar flows stale con mayor agresividad y reducir ventanas de failback.

### Resultados de Seguridad

Se valido el comportamiento fail-closed de HMAC con un paquete de telemetria sin firma. El contador `invalid_total` subio de `30915` a `30916`, y la razon registrada fue `missing_hmac_fields=1`. La conclusion es que el collector no acepta telemetria sin firma.

La arquitectura tambien contempla pruebas desde la maquina atacante GNS3 para MAC spoofing, IP spoofing y ARP poisoning. Estas pruebas no se validan solo mirando si un paquete pasa. Se validan revisando eventos en Ryu, estado del dispositivo en Redis, contadores de seguridad, logs y dashboard.

### Resultado de VXLAN no Full-Mesh

Se valido que el sistema no construye una malla completa artificial. Con 7 nodos, una malla completa implicaria 6 peers por nodo. Redis mostro 2 a 3 peers por nodo y `missing_peer_entries=[]`. La conclusion es que la topologia VXLAN conserva vecindad real y no full-mesh.

### Evaluacion Final de Pruebas

El proyecto demuestra conectividad distribuida, telemetria segura, observabilidad y recuperacion final ante fallos. La parte mas fuerte es la arquitectura: cada nodo mantiene control local, Redis coordina el estado y la red puede reconstruirse sin intervencion manual en escenarios no particionados.

La limitacion actual esta bien identificada. En caidas completas de nodos, el sistema vuelve, pero puede conservar estado stale durante la ventana de fallo y perder mas paquetes de los aceptables para un objetivo de reconvergencia rapida. Esta conclusion no debilita el informe; lo fortalece, porque esta respaldada por pruebas reales y define con precision el trabajo pendiente.

## Glosario

- AMI: Advanced Metering Infrastructure, infraestructura de medicion inteligente.

- ARP: protocolo que resuelve direcciones IP a direcciones MAC dentro de una red local.

- ARP poisoning: ataque que falsifica asociaciones IP-MAC para redirigir o interceptar trafico.

- BGP: protocolo de routing usado para intercambiar rutas y anunciar prefijos.

- Broadcast: trafico enviado a todos los equipos de un dominio de capa 2.

- Calico: CNI de Kubernetes que puede operar con BGP para distribuir rutas de pods.

- CNI: Container Network Interface, interfaz de red para contenedores en Kubernetes.

- ConfigMap: recurso Kubernetes usado para inyectar configuracion o codigo en pods.

- DaemonSet: recurso Kubernetes que ejecuta una copia de un pod en cada nodo.

- Dataplane: plano que reenvia paquetes segun reglas instaladas.

- DHCP: protocolo de asignacion automatica de direcciones IP.

- Dijkstra: algoritmo de camino mas corto usado para calcular rutas unicast.

- DPID: Datapath ID, identificador unico de un switch OpenFlow.

- ECMP: Equal-Cost Multi-Path, uso de multiples rutas con igual coste.

- Fail-closed: politica donde, ante error o falta de validacion, se deniega el trafico.

- FlowMod: mensaje OpenFlow usado para instalar, modificar o eliminar reglas.

- FRR: Free Range Routing, suite de protocolos de routing como OSPF y BGP.

- GNS3: plataforma de emulacion de redes usada para construir el laboratorio.

- HMAC: codigo de autenticacion basado en hash que valida integridad y autenticidad.

- hostNetwork: modo Kubernetes donde el pod usa directamente la red del nodo.

- K3s: distribucion ligera de Kubernetes.

- kube-vip: componente que expone una IP virtual de alta disponibilidad.

- LLDP: protocolo de descubrimiento de vecinos de capa 2.

- Loki: sistema de agregacion de logs usado junto a Grafana.

- MAC spoofing: suplantacion de una direccion MAC.

- Meter collector: servicio que recibe, valida y almacena telemetria AMI.

- MST: Minimum Spanning Tree, arbol minimo usado para evitar bucles en broadcast.

- Nonce: valor unico usado para evitar repeticion de mensajes.

- OFPP_LOCAL: puerto logico de OVS que entrega paquetes al host local.

- OpenFlow: protocolo usado por Ryu para controlar OVS.

- OSPF: protocolo de routing interior usado para construir el fabric L3.

- OVS: Open vSwitch, switch virtual programable.

- Packet-In: evento enviado por OVS al controlador cuando no existe una regla aplicable.

- Prometheus: sistema de recoleccion de metricas.

- Promtail: agente que envia logs a Loki.

- QEMU/KVM: tecnologia de virtualizacion usada para nodos Ubuntu en GNS3.

- Redis Sentinel: Redis con monitorizacion y failover automatico.

- Ryu: framework SDN en Python usado como controlador.

- Scapy: libreria Python para construir, enviar y capturar paquetes.

- SDN: Software Defined Networking, red definida por software.

- Smart Meter: medidor inteligente simulado que envia telemetria.

- StatefulSet: recurso Kubernetes para servicios con identidad estable y persistencia.

- STP/RSTP: protocolos de arbol de expansion usados para evitar loops de capa 2.

- Telemetria: datos medidos y enviados por los Smart Meters.

- Underlay: red base sobre la que se construye un overlay.

- VXLAN: encapsulacion de capa 2 sobre UDP para extender redes entre nodos.

- VTEP: extremo de un tunel VXLAN.
