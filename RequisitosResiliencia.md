# Requisitos de Resiliencia SDN

## Objetivo Principal

La arquitectura SDN distribuida sobre K3s/GNS3 debe mantener la conectividad entre Smart Meters a pesar de caídas de nodos, enlaces o fallos completos de la topología. El sistema debe detectar el fallo, reconverger automáticamente y restablecer la comunicación sin intervención manual.

## Escenarios de Caída

### 1. Caída de un Control Plane

**1.1 Caída de Master-1 (control-plane primario)**
- Master-1 actúa como nodo principal del cluster y gateway STP hacia `Mgmt-STP-Switch`.
- Al caer, etcd debe mantener quorum con `control-2` y `control-3`.
- Redis Sentinel debe promover una nueva réplica a master.
- Los Ryu controllers en los nodos restantes deben continuar operando.
- STP debe reconverger y otro control-plane debe asumir el rol de gateway.

**1.2 Caída de un control-plane secundario (control-2 o control-3)**
- Menos crítico que la caída de Master-1.
- etcd mantiene quorum con los otros dos control-planes.
- Si el control-plane caído tenía Smart Meters conectados, estos quedan inaccesibles hasta su recuperación.

### 2. Caída de un Worker

- El worker deja de responder heartbeats en Redis (`switch:alive:{dpid}`).
- Ryu detecta la desconexión del switch vía OpenFlow.
- Los Smart Meters conectados al worker caído quedan inaccesibles.
- El fallo debe quedar aislado: si el ping es entre Smart Meters en otros nodos, no debe verse afectado.

### 3. Caída de un Enlace entre Nodos

- LLDP deja de detectar el vecino en el enlace caído.
- STP reconfigura el árbol de spanning.
- `ovs-sdn-initializer` elimina el túnel VXLAN obsoleto.
- Ryu recalcula rutas alternativas usando el grafo de forwarding restante.

### 4. Caída Completa de la Topología (Corte de Electricidad)

- Todos los nodos K3s se apagan simultáneamente.
- Al restaurar energía, los nodos arrancan en orden arbitrario.
- etcd debe formar quorum cuando haya suficientes nodos disponibles.
- Redis Sentinel elige un nuevo master cuando hay quorum.
- Los Ryu controllers se conectan a sus switches locales.
- `ovs-sdn-initializer` reconstruye los túneles VXLAN según LLDP.
- Los Smart Meters obtienen DHCP y reanudan telemetría.
- La recuperación debe ser automática y completa, sin intervención manual.

## Escenario de Pruebas

### Reglas de prueba

- Cada prueba evalúa un solo tipo de caída a la vez. No se mezclan dos escenarios de caída en la misma prueba.
- Solo se cae un nodo a la vez. No se provocan caídas simultáneas de múltiples nodos.
- Debe probarse con pares de Smart Meters distintos para cada escenario de caída, de modo que se cubran diferentes caminos dentro del anillo.
- Para las pruebas de caída de un control plane o de caída de un Smart Meter, el par de Smart Meters elegido para el ping debe tener como camino el nodo que se va a apagar. Esto permite demostrar que el ping se interrumpe ante la caída y se restablece después de que la arquitectura reconverja y genere un nuevo camino para el tráfico. Aplica también al master, ya que el master es un control plane.

### Configuración

- **Smart Meter origen**: Se selecciona un Smart Meter según el escenario a evaluar.
- **Smart Meter destino**: Se selecciona un Smart Meter distinto al origen, ubicado en un nodo diferente.
- **Prueba**: Ping continuo entre ambos Smart Meters.

### Procedimiento

1. Iniciar ping continuo entre el par de Smart Meters seleccionado.
2. Provocar la caída del escenario a evaluar (apagar nodo, cortar enlace, etc.).
3. Observar que el ping se interrumpe ante la caída.
4. Esperar a que la arquitectura reconverja y el ping se restablezca por sí solo.
5. Medir los tiempos de cada fase del proceso:
   - Tiempo desde la caída hasta el primer ping fallido.
   - Tiempo desde la caída hasta que la arquitectura genera un nuevo camino.
   - Tiempo desde la caída hasta que el ping se restablece.

## Limitaciones de la Arquitectura

### Comunicación solo con vecinos físicos

Los nodos solo pueden comunicarse con sus vecinos directos, simulando una arquitectura física real. No se permiten túneles VXLAN multi-salto a través de nodos intermedios.

### Túneles VXLAN solo sobre enlaces STP forwarding

Los túneles VXLAN solo pueden crearse sobre enlaces físicos que STP mantiene en estado `forwarding`. No es realista desplegar túneles VXLAN sobre enlaces que STP ha bloqueado, ya que en una arquitectura real STP garantiza que no haya loops en L2 y bloquear un enlace significa que el tráfico L2 entre esos dos nodos no está permitido por la red física.

### Topología fija de tipo anillo

- La topología física del proyecto GNS3 no puede modificarse.
- No se pueden crear nuevos enlaces entre nodos.
- La topología debe mantener una estructura de tipo anillo dentro del proyecto.

### Conectividad completa entre Smart Meters

- Todos los Smart Meters deben poder comunicarse entre sí.
- La red SDN debe garantizar conectividad completa entre cualquier par de Smart Meters, no solo entre pares específicos de prueba.

### Control planes conectados físicamente

- Los tres control planes (Master-1, control-2 y control-3) deben estar conectados físicamente entre sí dentro del anillo.
- Al menos un control plane debe tener conexión no bloqueada por STP en todo momento, garantizando que siempre exista un gateway STP disponible hacia `Mgmt-STP-Switch`.

## Verificaciones Importantes

### Observabilidad

- Grafana y el panel de operaciones (`:8081`) deben mostrar información real y actualizada del proyecto tras cada reconvergencia.
- No deben aparecer datos stale de nodos o enlaces caídos.
- La telemetría de los Smart Meters debe continuar enviándose al meter-collector y reflejarse en el panel de operaciones.

### Autorización AMI

- La autorización de los Smart Meters debe persistir tras la reconvergencia.
- Los Smart Meters previamente autorizados no deben requerir reautorización después de un fallo.

### Recuperación automática

- La recuperación post-fallo debe ser completamente automática y tolerante a fallos.
- No se debe recurrir a recuperación humana en ningún escenario.
- Basta con que la arquitectura vuelva a funcionar correctamente por sí sola.

### Commit y push

- Los cambios importantes en código o manifiestos deben commitearse y pushearse.

## Pistas y Consideraciones

### Interacción entre STP y VXLAN

Un problema identificado previamente fue que STP bloqueaba ciertos caminos físicos **dentro del anillo SDN** que luego impedían la creación de túneles VXLAN necesarios para la comunicación entre Smart Meters. Esto ocurría porque `ovs-sdn-initializer` solo crea túneles VXLAN sobre enlaces que están en estado `forwarding` según STP. El resultado era que la topología SDN quedaba dividida en 3 segmentos desconectados (master-segmento, control-2-segmento, control-3-segmento) sin posibilidad de comunicación entre ellos.

**Solución aplicada**: Se reconfiguraron los costes STP para que STP **bloquee primero los enlaces hacia el `Mgmt-STP-Switch`** (coste 200) en lugar de bloquear enlaces internos del anillo SDN (coste 4). De esta forma:

- Los enlaces internos del anillo SDN permanecen en `forwarding`, permitiendo que `ovs-sdn-initializer` cree túneles VXLAN entre todos los nodos.
- STP bloquea 2 de 3 enlaces al `Mgmt-STP-Switch`, manteniendo solo 1 activo para garantizar salida a internet/red de gestión.
- Al menos un control plane (master, control-2 o control-3) queda con conexión activa al switch.
- Los túneles VXLAN se crean exclusivamente entre vecinos físicos directos con STP `forwarding`, respetando la regla arquitectónica de no desplegar túneles sobre enlaces bloqueados.

**Costes configurados:**
- `STP_NODE_LINK_COST=4` (enlaces internos del anillo SDN entre nodos K3s)
- `STP_SWITCH_CONTROL_COST=200` (enlaces de control planes hacia Mgmt-STP-Switch)
- `STP_SWITCH_WORKER_COST=200` (enlaces de workers hacia Mgmt-STP-Switch, si los hubiera)
- `STP_UNKNOWN_LINK_COST=80` (enlaces a switches L2 simples sin LLDP)

**Validación de STP**: Se agregó la función `validate_stp_state()` en `ovs-sdn-initializer` que publica el estado de STP a Redis (`topology:stp_state:{dpid}`) y emite alertas cuando:
- El root bridge no es `0000.*` (no es el Mgmt-STP-Switch)
- Ningún puerto está en forwarding
- Un control plane no tiene root port hacia el mgmt-switch

**Tolerancia ante caídas**: Esta configuración debe garantizar la reconvergencia STP cuando un control plane conectado al switch cae. STP debe detectar la pérdida y abrir el camino de otro control plane al switch. Las pruebas de resiliencia validan este comportamiento.

Esta configuración debe mantenerse durante las pruebas de resiliencia para garantizar que la reconvergencia STP no bloquee caminos críticos para la red SDN.

## Resultados de Pruebas de Resiliencia

### Resumen de Escenarios

| Escenario | Descripción | Resultado | Detalles |
|-----------|-------------|-----------|----------|
| 1.1 | Caída Master-1 (control-plane primario) | OK | Ping recupera automáticamente tras failover Redis y reconvergencia STP (~5 min) |
| 1.2 | Caída control-2 (control-plane secundario) | OK | Ping recupera automáticamente (~5 min) |
| 2 | Caída worker-b56b35 | FALLA | Ping no recupera en 500s; arquitectura no reconverge automáticamente cuando el worker caído es parte indispensable del camino |
| 3 | Caída enlace ens5 en worker-b56b35 | FALLA | Ping no recupera en 180s; VXLAN persiste por reachabilidad alterna y no se recalcula ruta |
| 4 | Caída completa (todos los nodos) | OK | Recuperación automática tras ~7 minutos |

### Estado de Conectividad SDN Actual (Jun 2026: nueva arquitectura sin STP)

Tras eliminar STP del plano SDN (`br-sdn`) y reemplazarlo por MST (Prim) + Dijkstra multi-hop + ARP proxy + flood controlado, se verificó conectividad entre nodos y entre Smart Meters:

**Topología VXLAN por nodo (vecinos LLDP, no full mesh):**
- master (192.168.122.100): 4 VXLAN (control-3, worker-b56b35, worker-24cf41, worker-ea7e34)
- control-2 (192.168.122.106): 4 VXLAN (control-3, worker-b0ff27, worker-b56b35, worker-24cf41)
- control-3 (192.168.122.130): 4 VXLAN (control-2, worker-b0ff27, worker-b56b35, worker-24cf41, worker-ea7e34)
- worker-b0ff27 (192.168.122.115): 4 VXLAN (control-2, control-3, worker-b56b35, worker-24cf41, worker-ea7e34)
- worker-b56b35 (192.168.122.145): 4 VXLAN (master, control-2, control-3, worker-b0ff27, worker-24cf41, worker-ea7e34)
- worker-ea7e34 (192.168.122.70): 4 VXLAN (master, control-2, control-3, worker-b0ff27, worker-b56b35)
- worker-24cf41 (192.168.122.170): 4 VXLAN (master, control-2, control-3, worker-b0ff27, worker-b56b35, worker-ea7e34)

Cada nodo crea VXLAN SOLO a sus vecinos LLDP directos (no full mesh). Para alcanzar nodos no-adyacentes, Ryu hace path stitching multi-hop vía Dijkstra sobre el MST. El grafo es disperso (4-6 edges por nodo) y el MST tiene 6 edges (n-1 para 7 nodos).

**Plano de management (br0):** Sigue siendo Linux bridge con STP activo en `Mgmt-STP-Switch` (GNS3) como root. Los nodos K3s ejecutan `gns3-br0-tree.service` (configurable, modo `tree` solo como fallback). STP en `br0` es independiente del plano SDN y previene loops accidentales en el cableado físico de management. NO depende de STP para prevenir loops en el plano SDN (`br-sdn`).

**Pruebas de conectividad entre Smart Meters (Jun 2026):**
- SDNSmartMeter-1 (master, 10.0.0.14) → 10.0.0.11 (control-2): OK (31-60ms, MST flood con duplicados)
- SDNSmartMeter-1 → 10.0.0.19 (otro nodo): OK (5-27ms, ruta directa)
- SDNSmartMeter-1 → 10.0.0.1 (gateway Ryu): OK (<1ms, local en br-sdn)
- Resultados variables para guests en nodos donde Ryu aún está aprendiendo MAC (puede requerir 30-60s tras boot del pod para tener tabla FDB completa)

### Arquitectura del Plano de Control SDN

**Componentes principales en `services/ryu-controller/app.py`:**

1. **TopologyManager** — Lee `topology:links` (SET Redis) con enlaces LLDP descubiertos, construye grafo NetworkX, calcula MST con `nx.minimum_spanning_tree()` (Prim), publica `topology:mst_edges` (6 edges para 7 nodos). Recomputa cada 5s.

2. **ForwardingEngine** — Para cada destino MAC, ejecuta Dijkstra sobre el grafo full, llama `install_path_flows()` que instala flows explícitos en cada hop de la ruta vía `OFPInstructionActions(OFPIT_APPLY_ACTIONS)`. Sin OFPP_FLOOD.

3. **ArpHandler** — Proxy ARP con dedup via ZSET Redis (`topology:arp_dedup` con ventana 5s). Responde por la gateway IP `10.0.0.1` con la MAC del nodo local. Sintetiza ARP replies para guests conocidos.

4. **BroadcastController** — Flood SOLO por puertos MST (no MST edges hacia el mismo nodo origen). Genera `bcast_ports` = VXLAN ports a MST neighbors + ports físicos de guests. Sin OFPP_FLOOD.

5. **EventLinkAdd/Delete** — Handler de `ryu.topology.event` que actualiza `topology:links` y `topology:link_cost` en Redis. Invalida flows hacia peers muertos (conecta a `switch:dead` pub/sub).

**Flujos OpenFlow instalados:**
- Priority 65535: LLDP (dl_dst=01:80:c2:00:00:0e) → CONTROLLER
- Priority 200: ARP hacia 10.0.0.1 → CONTROLLER (para ARP proxy)
- Priority 200: IP hacia 10.0.0.1 → LOCAL (gateway del nodo)
- Priority 10: MAC learning flows (eth_dst → port específico)
- Priority 1: Path stitching flows (multi-hop vía VXLAN)

### Cambios de Implementación Recientes (Jun 2026)

**Eliminar STP del plano SDN:** La nueva arquitectura elimina STP/RSTP del plano `br-sdn` (datos SDN). Los loops se previenen con MST calculado por Ryu en lugar de spanning tree distribuido. `br0` (management) sigue siendo Linux bridge y mantiene STP activo vía `Mgmt-STP-Switch` como root (independiente del plano SDN).

**Topología VXLAN de vecinos LLDP (no full mesh):** Se modificó `deploy/k8s/03-sdn-network.yaml` para que cada nodo cree VXLAN solo a sus vecinos LLDP directos, leyendo `topology:links` de Redis en lugar de `HVALS topology:node_ips`. Esto:
- Reduce túneles de O(n²) a O(n) por nodo
- Permite multi-hop Dijkstra real con path stitching entre 2-3 saltos
- Hace MST computacionalmente eficiente (grafo disperso de 4-6 edges por nodo)
- Escala a >50 nodos sin saturar VXLAN port count

**Servicio STP deshabilitado en nodos K3s:** `gns3-br0-tree.service` queda `disabled` en cada nodo. El script `configure-br0-tree.sh` se mantiene como referencia pero no se ejecuta automáticamente. STP solo existe como fallback determinístico. Ver `AGENTS.md` bullet "VXLAN topology is neighbor-only (LLDP), NOT full mesh".

**Métricas Prometheus nuevas:** `ryu_topology_node_info`, `ryu_topology_edge_info`, `ryu_mst_edges`, `ryu_topology_version`, `ryu_topology_diameter` (cuando grafo conectado). Grafana Node Graph usa estas métricas para visualizar la topología y los paths activos (filtrable por `src_guest` y `dst_guest`).

**Limpieza de Redis legacy:** Eliminadas las keys `topology:stp_state:*` y `topology:br0_stp_ports` (ya no se usan en la nueva arquitectura).

### Análisis de Escenarios Fallidos (Jun 2026: nueva arquitectura)

#### Escenario 2: Caída de Worker

**Problema identificado**: Cuando un worker falla, las entradas `mac_to_port` en otros switches siguen apuntando al túnel VXLAN del worker muerto. Los flujos instalados envían tráfico al peer caído. Los paquetes no generan `packet-in` porque matching flujos existentes, por lo que Ryu nunca recalcula la ruta.

**Solución implementada** (commit `a403fd55`, mejorada en Jun 2026):
- Ryu publica el DPID del switch muerto al canal Redis `switch:dead`
- Todos los Ryu instances suscritos borran sus entradas `mac_to_port` que apuntan al peer muerto
- El handler de flow stats también limpia `mac_to_port` al eliminar flujos hacia peers inactivos
- El monitor detecta switches no responsivos tras 3 fallos consecutivos y transmite proactivamente la muerte
- Packet-in verifica liveness del puerto de salida antes de instalar flujos VXLAN

**Mejora con MST/Dijkstra (Jun 2026)**: Cuando un Ryu publica la muerte de un nodo, todos los Ryu instances recalculan el MST sin ese nodo. Las entradas `topology:mst_edges` se actualizan automáticamente y los flows instalados hacia peers muertos se invalidan. El nuevo Dijkstra encuentra rutas alternativas automáticamente (2-3 saltos típicos en grafo disperso).

#### Escenario 3: Caída de Enlace

**Problema identificado**: Cuando un enlace físico entre dos nodos cae, el túnel VXLAN entre ellos se invalida. El handler `EventLinkDelete` de Ryu debe detectar la caída y actualizar `topology:links`, lo que fuerza un recompute del MST y Dijkstra.

**Comportamiento con nueva arquitectura (Jun 2026):**
1. `EventLinkDelete` se dispara cuando Ryu pierde la adyacencia LLDP
2. Ryu elimina el link de `topology:links` y limpia flows que usaban ese VXLAN
3. MST se recomputa sin ese edge
4. Dijkstra encuentra nuevas rutas (posiblemente vía otros vecinos)
5. Si la nueva ruta no existe (grafo queda desconectado), el tráfico al nodo aislado se trata como destino inalcanzable

**Limitaciones de la topología**: Si el grafo LLDP queda completamente desconectado por la caída de un enlace crítico, algunos nodos quedan aislados del SDN. Esto es aceptable en topología anillo/cadena donde cada enlace es indispensable.

**Interacción con Mgmt-STP-Switch**: Si STP en `br0` re-balancea puertos por una caída, eso afecta la reachability IP de los nodos K3s (no del SDN), pero no impacta directamente la topología SDN porque Ryu ya no depende de STP para el plano de datos.

### Decisiones Arquitectónicas

1. **Propagación de muerte de switch**: Implementada via Redis pub/sub (`switch:dead`). Cuando un switch muere, todas las instancias Ryu limpian sus tablas `mac_to_port` hacia ese switch.

2. **Fallback de flooding**: Cuando se detecta que el puerto de salida es hacia un peer muerto, se cae a flooding en lugar de instalar un flujo inútil.

3. **Monitor de responsividad**: Cada 5 segundos, Ryu envía stats requests a sus switches. Tras 3 fallos consecutivos, se considera el switch muerto y se transmite su muerte.

4. **MST para prevención de loops en el plano SDN**: Ryu calcula un Minimum Spanning Tree (Prim) sobre el grafo de `topology:links` (vecinos LLDP). Broadcast (ARP, DHCP) se hace SOLO por puertos MST edges, no por flooding genérico. Esto previene loops en `br-sdn` sin necesidad de STP.

5. **Path stitching multi-hop (Dijkstra)**: Para tráfico unicast, Ryu corre Dijkstra sobre el grafo LLDP y computa la ruta completa. En cada hop instala un flow explícito `eth_dst=<mac> → output=<puerto al siguiente hop>`. Esto da rutas multi-hop de 2-3 saltos típicos sin necesidad de rutas estáticas o shortest-path bridges.

6. **Topología VXLAN sparse (vecinos LLDP)**: Cada nodo crea VXLAN solo a sus vecinos LLDP directos. Para alcanzar nodos no adyacentes, Ryu hace path stitching multi-hop. Esto evita O(n²) VXLAN tunnels y permite multi-hop real. Ver `AGENTS.md` para la decisión arquitectónica completa.
