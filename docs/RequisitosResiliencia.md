# Requisitos de Resiliencia SDN

## Objetivo Principal

La arquitectura SDN distribuida sobre K3s/GNS3 debe mantener la conectividad entre Smart Meters ante caídas de nodos, enlaces o fallos completos del laboratorio. El sistema debe detectar cambios físicos o lógicos, reconstruir el dataplane y restablecer conectividad sin intervención manual.

## Arquitectura Actual

- El plano de gestión/fabric de K3s es un **fabric L3 enrutado** (FRR/OSPF *unnumbered* + loopbacks `/32` derivadas de `machine-id`, montado por `fabric-bootstrap.service`). OSPF da alcanzabilidad + ECMP (es el failover); ya no hay `br0`, ni árbol `ACTIVE_BR0_PORTS`, ni daemons de failover L2.
- `br-sdn` es el dataplane de guests AMI. Es un OVS controlado por Ryu local en cada nodo mediante `tcp:127.0.0.1:6653`.
- Los túneles VXLAN se crean solo hacia vecinos directos del fabric (vecinos OSPF de 1 salto); el VTEP es la loopback del nodo. No se permite malla completa.
- Ryu calcula MST para broadcast controlado y Dijkstra para tráfico unicast multi-hop entre Smart Meters.
- Redis Sentinel mantiene estado compartido de topología, MAC learning, leases DHCP, seguridad AMI y telemetría.

## Ejecución de Pruebas

Las pruebas de resiliencia serán ejecutadas por agentes de IA con acceso al laboratorio. Cada agente debe registrar comandos, timestamps, evidencias antes/después y resultado final.

Las evidencias mínimas por prueba son:

- Estado de nodos K3s y pods en `sdn-controller`.
- Ping continuo entre Smart Meters seleccionados.
- `/api/sdn-topology`, `/api/stats`, `/api/guests` y `/api/telemetry-security`.
- Redis keys relevantes: `switch:alive:*`, `topology:vxlan_peers`, `topology:mst_edges`, `topology:guest_locations` y `mac_to_port:*`.
- Logs de Ryu, DHCP y meter-collector alrededor del fallo.
- Captura del tiempo de interrupción y del tiempo de recuperación.

## Reglas de Prueba

- Cada prueba evalúa un solo tipo de caída a la vez.
- No se mezclan dos escenarios de fallo en la misma prueba.
- El par de Smart Meters debe elegirse para que el fallo afecte el camino cuando sea posible.
- Si un Smart Meter queda conectado al nodo apagado, ese medidor se considera fuera de servicio; el criterio de aceptación aplica a los Smart Meters ubicados en nodos restantes.
- Las pruebas deben confirmar que no se crean túneles VXLAN full-mesh tras la reconvergencia.
- La recuperación se considera válida solo si la conectividad, la telemetría y el estado de seguridad coinciden con la topología activa.

## Escenarios de Caída

| Escenario | Comportamiento Esperado | Criterio de Aceptación |
| --- | --- | --- |
| Caída de enlace físico | LLDP deja de anunciar el vecino, `ovs-sdn-initializer` retira el VXLAN obsoleto, Ryu recalcula MST/Dijkstra. | El ping entre Smart Meters no aislados se restablece automáticamente por un camino alternativo. |
| Recuperación de enlace físico | LLDP vuelve a descubrir el vecino, se recrea el VXLAN directo y Ryu recalcula rutas. | El camino preferente vuelve a estar disponible sin pérdida permanente de conectividad. |
| Apagado de worker | Expira `switch:alive`, se limpian entradas obsoletas y Ryu omite el switch caído. | Smart Meters en nodos restantes siguen comunicándose; los guests del worker caído aparecen offline. |
| Encendido de worker | El nodo se une al cluster, arranca OVS/Ryu local, publica heartbeat y crea VXLAN a vecinos LLDP. | El switch vuelve a la topología y puede transportar tráfico. |
| Apagado de control-plane secundario | etcd mantiene quorum, Redis Sentinel conserva disponibilidad y los DaemonSets siguen operando en nodos restantes. | El plano de datos no pierde conectividad global entre Smart Meters no aislados. |
| Encendido de control-plane secundario | El nodo sincroniza etcd, Redis, Ryu, OVS y telemetría. | Los servicios vuelven a estado balanceado y la topología refleja el nodo recuperado. |
| Apagado del master principal | El cluster mantiene quorum con los control-plane restantes y el VIP/API siguen disponibles si hay quorum. | Servicios de control y telemetría siguen operando desde los otros control-plane. |
| Encendido del master principal | El master se reincorpora y sincroniza estado actual. | El cluster se estabiliza sin duplicación de servicios ni conflictos de red. |
| Blackout general | Todos los nodos se apagan y luego arrancan en orden arbitrario. | La red SDN se reconstruye desde cero, Redis Sentinel elige master, los medidores obtienen DHCP y la telemetría vuelve en tiempo prudente. |

## Verificaciones Importantes

### Observabilidad

- Grafana debe mostrar métricas, logs y salud de servicios actualizados.
- La Web de Operaciones SDN AMI (`:8081`) debe mostrar topología, guests, estado de seguridad y trazado de caminos real.
- No deben persistir nodos, enlaces o guests obsoletos como activos.

### Autorización AMI

- Los Smart Meters autorizados deben mantener su autorización tras reconvergencias.
- Los Smart Meters bloqueados o en cuarentena no deben poder publicar telemetría aceptada.
- Los rechazos deben quedar reflejados en `/api/telemetry-security`.

### Recuperación Automática

- No se debe recurrir a recuperación humana durante la prueba, salvo para iniciar la caída o restaurar energía/cableado físico.
- La arquitectura debe volver a funcionar correctamente por sí sola.
- Si el grafo físico queda particionado, se acepta pérdida de conectividad solo entre particiones sin camino físico disponible.

## Resultado Esperado del Informe de Agente IA

Cada agente debe entregar un resumen con:

- Escenario ejecutado.
- Smart Meters origen/destino.
- Comandos usados.
- Tiempo hasta el primer fallo observado.
- Tiempo hasta reconvergencia.
- Estado final de ping, topología, telemetría y seguridad.
- Problemas encontrados y evidencia textual suficiente para reproducirlos.
