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

Un problema identificado previamente fue que STP bloqueaba ciertos caminos físicos que luego impedían la creación de túneles VXLAN necesarios para la comunicación entre Smart Meters. Esto ocurría porque `ovs-sdn-initializer` solo crea túneles VXLAN sobre enlaces que están en estado `forwarding` según STP.

**Solución aplicada**: Se configuraron los costes STP para privilegiar las conexiones de los control planes hacia `Mgmt-STP-Switch` (coste 20) sobre las conexiones de los workers (coste 40). De esta forma, STP prefiere mantener activos los enlaces de los control planes y bloquea preferentemente enlaces entre workers, reduciendo la cantidad de túneles VXLAN bloqueados y mejorando la conectividad general entre Smart Meters.

Esta configuración debe mantenerse durante las pruebas de resiliencia para garantizar que la reconvergencia STP no bloquee caminos críticos para la red SDN.
