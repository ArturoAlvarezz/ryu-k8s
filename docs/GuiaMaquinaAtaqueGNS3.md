# Guia: Maquina de Ataques GNS3 para SDN

Esta guia describe como crear una maquina atacante dentro de la topologia GNS3 del laboratorio SDN y como ejecutar pruebas controladas de MAC spoofing, IP spoofing y ARP poisoning. El objetivo no es dejar trafico malicioso permanente, sino validar que el plano de seguridad rechaza fuentes no autorizadas y documentar que protecciones aun faltan en Ryu.

## 1. Imagen Recomendada

La prueba mas reciente uso un nodo Docker de GNS3, no una VM QEMU pesada. La imagen usada fue `arturoalvarez/ryu-dhcp:latest` porque ya esta disponible localmente y trae Python 3.9 con Scapy instalado.

Se creo un template GNS3 llamado `SDN-Attacker` con estas propiedades:

```text
template_type: docker
image: arturoalvarez/ryu-dhcp:latest
adapters: 1
console_type: telnet
start_command: sleep infinity
```

No se recomienda usar el template `Ubuntu Docker Guest` sin preparacion adicional. En la prueba real ese contenedor no traia Python y no podia instalar paquetes desde Internet porque queda dentro de la red aislada de GNS3.

## 2. Creacion del Nodo Atacante

La maquina creada fue:

```text
nombre: SDN-Attacker-1
template: SDN-Attacker
node_id: b4f0473a-c223-4cfe-9296-958740d46bb3
container_id: 9afeadfc4e9fbbbb66d7ee92a66a3a671e6297facf8a29d13ecd4cfcb288671f
imagen: arturoalvarez/ryu-dhcp:latest
```

Se conecto a un puerto libre del nodo `SDN-ControlPlane-1`:

```text
SDN-Attacker-1:eth0 <-> SDN-ControlPlane-1:Ethernet4
link_id: a6c9194d-7890-4dfb-a773-9e741c007c2a
```

En el host `master`, ese puerto aparece en OVS como `ens7` y OpenFlow lo ve como puerto `3` en `br-sdn`. El Smart Meter 1 esta en `ens8`, puerto OpenFlow `4`.

Comprobacion usada:

```bash
python3 tools/gns3/ssh_k3s.py 'kubectl exec -n sdn-controller ovs-sdn-initializer-wxbmf -- ovs-vsctl list-ports br-sdn'
python3 tools/gns3/ssh_k3s.py 'kubectl exec -n sdn-controller ovs-sdn-initializer-wxbmf -- ovs-ofctl -O OpenFlow13 show br-sdn'
```

## 3. Preparacion del Atacante

Verificar que el contenedor tenga Python, Scapy e interfaz activa:

```bash
docker exec 9afeadfc4e9fbbbb66d7ee92a66a3a671e6297facf8a29d13ecd4cfcb288671f sh -lc 'python3 --version; python3 -c "import scapy; print(scapy.__version__)"; ip addr show eth0'
```

Resultado esperado:

```text
Python 3.9.x
Scapy 2.5.x
eth0 UP con MAC 02:42:f0:47:3a:00
```

El atacante no necesita obtener IP por DHCP para forjar paquetes con Scapy. De hecho, para estas pruebas se enviaron tramas L2 crudas con IP origen falsa.

## 4. Baseline Antes de Atacar

Antes de ejecutar ataques, confirmar que el lab esta sano:

```bash
python3 tools/gns3/ssh_k3s.py 'kubectl get nodes --no-headers'
python3 tools/gns3/ssh_k3s.py 'kubectl get pods -n sdn-controller --field-selector=status.phase!=Running'
curl -s http://192.168.122.10:8081/api/guests
curl -s http://192.168.122.10:8081/api/sdn-topology
curl -s http://192.168.122.10:8081/api/telemetry-security
```

Baseline de la ejecucion documentada:

```text
Kubernetes: 7/7 Ready
Pods no Running en sdn-controller: ninguno
Smart Meters: 7/7 online
Topologia: 15 nodes / 26 edges
ICMP Smart Meters: 42/42 OK
```

## 5. Ejecucion de Ataques

Las pruebas se ejecutaron con Scapy desde `SDN-Attacker-1`. Para probar la autorizacion del collector, algunos paquetes se firmaron con HMAC valido usando el secreto de Kubernetes leido en runtime. No se debe guardar el secreto en archivos, scripts versionados ni documentacion.

La idea de cada ataque fue:

- MAC spoofing: enviar telemetria UDP desde una MAC falsa `aa:bb:cc:dd:ee:ff`.

- IP spoofing: enviar telemetria con IP origen falsa, por ejemplo `10.0.0.250`, o con combinaciones incoherentes de IP/device_id.

- ARP poisoning: enviar ARP reply falso anunciando que `10.0.0.1` esta asociado a la MAC del atacante `02:42:f0:47:3a:00`.

Para medir resultados, se reviso principalmente:

```bash
curl -s http://192.168.122.10:8081/api/telemetry-security
curl -s http://192.168.122.10:8081/api/guests
python3 tools/gns3/ssh_k3s.py 'kubectl logs -n sdn-controller -l app=ryu --since=20m --prefix | grep -Ei "spoof|poison|security|DETECTED|blocked" || true'
```

## 6. Resultados Observados

### MAC Spoofing

Con MAC falsa e IP no observada, el collector rechazo la telemetria como `source_not_observed`. Esto significa que una fuente que no existe en `topology:guest_ips` no puede inyectar telemetria aunque el HMAC sea valido.

Hallazgo importante: cuando se forjo una MAC L2 falsa pero se uso una IP origen y `device_id` legitimos con HMAC valido, no hubo bloqueo L2 especifico. Esto ocurre porque el collector valida segun `source_ip` observada en Redis, no segun la MAC Ethernet real del paquete, y porque en Ryu las funciones `_evaluate_security_threats`, `_record_security_event` y `_drop_guest_packet` estan actualmente como stubs.

Conclusion: el sistema bloquea fuentes no observadas, pero no implementa todavia anti-MAC-spoofing efectivo en Ryu.

### IP Spoofing

Con IP origen falsa no observada, el contador `source_not_observed` aumento.

Con combinaciones incoherentes de identidad e IP se observaron eventos `ip_mismatch`. Durante la prueba, el auto-registro del collector llego a actualizar temporalmente `security:device:SDN-SmartMeter-1` con la IP falsa `10.0.0.250`. Esto dejo a SM1 en `ip_mismatch` hasta que se restauro el registro a `10.0.0.11`.

Conclusion: el collector detecta inconsistencias de origen, pero el auto-registro debe endurecerse para no aceptar actualizaciones provocadas por trafico spoofeado.

### ARP Poisoning

El ARP poisoning no genero eventos de seguridad en Ryu ni en el collector. Esto es consistente con el codigo actual: Ryu procesa ARP para aprendizaje/proxy/flood control, pero la logica explicita de deteccion de poisoning esta desactivada.

Conclusion: ARP poisoning sigue siendo una brecha pendiente en el plano L2. Debe implementarse validacion ARP en Ryu comparando `hwsrc`, `psrc`, `in_port`, DHCP leases y registro de seguridad.

## 7. Limpieza Posterior

Despues de ejecutar ataques, limpiar cualquier estado temporal del atacante:

```bash
python3 tools/gns3/ssh_k3s.py 'MASTER=$(kubectl exec redis-0 -c sentinel -n sdn-controller -- redis-cli -p 26379 sentinel get-master-addr-by-name mymaster | sed -n "1p"); kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli -h $MASTER HDEL topology:guest_ips 02:42:f0:47:3a:00 aa:bb:cc:dd:ee:ff; kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli -h $MASTER HDEL topology:guest_locations 02:42:f0:47:3a:00 aa:bb:cc:dd:ee:ff; kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli -h $MASTER HDEL topology:guest_names 02:42:f0:47:3a:00 aa:bb:cc:dd:ee:ff; kubectl exec redis-0 -c redis -n sdn-controller -- redis-cli -h $MASTER HDEL mac_to_port:2326098758569 02:42:f0:47:3a:00 aa:bb:cc:dd:ee:ff'
```

Si el auto-registro altera un Smart Meter legitimo, restaurar su entrada. Para SM1, la restauracion usada fue:

```json
{
  "device_id": "SDN-SmartMeter-1",
  "mac": "02:42:53:4d:00:01",
  "ip": "10.0.0.11",
  "role": "smart_meter",
  "allowed_dst_ip": "10.0.0.1",
  "allowed_udp_port": 5555,
  "status": "authorized",
  "dpid": "2326098758569",
  "in_port": "4"
}
```

Enviar ese JSON a:

```bash
curl -X POST http://192.168.122.10:8081/api/devices \
  -H 'Content-Type: application/json' \
  --data '<json>'
```

Luego validar:

```bash
curl -s http://192.168.122.10:8081/api/guests
curl -s http://192.168.122.10:8081/api/sdn-topology
curl -s http://192.168.122.10:8081/api/stats
```

Estado final de la ejecucion documentada:

```text
Kubernetes: 7/7 Ready
Pods no Running en sdn-controller: ninguno
Smart Meters: 7/7 online y authorized
Topologia: 15 nodes / 26 edges
ICMP Smart Meters: 42/42 OK
GNS3: SDN-Attacker-1 started, sin enlaces suspendidos
```

## 8. Trabajo Pendiente

Los ataques muestran que la seguridad de telemetria funciona para fuentes no observadas y desajustes de identidad, pero falta proteccion L2 real en Ryu.

Acciones recomendadas:

- Implementar `_evaluate_security_threats` en Ryu.

- Bloquear MAC no registrada por `dpid/in_port` antes de instalar flows.

- Validar ARP con DHCP leases, `topology:guest_ips`, `topology:guest_locations` y registro de seguridad.

- Evitar que `sync_security_identity` actualice dispositivos autorizados usando trafico spoofeado.

- Registrar eventos explicitos de `mac_spoofing`, `ip_spoofing` y `arp_poisoning` para Grafana/Loki.

## 9. Estado tras endurecimiento (anti-spoofing implementado)

Las brechas de la seccion 6/8 ya estan corregidas. Resumen de lo implementado:

### 9.1 Ryu (`services/ryu-controller/app.py`)

`_evaluate_security_threats` ahora valida cada paquete que entra por un puerto
de **guest** (se eximen overlay VXLAN, puerto `LOCAL` del bridge y MACs de
worker/infra; el DHCP DISCOVER/REQUEST/REPLY se permite aunque la MAC no este
registrada). La validacion ocurre **antes** de aprender MAC/ubicacion en Redis,
de modo que el trafico spoofeado ya no envenena `mac_to_port`,
`topology:guest_ips` ni `topology:guest_locations`.

Un paquete que falla la validacion genera un evento de seguridad y un **drop
flow** de alta prioridad (`priority=220`, `hard_timeout=60s`, match
`in_port + eth_src`) que silencia el Packet-In repetido y caduca solo para
re-evaluar. Razones emitidas (`security:event_counter:{reason}`):

| Razon | Disparador |
|-------|-----------|
| `arp_mac_mismatch` | ARP con `hwsrc` != `eth.src` |
| `arp_gateway_spoof` | ARP que reclama el gateway `10.0.0.1` desde un guest |
| `arp_ip_mismatch` | ARP cuya `psrc` no corresponde al MAC/lease registrado |
| `ip_claim_conflict` | IPv4 origen que pertenece a OTRO Smart Meter registrado |
| `ip_mismatch` | MAC registrada usando una IP != su IP registrada |
| `mac_not_registered` | MAC no registrada hablando L3 por un puerto de guest |
| `mac_location_mismatch` | MAC registrada vista en `dpid/in_port` incorrecto |
| `status_blocked` / `status_quarantined` | dispositivo no `authorized` |

Eventos persistidos en Redis: lista `security:events` (recortada a 500),
contadores `security:event_counter:{reason}` y `:total`, y hash
`security:last_event`. Metricas Prometheus nuevas: `ryu_security_events_total`
y `ryu_security_events_by_type_total{type=...}` (nombre/label que consume el
panel "Eventos de Seguridad (por tipo)" del dashboard en `06-observability.yaml`;
scrapeadas en `:8000/metrics`, agregadas con `sum by (type)`; los logs
`SECURITY BLOCK ...` quedan en Loki). **OJO**: los contadores son in-memory por
pod y los emite el Ryu **dueno del datapath del atacante** (el pod conectado al
OVS de ese switch, no necesariamente el nodo donde esta el puerto fisico); como
todos los pods exportan metricas, Grafana los agrega bien. Se reinician al
reiniciar el pod (igual que `ryu_packet_in_total`); el panel usa `rate()`.

Flags de entorno: `SECURITY_ENFORCE` (default `true`), `SECURITY_LEARNING_MODE`
(solo registra, no instala drops), `SECURITY_ENFORCE_LOCATION` (default `true`),
`SECURITY_DROP_HARD_TIMEOUT`, `SECURITY_TELEMETRY_GUARD` (default `true`).

#### Guard de telemetria guest->gateway (cierre del MAC-spoofing en telemetria)

Problema: el `ovs-sdn-initializer` instala `priority=200,ip,nw_dst=10.0.0.1
actions=LOCAL`, que entrega la telemetria al host (collector) **sin Packet-In**.
Asi, una telemetria con MAC Ethernet falsa (`aa:bb:cc:dd:ee:ff`) pero IP/device_id
legitimos de SM1 (`10.0.0.11`, `SDN-SmartMeter-1`) y HMAC valido **nunca pasaba
por Ryu**: el collector solo ve la `source_ip` (que mapea a SM1) y la aceptaba.

Fix: Ryu instala en cada **puerto de guest** un flow de DESVIO
`priority=210,udp,nw_dst=10.0.0.1,tp_dst=5555 actions=CONTROLLER`
(`_install_telemetry_guard`, llamado en `switch_features`, `port_desc_stats` y
`port_status`). La telemetria al gateway ahora hace Packet-In y pasa por
`_evaluate_security_threats`:

- **Legitima** (MAC/IP/ubicacion registradas): se entrega al host por `LOCAL` y se
  instala un flow de *allow* por fuente
  (`priority=220,in_port,eth_src,udp,nw_dst=10.0.0.1,tp_dst=5555 -> LOCAL`,
  `idle_timeout=60s`) para que las siguientes lecturas no vuelvan al controlador.
- **Spoofeada**: se bloquea (p.ej. `ip_claim_conflict`) + drop flow `priority=220`
  y NO se entrega al collector.

Solo se desvia UDP a `10.0.0.1:5555` desde puertos guest; el resto del trafico al
gateway sigue por el flow `LOCAL` original. Esto NO rompe la telemetria legitima
(validado: 7/7 Smart Meters online tras el cambio).

### 9.2 meter-collector (`services/meter-collector/app.py`)

`sync_security_identity` y `_register_observed_meter` ya **no** mutan la
identidad de un dispositivo `authorized` basandose solo en trafico recibido.
La **MAC registrada es el ancla de confianza** (alta manual, determinista por
hostname): solo se refresca IP/ubicacion cuando la MAC observada en el binding
L2 coincide con la registrada (caso real de VM recreada / IP nueva por DHCP).
Cualquier discrepancia se registra como rechazo (`identity_conflict` /
`identity_unverified`) en el mismo stream `security:events` y NO muta
`security:device:*` ni los indices `security:ip_to_device:*` /
`security:mac_to_device:*`. Sin Redis se mantiene fail-closed (no muta).

Esto cierra el bug critico donde una telemetria spoofeada movia
`security:device:SDN-SmartMeter-1` a `10.0.0.250`.

### 9.3 Re-test

```bash
# Desde el atacante (distinta MAC por vector para no auto-silenciarse):
docker exec <attacker_container> python3 - < tools/gns3/test_security_threats.py   # iface eth0

# Observar eventos:
python3 tools/gns3/ssh_k3s.py 'kubectl exec -n sdn-controller redis-0 -c redis -- redis-cli -p 6379 LRANGE security:events 0 9'
python3 tools/gns3/ssh_k3s.py 'kubectl logs -n sdn-controller -l app=ryu --since=5m --prefix | grep SECURITY'
curl -s http://192.168.122.100:8000/metrics | grep ryu_security_events
```

Resultado esperado: cada vector incrementa su `security:event_counter:{reason}`,
`security:device:SDN-SmartMeter-1` permanece con `ip=10.0.0.11`, la MAC del
atacante NO aparece en `topology:guest_ips`/`guest_locations`, y el baseline se
mantiene (7/7 Smart Meters online y `authorized`, ICMP 42/42, topologia 15/26).

### 9.4 Resultados observados (re-test 2026-06-23)

`SDN-Attacker-1` quedo conectado a la misma `br-sdn` que SM1
(`dpid=2326098758569`, `in_port=3`; SM1 en `in_port=4`), manejada por Ryu en
`control-3`. Los 6 vectores fueron **bloqueados** (`enforced: true`):

| Vector | Razon emitida | Detalle |
|--------|---------------|---------|
| SM2 desde puerto del atacante | `mac_location_mismatch` | expected_dpid 2388559800552 vs observed 2326098758569 |
| SM1 MAC + IP `10.0.0.250` | `ip_mismatch` | expected_ip 10.0.0.11, device SDN-SmartMeter-1 |
| MAC ajena + IP de SM1 | `ip_claim_conflict` | ip_owner SDN-SmartMeter-1 |
| MAC desconocida + `10.0.0.240` | `mac_not_registered` | — |
| ARP psrc `10.0.0.1` | `arp_gateway_spoof` | — |
| ARP hwsrc != eth.src | `arp_mac_mismatch` | hwsrc ca:fe... vs eth 12:34... |

**Nota de datapath (actualizada):** el trafico IP generico al gateway sigue
yendo a `LOCAL` por el flow `priority=200`; pero la **telemetria** (`udp:5555 ->
10.0.0.1`) desde puertos guest ahora se DESVIA al controlador por el guard de
telemetria (`priority=210 -> CONTROLLER`, ver 9.1), de modo que Ryu valida su MAC
Ethernet real. Por eso la MAC-spoof de telemetria hacia `10.0.0.1` ya se bloquea
en Ryu (defensa en profundidad junto al collector), no solo en el collector.

Re-test especifico de la brecha (MAC `aa:bb:cc:dd:ee:ff` + IP `10.0.0.11` +
`device_id=SDN-SmartMeter-1` a `10.0.0.1:5555`): Ryu emite
`SECURITY BLOCK reason=ip_claim_conflict src_mac=aa:bb:cc:dd:ee:ff src_ip=10.0.0.11
ip_owner=SDN-SmartMeter-1 enforced=true`, instala `priority=220,in_port=3,
dl_src=aa:bb:cc:dd:ee:ff actions=drop`, y la telemetria NO llega al collector.

Estado post-ataque verificado:

- `security:device:SDN-SmartMeter-1` intacto (`ip=10.0.0.11`).
- `security:ip_to_device:10.0.0.250` inexistente (sin mutacion).
- MACs `02:42:f0:47:3a:00`, `aa:bb:cc:dd:ee:ff`, `de:ad:be:ef:00:99` ausentes de
  `topology:guest_ips`; ubicacion de SM2 sin secuestrar (`2388559800552:4`).
- Baseline: Kubernetes 7/7 Ready, 0 pods no-Running, Smart Meters 7/7 online y
  `authorized`, topologia 15/26, ICMP 42/42 OK, GNS3 sin enlaces suspendidos.
