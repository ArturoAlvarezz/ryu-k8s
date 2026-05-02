# Guía: Máquina de Ataques GNS3 para SDN

Esta guía explica cómo configurar y conectar un nodo de ataque dentro de la topología GNS3 de nuestro laboratorio SDN. Esta máquina será utilizada para simular amenazas como MAC Spoofing, IP Spoofing y ARP Poisoning y validar la seguridad del controlador Ryu.

## 1. Requisitos de la Imagen en GNS3
Para simular el ataque se recomienda utilizar un nodo que cuente con Python y acceso a paquetes de red.
Recomendación: **Ubuntu Server (QEMU)** o **Ubuntu Desktop (QEMU)**.

1. En GNS3, ve a *Edit -> Preferences -> QEMU VMs*.
2. Crea un nuevo template usando una imagen de Ubuntu (puedes descargar el appliance oficial `.gns3a` desde el marketplace de GNS3 o usar una imagen `.qcow2`).
3. Dale permisos de red asegurándote de asignarle al menos 1 interfaz.

## 2. Conexión a la Topología SDN
1. Arrastra el nuevo nodo Ubuntu (llamémoslo "Attacker") al canvas de GNS3.
2. Conecta su interfaz `eth0` a un puerto de uno de los switches Open vSwitch (OVS) que represente la red de acceso de los Smart Meters (dentro de un nodo K3s).
   - *Nota:* Asegúrate de conectarlo a la misma red puente `br-sdn` si estás usando el host directo, o al switch correspondiente que mapea a la SDN.
3. Inicia el nodo.

## 3. Preparación del Entorno de Ataque
Abre la consola del nodo "Attacker" e instala las dependencias necesarias. Dado que Scapy requiere privilegios para forjar paquetes crudos, ejecutaremos todo como `root`.

```bash
# Actualizar repositorios e instalar dependencias
apt-get update
apt-get install -y python3 python3-pip tcpdump
apt-get install -y build-essential python3-dev libpcap-dev

# Si hay problemas con pip (entornos manejados externamente), usa venv:
python3 -m venv /opt/attack-env
source /opt/attack-env/bin/activate

# Instalar Scapy
pip3 install scapy
```

## 4. Obtención de Credenciales Legítimas
Para realizar ataques de suplantación, necesitas una IP y una MAC válidas. Puedes capturar tráfico usando `tcpdump` para ver qué MACs están transmitiendo en la red:

```bash
tcpdump -i eth0 -n -e
```
*Identifica la MAC y la IP de un Smart Meter legítimo en el rango `10.0.0.x/24`.*

## 5. Carga y Ejecución del Script
1. Transfiere el archivo de pruebas de la raíz de nuestro repositorio (`tools/gns3/test_security_threats.py`) hacia el nodo "Attacker". Puedes hacerlo copiando y pegando el código mediante `vi test_security_threats.py`.
2. Otorga permisos de ejecución:
   ```bash
   chmod +x test_security_threats.py
   ```

3. Ejecuta el script pasándole la MAC y la IP legítima que observaste en el paso 4:
   ```bash
   python3 test_security_threats.py 02:42:XX:XX:XX:XX 10.0.0.Y
   ```

## 6. Validación de Resultados
El script simulará cuatro tipos de tráfico:
1. **Tráfico Legítimo**: Debería fluir correctamente (aunque si tu nodo de ataque está en un switch distinto al que originalmente se registró esa MAC, fallará por seguridad).
2. **MAC Spoofing**: Bloqueo inmediato al detectar una MAC no registrada.
3. **IP Spoofing**: El controlador detectará la inconsistencia entre la IP forjada y la MAC.
4. **ARP Poisoning**: El switch bloqueará los paquetes ARP que intenten envenenar la tabla anunciando la IP del gateway (`10.0.0.1`).

Puedes corroborar las acciones de bloqueo mirando el dashboard de Grafana de la infraestructura o directamente desde la CLI de Kubernetes:
```bash
kubectl logs -n sdn-controller -l app=ryu --tail=100 | grep DETECTED
```
