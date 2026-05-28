FROM python:3.9-alpine

LABEL maintainer="arturoalvarez"
LABEL description="SDN Smart Meter - Simulador de Medidor IoT para GNS3"
LABEL version="1.0"

# Instalar dependencias de red:
# - iproute2: comandos `ip` para gestión de interfaces
# - busybox-extras: incluye udhcpc para cliente DHCP
# - bash / sh: ya incluido en Alpine
RUN apk add --no-cache \
    iproute2 \
    busybox-extras \
    tcpdump \
    iputils

WORKDIR /app

# Sin dependencias externas (solo stdlib)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/
COPY meter_test.py /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/meter_test.py && \
    ln -s /app/meter_test.py /usr/local/bin/meter-test

# Variables de entorno por defecto
ENV DEVICE_ID=""
ENV COLLECTOR_IP="10.0.0.1"
ENV COLLECTOR_PORT="5555"
ENV REPORT_INTERVAL="5"
ENV PEER_IPS=""
ENV PEER_API_PORT="8080"
ENV PEER_ECHO_PORT="5560"
ENV PYTHONUNBUFFERED=1

# Puertos documentados: telemetría, API diagnóstico y UDP echo entre medidores.
EXPOSE 5555/udp
EXPOSE 5560/udp
EXPOSE 8080/tcp

ENTRYPOINT ["/entrypoint.sh"]
