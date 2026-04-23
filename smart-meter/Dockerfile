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
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Variables de entorno por defecto
ENV DEVICE_ID=""
ENV COLLECTOR_IP="255.255.255.255"
ENV COLLECTOR_PORT="5555"
ENV REPORT_INTERVAL="5"
ENV PYTHONUNBUFFERED=1

# Puerto de información (no escucha, solo documentación)
EXPOSE 5555/udp

ENTRYPOINT ["/entrypoint.sh"]
