FROM python:3.9-slim

LABEL maintainer="arturoalvarez"
LABEL description="SDN Meter Collector - Colector de telemetría IoT para red SDN"
LABEL version="1.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/
COPY registry.py /app/
COPY templates/ /app/templates/

# Wrapper entrypoint: borra el bytecode cache residual del build
# de la imagen para que el codigo del ConfigMap siempre sea el
# que se ejecuta (evita .pyc viejos con preferencia).
RUN printf '#!/bin/sh\nrm -rf /app/__pycache__\nexec python -B /app/app.py\n' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh


ENV PYTHONUNBUFFERED=1
ENV FLASK_PORT=5000
ENV UDP_PORT=5555

EXPOSE 5000
EXPOSE 5555/udp

CMD ["/app/entrypoint.sh"]
