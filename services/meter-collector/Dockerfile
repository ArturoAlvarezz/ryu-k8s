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
COPY templates/ /app/templates/

ENV PYTHONUNBUFFERED=1
ENV FLASK_PORT=5000
ENV UDP_PORT=5555

EXPOSE 5000
EXPOSE 5555/udp

CMD ["python", "app.py"]
