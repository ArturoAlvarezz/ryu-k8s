FROM python:3.9-slim

LABEL maintainer="arturoalvarez"
LABEL description="SDN attacker appliance for controlled GNS3 security tests"
LABEL version="1.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    tcpdump \
    libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY attack_menu.py /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/attack_menu.py && \
    ln -s /app/attack_menu.py /usr/local/bin/sdn-attack

ENV ATTACK_IFACE="eth0"
ENV PACKET_COUNT="3"
ENV PACKET_INTERVAL="1"
ENV RANDOMIZE_MACS="true"
ENV GATEWAY_IP="10.0.0.1"
ENV VICTIM_DEVICE_ID="SDN-SmartMeter-1"
ENV VICTIM_MAC="02:42:53:4d:00:01"
ENV VICTIM_IP="10.0.0.11"
ENV GUEST_DST_IP="10.0.0.13"
ENV FORGED_MAC="aa:bb:cc:dd:ee:ff"
ENV FORGED_IP="10.0.0.250"
ENV ARP_MISMATCH_MAC="ca:fe:ca:fe:ca:fe"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/entrypoint.sh"]
