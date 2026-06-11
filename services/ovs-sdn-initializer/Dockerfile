FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openvswitch-switch \
        kmod \
        iproute2 \
        iputils-ping \
        curl \
        redis-tools \
        lldpd \
        jq \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
