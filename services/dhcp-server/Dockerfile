FROM python:3.9-slim

# Scapy requires some underlying tcpdump and libpcap dependencies for sniffer
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/

# Disable python buffering for better logging
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
