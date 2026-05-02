FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY registry.py seed_devices.json ./

ENTRYPOINT ["python", "/app/registry.py"]
