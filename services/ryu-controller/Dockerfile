FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install OS dependencies just in case (optional, but good practice for eventlet/ryu C extensions if any)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
# Ryu depends on an old setuptools feature removed in 58.0.0+
RUN pip install --no-cache-dir "setuptools<58.0.0"
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Ryu application source code
COPY app.py .

# Expose OpenFlow ports
EXPOSE 6653
EXPOSE 6633

# Environment variables for Redis connection (defaults)
ENV REDIS_HOST="redis"
ENV REDIS_PORT="6379"

# Entrypoint for running the custom Ryu application
ENTRYPOINT ["ryu-manager", "app.py"]
