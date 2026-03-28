FROM python:3.10-slim

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código fuente
COPY . .

# Exponer el puerto
EXPOSE 5000

# Utilizar gunicorn para un servidor en producción
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
