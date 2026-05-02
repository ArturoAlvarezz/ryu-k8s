FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY registry.py ./
COPY web.py ./
COPY templates ./templates

EXPOSE 5000

ENTRYPOINT []
CMD ["gunicorn", "-b", "0.0.0.0:5000", "web:app"]
