FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY app/ app/
COPY registry_client.py .

RUN pip install --no-cache-dir -e .

# /data is a mounted Azure File Share — persists registry.key.pem and registry.db
VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
