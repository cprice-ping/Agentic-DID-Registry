FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY app/ app/
COPY registry_client.py .
COPY operator_cli.py .

RUN pip install --no-cache-dir -e .

# Mount persistent storage at /data for registry.key.pem, registry.db, and
# operator_jwks.json — any host works (cloud volume, k8s PVC, bind mount).
VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
