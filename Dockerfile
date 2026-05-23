FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY app.py /app/app.py

RUN mkdir -p /data

ENV PORT_INVENTORY_DIR=/data
ENV PORT_INVENTORY_DB=/data/port_inventory.sqlite3
ENV PORT_INVENTORY_HOST=0.0.0.0
ENV PORT_INVENTORY_PORT=8710

CMD ["python", "/app/app.py"]
