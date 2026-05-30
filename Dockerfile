# syntax=docker/dockerfile:1.7
FROM python:3.13-alpine

LABEL org.opencontainers.image.title="klaxon"
LABEL org.opencontainers.image.description="Homelab notification bridge — Grafana/Beszel webhook → ntfy with cascade (Telegram, SMTP) and admin UI"
LABEL org.opencontainers.image.source="https://git.luigibarretta.com/luigibarretta/homelab-klaxon"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Everything is stdlib — no pip install needed.
COPY app.py /app/app.py
COPY static/ /app/static/
COPY klaxon.default.toml /app/klaxon.default.toml

# Persistent state lives here (klaxon.toml + render-config.json + future).
VOLUME ["/data"]

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8181/healthz', timeout=2).status==200 else 1)"

CMD ["python", "/app/app.py"]
