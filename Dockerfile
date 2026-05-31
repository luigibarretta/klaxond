# syntax=docker/dockerfile:1.7
FROM python:3.13-alpine

LABEL org.opencontainers.image.title="klaxond"
LABEL org.opencontainers.image.description="Homelab notification bridge — Grafana/Beszel webhook → ntfy with cascade (Telegram, SMTP) and admin UI"
LABEL org.opencontainers.image.source="https://example.com/yourname/klaxond"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Runtime deps:
#  - PyJWT[crypto]: OIDC id_token verification (RS256/RS512/ES256)
#  - bcrypt: basic-auth password hashing
# Pinned to current major to keep image reproducible.
RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev \
 && pip install --no-cache-dir 'PyJWT[crypto]==2.10.1' 'bcrypt==4.2.1' \
 && apk del .build-deps

COPY app.py /app/app.py
COPY static/ /app/static/
COPY klaxond.default.toml /app/klaxond.default.toml

# Persistent state lives here (klaxon.toml + render-config.json + future).
VOLUME ["/data"]

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8181/healthz', timeout=2).status==200 else 1)"

CMD ["python", "/app/app.py"]
