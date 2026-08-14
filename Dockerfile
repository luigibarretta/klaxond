# syntax=docker/dockerfile:1.7
FROM mirror.gcr.io/library/rust:1.96-alpine AS build

WORKDIR /src/klaxond

RUN apk add --no-cache build-base perl

COPY Cargo.toml Cargo.lock ./
COPY --from=auth-modules Cargo.toml /src/auth-modules/Cargo.toml
COPY --from=auth-modules src/ /src/auth-modules/src/
COPY src/ ./src/
COPY docs/openapi.yaml ./docs/openapi.yaml

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    CARGO_TARGET_DIR=/src/target cargo build --release --locked \
    && cp /src/target/release/klaxond /tmp/klaxond

FROM mirror.gcr.io/library/alpine:3.23

LABEL org.opencontainers.image.title="klaxond"
LABEL org.opencontainers.image.description="Notification routing service with noise control, delivery history, and admin UI"
LABEL org.opencontainers.image.source="https://git.luigibarretta.com/luigibarretta/klaxond"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=build /tmp/klaxond /usr/local/bin/klaxond
COPY static/ /app/static/
COPY klaxond.default.toml /app/klaxond.default.toml

VOLUME ["/data"]

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- --timeout=2 http://127.0.0.1:8181/healthz | grep -qx OK

CMD ["/usr/local/bin/klaxond"]
