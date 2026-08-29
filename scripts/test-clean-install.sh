#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${USER:-user}-$$"
IMAGE="klaxond-clean-install:${RUN_ID}"
CONTAINER="klaxond-clean-install-${RUN_ID}"
VOLUME="klaxond-clean-install-${RUN_ID}"

cleanup() {
  docker container rm --force "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker info >/dev/null
docker build --pull=false --tag "$IMAGE" "$ROOT"
docker volume create "$VOLUME" >/dev/null
docker run --detach \
  --name "$CONTAINER" \
  --publish 127.0.0.1::8181 \
  --mount "type=volume,source=${VOLUME},target=/data" \
  "$IMAGE" >/dev/null

PUBLISHED="$(docker port "$CONTAINER" 8181/tcp | sed -n '1p')"
test -n "$PUBLISHED"
for _ in $(seq 1 30); do
  if curl -fsS "http://${PUBLISHED}/healthz" | grep -qx OK; then
    break
  fi
  sleep 1
done
curl -fsS "http://${PUBLISHED}/healthz" | grep -qx OK

docker exec "$CONTAINER" klaxond doctor --offline --json >/dev/null

# The development-only escape hatches must be explicit. This proves that a
# local ntfy-only configuration passes while the production default fails
# closed for the same insecure callback.
docker exec \
  --env KLAXOND_EMERGENCY_ENABLED=true \
  --env KLAXOND_EMERGENCY_ALLOW_INSECURE_PUBLIC_URL=true \
  --env KLAXOND_EMERGENCY_ALLOW_NTFY_ONLY=true \
  --env KLAXOND_PUBLIC_URL=http://localhost:8181 \
  --env NTFY_URL=http://ntfy.invalid \
  --env TOPIC_CRIT=critical-test \
  --env NTFY_TOKEN_CRIT=publish-token-placeholder \
  "$CONTAINER" klaxond doctor --offline --json >/dev/null

if docker exec \
  --env KLAXOND_EMERGENCY_ENABLED=true \
  --env KLAXOND_PUBLIC_URL=http://localhost:8181 \
  --env NTFY_URL=http://ntfy.invalid \
  --env TOPIC_CRIT=critical-test \
  --env NTFY_TOKEN_CRIT=publish-token-placeholder \
  "$CONTAINER" klaxond doctor --offline --json >/dev/null 2>&1; then
  echo "expected insecure emergency configuration to fail closed" >&2
  exit 1
fi

printf 'clean install passed: image=%s container=%s\n' "$IMAGE" "$CONTAINER"
