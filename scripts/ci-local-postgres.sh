#!/usr/bin/env bash
# ci-local fixture: the PostgreSQL database for the ignored persistence tests.
#
# In CI the job's `postgres` service already exists and the workflow exports
# KLAXOND_TEST_POSTGRES_URL; the fixture passes that URL through unchanged.
# Locally, without that variable, it starts a disposable postgres:17.6-alpine
# container (the same image as the CI service) on a random loopback port and
# removes it on teardown.
set -euo pipefail

: "${CI_LOCAL_FIXTURE_DIR:?run through ci-local (fixture postgres)}"
state="${CI_LOCAL_FIXTURE_DIR}/container"
image="postgres:17.6-alpine"

case "${1:-}" in
  start)
    if [[ -n "${KLAXOND_TEST_POSTGRES_URL:-}" ]]; then
      printf 'KLAXOND_TEST_POSTGRES_URL=%s\n' "$KLAXOND_TEST_POSTGRES_URL" > "$CI_LOCAL_FIXTURE_ENV"
      exit 0
    fi
    name="klaxond-ci-local-postgres-$$"
    docker run -d --rm --name "$name" \
      -e POSTGRES_DB=klaxond_test \
      -e POSTGRES_USER=klaxond \
      -e POSTGRES_PASSWORD=klaxond-test \
      -p 127.0.0.1::5432 \
      "$image" >/dev/null
    printf '%s\n' "$name" > "$state"
    port="$(docker port "$name" 5432/tcp)"
    port="${port##*:}"
    printf 'KLAXOND_TEST_POSTGRES_URL=postgres://klaxond:klaxond-test@127.0.0.1:%s/klaxond_test\n' \
      "$port" > "$CI_LOCAL_FIXTURE_ENV"
    ;;
  ready)
    # The CI service is gated by its own health check.
    [[ -f "$state" ]] || exit 0
    docker exec "$(cat "$state")" pg_isready -h 127.0.0.1 -U klaxond -d klaxond_test
    ;;
  stop)
    [[ -f "$state" ]] || exit 0
    docker rm -f "$(cat "$state")" >/dev/null
    ;;
  *)
    echo "usage: $0 start|ready|stop" >&2
    exit 2
    ;;
esac
