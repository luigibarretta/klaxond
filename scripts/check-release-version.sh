#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
test -n "$version"

require_literal() {
  local file="$1"
  local value="$2"
  if ! grep -Fq -- "$value" "$file"; then
    echo "release version mismatch: $file does not contain $value" >&2
    return 1
  fi
}

require_literal Cargo.lock "version = \"$version\""
require_literal docs/openapi.yaml "version: $version"
require_literal docker-compose.yml "ghcr.io/luigibarretta/klaxond:$version"
require_literal docker-compose.split.yml "ghcr.io/luigibarretta/klaxond:$version"
require_literal docker-compose.split.yml "ghcr.io/luigibarretta/klaxond-frontend:$version"
require_literal .env.example "KLAXOND_IMAGE=ghcr.io/luigibarretta/klaxond:$version"
require_literal .env.example "KLAXOND_BACKEND_IMAGE=ghcr.io/luigibarretta/klaxond:$version"
require_literal .env.example "KLAXOND_FRONTEND_IMAGE=ghcr.io/luigibarretta/klaxond-frontend:$version"
require_literal CHANGELOG.md "## $version"

echo "Release version contract passed: $version"
