#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARED="${KLAXOND_AUTH_GOLD_SHARED:-/home/ansible/auth-modules/scripts/check-auth-gold-standard.sh}"

fallback_check() {
  local status=0
  local rg_common=(
    --hidden
    -g '!.git/**'
    -g '!target/**'
    -g '!node_modules/**'
    -g '!auth-modules/**'
    -g '!static/vendor/**'
    -g '!static/mermaid.min.js'
    -g '!docs/**'
    -g '!CHANGELOG.md'
    -g '!scripts/check-auth-gold-standard.sh'
  )

  check_absent() {
    local title=$1
    local pattern=$2
    if output="$(rg -n -S "$pattern" "${rg_common[@]}" "$ROOT" 2>/dev/null)"; then
      echo
      echo "FAIL: $title"
      echo "$output"
      status=1
    else
      echo "ok: $title"
    fi
  }

  check_present() {
    local title=$1
    local pattern=$2
    if rg -q -S "$pattern" "${rg_common[@]}" "$ROOT" 2>/dev/null; then
      echo "ok: $title"
    else
      echo
      echo "FAIL: $title"
      status=1
    fi
  }

  check_absent \
    "bcrypt is not present in active code, manifests, or lockfiles" \
    'bcrypt|\$2[aby]\$'
  check_absent \
    "runtime code does not call or mount root /auth/* API paths" \
    '(route\([^;]*["`]/auth/|\("(GET|POST|PUT|PATCH|DELETE)",[[:space:]]*["`]/auth/|fetch\(["`]/auth/|href=["`]/auth/|location\.(href|assign|replace)\(["`]/auth/)'
  check_absent \
    "app manifests do not depend on openidconnect directly" \
    'openidconnect[[:space:]]*='
  check_absent \
    "app runtime OIDC code does not implement protocol validation locally" \
    'decode_header|JwkSet|verify_id_token|jwk_matches_algorithm|CoreProviderMetadata|AuthorizationCode|PkceCode'

  check_present "canonical password policy endpoint" '/api/auth/password-policy'
  check_present "canonical auth methods endpoint" '/api/auth/methods'
  check_present "shared OIDC protocol client" 'auth_modules::oidc|oidc-(async|blocking)'
  check_present "shared password module" 'auth_modules::password'
  check_present "shared auth method vocabulary" 'auth_modules::methods'
  check_present "shared auth brute-force policy" 'GOLD_AUTH_|auth_modules::rate_limit'
  check_present "shared TOTP module" 'auth_modules::totp'
  check_present "shared LDAP adapter" 'auth_modules::ldap'

  if [[ $status -eq 0 ]]; then
    echo
    echo "auth gold standard fallback guardrails passed for $ROOT"
  else
    echo
    echo "auth gold standard fallback guardrails failed"
  fi
  return "$status"
}

if (($# > 0)); then
  if [[ ! -f "$SHARED" ]]; then
    echo "error: shared auth gold standard guard not found at $SHARED" >&2
    exit 2
  fi
  exec bash "$SHARED" "$@"
fi

if [[ ! -f "$SHARED" ]]; then
  echo "warn: shared auth gold standard guard not found at $SHARED; using repo-local fallback"
  fallback_check
  exit $?
fi

set +e
output="$(bash "$SHARED" "$ROOT" 2>&1)"
status=$?
set -e

if [[ $status -eq 0 ]]; then
  printf '%s\n' "$output"
  exit 0
fi

unexpected=0
fail_count=0
while IFS= read -r line; do
  [[ $line == FAIL:* ]] || continue
  fail_count=$((fail_count + 1))
  case "$line" in
    "FAIL: repo-local auth gold standard wrapper missing or not executable in "*)
      if [[ $line == *" $ROOT" ]]; then
        unexpected=1
      fi
      ;;
    *)
      unexpected=1
      ;;
  esac
done <<<"$output"

if [[ $unexpected -eq 0 && $fail_count -gt 0 ]]; then
  while IFS= read -r line; do
    case "$line" in
      "FAIL: repo-local auth gold standard wrapper missing or not executable in "*)
        echo "warn: external repo auth gold standard wrapper missing outside $ROOT: ${line##* in }"
        ;;
      "auth gold standard guardrails failed")
        echo "auth gold standard guardrails passed for $ROOT"
        ;;
      *)
        printf '%s\n' "$line"
        ;;
    esac
  done <<<"$output"
  exit 0
fi

printf '%s\n' "$output"
exit "$status"
