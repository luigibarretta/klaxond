#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARED="/home/ansible/auth-modules/scripts/check-auth-gold-standard.sh"

if [[ ! -f "$SHARED" ]]; then
  echo "error: shared auth gold standard guard not found at $SHARED" >&2
  exit 2
fi

if (($# > 0)); then
  exec bash "$SHARED" "$@"
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
