#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required" >&2
  exit 2
fi

status=0

direct_dependency_pattern='^[[:space:]]*rsa[[:space:]]*='
private_api_pattern='EncodingKey::from_rsa(_pem|_der)?|RsaPrivateKey|DecodeRsaPrivateKey|EncodeRsaPrivateKey|rsa::(Oaep|Pkcs1v15Encrypt|Pkcs1v15Sign|Pss|pkcs1v15::SigningKey|pss::SigningKey)'

scan_pattern() {
  local pattern=$1
  shift
  local output rc

  set +e
  output="$(rg -n --no-heading -e "$pattern" "$@" 2>&1)"
  rc=$?
  set -e

  case "$rc" in
    0)
      printf '%s\n' "$output"
      return 0
      ;;
    1)
      return 1
      ;;
    *)
      printf 'error: RSA guard scan failed (rg exit %s):\n%s\n' "$rc" "$output" >&2
      exit 2
      ;;
  esac
}

if scan_pattern "$direct_dependency_pattern" Cargo.toml; then
  cat >&2 <<'MSG'
error: direct dependency on the RustCrypto rsa crate found.

Klaxond accepts rsa only as a tracked transitive dependency for public-key
OIDC/WebAuthn verification. Direct rsa usage needs a dedicated security review;
see docs/security-rsa-risk.md.
MSG
  status=1
fi

if scan_pattern "$private_api_pattern" Cargo.toml src; then
  cat >&2 <<'MSG'
error: production Rust code appears to use RSA private-key/decrypt/signing APIs.

RUSTSEC-2023-0071 has no patched rsa release. Do not add server-side RSA
private-key operations that a remote caller could time over the network.
Use HMAC, EdDSA, ECDSA, or a reviewed constant-time provider instead; see
docs/security-rsa-risk.md.
MSG
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  echo "RSA private-key usage guard passed."
fi

exit "$status"
