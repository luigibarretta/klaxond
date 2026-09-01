#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
canonical_checkout="${1:-${repo_root}/vendor/repo-tooling}"
pin_file="${repo_root}/dependencies/repo-tooling.sha"
vendored_dist="${repo_root}/third_party/repo-tooling"

pin="$(tr -d '[:space:]' < "${pin_file}")"
if [[ ! "${pin}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid repo-tooling commit pin in ${pin_file}" >&2
  exit 1
fi
if [[ ! -d "${canonical_checkout}/.git" ]]; then
  echo "Canonical repo-tooling checkout is missing: ${canonical_checkout}" >&2
  exit 1
fi
actual="$(git -c safe.directory="${canonical_checkout}" -C "${canonical_checkout}" rev-parse HEAD)"
if [[ "${actual}" != "${pin}" ]]; then
  echo "repo-tooling checkout ${actual} does not match pinned commit ${pin}" >&2
  exit 1
fi
diff -ru "${canonical_checkout}/dist" "${vendored_dist}"
echo "repo-tooling vendoring verified at ${pin}"
