#!/bin/bash
set -euo pipefail

workflow=.gitea/workflows/build.yml

grep -Fq '  publish-immutable:' "$workflow"
grep -Fq "(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v'))" "$workflow"
grep -Fq 'needs: [check, publish-immutable]' "$workflow"
grep -Fq 'SOURCE_IMAGE: git.luigibarretta.com/${{ github.repository_owner }}/klaxond:${{ github.sha }}' "$workflow"
grep -Fq 'org.opencontainers.image.version=${{ steps.package.outputs.version }}' "$workflow"
grep -Fq 'org.opencontainers.image.revision=${{ github.sha }}' "$workflow"
grep -Fq 'test "$version" = "$EXPECTED_VERSION"' "$workflow"
grep -Fq 'test "$revision" = "$EXPECTED_REVISION"' "$workflow"

if grep -Fq '  publish-main:' "$workflow"; then
  echo 'release pipeline still depends on the old branch-only publisher' >&2
  exit 1
fi

echo 'Release pipeline contract passed: checked tag SHA is published before promotion.'
