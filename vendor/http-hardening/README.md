# Vendored http-hardening

Klaxond vendors the `http-hardening` Rust crate (security response headers
and the outbound anti-SSRF guard) so a public checkout can be built without
access to Luigi Barretta's private shared-module repository.

- Upstream: `https://git.luigibarretta.com/luigibarretta/lib-http-hardening.git`
- Upstream tag: `v0.2.0`
- Upstream commit: `be757cf18f5986c3066fdb60499f5bfce0c61d8c`
  (also recorded in `dependencies/http-hardening.sha`)
- Vendored content: upstream `Cargo.toml`, `CHANGELOG.md`, `LICENSE-APACHE`
  and the complete `src/` tree, as an exact `git archive` of those paths;
  zero local patches
- Features used by Klaxond: `tower`, `reqwest`
- Upstream declared license: `MIT OR Apache-2.0`
- License selected for this distribution: `Apache-2.0`

`dependencies/vendored.json` declares this copy. The `vendored-deps` ci-local
step (`check-vendored-dep`) verifies the tree digest recorded in
`dependencies/http-hardening-vendor.sha256` and, when a clone of
`lib-http-hardening` is available (`.ci/lib-http-hardening` or
`../lib-http-hardening`), compares every vendored file with the pinned
commit. This README is a local file excluded from the comparison.

Do not edit this directory ad hoc. To refresh, copy a reviewed upstream
commit, record it here, and pass Klaxond's full delivery and security test
suite:

```bash
rm -rf vendor/http-hardening/src vendor/http-hardening/Cargo.toml vendor/http-hardening/CHANGELOG.md vendor/http-hardening/LICENSE-APACHE
git -C ../lib-http-hardening archive <commit> Cargo.toml CHANGELOG.md LICENSE-APACHE src | tar -x -C vendor/http-hardening
git -C ../lib-http-hardening rev-parse '<commit>^{commit}' > dependencies/http-hardening.sha
node third_party/repo-tooling/check-vendored-dep.mjs --only http-hardening --update-digest
node third_party/repo-tooling/check-vendored-dep.mjs --require-upstream
```
