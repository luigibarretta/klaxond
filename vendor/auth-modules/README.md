# Vendored auth-modules

Klaxond vendors the subset-independent `auth-modules` Rust crate so a public
checkout can be built without access to Luigi Barretta's private shared-module
repository.

- Upstream tag: `v0.2.0`
- Upstream commit: `2a9aec766b0edb4cf0a55f8a4acd246b73b8a078`
  (also recorded in `dependencies/auth-modules.sha`)
- Vendored content: upstream `Cargo.toml`, `CHANGELOG.md` and the complete
  `src/` tree, as an exact `git archive` of those paths
- Upstream declared license: `MIT OR Apache-2.0`
- License selected for this distribution: `Apache-2.0`

`dependencies/vendored.json` declares this copy. The `vendored-deps` ci-local
step (`check-vendored-dep`) verifies the tree digest recorded in
`dependencies/auth-modules-vendor.sha256` and, when a clone of
`lib-auth-modules` is available (`.ci/auth-modules` or `../lib-auth-modules`),
compares every vendored file with the pinned commit. This README and
`LICENSE-APACHE` are local files excluded from the comparison.

Do not edit this directory ad hoc. To refresh, copy a reviewed upstream
commit, record it here, and pass Klaxond's full authentication and security
test suite:

```bash
rm -rf vendor/auth-modules/src vendor/auth-modules/Cargo.toml vendor/auth-modules/CHANGELOG.md
git -C ../lib-auth-modules archive <commit> Cargo.toml CHANGELOG.md src | tar -x -C vendor/auth-modules
git -C ../lib-auth-modules rev-parse <commit> > dependencies/auth-modules.sha
node third_party/repo-tooling/check-vendored-dep.mjs --only auth-modules --update-digest
node third_party/repo-tooling/check-vendored-dep.mjs --require-upstream
```
