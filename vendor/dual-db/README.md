# Vendored dual-db

Klaxond vendors the `dual-db` Rust crate (the shared PostgreSQL + SQLite
schema migration runner) so a public checkout can be built without access to
Luigi Barretta's private shared-module repository.

- Upstream: `https://git.luigibarretta.com/luigibarretta/lib-dual-db.git`
- Upstream version: `0.1.0`
- Upstream commit: `baac890a24fe5d589141a50e5092dc36a3f25585`
  (also recorded in `dependencies/dual-db.sha`)
- Vendored content: upstream `Cargo.toml`, `CHANGELOG.md`, `LICENSE-APACHE`
  and the complete `src/` tree, as an exact `git archive` of those paths;
  zero local patches
- Features used by Klaxond: `sqlite`, `postgres` (`src/history/schema.rs`
  and the two `migration.rs` registries)
- Upstream declared license: `MIT OR Apache-2.0`
- License selected for this distribution: `Apache-2.0`

`dependencies/vendored.json` declares this copy. The `vendored-deps` ci-local
step (`check-vendored-dep`) verifies the tree digest recorded in
`dependencies/dual-db-vendor.sha256` and, when a clone of `lib-dual-db` is
available (`.ci/lib-dual-db` or `../lib-dual-db`), compares every vendored
file with the pinned commit. This README is a local file excluded from the
comparison.

Do not edit this directory ad hoc. To refresh, copy a reviewed upstream
commit, record it here, and pass Klaxond's full history test suite on both
backends:

```bash
rm -rf vendor/dual-db/src vendor/dual-db/Cargo.toml vendor/dual-db/CHANGELOG.md vendor/dual-db/LICENSE-APACHE
git -C ../lib-dual-db archive <commit> Cargo.toml CHANGELOG.md LICENSE-APACHE src | tar -x -C vendor/dual-db
git -C ../lib-dual-db rev-parse '<commit>^{commit}' > dependencies/dual-db.sha
node third_party/repo-tooling/check-vendored-dep.mjs --only dual-db --update-digest
node third_party/repo-tooling/check-vendored-dep.mjs --require-upstream
```
