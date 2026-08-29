# Vendored auth-modules

Klaxond vendors the subset-independent `auth-modules` Rust crate so a public
checkout can be built without access to Luigi Barretta's private shared-module
repository.

- Upstream commit: `f1056701b73ea8efa09e686d6de2d56276e26abf`
- Vendored content: upstream `Cargo.toml` and complete `src/` tree
- Upstream declared license: `MIT OR Apache-2.0`
- License selected for this distribution: `Apache-2.0`

Do not edit this directory ad hoc. Updates must copy a reviewed upstream commit,
record the new immutable commit here, and pass Klaxond's full authentication and
security test suite.
