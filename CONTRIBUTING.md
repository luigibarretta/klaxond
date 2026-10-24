# Contributing

Open an issue before a large behavior or storage change. Security reports belong
in the private advisory flow documented in `SECURITY.md`.

Use Rust 1.96.1, Go 1.24 and Node 24 LTS (CI pins 24.21.0; Node 20.19 or newer
still works). Every CI check is a step of `ci-local.json`, and the Gitea
workflow runs those same steps through `ci-local.mjs --ci`. Before pushing, run
the local gate:

```bash
export PATH=$HOME/.local/dev-build-lock-bin:$PATH   # dev-01: build lock first
node third_party/repo-tooling/ci-local.mjs --quick  # guards, contracts, LOC, audit, fmt
node third_party/repo-tooling/ci-local.mjs          # full gate, as in CI
node third_party/repo-tooling/ci-local.mjs --list   # steps and flags
```

The full gate covers the RSA/EC and auth gold-standard guards, the release and
release-pipeline contracts, LOC/NASA, static checks, the RustSec and npm audit,
rustfmt, `cargo check`/clippy for the workspace, the Rust tests, the PostgreSQL
persistence suite (a disposable `postgres:17.6-alpine` container locally, the
job service in CI), the Rust and Go SDK tests, OpenAPI lint and the Playwright
matrix. `scripts/check-ci-local-jobs.mjs` fails CI when a manifest step is not
run by exactly one workflow call. When you add a CI check, add it to
`ci-local.json` and to one `--only` list in `.gitea/workflows/build.yml`.

The matrix deliberately starts a clean local server for Chromium, Firefox,
desktop WebKit, and the WebKit-based Mobile Safari device profile in sequence.
This prevents configuration mutations in one browser run from leaking into the
next one.

`npm run test:e2e` runs the portable UI suite, including the full virtual
passkey lifecycle, in Chromium, Firefox, desktop WebKit and an iPhone device
profile. Public numbered releases
additionally require the physical Safari/macOS and iOS smoke tests documented
in `docs/browser-support.md`; private maintainer tags do not satisfy or waive
that public-platform gate.

Do not edit `vendor/auth-modules` ad hoc. A vendor refresh must name an immutable
upstream commit in its README and pass the full authentication/security suite.
Never commit `.env`, settings exports, session keys, database files or tokens.
