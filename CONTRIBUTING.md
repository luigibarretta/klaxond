# Contributing

Open an issue before a large behavior or storage change. Security reports belong
in the private advisory flow documented in `SECURITY.md`.

Use Rust 1.96.1, Go 1.24 and Node 20.19 or newer. Before submitting a change:

```bash
bash scripts/check-rsa-private-usage.sh
bash scripts/check-auth-gold-standard.sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo test --manifest-path sdk/rust/Cargo.toml --locked
(cd sdk/go && go test ./...)
npm ci
npm run static:check
npm run openapi:lint
npm run release:check
npm run test:e2e
```

The matrix deliberately starts a clean local server for Chromium, Firefox, and WebKit in sequence. This prevents configuration mutations in one browser run from leaking into the next one.

`npm run test:e2e` runs the portable UI suite, including the full virtual
passkey lifecycle, in Chromium, Firefox and WebKit. Numbered releases
additionally require the physical Safari/macOS and iOS smoke tests documented
in `docs/browser-support.md`.

Do not edit `vendor/auth-modules` ad hoc. A vendor refresh must name an immutable
upstream commit in its README and pass the full authentication/security suite.
Never commit `.env`, settings exports, session keys, database files or tokens.
