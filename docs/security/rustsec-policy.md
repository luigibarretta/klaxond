# RustSec and Dependency Audit Policy

Dependency audits are release gates. The `audit-lockfiles` step of
`ci-local.json` (ci-local's `audit-all-lockfiles`) runs `cargo audit` on
`Cargo.lock` and `npm audit --package-lock-only --audit-level=moderate` on
`package-lock.json`. CI runs it through
`node third_party/repo-tooling/ci-local.mjs --ci --only ...`; run it locally with
`node third_party/repo-tooling/ci-local.mjs --only audit-lockfiles` or the full
gate. Every advisory fails the step unless it is listed below and ignored in
that step with its reason.

## Accepted advisories

### `RUSTSEC-2023-0071` / RustCrypto `rsa` Marvin timing side channel

Status: ignored explicitly in the `audit-lockfiles` step.

`rsa` arrives through `jsonwebtoken` and `webauthn-rs` and is used only to
verify signatures with public keys. Klaxond performs no RSA private-key
operation. The threat model, controls and review checklist are in
[`../security-rsa-risk.md`](../security-rsa-risk.md).

### `RUSTSEC-2026-0387` / `crypto-bigint` 0.5 timing variability

Status: ignored explicitly in the `audit-lockfiles` step (advisory published
2026-10-23).

Impact: `crypto-bigint` 0.5.5 arrives only through `elliptic-curve` 0.13:

- `p256`/`p384` 0.13 via `jsonwebtoken` 10 and `openidconnect` 4 in the vendored
  `auth-modules`, used to verify OIDC ID and logout tokens (ES256/ES384) with
  the provider's public keys;
- `crypto-glue` (`p256`/`p384`/`p521`) via `webauthn-rs`, used to verify
  passkey assertions and attestations with credential public keys.

Klaxond performs no elliptic-curve private-key operation: no EC signing, key
agreement or decryption happens in the daemon, so no secret operand reaches the
affected arithmetic. The only EC private key in the dependency tree is a fixture
in the `auth-modules` logout-token unit tests (`#[cfg(test)]`), which is not
compiled into klaxond. The fix requires `crypto-bigint` >= 0.7.6 (the
`elliptic-curve` 0.14 line), which is semver-incompatible with every current
`jsonwebtoken` release, so no lockfile-only upgrade exists.

Controls: `scripts/check-rsa-private-usage.sh` (the `rsa-guard` step) fails on
a direct `p256`/`p384`/`p521`/`ecdsa`/`elliptic-curve`/`crypto-bigint`
dependency in `Cargo.toml` and on `EncodingKey::from_ec_*` or
`SigningKey`/`SecretKey`/`NonZeroScalar`/`EphemeralSecret`/ECDH from those
crates in `src/`.

Exit path: remove the ignore once `jsonwebtoken` and `openidconnect` move to
`elliptic-curve` >= 0.14 / `crypto-bigint` >= 0.7.6 (then `auth-modules`
upgrades) and `webauthn-rs` follows, so `cargo audit` passes without it.
Re-review immediately if klaxond ever adds server-side EC signing.

The same reasoning is applied in CoveyOS and StudioFlow
(`docs/security/rustsec-policy.md` in each repository).
