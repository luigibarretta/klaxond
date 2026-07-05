# RSA Timing Advisory Risk Note

Klaxond currently carries the RustCrypto `rsa` crate transitively through
`jsonwebtoken` and `webauthn-rs`. `cargo audit` reports
[`RUSTSEC-2023-0071`](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) /
[`GHSA-c38w-74pg-36hr`](https://github.com/RustCrypto/RSA/security/advisories/GHSA-c38w-74pg-36hr)
for that crate. No patched `rsa` release is available at the time this note was
written.

## Local Assessment

The vulnerable scenario is a remotely measurable server-side RSA private-key
operation, such as decrypting attacker-controlled ciphertexts or signing
attacker-controlled messages with an RSA private key in an API request path.

Klaxond does not intentionally do that:

- OIDC/JWT support verifies provider-issued tokens from JWKS public keys via
  `jsonwebtoken::DecodingKey`.
- WebAuthn/passkey support verifies authenticator signatures via `webauthn-rs`.
- Klaxond does not keep an RSA private key for request-time signing or
  decryption.

Because the current usage is public-key verification, the advisory is accepted
as a tracked transitive dependency risk, not as an exposed private-key timing
oracle.

## Required Controls

- Keep `RUSTSEC-2023-0071` ignored explicitly when running `cargo audit` until
  RustCrypto publishes a fixed `rsa` release.
- Run `scripts/check-rsa-private-usage.sh` in CI to block direct RSA crate usage
  and obvious private-key RSA APIs in production Rust code.
- Prefer non-RSA OIDC signing algorithms, such as ES256 or EdDSA, when the
  identity provider and client libraries support them.
- Reassess this note before adding JWE/RSA decryption, local RSA JWT signing,
  S/MIME-style RSA operations, or any other private-key RSA operation.
- Track upstream status in
  [RustCrypto/RSA issue 390](https://github.com/RustCrypto/RSA/issues/390) and
  the RustSec advisory.

## Review Checklist

Before accepting a future RSA-related change, confirm:

- No `rsa` direct dependency is added to `Cargo.toml` without a dedicated design
  review.
- No production code introduces `RsaPrivateKey`, `EncodingKey::from_rsa_*`,
  RSA decrypt, or RSA signing-key APIs.
- Any new token signing uses HMAC, EdDSA, or ECDSA unless an RSA-specific
  threat model is documented.
- Any new cryptography exposed to remote callers has timing and chosen-input
  behavior reviewed explicitly.
