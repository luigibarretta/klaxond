# Changelog

All notable changes to `auth-modules` are recorded here. The crate follows
semantic versioning; while it is `0.x`, a minor release may deprecate APIs,
and deprecated APIs are removed only after every known consumer has migrated
(see `docs/shared-component-boundaries.md`, compatibility rules).

## 0.2.0 - 2026-11-08

### Added

- `client_ip` (feature `client-ip`): `TrustedProxies` (validated CIDR list
  plus the single forwarding header the proxies maintain) and
  `ForwardingHeaders`; resolves the client address from the right of
  `X-Forwarded-For`, RFC 7239 `Forwarded` or `X-Real-IP`, skipping trusted
  hops, falling back to the peer on malformed trusted hops, and normalizing
  IPv4-mapped IPv6 addresses.
- `secrets::files` (feature `secret-files`, Unix): `read_private_file`,
  `read_private_string`, `read_private_file_with`/`read_private_string_with`
  with `PrivateFileOptions`/`FileOwner`, and `write_private_atomic`. Rejects
  symlinks, non-regular files, group/other permissions, foreign owners,
  oversized and empty files; returns `Redacted` values.
- `keys` (feature `keys`): `MasterKey`, compile-time validated namespaced
  `KeyLabel`, HKDF-SHA256 `SubKey` derivation (RFC 5869 vectors), HMAC
  helpers, and `KeyRing` with legacy master and legacy raw keys for
  verification during rotation (raw legacy keys are scoped to explicit
  labels via `with_legacy_raw(secret, &[labels])`); `legacy_hmac_sha256`.
- `one_time_token::issue_for_delivery` returning
  `(StoredTokenHash, DeliverableToken)`; the token is neither `Clone`,
  `Display` nor `Serialize` and leaves only through a `TokenDelivery`.
- `oidc::CallbackParams` and `exchange_callback` (prepared clients and free
  functions, async and blocking): constant-time `state` verification before
  discovery or the token request (audit finding AM-03).

### Deprecated

- `one_time_token::issue_token`: use `issue_for_delivery`.
- `oidc::async_client::exchange_code`, `oidc::blocking::exchange_code` and the
  `exchange_code` methods of the prepared clients: use `exchange_callback`.

**Build-breaking for `clippy -D warnings` consumers.** The new
`#[deprecated]` attributes turn every remaining call into a warning, and
consumers that deny warnings (`cargo clippy -- -D warnings`,
`RUSTFLAGS=-D warnings`) fail to build after bumping to 0.2.0 until they
migrate. Runtime behaviour of the deprecated functions is unchanged. Bridge:
`#[allow(deprecated)]` on the individual call site (never crate-wide), removed
in the follow-up. Recommended order, one consumer at a time: bump with
bridges, then `exchange_callback` (AM-03), then `issue_for_delivery`, then
drop the bridges; see "Migrating to 0.2.0" in the README.

### Changed

- The default feature set now also enables `client-ip`, `keys` and
  `secret-files`. Consumers that disable default features are unaffected.
