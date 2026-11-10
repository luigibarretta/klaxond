# Changelog

All notable changes to `http-hardening` are recorded here. The crate follows
semantic versioning; while it is `0.x`, a minor release may deprecate APIs,
and deprecated APIs are removed only after every known consumer has migrated.

## 0.2.0 - 2026-11-09

Fixes from the independent adversarial audit of 0.1.0 (07358543). Breaking
changes are allowed while no consumer has adopted the crate.

### Security

- ureq: the guarded agent is built with `try_proxy_from_env(false)` (ureq
  resolves the proxy netloc, so a proxy from `HTTP_PROXY` bypassed the
  guard) and `redirects(0)`; `GuardedAgent` follows 3xx itself and runs
  `NetGuard::check_redirect` on every hop, closing the https to http
  downgrade and the ureq hop-count off-by-one.
- `security_headers`: the default is now `ExistingHeaders::Overwrite`, so
  handler or upstream (reverse-proxied) values cannot weaken the policy;
  `SecurityHeadersBuilder::keep_if_present(&[..])` opts single headers in.
- Correct-by-construction clients: `reqwest_adapter::GuardedClient` and
  `PinnedClient`, `ureq_adapter::GuardedAgent` always run `check_url`
  (literal IP hosts skip hyper's resolver; ports are enforced there).
  `PinnedClient` refuses URLs whose host or port differ from the target
  (`NetGuardError::TargetMismatch`).
- `Cidr`: IPv4-mapped IPv6 networks are refused (a mapped `/128` or bare
  address is canonicalised to IPv4); prefixes shorter than /8 (IPv4) or /32
  (IPv6) need `Cidr::new_wide`, `Cidr::parse_wide` or
  `NetGuardBuilder::allow_wide_cidr`.
- Permissions-Policy origins reject `\`, `(`, `)` and `"`.

### Changed

- Features: `default = ["http", "net-guard"]`; `http` gates the typed
  `http` 1.x view, `net-guard` gates `net_guard` (dep `url`); with
  `default-features = false` the crate has no dependencies.
  `SecurityHeaders::headers_str()`, `get()` (now `&str`), `keeps_existing()`,
  `is_valid_header_name` / `is_valid_header_value` serve std-only servers.
- `ContentSecurityPolicy::strict()` no longer contains `form-action 'self'`
  (Chrome applies it to the 302 of a login POST to an external IdP).
- `NetGuardBuilder::allow_cidr` returns `Result` and fails with
  `CidrError::TooManyEntries` instead of silently dropping entries.
- Renamed `reqwest_adapter::client_builder` to `client_builder_unchecked`
  and `ureq_adapter::agent_builder` to `agent_builder_unchecked`.
- Removed `SecurityHeaders::existing()`.

### Re-audit fixes (06264b6c)

- ureq `GuardedAgent::send`: a 307/308 to another origin is no longer
  followed (the closure would replay `Authorization`, `Cookie` and body to
  it); the 3xx response is returned. Same-origin 307/308 replay the closure;
  301/302/303 continue as a plain `GET` without the caller's headers or
  body, and `HEAD` stays `HEAD`.
- reqwest: `GuardedClient` and `PinnedClient` return `GuardedRequest`, which
  wraps `RequestBuilder` privately so `build_split()` (inner client) and
  `Request::url_mut()` are out of reach. New feature `reqwest-serde` adds
  `json`, `form`, `query`; feature `reqwest` now also enables `http`.
- `client_builder_unchecked`, `pinned_client_builder` and
  `agent_builder_unchecked` are `#[doc(hidden)]` and document that
  `.proxy()` re-enables proxying.
- `keep_if_present` fails with `HeaderPolicyError::KeptHeaderNotInPolicy`
  for a name the policy does not send.
- Documented the worst-case redirect chain duration
  `(max_hops + 1) * timeout` and that consumers must enable a reqwest/ureq
  TLS backend feature for https.

### Documentation

- HSTS `includeSubDomains` and HTTP-only LAN subdomains; `localhost` with a
  `127.0.0.0/8` allowlist also needs `::1/128`; CSP hash route for fixed
  inline scripts (no nonces); `form-action` opt-in.

## 0.1.0 - 2026-11-09

### Added

- `security_headers`: `SecurityHeaders` / `SecurityHeadersBuilder` with strict
  defaults (HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, COOP, CORP), extra static headers,
  `ExistingHeaders::{Keep, Overwrite}` and `apply(&mut HeaderMap)`;
  `ContentSecurityPolicy` builder (`strict`, `set`, `add`, `remove`,
  `upgrade_insecure_requests`, report-only) with injection-safe token
  validation; `PermissionsPolicy`, `Hsts`, `FrameOptions`, `ReferrerPolicy`,
  `CrossOriginOpenerPolicy`, `CrossOriginResourcePolicy`.
- `security_headers::SecurityHeadersLayer` (feature `tower`) for http 1.x
  services such as axum 0.8 routers.
- `net_guard`: `NetGuard` / `NetGuardBuilder` (scheme and port allowlists,
  CIDR allowlist, redirect policy, DNS answer limit), `check_url`,
  `parse_url`, `check_ip`, `check_addresses`, `resolve` / `resolve_with`
  returning a pinned `ResolvedTarget`, `check_redirect`; `classify` /
  `AddressClass` covering the IANA special-purpose registries and IPv6
  encodings of IPv4 (mapped, compatible, NAT64, 6to4, Teredo); `Cidr` and
  `parse_cidr_list`; `DnsLookup` / `SystemDns`.
- `net_guard::reqwest_adapter` (feature `reqwest`): `GuardedResolver`,
  `PinnedResolver`, `redirect_policy`, `client_builder`,
  `pinned_client_builder`.
- `net_guard::ureq_adapter` (feature `ureq`): `UreqResolver`,
  `agent_builder`.
- Repository tooling: ci-local manifest, Gitea workflow, LOC and NASA
  baselines, cargo-audit and cargo-deny configuration, empty OpenVEX file.
