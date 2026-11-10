//! Shared HTTP hardening for personal projects.
//!
//! - [`security_headers`]: framework-agnostic security response headers
//!   (HSTS, CSP builder, nosniff, Referrer-Policy, Permissions-Policy,
//!   framing, COOP/CORP). The core is std-only; feature `http` adds typed
//!   `http` 1.x headers and `apply(&mut HeaderMap)`, feature `tower` a layer.
//! - `net_guard` (feature `net-guard`): anti-SSRF guard for outbound requests
//!   (scheme allowlist, resolve-once-and-pin, special-purpose address
//!   rejection in every IPv4 and IPv6 encoding, explicit CIDR allowlist,
//!   redirect policy), with correct-by-construction reqwest (feature
//!   `reqwest`) and ureq (feature `ureq`) clients.
//!
//! With `default-features = false` the crate has no dependencies at all.

#[cfg(feature = "net-guard")]
pub mod net_guard;
pub mod security_headers;
