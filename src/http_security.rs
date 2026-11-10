//! Security response headers applied to every response (audit K-02).
//!
//! The policy is the shared `http_hardening::security_headers` default
//! (nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP
//! and CORP `same-origin`, a deny-by-default Permissions-Policy) with an
//! enforced Content-Security-Policy fitted to the Klaxond pages:
//!
//! - scripts: same-origin files plus the SHA-256 of every inline `<script>`
//!   of `static/index.html` and `static/swagger.html` (read once at startup)
//!   and of the embedded passkey-login and step-up pages; no
//!   `'unsafe-inline'` and no `'unsafe-eval'` for scripts;
//! - styles: `'self'` plus `'unsafe-inline'`, because the UI templates carry
//!   `style` attributes and Mermaid and Swagger UI inject `<style>` elements;
//! - images: `'self'` and `data:`; connections: same origin only.
//!
//! HSTS is sent only when `server.public_url` is `https`. Handler values are
//! overwritten, except `Cross-Origin-Resource-Policy`, which the rendered
//! alert image route sets to `cross-origin` so the ntfy web app can show the
//! attachment. Ingest and API routes are unaffected: these are response
//! headers only, and no route relies on being framed.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_hardening::security_headers::{
    ContentSecurityPolicy, HeaderPolicyError, Hsts, SecurityHeaders, SecurityHeadersLayer,
};
use sha2::{Digest, Sha256};
use std::path::Path;

#[cfg(test)]
mod tests;

/// Headers a route may set itself and keep (`/img/*.png`).
const ROUTE_OWNED_HEADERS: [&str; 1] = ["cross-origin-resource-policy"];
/// Static pages whose inline scripts are allowed by hash.
const STATIC_PAGES: [&str; 2] = ["index.html", "swagger.html"];
/// Upper bound of inline scripts hashed per page.
const MAX_INLINE_SCRIPTS: usize = 16;

/// Builds the layer for the server router. A static page that cannot be read
/// contributes no hash (its inline script is then blocked, never allowed).
pub fn security_headers_layer(
    static_dir: &Path,
    public_url: &str,
) -> Result<SecurityHeadersLayer, HeaderPolicyError> {
    let mut pages = Vec::with_capacity(STATIC_PAGES.len());
    for name in STATIC_PAGES {
        let path = static_dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(html) => pages.push(html),
            Err(error) => tracing::warn!(
                path = %path.display(),
                "static page not readable, CSP allows none of its inline scripts: {error}"
            ),
        }
    }
    let policy = security_headers(public_url, &pages)?;
    Ok(SecurityHeadersLayer::new(policy))
}

pub fn security_headers(
    public_url: &str,
    static_pages: &[String],
) -> Result<SecurityHeaders, HeaderPolicyError> {
    let embedded = [
        crate::handlers::PASSKEY_LOGIN_HTML,
        crate::handlers::STEP_UP_HTML,
    ];
    let pages = static_pages
        .iter()
        .map(String::as_str)
        .chain(embedded)
        .collect::<Vec<_>>();
    SecurityHeaders::builder()
        .csp(Some(content_security_policy(&pages)?))
        .hsts(is_https(public_url).then(Hsts::default))
        .keep_if_present(&ROUTE_OWNED_HEADERS)
        .build()
}

fn content_security_policy(pages: &[&str]) -> Result<ContentSecurityPolicy, HeaderPolicyError> {
    let mut csp =
        ContentSecurityPolicy::strict().set("style-src", &["'self'", "'unsafe-inline'"])?;
    let mut hashes: Vec<String> = Vec::new();
    for hash in pages.iter().flat_map(|page| inline_script_hashes(page)) {
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    for hash in &hashes {
        csp = csp.add("script-src", hash)?;
    }
    Ok(csp)
}

fn is_https(public_url: &str) -> bool {
    public_url
        .trim()
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

/// CSP source expressions (`'sha256-...'`) for the inline scripts of `html`:
/// every `<script>` element without a `src` attribute, hashed over its exact
/// text as the browser does.
pub fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut hashes = Vec::new();
    let mut rest = html;
    for _ in 0..MAX_INLINE_SCRIPTS {
        let Some((attributes, body, after)) = next_script(rest) else {
            break;
        };
        let has_src = attributes
            .split_whitespace()
            .any(|attribute| attribute.to_ascii_lowercase().starts_with("src="));
        if !has_src {
            let digest = Sha256::digest(body.as_bytes());
            hashes.push(format!("'sha256-{}'", STANDARD.encode(digest)));
        }
        rest = after;
    }
    hashes
}

/// Splits the next `<script ...>body</script` into (attributes, body, rest).
fn next_script(html: &str) -> Option<(&str, &str, &str)> {
    const OPEN: &str = "<script";
    let start = html.find(OPEN)?;
    let after_name = html.get(start + OPEN.len()..)?;
    let (attributes, tail) = after_name.split_once('>')?;
    let close = tail.find("</script")?;
    Some((attributes, tail.get(..close)?, tail.get(close..)?))
}
