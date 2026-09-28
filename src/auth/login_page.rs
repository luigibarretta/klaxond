use axum::body::Body;
use axum::http::{Response, StatusCode};

pub(super) fn login_page(
    mode: &str,
    passkeys_enabled: bool,
    magic_link_enabled: bool,
    return_to: &str,
) -> Response<Body> {
    let start_url = format!(
        "/api/auth/login?start=1&return_to={}",
        urlencoding::encode(return_to)
    );
    let start_url = html_attr(&start_url);
    let return_to = html_attr(return_to);
    let primary = primary_auth_html(mode, &start_url, &return_to);
    let passkey = passkey_html(passkeys_enabled);
    let magic_link = magic_link_html(magic_link_enabled, &return_to);
    let author_link = author_link_html();
    let html = login_document(&primary, passkey, &magic_link, &author_link);
    Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store")
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(html))
        .expect("static login response headers are valid")
}

fn primary_auth_html(mode: &str, start_url: &str, return_to: &str) -> String {
    match mode {
        "oidc" => format!(r#"<a class="btn primary" href="{start_url}">Continue with SSO</a>"#),
        "basic" => format!(
            r#"<form class="login-form" method="post" action="/api/auth/local/login">
<input type="hidden" name="return_to" value="{return_to}">
<label><span>Username</span><input name="username" type="text" autocomplete="username" required></label>
<label><span>Password</span><input name="password" type="password" autocomplete="current-password" required></label>
<label><span>TOTP code</span><input name="totp" type="text" inputmode="numeric" pattern="[0-9]{{6}}" autocomplete="one-time-code" placeholder="000000"></label>
<button class="btn primary" type="submit">Sign in</button>
</form>"#
        ),
        "trusted-proxy" => {
            format!(
                r#"<a class="btn primary" href="{return_to}">Continue through trusted proxy</a>"#
            )
        }
        _ => format!(r#"<a class="btn primary" href="{return_to}">Continue</a>"#),
    }
}

fn passkey_html(enabled: bool) -> &'static str {
    if enabled {
        r#"<a class="btn" href="/api/auth/passkey/login">Use passkey</a>"#
    } else {
        ""
    }
}

fn magic_link_html(enabled: bool, return_to: &str) -> String {
    if enabled {
        format!(
            r#"<form class="login-form" method="post" action="/api/auth/magic/request">
<input type="hidden" name="return_to" value="{return_to}">
<label><span>Username</span><input name="username" type="text" autocomplete="username" required></label>
<button class="btn" type="submit">Use magic link</button>
</form>"#
        )
    } else {
        String::new()
    }
}

fn login_document(primary: &str, passkey: &str, magic_link: &str, author_link: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to Klaxond</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="auth-login"><section class="card auth-login-card">
<div class="login-brand">
<img class="login-logo" src="/ui/favicon.svg" alt="" aria-hidden="true">
<div class="login-brand-text"><h1>Klaxond</h1><span>Reliable alerts. Less noise.</span></div>
<span class="login-version">v{version}</span>
</div>
<h2>Sign in to Klaxond</h2>
<p class="login-note">You are signed out locally. If your SSO session is still active, continuing may sign you back in without asking for credentials.</p>
<div class="login-actions">{primary}{passkey}{magic_link}</div>
<nav class="login-legal" aria-label="Legal links">
<a href="/legal/privacy?from=login">Privacy</a>
<a href="/legal/accessibility?from=login">Accessibility</a>
<a href="/legal/terms?from=login">Terms</a>
<a href="/legal/cookies?from=login">Cookies</a>
<a href="/legal/notice?from=login">Legal notice</a>
</nav>
<p class="muted login-byline">by {author_link}</p>
</section></main></body></html>"#,
        version = crate::config::VERSION
    )
}

fn author_link_html() -> String {
    format!(
        r#"<a href="{}" target="_blank" rel="noopener">{}</a>"#,
        html_attr(crate::config::AUTHOR_URL),
        html_attr(crate::config::AUTHOR_NAME)
    )
}

fn html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
