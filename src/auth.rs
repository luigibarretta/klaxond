use crate::config::AuthConfig;
use crate::state::AppState;
use crate::util::{b64url_decode_padded, b64url_no_pad, hmac_hex, now_epoch_i64, token_urlsafe};
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE, HOST, SET_COOKIE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use bcrypt::verify;
use constant_time_eq::constant_time_eq;
use ipnet::IpNet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use url::Url;

const PUBLIC_PREFIXES: &[&str] = &[
    "/webhook/",
    "/beszel/",
    "/healthchecks/",
    "/wud/",
    "/authentik/",
    "/shelfmark/",
    "/prowlarr/",
    "/decypharr/",
    "/pve/",
    "/healthz",
    "/metrics",
    "/api/ack/",
    "/img/",
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/static/",
    "/favicon.ico",
];

pub const AUTH_SESSION_COOKIE: &str = "klaxond_session";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub sub: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub mode: String,
    #[serde(default)]
    pub exp: i64,
}

pub enum AuthOutcome {
    Authorized(User, Option<String>),
    Rejected(Response<Body>),
}

pub fn is_public(path: &str) -> bool {
    PUBLIC_PREFIXES
        .iter()
        .any(|p| path == *p || path.starts_with(p))
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let cfg = state.cfg().auth;
    if cfg.mode == "none" {
        return AuthOutcome::Authorized(
            User {
                sub: "anonymous".into(),
                email: String::new(),
                name: String::new(),
                groups: vec![],
                mode: "none".into(),
                exp: 0,
            },
            None,
        );
    }
    if let Some(cookie) = headers.get(COOKIE).and_then(|v| v.to_str().ok())
        && let Some(value) = cookie_value(cookie, AUTH_SESSION_COOKIE)
        && let Some(user) = verify_session(state, value)
    {
        return AuthOutcome::Authorized(user, None);
    }
    match cfg.mode.as_str() {
        "basic" => authenticate_basic(state, &cfg, headers),
        "trusted-proxy" => authenticate_trusted_proxy(&cfg, headers, peer),
        "oidc" => {
            let location = format!("/auth/login?return_to={}", urlencoding::encode(path));
            AuthOutcome::Rejected(redirect(&location))
        }
        _ => AuthOutcome::Rejected(StatusCode::FORBIDDEN.into_response()),
    }
}

fn authenticate_basic(state: &AppState, cfg: &AuthConfig, headers: &HeaderMap) -> AuthOutcome {
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(raw) = auth.strip_prefix("Basic ")
        && let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw)
        && let Ok(s) = String::from_utf8(decoded)
        && let Some((user, pwd)) = s.split_once(':')
        && cfg.basic.username == user
        && !cfg.basic.password_hash.is_empty()
        && verify(pwd, &cfg.basic.password_hash).unwrap_or(false)
    {
        let mut u = User {
            sub: user.to_string(),
            email: String::new(),
            name: String::new(),
            groups: vec![],
            mode: "basic".into(),
            exp: 0,
        };
        let cookie = issue_session(state, cfg, &mut u);
        return AuthOutcome::Authorized(u, Some(cookie));
    }
    let mut resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .unwrap();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("Basic realm=\"{}\"", cfg.basic.realm)).unwrap(),
    );
    AuthOutcome::Rejected(resp)
}

fn authenticate_trusted_proxy(
    cfg: &AuthConfig,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> AuthOutcome {
    let peer_ip = peer.map(|p| p.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    if !cidr_match(peer_ip, &cfg.trusted_proxy.trusted_cidrs) {
        return AuthOutcome::Rejected(
            (StatusCode::FORBIDDEN, "untrusted peer (trusted-proxy mode)").into_response(),
        );
    }
    let uh = &cfg.trusted_proxy.user_header;
    let Some(user_val) = header_by_name(headers, uh) else {
        return AuthOutcome::Rejected(
            (StatusCode::UNAUTHORIZED, format!("missing {uh} header")).into_response(),
        );
    };
    AuthOutcome::Authorized(
        User {
            sub: user_val,
            email: header_by_name(headers, &cfg.trusted_proxy.email_header).unwrap_or_default(),
            groups: header_by_name(headers, &cfg.trusted_proxy.groups_header)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.to_string())
                .collect(),
            name: String::new(),
            mode: "trusted-proxy".into(),
            exp: 0,
        },
        None,
    )
}

pub async fn oidc_login_redirect(
    state: &AppState,
    headers: HeaderMap,
    uri: &str,
) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let issuer = cfg.issuer.trim_end_matches('/').to_string();
    if issuer.is_empty() || cfg.client_id.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "OIDC not configured (set issuer + client_id in Auth tab)",
        )
            .into_response();
    }
    let discovery = match oidc_discovery(state, &issuer).await {
        Ok(d) => d,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
    let return_to = Url::parse(&format!("http://localhost{uri}"))
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "return_to")
                .map(|(_, v)| v.to_string())
        })
        .unwrap_or_else(|| "/".into());
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let scheme = if headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https")
        == "https"
    {
        "https"
    } else {
        "http"
    };
    let redirect_uri = format!("{scheme}://{host}{}", cfg.redirect_path);
    let state_token = token_urlsafe(24);
    {
        let mut states = state.oidc_states.lock().expect("oidc states poisoned");
        states.insert(state_token.clone(), (crate::util::now_epoch(), return_to));
        let cutoff = crate::util::now_epoch() - 600.0;
        states.retain(|_, (ts, _)| *ts >= cutoff);
    }
    let mut url = Url::parse(
        discovery
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )
    .unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &cfg.scopes)
        .append_pair("state", &state_token);
    redirect(url.as_str())
}

pub async fn oidc_callback(state: &AppState, headers: HeaderMap, uri: &str) -> Response<Body> {
    let cfg = state.cfg().auth.oidc;
    let issuer = cfg.issuer.trim_end_matches('/').to_string();
    let parsed = Url::parse(&format!("http://localhost{uri}")).unwrap();
    let code = parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string());
    let state_param = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string());
    let (Some(code), Some(state_param)) = (code, state_param) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    let return_to = {
        let mut states = state.oidc_states.lock().expect("oidc states poisoned");
        match states.remove(&state_param) {
            Some((_, ret)) => ret,
            None => return redirect("/"),
        }
    };
    let discovery = match oidc_discovery(state, &issuer).await {
        Ok(d) => d,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("OIDC discovery failed: {err}"),
            )
                .into_response();
        }
    };
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let scheme = if headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https")
        == "https"
    {
        "https"
    } else {
        "http"
    };
    let redirect_uri = format!("{scheme}://{host}{}", cfg.redirect_path);
    let token_endpoint = discovery
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tokens = match state
        .http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &cfg.client_id),
            ("client_secret", &cfg.client_secret),
        ])
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => v,
            Err(err) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("token exchange failed: {err}"),
                )
                    .into_response();
            }
        },
        Ok(resp) => {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return (
                StatusCode::BAD_GATEWAY,
                format!(
                    "token exchange failed: {code} {}",
                    &body[..body.len().min(200)]
                ),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("token exchange failed: {err}"),
            )
                .into_response();
        }
    };
    let Some(id_token) = tokens.get("id_token").and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_GATEWAY, "no id_token in response").into_response();
    };
    let claims = match verify_id_token(state, &issuer, &discovery, id_token, &cfg.client_id).await {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                format!("id_token verify failed: {err}"),
            )
                .into_response();
        }
    };
    if !cfg.required_group.trim().is_empty() {
        let groups = claims
            .get("groups")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !groups
            .iter()
            .any(|g| g.as_str() == Some(cfg.required_group.as_str()))
        {
            return (
                StatusCode::FORBIDDEN,
                format!("required_group '{}' not in user claims", cfg.required_group),
            )
                .into_response();
        }
    }
    let mut user = User {
        sub: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        email: claims
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: claims
            .get("name")
            .or_else(|| claims.get("preferred_username"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        groups: claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        mode: "oidc".into(),
        exp: 0,
    };
    let cfg_all = state.cfg().auth;
    let cookie = issue_session(state, &cfg_all, &mut user);
    let mut resp = redirect(if return_to.is_empty() {
        "/"
    } else {
        &return_to
    });
    resp.headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

pub fn logout() -> Response<Body> {
    let mut resp = redirect("/");
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("klaxond_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"),
    );
    resp
}

fn issue_session(state: &AppState, cfg: &AuthConfig, user: &mut User) -> String {
    user.exp = now_epoch_i64() + (cfg.session_timeout_hours * 3600) as i64;
    let payload = serde_json::to_vec(user).unwrap_or_default();
    let body = b64url_no_pad(&payload);
    let sig = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    let val = format!("{body}.{sig}");
    format!(
        "{AUTH_SESSION_COOKIE}={val}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}",
        cfg.session_timeout_hours * 3600
    )
}

fn verify_session(state: &AppState, cookie_value: &str) -> Option<User> {
    let (body, sig) = cookie_value.split_once('.')?;
    let expected = hmac_hex(state.session_key.as_slice(), body.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let bytes = b64url_decode_padded(body).ok()?;
    let user: User = serde_json::from_slice(&bytes).ok()?;
    if user.exp > 0 && user.exp < now_epoch_i64() {
        return None;
    }
    Some(user)
}

fn cookie_value<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    for c in cookie.split(';') {
        let c = c.trim();
        if let Some(rest) = c.strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
    }
    None
}

fn cidr_match(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

fn header_by_name(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

fn redirect(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap()
}

async fn oidc_discovery(state: &AppState, issuer: &str) -> anyhow::Result<Value> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    Ok(state
        .http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?)
}

async fn verify_id_token(
    state: &AppState,
    issuer: &str,
    discovery: &Value,
    id_token: &str,
    client_id: &str,
) -> anyhow::Result<Value> {
    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("issuer discovery missing jwks_uri"))?;
    let jwks = state
        .http
        .get(jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow::anyhow!("kid not found in JWKS"))?;
    let key = DecodingKey::from_jwk(jwk)?;
    let alg = header.alg;
    let mut validation = Validation::new(match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384 => alg,
        _ => Algorithm::RS256,
    });
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[discovery
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or(issuer)]);
    let data = decode::<Value>(id_token, &key, &validation)?;
    Ok(data.claims)
}
