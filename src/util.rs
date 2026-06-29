use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Serialize;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type HmacSha256 = Hmac<Sha256>;

pub fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn now_epoch_i64() -> i64 {
    now_epoch() as i64
}

pub fn b64url_no_pad(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode_padded(s: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .or_else(|_| general_purpose::URL_SAFE.decode(s.as_bytes()))
        .context("invalid base64url")
}

pub fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

pub fn random_hex(bytes: usize) -> String {
    let mut out = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut out);
    hex::encode(out)
}

pub fn token_urlsafe(bytes: usize) -> String {
    let mut out = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut out);
    b64url_no_pad(&out)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = tmp_path(path, "tmp");
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_write(path, &bytes)
}

pub fn tmp_path(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    path.with_file_name(format!("{name}.{suffix}"))
}

pub fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

pub fn env_string(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

pub fn strip_non_ascii(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii())
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn json_get_str<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

pub fn toml_get<'a>(v: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    Some(cur)
}

pub fn toml_string(v: Option<&toml::Value>) -> String {
    v.and_then(|x| x.as_str()).unwrap_or("").to_string()
}

pub fn toml_bool(v: Option<&toml::Value>, default: bool) -> bool {
    v.and_then(|x| x.as_bool()).unwrap_or(default)
}

pub fn ensure_object(value: &mut toml::Value) -> &mut toml::map::Map<String, toml::Value> {
    if !value.is_table() {
        *value = toml::Value::Table(toml::map::Map::new());
    }
    value.as_table_mut().expect("table after initialization")
}

pub fn toml_table_mut<'a>(
    root: &'a mut toml::Value,
    path: &[&str],
) -> &'a mut toml::map::Map<String, toml::Value> {
    let mut cur = root;
    for p in path {
        let table = ensure_object(cur);
        cur = table
            .entry((*p).to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    }
    ensure_object(cur)
}
