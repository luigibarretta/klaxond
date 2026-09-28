pub(super) fn env_or_toml_bool(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: bool,
) -> anyhow::Result<bool> {
    if std::env::var_os(env).is_some() {
        return env_bool(env, fallback);
    }
    Ok(table
        .and_then(|value| value.get(key))
        .and_then(toml::Value::as_bool)
        .unwrap_or(fallback))
}

pub(super) fn env_or_toml_u64(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: u64,
) -> anyhow::Result<u64> {
    if std::env::var_os(env).is_some() {
        return env_u64(env, fallback);
    }
    Ok(table
        .and_then(|value| value.get(key))
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(fallback))
}

pub(super) fn env_or_toml_u32(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: u32,
) -> anyhow::Result<u32> {
    let value = env_or_toml_u64(table, env, key, u64::from(fallback))?;
    u32::try_from(value).map_err(|_| anyhow::anyhow!("{env} must fit in an unsigned integer"))
}

pub(super) fn env_or_toml_list(
    table: Option<&toml::Value>,
    env: &str,
    key: &str,
    fallback: Vec<String>,
) -> Vec<String> {
    std::env::var(env)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| csv_list(&value))
        .or_else(|| {
            table
                .and_then(|value| value.get(key))
                .and_then(toml::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
        })
        .unwrap_or(fallback)
}

pub(super) fn env_bool(name: &str, fallback: bool) -> anyhow::Result<bool> {
    let Ok(value) = std::env::var(name) else {
        return Ok(fallback);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("{name} must be a boolean"),
    }
}

pub(super) fn env_u64(name: &str, fallback: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{name} must be an unsigned integer")),
        Err(_) => Ok(fallback),
    }
}

pub(super) fn env_u32(name: &str, fallback: u32) -> anyhow::Result<u32> {
    u32::try_from(env_u64(name, u64::from(fallback))?)
        .map_err(|_| anyhow::anyhow!("{name} must fit in an unsigned integer"))
}

pub(super) fn csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) fn table_string(table: &toml::Table, key: &str, fallback: &str) -> String {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

pub(super) fn table_bool(table: &toml::Table, key: &str, fallback: bool) -> bool {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or(fallback)
}

pub(super) fn table_u64(table: &toml::Table, key: &str, fallback: u64) -> u64 {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(fallback)
}

pub(super) fn table_u32(table: &toml::Table, key: &str, fallback: u32) -> u32 {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(fallback)
}

pub(super) fn table_list(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
