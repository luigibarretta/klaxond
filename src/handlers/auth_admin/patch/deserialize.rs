use serde::Deserialize;
use serde::de::{self, DeserializeOwned};
use serde_json::Value;

pub(super) fn optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(value)) => Some(value),
        _ => None,
    })
}

pub(super) fn optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(value)) => value.as_u64(),
        _ => None,
    })
}

pub(super) fn optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Bool(value)) => Some(value),
        _ => None,
    })
}

pub(super) fn optional_string_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Array(values)) => Some(
            values
                .into_iter()
                .filter_map(|value| match value {
                    Value::String(value) => Some(value),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    })
}

pub(super) fn optional_object_patch<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: DeserializeOwned,
{
    match Option::<Value>::deserialize(deserializer)? {
        Some(value @ Value::Object(_)) => serde_json::from_value(value)
            .map(Some)
            .map_err(de::Error::custom),
        _ => Ok(None),
    }
}
