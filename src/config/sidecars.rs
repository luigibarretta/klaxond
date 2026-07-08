use super::auth_sidecar::merge_auth_toml;
use super::dedup_config::dedup_from_toml;
use super::ntfy_topics::ntfy_topics_from_toml;
use super::render::read_component_dashboards;
use super::{AuthConfig, Paths, save_auth, save_dedup, save_ntfy_topics, save_render_config};
use crate::util::toml_get;
use anyhow::Result;

pub fn restore_sidecars_from_toml(paths: &Paths, toml: &toml::Value) -> Result<Vec<&'static str>> {
    let mut restored = Vec::new();
    if toml_get(toml, &["render", "component_dashboards"]).is_some() {
        let dashboards =
            read_component_dashboards(toml_get(toml, &["render", "component_dashboards"]));
        if !dashboards.is_empty() {
            save_render_config(paths, &dashboards)?;
            restored.push("render");
        }
    }
    if toml_get(toml, &["dedup"]).is_some() {
        let dedup = dedup_from_toml(toml_get(toml, &["dedup"]));
        save_dedup(paths, &dedup)?;
        restored.push("dedup");
    }
    if let Some(auth_seed) = toml_get(toml, &["auth"]) {
        let auth = merge_auth_toml(AuthConfig::default(), auth_seed);
        save_auth(paths, &auth)?;
        restored.push("auth");
    }
    if let Some(topics) = ntfy_topics_from_toml(toml) {
        let topics = topics
            .into_iter()
            .filter(|t| !t.name.is_empty())
            .collect::<Vec<_>>();
        if !topics.is_empty() {
            save_ntfy_topics(paths, &topics)?;
            restored.push("ntfy_topics");
        }
    }
    Ok(restored)
}
