use super::super::render::{load_render_config, read_component_dashboards, read_component_image};
use super::super::{Paths, default_icons, default_priorities, default_tag_prefixes};
use super::{EmptyExt, env_or_positive_toml_u64, merge_string_map, nonempty_env_or_toml};
use crate::util::{env_string, toml_get};
use anyhow::Result;
use std::collections::HashMap;

pub(super) struct RenderRuntime {
    pub(super) priorities: HashMap<String, String>,
    pub(super) icons: HashMap<String, String>,
    pub(super) tag_prefixes: HashMap<String, String>,
    pub(super) fallback_runbooks: HashMap<String, String>,
    pub(super) source_urls: HashMap<String, String>,
    pub(super) component_dashboards: HashMap<String, [String; 2]>,
    pub(super) component_image: HashMap<String, (String, Option<u64>)>,
    pub(super) grafana_base: String,
    pub(super) grafana_render_base: String,
    pub(super) grafana_render_token: String,
    pub(super) render_image_ttl: u64,
}

struct RenderMaps {
    priorities: HashMap<String, String>,
    icons: HashMap<String, String>,
    tag_prefixes: HashMap<String, String>,
    fallback_runbooks: HashMap<String, String>,
    source_urls: HashMap<String, String>,
}

pub(super) fn load_render(paths: &Paths, toml: &toml::Value) -> Result<RenderRuntime> {
    let maps = render_maps(toml);
    let seed = read_component_dashboards(toml_get(toml, &["render", "component_dashboards"]));
    Ok(RenderRuntime {
        priorities: maps.priorities,
        icons: maps.icons,
        tag_prefixes: maps.tag_prefixes,
        fallback_runbooks: maps.fallback_runbooks,
        source_urls: maps.source_urls,
        component_dashboards: load_render_config(paths, &seed)?,
        component_image: read_component_image(toml_get(toml, &["render", "component_image"])),
        grafana_base: nonempty_env_or_toml("GRAFANA_BASE", toml, &["render", "grafana_base"])
            .if_empty_else(|| "https://grafana.example.com".to_string())
            .trim_end_matches('/')
            .to_string(),
        grafana_render_base: nonempty_env_or_toml(
            "GRAFANA_RENDER_BASE",
            toml,
            &["render", "grafana_render_base"],
        )
        .trim_end_matches('/')
        .to_string(),
        grafana_render_token: nonempty_env_or_toml(
            "GRAFANA_RENDER_TOKEN",
            toml,
            &["render", "grafana_render_token"],
        ),
        render_image_ttl: env_or_positive_toml_u64(
            "RENDER_IMAGE_TTL",
            toml,
            &["render", "render_image_ttl"],
            900,
        ),
    })
}

fn render_maps(toml: &toml::Value) -> RenderMaps {
    let mut priorities = default_priorities();
    merge_string_map(
        &mut priorities,
        toml_get(toml, &["render", "severity_priority"]),
    );
    let mut icons = default_icons();
    merge_string_map(&mut icons, toml_get(toml, &["render", "severity_emoji"]));
    let mut tag_prefixes = default_tag_prefixes();
    merge_string_map(
        &mut tag_prefixes,
        toml_get(toml, &["render", "severity_tag_prefix"]),
    );
    let mut fallback_runbooks = HashMap::from([
        ("beszel".to_string(), String::new()),
        ("healthchecks".to_string(), String::new()),
    ]);
    merge_string_map(
        &mut fallback_runbooks,
        toml_get(toml, &["render", "fallback_runbooks"]),
    );
    let mut source_urls = HashMap::new();
    merge_string_map(&mut source_urls, toml_get(toml, &["render", "source_urls"]));
    for (source, env) in [
        ("uptime-kuma", "KLAXOND_SOURCE_URL_UPTIME_KUMA"),
        ("healthchecks", "KLAXOND_SOURCE_URL_HEALTHCHECKS"),
        ("wud", "KLAXOND_SOURCE_URL_WUD"),
        ("pve", "KLAXOND_SOURCE_URL_PVE"),
        ("shelfmark", "KLAXOND_SOURCE_URL_SHELFMARK"),
        ("prowlarr", "KLAXOND_SOURCE_URL_PROWLARR"),
        ("decypharr", "KLAXOND_SOURCE_URL_DECYPHARR"),
        ("revaulter", "KLAXOND_SOURCE_URL_REVAULTER"),
    ] {
        let value = env_string(env);
        if !value.trim().is_empty() {
            source_urls.insert(source.to_string(), value);
        }
    }
    RenderMaps {
        priorities,
        icons,
        tag_prefixes,
        fallback_runbooks,
        source_urls,
    }
}
