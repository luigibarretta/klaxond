//! Central endpoint metadata used by auth, audit and documentation checks.

use axum::http::Method;
#[cfg(test)]
use std::collections::HashSet;

const DEFAULT_GET_SCOPE: &str = "admin:read";
const DEFAULT_MUTATION_SCOPE: &str = "admin:*";

pub const PUBLIC_ROUTES: &[PathPattern] = &[
    PathPattern::Prefix("/webhook/"),
    PathPattern::Prefix("/beszel/"),
    PathPattern::Prefix("/healthchecks/"),
    PathPattern::Prefix("/wud/"),
    PathPattern::Prefix("/authentik/"),
    PathPattern::Prefix("/shelfmark/"),
    PathPattern::Prefix("/prowlarr/"),
    PathPattern::Prefix("/decypharr/"),
    PathPattern::Prefix("/pve/"),
    PathPattern::Prefix("/healthz"),
    PathPattern::Prefix("/metrics"),
    PathPattern::Prefix("/api/ack/"),
    PathPattern::Prefix("/img/"),
    PathPattern::Prefix("/auth/login"),
    PathPattern::Prefix("/auth/callback"),
    PathPattern::Prefix("/auth/logout"),
    PathPattern::Prefix("/auth/passkey"),
    PathPattern::Prefix("/static/"),
    PathPattern::Prefix("/favicon.ico"),
    PathPattern::Exact("/ui/privacy"),
    PathPattern::Exact("/ui/accessibility"),
    PathPattern::Exact("/ui/terms"),
    PathPattern::Exact("/ui/cookies"),
    PathPattern::Exact("/ui/legal"),
    PathPattern::Exact("/openapi.yaml"),
    PathPattern::Exact("/api/openapi.yaml"),
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EndpointMethod {
    Get,
    Mutation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathPattern {
    Exact(&'static str),
    Prefix(&'static str),
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicy {
    pub method: EndpointMethod,
    pub path: PathPattern,
    pub scope: &'static str,
    pub csrf: CsrfPolicy,
    pub reauth: ReauthPolicy,
    pub audit: AuditPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrfPolicy {
    Required,
    Exempt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReauthPolicy {
    None,
    LocalSudo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditPolicy {
    None,
    Action(&'static str),
}

impl AuditPolicy {
    fn action(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Action(action) => Some(action),
        }
    }
}

impl PathPattern {
    fn matches(self, path: &str) -> bool {
        match self {
            Self::Exact(exact) => path == exact,
            Self::Prefix(prefix) => path.starts_with(prefix),
        }
    }

    #[cfg(test)]
    fn openapi_path(self) -> &'static str {
        match self {
            Self::Exact(exact) => exact,
            Self::Prefix("/api/test/") => "/api/test/{severity}",
            Self::Prefix(prefix) => prefix,
        }
    }
}

pub const ENDPOINT_POLICIES: &[EndpointPolicy] = &[
    get("/auth/me", "status:read"),
    get("/api/auth-config", "auth:read"),
    get("/api/auth/tokens", DEFAULT_GET_SCOPE),
    get("/api/auth/passkeys", DEFAULT_GET_SCOPE),
    get("/api/logs", "logs:read"),
    get("/api/audit", "audit:read"),
    get("/api/config/backup", "config:read"),
    get("/api/config/export", "admin:*"),
    get("/api/config/backups", "status:read"),
    get("/api/status", "status:read"),
    get("/api/deliveries", "status:read"),
    get("/api/cascade-config", "status:read"),
    get("/api/setup-status", "status:read"),
    get("/api/channel-test-matrix", "status:read"),
    get("/inhibitions", DEFAULT_GET_SCOPE),
    get("/api/inhibitions", DEFAULT_GET_SCOPE),
    get("/api/render-config", DEFAULT_GET_SCOPE),
    get("/api/ntfy-topics", DEFAULT_GET_SCOPE),
    get("/api/dedup-config", DEFAULT_GET_SCOPE),
    get("/api/delivery-config", DEFAULT_GET_SCOPE),
    get("/api/channel-config", DEFAULT_GET_SCOPE),
    get("/api/ingest-auth", DEFAULT_GET_SCOPE),
    get("/api/schedules", DEFAULT_GET_SCOPE),
    get("/api/acks", DEFAULT_GET_SCOPE),
    get("/api/inhibition-rules", DEFAULT_GET_SCOPE),
    sensitive_mutation("/api/auth-config", "auth:write", "auth.update"),
    sensitive_mutation("/api/auth/tokens", "auth:write", "auth.token.create"),
    sensitive_mutation("/api/auth/tokens/revoke", "auth:write", "auth.token.revoke"),
    sensitive_mutation("/api/auth/totp/start", "auth:write", "auth.totp.start"),
    sensitive_mutation("/api/auth/totp/enable", "auth:write", "auth.totp.enable"),
    sensitive_mutation("/api/auth/totp/disable", "auth:write", "auth.totp.disable"),
    sensitive_mutation(
        "/api/auth/passkeys/register/start",
        "auth:write",
        "auth.passkey.register.start",
    ),
    sensitive_mutation(
        "/api/auth/passkeys/register/finish",
        "auth:write",
        "auth.passkey.register.finish",
    ),
    sensitive_mutation(
        "/api/auth/passkeys/delete",
        "auth:write",
        "auth.passkey.delete",
    ),
    audited_exempt_mutation(
        "/api/config/import-preview",
        "config:read",
        "config.import_preview",
    ),
    sensitive_mutation("/api/config/restore", "config:write", "config.restore"),
    sensitive_mutation(
        "/api/channel-config",
        "routing:write",
        "config.channel.update",
    ),
    sensitive_mutation(
        "/api/ntfy-topics",
        "routing:write",
        "config.ntfy_topics.update",
    ),
    sensitive_mutation(
        "/api/ingest-auth",
        "routing:write",
        "config.ingest_auth.update",
    ),
    sensitive_mutation("/api/render-config", "render:write", "config.render.update"),
    exempt_mutation("/api/render-preview", "render:write"),
    sensitive_mutation(
        "/api/cascade-config",
        "cascade:write",
        "config.cascade.update",
    ),
    sensitive_mutation("/api/cascade/toggle", "cascade:write", "cascade.toggle"),
    exempt_mutation("/api/client-log", "admin:read"),
    exempt_mutation("/api/policy-simulate", "status:read"),
    sensitive_mutation(
        "/api/delivery-config",
        "delivery:write",
        "config.delivery.update",
    ),
    sensitive_mutation("/api/dedup-config", "dedup:write", "config.dedup.update"),
    sensitive_mutation(
        "/api/inhibition-rules",
        "inhibitions:write",
        "config.inhibition_rules.update",
    ),
    exempt_mutation("/api/inhibition-rules/test", "inhibitions:write"),
    sensitive_mutation(
        "/api/inhibitions/clear",
        "inhibitions:write",
        "runtime.inhibitions.clear",
    ),
    sensitive_mutation(
        "/api/schedules",
        "inhibitions:write",
        "config.schedules.update",
    ),
    sensitive_mutation("/api/acks/clear", "inhibitions:write", "runtime.acks.clear"),
    EndpointPolicy {
        method: EndpointMethod::Mutation,
        path: PathPattern::Prefix("/api/test/"),
        scope: "test:write",
        csrf: CsrfPolicy::Required,
        reauth: ReauthPolicy::None,
        audit: AuditPolicy::None,
    },
];

pub fn is_public(path: &str) -> bool {
    if is_public_ui_asset(path) {
        return true;
    }
    PUBLIC_ROUTES.iter().any(|route| route.matches(path))
}

pub fn required_scope(method: &Method, path: &str) -> &'static str {
    let endpoint_method = endpoint_method(method);
    policy_for(endpoint_method, path)
        .map(|policy| policy.scope)
        .unwrap_or_else(|| match endpoint_method {
            EndpointMethod::Get => DEFAULT_GET_SCOPE,
            EndpointMethod::Mutation => DEFAULT_MUTATION_SCOPE,
        })
}

pub fn csrf_exempt_mutation(path: &str) -> bool {
    policy_for(EndpointMethod::Mutation, path)
        .map(|policy| policy.csrf == CsrfPolicy::Exempt)
        .unwrap_or(false)
}

pub fn requires_sudo(path: &str) -> bool {
    policy_for(EndpointMethod::Mutation, path)
        .map(|policy| policy.reauth == ReauthPolicy::LocalSudo)
        .unwrap_or(false)
}

pub fn audit_action_for_post(path: &str) -> Option<&'static str> {
    policy_for(EndpointMethod::Mutation, path).and_then(|policy| policy.audit.action())
}

fn policy_for(method: EndpointMethod, path: &str) -> Option<&'static EndpointPolicy> {
    ENDPOINT_POLICIES
        .iter()
        .find(|policy| policy.method == method && policy.path.matches(path))
}

fn endpoint_method(method: &Method) -> EndpointMethod {
    if *method == Method::GET {
        EndpointMethod::Get
    } else {
        EndpointMethod::Mutation
    }
}

const fn get(path: &'static str, scope: &'static str) -> EndpointPolicy {
    EndpointPolicy {
        method: EndpointMethod::Get,
        path: PathPattern::Exact(path),
        scope,
        csrf: CsrfPolicy::Required,
        reauth: ReauthPolicy::None,
        audit: AuditPolicy::None,
    }
}

const fn sensitive_mutation(
    path: &'static str,
    scope: &'static str,
    audit_action: &'static str,
) -> EndpointPolicy {
    EndpointPolicy {
        method: EndpointMethod::Mutation,
        path: PathPattern::Exact(path),
        scope,
        csrf: CsrfPolicy::Required,
        reauth: ReauthPolicy::LocalSudo,
        audit: AuditPolicy::Action(audit_action),
    }
}

const fn exempt_mutation(path: &'static str, scope: &'static str) -> EndpointPolicy {
    EndpointPolicy {
        method: EndpointMethod::Mutation,
        path: PathPattern::Exact(path),
        scope,
        csrf: CsrfPolicy::Exempt,
        reauth: ReauthPolicy::None,
        audit: AuditPolicy::None,
    }
}

const fn audited_exempt_mutation(
    path: &'static str,
    scope: &'static str,
    audit_action: &'static str,
) -> EndpointPolicy {
    EndpointPolicy {
        method: EndpointMethod::Mutation,
        path: PathPattern::Exact(path),
        scope,
        csrf: CsrfPolicy::Exempt,
        reauth: ReauthPolicy::None,
        audit: AuditPolicy::Action(audit_action),
    }
}

fn is_public_ui_asset(path: &str) -> bool {
    path.starts_with("/ui/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policies_do_not_duplicate_method_and_path() {
        let mut seen = HashSet::new();
        for policy in ENDPOINT_POLICIES {
            assert!(
                seen.insert((policy.method, policy.path)),
                "duplicate endpoint policy: {:?} {:?}",
                policy.method,
                policy.path
            );
        }
    }

    #[test]
    fn public_routes_do_not_duplicate_patterns() {
        let mut seen = HashSet::new();
        for route in PUBLIC_ROUTES {
            assert!(seen.insert(*route), "duplicate public route: {route:?}");
        }
    }

    #[test]
    fn sudo_mutations_require_csrf() {
        for policy in ENDPOINT_POLICIES {
            if policy.reauth == ReauthPolicy::LocalSudo {
                assert!(
                    policy.csrf == CsrfPolicy::Required,
                    "sudo mutation must require CSRF: {:?}",
                    policy.path
                );
            }
        }
    }

    #[test]
    fn all_known_exact_endpoints_are_documented_in_openapi() {
        let openapi = include_str!("../docs/openapi.yaml");
        let documented = ENDPOINT_POLICIES
            .iter()
            .map(|policy| policy.path.openapi_path())
            .collect::<HashSet<_>>();

        for path in documented {
            assert!(
                openapi.contains(&format!("  {path}:")),
                "OpenAPI missing path {path}"
            );
        }
    }

    #[test]
    fn csrf_required_mutations_are_documented_with_csrf_header() {
        let openapi = include_str!("../docs/openapi.yaml");
        for policy in ENDPOINT_POLICIES
            .iter()
            .filter(|policy| policy.method == EndpointMethod::Mutation)
        {
            let block = documented_operation(openapi, policy);
            let has_csrf = block.contains("csrfHeader");
            assert_eq!(
                has_csrf,
                policy.csrf == CsrfPolicy::Required,
                "OpenAPI CSRF documentation drift for {:?}",
                policy.path
            );
        }
    }

    #[test]
    fn sudo_mutations_are_documented_with_reauth_required() {
        let openapi = include_str!("../docs/openapi.yaml");
        for policy in ENDPOINT_POLICIES
            .iter()
            .filter(|policy| policy.method == EndpointMethod::Mutation)
        {
            let block = documented_operation(openapi, policy);
            let has_reauth = block.contains("ReauthRequired");
            assert_eq!(
                has_reauth,
                policy.reauth == ReauthPolicy::LocalSudo,
                "OpenAPI reauth documentation drift for {:?}",
                policy.path
            );
        }
    }

    #[test]
    fn scope_policy_preserves_existing_access_contracts() {
        assert_eq!(required_scope(&Method::GET, "/api/logs"), "logs:read");
        assert_eq!(required_scope(&Method::GET, "/api/audit"), "audit:read");
        assert_eq!(
            required_scope(&Method::GET, "/api/config/backup"),
            "config:read"
        );
        assert_eq!(
            required_scope(&Method::GET, "/api/config/export"),
            "admin:*"
        );
        assert_eq!(
            required_scope(&Method::GET, "/api/auth/tokens"),
            "admin:read"
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/config/import-preview"),
            "config:read"
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/config/restore"),
            "config:write"
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/test/critical"),
            "test:write"
        );
        assert_eq!(
            required_scope(&Method::DELETE, "/api/auth-config"),
            "auth:write"
        );
    }

    #[test]
    fn csrf_and_sudo_policy_preserves_existing_sensitive_paths() {
        assert!(csrf_exempt_mutation("/api/render-preview"));
        assert!(csrf_exempt_mutation("/api/client-log"));
        assert!(csrf_exempt_mutation("/api/policy-simulate"));
        assert!(!csrf_exempt_mutation("/api/auth-config"));
        assert!(requires_sudo("/api/auth-config"));
        assert!(requires_sudo("/api/config/restore"));
        assert!(!requires_sudo("/api/render-preview"));
        assert!(!requires_sudo("/api/test/critical"));
    }

    #[test]
    fn audit_actions_are_owned_by_endpoint_policy() {
        assert_eq!(
            audit_action_for_post("/api/auth-config"),
            Some("auth.update")
        );
        assert_eq!(
            audit_action_for_post("/api/config/import-preview"),
            Some("config.import_preview")
        );
        assert_eq!(audit_action_for_post("/api/render-preview"), None);
    }

    fn documented_operation<'a>(openapi: &'a str, policy: &EndpointPolicy) -> &'a str {
        let path = policy.path.openapi_path();
        let method = match policy.method {
            EndpointMethod::Get => "get",
            EndpointMethod::Mutation => "post",
        };
        openapi_operation_block(openapi, path, method).unwrap_or_else(|| {
            panic!(
                "OpenAPI missing operation {method} {path} for {:?}",
                policy.path
            )
        })
    }

    fn openapi_operation_block<'a>(openapi: &'a str, path: &str, method: &str) -> Option<&'a str> {
        let path_marker = format!("  {path}:");
        let path_start = openapi.find(&path_marker)?;
        let path_rest = &openapi[path_start..];
        let next_path = path_rest[path_marker.len()..]
            .find("\n  /")
            .map(|idx| path_marker.len() + idx);
        let components = path_rest.find("\ncomponents:");
        let path_end = [next_path, components]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(path_rest.len());
        let path_block = &path_rest[..path_end];
        let method_marker = format!("    {method}:");
        let method_start = path_block.find(&method_marker)?;
        Some(&path_block[method_start..])
    }
}
