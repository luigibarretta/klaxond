use super::*;
use std::collections::HashSet;
mod operations;

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
    let openapi = include_str!("../../docs/openapi.yaml");
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
fn openapi_info_version_matches_crate_version() {
    let openapi = include_str!("../../docs/openapi.yaml");
    assert!(
        openapi.contains(&format!("  version: {}", env!("CARGO_PKG_VERSION"))),
        "OpenAPI info.version must match Cargo package version"
    );
}

#[test]
fn all_ingest_operations_document_fail_closed_auth_responses() {
    let openapi = include_str!("../../docs/openapi.yaml");
    let paths = [
        "/webhook/{severity}",
        "/beszel/{severity}",
        "/healthchecks/{severity}",
        "/uptime-kuma/{severity}",
        "/wud/{severity}",
        "/authentik/{severity}",
        "/shelfmark/{severity}",
        "/prowlarr/{severity}",
        "/decypharr/{severity}",
        "/pve/{severity}",
        "/blackstart/{severity}",
        "/github/{severity}",
        "/revaulter/{severity}",
        "/ingest/{source}/{severity}",
    ];

    for path in paths {
        let block = openapi_operation_block(openapi, path, "post")
            .unwrap_or_else(|| panic!("OpenAPI missing ingest operation POST {path}"));
        assert!(
            block.contains("\"401\":")
                && block.contains("#/components/responses/IngestUnauthorized"),
            "OpenAPI ingest operation POST {path} must document invalid credentials as 401"
        );
        assert!(
            block.contains("\"404\":")
                && block.contains("#/components/responses/IngestSourceDisabled"),
            "OpenAPI ingest operation POST {path} must document a disabled source as 404"
        );
    }
}

#[test]
fn csrf_required_mutations_are_documented_with_csrf_header() {
    let openapi = include_str!("../../docs/openapi.yaml");
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
    let openapi = include_str!("../../docs/openapi.yaml");
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
        required_scope(&Method::GET, "/api/status/activity"),
        "status:read"
    );
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
        required_scope(&Method::DELETE, "/api/auth/config"),
        "auth:write"
    );
}

#[test]
fn csrf_and_sudo_policy_preserves_existing_sensitive_paths() {
    assert!(csrf_exempt_mutation("/api/render-preview"));
    assert!(csrf_exempt_mutation("/api/client-log"));
    assert!(csrf_exempt_mutation("/api/policy-simulate"));
    assert!(!csrf_exempt_mutation("/api/auth/config"));
    assert!(requires_sudo("/api/auth/config"));
    assert!(requires_sudo("/api/config/restore"));
    assert!(!requires_sudo("/api/render-preview"));
    assert!(!requires_sudo("/api/test/critical"));
}

#[test]
fn audit_actions_are_owned_by_endpoint_policy() {
    assert_eq!(
        audit_action_for_post("/api/auth/config"),
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
        EndpointMethod::Mutation => match policy.path {
            PathPattern::Prefix("/api/auth/tokens/")
            | PathPattern::Prefix("/api/auth/passkey/credentials/") => "delete",
            _ => "post",
        },
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
