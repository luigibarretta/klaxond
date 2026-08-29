//! Central endpoint metadata used by auth, audit and documentation checks.

use axum::http::Method;

const DEFAULT_GET_SCOPE: &str = "admin:read";
const DEFAULT_MUTATION_SCOPE: &str = "admin:*";

mod policies;
#[cfg(test)]
mod tests;

pub use policies::{ENDPOINT_POLICIES, PUBLIC_ROUTES};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EndpointMethod {
    Get,
    Mutation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathPattern {
    Exact(&'static str),
    Prefix(&'static str),
    EmergencyDetail,
    EmergencyAction,
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
            Self::EmergencyDetail => emergency_segments(path) == 1,
            Self::EmergencyAction => emergency_segments(path) == 2,
        }
    }

    #[cfg(test)]
    fn openapi_path(self) -> &'static str {
        match self {
            Self::Exact(exact) => exact,
            Self::Prefix("/api/test/") => "/api/test/{severity}",
            Self::Prefix("/api/auth/tokens/") => "/api/auth/tokens/{id}",
            Self::Prefix("/api/auth/magic/callback/") => "/api/auth/magic/callback/{token}",
            Self::Prefix("/api/auth/passkey/credentials/") => "/api/auth/passkey/credentials/{id}",
            Self::Prefix("/api/emergencies/") => "/api/emergencies/{id}",
            Self::Prefix(prefix) => prefix,
            Self::EmergencyDetail => "/api/emergencies/{id}",
            Self::EmergencyAction => "/api/emergencies/{id}/{action}",
        }
    }
}

fn emergency_segments(path: &str) -> usize {
    path.strip_prefix("/api/emergencies/")
        .map(|rest| {
            rest.trim_matches('/')
                .split('/')
                .filter(|part| !part.is_empty())
                .count()
        })
        .unwrap_or(0)
}

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

fn is_public_ui_asset(path: &str) -> bool {
    path.starts_with("/ui/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('.'))
}
