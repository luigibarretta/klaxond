//! ureq agent that checks every request URL and follows redirects itself.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use super::agent_builder_unchecked;
use crate::net_guard::{NetGuard, NetGuardError, RedirectPolicy, MAX_REDIRECT_HOPS};

/// Settings a guarded agent may carry. Proxy settings are deliberately absent.
#[derive(Clone, Debug, Default)]
pub struct AgentOptions {
    /// Connect timeout.
    pub timeout_connect: Option<Duration>,
    /// Overall timeout of each request. Each redirect hop is a separate
    /// request, so a chain can take up to `(max_hops + 1) * timeout`.
    pub timeout: Option<Duration>,
    /// `User-Agent` header.
    pub user_agent: Option<String>,
}

/// Error of a guarded ureq call.
#[derive(Debug)]
#[non_exhaustive]
pub enum GuardedCallError {
    /// The guard refused the URL or a redirect hop.
    Guard(NetGuardError),
    /// ureq failed (transport error or 4xx/5xx status).
    Ureq(Box<ureq::Error>),
}

impl fmt::Display for GuardedCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(error) => write!(f, "{error}"),
            Self::Ureq(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GuardedCallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(error) => Some(error),
            Self::Ureq(error) => Some(error.as_ref()),
        }
    }
}

impl From<NetGuardError> for GuardedCallError {
    fn from(error: NetGuardError) -> Self {
        Self::Guard(error)
    }
}

impl From<ureq::Error> for GuardedCallError {
    fn from(error: ureq::Error) -> Self {
        Self::Ureq(Box::new(error))
    }
}

/// ureq agent whose requests are always checked by the guard. The inner
/// agent is not exposed, so no request can skip the check.
#[derive(Clone, Debug)]
pub struct GuardedAgent {
    guard: Arc<NetGuard>,
    agent: ureq::Agent,
}

impl GuardedAgent {
    /// Agent with default options.
    pub fn new(guard: Arc<NetGuard>) -> Self {
        Self::with_options(guard, &AgentOptions::default())
    }

    /// Agent with timeouts and user agent.
    pub fn with_options(guard: Arc<NetGuard>, options: &AgentOptions) -> Self {
        let mut builder = agent_builder_unchecked(Arc::clone(&guard));
        if let Some(timeout) = options.timeout_connect {
            builder = builder.timeout_connect(timeout);
        }
        if let Some(timeout) = options.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(user_agent) = &options.user_agent {
            builder = builder.user_agent(user_agent);
        }
        Self {
            guard,
            agent: builder.build(),
        }
    }

    /// The guard in use.
    pub fn guard(&self) -> &NetGuard {
        &self.guard
    }

    /// Checks `url` and returns a single request (no redirect following).
    pub fn request(&self, method: &str, url: &Url) -> Result<ureq::Request, NetGuardError> {
        self.guard.check_url(url)?;
        Ok(self.agent.request_url(method, url))
    }

    /// Sends a request without body, following redirects per the guard.
    pub fn call(&self, method: &str, url: &Url) -> Result<ureq::Response, GuardedCallError> {
        self.send(method, url, ureq::Request::call)
    }

    /// Sends a request with `send` (e.g. `|r| r.set("authorization", t).send_json(&b)`),
    /// following redirects per the guard's [`RedirectPolicy`]. With redirects
    /// disabled the 3xx response is returned. Redirect handling never leaks
    /// what `send` adds (headers such as `Authorization` or `Cookie`, body):
    ///
    /// - 301, 302, 303: the next hop is a plain `GET` (`HEAD` stays `HEAD`)
    ///   built by the guard, without the caller's headers or body;
    /// - 307, 308 to the same origin (scheme, host, port): `send` runs again,
    ///   so method, headers and body are replayed as the status requires;
    /// - 307, 308 to another origin: not followed; the 3xx response is
    ///   returned so the caller decides whether to re-send its credentials.
    ///
    /// Worst-case duration is `(max_hops + 1) * AgentOptions::timeout`, since
    /// each hop is a separate request.
    pub fn send<F>(
        &self,
        method: &str,
        url: &Url,
        mut send: F,
    ) -> Result<ureq::Response, GuardedCallError>
    where
        F: FnMut(ureq::Request) -> Result<ureq::Response, ureq::Error>,
    {
        let mut current = url.clone();
        let mut method = method.to_ascii_uppercase();
        let mut replay = true;
        for followed in 0..=usize::from(MAX_REDIRECT_HOPS) {
            let request = self.request(&method, &current)?;
            let response = if replay {
                send(request)?
            } else {
                request.call()?
            };
            let Some(next) = redirect_target(&response, &current)? else {
                return Ok(response);
            };
            if self.guard.redirect_policy() == RedirectPolicy::Disabled {
                return Ok(response);
            }
            self.guard.check_redirect(&current, &next, followed)?;
            if matches!(response.status(), 307 | 308) {
                if replay && !same_origin(&current, &next) {
                    return Ok(response);
                }
            } else {
                method = method_after_redirect(&method);
                replay = false;
            }
            current = next;
        }
        Err(NetGuardError::TooManyRedirects(MAX_REDIRECT_HOPS).into())
    }
}

/// Absolute target of a redirect response, if it is one with a `Location`.
fn redirect_target(response: &ureq::Response, current: &Url) -> Result<Option<Url>, NetGuardError> {
    if !matches!(response.status(), 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    match response.header("location") {
        None => Ok(None),
        Some(location) => Ok(Some(current.join(location)?)),
    }
}

/// Method of the hop after a 301, 302 or 303: `HEAD` stays `HEAD`,
/// everything else becomes a body-less `GET`.
fn method_after_redirect(method: &str) -> String {
    if method == "HEAD" {
        "HEAD".to_owned()
    } else {
        "GET".to_owned()
    }
}

/// Same scheme, host and effective port.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}
