//! Error type of the outbound network guard.

use std::fmt;
use std::io;
use std::net::IpAddr;

use super::ip::AddressClass;

/// Why an outbound URL, host or address was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum NetGuardError {
    /// The URL could not be parsed.
    InvalidUrl(url::ParseError),
    /// The scheme is not in the guard's allowlist.
    SchemeNotAllowed(String),
    /// The URL carries a username or password.
    CredentialsInUrl,
    /// The URL has no host.
    MissingHost,
    /// The URL has no explicit port and its scheme has no default port.
    MissingPort,
    /// The port is zero or not in the guard's port allowlist.
    PortNotAllowed(u16),
    /// A host name or `host:port` string is malformed.
    InvalidHost(String),
    /// The address (literal or resolved) is not an allowed destination.
    BlockedAddress {
        /// Offending address, as given or resolved.
        addr: IpAddr,
        /// Classification that caused the refusal.
        class: AddressClass,
    },
    /// DNS resolution failed.
    Dns {
        /// Host that was being resolved.
        host: String,
        /// Underlying resolver error.
        source: io::Error,
    },
    /// DNS returned no address.
    NoAddresses(String),
    /// DNS returned more addresses than the guard accepts.
    TooManyAddresses {
        /// Host that was being resolved.
        host: String,
        /// Configured maximum.
        limit: usize,
    },
    /// The guard does not follow redirects.
    RedirectsDisabled,
    /// The redirect chain exceeded the configured number of hops.
    TooManyRedirects(u8),
    /// A redirect went from a secure scheme to a plaintext one.
    SchemeDowngrade,
    /// A pinned resolver was asked for a host it was not pinned to.
    HostMismatch {
        /// Host the resolver was pinned to.
        expected: String,
        /// Host that was requested.
        actual: String,
    },
    /// A pinned client was asked for a URL whose host or port differs from
    /// the resolved target.
    TargetMismatch {
        /// `host:port` of the pinned target.
        expected: String,
        /// `host:port` of the requested URL.
        actual: String,
    },
}

impl fmt::Display for NetGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(error) => write!(f, "invalid outbound URL: {error}"),
            Self::SchemeNotAllowed(scheme) => write!(f, "scheme '{scheme}' is not allowed"),
            Self::CredentialsInUrl => f.write_str("outbound URL must not include credentials"),
            Self::MissingHost => f.write_str("outbound URL has no host"),
            Self::MissingPort => f.write_str("outbound URL has no port"),
            Self::PortNotAllowed(port) => write!(f, "port {port} is not allowed"),
            Self::InvalidHost(host) => write!(f, "invalid outbound host '{host}'"),
            Self::BlockedAddress { addr, class } => {
                write!(f, "address {addr} is not allowed ({})", class.as_str())
            }
            Self::Dns { host, source } => write!(f, "DNS lookup for '{host}' failed: {source}"),
            Self::NoAddresses(host) => write!(f, "'{host}' did not resolve to any address"),
            Self::TooManyAddresses { host, limit } => {
                write!(f, "'{host}' resolved to more than {limit} addresses")
            }
            Self::RedirectsDisabled => f.write_str("redirects are disabled"),
            Self::TooManyRedirects(limit) => write!(f, "more than {limit} redirects"),
            Self::SchemeDowngrade => f.write_str("redirect downgrades to a plaintext scheme"),
            Self::HostMismatch { expected, actual } => {
                write!(
                    f,
                    "resolver pinned to '{expected}' was asked for '{actual}'"
                )
            }
            Self::TargetMismatch { expected, actual } => {
                write!(f, "client pinned to '{expected}' was asked for '{actual}'")
            }
        }
    }
}

impl std::error::Error for NetGuardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUrl(error) => Some(error),
            Self::Dns { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<url::ParseError> for NetGuardError {
    fn from(error: url::ParseError) -> Self {
        Self::InvalidUrl(error)
    }
}

impl From<NetGuardError> for io::Error {
    /// Policy refusals map to `PermissionDenied`; resolver failures keep
    /// their original kind. Used by resolver adapters that speak `io::Error`.
    fn from(error: NetGuardError) -> Self {
        let kind = match &error {
            NetGuardError::Dns { source, .. } => source.kind(),
            NetGuardError::InvalidUrl(_) | NetGuardError::InvalidHost(_) => {
                io::ErrorKind::InvalidInput
            }
            _ => io::ErrorKind::PermissionDenied,
        };
        io::Error::new(kind, error)
    }
}
