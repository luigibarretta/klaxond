//! Builder for [`SecurityHeaders`].

use super::validate::{is_valid_header_name, is_valid_header_value};
use super::{
    ContentSecurityPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy, Entry,
    ExistingHeaders, FrameOptions, HeaderPolicyError, Hsts, PermissionsPolicy, ReferrerPolicy,
    SecurityHeaders,
};

/// Maximum number of extra headers added with [`SecurityHeadersBuilder::header`].
pub const MAX_EXTRA_HEADERS: usize = 16;

/// Builder for [`SecurityHeaders`]. Every header is on by default with a
/// strict value; pass `None` to drop one.
#[derive(Clone, Debug)]
pub struct SecurityHeadersBuilder {
    hsts: Option<Hsts>,
    csp: Option<ContentSecurityPolicy>,
    csp_report_only: Option<ContentSecurityPolicy>,
    frame: FrameOptions,
    nosniff: bool,
    referrer: Option<ReferrerPolicy>,
    permissions: Option<PermissionsPolicy>,
    coop: Option<CrossOriginOpenerPolicy>,
    corp: Option<CrossOriginResourcePolicy>,
    extra: Vec<(String, String)>,
    existing: ExistingHeaders,
    keep: Vec<String>,
}

impl Default for SecurityHeadersBuilder {
    fn default() -> Self {
        Self {
            hsts: Some(Hsts::default()),
            csp: Some(ContentSecurityPolicy::strict()),
            csp_report_only: None,
            frame: FrameOptions::Deny,
            nosniff: true,
            referrer: Some(ReferrerPolicy::NoReferrer),
            permissions: Some(PermissionsPolicy::default()),
            coop: Some(CrossOriginOpenerPolicy::SameOrigin),
            corp: Some(CrossOriginResourcePolicy::SameOrigin),
            extra: Vec::new(),
            existing: ExistingHeaders::Overwrite,
            keep: Vec::new(),
        }
    }
}

impl SecurityHeadersBuilder {
    /// `Strict-Transport-Security` (`None` for plain-HTTP-only deployments).
    ///
    /// The default carries `includeSubDomains`: browsers then refuse plain
    /// HTTP for every subdomain of the host that sent it. If a sibling such
    /// as `printer.lan.example` is only reachable over HTTP, use
    /// `Hsts::default().include_subdomains(false)` on the parent domain.
    pub fn hsts(mut self, hsts: Option<Hsts>) -> Self {
        self.hsts = hsts;
        self
    }

    /// Enforced `Content-Security-Policy`. Its `frame-ancestors` is always
    /// rewritten from [`FrameOptions`]; with `None` the header carries only
    /// `frame-ancestors`.
    pub fn csp(mut self, csp: Option<ContentSecurityPolicy>) -> Self {
        self.csp = csp;
        self
    }

    /// `Content-Security-Policy-Report-Only`, e.g. to trial a stricter policy.
    pub fn csp_report_only(mut self, csp: Option<ContentSecurityPolicy>) -> Self {
        self.csp_report_only = csp;
        self
    }

    /// Framing policy (`X-Frame-Options` and CSP `frame-ancestors`).
    pub fn frame_options(mut self, frame: FrameOptions) -> Self {
        self.frame = frame;
        self
    }

    /// `X-Content-Type-Options: nosniff` on or off.
    pub fn nosniff(mut self, enabled: bool) -> Self {
        self.nosniff = enabled;
        self
    }

    /// `Referrer-Policy`.
    pub fn referrer_policy(mut self, policy: Option<ReferrerPolicy>) -> Self {
        self.referrer = policy;
        self
    }

    /// `Permissions-Policy`.
    pub fn permissions_policy(mut self, policy: Option<PermissionsPolicy>) -> Self {
        self.permissions = policy;
        self
    }

    /// `Cross-Origin-Opener-Policy`.
    pub fn cross_origin_opener_policy(mut self, policy: Option<CrossOriginOpenerPolicy>) -> Self {
        self.coop = policy;
        self
    }

    /// `Cross-Origin-Resource-Policy`.
    pub fn cross_origin_resource_policy(
        mut self,
        policy: Option<CrossOriginResourcePolicy>,
    ) -> Self {
        self.corp = policy;
        self
    }

    /// Extra static header (e.g. `Cache-Control: no-store`); validated at build.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.extra.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Global conflict mode (default [`ExistingHeaders::Overwrite`]).
    pub fn existing_headers(mut self, mode: ExistingHeaders) -> Self {
        self.existing = mode;
        self
    }

    /// Lets a value already present on the response win for the listed
    /// headers only (case-insensitive), e.g. `&["content-security-policy"]`
    /// for a route that ships its own sandboxed CSP. Names are validated at
    /// build.
    pub fn keep_if_present(mut self, names: &[&str]) -> Self {
        self.keep
            .extend(names.iter().map(|name| name.trim().to_ascii_lowercase()));
        self
    }

    /// Validates and renders the headers.
    pub fn build(self) -> Result<SecurityHeaders, HeaderPolicyError> {
        let mut out = Vec::new();
        if let Some(hsts) = &self.hsts {
            push(&mut out, "strict-transport-security", &hsts.render())?;
        }
        // Without a CSP, a policy carrying only frame-ancestors is still sent so
        // framing protection never depends on X-Frame-Options alone.
        let csp = self
            .csp
            .clone()
            .unwrap_or_else(ContentSecurityPolicy::empty);
        let csp = csp.set("frame-ancestors", &self.frame.ancestors())?;
        push(&mut out, "content-security-policy", &csp.render())?;
        if let Some(csp) = &self.csp_report_only {
            push(
                &mut out,
                "content-security-policy-report-only",
                &csp.render(),
            )?;
        }
        if let Some(value) = self.frame.x_frame_options() {
            push(&mut out, "x-frame-options", value)?;
        }
        if self.nosniff {
            push(&mut out, "x-content-type-options", "nosniff")?;
        }
        self.push_policies(&mut out)?;
        if self.extra.len() > MAX_EXTRA_HEADERS {
            return Err(HeaderPolicyError::TooManyExtraHeaders);
        }
        for (name, value) in &self.extra {
            push(&mut out, name, value)?;
        }
        self.mark_kept(&mut out)?;
        SecurityHeaders::from_entries(out)
    }

    fn push_policies(&self, out: &mut Vec<Entry>) -> Result<(), HeaderPolicyError> {
        if let Some(policy) = self.referrer {
            push(out, "referrer-policy", policy.as_str())?;
        }
        if let Some(policy) = self.permissions.as_ref().filter(|p| !p.is_empty()) {
            push(out, "permissions-policy", &policy.render())?;
        }
        if let Some(policy) = self.coop {
            push(out, "cross-origin-opener-policy", policy.as_str())?;
        }
        if let Some(policy) = self.corp {
            push(out, "cross-origin-resource-policy", policy.as_str())?;
        }
        Ok(())
    }

    fn mark_kept(&self, out: &mut [Entry]) -> Result<(), HeaderPolicyError> {
        if self.keep.len() > MAX_EXTRA_HEADERS * 2 {
            return Err(HeaderPolicyError::TooManyExtraHeaders);
        }
        if let Some(bad) = self.keep.iter().find(|name| !is_valid_header_name(name)) {
            return Err(HeaderPolicyError::InvalidHeader(bad.clone()));
        }
        if let Some(unknown) = self
            .keep
            .iter()
            .find(|name| !out.iter().any(|entry| entry.name == **name))
        {
            return Err(HeaderPolicyError::KeptHeaderNotInPolicy(unknown.clone()));
        }
        let keep_all = self.existing == ExistingHeaders::Keep;
        for entry in out.iter_mut() {
            entry.keep_existing = keep_all || self.keep.contains(&entry.name);
        }
        Ok(())
    }
}

/// Adds or replaces one header; later entries win over earlier ones.
fn push(out: &mut Vec<Entry>, name: &str, value: &str) -> Result<(), HeaderPolicyError> {
    let name = name.trim().to_ascii_lowercase();
    if !is_valid_header_name(&name) || !is_valid_header_value(value) {
        return Err(HeaderPolicyError::InvalidHeader(name));
    }
    out.retain(|existing| existing.name != name);
    out.push(Entry {
        name,
        value: value.to_owned(),
        keep_existing: false,
    });
    Ok(())
}
