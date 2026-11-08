// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Host patterns: `api.example.com`, `api.example.com:8443`, `*.example.com`.
//!
//! A pattern always carries a port (443 when omitted) so a credential bound
//! to `api.example.com` is never sent to a different service on another port
//! of the same name. A leading `*.` matches exactly one label, mirroring TLS
//! wildcard certificate semantics.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

pub const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostPattern {
    host: String,
    port: u16,
}

fn invalid(input: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidHost {
        input: input.to_string(),
        reason: reason.into(),
    }
}

fn validate_dns_name(input: &str, name: &str) -> Result<(), CoreError> {
    if name.is_empty() || name.len() > 253 {
        return Err(invalid(input, "host name must be 1-253 characters"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid(input, "each label must be 1-63 characters"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(invalid(
                input,
                format!("label '{label}' may only contain a-z, 0-9 and '-'"),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid(
                input,
                format!("label '{label}' cannot start or end with '-'"),
            ));
        }
    }
    Ok(())
}

impl HostPattern {
    /// Parses `host`, `host:port`, `*.host`, `[v6]:port` or an IP literal.
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid(input, "host cannot be empty"));
        }
        if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('@') {
            return Err(invalid(
                input,
                "expected a bare host[:port], not a URL (scheme, path and userinfo are not allowed)",
            ));
        }
        let (host, port) = split_host_port(input, trimmed)?;
        let host = host.to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return Ok(Self { host, port });
        }
        if let Some(suffix) = host.strip_prefix("*.") {
            if suffix.contains('*') {
                return Err(invalid(
                    input,
                    "only a single leading '*.' wildcard is allowed",
                ));
            }
            validate_dns_name(input, suffix)?;
            if !suffix.contains('.') {
                return Err(invalid(
                    input,
                    "a wildcard must cover at least two labels (e.g. '*.example.com')",
                ));
            }
        } else {
            if host.contains('*') {
                return Err(invalid(
                    input,
                    "wildcards are only allowed as a leading '*.'",
                ));
            }
            validate_dns_name(input, &host)?;
        }
        Ok(Self { host, port })
    }

    /// Parses a self-hosted base URL (`https://git.internal.example:8443`).
    /// Only `https` is accepted: credentials are never injected on plain HTTP.
    pub fn from_https_base_url(input: &str) -> Result<Self, CoreError> {
        let trimmed = input.trim();
        let rest = trimmed
            .strip_prefix("https://")
            .ok_or_else(|| invalid(input, "base URL must start with https://"))?;
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.contains('*') {
            return Err(invalid(input, "base URL cannot contain a wildcard"));
        }
        Self::parse(authority)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_wildcard(&self) -> bool {
        self.host.starts_with("*.")
    }

    /// The DNS name to put in an interception certificate SAN.
    pub fn certificate_name(&self) -> &str {
        &self.host
    }

    /// Does a concrete request target (already lower-cased host) match?
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.port != port {
            return false;
        }
        match self.host.strip_prefix("*.") {
            Some(suffix) => host
                .strip_suffix(suffix)
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            None => self.host == host,
        }
    }

    /// Is some target matched by both? A wildcard covers exactly one label,
    /// so two different wildcards never share a target.
    pub fn overlaps(&self, other: &HostPattern) -> bool {
        self.port == other.port
            && (self.host == other.host
                || (!other.is_wildcard() && self.matches(&other.host, other.port))
                || (!self.is_wildcard() && other.matches(&self.host, self.port)))
    }

    /// Is every target matched by `other` also matched by `self`?
    pub fn covers(&self, other: &HostPattern) -> bool {
        if self.port != other.port {
            return false;
        }
        if self == other {
            return true;
        }
        if other.is_wildcard() {
            return false;
        }
        self.matches(&other.host, other.port)
    }
}

fn split_host_port<'a>(input: &str, trimmed: &'a str) -> Result<(&'a str, u16), CoreError> {
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| invalid(input, "unterminated IPv6 literal"))?;
        if addr.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid(input, "invalid IPv6 literal"));
        }
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(input, p)?,
            None if after.is_empty() => DEFAULT_HTTPS_PORT,
            None => return Err(invalid(input, "unexpected characters after IPv6 literal")),
        };
        return Ok((addr, port));
    }
    match trimmed.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') {
                return Err(invalid(input, "IPv6 literals must be wrapped in brackets"));
            }
            Ok((host, parse_port(input, port)?))
        }
        None => Ok((trimmed, DEFAULT_HTTPS_PORT)),
    }
}

fn parse_port(input: &str, port: &str) -> Result<u16, CoreError> {
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(invalid(input, format!("invalid port '{port}'"))),
        Ok(p) => Ok(p),
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == DEFAULT_HTTPS_PORT {
            f.write_str(&host)
        } else {
            write!(f, "{host}:{}", self.port)
        }
    }
}

impl TryFrom<String> for HostPattern {
    type Error = CoreError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        HostPattern::parse(&value)
    }
}

impl From<HostPattern> for String {
    fn from(value: HostPattern) -> Self {
        value.to_string()
    }
}

/// Splits a CONNECT authority (`host:port`) into a lower-cased host and port.
pub fn parse_authority(authority: &str) -> Option<(String, u16)> {
    let pattern = HostPattern::parse(authority).ok()?;
    if pattern.is_wildcard() {
        return None;
    }
    Some((pattern.host, pattern.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_with_and_without_ports() {
        let p = HostPattern::parse("API.Example.com").unwrap();
        assert_eq!(p.host(), "api.example.com");
        assert_eq!(p.port(), 443);
        assert_eq!(p.to_string(), "api.example.com");
        let p = HostPattern::parse("localhost:8443").unwrap();
        assert_eq!(p.port(), 8443);
        assert_eq!(p.to_string(), "localhost:8443");
        let p = HostPattern::parse("[::1]:9000").unwrap();
        assert_eq!(p.host(), "::1");
        assert_eq!(p.to_string(), "[::1]:9000");
        assert!(HostPattern::parse("127.0.0.1:1").is_ok());
    }

    #[test]
    fn rejects_urls_bad_wildcards_and_ports() {
        for bad in [
            "",
            "https://api.example.com",
            "api.example.com/path",
            "user@api.example.com",
            "*.com",
            "a.*.example.com",
            "*example.com",
            "api.example.com:0",
            "api.example.com:99999",
            "-bad.example.com",
            "bad_host.example.com",
            "::1",
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        let p = HostPattern::parse("*.example.com").unwrap();
        assert!(p.matches("a.example.com", 443));
        assert!(!p.matches("example.com", 443));
        assert!(!p.matches("a.b.example.com", 443));
        assert!(!p.matches("aexample.com", 443));
        assert!(!p.matches("a.example.com", 8443));
    }

    #[test]
    fn exact_match_requires_same_port() {
        let p = HostPattern::parse("api.example.com").unwrap();
        assert!(p.matches("api.example.com", 443));
        assert!(!p.matches("api.example.com", 444));
        assert!(!p.matches("evil-api.example.com", 443));
    }

    #[test]
    fn covers_is_subset_relation() {
        let wild = HostPattern::parse("*.example.com").unwrap();
        let exact = HostPattern::parse("api.example.com").unwrap();
        assert!(wild.covers(&exact));
        assert!(wild.covers(&wild));
        assert!(!exact.covers(&wild));
        assert!(!wild.covers(&HostPattern::parse("api.example.com:8443").unwrap()));
    }

    #[test]
    fn overlap_means_a_target_both_match() {
        let p = |s: &str| HostPattern::parse(s).unwrap();
        assert!(p("api.example.com").overlaps(&p("api.example.com")));
        assert!(p("*.example.com").overlaps(&p("api.example.com")));
        assert!(p("api.example.com").overlaps(&p("*.example.com")));
        assert!(p("*.example.com").overlaps(&p("*.example.com")));
        assert!(!p("*.example.com").overlaps(&p("*.api.example.com")));
        assert!(!p("*.example.com").overlaps(&p("example.com")));
        assert!(!p("api.example.com").overlaps(&p("api.example.com:8443")));
        assert!(!p("a.example.com").overlaps(&p("b.example.com")));
    }

    #[test]
    fn base_url_must_be_https() {
        let p = HostPattern::from_https_base_url("https://git.internal.example:8443/api").unwrap();
        assert_eq!(p.to_string(), "git.internal.example:8443");
        assert!(HostPattern::from_https_base_url("http://git.internal.example").is_err());
        assert!(HostPattern::from_https_base_url("https://*.internal.example").is_err());
    }

    #[test]
    fn parse_authority_rejects_wildcards() {
        assert_eq!(
            parse_authority("Example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(parse_authority("*.example.com:443"), None);
    }
}
