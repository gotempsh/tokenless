// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Path patterns and HTTP methods.
//!
//! A path pattern is either an exact path (`/user`) or a prefix ending in
//! `/*` (`/v1/*`, `/*`). There is deliberately no general glob: the matching
//! rules must be obvious to the person approving a rule.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PathPattern {
    raw: String,
}

impl PathPattern {
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let invalid = |reason: &str| CoreError::InvalidPath {
            input: input.to_string(),
            reason: reason.to_string(),
        };
        if !input.starts_with('/') {
            return Err(invalid("path patterns must start with '/'"));
        }
        if input.len() > 1024 {
            return Err(invalid("path pattern is longer than 1024 bytes"));
        }
        let body = input.strip_suffix('*').unwrap_or(input);
        if input.ends_with('*') && !body.ends_with('/') {
            return Err(invalid("a wildcard is only allowed as a trailing '/*'"));
        }
        if body.contains('*') || body.contains('?') || body.contains('#') {
            return Err(invalid("'*', '?' and '#' are only allowed as a trailing '/*'"));
        }
        check_request_path(body).map_err(|r| invalid(r.as_str()))?;
        Ok(Self {
            raw: input.to_string(),
        })
    }

    fn prefix(&self) -> Option<&str> {
        self.raw.strip_suffix('*')
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Matches a request path (without query string) that has already passed
    /// [`check_request_path`].
    pub fn matches(&self, path: &str) -> bool {
        match self.prefix() {
            Some(prefix) => path.starts_with(prefix),
            None => self.raw == path,
        }
    }

    /// Is every path matched by `other` also matched by `self`?
    pub fn covers(&self, other: &PathPattern) -> bool {
        match (self.prefix(), other.prefix()) {
            (None, None) => self.raw == other.raw,
            (None, Some(_)) => false,
            (Some(prefix), None) => other.raw.starts_with(prefix),
            (Some(prefix), Some(other_prefix)) => other_prefix.starts_with(prefix),
        }
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl TryFrom<String> for PathPattern {
    type Error = CoreError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        PathPattern::parse(&value)
    }
}

impl From<PathPattern> for String {
    fn from(value: PathPattern) -> Self {
        value.raw
    }
}

/// Why a request path was refused before rule matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    NotAbsolute,
    DotSegment,
    EncodedSeparator,
    Backslash,
    ControlCharacter,
}

impl PathRejection {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathRejection::NotAbsolute => "path must start with '/'",
            PathRejection::DotSegment => "path contains a '.' or '..' segment",
            PathRejection::EncodedSeparator => {
                "path contains an encoded '.', '/', '\\' or NUL that could bypass prefix rules"
            }
            PathRejection::Backslash => "path contains a backslash",
            PathRejection::ControlCharacter => "path contains a control character",
        }
    }
}

/// Rejects request paths whose meaning could differ between the broker and
/// the upstream (dot segments, percent-encoded separators). Prefix rules are
/// only sound on paths that cannot be re-interpreted after matching.
pub fn check_request_path(path: &str) -> Result<(), PathRejection> {
    if !path.starts_with('/') {
        return Err(PathRejection::NotAbsolute);
    }
    if path.contains('\\') {
        return Err(PathRejection::Backslash);
    }
    if path.chars().any(|c| c.is_control()) {
        return Err(PathRejection::ControlCharacter);
    }
    let lower = path.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c", "%00"].iter().any(|e| lower.contains(e)) {
        return Err(PathRejection::EncodedSeparator);
    }
    if path.split('/').any(|segment| segment == "." || segment == "..") {
        return Err(PathRejection::DotSegment);
    }
    Ok(())
}

/// An HTTP method, or `*` for any method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HttpMethod(String);

impl HttpMethod {
    pub const ANY: &'static str = "*";

    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let upper = input.trim().to_ascii_uppercase();
        let known = [
            "*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
        ];
        if known.contains(&upper.as_str()) {
            Ok(Self(upper))
        } else {
            Err(CoreError::InvalidMethod {
                input: input.to_string(),
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_any(&self) -> bool {
        self.0 == Self::ANY
    }

    pub fn matches(&self, method: &str) -> bool {
        self.is_any() || self.0.eq_ignore_ascii_case(method)
    }

    pub fn covers(&self, other: &HttpMethod) -> bool {
        self.is_any() || self == other
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HttpMethod {
    type Error = CoreError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        HttpMethod::parse(&value)
    }
}

impl From<HttpMethod> for String {
    fn from(value: HttpMethod) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_prefix_patterns() {
        let exact = PathPattern::parse("/user").unwrap();
        assert!(exact.matches("/user"));
        assert!(!exact.matches("/user/keys"));
        let prefix = PathPattern::parse("/v1/*").unwrap();
        assert!(prefix.matches("/v1/models"));
        assert!(prefix.matches("/v1/"));
        assert!(!prefix.matches("/v1"));
        assert!(!prefix.matches("/v2/models"));
        assert!(PathPattern::parse("/*").unwrap().matches("/anything/at/all"));
    }

    #[test]
    fn rejects_bad_patterns() {
        for bad in ["user", "/v1*", "/a/*/b", "/a?b", "/../x", "/%2e%2e/x", "/a\\b"] {
            assert!(PathPattern::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn covers_relation() {
        let all = PathPattern::parse("/*").unwrap();
        let v1 = PathPattern::parse("/v1/*").unwrap();
        let models = PathPattern::parse("/v1/models").unwrap();
        assert!(all.covers(&v1));
        assert!(v1.covers(&models));
        assert!(!models.covers(&v1));
        assert!(!v1.covers(&all));
        assert!(models.covers(&models));
    }

    #[test]
    fn request_path_checks_block_traversal_tricks() {
        assert!(check_request_path("/v1/models").is_ok());
        assert_eq!(check_request_path("/v1/../admin"), Err(PathRejection::DotSegment));
        assert_eq!(check_request_path("/v1/./x"), Err(PathRejection::DotSegment));
        assert_eq!(
            check_request_path("/v1/%2E%2E/admin"),
            Err(PathRejection::EncodedSeparator)
        );
        assert_eq!(check_request_path("/v1%2fadmin"), Err(PathRejection::EncodedSeparator));
        assert_eq!(check_request_path("v1"), Err(PathRejection::NotAbsolute));
    }

    #[test]
    fn methods() {
        let any = HttpMethod::parse("*").unwrap();
        let get = HttpMethod::parse("get").unwrap();
        assert_eq!(get.as_str(), "GET");
        assert!(any.matches("DELETE"));
        assert!(get.matches("GET"));
        assert!(!get.matches("POST"));
        assert!(any.covers(&get));
        assert!(!get.covers(&any));
        assert!(HttpMethod::parse("CONNECT").is_err());
        assert!(HttpMethod::parse("TRACE").is_err());
    }
}
