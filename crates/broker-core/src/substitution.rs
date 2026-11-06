// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Substitutions: the agent sends a placeholder such as `__GITHUB_TOKEN__`
//! and the proxy swaps in the real value on the way out.
//!
//! Injection covers APIs that authenticate with one header. Substitutions
//! cover the rest: a key in the query string, a token in the URL path, a
//! secret inside a JSON body, or a tool that refuses to start unless it is
//! given a key. Each substitution names one of the credential's secret
//! fields and the places the proxy should look. Values are encoded for the
//! place they land in, so a value can never add a path segment, a query
//! parameter or a header line.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::injection::{validate_header_value, SecretFields};

pub const MIN_PLACEHOLDER: usize = 8;
pub const MAX_PLACEHOLDER: usize = 128;
pub const MAX_SUBSTITUTIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstitutionLocation {
    /// The URL path. The value is percent-encoded, so `/` stays inside one segment.
    Path,
    /// The query string. The value is percent-encoded.
    Query,
    /// Request header values the agent sends (not the ones the broker injects).
    Header,
    /// The request body: JSON-escaped for JSON, form-encoded for forms,
    /// verbatim otherwise. Compressed or oversized bodies are left alone.
    Body,
}

impl SubstitutionLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            SubstitutionLocation::Path => "path",
            SubstitutionLocation::Query => "query",
            SubstitutionLocation::Header => "header",
            SubstitutionLocation::Body => "body",
        }
    }
}

/// Configuration stored with a credential. Holds no secret: the value comes
/// from the credential's own field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Substitution {
    /// What the agent sends, e.g. `__GITHUB_TOKEN__`.
    pub placeholder: String,
    /// The credential's secret field whose value replaces it.
    pub field: String,
    /// Environment variable the launcher sets to the placeholder, for tools
    /// that will not start without a key (e.g. `GITHUB_TOKEN`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    pub locations: Vec<SubstitutionLocation>,
}

fn invalid(placeholder: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidSubstitution {
        placeholder: placeholder.to_string(),
        reason: reason.into(),
    }
}

fn validate_env_name(placeholder: &str, name: &str) -> Result<(), CoreError> {
    let mut chars = name.chars();
    let valid = name.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        return Err(invalid(
            placeholder,
            format!(
                "environment variable '{name}' must be UPPER_SNAKE_CASE, at most 64 characters"
            ),
        ));
    }
    if name.starts_with("CREDENTIAL_BROKER_")
        || [
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "PATH",
            "HOME",
        ]
        .contains(&name)
    {
        return Err(invalid(
            placeholder,
            format!("environment variable '{name}' is set by the launcher itself"),
        ));
    }
    Ok(())
}

/// Checks a credential's substitutions against the template's field names.
pub fn validate_substitutions(
    substitutions: &[Substitution],
    field_names: &[&str],
) -> Result<(), CoreError> {
    if substitutions.len() > MAX_SUBSTITUTIONS {
        return Err(invalid(
            "",
            format!("a credential may have at most {MAX_SUBSTITUTIONS} substitutions"),
        ));
    }
    let mut placeholders: Vec<&str> = Vec::new();
    let mut envs: Vec<&str> = Vec::new();
    for sub in substitutions {
        let p = sub.placeholder.as_str();
        if !(MIN_PLACEHOLDER..=MAX_PLACEHOLDER).contains(&p.len()) {
            return Err(invalid(
                p,
                format!(
                    "placeholders must be {MIN_PLACEHOLDER}-{MAX_PLACEHOLDER} characters, so ordinary text never matches one"
                ),
            ));
        }
        if !p
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
        {
            return Err(invalid(
                p,
                "placeholders may only contain letters, digits, '_', '-' and '.'",
            ));
        }
        if placeholders
            .iter()
            .any(|other| other.contains(p) || p.contains(other))
        {
            return Err(invalid(
                p,
                "placeholders must be distinct and none may contain another",
            ));
        }
        placeholders.push(p);
        if !field_names.contains(&sub.field.as_str()) {
            return Err(invalid(
                p,
                format!(
                    "field '{}' is not one of this service's fields ({})",
                    sub.field,
                    field_names.join(", ")
                ),
            ));
        }
        if sub.locations.is_empty() {
            return Err(invalid(p, "choose at least one place to look for it"));
        }
        if let Some(env) = &sub.env {
            validate_env_name(p, env)?;
            if envs.contains(&env.as_str()) {
                return Err(invalid(
                    p,
                    format!("environment variable '{env}' is used twice"),
                ));
            }
            envs.push(env);
        }
    }
    Ok(())
}

/// A substitution with its secret value, sealed to data plane nodes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedSubstitution {
    pub placeholder: String,
    pub value: String,
    pub locations: Vec<SubstitutionLocation>,
}

impl RenderedSubstitution {
    pub fn applies_to(&self, location: SubstitutionLocation) -> bool {
        self.locations.contains(&location)
    }
}

impl fmt::Debug for RenderedSubstitution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderedSubstitution")
            .field("placeholder", &self.placeholder)
            .field("value", &"<redacted>")
            .field("locations", &self.locations)
            .finish()
    }
}

impl Drop for RenderedSubstitution {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Fills in each substitution from the credential's resolved fields.
pub fn render_substitutions(
    template_id: &str,
    substitutions: &[Substitution],
    fields: &SecretFields,
) -> Result<Vec<RenderedSubstitution>, CoreError> {
    substitutions
        .iter()
        .map(|sub| {
            let value = fields
                .get(&sub.field)
                .ok_or_else(|| CoreError::MissingField {
                    template_id: template_id.to_string(),
                    field: sub.field.clone(),
                })?;
            if sub.locations.contains(&SubstitutionLocation::Header) {
                validate_header_value(&sub.field, value)
                    .map_err(|e| invalid(&sub.placeholder, e.to_string()))?;
            }
            Ok(RenderedSubstitution {
                placeholder: sub.placeholder.clone(),
                value: value.to_string(),
                locations: sub.locations.clone(),
            })
        })
        .collect()
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn json_escape(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_string()).to_string();
    quoted[1..quoted.len() - 1].to_string()
}

/// How a body's content is encoded, which decides how values are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Json,
    Form,
    Raw,
}

impl BodyKind {
    pub fn from_content_type(content_type: Option<&str>) -> Self {
        let Some(ct) = content_type else {
            return BodyKind::Raw;
        };
        let media = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if media == "application/json" || media.ends_with("+json") {
            BodyKind::Json
        } else if media == "application/x-www-form-urlencoded" {
            BodyKind::Form
        } else {
            BodyKind::Raw
        }
    }
}

/// The result of applying substitutions to one part of a request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Placeholders that were found, for the audit record.
    pub placeholders: Vec<String>,
}

impl Applied {
    fn note(&mut self, placeholder: &str) {
        if !self.placeholders.iter().any(|p| p == placeholder) {
            self.placeholders.push(placeholder.to_string());
        }
    }

    pub fn merge(&mut self, other: Applied) {
        for p in other.placeholders {
            self.note(&p);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.placeholders.is_empty()
    }
}

fn replace_all(
    text: &str,
    subs: &[RenderedSubstitution],
    location: SubstitutionLocation,
    encode: impl Fn(&str) -> String,
    applied: &mut Applied,
) -> Option<String> {
    let mut out: Option<String> = None;
    for sub in subs.iter().filter(|s| s.applies_to(location)) {
        let current = out.as_deref().unwrap_or(text);
        if current.contains(&sub.placeholder) {
            let replaced = current.replace(&sub.placeholder, &encode(&sub.value));
            out = Some(replaced);
            applied.note(&sub.placeholder);
        }
    }
    out
}

/// Rewrites a request target (`/path?query`). `None` when nothing matched.
pub fn apply_to_target(
    path_and_query: &str,
    subs: &[RenderedSubstitution],
    applied: &mut Applied,
) -> Option<String> {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    let new_path = replace_all(
        path,
        subs,
        SubstitutionLocation::Path,
        percent_encode,
        applied,
    );
    let new_query = query.and_then(|q| {
        replace_all(
            q,
            subs,
            SubstitutionLocation::Query,
            percent_encode,
            applied,
        )
    });
    if new_path.is_none() && new_query.is_none() {
        return None;
    }
    let path = new_path.as_deref().unwrap_or(path);
    Some(match new_query.as_deref().or(query) {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    })
}

/// Rewrites one header value. `None` when nothing matched or the value is
/// not text.
pub fn apply_to_header(
    value: &[u8],
    subs: &[RenderedSubstitution],
    applied: &mut Applied,
) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    replace_all(
        text,
        subs,
        SubstitutionLocation::Header,
        str::to_string,
        applied,
    )
}

/// Rewrites a body. `None` when nothing matched or the body is not UTF-8.
pub fn apply_to_body(
    body: &[u8],
    kind: BodyKind,
    subs: &[RenderedSubstitution],
    applied: &mut Applied,
) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let encode = |v: &str| match kind {
        BodyKind::Json => json_escape(v),
        BodyKind::Form => percent_encode(v),
        BodyKind::Raw => v.to_string(),
    };
    replace_all(text, subs, SubstitutionLocation::Body, encode, applied).map(String::into_bytes)
}

/// Does any substitution look in the body?
pub fn wants_body(subs: &[RenderedSubstitution]) -> bool {
    subs.iter()
        .any(|s| s.applies_to(SubstitutionLocation::Body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use SubstitutionLocation::*;

    fn sub(
        placeholder: &str,
        value: &str,
        locations: &[SubstitutionLocation],
    ) -> RenderedSubstitution {
        RenderedSubstitution {
            placeholder: placeholder.into(),
            value: value.into(),
            locations: locations.to_vec(),
        }
    }

    fn config(placeholder: &str, field: &str) -> Substitution {
        Substitution {
            placeholder: placeholder.into(),
            field: field.into(),
            env: None,
            locations: vec![Header, Query],
        }
    }

    #[test]
    fn validation_explains_each_problem() {
        let fields = ["token"];
        assert!(validate_substitutions(&[config("__TOKEN__", "token")], &fields).is_ok());
        let cases = [
            (vec![config("short", "token")], "8-128"),
            (vec![config("__TO KEN__", "token")], "letters, digits"),
            (vec![config("__TOKEN__", "password")], "field 'password'"),
            (
                vec![config("__TOKEN__", "token"), config("__TOKEN__X", "token")],
                "contain another",
            ),
            (
                vec![Substitution {
                    locations: vec![],
                    ..config("__TOKEN__", "token")
                }],
                "at least one place",
            ),
            (
                vec![Substitution {
                    env: Some("github_token".into()),
                    ..config("__TOKEN__", "token")
                }],
                "UPPER_SNAKE_CASE",
            ),
            (
                vec![Substitution {
                    env: Some("HTTPS_PROXY".into()),
                    ..config("__TOKEN__", "token")
                }],
                "set by the launcher",
            ),
        ];
        for (subs, expected) in cases {
            let err = validate_substitutions(&subs, &fields)
                .unwrap_err()
                .to_string();
            assert!(err.contains(expected), "{err} should mention {expected}");
        }
    }

    #[test]
    fn path_values_stay_in_one_segment_and_query_values_in_one_parameter() {
        let subs = [sub("__KEY__1", "a/b&c=d e", &[Path, Query])];
        let mut applied = Applied::default();
        let out = apply_to_target("/v1/__KEY__1/x?key=__KEY__1&n=1", &subs, &mut applied).unwrap();
        assert_eq!(out, "/v1/a%2Fb%26c%3Dd%20e/x?key=a%2Fb%26c%3Dd%20e&n=1");
        assert_eq!(applied.placeholders, ["__KEY__1"]);
        let mut none = Applied::default();
        assert_eq!(apply_to_target("/v1/models?x=1", &subs, &mut none), None);
        assert!(none.is_empty());
    }

    #[test]
    fn locations_are_respected() {
        let subs = [sub("__KEY__1", "secret", &[Query])];
        let mut applied = Applied::default();
        assert_eq!(
            apply_to_target("/__KEY__1?k=__KEY__1", &subs, &mut applied).unwrap(),
            "/__KEY__1?k=secret"
        );
        assert_eq!(apply_to_header(b"x __KEY__1", &subs, &mut applied), None);
        assert_eq!(
            apply_to_body(b"__KEY__1", BodyKind::Raw, &subs, &mut applied),
            None
        );
    }

    #[test]
    fn bodies_are_encoded_for_their_content_type() {
        let subs = [sub("__KEY__1", "q\"u\\o", &[Body])];
        let mut applied = Applied::default();
        let json = apply_to_body(
            br#"{"key":"__KEY__1"}"#,
            BodyKind::Json,
            &subs,
            &mut applied,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["key"], "q\"u\\o");
        let form = apply_to_body(b"key=__KEY__1", BodyKind::Form, &subs, &mut applied).unwrap();
        assert_eq!(form, b"key=q%22u%5Co");
        let raw = apply_to_body(b"key: __KEY__1", BodyKind::Raw, &subs, &mut applied).unwrap();
        assert_eq!(raw, b"key: q\"u\\o");
        assert_eq!(
            apply_to_body(&[0xff, 0xfe], BodyKind::Raw, &subs, &mut applied),
            None
        );
        assert!(wants_body(&subs));
    }

    #[test]
    fn content_types_are_classified() {
        assert_eq!(
            BodyKind::from_content_type(Some("application/json; charset=utf-8")),
            BodyKind::Json
        );
        assert_eq!(
            BodyKind::from_content_type(Some("application/vnd.api+json")),
            BodyKind::Json
        );
        assert_eq!(
            BodyKind::from_content_type(Some("application/x-www-form-urlencoded")),
            BodyKind::Form
        );
        assert_eq!(
            BodyKind::from_content_type(Some("text/plain")),
            BodyKind::Raw
        );
        assert_eq!(BodyKind::from_content_type(None), BodyKind::Raw);
    }

    #[test]
    fn rendering_checks_header_values_and_redacts() {
        let fields = SecretFields::new([("token".to_string(), "ghp_value".to_string())].into());
        let mut cfg = config("__TOKEN__", "token");
        let rendered = render_substitutions("t", std::slice::from_ref(&cfg), &fields).unwrap();
        assert_eq!(rendered[0].value, "ghp_value");
        assert!(!format!("{rendered:?}").contains("ghp_value"));
        let bad = SecretFields::new([("token".to_string(), "a\r\nb".to_string())].into());
        assert!(render_substitutions("t", std::slice::from_ref(&cfg), &bad).is_err());
        cfg.locations = vec![Body];
        assert!(render_substitutions("t", &[cfg], &bad).is_ok());
    }
}
