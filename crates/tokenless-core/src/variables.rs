// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Variables: named secrets stored once and referenced as `{{KEY}}` from
//! credential fields and custom headers.
//!
//! References are resolved by the control plane when it builds a node's
//! snapshot, so the data plane only ever sees the rendered headers. A value
//! is never substituted recursively: a variable whose value contains
//! `{{OTHER}}` is sent as written.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::injection::{
    validate_header_name, validate_header_value, InjectedHeader, InjectedHeaders, SecretMaterial,
};

pub const MAX_KEY_LEN: usize = 64;
pub const MAX_VALUE_LEN: usize = 8192;
pub const MAX_CUSTOM_HEADERS: usize = 16;

/// Keys start with an uppercase letter and use `A-Z`, `0-9` and `_`.
pub fn validate_key(key: &str) -> Result<(), CoreError> {
    let invalid = |reason: &str| CoreError::InvalidVariableKey {
        key: key.to_string(),
        reason: reason.to_string(),
    };
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(invalid("keys must be 1-64 characters"));
    }
    if !key.starts_with(|c: char| c.is_ascii_uppercase()) {
        return Err(invalid("keys must start with an uppercase letter"));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(invalid(
            "keys may only contain uppercase letters, digits and '_'",
        ));
    }
    Ok(())
}

/// A piece of a template: literal text or a variable reference.
enum Part<'a> {
    Text(&'a str),
    Ref(&'a str),
}

fn parse<'a>(context: &str, text: &'a str) -> Result<Vec<Part<'a>>, CoreError> {
    let invalid = |reason: String| CoreError::InvalidVariableReference {
        context: context.to_string(),
        reason,
    };
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        if start > 0 {
            parts.push(Part::Text(&rest[..start]));
        }
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| invalid("'{{' is not closed with '}}'".into()))?;
        let key = after[..end].trim();
        validate_key(key).map_err(|e| invalid(e.to_string()))?;
        parts.push(Part::Ref(key));
        rest = &after[end + 2..];
    }
    if rest.contains("}}") {
        return Err(invalid("'}}' has no matching '{{'".into()));
    }
    if !rest.is_empty() {
        parts.push(Part::Text(rest));
    }
    Ok(parts)
}

/// The distinct keys `text` references, in order of first use.
pub fn references(context: &str, text: &str) -> Result<Vec<String>, CoreError> {
    let mut seen = BTreeSet::new();
    let mut keys = Vec::new();
    for part in parse(context, text)? {
        if let Part::Ref(key) = part {
            if seen.insert(key) {
                keys.push(key.to_string());
            }
        }
    }
    Ok(keys)
}

/// Replaces every reference in `text` with the value `lookup` returns.
pub fn substitute<'v>(
    context: &str,
    text: &str,
    lookup: impl Fn(&str) -> Option<&'v str>,
) -> Result<Zeroizing<String>, CoreError> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for part in parse(context, text)? {
        match part {
            Part::Text(t) => out.push_str(t),
            Part::Ref(key) => {
                let value = lookup(key).ok_or_else(|| CoreError::UnknownVariable {
                    context: context.to_string(),
                    key: key.to_string(),
                })?;
                out.push_str(value);
            }
        }
    }
    Ok(out)
}

/// A header sent with every request a credential is injected into. The
/// value is configuration, not a secret: anything secret in it comes from
/// a `{{VARIABLE}}` reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomHeader {
    pub name: String,
    pub value: String,
}

impl CustomHeader {
    /// Checks the name and the template, and returns the keys it references.
    /// `reserved` holds the lower-cased names the credential itself injects.
    pub fn validate(&self, reserved: &[String]) -> Result<Vec<String>, CoreError> {
        let invalid = |reason: String| CoreError::InvalidCustomHeader {
            name: self.name.clone(),
            reason,
        };
        let lower = validate_header_name(&self.name).map_err(|e| invalid(e.to_string()))?;
        if reserved.contains(&lower) {
            return Err(invalid(
                "the credential already sets this header; a custom header would be overwritten"
                    .into(),
            ));
        }
        if self.value.is_empty() {
            return Err(invalid("value cannot be empty".into()));
        }
        // The literal parts must already be a valid header value.
        validate_header_value(&self.name, &self.value).map_err(|e| invalid(e.to_string()))?;
        references(&format!("custom header '{}'", self.name), &self.value)
    }
}

/// Validates a credential's custom headers together and returns every key
/// they reference.
pub fn validate_custom_headers(
    headers: &[CustomHeader],
    reserved: &[String],
) -> Result<Vec<String>, CoreError> {
    if headers.len() > MAX_CUSTOM_HEADERS {
        return Err(CoreError::InvalidCustomHeader {
            name: String::new(),
            reason: format!("at most {MAX_CUSTOM_HEADERS} custom headers are allowed"),
        });
    }
    let mut names = BTreeSet::new();
    let mut keys = Vec::new();
    for header in headers {
        for key in header.validate(reserved)? {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        if !names.insert(header.name.to_ascii_lowercase()) {
            return Err(CoreError::InvalidCustomHeader {
                name: header.name.clone(),
                reason: "the same header is listed twice".into(),
            });
        }
    }
    Ok(keys)
}

/// Renders custom headers with variable values and appends them.
pub fn render_custom_headers<'v>(
    headers: &[CustomHeader],
    out: &mut InjectedHeaders,
    lookup: impl Fn(&str) -> Option<&'v str> + Copy,
) -> Result<(), CoreError> {
    for header in headers {
        let context = format!("custom header '{}'", header.name);
        let value = substitute(&context, &header.value, lookup)?;
        validate_header_value(&header.name, &value)?;
        let name = validate_header_name(&header.name)?;
        // Literal text is configuration; a header that references a
        // variable carries a secret, which the data plane redacts from
        // responses in whatever form they reflect it.
        let keys = references(&context, &header.value)?;
        if keys.is_empty() {
            out.headers
                .push(InjectedHeader::fixed(&name, value.to_string()));
            continue;
        }
        for key in keys {
            if let Some(secret) = lookup(&key) {
                out.secrets.push(SecretMaterial::new(secret));
            }
        }
        out.headers
            .push(InjectedHeader::credential(&name, value.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(key: &str) -> Option<&'static str> {
        match key {
            "GITHUB_TOKEN" => Some("ghp_secret"),
            "ORG_ID" => Some("42"),
            "NESTED" => Some("{{GITHUB_TOKEN}}"),
            _ => None,
        }
    }

    #[test]
    fn keys_are_upper_snake_case() {
        assert!(validate_key("GITHUB_TOKEN").is_ok());
        assert!(validate_key("A1").is_ok());
        for bad in ["", "github", "1ABC", "_A", "A-B", "A B", &"A".repeat(65)] {
            assert!(validate_key(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn references_are_found_once_and_in_order() {
        let keys = references("t", "{{ ORG_ID }}-{{GITHUB_TOKEN}}-{{ORG_ID}}").unwrap();
        assert_eq!(keys, ["ORG_ID", "GITHUB_TOKEN"]);
        assert!(references("t", "plain value").unwrap().is_empty());
    }

    #[test]
    fn malformed_references_explain_themselves() {
        let err = references("custom header 'x'", "{{ORG_ID")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("custom header 'x'") && err.contains("not closed"),
            "{err}"
        );
        assert!(references("t", "a }} b").is_err());
        assert!(references("t", "{{lower}}").is_err());
    }

    #[test]
    fn substitution_fills_whole_and_partial_values_without_recursion() {
        assert_eq!(
            *substitute("t", "{{GITHUB_TOKEN}}", lookup).unwrap(),
            "ghp_secret"
        );
        assert_eq!(
            *substitute("t", "org-{{ORG_ID}}", lookup).unwrap(),
            "org-42"
        );
        assert_eq!(
            *substitute("t", "{{NESTED}}", lookup).unwrap(),
            "{{GITHUB_TOKEN}}"
        );
        let err = substitute("field 'token'", "{{MISSING}}", lookup).unwrap_err();
        assert!(matches!(err, CoreError::UnknownVariable { ref key, .. } if key == "MISSING"));
    }

    #[test]
    fn custom_headers_cannot_shadow_the_credential_or_framing() {
        let reserved = vec!["authorization".to_string()];
        let h = |name: &str, value: &str| CustomHeader {
            name: name.into(),
            value: value.into(),
        };
        assert_eq!(
            validate_custom_headers(
                &[h("Notion-Version", "2022-06-28"), h("X-Org", "{{ORG_ID}}")],
                &reserved
            )
            .unwrap(),
            ["ORG_ID"]
        );
        assert!(validate_custom_headers(&[h("Authorization", "x")], &reserved).is_err());
        assert!(validate_custom_headers(&[h("Host", "x")], &reserved).is_err());
        assert!(validate_custom_headers(&[h("X-A", "1"), h("x-a", "2")], &reserved).is_err());
        assert!(validate_custom_headers(&[h("X-A", "")], &reserved).is_err());
        assert!(validate_custom_headers(&[h("X-A", "bad\nvalue")], &reserved).is_err());
    }

    #[test]
    fn rendered_custom_headers_are_checked_after_substitution() {
        let mut out = InjectedHeaders {
            headers: vec![],
            substitutions: vec![],
            secrets: vec![],
        };
        render_custom_headers(
            &[CustomHeader {
                name: "X-Org".into(),
                value: "org-{{ORG_ID}}".into(),
            }],
            &mut out,
            lookup,
        )
        .unwrap();
        assert_eq!(out.headers[0].name, "x-org");
        assert_eq!(out.headers[0].value, "org-42");

        let bad = |_: &str| Some("line\nbreak");
        let mut out = InjectedHeaders {
            headers: vec![],
            substitutions: vec![],
            secrets: vec![],
        };
        assert!(render_custom_headers(
            &[CustomHeader {
                name: "X-Org".into(),
                value: "{{ORG_ID}}".into(),
            }],
            &mut out,
            bad,
        )
        .is_err());
    }

    #[test]
    fn a_literal_custom_header_is_fixed_and_a_variable_one_is_credential_material() {
        let mut out = InjectedHeaders {
            headers: vec![],
            substitutions: vec![],
            secrets: vec![],
        };
        render_custom_headers(
            &[
                CustomHeader {
                    name: "X-Api-Version".into(),
                    value: "2024-01-01".into(),
                },
                CustomHeader {
                    name: "X-Org-Token".into(),
                    value: "tok-{{GITHUB_TOKEN}}".into(),
                },
            ],
            &mut out,
            lookup,
        )
        .unwrap();
        assert!(out.headers[0].fixed, "a literal value is configuration");
        assert!(
            !out.headers[1].fixed,
            "a variable makes it credential material"
        );
        let secrets: Vec<&str> = out.secrets.iter().map(SecretMaterial::expose).collect();
        assert_eq!(secrets, ["ghp_secret"]);
    }
}
