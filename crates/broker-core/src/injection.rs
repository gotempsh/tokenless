// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The fixed set of injection methods. Templates only parameterise these;
//! they can never introduce new behaviour.

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::CoreError;

/// Header names an injection may never set: framing, hop-by-hop and proxy
/// headers would let a template change how the request is routed or parsed.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "cookie",
    "set-cookie",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum InjectionSpec {
    /// `Authorization: Bearer <field>`
    Bearer { field: String },
    /// `Authorization: Basic base64(<username_field>:<password_field>)`
    Basic {
        username_field: String,
        password_field: String,
    },
    /// `<name>: <prefix><field>`
    Header {
        name: String,
        field: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
}

pub fn validate_header_name(name: &str) -> Result<String, CoreError> {
    let invalid = |reason: &str| CoreError::InvalidHeaderName {
        name: name.to_string(),
        reason: reason.to_string(),
    };
    if name.is_empty() || name.len() > 128 {
        return Err(invalid("header names must be 1-128 characters"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
    {
        return Err(invalid("header names may only contain RFC 9110 token characters"));
    }
    let lower = name.to_ascii_lowercase();
    if FORBIDDEN_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
        return Err(invalid(
            "framing, hop-by-hop, cookie and proxy headers cannot be injected",
        ));
    }
    Ok(lower)
}

fn validate_header_value(field: &str, value: &str) -> Result<(), CoreError> {
    if value.len() > 8192 {
        return Err(CoreError::InvalidFieldValue {
            field: field.to_string(),
            reason: "value is longer than 8192 bytes".into(),
        });
    }
    if let Some(bad) = value
        .bytes()
        .find(|b| !(*b == b'\t' || (0x20..0x7f).contains(b)))
    {
        return Err(CoreError::InvalidFieldValue {
            field: field.to_string(),
            reason: format!("byte 0x{bad:02x} is not allowed (printable ASCII only)"),
        });
    }
    Ok(())
}

impl InjectionSpec {
    /// Field names this injection reads.
    pub fn fields(&self) -> Vec<&str> {
        match self {
            InjectionSpec::Bearer { field } => vec![field],
            InjectionSpec::Basic {
                username_field,
                password_field,
            } => vec![username_field, password_field],
            InjectionSpec::Header { field, .. } => vec![field],
        }
    }

    /// Lower-cased header names this injection sets. The data plane strips
    /// any client-supplied header with one of these names.
    pub fn header_names(&self) -> Vec<String> {
        match self {
            InjectionSpec::Bearer { .. } | InjectionSpec::Basic { .. } => {
                vec!["authorization".to_string()]
            }
            InjectionSpec::Header { name, .. } => vec![name.to_ascii_lowercase()],
        }
    }

    pub fn validate(&self, template_id: &str) -> Result<(), CoreError> {
        if let InjectionSpec::Header { name, prefix, .. } = self {
            validate_header_name(name)?;
            if let Some(prefix) = prefix {
                validate_header_value("prefix", prefix).map_err(|e| CoreError::InvalidTemplate {
                    template_id: template_id.to_string(),
                    reason: e.to_string(),
                })?;
            }
        }
        Ok(())
    }

    /// Renders the headers to inject from the credential's secret fields.
    pub fn render(
        &self,
        template_id: &str,
        fields: &SecretFields,
    ) -> Result<InjectedHeaders, CoreError> {
        let get = |name: &str| {
            fields.get(name).ok_or_else(|| CoreError::MissingField {
                template_id: template_id.to_string(),
                field: name.to_string(),
            })
        };
        let header = match self {
            InjectionSpec::Bearer { field } => {
                let token = get(field)?;
                validate_header_value(field, token)?;
                InjectedHeader::new("authorization", format!("Bearer {token}"))
            }
            InjectionSpec::Basic {
                username_field,
                password_field,
            } => {
                let user = get(username_field)?;
                let pass = get(password_field)?;
                if user.contains(':') {
                    return Err(CoreError::InvalidFieldValue {
                        field: username_field.clone(),
                        reason: "a basic-auth username cannot contain ':'".into(),
                    });
                }
                let mut joined = format!("{user}:{pass}");
                let encoded = STANDARD.encode(joined.as_bytes());
                joined.zeroize();
                InjectedHeader::new("authorization", format!("Basic {encoded}"))
            }
            InjectionSpec::Header {
                name,
                field,
                prefix,
            } => {
                let value = get(field)?;
                validate_header_value(field, value)?;
                let name = validate_header_name(name)?;
                InjectedHeader::new(&name, format!("{}{value}", prefix.as_deref().unwrap_or("")))
            }
        };
        Ok(InjectedHeaders {
            headers: vec![header],
        })
    }
}

/// Credential field values. Never logged, zeroised on drop.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretFields(BTreeMap<String, String>);

impl SecretFields {
    pub fn new(values: BTreeMap<String, String>) -> Self {
        Self(values)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn names(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFields")
            .field("names", &self.0.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Drop for SecretFields {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectedHeader {
    pub name: String,
    pub value: String,
}

impl InjectedHeader {
    fn new(name: &str, value: String) -> Self {
        Self {
            name: name.to_string(),
            value,
        }
    }
}

impl fmt::Debug for InjectedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectedHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for InjectedHeader {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// The plaintext that is sealed to a data plane node for each rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectedHeaders {
    pub headers: Vec<InjectedHeader>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> SecretFields {
        SecretFields::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn bearer_renders_authorization() {
        let spec = InjectionSpec::Bearer {
            field: "token".into(),
        };
        let out = spec.render("t", &fields(&[("token", "abc")])).unwrap();
        assert_eq!(out.headers[0].name, "authorization");
        assert_eq!(out.headers[0].value, "Bearer abc");
        assert_eq!(spec.header_names(), vec!["authorization"]);
    }

    #[test]
    fn basic_renders_base64() {
        let spec = InjectionSpec::Basic {
            username_field: "user".into(),
            password_field: "pass".into(),
        };
        let out = spec
            .render("t", &fields(&[("user", "u"), ("pass", "p")]))
            .unwrap();
        assert_eq!(out.headers[0].value, "Basic dTpw");
        assert!(spec
            .render("t", &fields(&[("user", "a:b"), ("pass", "p")]))
            .is_err());
    }

    #[test]
    fn custom_header_with_prefix() {
        let spec = InjectionSpec::Header {
            name: "X-Api-Key".into(),
            field: "key".into(),
            prefix: Some("Key ".into()),
        };
        let out = spec.render("t", &fields(&[("key", "k1")])).unwrap();
        assert_eq!(out.headers[0].name, "x-api-key");
        assert_eq!(out.headers[0].value, "Key k1");
    }

    #[test]
    fn rejects_forbidden_header_names() {
        for name in ["Host", "Proxy-Authorization", "Cookie", "Transfer-Encoding", "bad header"] {
            let spec = InjectionSpec::Header {
                name: name.into(),
                field: "k".into(),
                prefix: None,
            };
            assert!(spec.validate("t").is_err(), "{name} should be rejected");
        }
    }

    #[test]
    fn rejects_header_injection_in_values() {
        let spec = InjectionSpec::Bearer {
            field: "token".into(),
        };
        let err = spec
            .render("t", &fields(&[("token", "abc\r\nX-Evil: 1")]))
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidFieldValue { .. }));
    }

    #[test]
    fn missing_field_names_the_field() {
        let spec = InjectionSpec::Bearer {
            field: "token".into(),
        };
        let err = spec.render("github", &fields(&[])).unwrap_err();
        assert_eq!(
            err,
            CoreError::MissingField {
                template_id: "github".into(),
                field: "token".into()
            }
        );
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let f = fields(&[("token", "super-secret-value")]);
        assert!(!format!("{f:?}").contains("super-secret-value"));
        let spec = InjectionSpec::Bearer {
            field: "token".into(),
        };
        let out = spec.render("t", &f).unwrap();
        assert!(!format!("{out:?}").contains("super-secret-value"));
    }
}
