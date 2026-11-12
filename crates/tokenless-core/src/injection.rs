// SPDX-FileCopyrightText: 2026 tokenless contributors
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

/// Credential-bearing headers a client may never supply on a host that has a
/// rule: the broker owns authentication to that host.
pub const ALWAYS_STRIPPED: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "private-token",
    "x-auth-token",
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
    /// `Authorization: Basic base64(<username>:<password_field>)` with a
    /// fixed username: how Git hosts take a token over HTTPS
    /// (`x-access-token` on GitHub, `oauth2` on GitLab).
    BasicToken {
        username: String,
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
        return Err(invalid(
            "header names may only contain RFC 9110 token characters",
        ));
    }
    let lower = name.to_ascii_lowercase();
    if FORBIDDEN_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
        return Err(invalid(
            "framing, hop-by-hop, cookie and proxy headers cannot be injected",
        ));
    }
    Ok(lower)
}

pub(crate) fn validate_header_value(field: &str, value: &str) -> Result<(), CoreError> {
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

/// A `basic_token` username is part of the template, so it is checked when
/// the template is loaded: non-empty, printable, no ':'.
fn check_basic_token_username(template_id: &str, username: &str) -> Result<(), CoreError> {
    let printable = username.bytes().all(|b| (0x21..0x7f).contains(&b));
    if username.is_empty() || username.contains(':') || !printable {
        return Err(CoreError::InvalidTemplate {
            template_id: template_id.to_string(),
            reason: format!(
                "the basic_token username '{}' must be non-empty printable ASCII with no ':' or space",
                username.escape_debug()
            ),
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
            InjectionSpec::BasicToken { password_field, .. } => vec![password_field],
            InjectionSpec::Header { field, .. } => vec![field],
        }
    }

    /// Lower-cased header names this injection sets. The data plane strips
    /// any client-supplied header with one of these names.
    pub fn header_names(&self) -> Vec<String> {
        match self {
            InjectionSpec::Bearer { .. }
            | InjectionSpec::Basic { .. }
            | InjectionSpec::BasicToken { .. } => vec!["authorization".to_string()],
            InjectionSpec::Header { name, .. } => vec![name.to_ascii_lowercase()],
        }
    }

    /// Every header the data plane removes from client requests before
    /// injecting: the always-stripped set plus this injection's own names.
    pub fn strip_set(&self) -> Vec<String> {
        let mut names: Vec<String> = ALWAYS_STRIPPED.iter().map(|s| s.to_string()).collect();
        for name in self.header_names() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        names
    }

    pub fn validate(&self, template_id: &str) -> Result<(), CoreError> {
        if let InjectionSpec::Header { name, prefix, .. } = self {
            validate_header_name(name)?;
            if let Some(prefix) = prefix {
                validate_header_value("prefix", prefix).map_err(|e| {
                    CoreError::InvalidTemplate {
                        template_id: template_id.to_string(),
                        reason: e.to_string(),
                    }
                })?;
            }
        }
        if let InjectionSpec::BasicToken { username, .. } = self {
            check_basic_token_username(template_id, username)?;
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
        let mut secrets = Vec::with_capacity(2);
        let header = match self {
            InjectionSpec::Bearer { field } => {
                let token = get(field)?;
                validate_header_value(field, token)?;
                secrets.push(SecretMaterial::new(token));
                InjectedHeader::credential("authorization", format!("Bearer {token}"))
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
                let joined = SecretMaterial::new(format!("{user}:{pass}"));
                let encoded = STANDARD.encode(joined.expose().as_bytes());
                secrets.push(SecretMaterial::new(pass));
                secrets.push(joined);
                InjectedHeader::credential("authorization", format!("Basic {encoded}"))
            }
            InjectionSpec::BasicToken {
                username,
                password_field,
            } => {
                check_basic_token_username(template_id, username)?;
                let pass = get(password_field)?;
                let joined = SecretMaterial::new(format!("{username}:{pass}"));
                let encoded = STANDARD.encode(joined.expose().as_bytes());
                secrets.push(SecretMaterial::new(pass));
                secrets.push(joined);
                InjectedHeader::credential("authorization", format!("Basic {encoded}"))
            }
            InjectionSpec::Header {
                name,
                field,
                prefix,
            } => {
                let value = get(field)?;
                validate_header_value(field, value)?;
                let name = validate_header_name(name)?;
                secrets.push(SecretMaterial::new(value));
                InjectedHeader::credential(
                    &name,
                    format!("{}{value}", prefix.as_deref().unwrap_or("")),
                )
            }
        };
        Ok(InjectedHeaders {
            headers: vec![header],
            substitutions: vec![],
            secrets,
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

    /// Variable keys the field values reference, in order of first use.
    pub fn variable_references(&self) -> Result<Vec<String>, CoreError> {
        let mut keys: Vec<String> = Vec::new();
        for (name, value) in &self.0 {
            for key in crate::variables::references(&format!("credential field '{name}'"), value)? {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        Ok(keys)
    }

    /// A copy with every `{{VARIABLE}}` reference replaced by its value.
    pub fn resolve<'v>(
        &self,
        lookup: impl Fn(&str) -> Option<&'v str> + Copy,
    ) -> Result<SecretFields, CoreError> {
        let mut out = BTreeMap::new();
        for (name, value) in &self.0 {
            let context = format!("credential field '{name}'");
            let resolved = crate::variables::substitute(&context, value, lookup)?;
            out.insert(name.clone(), resolved.to_string());
        }
        Ok(SecretFields(out))
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
    /// The value is not credential material (a version pin, an `Accept`
    /// type), so the data plane does not redact it from responses. Absent
    /// means credential material: a control plane that predates this field
    /// gets every injected value redacted, never too little.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fixed: bool,
}

impl InjectedHeader {
    /// A header whose value carries credential material.
    pub fn credential(name: &str, value: String) -> Self {
        Self {
            name: name.to_string(),
            value,
            fixed: false,
        }
    }

    /// A header whose value is not secret, sent as written.
    pub fn fixed(name: &str, value: String) -> Self {
        Self {
            name: name.to_string(),
            value,
            fixed: true,
        }
    }
}

impl fmt::Debug for InjectedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectedHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("fixed", &self.fixed)
            .finish()
    }
}

impl Drop for InjectedHeader {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// A raw secret value a rule's headers were rendered from (a token, a
/// password, a `user:password` pair). The data plane redacts it from
/// responses in the encodings an upstream is likely to reflect it in. Never
/// logged, zeroised on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretMaterial(String);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial(<redacted>)")
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The plaintext that is sealed to a data plane node for each rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectedHeaders {
    pub headers: Vec<InjectedHeader>,
    /// Placeholders the proxy swaps for real values; see [`crate::substitution`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub substitutions: Vec<crate::substitution::RenderedSubstitution>,
    /// The raw secrets behind `headers`, so a response that reflects one in
    /// another form (the bare token, a Basic password) is redacted too. The
    /// data plane also derives what it can from the header values, so an
    /// older control plane that leaves this empty is still covered for
    /// `Bearer` and `Basic`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretMaterial>,
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
    fn basic_token_sends_the_fixed_username_and_the_token() {
        let spec = InjectionSpec::BasicToken {
            username: "x-access-token".into(),
            password_field: "token".into(),
        };
        let out = spec.render("t", &fields(&[("token", "abc")])).unwrap();
        assert_eq!(
            out.headers[0].value,
            format!("Basic {}", STANDARD.encode("x-access-token:abc"))
        );
        assert_eq!(spec.fields(), vec!["token"]);
        let bad = InjectionSpec::BasicToken {
            username: "a:b".into(),
            password_field: "token".into(),
        };
        assert!(bad.render("t", &fields(&[("token", "abc")])).is_err());
        assert!(
            bad.validate("t").is_err(),
            "refused when the template loads"
        );
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
        for name in [
            "Host",
            "Proxy-Authorization",
            "Cookie",
            "Transfer-Encoding",
            "bad header",
        ] {
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

    #[test]
    fn rendering_lists_the_raw_secrets_behind_each_header() {
        let secrets = |spec: InjectionSpec, pairs: &[(&str, &str)]| {
            let out = spec.render("t", &fields(pairs)).unwrap();
            assert!(out.headers.iter().all(|h| !h.fixed));
            out.secrets
                .iter()
                .map(|s| s.expose().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            secrets(
                InjectionSpec::Bearer {
                    field: "token".into()
                },
                &[("token", "xoxb-test-0000")]
            ),
            ["xoxb-test-0000"]
        );
        assert_eq!(
            secrets(
                InjectionSpec::Header {
                    name: "X-Api-Key".into(),
                    field: "key".into(),
                    prefix: Some("key=".into()),
                },
                &[("key", "test-key-0000")]
            ),
            ["test-key-0000"]
        );
        assert_eq!(
            secrets(
                InjectionSpec::BasicToken {
                    username: "x-access-token".into(),
                    password_field: "token".into(),
                },
                &[("token", "ghp_test0000")]
            ),
            ["ghp_test0000", "x-access-token:ghp_test0000"]
        );
        assert_eq!(
            secrets(
                InjectionSpec::Basic {
                    username_field: "user".into(),
                    password_field: "pass".into(),
                },
                &[("user", "test-user"), ("pass", "test-pass-0000")]
            ),
            ["test-pass-0000", "test-user:test-pass-0000"]
        );
    }

    #[test]
    fn the_sealed_form_stays_compatible_in_both_directions() {
        // An older control plane's plaintext: no `fixed`, no `secrets`.
        let old: InjectedHeaders =
            serde_json::from_str(r#"{"headers":[{"name":"authorization","value":"Bearer t"}]}"#)
                .unwrap();
        assert!(!old.headers[0].fixed, "absent means credential material");
        assert!(old.secrets.is_empty());
        // Default values are not written, so older data planes read the
        // same shape they always did.
        let credential = InjectedHeaders {
            headers: vec![InjectedHeader::credential(
                "authorization",
                "Bearer t".into(),
            )],
            substitutions: vec![],
            secrets: vec![],
        };
        assert_eq!(
            serde_json::to_string(&credential).unwrap(),
            r#"{"headers":[{"name":"authorization","value":"Bearer t"}]}"#
        );
        let fixed = serde_json::to_string(&InjectedHeader::fixed("accept", "a/b".into())).unwrap();
        assert_eq!(fixed, r#"{"name":"accept","value":"a/b","fixed":true}"#);
    }

    #[test]
    fn secret_material_is_never_formatted() {
        let out = InjectionSpec::Bearer {
            field: "token".into(),
        }
        .render("t", &fields(&[("token", "xoxb-test-0000")]))
        .unwrap();
        assert!(!format!("{out:?}").contains("xoxb-test-0000"));
    }
}
