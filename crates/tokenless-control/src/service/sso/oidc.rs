// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OpenID Connect protocol, without storage: discovery, the
//! authorization code exchange with PKCE, and what an ID token must say.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;
use tokenless_auth::jwt::Algorithm;
use tokenless_core::authz::Role;
use url::Url;

use crate::model::RoleMapping;

/// How far the provider's clock may be from ours.
pub const CLOCK_SKEW_SECS: i64 = 60;
/// The most groups read from one person's claims.
pub const MAX_GROUPS: usize = 1000;
/// The path every provider sends people back to.
pub const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";

/// A reply from a provider: its status and body.
pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{reason}")]
pub struct TransportError {
    pub reason: String,
}

/// How the control plane reaches identity providers. The server supplies
/// one over HTTPS with timeouts and a size limit; tests supply a fake.
#[async_trait]
pub trait OidcTransport: Send + Sync {
    /// A GET, with `Authorization: Bearer` when `bearer` is set.
    async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<HttpReply, TransportError>;
    /// A form POST, with HTTP Basic authentication when `basic` is set.
    async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<HttpReply, TransportError>;
}

/// Reaches no provider: for a control plane without single sign-on, and
/// tests that need none.
pub struct NoTransport;

#[async_trait]
impl OidcTransport for NoTransport {
    async fn get(&self, url: &Url, _bearer: Option<&str>) -> Result<HttpReply, TransportError> {
        Err(TransportError {
            reason: format!("this control plane reaches no identity provider (GET {url})"),
        })
    }

    async fn post_form(
        &self,
        url: &Url,
        _form: &[(&str, &str)],
        _basic: Option<(&str, &str)>,
    ) -> Result<HttpReply, TransportError> {
        Err(TransportError {
            reason: format!("this control plane reaches no identity provider (POST {url})"),
        })
    }
}

/// The fields of a provider's discovery document that are used.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl Discovery {
    /// The algorithms to accept: those the provider says it signs with,
    /// among those verified here; all of them when it does not say.
    pub fn algorithms(&self) -> Vec<Algorithm> {
        match &self.id_token_signing_alg_values_supported {
            Some(listed) => listed.iter().filter_map(|a| Algorithm::parse(a)).collect(),
            None => Algorithm::ALL.to_vec(),
        }
    }

    /// Whether the client secret goes in the form rather than in Basic
    /// authentication: only for a provider that lists `client_secret_post`
    /// and not `client_secret_basic`.
    pub fn secret_in_form(&self) -> bool {
        self.token_endpoint_auth_methods_supported
            .as_ref()
            .is_some_and(|m| {
                m.iter().any(|m| m == "client_secret_post")
                    && !m.iter().any(|m| m == "client_secret_basic")
            })
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// An HTTPS URL, or HTTP to this machine, with no credentials or fragment.
pub fn check_url(what: &str, raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|e| format!("{what} '{raw}' is not a URL: {e}"))?;
    let secure = url.scheme() == "https" || (url.scheme() == "http" && is_loopback(&url));
    if !secure {
        return Err(format!(
            "{what} '{raw}' must use https (http only to localhost)"
        ));
    }
    if url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{what} '{raw}' must name a host and no credentials"
        ));
    }
    if url.fragment().is_some() {
        return Err(format!("{what} '{raw}' must not have a #fragment"));
    }
    Ok(url)
}

/// Where the issuer's discovery document is (OpenID Connect Discovery §4).
pub fn discovery_url(issuer: &str) -> Result<Url, String> {
    check_url(
        "discovery document",
        &format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ),
    )
}

/// Parses a discovery document and checks it belongs to `issuer`, whose
/// endpoints must all be HTTPS.
pub fn parse_discovery(issuer: &str, body: &[u8]) -> Result<Discovery, String> {
    let d: Discovery = serde_json::from_slice(body)
        .map_err(|e| format!("the discovery document is not valid: {e}"))?;
    if d.issuer != issuer {
        return Err(format!(
            "the discovery document is for issuer '{}', not '{issuer}'; set the issuer exactly as the provider names it",
            d.issuer
        ));
    }
    check_url("authorization_endpoint", &d.authorization_endpoint)?;
    check_url("token_endpoint", &d.token_endpoint)?;
    check_url("jwks_uri", &d.jwks_uri)?;
    if let Some(u) = &d.userinfo_endpoint {
        check_url("userinfo_endpoint", u)?;
    }
    if d.algorithms().is_empty() {
        return Err(format!(
            "the provider signs ID tokens only with {:?}; accepted are RS*, PS*, ES256, ES384 and EdDSA",
            d.id_token_signing_alg_values_supported.unwrap_or_default()
        ));
    }
    Ok(d)
}

/// The PKCE S256 challenge for a verifier (RFC 7636 §4.2).
pub fn pkce_challenge(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// What a valid ID token must match.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    pub now: DateTime<Utc>,
}

/// The parts of a checked ID token that are used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdToken {
    pub subject: String,
    pub auth_time: Option<DateTime<Utc>>,
}

fn timestamp(claims: &Map<String, Value>, name: &str) -> Result<Option<DateTime<Utc>>, String> {
    match claims.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| f as i64))
            .and_then(|s| DateTime::from_timestamp(s, 0))
            .map(Some)
            .ok_or_else(|| format!("the ID token's '{name}' is not a time")),
    }
}

/// Checks an ID token's claims (OpenID Connect Core §3.1.3.7): issuer,
/// audience, authorized party, expiry, issue time and nonce.
pub fn check_id_token(claims: &Map<String, Value>, expect: &Expected) -> Result<IdToken, String> {
    let skew = chrono::Duration::seconds(CLOCK_SKEW_SECS);
    if claims.get("iss").and_then(Value::as_str) != Some(expect.issuer) {
        return Err(format!(
            "the ID token was issued by {}, not '{}'",
            claims.get("iss").map_or("nobody".into(), |v| format!(
                "'{}'",
                v.as_str().unwrap_or("?")
            )),
            expect.issuer
        ));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expect.client_id) {
        return Err(format!(
            "the ID token is for {audiences:?}, not this client ('{}')",
            expect.client_id
        ));
    }
    let azp = claims.get("azp").and_then(Value::as_str);
    if (audiences.len() > 1 || azp.is_some()) && azp != Some(expect.client_id) {
        return Err(format!(
            "the ID token was issued to {azp:?}, not this client ('{}')",
            expect.client_id
        ));
    }
    let exp = timestamp(claims, "exp")?.ok_or("the ID token has no 'exp'")?;
    if exp + skew <= expect.now {
        return Err(format!("the ID token expired at {exp}"));
    }
    let iat = timestamp(claims, "iat")?.ok_or("the ID token has no 'iat'")?;
    if iat > expect.now + skew {
        return Err(format!("the ID token is issued in the future ({iat})"));
    }
    if let Some(nbf) = timestamp(claims, "nbf")? {
        if nbf > expect.now + skew {
            return Err(format!("the ID token is not valid before {nbf}"));
        }
    }
    let nonce = claims.get("nonce").and_then(Value::as_str).unwrap_or("");
    if !tokenless_auth::token::hashes_equal(nonce, expect.nonce) {
        return Err("the ID token's nonce is not the one this sign-in sent".into());
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or("the ID token has no usable 'sub'")?
        .to_string();
    Ok(IdToken {
        subject,
        auth_time: timestamp(claims, "auth_time")?,
    })
}

/// A claim by name, or by a dotted path into nested objects
/// (`realm_access.roles`). A name that itself contains dots, as namespaced
/// claims do (`https://example.com/groups`), is matched whole first.
pub fn claim<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(path) {
        return Some(v);
    }
    let mut parts = path.split('.');
    let mut current = claims.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

/// The group names in a claim: a list of strings or one string.
pub fn groups(value: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = match value {
        Some(Value::String(g)) => vec![g.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .take(MAX_GROUPS)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };
    out.sort();
    out.dedup();
    out
}

fn rank(role: Role) -> u8 {
    match role {
        Role::Viewer => 1,
        Role::Editor => 2,
        Role::Admin => 3,
    }
}

/// The highest role any of `groups` maps to; `None` when none is mapped.
pub fn mapped_role(mappings: &[RoleMapping], groups: &[String]) -> Option<Role> {
    mappings
        .iter()
        .filter(|m| groups.contains(&m.group))
        .map(|m| m.role)
        .max_by_key(|r| rank(*r))
}

/// A username for a new single sign-on account: the claim's value
/// lower-cased, 3-128 characters of `a-z 0-9 _ - . @ +`.
pub fn username(value: Option<&Value>) -> Option<String> {
    let raw = value?.as_str()?.trim().to_ascii_lowercase();
    let ok = (3..=128).contains(&raw.len())
        && raw
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-.@+".contains(c));
    ok.then_some(raw)
}

/// A provider's error parameter or body, cut to a readable length.
pub fn provider_error(error: &str, description: Option<&str>) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect::<String>()
    };
    match description.filter(|d| !d.is_empty()) {
        Some(d) => format!("{}: {}", clean(error), clean(d)),
        None => clean(error),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn expect(now: DateTime<Utc>) -> Expected<'static> {
        Expected {
            issuer: "https://idp.example.test",
            client_id: "tokenless",
            nonce: "n-1",
            now,
        }
    }

    fn good(now: i64) -> Value {
        json!({
            "iss": "https://idp.example.test",
            "aud": "tokenless",
            "sub": "person-1",
            "exp": now + 300,
            "iat": now,
            "nonce": "n-1",
            "auth_time": now - 5,
        })
    }

    #[test]
    fn a_valid_id_token_names_its_subject_and_sign_in_time() {
        let now = Utc::now();
        let t = now.timestamp();
        let id = check_id_token(&map(good(t)), &expect(now)).unwrap();
        assert_eq!(id.subject, "person-1");
        assert_eq!(id.auth_time.map(|a| a.timestamp()), Some(t - 5));
        // Several audiences need this client as the authorized party.
        let mut multi = good(t);
        multi["aud"] = json!(["other", "tokenless"]);
        assert!(check_id_token(&map(multi.clone()), &expect(now)).is_err());
        multi["azp"] = json!("tokenless");
        assert!(check_id_token(&map(multi), &expect(now)).is_ok());
    }

    #[test]
    fn an_id_token_for_someone_else_or_out_of_time_is_refused() {
        let now = Utc::now();
        let t = now.timestamp();
        let cases: Vec<(&str, Value)> = vec![
            ("iss", json!("https://idp.example.test/")),
            ("aud", json!("another-client")),
            ("aud", json!(["another-client"])),
            ("azp", json!("another-client")),
            ("exp", json!(t - CLOCK_SKEW_SECS - 1)),
            ("exp", json!("tomorrow")),
            ("iat", json!(t + CLOCK_SKEW_SECS + 10)),
            ("nbf", json!(t + CLOCK_SKEW_SECS + 10)),
            ("nonce", json!("n-2")),
            ("sub", json!("")),
        ];
        for (name, value) in cases {
            let mut claims = good(t);
            claims[name] = value.clone();
            assert!(
                check_id_token(&map(claims), &expect(now)).is_err(),
                "{name} = {value}"
            );
        }
        for missing in ["iss", "aud", "exp", "iat", "nonce", "sub"] {
            let mut claims = map(good(t));
            claims.remove(missing);
            assert!(check_id_token(&claims, &expect(now)).is_err(), "{missing}");
        }
    }

    #[test]
    fn groups_are_found_by_name_or_path_and_map_to_the_highest_role() {
        let claims = map(json!({
            "groups": ["dev", "ops", "dev"],
            "realm_access": {"roles": ["broker-admins"]},
            "https://example.test/groups": "auditors",
        }));
        assert_eq!(groups(claim(&claims, "groups")), ["dev", "ops"]);
        assert_eq!(
            groups(claim(&claims, "realm_access.roles")),
            ["broker-admins"]
        );
        assert_eq!(
            groups(claim(&claims, "https://example.test/groups")),
            ["auditors"]
        );
        assert!(groups(claim(&claims, "realm_access.missing")).is_empty());
        let mappings = vec![
            RoleMapping {
                group: "dev".into(),
                role: Role::Viewer,
            },
            RoleMapping {
                group: "ops".into(),
                role: Role::Editor,
            },
        ];
        assert_eq!(
            mapped_role(&mappings, &["dev".into(), "ops".into()]),
            Some(Role::Editor)
        );
        assert_eq!(mapped_role(&mappings, &["dev".into()]), Some(Role::Viewer));
        assert_eq!(mapped_role(&mappings, &["Dev".into()]), None);
        assert_eq!(mapped_role(&mappings, &[]), None);
    }

    #[test]
    fn discovery_must_be_for_the_issuer_over_https() {
        let doc = |issuer: &str, token: &str| {
            json!({
                "issuer": issuer,
                "authorization_endpoint": "https://idp.example.test/auth",
                "token_endpoint": token,
                "jwks_uri": "https://idp.example.test/keys",
                "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            })
            .to_string()
        };
        let d = parse_discovery(
            "https://idp.example.test",
            doc("https://idp.example.test", "https://idp.example.test/token").as_bytes(),
        )
        .unwrap();
        assert_eq!(d.algorithms(), [Algorithm::Rs256]);
        assert!(parse_discovery(
            "https://idp.example.test",
            doc(
                "https://evil.example.test",
                "https://idp.example.test/token"
            )
            .as_bytes()
        )
        .is_err());
        assert!(parse_discovery(
            "https://idp.example.test",
            doc("https://idp.example.test", "http://idp.example.test/token").as_bytes()
        )
        .is_err());
        assert!(check_url("x", "http://127.0.0.1:9/a").is_ok());
        assert!(check_url("x", "http://localhost/a").is_ok());
        for bad in [
            "http://idp.example.test",
            "https://u:p@idp.example.test",
            "ftp://x",
            "https://x/#f",
        ] {
            assert!(check_url("x", bad).is_err(), "{bad}");
        }
        assert_eq!(
            discovery_url("https://idp.example.test/realms/a/")
                .unwrap()
                .as_str(),
            "https://idp.example.test/realms/a/.well-known/openid-configuration"
        );
    }

    #[test]
    fn usernames_pkce_and_provider_errors() {
        assert_eq!(
            username(Some(&json!(" Ada.Lovelace@Example.test "))).as_deref(),
            Some("ada.lovelace@example.test")
        );
        for bad in [
            json!("ab"),
            json!("a b c"),
            json!(7),
            json!("x".repeat(129)),
        ] {
            assert_eq!(username(Some(&bad)), None, "{bad}");
        }
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(
            provider_error("access_denied", Some("no\nway")),
            "access_denied: noway"
        );
    }
}
