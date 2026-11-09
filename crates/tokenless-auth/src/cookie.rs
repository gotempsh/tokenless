// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Session and single sign-on cookie formatting. The `__Host-` prefix makes browsers enforce
//! `Secure`, `Path=/` and no `Domain`, so a sibling subdomain cannot plant or
//! read it.

pub const SESSION_COOKIE: &str = "__Host-broker_session";

pub fn session_cookie(token: &str, max_age_secs: u64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age_secs}"
    )
}

pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

/// Extracts the session token from a `Cookie` header value.
pub fn session_from_cookie_header(header: &str) -> Option<&str> {
    named_cookie(header, SESSION_COOKIE)
}

/// Carries a single sign-on in progress, sealed (see [`crate::sealed`]),
/// in the browser that started it. `Lax`, not `Strict`: the browser comes
/// back from the identity provider, another site, and must still send it.
/// `Path=/`, as a `__Host-` cookie must be; only the callback reads it.
pub const SSO_FLOW_COOKIE: &str = "__Host-tokenless_sso";

pub fn sso_flow_cookie(value: &str, max_age_secs: u64) -> String {
    format!(
        "{SSO_FLOW_COOKIE}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}"
    )
}

pub fn clear_sso_flow_cookie() -> String {
    format!("{SSO_FLOW_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
}

pub fn sso_flow_from_cookie_header(header: &str) -> Option<&str> {
    named_cookie(header, SSO_FLOW_COOKIE)
}

fn named_cookie<'a>(header: &'a str, wanted: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == wanted && !value.is_empty()).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_has_all_protections() {
        let c = session_cookie("abc", 3600);
        for attr in [
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Path=/",
            "Max-Age=3600",
        ] {
            assert!(c.contains(attr), "missing {attr}");
        }
        assert!(!c.contains("Domain"));
    }

    #[test]
    fn the_sso_flow_cookie_survives_the_way_back_from_the_provider() {
        let c = sso_flow_cookie("abc", 600);
        for attr in [
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Path=/",
            "Max-Age=600",
        ] {
            assert!(c.contains(attr), "missing {attr}");
        }
        assert!(c.starts_with("__Host-"));
        let header = format!("{SESSION_COOKIE}=s; {SSO_FLOW_COOKIE}=f");
        assert_eq!(sso_flow_from_cookie_header(&header), Some("f"));
        assert_eq!(session_from_cookie_header(&header), Some("s"));
        assert!(clear_sso_flow_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn parses_cookie_header() {
        let header = format!("other=1; {SESSION_COOKIE}=tok; x=y");
        assert_eq!(session_from_cookie_header(&header), Some("tok"));
        assert_eq!(session_from_cookie_header("other=1"), None);
        assert_eq!(
            session_from_cookie_header(&format!("{SESSION_COOKIE}=")),
            None
        );
    }
}
