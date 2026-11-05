// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Session cookie formatting. The `__Host-` prefix makes browsers enforce
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
    header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == SESSION_COOKIE && !value.is_empty()).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_has_all_protections() {
        let c = session_cookie("abc", 3600);
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=3600"] {
            assert!(c.contains(attr), "missing {attr}");
        }
        assert!(!c.contains("Domain"));
    }

    #[test]
    fn parses_cookie_header() {
        let header = format!("other=1; {SESSION_COOKIE}=tok; x=y");
        assert_eq!(session_from_cookie_header(&header), Some("tok"));
        assert_eq!(session_from_cookie_header("other=1"), None);
        assert_eq!(session_from_cookie_header(&format!("{SESSION_COOKIE}=")), None);
    }
}
