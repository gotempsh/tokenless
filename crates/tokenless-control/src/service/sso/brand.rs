// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which product an identity provider is, read from its issuer, so the
//! sign-in button can carry that product's logo. Nothing else depends on
//! it: a provider not recognised here works the same, under the OpenID
//! Connect logo.

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderBrand {
    Keycloak,
    Okta,
    Microsoft,
    Google,
    Auth0,
    Authentik,
    Gitlab,
    /// Any other OpenID Connect provider.
    Openid,
}

impl ProviderBrand {
    /// The product behind `issuer`, by the URL shapes each one publishes.
    /// A custom domain in front of a hosted provider reads as
    /// [`ProviderBrand::Openid`] unless its path gives the product away.
    pub fn of_issuer(issuer: &str) -> Self {
        let Ok(url) = Url::parse(issuer) else {
            return Self::Openid;
        };
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let under = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
        let path = url.path();
        if [
            "okta.com",
            "oktapreview.com",
            "okta-emea.com",
            "okta-gov.com",
        ]
        .iter()
        .any(|d| under(d))
        {
            Self::Okta
        } else if [
            "microsoftonline.com",
            "microsoftonline.us",
            "sts.windows.net",
        ]
        .iter()
        .any(|d| under(d))
            || host.ends_with(".ciamlogin.com")
        {
            Self::Microsoft
        } else if host == "accounts.google.com" {
            Self::Google
        } else if under("auth0.com") {
            Self::Auth0
        } else if host == "gitlab.com" {
            Self::Gitlab
        } else if path.starts_with("/realms/") || path.starts_with("/auth/realms/") {
            // Keycloak, and the Red Hat build of it; `/auth` before
            // version 17.
            Self::Keycloak
        } else if path.starts_with("/application/o/") {
            Self::Authentik
        } else {
            Self::Openid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderBrand::{self, *};

    #[test]
    fn hosted_providers_are_known_by_their_domain() {
        for (issuer, brand) in [
            ("https://example.okta.com", Okta),
            ("https://example.oktapreview.com/oauth2/default", Okta),
            (
                "https://login.microsoftonline.com/0000-tenant/v2.0",
                Microsoft,
            ),
            ("https://sts.windows.net/0000-tenant/", Microsoft),
            ("https://example.ciamlogin.com/0000-tenant/v2.0", Microsoft),
            ("https://accounts.google.com", Google),
            ("https://example.eu.auth0.com/", Auth0),
            ("https://gitlab.com", Gitlab),
        ] {
            assert_eq!(ProviderBrand::of_issuer(issuer), brand, "{issuer}");
        }
    }

    #[test]
    fn self_hosted_providers_are_known_by_their_path() {
        for (issuer, brand) in [
            ("http://localhost:8080/realms/example", Keycloak),
            ("https://sso.example.com/auth/realms/example", Keycloak),
            ("https://id.example.com/application/o/tokenless/", Authentik),
        ] {
            assert_eq!(ProviderBrand::of_issuer(issuer), brand, "{issuer}");
        }
    }

    #[test]
    fn anything_else_is_a_plain_openid_provider() {
        for issuer in [
            "https://id.example.com",
            "https://gitlab.example.com",
            // Lookalikes are not the hosted product.
            "https://okta.com.example.net",
            "https://notokta.com",
            "https://example.com/okta.com/realms-like",
            "not a url",
            "",
        ] {
            assert_eq!(ProviderBrand::of_issuer(issuer), Openid, "{issuer}");
        }
    }

    #[test]
    fn it_reads_as_one_lowercase_word() {
        assert_eq!(serde_json::to_string(&Keycloak).unwrap(), "\"keycloak\"");
        assert_eq!(serde_json::to_string(&Openid).unwrap(), "\"openid\"");
    }
}
