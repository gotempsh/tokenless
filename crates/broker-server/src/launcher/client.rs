// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small client for the parts of the management API a launcher needs.

use std::collections::BTreeMap;
use std::time::Duration;

use broker_control::model::{Page, ProxySession, Vault};
use broker_control::service::sessions::{DiscoveredService, SessionDiscovery};
use broker_core::ids::VaultId;
use reqwest::{RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::LauncherError;

const TIMEOUT: Duration = Duration::from_secs(30);

/// What to mint: a bundle of the vault and the session's limits.
#[derive(Debug, Clone, Serialize)]
pub struct MintRequest {
    pub bundle: String,
    pub ttl_secs: u64,
    /// Last as long as Settings allow, ignoring `ttl_secs`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub longest: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_limit: Option<u64>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
pub struct Minted {
    pub token: String,
    pub session: ProxySession,
}

impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted")
            .field("token", &"***")
            .field("session", &self.session)
            .finish()
    }
}

/// What a session port serves at `/services`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortServices {
    pub bundle: Option<String>,
    pub services: Vec<DiscoveredService>,
}

#[derive(Deserialize, Default)]
struct Problem {
    #[serde(default)]
    title: String,
    #[serde(default)]
    detail: String,
}

/// How the launcher proves who it is to the management API.
pub enum Credentials {
    /// An API key (`cbk_...`), usually a session issuer.
    ApiKey(Zeroizing<String>),
    /// The person's console session from `tokenless login`.
    Session {
        token: Zeroizing<String>,
        csrf_token: String,
    },
}

pub struct ApiClient {
    http: reqwest::Client,
    base: String,
    credentials: Option<Credentials>,
}

impl ApiClient {
    /// `server` is the management API origin, e.g. `http://127.0.0.1:8080`.
    pub fn new(server: &str, credentials: Option<Credentials>) -> Result<Self, LauncherError> {
        let base = server.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(LauncherError::config(format!(
                "--server '{base}' must start with http:// or https://"
            )));
        }
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            // The launcher talks to the broker directly, never through the
            // proxy it is about to configure for the agent.
            .no_proxy()
            .build()
            .map_err(|e| LauncherError::Http {
                operation: "building the HTTP client",
                url: base.clone(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            http,
            base,
            credentials,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.base)
    }

    fn authed(
        &self,
        builder: RequestBuilder,
        operation: &'static str,
    ) -> Result<RequestBuilder, LauncherError> {
        match self.credentials.as_ref() {
            Some(Credentials::ApiKey(key)) => Ok(builder.bearer_auth(key.as_str())),
            Some(Credentials::Session { token, csrf_token }) => Ok(builder
                .header(
                    reqwest::header::COOKIE,
                    format!("{}={}", broker_auth::cookie::SESSION_COOKIE, token.as_str()),
                )
                .header(broker_auth::csrf::CSRF_HEADER, csrf_token)),
            None => Err(LauncherError::config(format!(
                "{operation} needs an API key or a signed-in person: set TOKENLESS_API_KEY, pass --api-key-file, or run tokenless login"
            ))),
        }
    }

    async fn send(
        &self,
        builder: RequestBuilder,
        operation: &'static str,
        url: &str,
    ) -> Result<Response, LauncherError> {
        let response = builder.send().await.map_err(|e| LauncherError::Http {
            operation,
            url: url.to_string(),
            reason: e.to_string(),
        })?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let problem: Problem = response.json().await.unwrap_or_default();
        Err(LauncherError::Api {
            operation,
            status,
            title: problem.title,
            detail: problem.detail,
        })
    }

    async fn json<T: serde::de::DeserializeOwned>(
        response: Response,
        operation: &'static str,
        url: &str,
    ) -> Result<T, LauncherError> {
        response.json().await.map_err(|e| LauncherError::Http {
            operation,
            url: url.to_string(),
            reason: format!("unexpected response body: {e}"),
        })
    }

    /// A vault id as given, a vault name, or, when `reference` is `None`,
    /// the only vault the caller can see (a vault-bound API key sees one).
    pub async fn resolve_vault(&self, reference: Option<&str>) -> Result<VaultId, LauncherError> {
        if let Some(id) = reference.and_then(|r| r.trim().parse::<VaultId>().ok()) {
            return Ok(id);
        }
        const OP: &str = "listing vaults";
        let url = self.url("/vaults?page_size=100");
        let response = self
            .send(self.authed(self.http.get(&url), OP)?, OP, &url)
            .await?;
        let vaults: Page<Vault> = Self::json(response, OP, &url).await?;
        let names = || {
            vaults
                .items
                .iter()
                .map(|v| v.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match reference {
            Some(name) => vaults
                .items
                .iter()
                .find(|v| v.name == name.trim())
                .map(|v| v.id)
                .ok_or_else(|| {
                    LauncherError::config(format!(
                        "no vault named '{name}' is visible here (visible: {})",
                        names()
                    ))
                }),
            None => match vaults.items.as_slice() {
                [only] => Ok(only.id),
                [] => Err(LauncherError::config("no vault is visible here")),
                _ => Err(LauncherError::config(format!(
                    "several vaults are visible ({}); pass --vault",
                    names()
                ))),
            },
        }
    }

    pub async fn mint(&self, vault: &VaultId, req: &MintRequest) -> Result<Minted, LauncherError> {
        const OP: &str = "minting a session";
        let url = self.url(&format!("/vaults/{vault}/sessions"));
        let builder = self.authed(self.http.post(&url), OP)?.json(req);
        let response = self.send(builder, OP, &url).await?;
        Self::json(response, OP, &url).await
    }

    /// Ends the session `token` belongs to; the token is the credential.
    pub async fn revoke_self(&self, token: &str) -> Result<ProxySession, LauncherError> {
        const OP: &str = "revoking the session";
        let url = self.url("/sessions/revoke-self");
        let builder = self.http.post(&url).bearer_auth(token);
        let response = self.send(builder, OP, &url).await?;
        Self::json(response, OP, &url).await
    }

    /// The services the session `token` belongs to can reach.
    pub async fn discover(&self, token: &str) -> Result<SessionDiscovery, LauncherError> {
        const OP: &str = "looking up the session's services";
        let url = self.url("/sessions/self");
        let builder = self.http.get(&url).bearer_auth(token);
        let response = self.send(builder, OP, &url).await?;
        Self::json(response, OP, &url).await
    }

    /// Asks a session port (`http://127.0.0.1:<port>`) what it reaches.
    pub async fn port_services(&self, port_url: &str) -> Result<PortServices, LauncherError> {
        const OP: &str = "asking the session port for its services";
        let url = format!(
            "{}{}",
            port_url.trim_end_matches('/'),
            super::port::SERVICES_PATH
        );
        let response = self.send(self.http.get(&url), OP, &url).await?;
        Self::json(response, OP, &url).await
    }

    /// Ends a session by id; needs an API key allowed to revoke sessions.
    pub async fn revoke_by_id(&self, id: &str) -> Result<ProxySession, LauncherError> {
        const OP: &str = "revoking the session";
        let url = self.url(&format!("/sessions/{}/revoke", id.trim()));
        let response = self
            .send(self.authed(self.http.post(&url), OP)?, OP, &url)
            .await?;
        Self::json(response, OP, &url).await
    }

    /// The CA agents must trust for intercepted hosts, as PEM.
    pub async fn interception_ca(&self) -> Result<(String, String), LauncherError> {
        const OP: &str = "downloading the interception CA";
        let url = self.url("/ca/interception.pem");
        let response = self.send(self.http.get(&url), OP, &url).await?;
        let pem = response.text().await.map_err(|e| LauncherError::Http {
            operation: OP,
            url: url.clone(),
            reason: e.to_string(),
        })?;
        Ok((pem, url))
    }
}
