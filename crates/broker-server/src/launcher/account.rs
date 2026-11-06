// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Acting as a person from the terminal: `tokenless login` signs in like the
//! console does and keeps the session in the OS keychain, and the commands
//! that set up a broker (`service add`, `proxy add`) use it. They go through
//! the same checks as the console: a person's session with its CSRF token,
//! and a fresh authenticator code when an action asks for one. API keys
//! cannot do these things.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use broker_auth::cookie::{session_from_cookie_header, SESSION_COOKIE};
use broker_auth::csrf::CSRF_HEADER;
use broker_control::model::{AccessBundle, CredentialMeta, Page, Rule, StoredTemplate, Vault};
use broker_control::service::auth::UserSummary;
use broker_core::ids::{BundleId, CredentialId, RuleId, VaultId};
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use super::LauncherError;

const TIMEOUT: Duration = Duration::from_secs(30);
const KEYCHAIN_SERVICE: &str = "tokenless";

/// A console session kept between commands. The token is a credential: it
/// lives in the OS keychain, never in a file.
#[derive(Clone, Serialize, Deserialize)]
pub struct SavedSession {
    pub server: String,
    pub username: String,
    pub totp_enrolled: bool,
    pub token: String,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for SavedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedSession")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("totp_enrolled", &self.totp_enrolled)
            .field("token", &"***")
            .field("csrf_token", &"***")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Where sessions are kept, one per server.
pub trait SessionVault: Send + Sync {
    fn load(&self, server: &str) -> Result<Option<SavedSession>, LauncherError>;
    fn save(&self, session: &SavedSession) -> Result<(), LauncherError>;
    /// Returns whether there was one.
    fn delete(&self, server: &str) -> Result<bool, LauncherError>;
}

/// The OS keychain: the macOS Keychain, the Linux kernel keyring or the
/// Windows Credential Manager.
pub struct Keychain;

impl Keychain {
    fn entry(server: &str) -> Result<keyring::Entry, LauncherError> {
        keyring::Entry::new(KEYCHAIN_SERVICE, server).map_err(|e| keychain("opening", server, e))
    }
}

fn keychain(operation: &'static str, server: &str, e: keyring::Error) -> LauncherError {
    LauncherError::Keychain {
        operation,
        server: server.to_string(),
        reason: e.to_string(),
    }
}

impl SessionVault for Keychain {
    fn load(&self, server: &str) -> Result<Option<SavedSession>, LauncherError> {
        match Self::entry(server)?.get_password() {
            Ok(json) => {
                serde_json::from_str(&json)
                    .map(Some)
                    .map_err(|e| LauncherError::Keychain {
                        operation: "reading",
                        server: server.to_string(),
                        reason: format!(
                            "the saved session is unreadable ({e}); run tokenless login"
                        ),
                    })
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keychain("reading", server, e)),
        }
    }

    fn save(&self, session: &SavedSession) -> Result<(), LauncherError> {
        let json = Zeroizing::new(serde_json::to_string(session).map_err(|e| {
            LauncherError::Keychain {
                operation: "saving",
                server: session.server.clone(),
                reason: e.to_string(),
            }
        })?);
        Self::entry(&session.server)?
            .set_password(&json)
            .map_err(|e| keychain("saving", &session.server, e))
    }

    fn delete(&self, server: &str) -> Result<bool, LauncherError> {
        match Self::entry(server)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(keychain("removing", server, e)),
        }
    }
}

/// Sessions held in memory, for tests.
#[derive(Default)]
pub struct MemoryVault {
    sessions: Mutex<HashMap<String, SavedSession>>,
}

impl SessionVault for MemoryVault {
    fn load(&self, server: &str) -> Result<Option<SavedSession>, LauncherError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| LauncherError::config("session store lock poisoned"))?
            .get(server)
            .cloned())
    }

    fn save(&self, session: &SavedSession) -> Result<(), LauncherError> {
        self.sessions
            .lock()
            .map_err(|_| LauncherError::config("session store lock poisoned"))?
            .insert(session.server.clone(), session.clone());
        Ok(())
    }

    fn delete(&self, server: &str) -> Result<bool, LauncherError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| LauncherError::config("session store lock poisoned"))?
            .remove(server)
            .is_some())
    }
}

/// Asks the person at the terminal for something secret.
pub trait Prompter: Send + Sync {
    fn secret(&self, label: &str) -> Result<Zeroizing<String>, LauncherError>;
}

#[derive(Deserialize, Default)]
struct Problem {
    #[serde(default)]
    title: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    code: String,
}

fn normalise(server: &str) -> Result<String, LauncherError> {
    let base = server.trim().trim_end_matches('/').to_string();
    if base.starts_with("http://") || base.starts_with("https://") {
        Ok(base)
    } else {
        Err(LauncherError::config(format!(
            "--server '{base}' must start with http:// or https://"
        )))
    }
}

fn http_client(base: &str) -> Result<reqwest::Client, LauncherError> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .no_proxy()
        .build()
        .map_err(|e| LauncherError::Http {
            operation: "building the HTTP client",
            url: base.to_string(),
            reason: e.to_string(),
        })
}

/// A one-time token that enrols a proxy.
#[derive(Deserialize)]
pub struct JoinToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinToken")
            .field("token", &"***")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// What a sign-in attempt led to.
pub enum SignIn {
    Done(SavedSession),
    /// The password was right and the account has an authenticator: try
    /// again with its code.
    CodeNeeded,
}

#[derive(Deserialize)]
struct LoginReply {
    user: UserSummary,
    csrf_token: String,
    expires_at: DateTime<Utc>,
}

/// Signs in with a username and password (and the authenticator code, when
/// the account has one).
pub async fn sign_in(
    server: &str,
    username: &str,
    password: &str,
    code: Option<&str>,
) -> Result<SignIn, LauncherError> {
    const OP: &str = "signing in";
    let base = normalise(server)?;
    let url = format!("{base}/api/v1/auth/login");
    let mut body = json!({ "username": username, "password": password });
    if let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) {
        body["totp_code"] = json!(code);
    }
    let response = http_client(&base)?
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| LauncherError::Http {
            operation: OP,
            url: url.clone(),
            reason: e.to_string(),
        })?;
    let status = response.status();
    if !status.is_success() {
        let problem: Problem = response.json().await.unwrap_or_default();
        if problem.code == "second_factor_required" {
            return Ok(SignIn::CodeNeeded);
        }
        return Err(LauncherError::Api {
            operation: OP,
            status: status.as_u16(),
            title: problem.title,
            detail: problem.detail,
        });
    }
    let token = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(session_from_cookie_header)
        .map(str::to_string)
        .ok_or_else(|| LauncherError::Http {
            operation: OP,
            url: url.clone(),
            reason: "the reply carried no session cookie".into(),
        })?;
    let reply: LoginReply = response.json().await.map_err(|e| LauncherError::Http {
        operation: OP,
        url: url.clone(),
        reason: format!("unexpected response body: {e}"),
    })?;
    Ok(SignIn::Done(SavedSession {
        server: base,
        username: reply.user.username,
        totp_enrolled: reply.user.totp_enrolled,
        token,
        csrf_token: reply.csrf_token,
        expires_at: reply.expires_at,
    }))
}

/// The management API as the signed-in person.
pub struct ConsoleClient<'p> {
    http: reqwest::Client,
    session: SavedSession,
    prompter: &'p dyn Prompter,
}

impl<'p> ConsoleClient<'p> {
    /// The saved session for `server`, or an error saying to sign in.
    pub fn open(
        vault: &dyn SessionVault,
        server: &str,
        prompter: &'p dyn Prompter,
    ) -> Result<Self, LauncherError> {
        let base = normalise(server)?;
        let session = vault
            .load(&base)?
            .filter(|s| s.expires_at > Utc::now())
            .ok_or_else(|| LauncherError::NotSignedIn {
                server: base.clone(),
            })?;
        Ok(Self {
            http: http_client(&base)?,
            session,
            prompter,
        })
    }

    pub fn session(&self) -> &SavedSession {
        &self.session
    }

    async fn send(
        &self,
        method: &Method,
        path: &str,
        body: Option<&serde_json::Value>,
        operation: &'static str,
    ) -> Result<reqwest::Response, LauncherError> {
        let url = format!("{}/api/v1{path}", self.session.server);
        let mut request = self
            .http
            .request(method.clone(), &url)
            .header(
                reqwest::header::COOKIE,
                format!("{SESSION_COOKIE}={}", self.session.token),
            )
            .header(CSRF_HEADER, &self.session.csrf_token);
        if let Some(body) = body {
            request = request.json(body);
        }
        request.send().await.map_err(|e| LauncherError::Http {
            operation,
            url,
            reason: e.to_string(),
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        operation: &'static str,
    ) -> Result<T, LauncherError> {
        let mut stepped_up = false;
        loop {
            let response = self.send(&method, path, body.as_ref(), operation).await?;
            let status = response.status();
            if status.is_success() {
                let text = response.text().await.map_err(|e| LauncherError::Http {
                    operation,
                    url: path.to_string(),
                    reason: e.to_string(),
                })?;
                // Some replies (204) have no body.
                let text = if text.is_empty() { "null" } else { &text };
                return serde_json::from_str(text).map_err(|e| LauncherError::Http {
                    operation,
                    url: path.to_string(),
                    reason: format!("unexpected response body: {e}"),
                });
            }
            let problem: Problem = response.json().await.unwrap_or_default();
            if problem.code == "step_up_required" && !stepped_up {
                self.step_up().await?;
                stepped_up = true;
                continue;
            }
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(LauncherError::NotSignedIn {
                    server: self.session.server.clone(),
                });
            }
            return Err(LauncherError::Api {
                operation,
                status: status.as_u16(),
                title: problem.title,
                detail: problem.detail,
            });
        }
    }

    /// Confirms it is still the person at the keyboard, as the console asks
    /// before sensitive actions.
    async fn step_up(&self) -> Result<(), LauncherError> {
        let proof = if self.session.totp_enrolled {
            json!({ "code": self.prompter.secret("Authenticator code")?.trim() })
        } else {
            json!({ "password": self.prompter.secret("Password")?.as_str() })
        };
        const OP: &str = "confirming it is you";
        let response = self
            .send(&Method::POST, "/auth/step-up", Some(&proof), OP)
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status().as_u16();
        let problem: Problem = response.json().await.unwrap_or_default();
        Err(LauncherError::Api {
            operation: OP,
            status,
            title: problem.title,
            detail: problem.detail,
        })
    }

    pub async fn logout(&self) -> Result<(), LauncherError> {
        self.call::<serde_json::Value>(Method::POST, "/auth/logout", None, "signing out")
            .await
            .map(|_| ())
    }

    pub async fn templates(&self) -> Result<Vec<StoredTemplate>, LauncherError> {
        self.call(Method::GET, "/templates", None, "listing service templates")
            .await
    }

    pub async fn vaults(&self) -> Result<Vec<Vault>, LauncherError> {
        let page: Page<Vault> = self
            .call(Method::GET, "/vaults?page_size=100", None, "listing vaults")
            .await?;
        Ok(page.items)
    }

    pub async fn create_vault(&self, name: &str) -> Result<Vault, LauncherError> {
        self.call(
            Method::POST,
            "/vaults",
            Some(json!({ "name": name })),
            "creating the vault",
        )
        .await
    }

    pub async fn bundles(&self, vault: &VaultId) -> Result<Vec<AccessBundle>, LauncherError> {
        let page: Page<AccessBundle> = self
            .call(
                Method::GET,
                &format!("/vaults/{vault}/bundles?page_size=100"),
                None,
                "listing access bundles",
            )
            .await?;
        Ok(page.items)
    }

    pub async fn create_join_token(&self) -> Result<JoinToken, LauncherError> {
        self.call(
            Method::POST,
            "/nodes/join-tokens",
            Some(json!({})),
            "creating a proxy join token",
        )
        .await
    }
}

/// `tokenless service add`: a service from a template, its rule, and its
/// place in an access bundle, like the console's Add a service.
#[derive(Debug)]
pub struct AddService {
    pub template_id: String,
    pub name: Option<String>,
    /// Created when no vault has this name.
    pub vault: String,
    /// Joined when the vault has a bundle of this name, created otherwise.
    pub bundle: Option<String>,
    pub read_only: bool,
}

#[derive(Debug)]
pub struct AddedService {
    pub vault: Vault,
    pub vault_created: bool,
    pub credential: CredentialMeta,
    pub rule: Rule,
    pub bundle: Option<(AccessBundle, bool)>,
}

/// The approved template to add a service from: the newest version of `id`.
pub fn pick_template(
    templates: Vec<StoredTemplate>,
    id: &str,
) -> Result<StoredTemplate, LauncherError> {
    let wanted = id.trim().to_ascii_lowercase();
    templates
        .into_iter()
        .filter(|t| {
            t.template.id == wanted && t.status == broker_control::model::TemplateStatus::Approved
        })
        .max_by_key(|t| t.template.version)
        .ok_or_else(|| {
            LauncherError::config(format!(
                "no approved template '{wanted}'; the console's Templates page lists them"
            ))
        })
}

impl ConsoleClient<'_> {
    /// Adds the service. `fields` holds the template's credential fields;
    /// they are sent once over this connection and stored encrypted.
    pub async fn add_service(
        &self,
        plan: &AddService,
        template: &StoredTemplate,
        fields: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<AddedService, LauncherError> {
        let vault_name = plan.vault.trim();
        let (vault, vault_created) = match self
            .vaults()
            .await?
            .into_iter()
            .find(|v| v.name == vault_name)
        {
            Some(v) => (v, false),
            None => (self.create_vault(vault_name).await?, true),
        };
        let name = plan
            .name
            .clone()
            .unwrap_or_else(|| template.template.id.clone());
        let body = json!({
            "name": name,
            "template_id": template.template.id,
            "template_version": template.template.version,
            "fields": fields.iter().map(|(k, v)| (k.clone(), v.as_str().to_string())).collect::<BTreeMap<_, _>>(),
        });
        let credential: CredentialMeta = self
            .call(
                Method::POST,
                &format!("/vaults/{}/credentials", vault.id),
                Some(body),
                "saving the service",
            )
            .await?;
        drop(fields);
        let rule = self
            .create_rule(&vault.id, &credential.id, &name, plan.read_only)
            .await?;
        let bundle = match &plan.bundle {
            None => None,
            Some(bundle_name) => Some(self.join_bundle(&vault.id, bundle_name, &rule.id).await?),
        };
        Ok(AddedService {
            vault,
            vault_created,
            credential,
            rule,
            bundle,
        })
    }

    async fn create_rule(
        &self,
        vault: &VaultId,
        credential: &CredentialId,
        name: &str,
        read_only: bool,
    ) -> Result<Rule, LauncherError> {
        let mut body = json!({ "name": name, "credential_id": credential });
        if read_only {
            body["methods"] = json!(["GET", "HEAD"]);
        }
        self.call(
            Method::POST,
            &format!("/vaults/{vault}/rules"),
            Some(body),
            "creating the service's rule",
        )
        .await
    }

    /// Adds the rule to the vault's bundle of this name, creating it when
    /// there is none. Returns the bundle and whether it was created.
    async fn join_bundle(
        &self,
        vault: &VaultId,
        name: &str,
        rule: &RuleId,
    ) -> Result<(AccessBundle, bool), LauncherError> {
        let name = name.trim();
        match self
            .bundles(vault)
            .await?
            .into_iter()
            .find(|b| b.name == name)
        {
            None => {
                let bundle = self
                    .call(
                        Method::POST,
                        &format!("/vaults/{vault}/bundles"),
                        Some(json!({ "name": name, "rule_ids": [rule] })),
                        "creating the access bundle",
                    )
                    .await?;
                Ok((bundle, true))
            }
            Some(existing) => {
                let mut rule_ids: Vec<RuleId> = existing.rule_ids.clone();
                if !rule_ids.contains(rule) {
                    rule_ids.push(*rule);
                }
                let id: BundleId = existing.id;
                let bundle = self
                    .call(
                        Method::PATCH,
                        &format!("/bundles/{id}"),
                        Some(json!({ "rule_ids": rule_ids })),
                        "adding the service to the access bundle",
                    )
                    .await?;
                Ok((bundle, false))
            }
        }
    }
}

/// The node API address for a management API URL: same host, port 8443,
/// which is where `tokenless serve` listens by default.
pub fn default_control_url(server: &str) -> Result<String, LauncherError> {
    let base = normalise(server)?;
    let url = reqwest::Url::parse(&base)
        .map_err(|e| LauncherError::config(format!("--server '{base}' is not a URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| LauncherError::config(format!("--server '{base}' has no host")))?;
    // An IPv6 host comes back already bracketed.
    Ok(format!("https://{host}:8443"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_api_is_on_8443_of_the_same_host() {
        assert_eq!(
            default_control_url("http://127.0.0.1:8080").unwrap(),
            "https://127.0.0.1:8443"
        );
        assert_eq!(
            default_control_url("https://broker.example.com/").unwrap(),
            "https://broker.example.com:8443"
        );
        assert_eq!(
            default_control_url("http://[::1]:8080").unwrap(),
            "https://[::1]:8443"
        );
        assert!(default_control_url("broker.example.com").is_err());
    }

    #[test]
    fn saved_sessions_never_print_their_token() {
        let s = SavedSession {
            server: "http://127.0.0.1:8080".into(),
            username: "admin".into(),
            totp_enrolled: false,
            token: "cbs_secret-token".into(),
            csrf_token: "csrf-secret".into(),
            expires_at: Utc::now(),
        };
        let shown = format!("{s:?}");
        assert!(!shown.contains("secret"), "{shown}");
    }

    #[test]
    fn memory_vault_keeps_one_session_per_server() {
        let vault = MemoryVault::default();
        let s = SavedSession {
            server: "http://a".into(),
            username: "admin".into(),
            totp_enrolled: false,
            token: "t".into(),
            csrf_token: "c".into(),
            expires_at: Utc::now(),
        };
        vault.save(&s).unwrap();
        assert!(vault.load("http://a").unwrap().is_some());
        assert!(vault.load("http://b").unwrap().is_none());
        assert!(vault.delete("http://a").unwrap());
        assert!(!vault.delete("http://a").unwrap());
    }
}
