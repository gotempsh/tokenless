// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Acting as a person from the terminal: `tokenless login` signs in like the
//! console does and keeps the session in the OS keychain (or a private file
//! where there is none), and the commands
//! that set up a broker (`service add`, `proxy add`) use it. They go through
//! the same checks as the console: a person's session with its CSRF token,
//! and a fresh authenticator code when an action asks for one. API keys
//! cannot do these things.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokenless_auth::cookie::{session_from_cookie_header, SESSION_COOKIE};
use tokenless_auth::csrf::CSRF_HEADER;
use tokenless_control::model::{
    AccessBundle, Alert, CredentialMeta, Node, Page, ProxySession, Rule, Settings, StoredTemplate,
    Tripwire, Vault,
};
use tokenless_control::service::auth::{SignIn as SignInRecord, SignInsRevoked, UserSummary};
use tokenless_control::service::launcher_keys::{
    CreatedLauncherKey, LauncherKey, RevokedLauncherKey,
};
use tokenless_control::service::tripwires::CreatedTripwire;
use tokenless_core::ids::{
    AlertId, ApiKeyId, BundleId, CredentialId, RuleId, SignInId, TripwireId, UserId, VaultId,
};
use tokenless_core::tripwire::TripwireKind;
use zeroize::Zeroizing;

use super::LauncherError;

const TIMEOUT: Duration = Duration::from_secs(30);
const KEYCHAIN_SERVICE: &str = "tokenless";

/// A console session kept between commands. The token is a credential: it
/// lives in the OS keychain, or in a file only its owner can read when this
/// machine has no usable keychain.
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
    fn get(server: &str) -> Result<Option<Zeroizing<String>>, keyring::Error> {
        match keyring::Entry::new(KEYCHAIN_SERVICE, server)?.get_password() {
            Ok(json) => Ok(Some(Zeroizing::new(json))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn set(server: &str, json: &str) -> Result<(), keyring::Error> {
        keyring::Entry::new(KEYCHAIN_SERVICE, server)?.set_password(json)
    }

    fn remove(server: &str) -> Result<bool, keyring::Error> {
        match keyring::Entry::new(KEYCHAIN_SERVICE, server)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// The keychain cannot be used at all here, as opposed to failing on one
/// entry: Docker's default seccomp profile blocks the Linux kernel keyring,
/// and a headless machine may have no keychain service.
fn keychain_unavailable(e: &keyring::Error) -> bool {
    matches!(
        e,
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_)
    )
}

fn keychain(operation: &'static str, server: &str, e: keyring::Error) -> LauncherError {
    LauncherError::Keychain {
        operation,
        server: server.to_string(),
        reason: e.to_string(),
    }
}

fn encode(session: &SavedSession) -> Result<Zeroizing<String>, LauncherError> {
    serde_json::to_string(session)
        .map(Zeroizing::new)
        .map_err(|e| LauncherError::Keychain {
            operation: "saving",
            server: session.server.clone(),
            reason: e.to_string(),
        })
}

fn decode(server: &str, json: &str) -> Result<SavedSession, LauncherError> {
    serde_json::from_str(json).map_err(|e| LauncherError::Keychain {
        operation: "reading",
        server: server.to_string(),
        reason: format!("the saved session is unreadable ({e}); run tokenless login"),
    })
}

impl SessionVault for Keychain {
    fn load(&self, server: &str) -> Result<Option<SavedSession>, LauncherError> {
        match Self::get(server).map_err(|e| keychain("reading", server, e))? {
            Some(json) => decode(server, &json).map(Some),
            None => Ok(None),
        }
    }

    fn save(&self, session: &SavedSession) -> Result<(), LauncherError> {
        Self::set(&session.server, &encode(session)?)
            .map_err(|e| keychain("saving", &session.server, e))
    }

    fn delete(&self, server: &str) -> Result<bool, LauncherError> {
        Self::remove(server).map_err(|e| keychain("removing", server, e))
    }
}

/// Sessions in files only their owner can read (`0600` in a `0700`
/// directory), one per server, for machines without a usable keychain.
pub struct SessionFiles {
    dir: PathBuf,
}

impl SessionFiles {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// `$XDG_CONFIG_HOME/tokenless/sessions`, or
    /// `~/.config/tokenless/sessions`.
    pub fn default_dir() -> Option<PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|h| !h.is_empty())
                    .map(|home| PathBuf::from(home).join(".config"))
            })?;
        Some(config.join("tokenless").join("sessions"))
    }

    pub fn path(&self, server: &str) -> PathBuf {
        let name: String = server
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{name}.json"))
    }

    fn io(context: String) -> impl FnOnce(std::io::Error) -> LauncherError {
        move |source| LauncherError::Io { context, source }
    }
}

impl SessionVault for SessionFiles {
    fn load(&self, server: &str) -> Result<Option<SavedSession>, LauncherError> {
        let path = self.path(server);
        let json = match std::fs::read_to_string(&path) {
            Ok(json) => Zeroizing::new(json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Self::io(format!("reading {}", path.display()))(e)),
        };
        let session = decode(server, &json)?;
        // Two servers whose names differ only in punctuation share a file
        // name; never hand one server's session to the other.
        Ok((session.server == server).then_some(session))
    }

    fn save(&self, session: &SavedSession) -> Result<(), LauncherError> {
        use std::io::Write;
        let json = encode(session)?;
        let mut dir = std::fs::DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            dir.mode(0o700);
        }
        dir.create(&self.dir)
            .map_err(Self::io(format!("creating {}", self.dir.display())))?;
        let path = self.path(&session.server);
        let tmp = path.with_extension("tmp");
        // A leftover temporary file may have wider permissions; the mode
        // below only applies to a file this call creates.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Self::io(format!("removing {}", tmp.display()))(e)),
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(Self::io(format!("writing {}", tmp.display())))?;
        file.write_all(json.as_bytes())
            .map_err(Self::io(format!("writing {}", tmp.display())))?;
        drop(file);
        std::fs::rename(&tmp, &path).map_err(Self::io(format!("replacing {}", path.display())))
    }

    fn delete(&self, server: &str) -> Result<bool, LauncherError> {
        let path = self.path(server);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Self::io(format!("removing {}", path.display()))(e)),
        }
    }
}

/// Where `tokenless login` put the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Keychain,
    /// The keychain was unavailable for `reason`.
    File {
        path: PathBuf,
        reason: String,
    },
}

/// The keychain, falling back to [`SessionFiles`] when this machine has no
/// usable keychain. Only that case falls back: any other keychain error
/// is returned.
pub struct SessionStore {
    files: Option<SessionFiles>,
}

impl SessionStore {
    pub fn new(files: Option<SessionFiles>) -> Self {
        Self { files }
    }

    /// The keychain, and files in [`SessionFiles::default_dir`].
    pub fn system() -> Self {
        Self::new(SessionFiles::default_dir().map(SessionFiles::new))
    }

    fn files(&self, server: &str, e: keyring::Error) -> Result<&SessionFiles, LauncherError> {
        self.files.as_ref().ok_or_else(|| LauncherError::Keychain {
            operation: "saving",
            server: server.to_string(),
            reason: format!(
                "{e}, and HOME is not set, so there is nowhere else to keep it; set HOME, or use an API key (TOKENLESS_API_KEY)"
            ),
        })
    }

    /// Saves the session and says where it went.
    pub fn store(&self, session: &SavedSession) -> Result<Stored, LauncherError> {
        let json = encode(session)?;
        match Keychain::set(&session.server, &json) {
            Ok(()) => {
                // A file from a time without a keychain is now stale.
                if let Some(files) = &self.files {
                    files.delete(&session.server)?;
                }
                Ok(Stored::Keychain)
            }
            Err(e) if keychain_unavailable(&e) => {
                let reason = e.to_string();
                let files = self.files(&session.server, e)?;
                files.save(session)?;
                Ok(Stored::File {
                    path: files.path(&session.server),
                    reason,
                })
            }
            Err(e) => Err(keychain("saving", &session.server, e)),
        }
    }
}

impl SessionVault for SessionStore {
    fn load(&self, server: &str) -> Result<Option<SavedSession>, LauncherError> {
        match Keychain::get(server) {
            Ok(Some(json)) => return decode(server, &json).map(Some),
            Ok(None) => {}
            Err(e) if keychain_unavailable(&e) => {}
            Err(e) => return Err(keychain("reading", server, e)),
        }
        match &self.files {
            Some(files) => files.load(server),
            None => Ok(None),
        }
    }

    fn save(&self, session: &SavedSession) -> Result<(), LauncherError> {
        self.store(session).map(|_| ())
    }

    fn delete(&self, server: &str) -> Result<bool, LauncherError> {
        let in_keychain = match Keychain::remove(server) {
            Ok(removed) => removed,
            Err(e) if keychain_unavailable(&e) => false,
            Err(e) => return Err(keychain("removing", server, e)),
        };
        let in_file = match &self.files {
            Some(files) => files.delete(server)?,
            None => false,
        };
        Ok(in_keychain || in_file)
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

/// How the CLI names itself to the control plane, so a person's list of
/// sign-ins tells a `tokenless login` apart from a browser.
pub const USER_AGENT: &str = concat!("tokenless/", env!("CARGO_PKG_VERSION"));

fn http_client(base: &str) -> Result<reqwest::Client, LauncherError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
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

/// How many items a list call asks for at a time: the API's maximum.
const PAGE_SIZE: usize = 100;

/// The sessions `sessions` found, and whether more matched past its
/// limit.
#[derive(Debug, Clone)]
pub struct Sessions {
    pub sessions: Vec<ProxySession>,
    pub more: bool,
}

/// Which sessions `ConsoleClient::sessions` lists.
#[derive(Debug, Clone)]
pub enum SessionScope {
    /// Every vault the person can see.
    Everywhere,
    Vault(VaultId),
    Bundle(BundleId),
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

    /// Every item of a paginated list, `PAGE_SIZE` at a time.
    async fn pages<T: DeserializeOwned>(
        &self,
        path: &str,
        operation: &'static str,
    ) -> Result<Vec<T>, LauncherError> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut page: u64 = 1;
        loop {
            let got: Page<T> = self
                .call(
                    Method::GET,
                    &format!("{path}{sep}page={page}&page_size={PAGE_SIZE}"),
                    None,
                    operation,
                )
                .await?;
            let fetched = got.items.len();
            items.extend(got.items);
            if fetched < PAGE_SIZE || u64::try_from(items.len()).unwrap_or(u64::MAX) >= got.total {
                break;
            }
            page += 1;
        }
        Ok(items)
    }

    pub async fn vaults(&self) -> Result<Vec<Vault>, LauncherError> {
        self.pages("/vaults", "listing vaults").await
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
        self.pages(
            &format!("/vaults/{vault}/bundles"),
            "listing access bundles",
        )
        .await
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

    /// A launcher key for `bundle` (a name or id). Creating one is new
    /// access, so the server may ask to confirm it is you first.
    pub async fn create_launcher_key(
        &self,
        vault: &VaultId,
        request: &serde_json::Value,
    ) -> Result<CreatedLauncherKey, LauncherError> {
        self.call(
            Method::POST,
            &format!("/vaults/{vault}/launcher-keys"),
            Some(request.clone()),
            "creating the launcher key",
        )
        .await
    }

    /// The vault's launcher keys, revoked and expired ones included.
    pub async fn launcher_keys(&self, vault: &VaultId) -> Result<Vec<LauncherKey>, LauncherError> {
        self.pages(
            &format!("/vaults/{vault}/launcher-keys"),
            "listing launcher keys",
        )
        .await
    }

    /// Revokes the key and ends the live sessions it started.
    pub async fn revoke_launcher_key(
        &self,
        vault: &VaultId,
        id: &ApiKeyId,
    ) -> Result<RevokedLauncherKey, LauncherError> {
        self.call(
            Method::POST,
            &format!("/vaults/{vault}/launcher-keys/{id}/revoke"),
            Some(json!({})),
            "revoking the launcher key",
        )
        .await
    }

    /// A new tripwire in `vault`, with its decoy and how to plant it.
    pub async fn create_tripwire(
        &self,
        vault: &VaultId,
        name: &str,
        kind: TripwireKind,
    ) -> Result<CreatedTripwire, LauncherError> {
        self.call(
            Method::POST,
            &format!("/vaults/{vault}/tripwires"),
            Some(json!({ "name": name, "kind": kind })),
            "creating the tripwire",
        )
        .await
    }

    pub async fn tripwires(&self, vault: &VaultId) -> Result<Vec<Tripwire>, LauncherError> {
        self.pages(&format!("/vaults/{vault}/tripwires"), "listing tripwires")
            .await
    }

    pub async fn delete_tripwire(&self, id: &TripwireId) -> Result<Tripwire, LauncherError> {
        self.call(
            Method::DELETE,
            &format!("/tripwires/{id}"),
            None,
            "deleting the tripwire",
        )
        .await
    }

    /// The signed-in person's sign-ins, the current one marked.
    pub async fn sign_ins(&self) -> Result<Vec<SignInRecord>, LauncherError> {
        self.pages("/auth/sign-ins", "listing your sign-ins").await
    }

    /// The newest alerts, up to `limit`; only those not acknowledged
    /// unless `all`.
    pub async fn alerts(&self, all: bool, limit: u64) -> Result<Page<Alert>, LauncherError> {
        self.call(
            Method::GET,
            &format!("/alerts?open={}&page_size={limit}", !all),
            None,
            "listing alerts",
        )
        .await
    }

    /// Every alert not acknowledged yet, newest first.
    pub async fn open_alerts(&self) -> Result<Vec<Alert>, LauncherError> {
        self.pages("/alerts?open=true", "listing alerts").await
    }

    pub async fn acknowledge_alert(&self, id: &AlertId) -> Result<Alert, LauncherError> {
        self.call(
            Method::POST,
            &format!("/alerts/{id}/acknowledge"),
            Some(json!({})),
            "acknowledging the alert",
        )
        .await
    }

    /// Ends one of the signed-in person's sign-ins.
    pub async fn revoke_sign_in(&self, id: &SignInId) -> Result<(), LauncherError> {
        self.call::<serde_json::Value>(
            Method::POST,
            &format!("/auth/sign-ins/{id}/revoke"),
            Some(json!({})),
            "ending the sign-in",
        )
        .await
        .map(|_| ())
    }

    /// Ends every sign-in of the signed-in person but this one.
    pub async fn revoke_other_sign_ins(&self) -> Result<SignInsRevoked, LauncherError> {
        self.call(
            Method::POST,
            "/auth/sign-ins/revoke-others",
            Some(json!({})),
            "signing out everywhere else",
        )
        .await
    }

    /// Everyone with an account, for an admin.
    pub async fn users(&self) -> Result<Vec<UserSummary>, LauncherError> {
        self.pages("/users", "listing people").await
    }

    /// Someone's sign-ins, for an admin.
    pub async fn user_sign_ins(&self, user: &UserId) -> Result<Vec<SignInRecord>, LauncherError> {
        self.pages(&format!("/users/{user}/sign-ins"), "listing their sign-ins")
            .await
    }

    /// Signs someone out everywhere, for an admin.
    pub async fn revoke_user_sign_ins(
        &self,
        user: &UserId,
    ) -> Result<SignInsRevoked, LauncherError> {
        self.call(
            Method::POST,
            &format!("/users/{user}/sign-ins/revoke"),
            Some(json!({})),
            "signing them out everywhere",
        )
        .await
    }

    /// The signed-in person, which also proves the saved session still works.
    pub async fn me(&self) -> Result<UserSummary, LauncherError> {
        #[derive(Deserialize)]
        struct Me {
            user: UserSummary,
        }
        let me: Me = self
            .call(Method::GET, "/auth/me", None, "checking the session")
            .await?;
        Ok(me.user)
    }

    /// The instance's settings. Admins only.
    pub async fn settings(&self) -> Result<Settings, LauncherError> {
        self.call(Method::GET, "/settings", None, "reading settings")
            .await
    }

    /// The enrolled proxies. Needs a role that may see them.
    pub async fn nodes(&self) -> Result<Vec<Node>, LauncherError> {
        self.pages("/nodes", "listing proxies").await
    }

    /// The rules in `vault`.
    pub async fn rules(&self, vault: &VaultId) -> Result<Vec<Rule>, LauncherError> {
        self.pages(&format!("/vaults/{vault}/rules"), "listing rules")
            .await
    }

    /// The services in `vault`.
    pub async fn credentials(&self, vault: &VaultId) -> Result<Vec<CredentialMeta>, LauncherError> {
        self.pages(&format!("/vaults/{vault}/credentials"), "listing services")
            .await
    }

    /// The newest sessions in `scope`, up to `limit`; only the live ones
    /// (neither revoked nor expired) when `active`. Each page continues
    /// after the last session of the one before, not at an offset, so
    /// sessions minted or ended meanwhile neither repeat nor skip a row.
    pub async fn sessions(
        &self,
        scope: &SessionScope,
        active: bool,
        limit: usize,
    ) -> Result<Sessions, LauncherError> {
        let path = match scope {
            SessionScope::Everywhere => "/sessions".to_string(),
            SessionScope::Vault(vault) => format!("/vaults/{vault}/sessions"),
            SessionScope::Bundle(bundle) => format!("/bundles/{bundle}/sessions"),
        };
        let mut items: Vec<ProxySession> = Vec::new();
        let mut more = false;
        while items.len() < limit {
            let want = (limit - items.len()).min(PAGE_SIZE);
            let mut url = format!("{path}?active={active}&page_size={want}");
            if let Some(last) = items.last() {
                url.push_str(&format!(
                    "&after_created_at={}&after_id={}",
                    last.created_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
                    last.id
                ));
            }
            let got: Page<ProxySession> = self
                .call(Method::GET, &url, None, "listing sessions")
                .await?;
            let fetched = got.items.len();
            // After a cursor, `total` counts what is left from there.
            more = got.total > u64::try_from(fetched).unwrap_or(u64::MAX);
            items.extend(got.items);
            if fetched < want {
                break;
            }
        }
        items.truncate(limit);
        Ok(Sessions {
            sessions: items,
            more,
        })
    }
}

/// Whether a control plane answers at `server`: any HTTP answer counts,
/// since the check is not signed in. The error says why it does not.
pub async fn probe(server: &str) -> Result<String, String> {
    let base = normalise(server).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    client
        .get(format!("{base}/api/v1/auth/me"))
        .send()
        .await
        .map(|_| base)
        .map_err(|e| {
            if e.is_connect() {
                "nothing is listening there".to_string()
            } else if e.is_timeout() {
                "it did not answer within 5 seconds".to_string()
            } else {
                e.to_string()
            }
        })
}

/// The console page that adds a `template` service, with the vault and
/// bundle chosen when they exist. The person types the secret there, in
/// their browser, signed in as themselves.
pub fn add_service_url(
    server: &str,
    template: &str,
    vault: Option<&VaultId>,
    bundle: Option<&BundleId>,
) -> Result<String, LauncherError> {
    let base = normalise(server)?;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if let Some(vault) = vault {
        query.append_pair("vault", &vault.to_string());
    }
    if let Some(bundle) = bundle {
        query.append_pair("bundle", &bundle.to_string());
    }
    let query = query.finish();
    let template: String = url::form_urlencoded::byte_serialize(template.as_bytes()).collect();
    Ok(if query.is_empty() {
        format!("{base}/#/add-service/{template}")
    } else {
        format!("{base}/#/add-service/{template}?{query}")
    })
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
            t.template.id == wanted
                && t.status == tokenless_control::model::TemplateStatus::Approved
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
        // Checked before anything is stored, so a bad name cannot leave a
        // stored credential behind.
        if let Some(bundle) = &plan.bundle {
            tokenless_control::service::bundles::validate_bundle_name(bundle)
                .map_err(|e| LauncherError::config(e.to_string()))?;
        }
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
        let partly = |step: &'static str| {
            let (service, vault) = (credential.name.clone(), vault.name.clone());
            move |source: LauncherError| LauncherError::PartlyAdded {
                service,
                vault,
                step,
                source: Box::new(source),
            }
        };
        let rule = self
            .create_rule(&vault.id, &credential.id, &name, plan.read_only)
            .await
            .map_err(partly("creating its rule"))?;
        let bundle = match &plan.bundle {
            None => None,
            Some(bundle_name) => Some(
                self.join_bundle(&vault.id, bundle_name, &rule.id)
                    .await
                    .map_err(partly("adding it to the access bundle"))?,
            ),
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

    fn session(server: &str) -> SavedSession {
        SavedSession {
            server: server.into(),
            username: "admin".into(),
            totp_enrolled: false,
            token: "cbs_file-token".into(),
            csrf_token: "c".into(),
            expires_at: Utc::now(),
        }
    }

    #[test]
    fn session_files_round_trip_one_file_per_server() {
        let dir = tempfile::tempdir().unwrap();
        let files = SessionFiles::new(dir.path().join("tokenless").join("sessions"));
        assert!(files.load("http://127.0.0.1:8080").unwrap().is_none());
        files.save(&session("http://127.0.0.1:8080")).unwrap();
        files.save(&session("https://broker.example.com")).unwrap();

        let loaded = files.load("http://127.0.0.1:8080").unwrap().unwrap();
        assert_eq!(loaded.token, "cbs_file-token");
        assert_eq!(
            files.path("http://127.0.0.1:8080"),
            dir.path()
                .join("tokenless/sessions/http___127.0.0.1_8080.json")
        );
        assert!(files.delete("http://127.0.0.1:8080").unwrap());
        assert!(!files.delete("http://127.0.0.1:8080").unwrap());
        assert!(files.load("http://127.0.0.1:8080").unwrap().is_none());
        assert!(files.load("https://broker.example.com").unwrap().is_some());
    }

    #[test]
    fn a_session_file_is_never_read_for_another_server() {
        let dir = tempfile::tempdir().unwrap();
        let files = SessionFiles::new(dir.path());
        files.save(&session("http://a:1")).unwrap();
        // Same file name, different server.
        assert_eq!(files.path("http://a:1"), files.path("http://a_1"));
        assert!(files.load("http://a_1").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn session_files_are_readable_only_by_their_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let files = SessionFiles::new(dir.path().join("sessions"));
        let path = files.path("http://a");
        // A leftover temporary file anyone can read does not lend its mode.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        files.save(&session("http://a")).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert!(!tmp.exists());

        let fresh = SessionFiles::new(dir.path().join("new"));
        fresh.save(&session("http://a")).unwrap();
        assert_eq!(mode(&dir.path().join("new")), 0o700);
    }

    #[test]
    fn without_a_home_the_store_says_what_to_do() {
        let store = SessionStore::new(None);
        let err = store
            .files(
                "http://a",
                keyring::Error::PlatformFailure("blocked".into()),
            )
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("TOKENLESS_API_KEY"), "{err}");
    }
}
