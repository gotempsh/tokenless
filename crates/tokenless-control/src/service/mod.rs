// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod alerts;
pub mod audit;
pub mod audit_export;
pub mod auth;
pub mod bundles;
pub mod launcher_keys;
pub mod nodes;
pub mod overview;
pub mod policy;
pub mod refresh;
pub(crate) mod render;
pub mod sessions;
pub mod sso;
#[cfg(test)]
pub(crate) mod testing;
pub mod tripwires;
pub mod users;
pub mod variables;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditEvent;
use tokenless_core::authz::{Action, Decision, Principal, PrincipalKind};
use tokenless_core::ids::VaultId;
use tracing::error;

use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::LaunchScope;
use crate::notify::PolicyNotifier;
use crate::probe::CredentialProber;
use crate::store::{
    AlertStore, AuditExportStore, AuditSink, Authorizer, CredentialStore, IdentityStore, NodeStore,
    PolicyStore, SsoStore, TripwireStore,
};

#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// How long a node may keep serving without a newer snapshot.
    pub lease_secs: u32,
    pub node_cert_ttl: chrono::Duration,
    pub ui_session_ttl_secs: u64,
    pub step_up_window_secs: u64,
    pub join_token_ttl_secs: u64,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            lease_secs: 60,
            node_cert_ttl: chrono::Duration::hours(24),
            ui_session_ttl_secs: 12 * 3600,
            step_up_window_secs: 300,
            join_token_ttl_secs: 3600,
        }
    }
}

/// The authenticated party behind a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: Principal,
    /// When the caller last proved a second factor (people only).
    pub step_up_at: Option<DateTime<Utc>>,
    /// Whether the caller has a second factor to step up with. Only people
    /// with an authenticator enrolled are asked to step up: for a
    /// password-only account it would just ask for the same password again.
    pub second_factor: bool,
    /// Set for a launcher key: it starts sessions from one bundle and does
    /// nothing else, whatever its role would allow.
    pub launch: Option<LaunchScope>,
}

impl Caller {
    pub fn actor(&self) -> &str {
        &self.principal.actor
    }

    /// A program calling for its own users, which it has already
    /// authorised; see [`Principal::service`].
    pub fn service(principal: Principal) -> Self {
        Self {
            principal,
            step_up_at: None,
            second_factor: false,
            launch: None,
        }
    }
}

#[derive(Clone)]
pub struct Stores {
    pub credentials: Arc<dyn CredentialStore>,
    pub policy: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditSink>,
    pub identity: Arc<dyn IdentityStore>,
    pub sso: Arc<dyn SsoStore>,
    pub audit_export: Arc<dyn AuditExportStore>,
    pub nodes: Arc<dyn NodeStore>,
    pub alerts: Arc<dyn AlertStore>,
    pub tripwires: Arc<dyn TripwireStore>,
}

/// Authorisation plus step-up enforcement, shared by every service.
#[derive(Clone)]
pub struct Guard {
    authorizer: Arc<dyn Authorizer>,
    step_up_window_secs: u64,
}

impl Guard {
    pub fn new(authorizer: Arc<dyn Authorizer>, step_up_window_secs: u64) -> Self {
        Self {
            authorizer,
            step_up_window_secs,
        }
    }

    pub async fn check(
        &self,
        caller: &Caller,
        action: Action,
        vault: Option<&VaultId>,
    ) -> Result<(), ControlError> {
        if let Some(scope) = &caller.launch {
            if !matches!(action, Action::VaultRead | Action::SessionMint) {
                return Err(ControlError::Forbidden {
                    reason: format!(
                        "{} is a launcher key: it only starts sessions from access bundle {}, so it may not '{action}'",
                        caller.actor(),
                        scope.bundle_id
                    ),
                });
            }
        }
        if let Decision::Deny { reason } = self
            .authorizer
            .authorize(&caller.principal, action, vault)
            .await
        {
            return Err(ControlError::Forbidden { reason });
        }
        if action.requires_step_up() {
            self.require_step_up(caller, action)?;
        }
        Ok(())
    }

    /// People with a second factor prove it again before sensitive
    /// actions; API keys may not take them at all. A service is exempt: the
    /// program that embeds the services authenticates its own users.
    pub fn require_step_up(&self, caller: &Caller, action: Action) -> Result<(), ControlError> {
        match caller.principal.kind {
            PrincipalKind::User => {}
            PrincipalKind::Service => return Ok(()),
            PrincipalKind::ApiKey => {
                return Err(ControlError::Forbidden {
                    reason: format!(
                        "'{action}' needs a person with a second factor; {} is an API key",
                        caller.actor()
                    ),
                });
            }
        }
        if !caller.second_factor {
            return Ok(());
        }
        let window =
            chrono::Duration::seconds(i64::try_from(self.step_up_window_secs).unwrap_or(300));
        let fresh = caller
            .step_up_at
            .is_some_and(|at| Utc::now().signed_duration_since(at) <= window);
        if fresh {
            Ok(())
        } else {
            Err(ControlError::StepUpRequired {
                action: action.to_string(),
                window_secs: self.step_up_window_secs,
            })
        }
    }
}

/// Writes audit events that describe no stored change: denials and
/// validation requests. Events for a change are handed to the store method
/// that makes it and committed with it. A failed write here is logged at
/// error level.
#[derive(Clone)]
pub struct AuditRecorder {
    sink: Arc<dyn AuditSink>,
}

impl AuditRecorder {
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    pub async fn record(&self, event: AuditEvent) {
        if let Err(e) = self.sink.record(std::slice::from_ref(&event)).await {
            error!(
                action = %event.action,
                actor = %event.actor,
                target = ?event.target,
                error = %e,
                "failed to write audit event"
            );
        }
    }
}

/// The stores [`ControlServices`] needs: everything but accounts.
#[derive(Clone)]
pub struct ServiceStores {
    pub credentials: Arc<dyn CredentialStore>,
    pub policy: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditSink>,
    pub nodes: Arc<dyn NodeStore>,
    pub alerts: Arc<dyn AlertStore>,
    pub tripwires: Arc<dyn TripwireStore>,
}

/// The control services without accounts, sign-in or API keys, for a
/// program that embeds them: it authenticates its own users, decides what
/// they may do through its [`Authorizer`], and calls these services as a
/// [`Caller::service`]. It needs no [`IdentityStore`].
pub struct ControlServices {
    pub policy: policy::PolicyService,
    pub sessions: sessions::SessionService,
    pub bundles: bundles::BundleService,
    pub nodes: nodes::NodeService,
    pub variables: variables::VariableService,
    pub audit: audit::AuditService,
    pub alerts: Arc<alerts::AlertService>,
    pub tripwires: tripwires::TripwireService,
    pub keys: Arc<KeyRing>,
    pub notifier: Arc<PolicyNotifier>,
}

impl ControlServices {
    pub async fn new(
        stores: ServiceStores,
        authorizer: Arc<dyn Authorizer>,
        cipher: Arc<dyn SecretCipher>,
        prober: Arc<dyn CredentialProber>,
        config: ControlConfig,
    ) -> Result<Self, ControlError> {
        let keys = Arc::new(KeyRing::load_or_create(stores.nodes.as_ref(), cipher.as_ref()).await?);
        let guard = Guard::new(authorizer, config.step_up_window_secs);
        Self::wire(stores, guard, cipher, prober, config, keys).await
    }

    async fn wire(
        stores: ServiceStores,
        guard: Guard,
        cipher: Arc<dyn SecretCipher>,
        prober: Arc<dyn CredentialProber>,
        config: ControlConfig,
        keys: Arc<KeyRing>,
    ) -> Result<Self, ControlError> {
        let notifier = Arc::new(PolicyNotifier::new());
        let recorder = AuditRecorder::new(stores.audit.clone());
        let policy = policy::PolicyService::new(
            stores.policy.clone(),
            stores.credentials.clone(),
            cipher.clone(),
            guard.clone(),
            recorder.clone(),
            notifier.clone(),
            prober,
        );
        policy.seed_builtin_templates().await?;
        let variables = variables::VariableService::new(
            stores.credentials.clone(),
            stores.policy.clone(),
            cipher.clone(),
            guard.clone(),
            notifier.clone(),
        );
        let bundles =
            bundles::BundleService::new(stores.policy.clone(), guard.clone(), notifier.clone());
        let sessions = sessions::SessionService::new(
            stores.policy.clone(),
            stores.credentials.clone(),
            stores.nodes.clone(),
            keys.clone(),
            guard.clone(),
            notifier.clone(),
        );
        let alerts = Arc::new(alerts::AlertService::new(
            stores.alerts,
            stores.policy.clone(),
            guard.clone(),
        ));
        let nodes = nodes::NodeService::new(
            stores.nodes.clone(),
            stores.policy.clone(),
            stores.credentials.clone(),
            stores.audit.clone(),
            cipher,
            keys.clone(),
            guard.clone(),
            recorder,
            notifier.clone(),
            alerts.clone(),
            stores.tripwires.clone(),
            config,
        );
        let tripwires = tripwires::TripwireService::new(
            stores.tripwires,
            stores.policy.clone(),
            guard.clone(),
            notifier.clone(),
        );
        let audit = audit::AuditService::new(stores.audit, guard);
        Ok(Self {
            policy,
            sessions,
            bundles,
            nodes,
            variables,
            audit,
            alerts,
            tripwires,
            keys,
            notifier,
        })
    }
}

/// Everything the HTTP layer needs, wired once at startup.
pub struct ControlPlane {
    pub auth: auth::AuthService,
    pub launcher_keys: launcher_keys::LauncherKeyService,
    pub sso: sso::SsoService,
    pub audit_export: audit_export::AuditExportService,
    pub policy: policy::PolicyService,
    pub sessions: sessions::SessionService,
    pub bundles: bundles::BundleService,
    pub nodes: nodes::NodeService,
    pub users: users::UserService,
    pub variables: variables::VariableService,
    pub audit: audit::AuditService,
    pub alerts: Arc<alerts::AlertService>,
    pub tripwires: tripwires::TripwireService,
    pub keys: Arc<KeyRing>,
    pub notifier: Arc<PolicyNotifier>,
}

impl ControlPlane {
    pub async fn new(
        stores: Stores,
        authorizer: Arc<dyn Authorizer>,
        cipher: Arc<dyn SecretCipher>,
        prober: Arc<dyn CredentialProber>,
        oidc: Arc<dyn sso::oidc::OidcTransport>,
        webhooks: Arc<dyn audit_export::WebhookTransport>,
        config: ControlConfig,
    ) -> Result<Self, ControlError> {
        let keys = Arc::new(KeyRing::load_or_create(stores.nodes.as_ref(), cipher.as_ref()).await?);
        let guard = Guard::new(authorizer, config.step_up_window_secs);
        let users = users::UserService::new(
            stores.identity.clone(),
            stores.sso.clone(),
            cipher.clone(),
            guard.clone(),
        );
        let sso = sso::SsoService::new(
            stores.identity.clone(),
            stores.sso.clone(),
            cipher.clone(),
            keys.clone(),
            guard.clone(),
            AuditRecorder::new(stores.audit.clone()),
            config.clone(),
            oidc,
        )?;
        let audit_export = audit_export::AuditExportService::new(
            stores.audit_export.clone(),
            stores.policy.clone(),
            cipher.clone(),
            guard.clone(),
            AuditRecorder::new(stores.audit.clone()),
            webhooks,
        );
        let auth = auth::AuthService::new(
            stores.identity.clone(),
            stores.sso.clone(),
            cipher.clone(),
            keys.clone(),
            guard.clone(),
            AuditRecorder::new(stores.audit.clone()),
            config.clone(),
        )?;
        let (identity, policy, nodes, launcher_guard) = (
            stores.identity.clone(),
            stores.policy.clone(),
            stores.nodes.clone(),
            guard.clone(),
        );
        let services = ControlServices::wire(
            ServiceStores {
                credentials: stores.credentials,
                policy: stores.policy,
                audit: stores.audit,
                nodes: stores.nodes,
                alerts: stores.alerts,
                tripwires: stores.tripwires,
            },
            guard,
            cipher,
            prober,
            config,
            keys,
        )
        .await?;
        let launcher_keys = launcher_keys::LauncherKeyService::new(
            identity.clone(),
            policy,
            nodes,
            launcher_guard,
            services.notifier.clone(),
        );
        Ok(Self {
            auth,
            launcher_keys,
            sso,
            audit_export,
            policy: services.policy,
            sessions: services.sessions.with_identity(identity),
            bundles: services.bundles,
            nodes: services.nodes,
            users,
            variables: services.variables,
            audit: services.audit,
            alerts: services.alerts,
            tripwires: services.tripwires,
            keys: services.keys,
            notifier: services.notifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rand::rngs::OsRng;
    use tokenless_auth::totp;
    use tokenless_core::authz::Role;
    use tokenless_core::injection::InjectedHeaders;
    use tokenless_core::protocol::{AuditBatch, EnrollRequest};
    use tokenless_core::seal::{encode_public_key, open, SealPublicKey, SealSecretKey};
    use tokenless_core::snapshot::{decode_verifying_key, rule_aad};

    use super::auth::{
        ChangePassword, CreateApiKey, DisableAuthenticator, EnableAuthenticator, LoginRequest,
        SessionAuth,
    };
    use super::policy::{CreateCredential, CreateRule, UpdateRule};
    use super::sessions::MintSession;
    use super::*;
    use crate::cipher::AesGcmCipher;
    use crate::envelope::Envelope;
    use crate::memory::MemoryStore;
    use crate::model::{PageRequest, SessionListing};
    use crate::store::RbacAuthorizer;
    use crate::store::{CiphertextOwner, NodeStore};
    use crate::StoreError;

    async fn plane() -> ControlPlane {
        plane_with(Arc::new(crate::probe::DisabledProber)).await
    }

    fn stores(store: &Arc<MemoryStore>) -> Stores {
        Stores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            identity: store.clone(),
            sso: store.clone(),
            audit_export: store.clone(),
            nodes: store.clone(),
            alerts: store.clone(),
            tripwires: store.clone(),
        }
    }

    async fn plane_with(prober: Arc<dyn CredentialProber>) -> ControlPlane {
        let store = Arc::new(MemoryStore::new());
        let cipher = Arc::new(
            Envelope::open(&AesGcmCipher::generate_key(), store.clone())
                .await
                .unwrap(),
        );
        ControlPlane::new(
            stores(&store),
            Arc::new(RbacAuthorizer),
            cipher,
            prober,
            Arc::new(sso::oidc::NoTransport),
            Arc::new(audit_export::DisabledWebhookTransport),
            ControlConfig::default(),
        )
        .await
        .unwrap()
    }

    fn admin(step_up_age_secs: i64) -> Caller {
        Caller {
            principal: Principal {
                kind: PrincipalKind::User,
                actor: "user:test-admin".into(),
                role: Role::Admin,
                vault: None,
            },
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(step_up_age_secs)),
            second_factor: true,
            launch: None,
        }
    }

    fn now_secs() -> u64 {
        u64::try_from(Utc::now().timestamp()).unwrap()
    }

    fn bearer(fields: &[(&str, &str)], hosts: &[&str]) -> CreateCredential {
        CreateCredential {
            name: "api".into(),
            template_id: "generic-bearer".into(),
            template_version: None,
            host_override: hosts.iter().map(|h| h.to_string()).collect(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            custom_headers: vec![],
            substitutions: vec![],
            not_after: None,
        }
    }

    /// Creates the first admin, signs it in, and returns the session, the
    /// generated password and the session token.
    async fn first_admin(cp: &ControlPlane) -> (SessionAuth, String, String) {
        let creds = cp.auth.create_initial_admin().await.unwrap().unwrap();
        let password = creds.password.to_string();
        let outcome = cp
            .auth
            .login(LoginRequest {
                username: creds.username.clone(),
                password: password.clone(),
                totp_code: None,
            })
            .await
            .unwrap();
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();
        (auth, password, outcome.token)
    }

    /// Turns on an authenticator for `auth` and returns its secret. The
    /// current time step is spent by the enrolment.
    async fn add_authenticator(cp: &ControlPlane, auth: &SessionAuth, password: &str) -> String {
        let enrol = cp.auth.new_totp_enrollment(&auth.user.username).unwrap();
        let summary = cp
            .auth
            .enable_authenticator(
                auth,
                &EnableAuthenticator {
                    secret: enrol.secret.clone(),
                    code: totp::code_at(&enrol.secret, now_secs()).unwrap(),
                    password: password.into(),
                },
            )
            .await
            .unwrap();
        assert!(summary.totp_enrolled);
        enrol.secret
    }

    fn login(username: &str, password: &str, code: Option<String>) -> LoginRequest {
        LoginRequest {
            username: username.into(),
            password: password.into(),
            totp_code: code,
        }
    }

    #[tokio::test]
    async fn secrets_stored_before_the_key_hierarchy_are_re_encrypted_under_it() {
        let store = Arc::new(MemoryStore::new());
        let root = AesGcmCipher::generate_key();
        // As stored before: every secret directly under the one key file.
        let old = ControlPlane::new(
            stores(&store),
            Arc::new(RbacAuthorizer),
            Arc::new(AesGcmCipher::new(&root).unwrap()),
            Arc::new(crate::probe::DisabledProber),
            Arc::new(sso::oidc::NoTransport),
            Arc::new(audit_export::DisabledWebhookTransport),
            ControlConfig::default(),
        )
        .await
        .unwrap();
        let (auth, password, _) = first_admin(&old).await;
        let secret = add_authenticator(&old, &auth, &password).await;
        let vault = old.policy.create_vault(&admin(0), "main").await.unwrap();
        let credential = old
            .policy
            .create_credential(
                &admin(0),
                &vault.id,
                bearer(&[("token", "legacy-token")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let before = store.list_ciphertexts().await.unwrap();
        assert!(before.iter().all(|c| c.ciphertext[0] == 1));

        // A different key is refused before anything is written under it.
        let wrong = Envelope::open(&AesGcmCipher::generate_key(), store.clone()).await;
        assert!(matches!(wrong, Err(ControlError::Crypto { .. })));
        assert!(store
            .get_key_material("envelope/instance-key")
            .await
            .unwrap()
            .is_none());

        let envelope = Arc::new(Envelope::open(&root, store.clone()).await.unwrap());
        for stored in store.list_ciphertexts().await.unwrap() {
            let hierarchy = matches!(&stored.owner,
                CiphertextOwner::KeyMaterial { name } if name.starts_with("envelope/"));
            assert!(
                hierarchy || stored.ciphertext[0] == 2,
                "{:?} was not re-encrypted",
                stored.owner
            );
        }
        // Opening again finds nothing left to migrate.
        Envelope::open(&root, store.clone()).await.unwrap();

        // Everything still reads: the signing keys load, the authenticator
        // verifies, and the credential decrypts under its vault's key.
        let cp = ControlPlane::new(
            stores(&store),
            Arc::new(RbacAuthorizer),
            envelope.clone(),
            Arc::new(crate::probe::DisabledProber),
            Arc::new(sso::oidc::NoTransport),
            Arc::new(audit_export::DisabledWebhookTransport),
            ControlConfig::default(),
        )
        .await
        .unwrap();
        cp.auth
            .login(login(
                "admin",
                &password,
                Some(totp::code_at(&secret, now_secs() + 30).unwrap()),
            ))
            .await
            .unwrap();
        let ciphertext = store
            .load_secret_ciphertext(&credential.id)
            .await
            .unwrap()
            .unwrap();
        let plaintext = envelope
            .decrypt(
                &ciphertext,
                &policy::credential_aad(&credential.id, &vault.id),
            )
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&plaintext).contains("legacy-token"));
        let audit = cp
            .audit
            .query(&admin(0), None, None, PageRequest::default())
            .await
            .unwrap();
        assert!(audit.items.iter().any(|e| e.action == "keys.migrate"));
    }

    #[tokio::test]
    async fn built_in_templates_are_seeded_once() {
        let cp = plane().await;
        // `plane()` already seeded them on start; a second start adds none.
        assert_eq!(cp.policy.seed_builtin_templates().await.unwrap(), 0);
        assert!(!tokenless_core::template::builtin_templates()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn first_start_creates_the_admin_with_a_generated_password() {
        let cp = plane().await;
        let creds = cp.auth.create_initial_admin().await.unwrap().unwrap();
        assert_eq!(creds.username, "admin");
        assert!(!format!("{creds:?}").contains(creds.password.as_str()));
        // Only the first start creates it.
        assert!(cp.auth.create_initial_admin().await.unwrap().is_none());

        assert!(cp
            .auth
            .login(login("admin", "wrong password!!", None))
            .await
            .is_err());
        let outcome = cp
            .auth
            .login(login("admin", &creds.password, None))
            .await
            .unwrap();
        assert_eq!(outcome.user.role, Role::Admin);
        assert!(!outcome.user.totp_enrolled, "the authenticator is opt-in");
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();
        assert!(cp.auth.verify_csrf(&auth.token_hash, &outcome.csrf_token));
        assert!(!cp.auth.verify_csrf(&auth.token_hash, "forged"));
        cp.auth.logout(&auth).await.unwrap();
        assert!(cp.auth.authenticate_session(&outcome.token).await.is_err());
    }

    #[tokio::test]
    async fn an_authenticator_can_be_turned_on_and_off() {
        let cp = plane().await;
        let (auth, password, _) = first_admin(&cp).await;
        let enrol = cp.auth.new_totp_enrollment("admin").unwrap();
        let enable = |code: String, password: &str| EnableAuthenticator {
            secret: enrol.secret.clone(),
            code,
            password: password.into(),
        };
        assert!(matches!(
            cp.auth
                .enable_authenticator(&auth, &enable("000000".into(), &password))
                .await,
            Err(ControlError::Validation { .. })
        ));
        let code = totp::code_at(&enrol.secret, now_secs()).unwrap();
        assert!(matches!(
            cp.auth
                .enable_authenticator(&auth, &enable(code.clone(), "not the password"))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        cp.auth
            .enable_authenticator(&auth, &enable(code.clone(), &password))
            .await
            .unwrap();
        assert!(matches!(
            cp.auth
                .enable_authenticator(&auth, &enable(code.clone(), &password))
                .await,
            Err(ControlError::Conflict { .. })
        ));
        assert!(matches!(
            cp.auth.login(login("admin", &password, None)).await,
            Err(ControlError::SecondFactorRequired { .. })
        ));
        // The enrolment's code is spent: it cannot sign in again.
        assert!(cp
            .auth
            .login(login("admin", &password, Some(code)))
            .await
            .is_err());

        let disable = |code: String| DisableAuthenticator {
            code,
            password: password.clone(),
        };
        assert!(matches!(
            cp.auth
                .disable_authenticator(&auth, &disable("000000".into()))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        let off = cp
            .auth
            .disable_authenticator(
                &auth,
                &disable(totp::code_at(&enrol.secret, now_secs() + 30).unwrap()),
            )
            .await
            .unwrap();
        assert!(!off.totp_enrolled);
        assert!(matches!(
            cp.auth
                .disable_authenticator(&auth, &disable("123456".into()))
                .await,
            Err(ControlError::Conflict { .. })
        ));
        cp.auth
            .login(login("admin", &password, None))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_new_password_keeps_this_session_and_ends_the_others() {
        let cp = plane().await;
        let (auth, password, token) = first_admin(&cp).await;
        let other = cp
            .auth
            .login(login("admin", &password, None))
            .await
            .unwrap();
        let change = |current: &str, new: &str| ChangePassword {
            current_password: current.into(),
            new_password: new.into(),
        };
        assert!(matches!(
            cp.auth
                .change_password(&auth, &change("not the password", "a brand new password"))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        assert!(cp
            .auth
            .change_password(&auth, &change(&password, "short"))
            .await
            .is_err());
        assert!(matches!(
            cp.auth
                .change_password(&auth, &change(&password, &password))
                .await,
            Err(ControlError::Validation { .. })
        ));
        cp.auth
            .change_password(&auth, &change(&password, "a brand new password"))
            .await
            .unwrap();
        cp.auth
            .authenticate_session(&token)
            .await
            .expect("the session that changed it stays");
        assert!(
            cp.auth.authenticate_session(&other.token).await.is_err(),
            "other sessions end"
        );
        assert!(cp
            .auth
            .login(login("admin", &password, None))
            .await
            .is_err());
        cp.auth
            .login(login("admin", "a brand new password", None))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_reset_password_replaces_the_old_one_and_ends_every_session() {
        let cp = plane().await;
        let (_, password, token) = first_admin(&cp).await;
        assert!(matches!(
            cp.auth.reset_password("nobody").await,
            Err(ControlError::NotFound { ref id, .. }) if id == "nobody"
        ));
        let reset = cp.auth.reset_password(" Admin ").await.unwrap();
        assert_eq!(reset.username, "admin");
        assert_ne!(*reset.password, password);
        assert!(cp.auth.authenticate_session(&token).await.is_err());
        assert!(cp
            .auth
            .login(login("admin", &password, None))
            .await
            .is_err());
        cp.auth
            .login(login("admin", &reset.password, None))
            .await
            .unwrap();
    }

    /// The first admin with an authenticator, as a fresh-step-up caller.
    async fn setup_admin(cp: &ControlPlane) -> Caller {
        let (auth, password, _) = first_admin(cp).await;
        add_authenticator(cp, &auth, &password).await;
        Caller {
            step_up_at: Some(Utc::now()),
            second_factor: true,
            ..auth.caller
        }
    }

    #[tokio::test]
    async fn invited_people_get_the_offered_role_and_can_be_disabled() {
        use super::users::{AcceptInviteRequest, CreateInvite, UpdateUser};

        let cp = plane().await;
        let admin = setup_admin(&cp).await;
        let invite = |role| CreateInvite {
            role,
            expires_in_hours: None,
        };
        let stale = Caller {
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(3600)),
            ..admin.clone()
        };
        assert!(matches!(
            cp.users.create_invite(&stale, invite(Role::Editor)).await,
            Err(ControlError::StepUpRequired { .. })
        ));
        assert!(matches!(
            cp.users
                .create_invite(
                    &admin,
                    CreateInvite {
                        role: Role::Viewer,
                        expires_in_hours: Some(24 * 30),
                    }
                )
                .await,
            Err(ControlError::Validation { .. })
        ));

        let issued = cp
            .users
            .create_invite(&admin, invite(Role::Editor))
            .await
            .unwrap();
        assert!(issued.token.starts_with("cbinv_"));
        let info = cp.users.inspect_invite(&issued.token).await.unwrap();
        assert_eq!(info.role, Role::Editor);
        assert!(cp.users.inspect_invite("cbinv_unknown").await.is_err());

        let enrol = cp.users.invite_totp(&issued.token, "bob").await.unwrap();
        let accept = |code: String| AcceptInviteRequest {
            invite_token: issued.token.clone(),
            username: "bob".into(),
            password: "a different long password".into(),
            totp_secret: Some(enrol.secret.clone()),
            totp_code: Some(code),
        };
        assert!(matches!(
            cp.users.accept_invite(accept("000000".into())).await,
            Err(ControlError::Validation { .. })
        ));
        // The previous step is still accepted; using it leaves the current
        // and next steps for the logins below.
        let bob = cp
            .users
            .accept_invite(accept(
                totp::code_at(&enrol.secret, now_secs() - 30).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(bob.role, Role::Editor);
        assert!(matches!(
            cp.users
                .accept_invite(accept(totp::code_at(&enrol.secret, now_secs()).unwrap()))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));

        let login = |offset: u64| LoginRequest {
            username: "bob".into(),
            password: "a different long password".into(),
            totp_code: Some(totp::code_at(&enrol.secret, now_secs() + offset).unwrap()),
        };
        let session = cp.auth.login(login(0)).await.unwrap();
        let bob_caller = cp
            .auth
            .authenticate_session(&session.token)
            .await
            .unwrap()
            .caller;
        assert_eq!(bob_caller.principal.role, Role::Editor);
        assert!(matches!(
            cp.users
                .list_users(&bob_caller, PageRequest::default())
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        assert!(matches!(
            cp.users
                .create_invite(&bob_caller, invite(Role::Admin))
                .await,
            Err(ControlError::Forbidden { .. })
        ));

        let admin_id: tokenless_core::ids::UserId =
            admin.actor().trim_start_matches("user:").parse().unwrap();
        let disable = UpdateUser {
            role: None,
            disabled: Some(true),
        };
        assert!(matches!(
            cp.users
                .update_user(&admin, &admin_id, disable.clone())
                .await,
            Err(ControlError::Validation { .. })
        ));
        assert!(matches!(
            cp.users
                .update_user(
                    &admin,
                    &admin_id,
                    UpdateUser {
                        role: Some(Role::Viewer),
                        disabled: None,
                    }
                )
                .await,
            Err(ControlError::Conflict { .. })
        ));

        let updated = cp
            .users
            .update_user(&admin, &bob.id, disable)
            .await
            .unwrap();
        assert!(updated.disabled_at.is_some());
        assert!(cp.auth.authenticate_session(&session.token).await.is_err());
        // Refused before the TOTP code is checked, so the step stays unused.
        assert!(cp.auth.login(login(30)).await.is_err());
        cp.users
            .update_user(
                &admin,
                &bob.id,
                UpdateUser {
                    role: Some(Role::Viewer),
                    disabled: Some(false),
                },
            )
            .await
            .unwrap();
        let session = cp.auth.login(login(30)).await.unwrap();
        let auth = cp.auth.authenticate_session(&session.token).await.unwrap();
        assert_eq!(auth.user.role, Role::Viewer);

        let users = cp
            .users
            .list_users(&admin, PageRequest::default())
            .await
            .unwrap();
        assert_eq!(users.total, 2);
        let invites = cp
            .users
            .list_invites(&admin, PageRequest::default())
            .await
            .unwrap();
        assert_eq!(invites.items[0].accepted_by, Some(bob.id));

        let actions: Vec<String> = cp
            .audit
            .query(&admin, None, Some("user.".into()), PageRequest::default())
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|e| e.action)
            .collect();
        for expected in ["user.invite", "user.invite.accept", "user.update"] {
            assert!(
                actions.iter().any(|a| a == expected),
                "missing audit action {expected} in {actions:?}"
            );
        }
    }

    #[tokio::test]
    async fn revoked_invites_cannot_be_accepted() {
        use super::users::CreateInvite;

        let cp = plane().await;
        let admin = setup_admin(&cp).await;
        let issued = cp
            .users
            .create_invite(
                &admin,
                CreateInvite {
                    role: Role::Viewer,
                    expires_in_hours: Some(1),
                },
            )
            .await
            .unwrap();
        cp.users
            .revoke_invite(&admin, &issued.invite.id)
            .await
            .unwrap();
        assert!(matches!(
            cp.users.inspect_invite(&issued.token).await,
            Err(ControlError::Unauthenticated { .. })
        ));
        assert!(cp.users.invite_totp(&issued.token, "carol").await.is_err());
    }

    #[tokio::test]
    async fn password_only_accounts_sign_in_and_step_up_with_the_password() {
        use super::auth::StepUpProof;

        let cp = plane().await;
        let (_, password, _) = first_admin(&cp).await;
        let login = |password: &str| LoginRequest {
            username: "admin".into(),
            password: password.into(),
            totp_code: None,
        };
        assert!(cp.auth.login(login("not the password")).await.is_err());
        let outcome = cp.auth.login(login(&password)).await.unwrap();
        assert!(!outcome.user.totp_enrolled);
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();

        let proof = |code: Option<&str>, password: Option<&str>| StepUpProof {
            code: code.map(str::to_string),
            password: password.map(str::to_string),
        };
        assert!(cp
            .auth
            .step_up(&auth, &proof(None, Some("not the password")))
            .await
            .is_err());
        assert!(cp
            .auth
            .step_up(&auth, &proof(Some("123456"), None))
            .await
            .is_err());
        cp.auth
            .step_up(&auth, &proof(None, Some(&password)))
            .await
            .unwrap();

        // Sensitive actions are not gated on a step-up the account cannot
        // give with anything but the password it signed in with.
        assert!(!auth.caller.second_factor);
        let long_ago = Caller {
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(3600)),
            ..auth.caller.clone()
        };
        cp.users
            .create_invite(
                &long_ago,
                super::users::CreateInvite {
                    role: Role::Editor,
                    expires_in_hours: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enrolled_accounts_cannot_skip_the_code() {
        use super::auth::StepUpProof;

        let cp = plane().await;
        let (first, password, _) = first_admin(&cp).await;
        let secret = add_authenticator(&cp, &first, &password).await;
        let without_code = LoginRequest {
            username: "admin".into(),
            password: password.clone(),
            totp_code: None,
        };
        // The right password without a code asks for the code, as often as
        // it is tried, without using up the sign-in attempts.
        for _ in 0..6 {
            assert!(matches!(
                cp.auth.login(without_code.clone()).await,
                Err(ControlError::SecondFactorRequired { ref username }) if username == "admin"
            ));
        }
        // A wrong password never reveals that the account has an authenticator.
        assert!(matches!(
            cp.auth
                .login(LoginRequest {
                    password: "wrong horse battery".into(),
                    ..without_code.clone()
                })
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        assert!(matches!(
            cp.auth
                .login(LoginRequest {
                    totp_code: Some("000000".into()),
                    ..without_code.clone()
                })
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        let outcome = cp
            .auth
            .login(LoginRequest {
                totp_code: Some(totp::code_at(&secret, now_secs() + 30).unwrap()),
                ..without_code
            })
            .await
            .unwrap();
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();
        assert!(auth.caller.second_factor);
        let long_ago = Caller {
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(3600)),
            ..auth.caller.clone()
        };
        assert!(matches!(
            cp.users
                .create_invite(
                    &long_ago,
                    super::users::CreateInvite {
                        role: Role::Editor,
                        expires_in_hours: None,
                    },
                )
                .await,
            Err(ControlError::StepUpRequired { .. })
        ));
        // The password must not stand in for the second factor.
        assert!(cp
            .auth
            .step_up(
                &auth,
                &StepUpProof {
                    code: None,
                    password: Some(password),
                }
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn login_is_rate_limited() {
        let cp = plane().await;
        for _ in 0..5 {
            let _ = cp
                .auth
                .login(LoginRequest {
                    username: "nobody".into(),
                    password: "whatever-password".into(),
                    totp_code: Some("123456".into()),
                })
                .await;
        }
        let res = cp
            .auth
            .login(LoginRequest {
                username: "nobody".into(),
                password: "whatever-password".into(),
                totp_code: Some("123456".into()),
            })
            .await;
        assert!(matches!(res, Err(ControlError::RateLimited { .. })));
    }

    #[tokio::test]
    async fn admins_see_proxies_and_api_keys_without_a_fresh_step_up() {
        // The console polls the proxy list on every page; an admin who
        // signed in a while ago must not be asked to confirm just to look.
        let cp = plane().await;
        let stale = admin(3600);
        let page = || PageRequest::new(Some(1), Some(20));
        cp.nodes.list_nodes(&stale, page()).await.unwrap();
        cp.auth.list_api_keys(&stale, page()).await.unwrap();
        let missing = tokenless_core::ids::NodeId::new();
        assert!(matches!(
            cp.nodes.get_node(&stale, &missing).await,
            Err(ControlError::NotFound { .. })
        ));
        // Changing them still needs one.
        assert!(matches!(
            cp.nodes.revoke_node(&stale, &missing).await,
            Err(ControlError::StepUpRequired { .. })
        ));
        assert!(matches!(
            cp.auth
                .revoke_api_key(&stale, &tokenless_core::ids::ApiKeyId::new())
                .await,
            Err(ControlError::StepUpRequired { .. })
        ));
    }

    #[tokio::test]
    async fn credential_writes_need_fresh_step_up_and_stay_write_only() {
        let cp = plane().await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let stale = admin(3600);
        let res = cp
            .policy
            .create_credential(
                &stale,
                &vault.id,
                bearer(&[("token", "s3cr3t-value")], &["api.example.com"]),
            )
            .await;
        assert!(matches!(res, Err(ControlError::StepUpRequired { .. })));

        let meta = cp
            .policy
            .create_credential(
                &admin(0),
                &vault.id,
                bearer(&[("token", "s3cr3t-value")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let listed = cp
            .policy
            .list_credentials(&admin(0), &vault.id, PageRequest::default())
            .await
            .unwrap();
        for json in [
            serde_json::to_string(&meta).unwrap(),
            serde_json::to_string(&listed).unwrap(),
        ] {
            assert!(!json.contains("s3cr3t-value"));
        }
        let audit = cp
            .audit
            .query(&admin(0), None, None, PageRequest::default())
            .await
            .unwrap();
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .contains("s3cr3t-value"));
        assert!(audit.items.iter().any(|e| e.action == "credential.create"
            && e.detail.get("widened").map(String::as_str) == Some("true")));
    }

    #[tokio::test]
    async fn duplicate_service_name_is_a_readable_conflict() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let req = bearer(&[("token", "t")], &["api.example.com"]);
        cp.policy
            .create_credential(&a, &vault.id, req.clone())
            .await
            .unwrap();
        match cp.policy.create_credential(&a, &vault.id, req).await {
            Err(ControlError::Conflict { message }) => assert_eq!(
                message,
                "a service named 'api' already exists in vault 'main'; choose another name"
            ),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn templates_cap_scope() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let mut github = bearer(&[("token", "t")], &["api.example.com"]);
        github.template_id = "github".into();
        assert!(matches!(
            cp.policy
                .create_credential(&a, &vault.id, github.clone())
                .await,
            Err(ControlError::Core(
                tokenless_core::CoreError::Widening { .. }
            ))
        ));
        github.host_override.clear();
        let cred = cp
            .policy
            .create_credential(&a, &vault.id, github)
            .await
            .unwrap();
        let rule = |hosts: Option<Vec<String>>, paths: Option<Vec<String>>| CreateRule {
            name: "r".into(),
            credential_id: cred.id,
            hosts,
            paths,
            methods: Some(vec!["GET".into()]),
            mcp_tools: None,
            git: None,
        };
        assert!(cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                rule(Some(vec!["evil.example.com".into()]), None)
            )
            .await
            .is_err());
        let created = cp
            .policy
            .create_rule(&a, &vault.id, rule(None, Some(vec!["/repos/*".into()])))
            .await
            .unwrap();
        assert_eq!(created.allow.hosts[0].host(), "api.github.com");

        let stale = admin(3600);
        let narrowed = cp
            .policy
            .update_rule(
                &stale,
                &created.id,
                UpdateRule {
                    paths: Some(vec!["/repos/a/*".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(narrowed.allow.paths[0].as_str(), "/repos/a/*");
        let widen = cp
            .policy
            .update_rule(
                &stale,
                &created.id,
                UpdateRule {
                    paths: Some(vec!["/*".into()]),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(widen, Err(ControlError::StepUpRequired { .. })));
        assert!(matches!(
            cp.policy.delete_credential(&a, &cred.id).await,
            Err(ControlError::Conflict { .. })
        ));
    }

    #[tokio::test]
    async fn git_scopes_are_normalised_and_widening_them_needs_step_up() {
        use tokenless_core::git::GitScope;

        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["git.example.com"]),
            )
            .await
            .unwrap();
        let git = |repositories: &[&str], push| GitScope {
            repositories: repositories.iter().map(|r| r.to_string()).collect(),
            push,
        };
        let rule = |scope| CreateRule {
            name: "clone".into(),
            credential_id: cred.id,
            hosts: None,
            paths: None,
            methods: None,
            mcp_tools: None,
            git: Some(scope),
        };
        assert!(matches!(
            cp.policy
                .create_rule(&a, &vault.id, rule(git(&["acme/../widgets"], false)))
                .await,
            Err(ControlError::Core(
                tokenless_core::CoreError::InvalidGitScope { .. }
            ))
        ));
        let created = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                rule(git(&[" /Acme/Widgets.git", "acme/other"], false)),
            )
            .await
            .unwrap();
        assert_eq!(
            created.allow.git,
            Some(git(&["acme/other", "acme/widgets"], false))
        );

        let stale = admin(3600);
        let update = |git: Option<GitScope>, remove_git| UpdateRule {
            git,
            remove_git,
            ..Default::default()
        };
        // Fewer repositories narrow; pushing, another repository or no Git
        // scope at all widen.
        let narrowed = cp
            .policy
            .update_rule(
                &stale,
                &created.id,
                update(Some(git(&["acme/widgets"], false)), false),
            )
            .await
            .unwrap();
        assert_eq!(narrowed.allow.git, Some(git(&["acme/widgets"], false)));
        for widen in [
            update(Some(git(&["acme/widgets"], true)), false),
            update(Some(git(&["acme/widgets", "acme/third"], false)), false),
            update(None, true),
        ] {
            assert!(matches!(
                cp.policy.update_rule(&stale, &created.id, widen).await,
                Err(ControlError::StepUpRequired { .. })
            ));
        }
        assert!(matches!(
            cp.policy
                .update_rule(
                    &a,
                    &created.id,
                    update(Some(git(&["acme/widgets"], true)), true)
                )
                .await,
            Err(ControlError::Validation { .. })
        ));
        let removed = cp
            .policy
            .update_rule(&a, &created.id, update(None, true))
            .await
            .unwrap();
        assert_eq!(removed.allow.git, None);
    }

    #[tokio::test]
    async fn sessions_mint_from_an_access_bundle_by_name() {
        use crate::service::bundles::{CreateBundle, UpdateBundle};

        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let other = cp.policy.create_vault(&a, "other").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let mut rules = Vec::new();
        for name in ["read", "write"] {
            let rule = cp
                .policy
                .create_rule(
                    &a,
                    &vault.id,
                    CreateRule {
                        name: name.into(),
                        credential_id: cred.id,
                        hosts: None,
                        paths: None,
                        methods: None,
                        mcp_tools: None,
                        git: None,
                    },
                )
                .await
                .unwrap();
            rules.push(rule);
        }
        let bundle = cp
            .bundles
            .create(
                &a,
                &vault.id,
                CreateBundle {
                    request_limit: None,
                    name: "code-review".into(),
                    description: "GitHub for reviews".into(),
                    rule_ids: vec![rules[1].id, rules[0].id, rules[0].id],
                },
            )
            .await
            .unwrap();
        let mut expected = vec![rules[0].id, rules[1].id];
        expected.sort();
        assert_eq!(bundle.rule_ids, expected, "sorted and deduplicated");

        // An editor key mints by name.
        let (plaintext, _) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "launcher".into(),
                    vault_id: vault.id,
                    role: Role::Editor,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        let key = cp.auth.authenticate_api_key(&plaintext).await.unwrap();
        let by_bundle = |bundle: &str| MintSession {
            rule_ids: vec![],
            bundle: Some(bundle.into()),
            ttl_secs: Some(600),
            longest: false,
            request_limit: None,
            labels: BTreeMap::new(),
            node_id: None,
            binding: None,
            not_after: None,
            rule_not_after: Default::default(),
            strict: false,
            renews: None,
        };
        let minted = cp
            .sessions
            .mint(&key, &vault.id, by_bundle("code-review"))
            .await
            .unwrap();
        assert_eq!(minted.session.rule_ids, expected);
        let reference = minted.session.bundle.clone().unwrap();
        assert_eq!(
            (reference.id, reference.name.as_str()),
            (bundle.id, "code-review")
        );
        // By id works too.
        cp.sessions
            .mint(&key, &vault.id, by_bundle(&bundle.id.to_string()))
            .await
            .unwrap();

        // The bundle's page lists only the sessions minted from it.
        cp.sessions
            .mint(
                &a,
                &vault.id,
                MintSession {
                    rule_ids: vec![rules[0].id],
                    bundle: None,
                    ttl_secs: Some(600),
                    longest: false,
                    request_limit: None,
                    labels: BTreeMap::new(),
                    node_id: None,
                    binding: None,
                    not_after: None,
                    rule_not_after: Default::default(),
                    strict: false,
                    renews: None,
                },
            )
            .await
            .unwrap();
        let listed = cp
            .sessions
            .list_for_bundle(
                &a,
                &bundle.id,
                SessionListing::default(),
                PageRequest::new(None, None),
            )
            .await
            .unwrap();
        assert_eq!(
            listed.total, 2,
            "the rule-minted session is not the bundle's"
        );
        assert!(listed
            .items
            .iter()
            .all(|s| s.bundle.as_ref().map(|b| b.id) == Some(bundle.id)));
        let missing = tokenless_core::ids::BundleId::new();
        let err = cp
            .sessions
            .list_for_bundle(
                &a,
                &missing,
                SessionListing::default(),
                PageRequest::new(None, None),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ControlError::NotFound { .. })
                && err.to_string().contains(&missing.to_string()),
            "{err}"
        );

        // Disabled rules are skipped, and a bundle with none left refuses.
        for (i, rule) in rules.iter().enumerate() {
            cp.policy
                .update_rule(
                    &a,
                    &rule.id,
                    UpdateRule {
                        enabled: Some(false),
                        ..UpdateRule::default()
                    },
                )
                .await
                .unwrap();
            let result = cp
                .sessions
                .mint(&key, &vault.id, by_bundle("code-review"))
                .await;
            if i == 0 {
                assert_eq!(result.unwrap().session.rule_ids, vec![rules[1].id]);
            } else {
                let err = result.unwrap_err().to_string();
                assert!(err.contains("has no enabled rules"), "{err}");
            }
        }

        let both = MintSession {
            rule_ids: vec![rules[0].id],
            ..by_bundle("code-review")
        };
        assert!(matches!(
            cp.sessions.mint(&a, &vault.id, both).await,
            Err(ControlError::Validation { .. })
        ));
        let err = cp
            .sessions
            .mint(&a, &vault.id, by_bundle("missing"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("'missing' in vault"), "{err}");
        // A bundle id from another vault is not found there.
        assert!(matches!(
            cp.sessions
                .mint(&a, &other.id, by_bundle(&bundle.id.to_string()))
                .await,
            Err(ControlError::NotFound { .. })
        ));

        // Only editors and admins manage bundles.
        let (viewer_key, _) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "dashboard".into(),
                    vault_id: vault.id,
                    role: Role::Viewer,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        let viewer = cp.auth.authenticate_api_key(&viewer_key).await.unwrap();
        // Whoever may mint learns the lifetimes; a viewer does not.
        assert_eq!(
            cp.sessions.limits(&key, &vault.id).await.unwrap(),
            sessions::SessionLimits {
                max_ttl_secs: tokenless_core::session::DEFAULT_MAX_SESSION_TTL_SECS,
                default_ttl_secs: tokenless_core::session::DEFAULT_SESSION_TTL_SECS,
            }
        );
        assert!(matches!(
            cp.sessions.limits(&viewer, &vault.id).await,
            Err(ControlError::Forbidden { .. })
        ));
        // A session's record is readable in its vault, and only there.
        assert_eq!(
            cp.sessions
                .get(&viewer, &minted.session.id)
                .await
                .unwrap()
                .id,
            minted.session.id
        );
        assert!(matches!(
            cp.sessions
                .get(&viewer, &tokenless_core::ids::SessionId::new())
                .await,
            Err(ControlError::NotFound { .. })
        ));
        let (outsider_key, _) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "outsider".into(),
                    vault_id: other.id,
                    role: Role::Viewer,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        let outsider = cp.auth.authenticate_api_key(&outsider_key).await.unwrap();
        assert!(matches!(
            cp.sessions.get(&outsider, &minted.session.id).await,
            Err(ControlError::Forbidden { .. })
        ));
        // So is what it reaches, in the session's rule order.
        let reached: Vec<_> = cp
            .sessions
            .services(&viewer, &minted.session.id)
            .await
            .unwrap()
            .iter()
            .map(|s| s.rule_id)
            .collect();
        assert_eq!(reached, minted.session.rule_ids);
        assert!(matches!(
            cp.sessions.services(&outsider, &minted.session.id).await,
            Err(ControlError::Forbidden { .. })
        ));
        assert!(matches!(
            cp.bundles
                .create(
                    &viewer,
                    &vault.id,
                    CreateBundle {
                        request_limit: None,
                        name: "mine".into(),
                        description: String::new(),
                        rule_ids: vec![],
                    },
                )
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        // Rules from another vault cannot be bundled.
        let foreign = cp
            .bundles
            .create(
                &a,
                &other.id,
                CreateBundle {
                    request_limit: None,
                    name: "x".into(),
                    description: String::new(),
                    rule_ids: vec![rules[0].id],
                },
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(foreign.contains("belongs to vault"), "{foreign}");
        // Names are unique per vault.
        assert!(matches!(
            cp.bundles
                .create(
                    &a,
                    &vault.id,
                    CreateBundle {
                        request_limit: None,
                        name: "code-review".into(),
                        description: String::new(),
                        rule_ids: vec![],
                    },
                )
                .await,
            Err(ControlError::Store(StoreError::Conflict { .. }))
        ));
        // People see every vault's bundles in one list; a key sees only
        // its own vault's.
        cp.bundles
            .create(
                &a,
                &other.id,
                CreateBundle {
                    request_limit: None,
                    name: "other-job".into(),
                    description: String::new(),
                    rule_ids: vec![],
                },
            )
            .await
            .unwrap();
        let every = cp
            .bundles
            .list_all(&a, PageRequest::new(None, None))
            .await
            .unwrap();
        let mut vaults: Vec<_> = every
            .items
            .iter()
            .map(|b| (b.name.as_str(), b.vault_id))
            .collect();
        vaults.sort_by_key(|(name, _)| *name);
        assert_eq!(
            vaults,
            vec![("code-review", vault.id), ("other-job", other.id)]
        );
        let scoped = cp
            .bundles
            .list_all(&key, PageRequest::new(None, None))
            .await
            .unwrap();
        assert!(
            scoped.items.iter().all(|b| b.vault_id == vault.id) && scoped.total == 1,
            "{scoped:?}"
        );

        // Deleting a rule takes it out of the bundle.
        cp.policy.delete_rule(&a, &rules[0].id).await.unwrap();
        let after = cp.bundles.get(&a, &bundle.id).await.unwrap();
        assert_eq!(after.rule_ids, vec![rules[1].id]);
        let renamed = cp
            .bundles
            .update(
                &a,
                &bundle.id,
                UpdateBundle {
                    name: Some("review".into()),
                    ..UpdateBundle::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(renamed.rule_ids, vec![rules[1].id]);
        // Deleting the bundle ends the sessions minted from it.
        let deleted = cp.bundles.delete(&a, &bundle.id).await.unwrap();
        assert!(deleted.sessions_revoked >= 2, "{deleted:?}");
        let ended = cp
            .sessions
            .list(
                &a,
                &vault.id,
                SessionListing::default(),
                PageRequest::new(None, None),
            )
            .await
            .unwrap();
        let first = ended
            .items
            .iter()
            .find(|s| s.id == minted.session.id)
            .unwrap();
        assert!(first.revoked_at.is_some());
        assert!(cp
            .bundles
            .list(&a, &vault.id, PageRequest::new(None, None))
            .await
            .unwrap()
            .items
            .is_empty());
    }

    #[tokio::test]
    async fn api_keys_are_vault_bound_and_cannot_step_up() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let other = cp.policy.create_vault(&a, "other").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let (plaintext, record) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "ci".into(),
                    vault_id: vault.id,
                    role: Role::Editor,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        assert!(plaintext.starts_with(&record.prefix));
        assert!(!serde_json::to_string(&record).unwrap().contains(&plaintext));
        let key = cp.auth.authenticate_api_key(&plaintext).await.unwrap();
        let minted = cp
            .sessions
            .mint(
                &key,
                &vault.id,
                MintSession {
                    rule_ids: vec![rule.id],
                    bundle: None,
                    ttl_secs: None,
                    longest: false,
                    request_limit: None,
                    labels: BTreeMap::new(),
                    node_id: None,
                    binding: None,
                    not_after: None,
                    rule_not_after: Default::default(),
                    strict: false,
                    renews: None,
                },
            )
            .await
            .unwrap();
        assert!(minted.token.starts_with("v4.public."));
        assert!(matches!(
            cp.sessions
                .mint(
                    &key,
                    &other.id,
                    MintSession {
                        rule_ids: vec![rule.id],
                        bundle: None,
                        ttl_secs: None,
                        longest: false,
                        request_limit: None,
                        labels: BTreeMap::new(),
                        node_id: None,
                        binding: None,
                        not_after: None,
                        rule_not_after: Default::default(),
                        strict: false,
                        renews: None,
                    },
                )
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        assert!(matches!(
            cp.policy
                .create_credential(&key, &vault.id, bearer(&[("token", "t")], &[]))
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        cp.auth.revoke_api_key(&a, &record.id).await.unwrap();
        assert!(cp.auth.authenticate_api_key(&plaintext).await.is_err());
    }

    #[tokio::test]
    async fn enrolment_and_sealed_snapshot() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "injected-secret")], &["localhost:8443"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let join = cp.nodes.create_join_token(&a, None).await.unwrap();
        let tls_key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&tls_key)
            .unwrap()
            .pem()
            .unwrap();
        let seal_secret = SealSecretKey::random_from_rng(OsRng);
        let request = EnrollRequest {
            join_token: join.token.clone(),
            node_name: "node-a".into(),
            csr_pem: csr,
            seal_public_key: encode_public_key(&SealPublicKey::from(&seal_secret)),
        };
        let enrolled = cp.nodes.enroll(request.clone()).await.unwrap();
        assert!(matches!(
            cp.nodes.enroll(request).await,
            Err(ControlError::Unauthenticated { .. })
        ));
        let node = cp.nodes.authenticate(&enrolled.node_id).await.unwrap();
        // The proxy's detail page reads it by ID; admins only.
        let fetched = cp.nodes.get_node(&a, &enrolled.node_id).await.unwrap();
        assert_eq!(fetched.name, "node-a");
        let missing = tokenless_core::ids::NodeId::new();
        let err = cp.nodes.get_node(&a, &missing).await.unwrap_err();
        assert!(
            matches!(err, ControlError::NotFound { .. })
                && err.to_string().contains(&missing.to_string()),
            "{err}"
        );
        let mut viewer = a.clone();
        viewer.principal.role = Role::Viewer;
        assert!(matches!(
            cp.nodes.get_node(&viewer, &enrolled.node_id).await,
            Err(ControlError::Forbidden { .. })
        ));
        let verify = decode_verifying_key(&enrolled.snapshot_verify_key).unwrap();

        let first = cp
            .nodes
            .build_snapshot(&node)
            .await
            .unwrap()
            .verify(&verify)
            .unwrap();
        assert_eq!(first.rules.len(), 1);
        let sealed = &first.rules[0];
        let plaintext = open(
            &seal_secret,
            &sealed.headers,
            &rule_aad(&node.id, &rule.id, &cred.id),
        )
        .unwrap();
        let headers: InjectedHeaders = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(headers.headers[0].value, "Bearer injected-secret");
        assert!(!first_contains(&first, "injected-secret"));

        let minted = cp
            .sessions
            .mint(
                &a,
                &vault.id,
                MintSession {
                    rule_ids: vec![rule.id],
                    bundle: None,
                    ttl_secs: Some(60),
                    longest: false,
                    request_limit: Some(3),
                    labels: BTreeMap::new(),
                    node_id: None,
                    binding: None,
                    not_after: None,
                    rule_not_after: Default::default(),
                    strict: false,
                    renews: None,
                },
            )
            .await
            .unwrap();
        cp.sessions.revoke(&a, &minted.session.id).await.unwrap();
        let second = cp
            .nodes
            .build_snapshot(&node)
            .await
            .unwrap()
            .verify(&verify)
            .unwrap();
        assert!(second.version > first.version);
        assert_eq!(second.revoked_sessions, vec![minted.session.id]);
        assert!(second.limited_sessions.is_empty());

        cp.nodes.revoke_node(&a, &node.id).await.unwrap();
        assert!(cp.nodes.authenticate(&node.id).await.is_err());
    }

    /// The plaintext (or its base64) must never appear in a snapshot body.
    fn first_contains(body: &tokenless_core::snapshot::SnapshotBody, needle: &str) -> bool {
        let json = serde_json::to_string(body).unwrap();
        json.contains(needle) || json.contains(&STANDARD.encode(needle))
    }

    #[tokio::test]
    async fn node_audit_cannot_forge_control_plane_events() {
        let cp = plane().await;
        let node = crate::model::Node {
            id: tokenless_core::ids::NodeId::new(),
            name: "n".into(),
            seal_public_key: String::new(),
            cert_serial: String::new(),
            cert_not_after: Utc::now(),
            enrolled_at: Utc::now(),
            last_seen_at: None,
            revoked_at: None,
            scoped_rules: false,
        };
        let forged = AuditEvent::new(
            "user:someone",
            "credential.delete",
            tokenless_core::audit::AuditOutcome::Success,
        );
        assert!(cp
            .nodes
            .ingest_audit(
                &node,
                AuditBatch {
                    events: vec![forged]
                }
            )
            .await
            .is_err());
        let vault = tokenless_core::ids::VaultId::new();
        let ok = AuditEvent::new(
            "user:someone",
            "proxy.inject",
            tokenless_core::audit::AuditOutcome::Success,
        )
        .detail("scope", format!("vault:{vault}"));
        cp.nodes
            .ingest_audit(&node, AuditBatch { events: vec![ok] })
            .await
            .unwrap();
        let page = cp
            .audit
            .query(
                &admin(0),
                Some(vault),
                Some("proxy.".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items[0].actor, format!("node:{}", node.id));
    }

    /// host, port, method, path, injected headers
    type SeenProbe = (String, u16, String, String, Vec<(String, String)>);

    /// Records what it was asked to send and answers with a fixed status.
    struct RecordingProber {
        status: u16,
        seen: std::sync::Mutex<Vec<SeenProbe>>,
    }

    #[async_trait::async_trait]
    impl CredentialProber for RecordingProber {
        async fn probe(
            &self,
            request: crate::probe::ProbeRequest,
            egress: &tokenless_core::egress::EgressPolicy,
        ) -> Result<u16, crate::probe::ProbeError> {
            assert!(
                egress.block_private,
                "default egress policy must be passed through"
            );
            self.seen.lock().unwrap().push((
                request.host,
                request.port,
                request.method,
                request.path,
                request
                    .headers
                    .headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect(),
            ));
            Ok(self.status)
        }
    }

    fn openai(key: &str) -> CreateCredential {
        CreateCredential {
            name: "models".into(),
            template_id: "openai".into(),
            template_version: None,
            host_override: vec![],
            fields: [("api_key".to_string(), key.to_string())].into(),
            custom_headers: vec![],
            substitutions: vec![],
            not_after: None,
        }
    }

    #[tokio::test]
    async fn vaults_are_deleted_by_admins_and_live_sessions_need_force() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "doomed").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let minted = cp
            .sessions
            .mint(
                &a,
                &vault.id,
                MintSession {
                    rule_ids: vec![rule.id],
                    bundle: None,
                    ttl_secs: Some(600),
                    longest: false,
                    request_limit: None,
                    labels: Default::default(),
                    node_id: None,
                    binding: None,
                    not_after: None,
                    rule_not_after: Default::default(),
                    strict: false,
                    renews: None,
                },
            )
            .await
            .unwrap();

        let editor = Caller {
            principal: Principal {
                kind: PrincipalKind::User,
                actor: "user:test-editor".into(),
                role: Role::Editor,
                vault: None,
            },
            step_up_at: Some(Utc::now()),
            second_factor: true,
            launch: None,
        };
        assert!(matches!(
            cp.policy.delete_vault(&editor, &vault.id, true).await,
            Err(ControlError::Forbidden { .. })
        ));
        assert!(matches!(
            cp.policy.delete_vault(&admin(3600), &vault.id, true).await,
            Err(ControlError::StepUpRequired { .. })
        ));
        let busy = cp
            .policy
            .delete_vault(&a, &vault.id, false)
            .await
            .unwrap_err();
        assert!(
            matches!(busy, ControlError::Conflict { .. })
                && busy.to_string().contains("1 live session"),
            "{busy}"
        );

        let done = cp.policy.delete_vault(&a, &vault.id, true).await.unwrap();
        assert_eq!(
            (done.credentials, done.rules, done.sessions_revoked),
            (1, 1, 1)
        );
        assert!(matches!(
            cp.policy.get_vault(&a, &vault.id).await,
            Err(ControlError::NotFound { .. })
        ));
        // The token is refused from now on: discovery says it was revoked.
        let err = cp.sessions.discover_self(&minted.token).await.unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
        let events = cp
            .audit
            .query(
                &a,
                Some(vault.id),
                Some("vault.delete".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(events.items.len(), 1);
        assert_eq!(
            events.items[0].detail.get("forced").map(String::as_str),
            Some("true")
        );
    }

    /// What an embedding program does: no accounts, a service caller.
    #[tokio::test]
    async fn embedded_services_need_no_accounts_and_hold_a_service_to_its_vault() {
        let store = Arc::new(MemoryStore::new());
        let cipher = Arc::new(
            Envelope::open(&AesGcmCipher::generate_key(), store.clone())
                .await
                .unwrap(),
        );
        let cs = ControlServices::new(
            ServiceStores {
                credentials: store.clone(),
                policy: store.clone(),
                audit: store.clone(),
                nodes: store.clone(),
                alerts: store.clone(),
                tripwires: store.clone(),
            },
            Arc::new(RbacAuthorizer),
            cipher,
            Arc::new(crate::probe::DisabledProber),
            ControlConfig::default(),
        )
        .await
        .unwrap();
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let mine = cs.policy.create_vault(&host, "project-a").await.unwrap();
        let other = cs.policy.create_vault(&host, "project-b").await.unwrap();

        // Bound to one vault: storing a credential needs no step-up there.
        let scoped = Caller::service(Principal::service("host", Role::Admin, Some(mine.id)));
        let cred = cs
            .policy
            .create_credential(
                &scoped,
                &mine.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let rule = cs
            .policy
            .create_rule(
                &scoped,
                &mine.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let minted = cs
            .sessions
            .mint(
                &scoped,
                &mine.id,
                MintSession {
                    rule_ids: vec![rule.id],
                    bundle: None,
                    ttl_secs: Some(600),
                    longest: false,
                    request_limit: None,
                    labels: BTreeMap::new(),
                    node_id: None,
                    binding: None,
                    not_after: None,
                    rule_not_after: Default::default(),
                    strict: false,
                    renews: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(minted.session.created_by, "service:host");

        // The other vault is out of reach.
        let denied = cs
            .policy
            .create_credential(
                &scoped,
                &other.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap_err();
        assert!(matches!(denied, ControlError::Forbidden { .. }), "{denied}");
        let denied = cs
            .policy
            .create_vault(&scoped, "project-c")
            .await
            .unwrap_err();
        assert!(matches!(denied, ControlError::Forbidden { .. }), "{denied}");

        let events = cs
            .audit
            .query(
                &host,
                Some(mine.id),
                Some("credential.create".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(events.items[0].actor, "service:host");

        // An embedded data plane: registered without a join token, fed
        // snapshots signed with the key it is given, audited as itself.
        let seal_secret = SealSecretKey::random_from_rng(OsRng);
        let public = encode_public_key(&SealPublicKey::from(&seal_secret));
        let denied = cs
            .nodes
            .register_embedded(&scoped, "embedded", &public)
            .await
            .unwrap_err();
        assert!(matches!(denied, ControlError::Forbidden { .. }), "{denied}");
        let registered = cs
            .nodes
            .register_embedded(&host, "embedded", &public)
            .await
            .unwrap();
        assert!(registered.node.cert_serial.is_empty());
        let signed = cs.nodes.build_snapshot(&registered.node).await.unwrap();
        let body = signed.verify(&registered.snapshot_verify_key).unwrap();
        assert_eq!(body.node_id, registered.node.id);
        // It is scoped: no session runs on it yet, so it holds no rule.
        assert!(registered.node.scoped_rules);
        assert!(body.rules.is_empty());
        let shipped = AuditEvent::new(
            "forged",
            "proxy.request",
            tokenless_core::audit::AuditOutcome::Success,
        )
        .detail(
            "scope",
            tokenless_core::scope::Scope::for_vault(&mine.id).to_string(),
        );
        cs.nodes
            .ingest_audit(
                &registered.node,
                AuditBatch {
                    events: vec![shipped],
                },
            )
            .await
            .unwrap();
        let events = cs
            .audit
            .query(
                &host,
                Some(mine.id),
                Some("proxy.".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            events.items[0].actor,
            format!("node:{}", registered.node.id)
        );
    }

    #[tokio::test]
    async fn sessions_can_be_minted_for_one_node_and_binding() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let public =
            encode_public_key(&SealPublicKey::from(&SealSecretKey::random_from_rng(OsRng)));
        let node = cp
            .nodes
            .register_embedded(&a, "embedded", &public)
            .await
            .unwrap()
            .node
            .id;
        let mint = |id: &str| MintSession {
            rule_ids: vec![rule.id],
            bundle: None,
            ttl_secs: Some(600),
            longest: false,
            request_limit: None,
            labels: BTreeMap::new(),
            node_id: Some(node),
            binding: Some(sessions::SessionBinding {
                id: id.into(),
                generation: 4,
            }),
            not_after: None,
            rule_not_after: Default::default(),
            strict: false,
            renews: None,
        };
        let minted = cp
            .sessions
            .mint(&a, &vault.id, mint("sbx-7"))
            .await
            .unwrap();
        let keys = std::collections::HashMap::from([(
            cp.keys.session_signer.kid().to_string(),
            cp.keys.session_signer.verifying_key(),
        )]);
        let claims =
            tokenless_core::session::verify_session(&minted.token, &keys, chrono::Utc::now())
                .unwrap();
        assert_eq!(claims.aud, Some(node));
        assert_eq!(claims.sub.as_deref(), Some("sbx-7/4"));

        let events = cp
            .audit
            .query(
                &a,
                Some(vault.id),
                Some("session.mint".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        let detail = &events.items[0].detail;
        assert_eq!(detail.get("binding").map(String::as_str), Some("sbx-7/4"));
        assert_eq!(detail.get("node_id"), Some(&node.to_string()));

        let err = cp
            .sessions
            .mint(&a, &vault.id, mint("sbx/7"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ControlError::Core(tokenless_core::CoreError::InvalidBinding { .. })
            ),
            "{err}"
        );

        // Choosing where credentials go is node management: an editor who
        // may mint in the vault can't send its sessions to a node.
        let editor = Caller {
            principal: Principal {
                kind: PrincipalKind::User,
                actor: "user:test-editor".into(),
                role: Role::Editor,
                vault: None,
            },
            step_up_at: Some(Utc::now()),
            second_factor: true,
            launch: None,
        };
        let mut unbound = mint("sbx-8");
        unbound.binding = None;
        let denied = cp
            .sessions
            .mint(&editor, &vault.id, unbound.clone())
            .await
            .unwrap_err();
        assert!(matches!(denied, ControlError::Forbidden { .. }), "{denied}");
        unbound.node_id = None;
        cp.sessions
            .mint(&editor, &vault.id, unbound.clone())
            .await
            .unwrap();

        // Only to a node that exists and isn't revoked.
        let unknown = tokenless_core::ids::NodeId::new();
        unbound.node_id = Some(unknown);
        let err = cp
            .sessions
            .mint(&a, &vault.id, unbound.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::NotFound { .. }), "{err}");
        assert!(err.to_string().contains(&unknown.to_string()), "{err}");
        cp.nodes.revoke_node(&a, &node).await.unwrap();
        unbound.node_id = Some(node);
        let err = cp.sessions.mint(&a, &vault.id, unbound).await.unwrap_err();
        assert!(err.to_string().contains("is revoked"), "{err}");
    }

    #[tokio::test]
    async fn session_lifetime_cap_is_a_setting_and_labels_are_editable() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let mint = |ttl: u64| MintSession {
            rule_ids: vec![rule.id],
            bundle: None,
            ttl_secs: Some(ttl),
            longest: false,
            request_limit: None,
            labels: [("agent".to_string(), "reviewer".to_string())].into(),
            node_id: None,
            binding: None,
            not_after: None,
            rule_not_after: Default::default(),
            strict: false,
            renews: None,
        };
        let err = cp
            .sessions
            .mint(&a, &vault.id, mint(30 * 86_400))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("604800"), "{err}");

        let mut settings = cp.policy.get_settings(&a).await.unwrap();
        settings.max_session_ttl_secs = 30 * 86_400;
        let stale = cp.policy.put_settings(&admin(3600), settings.clone()).await;
        assert!(
            matches!(stale, Err(ControlError::StepUpRequired { .. })),
            "raising the cap needs step-up"
        );
        cp.policy.put_settings(&a, settings.clone()).await.unwrap();
        let long = cp
            .sessions
            .mint(&a, &vault.id, mint(30 * 86_400))
            .await
            .unwrap();
        assert_eq!(
            (long.session.expires_at - long.session.created_at).num_seconds(),
            30 * 86_400
        );
        // `longest` takes the cap, whatever ttl_secs says.
        let longest = cp
            .sessions
            .mint(
                &a,
                &vault.id,
                MintSession {
                    longest: true,
                    ..mint(60)
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (longest.session.expires_at - longest.session.created_at).num_seconds(),
            30 * 86_400
        );
        settings.max_session_ttl_secs = 30;
        assert!(cp.policy.put_settings(&a, settings).await.is_err());

        let relabelled = cp
            .sessions
            .update_labels(
                &a,
                &long.session.id,
                [("ticket".to_string(), "T-42".to_string())].into(),
            )
            .await
            .unwrap();
        assert_eq!(
            relabelled.labels.get("ticket").map(String::as_str),
            Some("T-42")
        );
        assert!(!relabelled.labels.contains_key("agent"));
        let bad = cp
            .sessions
            .update_labels(
                &a,
                &long.session.id,
                [("".to_string(), "x".to_string())].into(),
            )
            .await;
        assert!(bad.is_err());
        let missing = cp
            .sessions
            .update_labels(
                &a,
                &tokenless_core::ids::SessionId::new(),
                Default::default(),
            )
            .await;
        assert!(matches!(missing, Err(ControlError::NotFound { .. })));
    }

    #[tokio::test]
    async fn always_reachable_hosts_widen_egress_and_need_step_up() {
        use tokenless_core::host::HostPattern;
        let cp = plane().await;
        let host = |h: &str| HostPattern::parse(h).unwrap();
        let mut settings = cp.policy.get_settings(&admin(0)).await.unwrap();
        settings.unmatched_host_policy = tokenless_core::snapshot::UnmatchedHostPolicy::Deny;
        cp.policy
            .put_settings(&admin(0), settings.clone())
            .await
            .unwrap();

        settings.passthrough_hosts = vec![host("registry.npmjs.org"), host("registry.npmjs.org")];
        let stale = cp.policy.put_settings(&admin(3600), settings.clone()).await;
        assert!(matches!(stale, Err(ControlError::StepUpRequired { .. })));
        let saved = cp
            .policy
            .put_settings(&admin(0), settings.clone())
            .await
            .unwrap();
        assert_eq!(
            saved.passthrough_hosts,
            vec![host("registry.npmjs.org")],
            "deduplicated"
        );

        // Removing an exception narrows egress, so it needs no step-up.
        settings.passthrough_hosts.clear();
        cp.policy
            .put_settings(&admin(3600), settings.clone())
            .await
            .unwrap();

        settings.passthrough_hosts = (0..101)
            .map(|i| host(&format!("h{i}.example.com")))
            .collect();
        let too_many = cp
            .policy
            .put_settings(&admin(0), settings)
            .await
            .unwrap_err();
        assert!(too_many.to_string().contains("at most 100"), "{too_many}");
    }

    #[tokio::test]
    async fn substitutions_name_existing_fields_and_are_audited_by_placeholder() {
        use tokenless_core::substitution::{Substitution, SubstitutionLocation};
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let sub = |field: &str| Substitution {
            placeholder: "__OPENAI_KEY__".into(),
            field: field.into(),
            env: Some("OPENAI_API_KEY".into()),
            locations: vec![SubstitutionLocation::Header],
        };
        let mut req = openai("sk-substituted");
        req.substitutions = vec![sub("password")];
        let err = cp
            .policy
            .create_credential(&a, &vault.id, req.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("field 'password'"), "{err}");

        req.substitutions = vec![sub("api_key")];
        let meta = cp
            .policy
            .create_credential(&a, &vault.id, req)
            .await
            .unwrap();
        assert_eq!(meta.substitutions, vec![sub("api_key")]);
        assert!(!serde_json::to_string(&meta)
            .unwrap()
            .contains("sk-substituted"));

        let cleared = cp
            .policy
            .update_substitutions(&a, &meta.id, vec![])
            .await
            .unwrap();
        assert!(cleared.substitutions.is_empty());
        let missing = cp
            .policy
            .update_substitutions(&a, &tokenless_core::ids::CredentialId::new(), vec![])
            .await;
        assert!(matches!(missing, Err(ControlError::NotFound { .. })));

        let events = cp
            .audit
            .query(&a, Some(vault.id), None, PageRequest::default())
            .await
            .unwrap()
            .items;
        let update = events
            .iter()
            .find(|e| e.action == "credential.update_substitutions")
            .unwrap();
        assert_eq!(
            update.detail.get("substitutions").map(String::as_str),
            Some("none")
        );
        let create = events
            .iter()
            .find(|e| e.action == "credential.create")
            .unwrap();
        assert_eq!(
            create.detail.get("substitutions").map(String::as_str),
            Some("__OPENAI_KEY__")
        );
    }

    #[tokio::test]
    async fn validation_sends_the_declared_request_to_the_credential_host_only() {
        let prober = Arc::new(RecordingProber {
            status: 200,
            seen: Default::default(),
        });
        let cp = plane_with(prober.clone()).await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let meta = cp
            .policy
            .create_credential(&admin(0), &vault.id, openai("sk-validate-me"))
            .await
            .unwrap();
        let result = cp
            .policy
            .validate_credential(&admin(0), &meta.id)
            .await
            .unwrap();
        assert!(result.ok, "{result:?}");
        assert_eq!(result.status, Some(200));
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("sk-validate-me"));
        let seen = prober.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let (host, port, method, path, headers) = &seen[0];
        assert_eq!((host.as_str(), *port), ("api.openai.com", 443));
        assert_eq!((method.as_str(), path.as_str()), ("GET", "/v1/models"));
        assert_eq!(
            headers,
            &vec![(
                "authorization".to_string(),
                "Bearer sk-validate-me".to_string()
            )]
        );
        let audit = cp
            .audit
            .query(
                &admin(0),
                None,
                Some("credential.validate".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(audit.items.len(), 1);
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .contains("sk-validate-me"));

        // Validation exposes the secret to its own host, so it needs step-up.
        let stale = cp.policy.validate_credential(&admin(3600), &meta.id).await;
        assert!(matches!(stale, Err(ControlError::StepUpRequired { .. })));
    }

    #[tokio::test]
    async fn variables_fill_fields_and_custom_headers_and_stay_write_only() {
        use super::variables::{CreateVariable, SecretValue};
        use tokenless_core::variables::CustomHeader;
        let prober = Arc::new(RecordingProber {
            status: 200,
            seen: Default::default(),
        });
        let cp = plane_with(prober.clone()).await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let key = cp
            .variables
            .create(
                &a,
                CreateVariable {
                    key: "OPENAI_KEY".into(),
                    value: SecretValue::from("sk-from-variable".to_string()),
                },
            )
            .await
            .unwrap();
        cp.variables
            .create(
                &a,
                CreateVariable {
                    key: "ORG".into(),
                    value: SecretValue::from("acme-test".to_string()),
                },
            )
            .await
            .unwrap();
        let duplicate = cp
            .variables
            .create(
                &a,
                CreateVariable {
                    key: "ORG".into(),
                    value: SecretValue::from("x".to_string()),
                },
            )
            .await;
        assert!(matches!(duplicate, Err(ControlError::Conflict { .. })));

        let header = |name: &str, value: &str| CustomHeader {
            name: name.into(),
            value: value.into(),
        };
        let mut req = openai("{{OPENAI_KEY}}");
        req.custom_headers = vec![header("OpenAI-Organization", "org-{{ ORG }}")];
        let meta = cp
            .policy
            .create_credential(&a, &vault.id, req)
            .await
            .unwrap();
        assert_eq!(meta.variable_refs, ["OPENAI_KEY", "ORG"]);

        cp.policy.validate_credential(&a, &meta.id).await.unwrap();
        let sent = prober.seen.lock().unwrap()[0].4.clone();
        assert_eq!(
            sent,
            vec![
                ("authorization".into(), "Bearer sk-from-variable".into()),
                ("openai-organization".into(), "org-acme-test".into()),
            ]
        );

        // Replacing the value reaches every credential that uses it.
        cp.variables
            .replace_value(&a, &key.id, SecretValue::from("sk-rotated".to_string()))
            .await
            .unwrap();
        cp.policy.validate_credential(&a, &meta.id).await.unwrap();
        let sent = prober.seen.lock().unwrap()[1].4.clone();
        assert_eq!(sent[0].1, "Bearer sk-rotated");

        // The list shows where a variable is used, never its value.
        let listed = cp.variables.list(&a, PageRequest::default()).await.unwrap();
        let json = serde_json::to_string(&listed).unwrap();
        assert!(!json.contains("sk-rotated") && !json.contains("acme-test"));
        let used = &listed
            .items
            .iter()
            .find(|v| v.key == "OPENAI_KEY")
            .unwrap()
            .used_by;
        assert_eq!(used.len(), 1);
        assert_eq!(used[0].vault_name, "main");

        // In use: cannot be deleted until the reference goes.
        let in_use = cp.variables.delete(&a, &key.id).await;
        assert!(
            matches!(in_use, Err(ControlError::Conflict { .. })),
            "{in_use:?}"
        );

        // Unknown references and shadowing headers are refused up front.
        let unknown = cp
            .policy
            .create_credential(&a, &vault.id, openai("{{NOPE}}"))
            .await;
        assert!(
            matches!(&unknown, Err(ControlError::Validation { message }) if message.contains("NOPE")),
            "{unknown:?}"
        );
        let shadow = cp
            .policy
            .update_custom_headers(&a, &meta.id, vec![header("Authorization", "x")])
            .await;
        assert!(matches!(shadow, Err(ControlError::Core(_))), "{shadow:?}");

        let cleared = cp
            .policy
            .update_custom_headers(&a, &meta.id, vec![])
            .await
            .unwrap();
        assert_eq!(cleared.variable_refs, ["OPENAI_KEY"]);
        let org = listed.items.iter().find(|v| v.key == "ORG").unwrap();
        cp.variables.delete(&a, &org.id).await.unwrap();

        // Managing variables is an admin task.
        let mut viewer = admin(0);
        viewer.principal.role = Role::Viewer;
        assert!(matches!(
            cp.variables.list(&viewer, PageRequest::default()).await,
            Err(ControlError::Forbidden { .. })
        ));
    }

    #[tokio::test]
    async fn validation_reports_unexpected_status_and_missing_declarations() {
        let cp = plane_with(Arc::new(RecordingProber {
            status: 401,
            seen: Default::default(),
        }))
        .await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let meta = cp
            .policy
            .create_credential(&admin(0), &vault.id, openai("sk-revoked"))
            .await
            .unwrap();
        let result = cp
            .policy
            .validate_credential(&admin(0), &meta.id)
            .await
            .unwrap();
        assert!(!result.ok);
        assert_eq!(result.status, Some(401));

        let generic = cp
            .policy
            .create_credential(
                &admin(0),
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let res = cp.policy.validate_credential(&admin(0), &generic.id).await;
        assert!(
            matches!(res, Err(ControlError::Validation { .. })),
            "{res:?}"
        );
    }

    #[tokio::test]
    async fn validation_without_a_prober_explains_itself() {
        let cp = plane().await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let meta = cp
            .policy
            .create_credential(&admin(0), &vault.id, openai("sk-x"))
            .await
            .unwrap();
        let result = cp
            .policy
            .validate_credential(&admin(0), &meta.id)
            .await
            .unwrap();
        assert!(!result.ok);
        assert!(result.detail.contains("not available"), "{}", result.detail);
    }

    #[tokio::test]
    async fn vault_overviews_name_the_first_services_and_count_live_sessions() {
        let cp = plane().await;
        let a = admin(0);
        let main = cp.policy.create_vault(&a, "main").await.unwrap();
        let empty = cp.policy.create_vault(&a, "empty").await.unwrap();
        let mut first = None;
        for name in ["one", "two", "three", "four", "five"] {
            let mut req = bearer(&[("token", "t")], &["api.example.com"]);
            req.name = name.into();
            let cred = cp
                .policy
                .create_credential(&a, &main.id, req)
                .await
                .unwrap();
            first.get_or_insert(cred);
        }
        let rule = cp
            .policy
            .create_rule(
                &a,
                &main.id,
                CreateRule {
                    name: "read".into(),
                    credential_id: first.unwrap().id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        let mint = || MintSession {
            rule_ids: vec![rule.id],
            bundle: None,
            ttl_secs: Some(600),
            longest: false,
            request_limit: None,
            labels: BTreeMap::new(),
            node_id: None,
            binding: None,
            not_after: None,
            rule_not_after: Default::default(),
            strict: false,
            renews: None,
        };
        cp.sessions.mint(&a, &main.id, mint()).await.unwrap();
        let revoked = cp.sessions.mint(&a, &main.id, mint()).await.unwrap();
        cp.sessions.revoke(&a, &revoked.session.id).await.unwrap();

        let page = cp
            .vault_overviews(&a, PageRequest::new(None, None))
            .await
            .unwrap();
        let by_name = |name: &str| page.items.iter().find(|o| o.vault.name == name).unwrap();
        let main = by_name("main");
        assert_eq!(main.service_count, 5);
        assert_eq!(main.services.len(), overview::OVERVIEW_SERVICES as usize);
        // Only the session that is still live counts.
        assert_eq!(main.live_sessions, 1);
        assert_eq!(main.last_request_at, None, "nothing was brokered yet");
        let empty_overview = by_name("empty");
        assert_eq!(
            (empty_overview.service_count, empty_overview.live_sessions),
            (0, 0)
        );

        // A vault-bound key sees its own vault only.
        let (plaintext, _) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "viewer".into(),
                    vault_id: empty.id,
                    role: Role::Viewer,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        let viewer = cp.auth.authenticate_api_key(&plaintext).await.unwrap();
        let seen = cp
            .vault_overviews(&viewer, PageRequest::new(None, None))
            .await
            .unwrap();
        assert_eq!(
            seen.items.iter().map(|o| o.vault.id).collect::<Vec<_>>(),
            vec![empty.id]
        );
        // And one vault's overview is the same as its entry in the list.
        let one = cp.vault_overview_by_id(&a, &main.vault.id).await.unwrap();
        assert_eq!((one.service_count, one.live_sessions), (5, 1));
        assert!(matches!(
            cp.vault_overview_by_id(&viewer, &main.vault.id).await,
            Err(ControlError::Forbidden { .. })
        ));
    }
}
