// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod audit;
pub mod auth;
pub mod nodes;
pub mod policy;
pub mod sessions;

use std::sync::Arc;

use broker_core::audit::AuditEvent;
use broker_core::authz::{Action, Decision, Principal, PrincipalKind};
use broker_core::ids::VaultId;
use chrono::{DateTime, Utc};
use tracing::error;

use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::notify::PolicyNotifier;
use crate::store::{AuditSink, Authorizer, CredentialStore, IdentityStore, NodeStore, PolicyStore};

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
}

impl Caller {
    pub fn actor(&self) -> &str {
        &self.principal.actor
    }
}

#[derive(Clone)]
pub struct Stores {
    pub credentials: Arc<dyn CredentialStore>,
    pub policy: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditSink>,
    pub identity: Arc<dyn IdentityStore>,
    pub nodes: Arc<dyn NodeStore>,
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

    pub fn require_step_up(&self, caller: &Caller, action: Action) -> Result<(), ControlError> {
        if caller.principal.kind != PrincipalKind::User {
            return Err(ControlError::Forbidden {
                reason: format!(
                    "'{action}' needs a person with a second factor; {} is an API key",
                    caller.actor()
                ),
            });
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

/// Writes control plane audit events. A failed write is logged at error
/// level; the operation it describes has already been committed.
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

/// Everything the HTTP layer needs, wired once at startup.
pub struct ControlPlane {
    pub auth: auth::AuthService,
    pub policy: policy::PolicyService,
    pub sessions: sessions::SessionService,
    pub nodes: nodes::NodeService,
    pub audit: audit::AuditService,
    pub keys: Arc<KeyRing>,
    pub notifier: Arc<PolicyNotifier>,
}

impl ControlPlane {
    pub async fn new(
        stores: Stores,
        authorizer: Arc<dyn Authorizer>,
        cipher: Arc<dyn SecretCipher>,
        config: ControlConfig,
    ) -> Result<Self, ControlError> {
        let keys = Arc::new(KeyRing::load_or_create(stores.nodes.as_ref(), cipher.as_ref()).await?);
        let notifier = Arc::new(PolicyNotifier::new());
        let guard = Guard::new(authorizer, config.step_up_window_secs);
        let recorder = AuditRecorder::new(stores.audit.clone());
        let auth = auth::AuthService::new(
            stores.identity.clone(),
            cipher.clone(),
            keys.clone(),
            guard.clone(),
            recorder.clone(),
            config.clone(),
        )?;
        let policy = policy::PolicyService::new(
            stores.policy.clone(),
            stores.credentials.clone(),
            cipher.clone(),
            guard.clone(),
            recorder.clone(),
            notifier.clone(),
        );
        policy.seed_builtin_templates().await?;
        let sessions = sessions::SessionService::new(
            stores.policy.clone(),
            keys.clone(),
            guard.clone(),
            recorder.clone(),
            notifier.clone(),
        );
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
            config,
        );
        let audit = audit::AuditService::new(stores.audit, guard);
        Ok(Self {
            auth,
            policy,
            sessions,
            nodes,
            audit,
            keys,
            notifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use broker_auth::totp;
    use broker_core::authz::Role;
    use broker_core::injection::InjectedHeaders;
    use broker_core::protocol::{AuditBatch, EnrollRequest};
    use broker_core::seal::{encode_public_key, open, SealPublicKey, SealSecretKey};
    use broker_core::snapshot::{decode_verifying_key, rule_aad};
    use rand::rngs::OsRng;

    use super::auth::{CreateApiKey, LoginRequest, SetupRequest};
    use super::policy::{CreateCredential, CreateRule, UpdateRule};
    use super::sessions::MintSession;
    use super::*;
    use crate::cipher::AesGcmCipher;
    use crate::memory::MemoryStore;
    use crate::model::PageRequest;
    use crate::store::RbacAuthorizer;

    async fn plane() -> ControlPlane {
        let store = Arc::new(MemoryStore::new());
        let stores = Stores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            identity: store.clone(),
            nodes: store,
        };
        let cipher = Arc::new(AesGcmCipher::new(&AesGcmCipher::generate_key()).unwrap());
        ControlPlane::new(
            stores,
            Arc::new(RbacAuthorizer),
            cipher,
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
        }
    }

    #[tokio::test]
    async fn setup_login_and_csrf() {
        let cp = plane().await;
        assert!(cp.auth.setup_required().await.unwrap());
        let token = cp.auth.issue_setup_token().await.unwrap().unwrap();
        let enrol = cp.auth.new_totp_enrollment("admin").unwrap();
        let req = |code: String, tok: &str| SetupRequest {
            setup_token: tok.to_string(),
            username: "admin".into(),
            password: "correct horse battery".into(),
            totp_secret: enrol.secret.clone(),
            totp_code: code,
        };
        assert!(matches!(
            cp.auth.complete_setup(req("000000".into(), &token)).await,
            Err(ControlError::Validation { .. })
        ));
        let code = totp::code_at(&enrol.secret, now_secs()).unwrap();
        assert!(matches!(
            cp.auth
                .complete_setup(req(code.clone(), "cbsetup_wrong"))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        cp.auth
            .complete_setup(req(code.clone(), &token))
            .await
            .unwrap();
        assert!(matches!(
            cp.auth.complete_setup(req(code.clone(), &token)).await,
            Err(ControlError::Conflict { .. })
        ));
        assert!(cp.auth.issue_setup_token().await.unwrap().is_none());

        let login = |password: &str, code: String| LoginRequest {
            username: "admin".into(),
            password: password.into(),
            totp_code: code,
        };
        // The setup code's time step is spent: replaying it must fail.
        assert!(cp
            .auth
            .login(login("correct horse battery", code))
            .await
            .is_err());
        assert!(cp
            .auth
            .login(login(
                "wrong password!!",
                totp::code_at(&enrol.secret, now_secs() + 30).unwrap()
            ))
            .await
            .is_err());
        let outcome = cp
            .auth
            .login(login(
                "correct horse battery",
                totp::code_at(&enrol.secret, now_secs() + 30).unwrap(),
            ))
            .await
            .unwrap();
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();
        assert_eq!(auth.user.username, "admin");
        assert!(cp.auth.verify_csrf(&auth.token_hash, &outcome.csrf_token));
        assert!(!cp.auth.verify_csrf(&auth.token_hash, "forged"));
        cp.auth.logout(&auth).await.unwrap();
        assert!(cp.auth.authenticate_session(&outcome.token).await.is_err());
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
                    totp_code: "123456".into(),
                })
                .await;
        }
        let res = cp
            .auth
            .login(LoginRequest {
                username: "nobody".into(),
                password: "whatever-password".into(),
                totp_code: "123456".into(),
            })
            .await;
        assert!(matches!(res, Err(ControlError::RateLimited { .. })));
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
            Err(ControlError::Core(broker_core::CoreError::Widening { .. }))
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
                    role: Role::SessionIssuer,
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
                    ttl_secs: None,
                    request_limit: None,
                    labels: BTreeMap::new(),
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
                        ttl_secs: None,
                        request_limit: None,
                        labels: BTreeMap::new(),
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
                    ttl_secs: Some(60),
                    request_limit: Some(3),
                    labels: BTreeMap::new(),
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
    fn first_contains(body: &broker_core::snapshot::SnapshotBody, needle: &str) -> bool {
        let json = serde_json::to_string(body).unwrap();
        json.contains(needle) || json.contains(&STANDARD.encode(needle))
    }

    #[tokio::test]
    async fn node_audit_cannot_forge_control_plane_events() {
        let cp = plane().await;
        let node = crate::model::Node {
            id: broker_core::ids::NodeId::new(),
            name: "n".into(),
            seal_public_key: String::new(),
            cert_serial: String::new(),
            cert_not_after: Utc::now(),
            enrolled_at: Utc::now(),
            last_seen_at: None,
            revoked_at: None,
        };
        let forged = AuditEvent::new(
            "user:someone",
            "credential.delete",
            broker_core::audit::AuditOutcome::Success,
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
        let vault = broker_core::ids::VaultId::new();
        let ok = AuditEvent::new(
            "user:someone",
            "proxy.inject",
            broker_core::audit::AuditOutcome::Success,
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
}
