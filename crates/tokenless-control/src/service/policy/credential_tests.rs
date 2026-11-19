// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Testing a credential when it is added and on demand: what is sent and
//! where, how each answer is told apart, the rate limit, and that the
//! secret never comes back out in a result, an audit record, an error or
//! a log line.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokenless_core::authz::Role;
use tokenless_core::egress::EgressPolicy;
use tokenless_core::ids::VaultId;

use super::*;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::model::PageRequest;
use crate::probe::{ProbeError, ProbeRequest, PER_CREDENTIAL};
use crate::service::testing::{enrol, person_caller};
use crate::service::Caller;
use crate::store::RbacAuthorizer;
use crate::{ControlConfig, ControlPlane, Stores};

/// Unmistakably not a real key.
const SECRET: &str = "sk-tokenless-test-dummy-0000";

/// What one test request asked to send.
#[derive(Debug, Clone)]
struct Sent {
    host: String,
    port: u16,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    block_private: bool,
}

/// A stand-in upstream: answers every test request with `answer`.
struct Scripted {
    answer: Mutex<Result<u16, ProbeError>>,
    sent: Mutex<Vec<Sent>>,
}

impl Scripted {
    fn new(answer: Result<u16, ProbeError>) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            sent: Mutex::default(),
        })
    }

    fn answer(&self, answer: Result<u16, ProbeError>) {
        *self.answer.lock().unwrap() = answer;
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl CredentialProber for Scripted {
    async fn probe(&self, request: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError> {
        self.sent.lock().unwrap().push(Sent {
            host: request.host,
            port: request.port,
            method: request.method,
            path: request.path,
            headers: request
                .headers
                .headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            block_private: egress.block_private,
        });
        self.answer.lock().unwrap().clone()
    }
}

fn admin() -> Caller {
    person_caller("admin", Role::Admin)
}

struct T {
    store: Arc<MemoryStore>,
    cp: ControlPlane,
    vault: VaultId,
}

async fn setup(prober: Arc<dyn CredentialProber>) -> T {
    setup_on(Arc::new(MemoryStore::new()), prober).await
}

async fn setup_on(store: Arc<MemoryStore>, prober: Arc<dyn CredentialProber>) -> T {
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let cp = ControlPlane::new(
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
            members: store.clone(),
        },
        Arc::new(RbacAuthorizer),
        cipher,
        prober,
        Arc::new(crate::service::sso::oidc::NoTransport),
        Arc::new(crate::service::audit_export::DisabledWebhookTransport),
        ControlConfig::default(),
    )
    .await
    .unwrap();
    enrol(store.as_ref(), &admin()).await;
    let vault = cp.policy.create_vault(&admin(), "main").await.unwrap().id;
    T { store, cp, vault }
}

fn openai(name: &str) -> CreateCredential {
    CreateCredential {
        name: name.into(),
        template_id: "openai".into(),
        template_version: None,
        host_override: vec![],
        fields: [("api_key".to_string(), SECRET.to_string())].into(),
        custom_headers: vec![],
        substitutions: vec![],
        not_after: None,
    }
}

fn custom(name: &str) -> CreateCredential {
    CreateCredential {
        name: name.into(),
        template_id: "generic-bearer".into(),
        template_version: None,
        host_override: vec!["api.example.com".into()],
        fields: [("token".to_string(), SECRET.to_string())].into(),
        custom_headers: vec![],
        substitutions: vec![],
        not_after: None,
    }
}

async fn validations(t: &T) -> Vec<tokenless_core::audit::AuditEvent> {
    t.cp.audit
        .query(
            &admin(),
            None,
            Some("credential.validate".into()),
            PageRequest::default(),
        )
        .await
        .unwrap()
        .items
}

#[tokio::test]
async fn adding_a_service_tests_it_through_the_injection_the_proxy_uses() {
    let upstream = Scripted::new(Ok(200));
    let t = setup(upstream.clone()).await;
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, openai("models"))
            .await
            .unwrap();
    assert_eq!(added.test.outcome, TestOutcome::Accepted);
    assert!(added.test.ok);
    assert_eq!(added.test.status, Some(200));
    assert_eq!(added.test.host.as_deref(), Some("api.openai.com"));
    assert_eq!(added.credential.last_test.as_ref(), Some(&added.test));

    // One request: the template's GET, to the service's own host, with
    // the header the proxy would add, under the instance egress policy.
    let sent = upstream.sent();
    assert_eq!(sent.len(), 1);
    let s = &sent[0];
    assert_eq!((s.host.as_str(), s.port), ("api.openai.com", 443));
    assert_eq!((s.method.as_str(), s.path.as_str()), ("GET", "/v1/models"));
    assert_eq!(
        s.headers,
        vec![("authorization".to_string(), format!("Bearer {SECRET}"))]
    );
    assert!(s.block_private);

    // Kept on the service, and in the audit log with who, where and what.
    let stored =
        t.cp.policy
            .get_credential(&admin(), &added.credential.id)
            .await
            .unwrap();
    assert_eq!(stored.last_test, Some(added.test.clone()));
    let events = validations(&t).await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.actor, admin().actor());
    assert_eq!(e.vault_id, Some(t.vault));
    assert_eq!(
        e.target.as_deref(),
        Some(format!("credential:{}", added.credential.id).as_str())
    );
    assert_eq!(e.detail.get("name").map(String::as_str), Some("models"));
    assert_eq!(
        e.detail.get("outcome").map(String::as_str),
        Some("accepted")
    );
    assert_eq!(e.detail.get("status").map(String::as_str), Some("200"));
}

/// What the upstream does, what the test makes of it, the status it
/// reports and words its detail must contain.
type Case = (
    Result<u16, ProbeError>,
    TestOutcome,
    Option<u16>,
    &'static str,
);

#[tokio::test]
async fn each_answer_is_told_apart() {
    let upstream = Scripted::new(Ok(200));
    let t = setup(upstream.clone()).await;
    let host = || "api.openai.com".to_string();
    let cases: Vec<Case> = vec![
        (Ok(200), TestOutcome::Accepted, Some(200), "accepted"),
        (
            Ok(401),
            TestOutcome::Rejected,
            Some(401),
            "wrong, expired or missing",
        ),
        (Ok(403), TestOutcome::Rejected, Some(403), "scopes"),
        // A success code the template does not expect is no pass either.
        (
            Ok(204),
            TestOutcome::UnexpectedStatus,
            Some(204),
            "answered 204",
        ),
        (
            Ok(404),
            TestOutcome::UnexpectedStatus,
            Some(404),
            "answered 404",
        ),
        (
            Ok(429),
            TestOutcome::UnexpectedStatus,
            Some(429),
            "answered 429",
        ),
        (
            Ok(503),
            TestOutcome::UnexpectedStatus,
            Some(503),
            "answered 503",
        ),
        (
            Err(ProbeError::Resolve {
                host: host(),
                reason: "no such host".into(),
            }),
            TestOutcome::Unreachable,
            None,
            "could not resolve",
        ),
        (
            Err(ProbeError::Request {
                host: host(),
                reason: "TLS handshake failed: invalid peer certificate".into(),
            }),
            TestOutcome::Unreachable,
            None,
            "TLS handshake failed",
        ),
        (
            Err(ProbeError::Request {
                host: host(),
                reason: "connect failed: connection refused".into(),
            }),
            TestOutcome::Unreachable,
            None,
            "connection refused",
        ),
        (
            Err(ProbeError::Blocked {
                host: host(),
                ip: "10.0.0.5".into(),
                reason: "a private address".into(),
            }),
            TestOutcome::Blocked,
            None,
            "allow the range in Settings",
        ),
        (
            Err(ProbeError::TimedOut {
                host: host(),
                secs: 10,
            }),
            TestOutcome::TimedOut,
            None,
            "within 10s",
        ),
        (
            Err(ProbeError::Unavailable),
            TestOutcome::Unavailable,
            None,
            "not available",
        ),
    ];
    for (i, (answer, outcome, status, says)) in cases.into_iter().enumerate() {
        upstream.answer(answer);
        let added =
            t.cp.policy
                .add_credential(&admin(), &t.vault, openai(&format!("models-{i}")))
                .await
                .unwrap();
        let test = &added.test;
        assert_eq!(test.outcome, outcome, "{test:?}");
        assert_eq!(test.ok, outcome == TestOutcome::Accepted);
        assert_eq!(test.status, status);
        assert!(test.detail.contains(says), "{outcome:?}: {}", test.detail);
        // Whatever happened, the service stays, to be fixed or retested.
        let kept =
            t.cp.policy
                .get_credential(&admin(), &added.credential.id)
                .await
                .unwrap();
        assert_eq!(kept.last_test.as_ref(), Some(test));
    }
}

#[tokio::test]
async fn a_service_without_a_test_request_is_not_tested_and_says_so() {
    let upstream = Scripted::new(Ok(200));
    let t = setup(upstream.clone()).await;
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, custom("internal"))
            .await
            .unwrap();
    assert_eq!(added.test.outcome, TestOutcome::NoProbe);
    assert!(!added.test.ok, "never a pass without a request");
    assert_eq!(
        added.test.detail,
        "not tested: no test request defined for this service"
    );
    assert_eq!(added.test.status, None);
    assert!(upstream.sent().is_empty(), "nothing is sent");
    assert!(
        validations(&t).await.is_empty(),
        "nothing left, so no audit"
    );
    let again =
        t.cp.policy
            .test_credential(&admin(), &added.credential.id)
            .await
            .unwrap();
    assert_eq!(again.outcome, TestOutcome::NoProbe);
    assert!(upstream.sent().is_empty());
}

/// An install that stored a built-in template before the catalogue gave
/// it a test request still tests with it: same id and version, so the
/// same hosts and injection, and the request is checked against them.
#[tokio::test]
async fn a_builtin_stored_before_its_test_request_uses_the_catalogues() {
    use crate::model::{StoredTemplate, TemplateSource, TemplateStatus};
    use crate::store::PolicyStore;
    let store = Arc::new(MemoryStore::new());
    let (mut stale, yaml) = builtin_templates()
        .unwrap()
        .into_iter()
        .find(|(t, _)| t.id == "openai")
        .unwrap();
    stale.validation = None;
    store
        .insert_template(
            StoredTemplate {
                template: stale,
                yaml: yaml.to_string(),
                source: TemplateSource::Builtin,
                status: TemplateStatus::Approved,
                imported_by: None,
                approved_by: Some("system".into()),
                created_at: Utc::now(),
            },
            &[],
        )
        .await
        .unwrap();
    let upstream = Scripted::new(Ok(200));
    let t = setup_on(store, upstream.clone()).await;
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, openai("models"))
            .await
            .unwrap();
    assert_eq!(
        added.test.outcome,
        TestOutcome::Accepted,
        "{:?}",
        added.test
    );
    assert_eq!(upstream.sent()[0].path, "/v1/models");
}

#[tokio::test]
async fn tests_are_rate_limited_per_service() {
    let upstream = Scripted::new(Ok(401));
    let t = setup(upstream.clone()).await;
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, openai("models"))
            .await
            .unwrap();
    for _ in 1..PER_CREDENTIAL {
        t.cp.policy
            .test_credential(&admin(), &added.credential.id)
            .await
            .unwrap();
    }
    assert_eq!(upstream.sent().len(), PER_CREDENTIAL);
    upstream.answer(Ok(200));
    let limited =
        t.cp.policy
            .test_credential(&admin(), &added.credential.id)
            .await;
    assert!(
        matches!(
            limited,
            Err(ControlError::RateLimited { retry_after_secs, .. }) if retry_after_secs > 0
        ),
        "{limited:?}"
    );
    // Refused before anything was sent, and the last real result stands.
    assert_eq!(upstream.sent().len(), PER_CREDENTIAL);
    let kept =
        t.cp.policy
            .get_credential(&admin(), &added.credential.id)
            .await
            .unwrap();
    assert_eq!(
        kept.last_test.map(|t| t.outcome),
        Some(TestOutcome::Rejected)
    );
    assert_eq!(validations(&t).await.len(), PER_CREDENTIAL);
}

#[tokio::test]
async fn a_rate_limited_add_still_adds_the_service() {
    let upstream = Scripted::new(Ok(200));
    let t = setup(upstream.clone()).await;
    // The same person adding many services in a minute.
    let mut last = None;
    for i in 0..=crate::probe::PER_ACTOR {
        last = Some(
            t.cp.policy
                .add_credential(&admin(), &t.vault, openai(&format!("m{i}")))
                .await
                .unwrap(),
        );
    }
    let last = last.unwrap();
    assert_eq!(last.test.outcome, TestOutcome::RateLimited);
    assert!(last.test.retry_after_secs.is_some());
    assert!(last.test.detail.starts_with("not tested: too many tests"));
    // Not kept: it says nothing about the credential.
    assert_eq!(last.credential.last_test, None);
    assert_eq!(upstream.sent().len(), crate::probe::PER_ACTOR);
}

#[tokio::test]
async fn replacing_the_secret_forgets_the_old_result() {
    let t = setup(Scripted::new(Ok(401))).await;
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, openai("models"))
            .await
            .unwrap();
    assert!(added.credential.last_test.is_some());
    let rotated =
        t.cp.policy
            .rotate_credential(
                &admin(),
                &added.credential.id,
                RotateCredential {
                    fields: [("api_key".to_string(), "sk-tokenless-test-dummy-1111".into())].into(),
                    not_after: None,
                    expected_generation: None,
                    rotation_id: None,
                },
            )
            .await
            .unwrap();
    assert_eq!(rotated.last_test, None);
}

#[tokio::test]
async fn only_editors_of_the_vault_may_test() {
    let upstream = Scripted::new(Ok(200));
    let t = setup(upstream.clone()).await;
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, openai("models"))
            .await
            .unwrap();
    let outsider = person_caller("outsider", Role::Member);
    enrol(t.store.as_ref(), &outsider).await;
    let refused =
        t.cp.policy
            .test_credential(&outsider, &added.credential.id)
            .await;
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(upstream.sent().len(), 1);
}

/// A prober that puts the secret in its error (as a careless TLS or HTTP
/// library might) still cannot get it into the result, the stored test,
/// the audit log, or any log line.
#[tokio::test(flavor = "current_thread")]
async fn the_secret_never_comes_back_out() {
    let logs = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let upstream = Scripted::new(Err(ProbeError::Request {
        host: "api.openai.com".into(),
        reason: format!("bad header 'Authorization: Bearer {SECRET}'"),
    }));
    let t = setup(upstream.clone()).await;
    let mut seen = Vec::new();
    let added =
        t.cp.policy
            .add_credential(&admin(), &t.vault, openai("models"))
            .await
            .unwrap();
    assert_eq!(added.test.outcome, TestOutcome::Unreachable);
    seen.push(serde_json::to_string(&added).unwrap());
    for answer in [Ok(200), Ok(401), Ok(500)] {
        upstream.answer(answer);
        let test =
            t.cp.policy
                .test_credential(&admin(), &added.credential.id)
                .await
                .unwrap();
        seen.push(serde_json::to_string(&test).unwrap());
    }
    let limited = loop {
        match t
            .cp
            .policy
            .test_credential(&admin(), &added.credential.id)
            .await
        {
            Ok(test) => seen.push(serde_json::to_string(&test).unwrap()),
            Err(e) => break e,
        }
    };
    seen.push(limited.to_string());
    seen.push(format!("{limited:?}"));
    let listed =
        t.cp.policy
            .list_credentials(&admin(), &t.vault, PageRequest::default())
            .await
            .unwrap();
    seen.push(serde_json::to_string(&listed).unwrap());
    seen.push(serde_json::to_string(&validations(&t).await).unwrap());
    seen.push(logs.text());
    for text in &seen {
        assert!(!text.contains(SECRET), "the secret leaked into: {text}");
    }
    assert!(seen[0].contains("[redacted]"), "{}", seen[0]);
}

/// Collects log output for [`the_secret_never_comes_back_out`].
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
