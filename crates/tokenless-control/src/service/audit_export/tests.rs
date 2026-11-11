// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit export against a receiver simulated in memory: it records every
//! request and answers what the test tells it to.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use tokenless_core::authz::{Principal, PrincipalKind, Role};
use tokenless_core::scope::Scope;

use super::*;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::model::{AuditQuery, PageRequest, Vault};
use crate::store::{AuditSink, PolicyStore, RbacAuthorizer};
use crate::{ControlConfig, ControlPlane, Stores};

const URL: &str = "https://siem.example.test/ingest";

#[derive(Default)]
struct Receiver {
    requests: Mutex<Vec<WebhookRequest>>,
    /// Answers for the next requests, in order; 200 when empty.
    answers: Mutex<VecDeque<Result<u16, WebhookError>>>,
}

impl Receiver {
    fn answer(&self, answer: Result<u16, WebhookError>) {
        self.answers.lock().unwrap().push_back(answer);
    }

    fn requests(&self) -> Vec<WebhookRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// The events each request carried, as JSON.
    fn events(&self) -> Vec<Vec<Value>> {
        self.requests()
            .iter()
            .map(|r| {
                let body: Value = serde_json::from_slice(&r.body).unwrap();
                body["events"].as_array().unwrap().clone()
            })
            .collect()
    }
}

#[async_trait]
impl WebhookTransport for Receiver {
    async fn post(&self, request: WebhookRequest) -> Result<u16, WebhookError> {
        self.requests.lock().unwrap().push(request);
        self.answers.lock().unwrap().pop_front().unwrap_or(Ok(200))
    }
}

struct T {
    store: Arc<MemoryStore>,
    cp: ControlPlane,
    receiver: Arc<Receiver>,
}

impl T {
    fn export(&self) -> &AuditExportService {
        &self.cp.audit_export
    }

    /// Records `n` events as a proxy would.
    async fn record(&self, n: usize, action: &str) {
        let events: Vec<_> = (0..n)
            .map(|i| {
                AuditEvent::new("node:test", action, AuditOutcome::Success)
                    .detail("n", i.to_string())
            })
            .collect();
        self.store.record(&events).await.unwrap();
    }

    async fn audit(&self, action: &str) -> Vec<AuditEvent> {
        self.store
            .query(&AuditQuery {
                action_prefix: Some(action.into()),
                page: PageRequest::new(Some(1), Some(100)),
                ..Default::default()
            })
            .await
            .unwrap()
            .items
            .into_iter()
            .filter(|e| e.action == action)
            .collect()
    }

    async fn view(&self, id: &AuditDestinationId) -> AuditDestinationView {
        self.export().get(&admin(), id).await.unwrap()
    }
}

fn admin() -> Caller {
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: "user:test-admin".into(),
            role: Role::Admin,
            vault: None,
        },
        step_up_at: Some(Utc::now()),
        second_factor: true,
        launch: None,
    }
}

fn input() -> AuditDestinationInput {
    AuditDestinationInput {
        name: "SIEM".into(),
        url: URL.into(),
        format: PayloadFormat::Json,
        auth_header_name: None,
        auth_header_value: None,
        clear_auth_header: false,
        filter: AuditFilter::default(),
    }
}

fn create(start_at: StartAt) -> CreateAuditDestination {
    CreateAuditDestination {
        destination: input(),
        start_at,
    }
}

async fn setup() -> T {
    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let receiver = Arc::new(Receiver::default());
    let cp = ControlPlane::new(
        Stores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            identity: store.clone(),
            sso: store.clone(),
            audit_export: store.clone(),
            nodes: store.clone(),
        },
        Arc::new(RbacAuthorizer),
        cipher,
        Arc::new(crate::probe::DisabledProber),
        Arc::new(crate::service::sso::oidc::NoTransport),
        receiver.clone(),
        ControlConfig::default(),
    )
    .await
    .unwrap();
    T {
        store,
        cp,
        receiver,
    }
}

fn header<'a>(request: &'a WebhookRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn seqs(batch: &[Value]) -> Vec<u64> {
    batch.iter().map(|e| e["seq"].as_u64().unwrap()).collect()
}

#[tokio::test]
async fn events_are_sent_in_order_signed_and_only_once() {
    let t = setup().await;
    let created = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap();
    let id = created.destination.id;
    assert_eq!(
        created.destination.behind, 1,
        "only the destination's own creation is waiting"
    );
    t.record(3, "proxy.inject").await;

    let pass = t.export().deliver(&id).await.unwrap();
    assert_eq!((pass.batches, pass.events, pass.error), (1, 4, None));
    let requests = t.receiver.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.url, URL);
    assert_eq!(header(request, "content-type"), Some("application/json"));

    // Signed the Standard Webhooks way with the secret shown at creation.
    let batch_id = header(request, "webhook-id").unwrap();
    let timestamp: i64 = header(request, "webhook-timestamp")
        .unwrap()
        .parse()
        .unwrap();
    assert!((Utc::now().timestamp() - timestamp).abs() < 60);
    let expected =
        webhook::sign(&created.signing_secret, batch_id, timestamp, &request.body).unwrap();
    assert_eq!(
        header(request, "webhook-signature"),
        Some(expected.as_str())
    );

    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["type"], "tokenless.audit");
    assert_eq!(body["version"], 1);
    assert_eq!(body["batch_id"], batch_id);
    let events = body["events"].as_array().unwrap();
    assert_eq!(events[0]["action"], "audit_export.create");
    assert_eq!(events[1]["action"], "proxy.inject");
    assert_eq!(events[1]["detail"]["n"], "0");
    assert!(events[1]["id"].is_string() && events[1]["at"].is_string());
    let numbers = seqs(events);
    assert!(numbers.windows(2).all(|w| w[1] == w[0] + 1), "{numbers:?}");

    let view = t.view(&id).await;
    assert_eq!((view.status, view.behind), (DeliveryStatus::UpToDate, 0));
    assert!(view.last_success_at.is_some());
    // Nothing new: nothing sent.
    assert_eq!(
        t.export().deliver(&id).await.unwrap(),
        DeliveryPass::default()
    );
    assert_eq!(t.receiver.requests().len(), 1);
}

#[tokio::test]
async fn a_failed_batch_is_retried_from_the_same_cursor_with_the_same_id() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    t.record(2, "proxy.inject").await;
    t.receiver.answer(Ok(503));
    t.receiver.answer(Err(WebhookError {
        reason: "could not connect: refused".into(),
    }));

    let first = t.export().deliver(&id).await.unwrap();
    assert_eq!(first.error.as_deref(), Some("the receiver answered 503"));
    let view = t.view(&id).await;
    assert_eq!(view.status, DeliveryStatus::Retrying);
    assert_eq!(view.behind, 3);
    assert_eq!(view.consecutive_failures, 1);
    assert!(view.failing_since.is_some());

    let second = t.export().deliver(&id).await.unwrap();
    assert_eq!(second.error.as_deref(), Some("could not connect: refused"));
    assert_eq!(
        t.view(&id).await.failing_since,
        view.failing_since,
        "the run of failures keeps its start"
    );

    let third = t.export().deliver(&id).await.unwrap();
    assert_eq!((third.batches, third.events, third.error), (1, 3, None));
    let requests = t.receiver.requests();
    assert_eq!(requests.len(), 3);
    // The same events under the same id each time, so receivers can drop
    // a duplicate.
    let ids: Vec<_> = requests.iter().map(|r| header(r, "webhook-id")).collect();
    assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
    let events = t.receiver.events();
    assert_eq!(seqs(&events[0]), seqs(&events[2]));
    let view = t.view(&id).await;
    assert_eq!(view.status, DeliveryStatus::UpToDate);
    assert_eq!(
        (
            view.failing_since,
            view.last_error,
            view.consecutive_failures
        ),
        (None, None, 0)
    );
}

#[tokio::test]
async fn a_retry_is_the_same_batch_when_newer_events_were_written_meanwhile() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    t.record(2, "proxy.inject").await;
    t.receiver.answer(Ok(503));
    t.export().deliver(&id).await.unwrap();

    // The receiver may have stored the first attempt; more events arrive
    // before the retry.
    t.record(4, "proxy.inject").await;
    let retry = t.export().deliver(&id).await.unwrap();
    assert_eq!((retry.batches, retry.events, retry.error), (2, 7, None));
    let requests = t.receiver.requests();
    let ids: Vec<_> = requests.iter().map(|r| header(r, "webhook-id")).collect();
    assert_eq!(ids[0], ids[1], "the retry keeps its id: {ids:?}");
    assert_ne!(ids[1], ids[2], "the newer events are a batch of their own");
    let events = t.receiver.events();
    assert_eq!(seqs(&events[0]), seqs(&events[1]));
    let all: Vec<u64> = events[1..].iter().flat_map(|b| seqs(b)).collect();
    assert_eq!(
        all.len(),
        7,
        "nothing skipped or repeated after the retry: {all:?}"
    );
    assert_eq!(
        t.store
            .get_audit_destination(&id)
            .await
            .unwrap()
            .unwrap()
            .delivery
            .retry_until,
        None
    );
}

#[tokio::test]
async fn a_retry_keeps_its_id_across_pausing_renaming_and_a_new_secret() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    t.record(2, "proxy.inject").await;
    t.receiver.answer(Ok(503));
    t.export().deliver(&id).await.unwrap();

    // None of these changes which events the batch holds.
    t.export().set_paused(&admin(), &id, true).await.unwrap();
    t.export().set_paused(&admin(), &id, false).await.unwrap();
    t.export().rotate_secret(&admin(), &id).await.unwrap();
    let mut renamed = input();
    renamed.name = "Renamed".into();
    t.export().update(&admin(), &id, renamed).await.unwrap();

    t.export().deliver(&id).await.unwrap();
    let requests = t.receiver.requests();
    assert_eq!(
        header(&requests[0], "webhook-id"),
        header(&requests[1], "webhook-id"),
        "the receiver can drop the retry as a duplicate"
    );
    let events = t.receiver.events();
    assert_eq!(seqs(&events[0]), seqs(&events[1]));
}

#[tokio::test]
async fn a_filter_change_makes_the_retry_a_new_batch() {
    for (before, after) in [
        (vec![], vec!["proxy.".to_string()]),
        (vec!["proxy.".to_string()], vec![]),
    ] {
        let t = setup().await;
        let mut settings = input();
        settings.filter.action_prefixes = before;
        let id = t
            .export()
            .create(
                &admin(),
                CreateAuditDestination {
                    destination: settings.clone(),
                    start_at: StartAt::Oldest,
                },
            )
            .await
            .unwrap()
            .destination
            .id;
        t.record(2, "proxy.inject").await;
        t.receiver.answer(Ok(503));
        t.export().deliver(&id).await.unwrap();
        // Another filter selects other events from the same range, which
        // must not go out under the id of the batch the receiver may have.
        settings.filter.action_prefixes = after;
        t.export().update(&admin(), &id, settings).await.unwrap();

        t.export().deliver(&id).await.unwrap();
        let requests = t.receiver.requests();
        assert_ne!(
            header(&requests[0], "webhook-id"),
            header(&requests[1], "webhook-id")
        );
        assert_ne!(seqs(&t.receiver.events()[0]), seqs(&t.receiver.events()[1]));
    }
}

#[test]
fn a_filter_fingerprint_ignores_the_order_it_was_typed_in() {
    assert_eq!(filter_fingerprint(&AuditFilter::default()), None);
    let filter = |prefixes: &[&str], outcomes: Vec<AuditOutcome>| AuditFilter {
        action_prefixes: prefixes.iter().map(ToString::to_string).collect(),
        outcomes,
        vault_ids: vec![],
    };
    let a = filter(
        &["proxy.", "credential."],
        vec![AuditOutcome::Failure, AuditOutcome::Denied],
    );
    let b = filter(
        &["credential.", "proxy."],
        vec![AuditOutcome::Denied, AuditOutcome::Failure],
    );
    assert_eq!(filter_fingerprint(&a), filter_fingerprint(&b));
    assert!(filter_fingerprint(&a).is_some());
    // An item cannot move between lists, or merge with its neighbour,
    // and keep the fingerprint.
    assert_ne!(
        filter_fingerprint(&filter(&["proxy."], vec![])),
        filter_fingerprint(&filter(&["proxy.", ""], vec![]))
    );
    assert_ne!(
        filter_fingerprint(&filter(&["ab"], vec![])),
        filter_fingerprint(&filter(&["a", "b"], vec![]))
    );
}

#[tokio::test]
async fn failure_reasons_never_quote_the_receivers_url() {
    let t = setup().await;
    let mut with_token = input();
    with_token.url = "https://Ingest.Example.com/receiver/INGESTTOKEN?key=QUERYTOKEN".into();
    let id = t
        .export()
        .create(
            &admin(),
            CreateAuditDestination {
                destination: with_token.clone(),
                start_at: StartAt::Now,
            },
        )
        .await
        .unwrap()
        .destination
        .id;
    // Stored, and so sent, normalized; a transport quotes what it was sent,
    // as reqwest does, and may quote it twice.
    let sent = t.view(&id).await.url;
    assert_eq!(sent, Url::parse(&with_token.url).unwrap().to_string());
    for quoted in [sent.clone(), format!("{sent} (redirected from {sent})")] {
        let reason = format!("error sending request for url ({quoted})");
        t.receiver.answer(Err(WebhookError {
            reason: reason.clone(),
        }));
        let pass = t.export().deliver(&id).await.unwrap();
        t.receiver.answer(Err(WebhookError { reason }));
        let test = t.export().test(&admin(), &id).await.unwrap();
        let view = t.view(&id).await;
        for shown in [pass.error, test.error, view.last_error] {
            let shown = shown.unwrap();
            assert!(
                !shown.contains("TOKEN") && shown.contains("(https://ingest.example.com"),
                "{shown}"
            );
        }
    }
}

#[test]
fn without_url_leaves_other_reasons_alone() {
    assert_eq!(
        without_url("the receiver answered 503".into(), URL),
        "the receiver answered 503"
    );
    assert_eq!(
        without_url("bad: not a url".into(), "not a url"),
        "bad: an unreadable URL"
    );
}

#[tokio::test]
async fn audit_details_name_the_receiver_without_its_path_or_query() {
    let t = setup().await;
    let mut with_token = input();
    with_token.url =
        "https://ingest.example.com/receiver/v1/http/INGESTTOKEN?key=QUERYTOKEN".into();
    let id = t
        .export()
        .create(
            &admin(),
            CreateAuditDestination {
                destination: with_token.clone(),
                start_at: StartAt::Now,
            },
        )
        .await
        .unwrap()
        .destination
        .id;
    with_token.name = "Renamed".into();
    t.export().update(&admin(), &id, with_token).await.unwrap();
    for action in ["audit_export.create", "audit_export.update"] {
        let events = t.audit(action).await;
        assert_eq!(events.len(), 1, "{action}");
        assert_eq!(
            events[0].detail.get("url").map(String::as_str),
            Some("https://ingest.example.com")
        );
        let all = format!("{:?}", events[0]);
        assert!(
            !all.contains("INGESTTOKEN") && !all.contains("QUERYTOKEN"),
            "{all}"
        );
    }
    // The admin-only view still shows the whole URL, so it can be checked.
    assert!(t.view(&id).await.url.contains("INGESTTOKEN"));
}

#[tokio::test]
async fn a_receiver_failing_for_long_shows_as_failing() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    let long_ago = Utc::now() - Duration::seconds(FAILING_AFTER_SECS + 1);
    t.store
        .record_audit_delivery_failure(&id, 0, 1, "the receiver answered 500", long_ago)
        .await
        .unwrap();
    assert_eq!(t.view(&id).await.status, DeliveryStatus::Failing);
}

#[tokio::test]
async fn large_backlogs_go_in_batches_without_gaps() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Oldest))
        .await
        .unwrap()
        .destination
        .id;
    t.record(1199, "proxy.inject").await;
    let pass = t.export().deliver(&id).await.unwrap();
    assert_eq!((pass.batches, pass.events), (3, 1200));
    let sizes: Vec<_> = t.receiver.events().iter().map(Vec::len).collect();
    assert_eq!(sizes, vec![500, 500, 200]);
    let all: Vec<u64> = t.receiver.events().iter().flat_map(|b| seqs(b)).collect();
    assert_eq!(all, (1..=1200).collect::<Vec<u64>>());
}

#[tokio::test]
async fn a_batch_stays_under_the_body_limit() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    // About 100 KiB each: twelve would pass the 1 MiB limit.
    let big = "x".repeat(100 * 1024);
    let events: Vec<_> = (0..12)
        .map(|_| {
            AuditEvent::new("node:test", "proxy.inject", AuditOutcome::Success)
                .detail("pad", big.clone())
        })
        .collect();
    t.store.record(&events).await.unwrap();
    let pass = t.export().deliver(&id).await.unwrap();
    assert_eq!(pass.events, 13);
    assert!(pass.batches >= 2);
    for request in t.receiver.requests() {
        assert!(request.body.len() <= MAX_BODY, "{}", request.body.len());
    }
}

#[tokio::test]
async fn the_filter_passes_over_events_without_sending_them() {
    let t = setup().await;
    let vault = Vault {
        id: VaultId::new(),
        name: "prod".into(),
        scope: Scope::parse("prod").unwrap(),
        created_at: Utc::now(),
    };
    t.store.insert_vault(vault.clone(), &[]).await.unwrap();
    let mut req = create(StartAt::Now);
    req.destination.filter = AuditFilter {
        action_prefixes: vec!["credential.".into()],
        outcomes: vec![],
        vault_ids: vec![vault.id],
    };
    let id = t
        .export()
        .create(&admin(), req)
        .await
        .unwrap()
        .destination
        .id;
    t.record(5, "proxy.inject").await;
    let wanted =
        AuditEvent::new("user:x", "credential.create", AuditOutcome::Success).vault(vault.id);
    let other_vault =
        AuditEvent::new("user:x", "credential.create", AuditOutcome::Success).vault(VaultId::new());
    t.store
        .record(&[wanted.clone(), other_vault])
        .await
        .unwrap();

    let pass = t.export().deliver(&id).await.unwrap();
    assert_eq!((pass.batches, pass.events, pass.passed_over), (1, 1, 7));
    assert_eq!(t.receiver.events()[0][0]["id"], wanted.id.to_string());
    assert_eq!(t.view(&id).await.behind, 0);

    // Only passed-over events: the cursor moves, nothing is sent.
    t.record(3, "proxy.inject").await;
    let pass = t.export().deliver(&id).await.unwrap();
    assert_eq!((pass.batches, pass.passed_over), (0, 3));
    assert_eq!(t.receiver.requests().len(), 1);
    assert_eq!(t.view(&id).await.behind, 0);
}

#[tokio::test]
async fn ndjson_puts_one_event_per_line() {
    let t = setup().await;
    let mut req = create(StartAt::Now);
    req.destination.format = PayloadFormat::Ndjson;
    let id = t
        .export()
        .create(&admin(), req)
        .await
        .unwrap()
        .destination
        .id;
    t.record(2, "proxy.inject").await;
    t.export().deliver(&id).await.unwrap();
    let request = &t.receiver.requests()[0];
    assert_eq!(
        header(request, "content-type"),
        Some("application/x-ndjson")
    );
    let text = String::from_utf8(request.body.clone()).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert!(text.ends_with('\n'));
    assert_eq!(lines[2]["action"], "proxy.inject");
}

#[tokio::test]
async fn paused_destinations_send_nothing_until_resumed() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    let view = t.export().set_paused(&admin(), &id, true).await.unwrap();
    assert_eq!(view.status, DeliveryStatus::Paused);
    t.record(2, "proxy.inject").await;
    assert_eq!(
        t.export().deliver(&id).await.unwrap(),
        DeliveryPass::default()
    );
    assert!(t.receiver.requests().is_empty());
    t.export().set_paused(&admin(), &id, false).await.unwrap();
    // Creation, pause, two events, resume: nothing lost while paused.
    assert_eq!(t.export().deliver(&id).await.unwrap().events, 5);
    assert_eq!(t.audit("audit_export.pause").await.len(), 1);
    assert_eq!(t.audit("audit_export.resume").await.len(), 1);
}

#[tokio::test]
async fn skipping_drops_the_backlog_and_is_audited() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    t.receiver.answer(Ok(500));
    t.record(10, "proxy.inject").await;
    t.export().deliver(&id).await.unwrap();
    assert_eq!(t.view(&id).await.behind, 11);

    let skipped = t.export().skip_to_now(&admin(), &id).await.unwrap();
    assert_eq!(skipped.skipped, 11);
    assert_eq!(t.view(&id).await.failing_since, None);
    let event = &t.audit("audit_export.skip").await[0];
    assert_eq!(event.detail["skipped"], "11");
    // The skip's own event is the only one sent afterwards.
    let pass = t.export().deliver(&id).await.unwrap();
    assert_eq!(pass.events, 1);
    assert_eq!(t.receiver.events()[1][0]["action"], "audit_export.skip");
}

#[tokio::test]
async fn a_new_destination_starts_now_or_with_the_history() {
    let t = setup().await;
    t.record(4, "proxy.inject").await;
    let now = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap();
    assert_eq!(now.destination.behind, 1);
    let mut oldest = create(StartAt::Oldest);
    oldest.destination.name = "Archive".into();
    let oldest = t.export().create(&admin(), oldest).await.unwrap();
    assert_eq!(oldest.destination.behind, 6);
    assert_eq!(
        t.export()
            .deliver(&oldest.destination.id)
            .await
            .unwrap()
            .events,
        6
    );
}

#[tokio::test]
async fn the_auth_header_is_sent_kept_replaced_and_cleared() {
    let t = setup().await;
    let mut req = create(StartAt::Now);
    req.destination.auth_header_name = Some("Authorization".into());
    req.destination.auth_header_value = Some("Splunk 0000-token".into());
    let created = t.export().create(&admin(), req).await.unwrap();
    let id = created.destination.id;
    assert!(created.destination.has_auth_header);
    let shown = serde_json::to_string(&created.destination).unwrap();
    assert!(!shown.contains("0000-token") && !shown.contains(&created.signing_secret));

    t.export().deliver(&id).await.unwrap();
    assert_eq!(
        header(&t.receiver.requests()[0], "authorization"),
        Some("Splunk 0000-token")
    );

    // Same name, no value: kept.
    let mut keep = input();
    keep.auth_header_name = Some("Authorization".into());
    assert!(
        t.export()
            .update(&admin(), &id, keep)
            .await
            .unwrap()
            .has_auth_header
    );
    // Another name needs its value.
    let mut renamed = input();
    renamed.auth_header_name = Some("DD-API-KEY".into());
    assert!(matches!(
        t.export().update(&admin(), &id, renamed).await,
        Err(ControlError::Validation { .. })
    ));
    // Cleared.
    let mut cleared = input();
    cleared.clear_auth_header = true;
    let view = t.export().update(&admin(), &id, cleared).await.unwrap();
    assert!(!view.has_auth_header && view.auth_header_name.is_none());
    t.record(1, "proxy.inject").await;
    t.export().deliver(&id).await.unwrap();
    assert_eq!(header(&t.receiver.requests()[1], "authorization"), None);
}

#[tokio::test]
async fn updating_settings_keeps_the_cursor() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    t.record(3, "proxy.inject").await;
    t.export().deliver(&id).await.unwrap();
    let mut renamed = input();
    renamed.name = "Security lake".into();
    let view = t.export().update(&admin(), &id, renamed).await.unwrap();
    assert_eq!((view.name.as_str(), view.behind), ("Security lake", 1));
    assert_eq!(t.export().deliver(&id).await.unwrap().events, 1);
}

#[tokio::test]
async fn a_rotated_secret_signs_from_then_on() {
    let t = setup().await;
    let created = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap();
    let id = created.destination.id;
    let rotated = t.export().rotate_secret(&admin(), &id).await.unwrap();
    assert_ne!(rotated.signing_secret, created.signing_secret);
    t.export().deliver(&id).await.unwrap();
    let request = &t.receiver.requests()[0];
    let timestamp: i64 = header(request, "webhook-timestamp")
        .unwrap()
        .parse()
        .unwrap();
    let expected = webhook::sign(
        &rotated.signing_secret,
        header(request, "webhook-id").unwrap(),
        timestamp,
        &request.body,
    )
    .unwrap();
    assert_eq!(
        header(request, "webhook-signature"),
        Some(expected.as_str())
    );
    assert_eq!(t.audit("audit_export.rotate_secret").await.len(), 1);
}

#[tokio::test]
async fn a_test_event_reports_the_answer_without_moving_the_cursor() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    let ok = t.export().test(&admin(), &id).await.unwrap();
    assert_eq!((ok.delivered, ok.status, ok.error), (true, Some(200), None));
    let body: Value = serde_json::from_slice(&t.receiver.requests()[0].body).unwrap();
    assert_eq!(body["events"][0]["action"], "audit_export.test");
    assert_eq!(body["events"][0]["seq"], 0);

    t.receiver.answer(Ok(401));
    let refused = t.export().test(&admin(), &id).await.unwrap();
    assert_eq!(refused.status, Some(401));
    assert_eq!(refused.error.as_deref(), Some("the receiver answered 401"));
    let tests = t.audit("audit_export.test").await;
    assert_eq!(tests.len(), 2);
    assert!(tests.iter().any(|e| e.outcome == AuditOutcome::Failure));
    // Creation plus the two test records are still waiting.
    assert_eq!(t.view(&id).await.behind, 3);
}

#[tokio::test]
async fn settings_are_checked() {
    let t = setup().await;
    let bad = |f: fn(&mut AuditDestinationInput)| {
        let mut req = create(StartAt::Now);
        f(&mut req.destination);
        req
    };
    let cases: Vec<(&str, CreateAuditDestination)> = vec![
        (
            "plain http",
            bad(|d| d.url = "http://siem.example.test/x".into()),
        ),
        (
            "credentials in the URL",
            bad(|d| d.url = "https://u:p@siem.example.test/".into()),
        ),
        ("not a URL", bad(|d| d.url = "siem".into())),
        ("empty name", bad(|d| d.name = "  ".into())),
        (
            "reserved header",
            bad(|d| {
                d.auth_header_name = Some("Content-Type".into());
                d.auth_header_value = Some("x".into());
            }),
        ),
        (
            "signature header",
            bad(|d| {
                d.auth_header_name = Some("webhook-signature".into());
                d.auth_header_value = Some("x".into());
            }),
        ),
        (
            "header without a value",
            bad(|d| d.auth_header_name = Some("X-Token".into())),
        ),
        (
            "value without a header",
            bad(|d| d.auth_header_value = Some("x".into())),
        ),
        (
            "newline in a value",
            bad(|d| {
                d.auth_header_name = Some("X-Token".into());
                d.auth_header_value = Some("a\nb".into());
            }),
        ),
        (
            "bad action prefix",
            bad(|d| d.filter.action_prefixes = vec!["Proxy Inject".into()]),
        ),
        (
            "unknown vault",
            bad(|d| d.filter.vault_ids = vec![VaultId::new()]),
        ),
    ];
    for (what, req) in cases {
        assert!(
            matches!(
                t.export().create(&admin(), req).await,
                Err(ControlError::Validation { .. })
            ),
            "{what} should be refused"
        );
    }
    // http to this machine is fine (a local collector).
    let mut local = create(StartAt::Now);
    local.destination.name = "Local collector".into();
    local.destination.url = "http://127.0.0.1:8088/ingest".into();
    t.export().create(&admin(), local).await.unwrap();
    // Names are unique.
    t.export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap();
    assert!(matches!(
        t.export().create(&admin(), create(StartAt::Now)).await,
        Err(ControlError::Conflict { .. })
    ));
}

#[tokio::test]
async fn an_instance_has_at_most_ten_destinations() {
    let t = setup().await;
    for i in 0..MAX_AUDIT_DESTINATIONS {
        let mut req = create(StartAt::Now);
        req.destination.name = format!("d{i}");
        t.export().create(&admin(), req).await.unwrap();
    }
    let mut req = create(StartAt::Now);
    req.destination.name = "one too many".into();
    assert!(matches!(
        t.export().create(&admin(), req).await,
        Err(ControlError::Validation { .. })
    ));
}

#[tokio::test]
async fn only_admins_manage_destinations_and_changes_need_step_up() {
    let t = setup().await;
    let created = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap();
    let id = created.destination.id;
    let mut editor = admin();
    editor.principal.role = Role::Editor;
    assert!(matches!(
        t.export().list(&editor).await,
        Err(ControlError::Forbidden { .. })
    ));
    assert!(matches!(
        t.export().create(&editor, create(StartAt::Now)).await,
        Err(ControlError::Forbidden { .. })
    ));
    let mut stale = admin();
    stale.step_up_at = Some(Utc::now() - chrono::Duration::hours(1));
    // Reading needs no fresh second factor; changing does.
    t.export().list(&stale).await.unwrap();
    let step_up =
        |r: Result<(), ControlError>| matches!(r, Err(ControlError::StepUpRequired { .. }));
    assert!(step_up(
        t.export().update(&stale, &id, input()).await.map(drop)
    ));
    assert!(step_up(t.export().delete(&stale, &id).await));
    assert!(step_up(
        t.export().rotate_secret(&stale, &id).await.map(drop)
    ));
    assert!(step_up(t.export().skip_to_now(&stale, &id).await.map(drop)));
    assert!(step_up(
        t.export().set_paused(&stale, &id, true).await.map(drop)
    ));
    assert!(step_up(t.export().test(&stale, &id).await.map(drop)));

    t.export().delete(&admin(), &id).await.unwrap();
    assert!(t.export().list(&admin()).await.unwrap().is_empty());
    assert!(matches!(
        t.export().get(&admin(), &id).await,
        Err(ControlError::NotFound { .. })
    ));
    assert_eq!(t.audit("audit_export.create").await.len(), 1);
    assert_eq!(t.audit("audit_export.delete").await.len(), 1);
}

#[tokio::test]
async fn secrets_never_appear_in_debug_output() {
    let t = setup().await;
    let mut req = create(StartAt::Now);
    req.destination.auth_header_name = Some("X-Token".into());
    req.destination.auth_header_value = Some("header-secret-value".into());
    assert!(!format!("{req:?}").contains("header-secret-value"));
    let created = t.export().create(&admin(), req).await.unwrap();
    assert!(!format!("{created:?}").contains(&created.signing_secret));
    let stored = t
        .store
        .get_audit_destination(&created.destination.id)
        .await
        .unwrap()
        .unwrap();
    let shown = format!("{stored:?}");
    assert!(shown.contains("***") && !shown.contains("header-secret-value"));
}

#[tokio::test]
async fn the_sender_delivers_in_the_background_and_backs_off() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    t.receiver.answer(Ok(500));
    let export = t.export().clone();
    let sender = tokio::spawn(async move { export.run().await });
    t.record(1, "proxy.inject").await;
    // The first attempt fails; the retry waits about a second, then gets
    // through.
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
    loop {
        if t.view(&id).await.status == DeliveryStatus::UpToDate {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "not delivered in time"
        );
        tokio::time::sleep(StdDuration::from_millis(100)).await;
    }
    sender.abort();
    let requests = t.receiver.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        header(&requests[0], "webhook-id"),
        header(&requests[1], "webhook-id")
    );
}

#[tokio::test]
async fn new_settings_or_a_new_secret_are_tried_without_waiting_out_the_backoff() {
    let t = setup().await;
    let id = t
        .export()
        .create(&admin(), create(StartAt::Now))
        .await
        .unwrap()
        .destination
        .id;
    let backed_off = || {
        for _ in 0..10 {
            t.export().note_result(&id, true);
        }
        assert!(!t.export().due(&id, Instant::now()));
    };

    backed_off();
    t.export().update(&admin(), &id, input()).await.unwrap();
    assert!(t.export().due(&id, Instant::now()), "after new settings");

    backed_off();
    t.export().rotate_secret(&admin(), &id).await.unwrap();
    assert!(t.export().due(&id, Instant::now()), "after a new secret");

    // A test request changes nothing the sender uses.
    backed_off();
    t.export().test(&admin(), &id).await.unwrap();
    assert!(!t.export().due(&id, Instant::now()));
}

#[test]
fn backoff_doubles_up_to_five_minutes() {
    let secs: Vec<u64> = [1, 2, 3, 4, 9, 10, 30]
        .iter()
        .map(|n| backoff_delay(*n).as_secs())
        .collect();
    assert_eq!(secs, vec![1, 2, 4, 8, 256, 300, 300]);
}
