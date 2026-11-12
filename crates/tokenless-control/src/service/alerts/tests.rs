// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{TimeDelta, Utc};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Principal, PrincipalKind, Role};
use tokenless_core::ids::{AlertId, NodeId, SessionId, VaultId};
use tokenless_core::snapshot::{QUARANTINE_ACTION, TUNNEL_CUT_ACTION};

use super::*;
use crate::error::ControlError;
use crate::memory::MemoryStore;
use crate::model::{AuditQuery, Settings};
use crate::store::{AuditSink, PolicyStore, RbacAuthorizer};

fn service(store: &Arc<MemoryStore>) -> AlertService {
    AlertService::new(
        store.clone(),
        store.clone(),
        Guard::new(Arc::new(RbacAuthorizer), 300),
    )
}

fn node(name: &str) -> Node {
    Node {
        id: NodeId::new(),
        name: name.into(),
        seal_public_key: String::new(),
        cert_serial: String::new(),
        cert_not_after: Utc::now(),
        enrolled_at: Utc::now(),
        last_seen_at: None,
        revoked_at: None,
        scoped_rules: false,
    }
}

fn user(role: Role, vault: Option<VaultId>) -> Caller {
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: format!("user:{role}"),
            role,
            vault,
        },
        step_up_at: Some(Utc::now()),
        second_factor: true,
        launch: None,
    }
}

fn traffic(vault: VaultId, session: SessionId, outcome: AuditOutcome) -> AuditEvent {
    let mut e = AuditEvent::new("node:x", "proxy.deny", outcome)
        .detail("scope", format!("vault:{vault}"))
        .detail("session_id", session.to_string())
        .detail("host", "internal.example.com:443")
        .detail("label.agent", "builder");
    e.vault_id = Some(vault);
    e
}

fn refused_at(vault: VaultId, session: SessionId, secs_ago: i64) -> AuditEvent {
    let mut e = traffic(vault, session, AuditOutcome::Denied);
    e.at = Utc::now() - TimeDelta::seconds(secs_ago);
    e
}

/// A session the store knows, as one minted for an agent is.
async fn minted(store: &MemoryStore, vault: VaultId, expires_in_secs: i64) -> SessionId {
    let now = Utc::now();
    let session = crate::model::ProxySession {
        id: SessionId::new(),
        vault_id: vault,
        rule_ids: vec![],
        bundle: None,
        labels: Default::default(),
        request_limit: None,
        node_id: None,
        created_by: "user:test".into(),
        created_at: now,
        expires_at: now + TimeDelta::seconds(expires_in_secs),
        revoked_at: None,
    };
    store.insert_session(session.clone(), &[]).await.unwrap();
    session.id
}

async fn all(svc: &AlertService) -> Vec<Alert> {
    svc.list(
        &user(Role::Admin, None),
        AlertFilter::default(),
        PageRequest::new(Some(1), Some(100)),
    )
    .await
    .unwrap()
    .items
}

async fn set_alerts(store: &MemoryStore, alerts: AlertSettings) {
    store
        .put_settings(
            Settings {
                alerts,
                ..Settings::default()
            },
            &[],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_quarantine_raises_one_alert_and_an_audit_event() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let (vault, session) = (VaultId::new(), SessionId::new());
    let edge = node("edge-1");
    let mut report = AuditEvent::new("node:x", QUARANTINE_ACTION, AuditOutcome::Denied)
        .detail("session_id", session.to_string())
        .detail("refusals", "20")
        .detail("window_secs", "300")
        .detail("label.agent", "builder");
    report.vault_id = Some(vault);
    svc.observe(&edge, std::slice::from_ref(&report)).await;
    svc.observe(&edge, &[report]).await;

    let alerts = all(&svc).await;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    let a = &alerts[0];
    assert_eq!(a.kind, AlertKind::Quarantine);
    assert_eq!(a.session_id, Some(session));
    assert_eq!(a.vault_id, Some(vault));
    assert_eq!(a.node_id, Some(edge.id));
    assert!(
        a.summary
            .contains("cut off by proxy 'edge-1' after 20 refusals in 300s"),
        "{}",
        a.summary
    );
    assert_eq!(a.detail["label.agent"], "builder");
    assert_eq!(a.detail["refusals"], "20");

    let raised = store
        .query(&AuditQuery {
            action_prefix: Some("alert.raised".into()),
            page: PageRequest::new(Some(1), Some(10)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(raised.total, 1);
    let event = &raised.items[0];
    assert_eq!(event.actor, format!("node:{}", edge.id));
    assert_eq!(event.vault_id, Some(vault));
    assert_eq!(
        event.target.as_deref(),
        Some(format!("alert:{}", a.id).as_str())
    );
    assert_eq!(event.detail["kind"], "quarantine");
    assert_eq!(event.detail["session_id"], session.to_string());
}

#[tokio::test]
async fn refusals_raise_an_alert_at_the_threshold_within_the_window() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let (vault, session) = (VaultId::new(), SessionId::new());
    let edge = node("edge-1");
    // The default: 10 refusals in 300s. Nine, then the window passes.
    let early: Vec<_> = (0..9).map(|_| refused_at(vault, session, 400)).collect();
    svc.observe(&edge, &early).await;
    let allowed: Vec<_> = (0..20)
        .map(|_| traffic(vault, session, AuditOutcome::Success))
        .collect();
    svc.observe(&edge, &allowed).await;
    let late: Vec<_> = (0..9).map(|_| refused_at(vault, session, 0)).collect();
    svc.observe(&edge, &late).await;
    assert!(
        all(&svc).await.is_empty(),
        "nine in each window is below 10"
    );

    svc.observe(&edge, &[refused_at(vault, session, 0)]).await;
    let alerts = all(&svc).await;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, AlertKind::Refusals);
    assert!(
        alerts[0].summary.contains(
            "refused 10 times within 300s; the last was proxy.deny to internal.example.com:443"
        ),
        "{}",
        alerts[0].summary
    );

    // A lower threshold mid-window fires on the next refusal.
    let other = SessionId::new();
    let some: Vec<_> = (0..5).map(|_| refused_at(vault, other, 0)).collect();
    svc.observe(&edge, &some).await;
    set_alerts(
        &store,
        AlertSettings {
            refusals: Some(RefusalThreshold {
                refusals: 3,
                window_secs: 300,
            }),
            new_proxy: true,
        },
    )
    .await;
    svc.observe(&edge, &[refused_at(vault, other, 0)]).await;
    assert_eq!(all(&svc).await.len(), 2);

    // More refusals, even in a new window, raise nothing new for either.
    let more: Vec<_> = (0..30).map(|_| refused_at(vault, session, 0)).collect();
    svc.observe(&edge, &more).await;
    assert_eq!(all(&svc).await.len(), 2);
}

#[tokio::test]
async fn tunnels_a_proxy_cut_are_not_refusals() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let (vault, session) = (VaultId::new(), SessionId::new());
    // A busy session's tunnels, all cut when its lease ran out.
    let cut: Vec<_> = (0..30)
        .map(|_| {
            let mut e = refused_at(vault, session, 0);
            e.action = TUNNEL_CUT_ACTION.into();
            e
        })
        .collect();
    svc.observe(&node("edge-1"), &cut).await;
    assert!(all(&svc).await.is_empty());
}

#[tokio::test]
async fn a_session_used_through_a_second_proxy_raises_an_alert() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let vault = VaultId::new();
    let (session, other) = (
        minted(&store, vault, 900).await,
        minted(&store, vault, 900).await,
    );
    let (first, second) = (node("edge-1"), node("edge-2"));
    svc.observe(&first, &[traffic(vault, session, AuditOutcome::Success)])
        .await;
    svc.observe(&second, &[traffic(vault, other, AuditOutcome::Success)])
        .await;
    svc.observe(&first, &[traffic(vault, session, AuditOutcome::Success)])
        .await;
    assert!(all(&svc).await.is_empty(), "each session kept to one proxy");

    svc.observe(&second, &[traffic(vault, session, AuditOutcome::Success)])
        .await;
    let alerts = all(&svc).await;
    assert_eq!(alerts.len(), 1);
    let a = &alerts[0];
    assert_eq!(a.kind, AlertKind::NewProxy);
    assert_eq!(a.node_id, Some(second.id));
    assert_eq!(a.detail["first_node"], "edge-1");
    assert_eq!(a.detail["first_node_id"], first.id.to_string());
    assert!(a
        .summary
        .contains("through proxy 'edge-2' after first using 'edge-1'"));
}

#[tokio::test]
async fn a_session_the_control_plane_never_minted_is_not_tracked() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let (vault, made_up) = (VaultId::new(), SessionId::new());
    for edge in [node("edge-1"), node("edge-2")] {
        svc.observe(&edge, &[traffic(vault, made_up, AuditOutcome::Success)])
            .await;
    }
    assert!(all(&svc).await.is_empty());
    let signals = svc.signals.lock().unwrap();
    assert!(signals.first_proxy.is_empty());
}

#[tokio::test]
async fn a_full_first_proxy_map_forgets_expired_sessions_and_keeps_alerting() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let vault = VaultId::new();
    let (first, second) = (node("edge-1"), node("edge-2"));
    {
        let mut signals = svc.signals.lock().unwrap();
        let expired = Utc::now() - TimeDelta::seconds(1);
        for _ in 0..MAX_TRACKED_SESSIONS {
            signals.first_proxy.insert(
                SessionId::new(),
                FirstProxy {
                    node_id: first.id,
                    name: first.name.clone(),
                    expires_at: expired,
                },
            );
        }
    }
    let session = minted(&store, vault, 900).await;
    svc.observe(&first, &[traffic(vault, session, AuditOutcome::Success)])
        .await;
    svc.observe(&second, &[traffic(vault, session, AuditOutcome::Success)])
        .await;
    let alerts = all(&svc).await;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].kind, AlertKind::NewProxy);
    assert_eq!(svc.signals.lock().unwrap().first_proxy.len(), 1);
}

#[tokio::test]
async fn signals_turned_off_raise_nothing_but_a_quarantine_still_does() {
    let store = Arc::new(MemoryStore::new());
    set_alerts(
        &store,
        AlertSettings {
            refusals: None,
            new_proxy: false,
        },
    )
    .await;
    let svc = service(&store);
    let (vault, session) = (VaultId::new(), SessionId::new());
    let many: Vec<_> = (0..50).map(|_| refused_at(vault, session, 0)).collect();
    svc.observe(&node("edge-1"), &many).await;
    svc.observe(&node("edge-2"), &many).await;
    assert!(all(&svc).await.is_empty());

    let mut report = AuditEvent::new("node:x", QUARANTINE_ACTION, AuditOutcome::Denied)
        .detail("session_id", session.to_string());
    report.vault_id = Some(vault);
    svc.observe(&node("edge-1"), &[report]).await;
    let alerts = all(&svc).await;
    assert_eq!(alerts.len(), 1);
    assert!(
        alerts[0].summary.contains("after repeated refusals in ?s"),
        "a report without its counts still reads: {}",
        alerts[0].summary
    );
}

#[tokio::test]
async fn events_without_a_session_are_ignored() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let events = [
        AuditEvent::new("node:x", "proxy.deny", AuditOutcome::Denied),
        AuditEvent::new("node:x", "proxy.deny", AuditOutcome::Denied)
            .detail("session_id", "not-a-session"),
    ];
    for _ in 0..20 {
        svc.observe(&node("edge-1"), &events).await;
    }
    assert!(all(&svc).await.is_empty());
}

#[test]
fn tracking_drops_old_windows_when_full_and_then_refuses_new_sessions() {
    let now = Utc::now();
    let mut signals = Signals::default();
    let stale = now - TimeDelta::seconds(i64::from(RefusalThreshold::MAX_WINDOW_SECS) + 1);
    for i in 0..MAX_TRACKED_SESSIONS {
        signals.refusals.insert(
            SessionId::new(),
            Window {
                start: if i % 2 == 0 { stale } else { now },
                refusals: 1,
                alerted: false,
            },
        );
    }
    assert!(signals.room_for_refusals(now));
    assert_eq!(signals.refusals.len(), MAX_TRACKED_SESSIONS / 2);
    while signals.refusals.len() < MAX_TRACKED_SESSIONS {
        signals.refusals.insert(
            SessionId::new(),
            Window {
                start: now,
                refusals: 1,
                alerted: false,
            },
        );
    }
    assert!(!signals.room_for_refusals(now), "nothing old left to drop");
    assert_eq!(signals.refusals.len(), MAX_TRACKED_SESSIONS);
}

async fn raise_in(svc: &AlertService, vault: VaultId) -> Alert {
    let session = SessionId::new();
    let mut report = AuditEvent::new("node:x", QUARANTINE_ACTION, AuditOutcome::Denied)
        .detail("session_id", session.to_string());
    report.vault_id = Some(vault);
    svc.observe(&node("edge-1"), &[report]).await;
    all(svc)
        .await
        .into_iter()
        .find(|a| a.session_id == Some(session))
        .unwrap()
}

#[tokio::test]
async fn a_vault_bound_caller_sees_and_acknowledges_only_its_vault() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let (mine, theirs) = (VaultId::new(), VaultId::new());
    let own = raise_in(&svc, mine).await;
    let other = raise_in(&svc, theirs).await;
    let editor = user(Role::Editor, Some(mine));

    // Asking for another vault still lists only its own.
    let listed = svc
        .list(
            &editor,
            AlertFilter {
                vault_id: Some(theirs),
                ..AlertFilter::default()
            },
            PageRequest::new(Some(1), Some(100)),
        )
        .await
        .unwrap();
    assert_eq!(
        listed.items.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![own.id]
    );
    let summary = svc.summary(&editor).await.unwrap();
    assert_eq!(summary.open, 1);
    assert_eq!(summary.latest.map(|a| a.id), Some(own.id));
    let kinds: Vec<AlertKind> = summary.last_raised.iter().map(|l| l.kind).collect();
    assert_eq!(kinds, vec![AlertKind::Quarantine]);
    assert_eq!(summary.last_raised[0].at, own.raised_at);

    let err = svc.acknowledge(&editor, &other.id).await.unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { entity: "alert", id } if *id == other.id.to_string()),
        "another vault's alert is not found: {err:?}"
    );

    let seen = svc.acknowledge(&editor, &own.id).await.unwrap();
    assert_eq!(seen.acknowledged_by.as_deref(), Some("user:editor"));
    assert!(seen.acknowledged_at.is_some());
    // Again: kept as it was, no second audit event.
    let again = svc
        .acknowledge(&user(Role::Admin, None), &own.id)
        .await
        .unwrap();
    assert_eq!(again.acknowledged_by.as_deref(), Some("user:editor"));
    let acks = store
        .query(&AuditQuery {
            action_prefix: Some("alert.acknowledge".into()),
            page: PageRequest::new(Some(1), Some(10)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(acks.total, 1);
    assert_eq!(acks.items[0].actor, "user:editor");
    assert_eq!(acks.items[0].vault_id, Some(mine));
    assert_eq!(svc.summary(&editor).await.unwrap().open, 0);
}

#[tokio::test]
async fn a_viewer_sees_alerts_but_cannot_acknowledge_them() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let vault = VaultId::new();
    let alert = raise_in(&svc, vault).await;
    let viewer = user(Role::Viewer, Some(vault));
    assert_eq!(svc.summary(&viewer).await.unwrap().open, 1);
    let err = svc.acknowledge(&viewer, &alert.id).await.unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err:?}");
}

#[tokio::test]
async fn acknowledging_an_unknown_alert_names_it() {
    let store = Arc::new(MemoryStore::new());
    let svc = service(&store);
    let id = AlertId::new();
    let err = svc
        .acknowledge(&user(Role::Admin, None), &id)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { entity: "alert", id: missing } if *missing == id.to_string()),
        "{err:?}"
    );
}

#[test]
fn alert_settings_are_bounded_and_quieter_ones_loosen() {
    let threshold = |refusals, window_secs| AlertSettings {
        refusals: Some(RefusalThreshold {
            refusals,
            window_secs,
        }),
        new_proxy: true,
    };
    assert!(AlertSettings::default().validate().is_ok());
    for bad in [threshold(1, 300), threshold(10, 5), threshold(20_000, 300)] {
        let err = bad.validate().unwrap_err();
        assert!(
            matches!(&err, ControlError::Validation { .. })
                && err.to_string().contains("alerts.refusals null"),
            "{err}"
        );
    }
    let default = AlertSettings::default();
    assert!(!threshold(5, 300).loosens(&default), "stricter");
    assert!(
        !threshold(10, 600).loosens(&default),
        "same refusals over longer"
    );
    assert!(threshold(20, 300).loosens(&default));
    assert!(threshold(10, 60).loosens(&default));
    assert!(AlertSettings {
        refusals: None,
        ..default
    }
    .loosens(&default));
    assert!(AlertSettings {
        new_proxy: false,
        ..default
    }
    .loosens(&default));
    assert!(!default.loosens(&AlertSettings {
        refusals: None,
        new_proxy: false
    }));
}

#[tokio::test]
async fn quieter_alerts_need_a_step_up_and_bad_ones_are_refused() {
    let (store, cs) = crate::service::testing::services().await;
    let admin = |step_up_age: i64| Caller {
        step_up_at: Some(Utc::now() - TimeDelta::seconds(step_up_age)),
        ..user(Role::Admin, None)
    };
    let with = |alerts: AlertSettings| Settings {
        alerts,
        ..Settings::default()
    };
    let err = cs
        .policy
        .put_settings(
            &admin(0),
            with(AlertSettings {
                refusals: Some(RefusalThreshold {
                    refusals: 1,
                    window_secs: 300,
                }),
                new_proxy: true,
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ControlError::Validation { .. }), "{err:?}");

    // Stricter needs no fresh step-up.
    let stricter = AlertSettings {
        refusals: Some(RefusalThreshold {
            refusals: 5,
            window_secs: 300,
        }),
        new_proxy: true,
    };
    cs.policy
        .put_settings(&admin(3600), with(stricter))
        .await
        .unwrap();
    for quieter in [
        AlertSettings {
            new_proxy: false,
            ..stricter
        },
        AlertSettings {
            refusals: None,
            ..stricter
        },
    ] {
        let err = cs
            .policy
            .put_settings(&admin(3600), with(quieter))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ControlError::StepUpRequired { .. }),
            "{err:?}"
        );
    }
    cs.policy
        .put_settings(
            &admin(0),
            with(AlertSettings {
                refusals: None,
                new_proxy: false,
            }),
        )
        .await
        .unwrap();
    let saved = store.get_settings().await.unwrap();
    assert_eq!(saved.alerts.refusals, None);
    let audit = store
        .query(&AuditQuery {
            action_prefix: Some("settings.update".into()),
            page: PageRequest::new(Some(1), Some(1)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(audit.items[0].detail["alert_refusals"], "off");
    assert_eq!(audit.items[0].detail["alert_new_proxy"], "false");
}

#[tokio::test]
async fn a_node_s_audit_batch_raises_alerts() {
    use tokenless_core::protocol::AuditBatch;

    let (_, cs) = crate::service::testing::services().await;
    let host = Caller::service(Principal::service("host", Role::Admin, None));
    let (vault, _) = crate::service::testing::vault_with_rule(&cs, &host).await;
    let node = cs
        .nodes
        .register_embedded(&host, "edge-1", &{
            use rand::rngs::OsRng;
            use tokenless_core::seal::{encode_public_key, SealPublicKey, SealSecretKey};
            encode_public_key(&SealPublicKey::from(&SealSecretKey::random_from_rng(OsRng)))
        })
        .await
        .unwrap();
    let session = SessionId::new();
    let events = (0..10)
        .map(|_| {
            AuditEvent::new("node:x", "proxy.deny", AuditOutcome::Denied)
                .detail("scope", format!("vault:{vault}"))
                .detail("session_id", session.to_string())
        })
        .collect();
    cs.nodes
        .ingest_audit(&node.node, AuditBatch { events })
        .await
        .unwrap();
    let alerts = cs
        .alerts
        .list(
            &host,
            AlertFilter::default(),
            PageRequest::new(Some(1), Some(10)),
        )
        .await
        .unwrap();
    assert_eq!(alerts.total, 1);
    assert_eq!(alerts.items[0].kind, AlertKind::Refusals);
    // The node's scope detail names the vault, so the alert is the vault's.
    assert_eq!(alerts.items[0].vault_id, Some(vault));
}
