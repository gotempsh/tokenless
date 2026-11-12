// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an [`AlertStore`] must do: raise one alert per signal and session,
//! list them newest first with the open, vault and session filters, and
//! acknowledge an alert once, each write committed with its audit event.

use std::collections::BTreeMap;

use tokenless_control::model::{Alert, AlertFilter, AlertKind, AuditQuery, PageRequest};
use tokenless_control::store::{AlertStore, AuditSink};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::ids::{AlertId, NodeId, SessionId, VaultId};

use crate::{at, backend, ConformanceFailure};

const S: &str = "alert_store";

fn alert(kind: AlertKind, vault_id: VaultId, session_id: SessionId, offset: i64) -> Alert {
    Alert {
        id: AlertId::new(),
        kind,
        dedup_key: format!("{}:{session_id}", kind.as_str()),
        summary: format!("{} on {session_id}", kind.as_str()),
        vault_id: Some(vault_id),
        session_id: Some(session_id),
        node_id: Some(NodeId::new()),
        detail: BTreeMap::from([("node".to_string(), "edge-1".to_string())]),
        raised_at: at(offset),
        acknowledged_at: None,
        acknowledged_by: None,
    }
}

fn event(action: &str, alert: &Alert) -> AuditEvent {
    let mut e = AuditEvent::new("system", action, AuditOutcome::Success)
        .target(format!("alert:{}", alert.id));
    e.at = at(0);
    e
}

async fn audited<St: AuditSink>(store: &St, action: &str) -> Result<u64, ConformanceFailure> {
    Ok(store
        .query(&AuditQuery {
            action_prefix: Some(action.to_string()),
            page: PageRequest::new(Some(1), Some(100)),
            ..AuditQuery::default()
        })
        .await
        .map_err(backend(S, "audit_query"))?
        .total)
}

/// Expects an empty store.
pub async fn alert_store_suite<St>(store: &St) -> Result<(), ConformanceFailure>
where
    St: AlertStore + AuditSink,
{
    let (v1, v2) = (VaultId::new(), VaultId::new());
    let (s1, s2) = (SessionId::new(), SessionId::new());
    let first = alert(AlertKind::Refusals, v1, s1, 10);
    let raised = store
        .insert_alert(first.clone(), &[event("alert.raised", &first)])
        .await
        .map_err(backend(S, "insert"))?;
    ensure!(S, "insert", raised, "a new alert must be inserted");
    let got = store
        .get_alert(&first.id)
        .await
        .map_err(backend(S, "get"))?;
    ensure!(
        S,
        "round_trip",
        got.as_ref() == Some(&first),
        "the alert must read back as written, got {got:?}"
    );

    // The same signal on the same session again: nothing new, no audit.
    let again = alert(AlertKind::Refusals, v1, s1, 20);
    let raised = store
        .insert_alert(again.clone(), &[event("alert.raised", &again)])
        .await
        .map_err(backend(S, "dedup"))?;
    ensure!(
        S,
        "dedup",
        !raised,
        "an alert with a taken dedup_key must not be inserted"
    );
    let missing = store
        .get_alert(&again.id)
        .await
        .map_err(backend(S, "dedup"))?;
    ensure!(
        S,
        "dedup",
        missing.is_none(),
        "the duplicate must not be stored"
    );
    let n = audited(store, "alert.raised").await?;
    ensure!(
        S,
        "dedup_audit",
        n == 1,
        "a skipped duplicate records no audit event, got {n} events"
    );

    // Another signal on the same session, and one in another vault.
    let other_kind = alert(AlertKind::NewProxy, v1, s1, 30);
    let other_vault = alert(AlertKind::Quarantine, v2, s2, 40);
    for a in [&other_kind, &other_vault] {
        let raised = store
            .insert_alert(a.clone(), &[event("alert.raised", a)])
            .await
            .map_err(backend(S, "insert"))?;
        ensure!(S, "insert", raised, "{:?} must be inserted", a.kind);
    }

    let list = |filter: AlertFilter| async move {
        store
            .list_alerts(&filter, PageRequest::new(Some(1), Some(100)))
            .await
            .map_err(backend(S, "list"))
    };
    let all = list(AlertFilter::default()).await?;
    let order: Vec<AlertId> = all.items.iter().map(|a| a.id).collect();
    ensure!(
        S,
        "list_newest_first",
        all.total == 3 && order == vec![other_vault.id, other_kind.id, first.id],
        "three alerts newest first, got {} as {order:?}",
        all.total
    );
    let in_v1 = list(AlertFilter {
        vault_id: Some(v1),
        ..AlertFilter::default()
    })
    .await?;
    ensure!(
        S,
        "list_vault",
        in_v1.total == 2,
        "two alerts in the first vault, got {}",
        in_v1.total
    );
    let of_s2 = list(AlertFilter {
        session_id: Some(s2),
        ..AlertFilter::default()
    })
    .await?;
    ensure!(
        S,
        "list_session",
        of_s2.total == 1 && of_s2.items[0].id == other_vault.id,
        "one alert for the second session, got {}",
        of_s2.total
    );
    let of_kind = list(AlertFilter {
        kind: Some(AlertKind::NewProxy),
        ..AlertFilter::default()
    })
    .await?;
    ensure!(
        S,
        "list_kind",
        of_kind.total == 1 && of_kind.items[0].id == other_kind.id,
        "one second-proxy alert, got {}",
        of_kind.total
    );
    let page = store
        .list_alerts(&AlertFilter::default(), PageRequest::new(Some(2), Some(2)))
        .await
        .map_err(backend(S, "list_page"))?;
    ensure!(
        S,
        "list_page",
        page.total == 3 && page.items.len() == 1 && page.items[0].id == first.id,
        "page 2 of size 2 holds the oldest alert, got {} items",
        page.items.len()
    );

    // Acknowledged once; open alerts leave it out.
    let ack = event("alert.acknowledge", &first);
    let done = store
        .acknowledge_alert(
            &first.id,
            "user:conformance",
            at(50),
            std::slice::from_ref(&ack),
        )
        .await
        .map_err(backend(S, "acknowledge"))?;
    ensure!(S, "acknowledge", done, "an open alert must be acknowledged");
    let twice = store
        .acknowledge_alert(&first.id, "user:someone-else", at(60), &[ack])
        .await
        .map_err(backend(S, "acknowledge_twice"))?;
    ensure!(
        S,
        "acknowledge_twice",
        !twice,
        "acknowledging twice changes nothing"
    );
    let seen = store
        .get_alert(&first.id)
        .await
        .map_err(backend(S, "acknowledge"))?;
    ensure!(
        S,
        "acknowledge_kept",
        seen.as_ref()
            .is_some_and(|a| a.acknowledged_at == Some(at(50))
                && a.acknowledged_by.as_deref() == Some("user:conformance")),
        "the first acknowledgement is kept, got {seen:?}"
    );
    let n = audited(store, "alert.acknowledge").await?;
    ensure!(
        S,
        "acknowledge_audit",
        n == 1,
        "one acknowledgement audited, got {n}"
    );
    let open = list(AlertFilter {
        open_only: true,
        ..AlertFilter::default()
    })
    .await?;
    ensure!(
        S,
        "list_open",
        open.total == 2 && open.items.iter().all(|a| a.id != first.id),
        "two open alerts without the acknowledged one, got {}",
        open.total
    );

    let unknown = AlertId::new();
    match store
        .acknowledge_alert(&unknown, "user:conformance", at(70), &[])
        .await
    {
        Err(StoreError::NotFound { .. }) => {}
        other => {
            return Err(ConformanceFailure {
                suite: S,
                check: "acknowledge_missing",
                detail: format!("acknowledging an unknown alert must be NotFound, got {other:?}"),
            })
        }
    }
    Ok(())
}
