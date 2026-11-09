// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an [`AuditExportStore`] must do: number audit events in the order
//! they are written, read them back by number, keep destinations with
//! unique names, and keep their delivery state apart from their settings.

use tokenless_control::model::{AuditDestination, AuditFilter, DeliveryState, PayloadFormat};
use tokenless_control::store::{
    AuditExportStore, AuditSink, CiphertextOwner, NodeStore, StoredCiphertext,
};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::ids::AuditDestinationId;

use crate::{at, backend, ConformanceFailure};

const S: &str = "audit_export_store";

fn destination(name: &str, created_offset: i64) -> AuditDestination {
    AuditDestination {
        id: AuditDestinationId::new(),
        name: name.into(),
        url: format!("https://{name}.example.test/ingest"),
        format: PayloadFormat::Json,
        auth_header_name: Some("Authorization".into()),
        auth_header_value_enc: Some(vec![4, 5, 6]),
        signing_secret_enc: vec![1, 2, 3],
        filter: AuditFilter {
            action_prefixes: vec!["credential.".into()],
            outcomes: vec![AuditOutcome::Denied],
            vault_ids: vec![],
        },
        paused: false,
        created_at: at(created_offset),
        updated_at: at(created_offset),
        delivery: DeliveryState {
            cursor: 2,
            ..DeliveryState::default()
        },
    }
}

fn event(action: &str) -> AuditEvent {
    let mut e = AuditEvent::new("system", action, AuditOutcome::Success);
    e.at = at(0);
    e
}

async fn get<St: AuditExportStore>(
    store: &St,
    id: &AuditDestinationId,
) -> Result<AuditDestination, ConformanceFailure> {
    store
        .get_audit_destination(id)
        .await
        .map_err(backend(S, "get"))?
        .ok_or_else(|| ConformanceFailure {
            suite: S,
            check: "get",
            detail: format!("destination {id} vanished"),
        })
}

/// Sequence numbers, destinations and their delivery state. Expects an
/// empty store.
pub async fn audit_export_store_suite<St>(store: &St) -> Result<(), ConformanceFailure>
where
    St: AuditExportStore + AuditSink + NodeStore,
{
    // -- Sequence numbers ---------------------------------------------------
    let start = store
        .latest_audit_seq()
        .await
        .map_err(backend(S, "latest_seq"))?;
    let first: Vec<_> = (0..3).map(|i| event(&format!("first.{i}"))).collect();
    let second: Vec<_> = (0..2).map(|i| event(&format!("second.{i}"))).collect();
    store.record(&first).await.map_err(backend(S, "record"))?;
    store.record(&second).await.map_err(backend(S, "record"))?;
    let latest = store
        .latest_audit_seq()
        .await
        .map_err(backend(S, "latest_seq"))?;
    ensure!(
        S,
        "seq_counts",
        latest == start + 5,
        "five events recorded after {start} must end at {}, got {latest}",
        start + 5
    );
    let all = store
        .audit_events_after(start, 100)
        .await
        .map_err(backend(S, "events_after"))?;
    let numbers: Vec<u64> = all.iter().map(|(n, _)| *n).collect();
    let ids: Vec<_> = all.iter().map(|(_, e)| e.id).collect();
    let expected_ids: Vec<_> = first.iter().chain(&second).map(|e| e.id).collect();
    ensure!(
        S,
        "seq_order",
        numbers == ((start + 1)..=(start + 5)).collect::<Vec<_>>() && ids == expected_ids,
        "events must come back in the order written, numbered {}..={} without gaps; got {numbers:?}",
        start + 1,
        start + 5
    );
    ensure!(
        S,
        "seq_round_trip",
        all[0].1 == first[0],
        "an event read by number must equal the one recorded: {:?} vs {:?}",
        all[0].1,
        first[0]
    );
    let window = store
        .audit_events_after(start + 2, 2)
        .await
        .map_err(backend(S, "events_after"))?;
    let window: Vec<u64> = window.iter().map(|(n, _)| *n).collect();
    ensure!(
        S,
        "seq_window",
        window == vec![start + 3, start + 4],
        "after {} with a limit of 2 must be {:?}, got {window:?}",
        start + 2,
        vec![start + 3, start + 4]
    );
    let none = store
        .audit_events_after(latest, 10)
        .await
        .map_err(backend(S, "events_after"))?;
    ensure!(
        S,
        "seq_none_after_latest",
        none.is_empty(),
        "nothing may come after the latest number, got {} events",
        none.len()
    );

    // -- Destinations -------------------------------------------------------
    let a = destination("alpha", -20);
    let b = destination("beta", -10);
    store
        .insert_audit_destination(b.clone(), &[event("audit_export.create")])
        .await
        .map_err(backend(S, "insert"))?;
    store
        .insert_audit_destination(a.clone(), &[])
        .await
        .map_err(backend(S, "insert"))?;
    let after_insert = store
        .latest_audit_seq()
        .await
        .map_err(backend(S, "latest_seq"))?;
    ensure!(
        S,
        "audited_write_numbered",
        after_insert == latest + 1,
        "an audited write must number its event after the others ({}), got {after_insert}",
        latest + 1
    );
    let stored = get(store, &a.id).await?;
    ensure!(
        S,
        "round_trip",
        stored == a,
        "a destination must read back as written: {stored:?} vs {a:?}"
    );
    let names: Vec<String> = store
        .list_audit_destinations()
        .await
        .map_err(backend(S, "list"))?
        .into_iter()
        .map(|d| d.name)
        .collect();
    ensure!(
        S,
        "list_oldest_first",
        names == vec!["alpha".to_string(), "beta".to_string()],
        "list must be oldest first, got {names:?}"
    );
    let twin = AuditDestination {
        id: AuditDestinationId::new(),
        ..destination("alpha", 0)
    };
    let res = store.insert_audit_destination(twin, &[]).await;
    ensure!(
        S,
        "unique_name",
        matches!(res, Err(StoreError::Conflict { .. })),
        "a second destination named alpha must be Conflict, got {res:?}"
    );

    // Updating settings never touches the delivery state.
    let changed = AuditDestination {
        name: "alpha-2".into(),
        url: "https://alpha-2.example.test/".into(),
        format: PayloadFormat::Ndjson,
        auth_header_name: None,
        auth_header_value_enc: None,
        signing_secret_enc: vec![7, 7],
        filter: AuditFilter::default(),
        paused: true,
        updated_at: at(5),
        delivery: DeliveryState {
            cursor: 999,
            last_error: Some("not from the sender".into()),
            ..DeliveryState::default()
        },
        ..a.clone()
    };
    store
        .update_audit_destination(changed.clone(), &[])
        .await
        .map_err(backend(S, "update"))?;
    let stored = get(store, &a.id).await?;
    ensure!(
        S,
        "update_settings_only",
        stored
            == AuditDestination {
                delivery: a.delivery.clone(),
                ..changed.clone()
            },
        "update must replace the settings and keep the delivery state: {stored:?}"
    );
    let res = store
        .update_audit_destination(
            AuditDestination {
                name: "beta".into(),
                ..changed.clone()
            },
            &[],
        )
        .await;
    ensure!(
        S,
        "update_unique_name",
        matches!(res, Err(StoreError::Conflict { .. })),
        "renaming to an existing name must be Conflict, got {res:?}"
    );
    let res = store
        .update_audit_destination(destination("ghost", 0), &[])
        .await;
    ensure!(
        S,
        "update_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "updating a missing destination must be NotFound, got {res:?}"
    );

    // -- Delivery state -----------------------------------------------------
    store
        .record_audit_delivery_failure(&b.id, 2, 4, "first", at(10))
        .await
        .map_err(backend(S, "failure"))?;
    // From a cursor that is no longer the current one: counted, but it
    // does not move the end of the retry.
    store
        .record_audit_delivery_failure(&b.id, 1, 9, "second", at(20))
        .await
        .map_err(backend(S, "failure"))?;
    let failing = get(store, &b.id).await?.delivery;
    ensure!(
        S,
        "failure_run",
        failing.failing_since == Some(at(10))
            && failing.last_attempt_at == Some(at(20))
            && failing.last_error.as_deref() == Some("second")
            && failing.consecutive_failures == 2
            && failing.cursor == 2
            && failing.retry_until == Some(4),
        "two failures must keep the first's start, the second's error, count 2, the cursor and the retry's end from the current cursor: {failing:?}"
    );
    let current = get(store, &b.id).await?;
    store
        .update_audit_destination(current, &[])
        .await
        .map_err(backend(S, "update"))?;
    let edited = get(store, &b.id).await?.delivery;
    ensure!(
        S,
        "update_keeps_delivery",
        edited.retry_until == Some(4) && edited.cursor == 2 && edited.consecutive_failures == 2,
        "a settings update must keep the delivery state, pending retry included: {edited:?}"
    );
    store
        .record_audit_delivery_failure(&b.id, 2, 4, "third", at(25))
        .await
        .map_err(backend(S, "failure"))?;
    store
        .record_audit_delivery_failure(&AuditDestinationId::new(), 0, 1, "x", at(0))
        .await
        .map_err(backend(S, "failure_missing"))?;

    let stale = store
        .advance_audit_cursor(&b.id, 1, 5, at(30))
        .await
        .map_err(backend(S, "advance"))?;
    ensure!(
        S,
        "advance_compare",
        !stale && get(store, &b.id).await?.delivery.cursor == 2,
        "advancing from a cursor that is not the current one must change nothing"
    );
    let moved = store
        .advance_audit_cursor(&b.id, 2, 5, at(30))
        .await
        .map_err(backend(S, "advance"))?;
    let delivered = get(store, &b.id).await?.delivery;
    ensure!(
        S,
        "advance",
        moved
            && delivered
                == DeliveryState {
                    cursor: 5,
                    last_success_at: Some(at(30)),
                    last_attempt_at: Some(at(30)),
                    failing_since: None,
                    last_error: None,
                    consecutive_failures: 0,
                    retry_until: None,
                },
        "advancing must move the cursor and clear the failures and the retry: {delivered:?}"
    );
    let gone = store
        .advance_audit_cursor(&AuditDestinationId::new(), 0, 1, at(0))
        .await
        .map_err(backend(S, "advance"))?;
    ensure!(
        S,
        "advance_missing",
        !gone,
        "advancing a missing destination must return false"
    );

    store
        .record_audit_delivery_failure(&b.id, 5, 7, "down", at(40))
        .await
        .map_err(backend(S, "failure"))?;
    let before_skip = store
        .latest_audit_seq()
        .await
        .map_err(backend(S, "latest_seq"))?;
    store
        .set_audit_cursor(&b.id, 1, &[event("audit_export.skip")])
        .await
        .map_err(backend(S, "set_cursor"))?;
    let skipped = get(store, &b.id).await?.delivery;
    let after_skip = store
        .latest_audit_seq()
        .await
        .map_err(backend(S, "latest_seq"))?;
    ensure!(
        S,
        "set_cursor",
        skipped.cursor == 1
            && skipped.failing_since.is_none()
            && skipped.last_error.is_none()
            && skipped.consecutive_failures == 0
            && skipped.retry_until.is_none()
            && after_skip == before_skip + 1,
        "set_audit_cursor must put the cursor anywhere, clear the failures and the retry, and record its event: {skipped:?}"
    );
    let res = store
        .set_audit_cursor(&AuditDestinationId::new(), 0, &[])
        .await;
    ensure!(
        S,
        "set_cursor_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "moving a missing destination's cursor must be NotFound, got {res:?}"
    );

    // -- Secrets ------------------------------------------------------------
    let ciphertexts = store
        .list_ciphertexts()
        .await
        .map_err(backend(S, "list_ciphertexts"))?;
    let owned = |owner: CiphertextOwner| {
        ciphertexts
            .iter()
            .find(|c| c.owner == owner)
            .map(|c| c.ciphertext.clone())
    };
    ensure!(
        S,
        "secrets_listed",
        owned(CiphertextOwner::AuditDestinationSecret { id: b.id }) == Some(vec![1, 2, 3])
            && owned(CiphertextOwner::AuditDestinationHeader { id: b.id }) == Some(vec![4, 5, 6])
            && owned(CiphertextOwner::AuditDestinationSecret { id: a.id }) == Some(vec![7, 7])
            && owned(CiphertextOwner::AuditDestinationHeader { id: a.id }).is_none(),
        "list_ciphertexts must hold each destination's signing secret and auth header value"
    );
    let replaced = store
        .replace_ciphertexts(
            &[
                (
                    StoredCiphertext {
                        owner: CiphertextOwner::AuditDestinationSecret { id: b.id },
                        ciphertext: vec![1, 2, 3],
                    },
                    vec![8],
                ),
                (
                    StoredCiphertext {
                        owner: CiphertextOwner::AuditDestinationHeader { id: b.id },
                        ciphertext: vec![4, 5, 6],
                    },
                    vec![9],
                ),
            ],
            &[],
        )
        .await
        .map_err(backend(S, "replace_ciphertexts"))?;
    let after = get(store, &b.id).await?;
    ensure!(
        S,
        "secrets_replaced",
        replaced == 2
            && after.signing_secret_enc == vec![8]
            && after.auth_header_value_enc == Some(vec![9]),
        "replace_ciphertexts replaced {replaced} and left {after:?}"
    );

    // -- Deleting -----------------------------------------------------------
    store
        .delete_audit_destination(&a.id, &[])
        .await
        .map_err(backend(S, "delete"))?;
    let left = store
        .list_audit_destinations()
        .await
        .map_err(backend(S, "list"))?;
    ensure!(
        S,
        "delete",
        left.len() == 1 && left[0].id == b.id,
        "after deleting alpha only beta must be left, got {} destinations",
        left.len()
    );
    let res = store.delete_audit_destination(&a.id, &[]).await;
    ensure!(
        S,
        "delete_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "deleting it again must be NotFound, got {res:?}"
    );
    Ok(())
}
