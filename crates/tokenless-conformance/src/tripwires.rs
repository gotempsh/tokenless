// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a [`TripwireStore`] must do: keep each vault's tripwires with
//! unique names and their decoys, list them newest first per vault and
//! across vaults, note when one was tripped, delete one with its audit
//! event, and drop a vault's tripwires with the vault.

use tokenless_control::model::{AuditQuery, PageRequest, Tripwire};
use tokenless_control::store::{AuditSink, PolicyStore, TripwireStore};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::ids::TripwireId;
use tokenless_core::tripwire::TripwireKind;

use crate::{at, backend, vault, ConformanceFailure};

const S: &str = "tripwire_store";

fn tripwire(vault_id: tokenless_core::ids::VaultId, name: &str, offset: i64) -> Tripwire {
    let value = format!("sk-conformance-decoy-{name}-0123456789");
    Tripwire {
        id: TripwireId::new(),
        vault_id,
        name: name.into(),
        kind: TripwireKind::Generic,
        prefix: value.chars().take(8).collect(),
        value,
        created_by: "user:conformance".into(),
        created_at: at(offset),
        last_tripped_at: None,
    }
}

fn event(action: &str, t: &Tripwire) -> AuditEvent {
    let mut e = AuditEvent::new("user:conformance", action, AuditOutcome::Success)
        .target(format!("tripwire:{}", t.id));
    e.at = at(0);
    e
}

/// Expects an empty store.
pub async fn tripwire_store_suite<St>(store: &St) -> Result<(), ConformanceFailure>
where
    St: TripwireStore + PolicyStore + AuditSink,
{
    let v1 = vault("tripwires-one", 0);
    let v2 = vault("tripwires-two", 1);
    for v in [&v1, &v2] {
        store
            .insert_vault(v.clone(), &[])
            .await
            .map_err(backend(S, "vault"))?;
    }
    let laptop = tripwire(v1.id, "laptop", 10);
    let runner = tripwire(v1.id, "runner", 20);
    let other = tripwire(v2.id, "laptop", 30);
    for t in [&laptop, &runner, &other] {
        store
            .insert_tripwire(t.clone(), &[event("tripwire.create", t)])
            .await
            .map_err(backend(S, "insert"))?;
    }
    let got = store
        .get_tripwire(&laptop.id)
        .await
        .map_err(backend(S, "get"))?;
    ensure!(
        S,
        "round_trip",
        got.as_ref() == Some(&laptop),
        "the tripwire must read back as written, decoy included, got {got:?}"
    );

    match store
        .insert_tripwire(tripwire(v1.id, "laptop", 40), &[])
        .await
    {
        Err(StoreError::Conflict { .. }) => {}
        other => {
            return Err(ConformanceFailure {
                suite: S,
                check: "unique_name",
                detail: format!("a second 'laptop' in one vault must conflict, got {other:?}"),
            })
        }
    }

    let in_v1 = store
        .list_tripwires(&v1.id, PageRequest::new(Some(1), Some(10)))
        .await
        .map_err(backend(S, "list"))?;
    let order: Vec<TripwireId> = in_v1.items.iter().map(|t| t.id).collect();
    ensure!(
        S,
        "list_vault",
        in_v1.total == 2 && order == vec![runner.id, laptop.id],
        "the first vault's two, newest first, got {} as {order:?}",
        in_v1.total
    );
    let all = store.all_tripwires(10).await.map_err(backend(S, "all"))?;
    let order: Vec<TripwireId> = all.iter().map(|t| t.id).collect();
    ensure!(
        S,
        "all",
        order == vec![other.id, runner.id, laptop.id],
        "every vault's, newest first, got {order:?}"
    );
    let capped = store
        .all_tripwires(2)
        .await
        .map_err(backend(S, "all_limit"))?;
    ensure!(
        S,
        "all_limit",
        capped.len() == 2,
        "at most the limit, got {}",
        capped.len()
    );

    store
        .tripwire_tripped(&laptop.id, at(50))
        .await
        .map_err(backend(S, "tripped"))?;
    store
        .tripwire_tripped(&TripwireId::new(), at(50))
        .await
        .map_err(backend(S, "tripped_missing"))?;
    let tripped = store
        .get_tripwire(&laptop.id)
        .await
        .map_err(backend(S, "tripped"))?;
    ensure!(
        S,
        "tripped",
        tripped.and_then(|t| t.last_tripped_at) == Some(at(50)),
        "last_tripped_at must be recorded"
    );

    let deleted = store
        .delete_tripwire(&runner.id, &[event("tripwire.delete", &runner)])
        .await
        .map_err(backend(S, "delete"))?;
    let again = store
        .delete_tripwire(&runner.id, &[event("tripwire.delete", &runner)])
        .await
        .map_err(backend(S, "delete_again"))?;
    ensure!(
        S,
        "delete",
        deleted && !again,
        "deleted once, then reported missing"
    );
    let audited = store
        .query(&AuditQuery {
            action_prefix: Some("tripwire.delete".into()),
            page: PageRequest::new(Some(1), Some(10)),
            ..AuditQuery::default()
        })
        .await
        .map_err(backend(S, "delete_audit"))?;
    ensure!(
        S,
        "delete_audit",
        audited.total == 1,
        "one deletion audited, got {}",
        audited.total
    );

    store
        .delete_vault(&v2.id, at(60), &[])
        .await
        .map_err(backend(S, "delete_vault"))?;
    let gone = store
        .get_tripwire(&other.id)
        .await
        .map_err(backend(S, "delete_vault"))?;
    ensure!(
        S,
        "deleted_with_vault",
        gone.is_none(),
        "a deleted vault's tripwires must go with it"
    );
    Ok(())
}
