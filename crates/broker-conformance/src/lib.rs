// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behaviour every implementation of the broker's store traits must show.
//!
//! An embedding platform runs these against its own `CredentialStore`,
//! `PolicyStore`, `AuditSink`, `Authorizer`, `IdentityStore` and `NodeStore`
//! implementations. Each suite expects an empty store and returns the first
//! failed check with a description of what was expected.

use std::collections::BTreeMap;

use broker_control::model::{
    ApiKey, AuditQuery, CredentialMeta, JoinTokenRecord, Node, PageRequest, ProxySession, Rule,
    Settings, StoredTemplate, TemplateSource, TemplateStatus, UiSession, User, Vault,
};
use broker_control::store::{
    AuditSink, Authorizer, CredentialStore, IdentityStore, NodeStore, PolicyStore,
};
use broker_control::StoreError;
use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::{Action, Decision, Principal, PrincipalKind, Role};
use broker_core::egress::{EgressPolicy, IpCidr};
use broker_core::ids::{ApiKeyId, CredentialId, NodeId, RuleId, SessionId, UserId, VaultId};
use broker_core::rule::RuleScope;
use broker_core::scope::Scope;
use broker_core::snapshot::UnmatchedHostPolicy;
use broker_core::template::builtin_templates;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("conformance check '{suite}::{check}' failed: {detail}")]
pub struct ConformanceFailure {
    pub suite: &'static str,
    pub check: &'static str,
    pub detail: String,
}

macro_rules! ensure {
    ($suite:expr, $check:expr, $cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err(ConformanceFailure {
                suite: $suite,
                check: $check,
                detail: format!($($fmt)+),
            });
        }
    };
}

fn backend(suite: &'static str, check: &'static str) -> impl Fn(StoreError) -> ConformanceFailure {
    move |e| ConformanceFailure {
        suite,
        check,
        detail: format!("unexpected store error: {e}"),
    }
}

fn at(offset_secs: i64) -> DateTime<Utc> {
    // Whole seconds keep timestamp round-trips exact for every backend.
    let now = Utc::now().timestamp();
    DateTime::from_timestamp(now + offset_secs, 0).unwrap_or_else(Utc::now)
}

fn vault(name: &str, created_offset: i64) -> Vault {
    let id = VaultId::new();
    Vault {
        id,
        name: name.to_string(),
        scope: Scope::for_vault(&id),
        created_at: at(created_offset),
    }
}

fn credential(vault_id: VaultId, name: &str, created_offset: i64) -> CredentialMeta {
    CredentialMeta {
        id: CredentialId::new(),
        vault_id,
        name: name.to_string(),
        template_id: "github".into(),
        template_version: 1,
        host_override: vec![],
        field_names: vec!["token".into()],
        created_by: "user:conformance".into(),
        created_at: at(created_offset),
        updated_at: at(created_offset),
    }
}

fn scope() -> Result<RuleScope, ConformanceFailure> {
    let parse_err = |e: broker_core::CoreError| ConformanceFailure {
        suite: "fixtures",
        check: "rule_scope",
        detail: e.to_string(),
    };
    Ok(RuleScope {
        hosts: vec![broker_core::host::HostPattern::parse("api.example.com").map_err(parse_err)?],
        paths: vec![broker_core::path::PathPattern::parse("/*").map_err(parse_err)?],
        methods: vec![broker_core::path::HttpMethod::parse("GET").map_err(parse_err)?],
    })
}

fn rule(
    vault_id: VaultId,
    credential_id: CredentialId,
    name: &str,
    enabled: bool,
) -> Result<Rule, ConformanceFailure> {
    Ok(Rule {
        id: RuleId::new(),
        vault_id,
        credential_id,
        name: name.to_string(),
        allow: scope()?,
        enabled,
        created_by: "user:conformance".into(),
        created_at: at(0),
        updated_at: at(0),
    })
}

fn session(vault_id: VaultId, expires_offset: i64, limit: Option<u64>) -> ProxySession {
    ProxySession {
        id: SessionId::new(),
        vault_id,
        rule_ids: vec![RuleId::new()],
        labels: BTreeMap::from([("agent".to_string(), "conformance".to_string())]),
        request_limit: limit,
        created_by: "user:conformance".into(),
        created_at: at(-10),
        expires_at: at(expires_offset),
        revoked_at: None,
    }
}

pub async fn credential_store_suite(store: &dyn CredentialStore) -> Result<(), ConformanceFailure> {
    const S: &str = "credential_store";
    let vault_a = VaultId::new();
    let vault_b = VaultId::new();
    let first = credential(vault_a, "first", -20);
    let second = credential(vault_a, "second", -10);
    let other = credential(vault_b, "first", -5);
    for (meta, ct) in [
        (&first, b"ct-1".to_vec()),
        (&second, b"ct-2".to_vec()),
        (&other, b"ct-3".to_vec()),
    ] {
        store
            .insert_credential(meta.clone(), ct, &[])
            .await
            .map_err(backend(S, "insert"))?;
    }

    let fetched = store
        .get_credential(&first.id)
        .await
        .map_err(backend(S, "get"))?;
    ensure!(
        S,
        "get",
        fetched.as_ref() == Some(&first),
        "expected {first:?}, got {fetched:?}"
    );
    let missing = store
        .get_credential(&CredentialId::new())
        .await
        .map_err(backend(S, "get_missing"))?;
    ensure!(
        S,
        "get_missing",
        missing.is_none(),
        "unknown id returned {missing:?}"
    );

    let dup = store
        .insert_credential(credential(vault_a, "first", 0), b"x".to_vec(), &[])
        .await;
    ensure!(
        S,
        "duplicate_name",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "same name in one vault must be Conflict, got {dup:?}"
    );

    let page = store
        .list_credentials(&vault_a, PageRequest::new(Some(1), Some(1)))
        .await
        .map_err(backend(S, "list"))?;
    ensure!(
        S,
        "list_total",
        page.total == 2,
        "vault A has 2 credentials, total was {}",
        page.total
    );
    ensure!(
        S,
        "list_order",
        page.items.first().map(|m| m.id) == Some(second.id),
        "newest first expected, got {:?}",
        page.items
    );
    let page2 = store
        .list_credentials(&vault_a, PageRequest::new(Some(2), Some(1)))
        .await
        .map_err(backend(S, "list_page2"))?;
    ensure!(
        S,
        "list_page2",
        page2.items.first().map(|m| m.id) == Some(first.id),
        "second page should hold the oldest, got {:?}",
        page2.items
    );

    let ct = store
        .load_secret_ciphertext(&first.id)
        .await
        .map_err(backend(S, "load"))?;
    ensure!(
        S,
        "load",
        ct.as_deref() == Some(b"ct-1".as_slice()),
        "ciphertext must round-trip byte for byte"
    );

    store
        .replace_secret(
            &first.id,
            b"ct-rotated".to_vec(),
            vec!["token".into(), "extra".into()],
            at(5),
            &[],
        )
        .await
        .map_err(backend(S, "replace"))?;
    let ct = store
        .load_secret_ciphertext(&first.id)
        .await
        .map_err(backend(S, "replace_load"))?;
    ensure!(
        S,
        "replace",
        ct.as_deref() == Some(b"ct-rotated".as_slice()),
        "rotated ciphertext not returned"
    );
    let meta = store
        .get_credential(&first.id)
        .await
        .map_err(backend(S, "replace_meta"))?;
    ensure!(
        S,
        "replace_meta",
        meta.as_ref().map(|m| m.field_names.len()) == Some(2),
        "field names not updated: {meta:?}"
    );
    let missing = store
        .replace_secret(&CredentialId::new(), vec![], vec![], at(0), &[])
        .await;
    ensure!(
        S,
        "replace_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    store
        .delete_credential(&first.id, &[])
        .await
        .map_err(backend(S, "delete"))?;
    let gone = store
        .get_credential(&first.id)
        .await
        .map_err(backend(S, "delete_get"))?;
    ensure!(
        S,
        "delete",
        gone.is_none(),
        "credential still present after delete"
    );
    let gone_ct = store
        .load_secret_ciphertext(&first.id)
        .await
        .map_err(backend(S, "delete_ct"))?;
    ensure!(
        S,
        "delete_ciphertext",
        gone_ct.is_none(),
        "ciphertext still present after delete"
    );
    let again = store.delete_credential(&first.id, &[]).await;
    ensure!(
        S,
        "delete_missing",
        matches!(again, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {again:?}"
    );
    Ok(())
}

pub async fn policy_store_suite(store: &dyn PolicyStore) -> Result<(), ConformanceFailure> {
    const S: &str = "policy_store";
    // vaults
    let v1 = vault("alpha", -20);
    let v2 = vault("beta", -10);
    store
        .insert_vault(v1.clone(), &[])
        .await
        .map_err(backend(S, "vault_insert"))?;
    store
        .insert_vault(v2.clone(), &[])
        .await
        .map_err(backend(S, "vault_insert"))?;
    let dup = store.insert_vault(vault("alpha", 0), &[]).await;
    ensure!(
        S,
        "vault_duplicate",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "duplicate vault name must be Conflict, got {dup:?}"
    );
    let got = store
        .get_vault(&v1.id)
        .await
        .map_err(backend(S, "vault_get"))?;
    ensure!(
        S,
        "vault_get",
        got.as_ref() == Some(&v1),
        "expected {v1:?}, got {got:?}"
    );
    let page = store
        .list_vaults(PageRequest::default())
        .await
        .map_err(backend(S, "vault_list"))?;
    ensure!(
        S,
        "vault_list",
        page.total == 2 && page.items.first().map(|v| v.id) == Some(v2.id),
        "expected 2 vaults newest first, got {:?}",
        page.items
    );

    // templates
    let (template, yaml) = builtin_templates()
        .map_err(|e| ConformanceFailure {
            suite: S,
            check: "templates",
            detail: e.to_string(),
        })?
        .remove(0);
    let stored = StoredTemplate {
        template: template.clone(),
        yaml: yaml.to_string(),
        source: TemplateSource::Imported,
        status: TemplateStatus::PendingApproval,
        imported_by: Some("user:conformance".into()),
        approved_by: None,
        created_at: at(0),
    };
    store
        .insert_template(stored.clone(), &[])
        .await
        .map_err(backend(S, "template_insert"))?;
    let dup = store.insert_template(stored.clone(), &[]).await;
    ensure!(
        S,
        "template_duplicate",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "same id+version must be Conflict, got {dup:?}"
    );
    store
        .approve_template(&template.id, template.version, "user:admin", &[])
        .await
        .map_err(backend(S, "template_approve"))?;
    let got = store
        .get_template(&template.id, template.version)
        .await
        .map_err(backend(S, "template_get"))?;
    ensure!(
        S,
        "template_approve",
        got.as_ref().map(|t| (t.status, t.approved_by.clone()))
            == Some((TemplateStatus::Approved, Some("user:admin".into()))),
        "approval not persisted: {got:?}"
    );
    ensure!(
        S,
        "template_round_trip",
        got.as_ref().map(|t| &t.template) == Some(&template),
        "template content changed in storage"
    );
    let missing = store.approve_template("nope", 1, "x", &[]).await;
    ensure!(
        S,
        "template_approve_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    let list = store
        .list_templates()
        .await
        .map_err(backend(S, "template_list"))?;
    ensure!(
        S,
        "template_list",
        list.len() == 1,
        "expected 1 template, got {}",
        list.len()
    );

    // rules
    let cred = CredentialId::new();
    let r1 = rule(v1.id, cred, "one", true)?;
    let r2 = rule(v1.id, cred, "two", false)?;
    let r3 = rule(v2.id, CredentialId::new(), "one", true)?;
    for r in [&r1, &r2, &r3] {
        store
            .insert_rule(r.clone(), &[])
            .await
            .map_err(backend(S, "rule_insert"))?;
    }
    let dup = store
        .insert_rule(rule(v1.id, cred, "one", true)?, &[])
        .await;
    ensure!(
        S,
        "rule_duplicate",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "duplicate rule name in a vault must be Conflict, got {dup:?}"
    );
    let got = store
        .get_rule(&r1.id)
        .await
        .map_err(backend(S, "rule_get"))?;
    ensure!(
        S,
        "rule_get",
        got.as_ref() == Some(&r1),
        "rule did not round-trip: {got:?}"
    );
    let in_v1 = store
        .list_rules(&v1.id, PageRequest::default())
        .await
        .map_err(backend(S, "rule_list"))?;
    ensure!(
        S,
        "rule_list",
        in_v1.total == 2,
        "vault alpha has 2 rules, got {}",
        in_v1.total
    );
    let enabled = store
        .list_enabled_rules()
        .await
        .map_err(backend(S, "rule_enabled"))?;
    ensure!(
        S,
        "rule_enabled",
        enabled.len() == 2 && enabled.iter().all(|r| r.enabled),
        "expected the 2 enabled rules, got {enabled:?}"
    );
    let count = store
        .count_rules_for_credential(&cred)
        .await
        .map_err(backend(S, "rule_count"))?;
    ensure!(
        S,
        "rule_count",
        count == 2,
        "credential has 2 rules, got {count}"
    );
    let mut updated = r2.clone();
    updated.enabled = true;
    updated.name = "two-renamed".into();
    store
        .update_rule(updated.clone(), &[])
        .await
        .map_err(backend(S, "rule_update"))?;
    let got = store
        .get_rule(&r2.id)
        .await
        .map_err(backend(S, "rule_update_get"))?;
    ensure!(
        S,
        "rule_update",
        got.as_ref() == Some(&updated),
        "update not persisted: {got:?}"
    );
    let missing = store
        .update_rule(rule(v1.id, cred, "ghost", true)?, &[])
        .await;
    ensure!(
        S,
        "rule_update_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    store
        .delete_rule(&r1.id, &[])
        .await
        .map_err(backend(S, "rule_delete"))?;
    let missing = store.delete_rule(&r1.id, &[]).await;
    ensure!(
        S,
        "rule_delete_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    // sessions
    let active = session(v1.id, 600, None);
    let limited = session(v1.id, 600, Some(5));
    let expired = session(v1.id, -1, Some(5));
    for s in [&active, &limited, &expired] {
        store
            .insert_session(s.clone(), &[])
            .await
            .map_err(backend(S, "session_insert"))?;
    }
    let got = store
        .get_session(&active.id)
        .await
        .map_err(backend(S, "session_get"))?;
    ensure!(
        S,
        "session_get",
        got.as_ref() == Some(&active),
        "session did not round-trip: {got:?}"
    );
    let limits = store
        .list_limited_active(at(0))
        .await
        .map_err(backend(S, "session_limited"))?;
    ensure!(
        S,
        "session_limited",
        limits == vec![(limited.id, 5)],
        "only the unexpired limited session should be listed, got {limits:?}"
    );
    let first = store
        .revoke_session(&active.id, at(0), &[])
        .await
        .map_err(backend(S, "session_revoke"))?;
    let second = store
        .revoke_session(&active.id, at(1), &[])
        .await
        .map_err(backend(S, "session_revoke_again"))?;
    ensure!(
        S,
        "session_revoke",
        first && !second,
        "first revoke must return true and the second false, got {first}/{second}"
    );
    store
        .revoke_session(&expired.id, at(0), &[])
        .await
        .map_err(backend(S, "session_revoke_expired"))?;
    let revoked = store
        .list_revoked_unexpired(at(0))
        .await
        .map_err(backend(S, "session_revoked_list"))?;
    ensure!(
        S,
        "session_revoked_list",
        revoked == vec![active.id],
        "only unexpired revoked sessions should be listed, got {revoked:?}"
    );
    let missing = store.revoke_session(&SessionId::new(), at(0), &[]).await;
    ensure!(
        S,
        "session_revoke_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    let listed = store
        .list_sessions(&v1.id, PageRequest::default())
        .await
        .map_err(backend(S, "session_list"))?;
    ensure!(
        S,
        "session_list",
        listed.total == 3,
        "expected 3 sessions in vault alpha, got {}",
        listed.total
    );

    // settings
    let default = store
        .get_settings()
        .await
        .map_err(backend(S, "settings_default"))?;
    ensure!(
        S,
        "settings_default",
        default == Settings::default(),
        "default settings must be passthrough, got {default:?}"
    );
    let allow = "10.20.0.0/16"
        .parse::<IpCidr>()
        .map_err(|e| ConformanceFailure {
            suite: S,
            check: "settings_cidr",
            detail: e.to_string(),
        })?;
    let deny = Settings {
        unmatched_host_policy: UnmatchedHostPolicy::Deny,
        egress: EgressPolicy {
            block_private: false,
            allow: vec![allow],
        },
    };
    store
        .put_settings(deny.clone(), &[])
        .await
        .map_err(backend(S, "settings_put"))?;
    let got = store
        .get_settings()
        .await
        .map_err(backend(S, "settings_get"))?;
    ensure!(
        S,
        "settings_round_trip",
        got == deny,
        "settings did not round-trip: {got:?}"
    );
    Ok(())
}

pub async fn audit_sink_suite(sink: &dyn AuditSink) -> Result<(), ConformanceFailure> {
    const S: &str = "audit_sink";
    let vault_a = VaultId::new();
    let mut events = Vec::new();
    for i in 0..5i64 {
        let mut e = AuditEvent::new(
            "user:conformance",
            if i % 2 == 0 {
                "proxy.inject"
            } else {
                "rule.create"
            },
            AuditOutcome::Success,
        )
        .detail("index", i.to_string());
        e.at = at(i);
        if i < 3 {
            e = e.vault(vault_a);
        }
        events.push(e);
    }
    sink.record(&events).await.map_err(backend(S, "record"))?;
    let all = sink
        .query(&AuditQuery::default())
        .await
        .map_err(backend(S, "query"))?;
    ensure!(
        S,
        "query_total",
        all.total == 5,
        "expected 5 events, got {}",
        all.total
    );
    ensure!(
        S,
        "query_order",
        all.items.first().map(|e| e.detail.get("index").cloned()) == Some(Some("4".into())),
        "newest first expected"
    );
    ensure!(
        S,
        "round_trip",
        all.items.iter().any(|e| e == &events[4]),
        "events must round-trip unchanged"
    );
    let in_vault = sink
        .query(&AuditQuery {
            vault_id: Some(vault_a),
            ..Default::default()
        })
        .await
        .map_err(backend(S, "query_vault"))?;
    ensure!(
        S,
        "query_vault",
        in_vault.total == 3,
        "expected 3 events in the vault, got {}",
        in_vault.total
    );
    let proxy = sink
        .query(&AuditQuery {
            action_prefix: Some("proxy.".into()),
            ..Default::default()
        })
        .await
        .map_err(backend(S, "query_action"))?;
    ensure!(
        S,
        "query_action",
        proxy.total == 3 && proxy.items.iter().all(|e| e.action == "proxy.inject"),
        "expected 3 proxy.* events, got {:?}",
        proxy.items
    );
    let paged = sink
        .query(&AuditQuery {
            page: PageRequest::new(Some(2), Some(2)),
            ..Default::default()
        })
        .await
        .map_err(backend(S, "query_page"))?;
    ensure!(
        S,
        "query_page",
        paged.items.len() == 2 && paged.total == 5,
        "page 2 of size 2 should hold 2 of 5, got {} of {}",
        paged.items.len(),
        paged.total
    );
    Ok(())
}

async fn count_action(
    sink: &dyn AuditSink,
    action: &str,
    check: &'static str,
) -> Result<u64, ConformanceFailure> {
    let page = sink
        .query(&AuditQuery {
            action_prefix: Some(action.to_string()),
            ..Default::default()
        })
        .await
        .map_err(backend("audited_writes", check))?;
    Ok(page.items.iter().filter(|e| e.action == action).count() as u64)
}

/// A mutating store method commits the audit events it is given together
/// with the change, and only when the change succeeds. Run it against a
/// single backend that implements all three traits.
pub async fn audited_writes_suite<T>(store: &T) -> Result<(), ConformanceFailure>
where
    T: CredentialStore + PolicyStore + AuditSink,
{
    const S: &str = "audited_writes";
    let event = |action: &str| AuditEvent::new("user:conformance", action, AuditOutcome::Success);
    let vault_id = VaultId::new();
    let meta = credential(vault_id, "audited", -5);

    store
        .insert_credential(meta.clone(), b"ct".to_vec(), &[event("t.cred.create")])
        .await
        .map_err(backend(S, "insert"))?;
    let n = count_action(store, "t.cred.create", "insert").await?;
    ensure!(
        S,
        "insert",
        n == 1,
        "a successful insert must write its event, found {n}"
    );

    let dup = store
        .insert_credential(
            credential(vault_id, "audited", 0),
            b"ct".to_vec(),
            &[event("t.cred.dup")],
        )
        .await;
    ensure!(
        S,
        "conflict",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "duplicate name must conflict, got {dup:?}"
    );
    let n = count_action(store, "t.cred.dup", "conflict").await?;
    ensure!(
        S,
        "conflict",
        n == 0,
        "a conflicting insert must not write its event, found {n}"
    );

    let missing = store
        .delete_credential(&CredentialId::new(), &[event("t.cred.delete_missing")])
        .await;
    ensure!(
        S,
        "not_found",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "deleting an unknown credential must be NotFound, got {missing:?}"
    );
    let n = count_action(store, "t.cred.delete_missing", "not_found").await?;
    ensure!(
        S,
        "not_found",
        n == 0,
        "a failed delete must not write its event, found {n}"
    );

    let unknown_rule = rule(vault_id, meta.id, "missing", true)?;
    let missing = store
        .update_rule(unknown_rule, &[event("t.rule.update_missing")])
        .await;
    ensure!(
        S,
        "update_not_found",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "updating an unknown rule must be NotFound, got {missing:?}"
    );
    let n = count_action(store, "t.rule.update_missing", "update_not_found").await?;
    ensure!(
        S,
        "update_not_found",
        n == 0,
        "a failed update must not write its event, found {n}"
    );

    let proxy_session = session(vault_id, 600, None);
    store
        .insert_session(proxy_session.clone(), &[])
        .await
        .map_err(backend(S, "revoke"))?;
    for _ in 0..2 {
        store
            .revoke_session(&proxy_session.id, at(0), &[event("t.session.revoke")])
            .await
            .map_err(backend(S, "revoke"))?;
    }
    let n = count_action(store, "t.session.revoke", "revoke").await?;
    ensure!(
        S,
        "revoke",
        n == 2,
        "revoking (including the idempotent repeat) must write each event, found {n}"
    );

    let several = [event("t.many"), event("t.many"), event("t.many")];
    store
        .delete_credential(&meta.id, &several)
        .await
        .map_err(backend(S, "several"))?;
    let n = count_action(store, "t.many", "several").await?;
    ensure!(
        S,
        "several",
        n == 3,
        "every event passed must be written, found {n}"
    );
    Ok(())
}

/// Invariants every authoriser must keep, whatever its role model.
pub async fn authorizer_suite(authz: &dyn Authorizer) -> Result<(), ConformanceFailure> {
    const S: &str = "authorizer";
    let vault_a = VaultId::new();
    let vault_b = VaultId::new();
    let key = |role| Principal {
        kind: PrincipalKind::ApiKey,
        actor: "api_key:cbk_conformance".into(),
        role,
        vault: Some(vault_a),
    };
    for role in [Role::Editor, Role::Viewer, Role::SessionIssuer] {
        let d = authz
            .authorize(&key(role), Action::RuleRead, Some(&vault_b))
            .await;
        ensure!(
            S,
            "vault_binding",
            matches!(d, Decision::Deny { .. }),
            "a key bound to one vault must not act on another (role {role})"
        );
        for action in [
            Action::ApiKeyManage,
            Action::NodeManage,
            Action::TemplateApprove,
            Action::CredentialWiden,
            Action::SettingsWrite,
        ] {
            let d = authz.authorize(&key(role), action, Some(&vault_a)).await;
            ensure!(
                S,
                "instance_actions",
                matches!(d, Decision::Deny { .. }),
                "API keys must never get instance-level action {action}"
            );
        }
    }
    let d = authz
        .authorize(&key(Role::Admin), Action::VaultRead, Some(&vault_a))
        .await;
    ensure!(
        S,
        "no_admin_keys",
        matches!(d, Decision::Deny { .. }),
        "an API key holding the admin role must be refused"
    );
    let d = authz
        .authorize(
            &key(Role::SessionIssuer),
            Action::SessionMint,
            Some(&vault_a),
        )
        .await;
    ensure!(
        S,
        "issuer_can_mint",
        d == Decision::Allow,
        "a session issuer must be able to mint in its vault, got {d:?}"
    );
    let admin = Principal {
        kind: PrincipalKind::User,
        actor: "user:conformance".into(),
        role: Role::Admin,
        vault: None,
    };
    let d = authz.authorize(&admin, Action::NodeManage, None).await;
    ensure!(
        S,
        "admin_allowed",
        d == Decision::Allow,
        "an admin must be able to manage nodes, got {d:?}"
    );
    Ok(())
}

pub async fn identity_store_suite(store: &dyn IdentityStore) -> Result<(), ConformanceFailure> {
    const S: &str = "identity_store";
    ensure!(
        S,
        "empty",
        store.count_users().await.map_err(backend(S, "count"))? == 0,
        "store must start empty"
    );
    let user = User {
        id: UserId::new(),
        username: "admin".into(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        totp_secret_enc: vec![1, 2, 3],
        totp_last_step: Some(10),
        role: Role::Admin,
        created_at: at(0),
    };
    store
        .insert_user(user.clone(), &[])
        .await
        .map_err(backend(S, "user_insert"))?;
    let mut dup = user.clone();
    dup.id = UserId::new();
    let res = store.insert_user(dup, &[]).await;
    ensure!(
        S,
        "user_duplicate",
        matches!(res, Err(StoreError::Conflict { .. })),
        "duplicate username must be Conflict, got {res:?}"
    );
    let got = store
        .get_user_by_username("admin")
        .await
        .map_err(backend(S, "user_by_name"))?;
    ensure!(
        S,
        "user_round_trip",
        got.as_ref() == Some(&user),
        "user did not round-trip: {got:?}"
    );
    let replay = store
        .advance_totp_step(&user.id, 10)
        .await
        .map_err(backend(S, "totp_replay"))?;
    let older = store
        .advance_totp_step(&user.id, 9)
        .await
        .map_err(backend(S, "totp_older"))?;
    let newer = store
        .advance_totp_step(&user.id, 11)
        .await
        .map_err(backend(S, "totp_newer"))?;
    ensure!(
        S,
        "totp_monotonic",
        !replay && !older && newer,
        "TOTP steps must strictly increase (got replay={replay}, older={older}, newer={newer})"
    );

    let session = UiSession {
        token_hash: "h1".into(),
        user_id: user.id,
        created_at: at(-100),
        expires_at: at(100),
        step_up_at: None,
    };
    let stale = UiSession {
        token_hash: "h2".into(),
        expires_at: at(-1),
        ..session.clone()
    };
    store
        .insert_ui_session(session.clone(), &[])
        .await
        .map_err(backend(S, "ui_insert"))?;
    store
        .insert_ui_session(stale, &[])
        .await
        .map_err(backend(S, "ui_insert"))?;
    store
        .set_ui_session_step_up("h1", at(5), &[])
        .await
        .map_err(backend(S, "ui_step_up"))?;
    let got = store
        .get_ui_session("h1")
        .await
        .map_err(backend(S, "ui_get"))?;
    ensure!(
        S,
        "ui_step_up",
        got.and_then(|s| s.step_up_at) == Some(at(5)),
        "step-up time not stored"
    );
    let purged = store
        .delete_expired_ui_sessions(at(0))
        .await
        .map_err(backend(S, "ui_purge"))?;
    ensure!(
        S,
        "ui_purge",
        purged == 1,
        "expected 1 expired session purged, got {purged}"
    );
    store
        .delete_ui_session("h1", &[])
        .await
        .map_err(backend(S, "ui_delete"))?;
    ensure!(
        S,
        "ui_delete",
        store
            .get_ui_session("h1")
            .await
            .map_err(backend(S, "ui_get"))?
            .is_none(),
        "session survived delete"
    );

    store
        .replace_setup_token("old", at(0))
        .await
        .map_err(backend(S, "setup_replace"))?;
    store
        .replace_setup_token("new", at(1))
        .await
        .map_err(backend(S, "setup_replace"))?;
    let old = store
        .consume_setup_token("old")
        .await
        .map_err(backend(S, "setup_old"))?;
    let new = store
        .consume_setup_token("new")
        .await
        .map_err(backend(S, "setup_new"))?;
    let again = store
        .consume_setup_token("new")
        .await
        .map_err(backend(S, "setup_again"))?;
    ensure!(S, "setup_once", !old && new && !again, "setup token must be replaceable and consumable exactly once (old={old}, new={new}, again={again})");

    let key = ApiKey {
        id: ApiKeyId::new(),
        name: "ci".into(),
        prefix: "cbk_conformance".into(),
        secret_hash: "hash".into(),
        vault_id: VaultId::new(),
        role: Role::SessionIssuer,
        created_by: "user:conformance".into(),
        created_at: at(0),
        expires_at: at(3600),
        revoked_at: None,
        last_used_at: None,
    };
    store
        .insert_api_key(key.clone(), &[])
        .await
        .map_err(backend(S, "key_insert"))?;
    let dup = store
        .insert_api_key(
            ApiKey {
                id: ApiKeyId::new(),
                ..key.clone()
            },
            &[],
        )
        .await;
    ensure!(
        S,
        "key_duplicate",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "duplicate prefix must be Conflict, got {dup:?}"
    );
    let got = store
        .get_api_key_by_prefix(&key.prefix)
        .await
        .map_err(backend(S, "key_get"))?;
    ensure!(
        S,
        "key_hash_kept",
        got.as_ref().map(|k| k.secret_hash.as_str()) == Some("hash"),
        "secret hash must be stored for verification"
    );
    let first = store
        .revoke_api_key(&key.id, at(1), &[])
        .await
        .map_err(backend(S, "key_revoke"))?;
    let second = store
        .revoke_api_key(&key.id, at(2), &[])
        .await
        .map_err(backend(S, "key_revoke"))?;
    ensure!(
        S,
        "key_revoke",
        first && !second,
        "revoke must report the first change only"
    );
    let missing = store.revoke_api_key(&ApiKeyId::new(), at(0), &[]).await;
    ensure!(
        S,
        "key_revoke_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    Ok(())
}

pub async fn node_store_suite(store: &dyn NodeStore) -> Result<(), ConformanceFailure> {
    const S: &str = "node_store";
    let token = JoinTokenRecord {
        id: "jt1".into(),
        secret_hash: "secret-hash".into(),
        created_by: "user:conformance".into(),
        created_at: at(0),
        expires_at: at(600),
        consumed_at: None,
    };
    let expired = JoinTokenRecord {
        id: "jt2".into(),
        expires_at: at(-1),
        ..token.clone()
    };
    store
        .insert_join_token(token.clone(), &[])
        .await
        .map_err(backend(S, "join_insert"))?;
    store
        .insert_join_token(expired, &[])
        .await
        .map_err(backend(S, "join_insert"))?;
    let wrong = store
        .consume_join_token("jt1", "other", at(0))
        .await
        .map_err(backend(S, "join_wrong"))?;
    let ok = store
        .consume_join_token("jt1", "secret-hash", at(0))
        .await
        .map_err(backend(S, "join_ok"))?;
    let again = store
        .consume_join_token("jt1", "secret-hash", at(0))
        .await
        .map_err(backend(S, "join_again"))?;
    let stale = store
        .consume_join_token("jt2", "secret-hash", at(0))
        .await
        .map_err(backend(S, "join_expired"))?;
    ensure!(S, "join_once", !wrong && ok && !again && !stale, "join tokens must be single use, unexpired and hash-matched (wrong={wrong}, ok={ok}, again={again}, expired={stale})");

    let node = Node {
        id: NodeId::new(),
        name: "node-a".into(),
        seal_public_key: "pk".into(),
        cert_serial: "01".into(),
        cert_not_after: at(3600),
        enrolled_at: at(0),
        last_seen_at: None,
        revoked_at: None,
    };
    store
        .insert_node(node.clone(), &[])
        .await
        .map_err(backend(S, "node_insert"))?;
    store
        .update_node_cert(&node.id, "02", at(7200), &[])
        .await
        .map_err(backend(S, "node_cert"))?;
    store
        .touch_node(&node.id, at(10))
        .await
        .map_err(backend(S, "node_touch"))?;
    let got = store
        .get_node(&node.id)
        .await
        .map_err(backend(S, "node_get"))?;
    ensure!(
        S,
        "node_update",
        got.as_ref()
            .map(|n| (n.cert_serial.as_str(), n.last_seen_at))
            == Some(("02", Some(at(10)))),
        "node cert/heartbeat not stored: {got:?}"
    );
    let first = store
        .revoke_node(&node.id, at(20), &[])
        .await
        .map_err(backend(S, "node_revoke"))?;
    let second = store
        .revoke_node(&node.id, at(21), &[])
        .await
        .map_err(backend(S, "node_revoke"))?;
    ensure!(
        S,
        "node_revoke",
        first && !second,
        "revoke must report the first change only"
    );
    let listed = store
        .list_nodes(PageRequest::default())
        .await
        .map_err(backend(S, "node_list"))?;
    ensure!(
        S,
        "node_list",
        listed.total == 1,
        "expected 1 node, got {}",
        listed.total
    );

    let kept = store
        .put_key_material_if_absent("k", b"first".to_vec())
        .await
        .map_err(backend(S, "key_put"))?;
    let raced = store
        .put_key_material_if_absent("k", b"second".to_vec())
        .await
        .map_err(backend(S, "key_put"))?;
    ensure!(
        S,
        "key_first_wins",
        kept == b"first" && raced == b"first",
        "the first stored key material must win"
    );
    let got = store
        .get_key_material("k")
        .await
        .map_err(backend(S, "key_get"))?;
    ensure!(
        S,
        "key_get",
        got.as_deref() == Some(b"first".as_slice()),
        "key material not readable"
    );

    let a = store
        .next_snapshot_version()
        .await
        .map_err(backend(S, "version"))?;
    let b = store
        .next_snapshot_version()
        .await
        .map_err(backend(S, "version"))?;
    ensure!(
        S,
        "version_monotonic",
        b > a && a > 0,
        "snapshot versions must strictly increase from 1 (got {a} then {b})"
    );
    Ok(())
}
