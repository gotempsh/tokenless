// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behaviour every implementation of the broker's store traits must show.
//!
//! An embedding platform runs these against its own `CredentialStore`,
//! `PolicyStore`, `AuditSink`, `Authorizer`, `IdentityStore` and `NodeStore`
//! implementations. Each suite expects an empty store and returns the first
//! failed check with a description of what was expected.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokenless_control::model::{
    AccessBundle, ApiKey, AuditQuery, CredentialMeta, Invite, JoinTokenRecord, Node, PageRequest,
    ProxySession, Rule, SessionBundle, Settings, StoredTemplate, TemplateSource, TemplateStatus,
    UiSession, User, Variable, Vault, VaultDeletion,
};
use tokenless_control::store::{
    AuditSink, Authorizer, CiphertextOwner, CredentialStore, IdentityStore, NodeStore, PolicyStore,
};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Action, Decision, Principal, PrincipalKind, Role};
use tokenless_core::egress::{EgressPolicy, IpCidr};
use tokenless_core::ids::{
    ApiKeyId, BundleId, CredentialId, InviteId, NodeId, RuleId, SessionId, UserId, VariableId,
    VaultId,
};
use tokenless_core::rule::RuleScope;
use tokenless_core::scope::Scope;
use tokenless_core::snapshot::UnmatchedHostPolicy;
use tokenless_core::substitution::{Substitution, SubstitutionLocation};
use tokenless_core::template::builtin_templates;
use tokenless_core::variables::CustomHeader;

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

/// The instant every `at` offset counts from, read once so that a check
/// which writes `at(7)` and later compares against `at(7)` gets the same
/// value even when a second boundary passes in between.
static EPOCH: LazyLock<i64> = LazyLock::new(|| Utc::now().timestamp());

fn at(offset_secs: i64) -> DateTime<Utc> {
    // Whole seconds keep timestamp round-trips exact for every backend.
    DateTime::from_timestamp(*EPOCH + offset_secs, 0).unwrap_or_else(Utc::now)
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
        custom_headers: vec![],
        variable_refs: vec![],
        substitutions: vec![],
        created_by: "user:conformance".into(),
        created_at: at(created_offset),
        updated_at: at(created_offset),
    }
}

fn scope() -> Result<RuleScope, ConformanceFailure> {
    let parse_err = |e: tokenless_core::CoreError| ConformanceFailure {
        suite: "fixtures",
        check: "rule_scope",
        detail: e.to_string(),
    };
    Ok(RuleScope {
        hosts: vec![tokenless_core::host::HostPattern::parse("api.example.com").map_err(parse_err)?],
        paths: vec![tokenless_core::path::PathPattern::parse("/*").map_err(parse_err)?],
        methods: vec![tokenless_core::path::HttpMethod::parse("GET").map_err(parse_err)?],
        mcp_tools: Some(vec!["search".to_string()]),
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
        bundle: None,
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
            vec![],
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
        .replace_secret(&CredentialId::new(), vec![], vec![], vec![], at(0), &[])
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

fn variable(key: &str, created_offset: i64) -> Variable {
    Variable {
        id: VariableId::new(),
        key: key.to_string(),
        created_by: "user:conformance".into(),
        created_at: at(created_offset),
        updated_by: "user:conformance".into(),
        updated_at: at(created_offset),
    }
}

/// Variables, custom headers and the reference bookkeeping that keeps a
/// variable from being deleted while a credential uses it.
pub async fn variable_store_suite(store: &dyn CredentialStore) -> Result<(), ConformanceFailure> {
    const S: &str = "variable_store";
    let token = variable("GITHUB_TOKEN", -20);
    let org = variable("ORG_ID", -10);
    store
        .insert_variable(token.clone(), b"v-1".to_vec(), &[])
        .await
        .map_err(backend(S, "insert"))?;
    store
        .insert_variable(org.clone(), b"v-2".to_vec(), &[])
        .await
        .map_err(backend(S, "insert"))?;
    let dup = store
        .insert_variable(variable("GITHUB_TOKEN", 0), b"v-3".to_vec(), &[])
        .await;
    ensure!(
        S,
        "duplicate_key",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "a second variable with the same key must be a Conflict, got {dup:?}"
    );

    let fetched = store
        .get_variable(&token.id)
        .await
        .map_err(backend(S, "get"))?;
    ensure!(
        S,
        "get",
        fetched.as_ref() == Some(&token),
        "got {fetched:?}"
    );
    let page = store
        .list_variables(PageRequest::new(Some(1), Some(10)))
        .await
        .map_err(backend(S, "list"))?;
    let keys: Vec<&str> = page.items.iter().map(|v| v.key.as_str()).collect();
    ensure!(
        S,
        "list",
        page.total == 2 && keys == ["GITHUB_TOKEN", "ORG_ID"],
        "expected both variables ordered by key, got {keys:?} (total {})",
        page.total
    );
    let mut existing = store
        .existing_variable_keys(&["ORG_ID".into(), "MISSING".into()])
        .await
        .map_err(backend(S, "existing"))?;
    existing.sort();
    ensure!(S, "existing", existing == ["ORG_ID"], "got {existing:?}");

    store
        .replace_variable_value(&org.id, b"v-2b".to_vec(), "user:other", at(5), &[])
        .await
        .map_err(backend(S, "replace"))?;
    let loaded = store
        .load_variable_ciphertexts(&["ORG_ID".into()])
        .await
        .map_err(backend(S, "load"))?;
    ensure!(
        S,
        "replace",
        loaded.len() == 1
            && loaded[0].1 == b"v-2b"
            && loaded[0].0.updated_by == "user:other"
            && loaded[0].0.updated_at == at(5),
        "replaced value and updater not stored: {:?}",
        loaded.iter().map(|(v, _)| v).collect::<Vec<_>>()
    );
    let missing = store
        .replace_variable_value(&VariableId::new(), vec![], "x", at(0), &[])
        .await;
    ensure!(
        S,
        "replace_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    // A credential referencing ORG_ID from a custom header.
    let mut cred = credential(VaultId::new(), "with-headers", -5);
    cred.custom_headers = vec![CustomHeader {
        name: "X-Org".into(),
        value: "{{ORG_ID}}".into(),
    }];
    cred.variable_refs = vec!["ORG_ID".into()];
    store
        .insert_credential(cred.clone(), b"ct".to_vec(), &[])
        .await
        .map_err(backend(S, "credential_insert"))?;
    let plain = credential(VaultId::new(), "plain", -4);
    store
        .insert_credential(plain.clone(), b"ct".to_vec(), &[])
        .await
        .map_err(backend(S, "credential_insert"))?;
    let using = store
        .list_credentials_with_variables()
        .await
        .map_err(backend(S, "with_variables"))?;
    ensure!(
        S,
        "with_variables",
        using.len() == 1 && using[0] == cred,
        "only the referencing credential, with its headers, must be listed: {using:?}"
    );
    let blocked = store.delete_variable(&org.id, &[]).await;
    ensure!(
        S,
        "delete_in_use",
        matches!(blocked, Err(StoreError::Conflict { .. })),
        "deleting a referenced variable must be a Conflict, got {blocked:?}"
    );

    // Dropping the reference frees the variable.
    store
        .update_custom_headers(&cred.id, vec![], vec![], at(6), &[])
        .await
        .map_err(backend(S, "update_headers"))?;
    let updated = store
        .get_credential(&cred.id)
        .await
        .map_err(backend(S, "update_headers_get"))?;
    ensure!(
        S,
        "update_headers",
        updated
            .as_ref()
            .is_some_and(|m| m.custom_headers.is_empty() && m.variable_refs.is_empty()),
        "headers and refs not cleared: {updated:?}"
    );
    let missing = store
        .update_custom_headers(&CredentialId::new(), vec![], vec![], at(0), &[])
        .await;
    ensure!(
        S,
        "update_headers_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    // Substitutions are stored as configuration and read back as written.
    let substitution = Substitution {
        placeholder: "__GITHUB_TOKEN__".into(),
        field: "token".into(),
        env: Some("GITHUB_TOKEN".into()),
        locations: vec![SubstitutionLocation::Query, SubstitutionLocation::Body],
    };
    store
        .update_substitutions(&cred.id, vec![substitution.clone()], at(7), &[])
        .await
        .map_err(backend(S, "update_substitutions"))?;
    let updated = store
        .get_credential(&cred.id)
        .await
        .map_err(backend(S, "update_substitutions_get"))?;
    ensure!(
        S,
        "update_substitutions",
        updated
            .as_ref()
            .is_some_and(|m| m.substitutions == [substitution.clone()] && m.updated_at == at(7)),
        "substitutions not stored: {updated:?}"
    );
    let missing = store
        .update_substitutions(&CredentialId::new(), vec![], at(0), &[])
        .await;
    ensure!(
        S,
        "update_substitutions_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    store
        .delete_variable(&org.id, &[])
        .await
        .map_err(backend(S, "delete"))?;
    let gone = store
        .get_variable(&org.id)
        .await
        .map_err(backend(S, "delete_get"))?;
    ensure!(
        S,
        "delete",
        gone.is_none(),
        "variable still present after delete"
    );
    let again = store.delete_variable(&org.id, &[]).await;
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
        .list_sessions(Some(&v1.id), None, PageRequest::default())
        .await
        .map_err(backend(S, "session_list"))?;
    ensure!(
        S,
        "session_list",
        listed.total == 3,
        "expected 3 sessions in vault alpha, got {}",
        listed.total
    );
    store
        .insert_session(session(VaultId::new(), 30, None), &[])
        .await
        .map_err(backend(S, "session_insert_other"))?;
    let bundle_id = BundleId::new();
    let from_bundle = ProxySession {
        bundle: Some(SessionBundle {
            id: bundle_id,
            name: "code-review".into(),
        }),
        ..session(v1.id, 30, None)
    };
    store
        .insert_session(from_bundle.clone(), &[])
        .await
        .map_err(backend(S, "session_insert_bundle"))?;
    let by_bundle = store
        .list_sessions(Some(&v1.id), Some(&bundle_id), PageRequest::default())
        .await
        .map_err(backend(S, "session_list_bundle"))?;
    ensure!(
        S,
        "session_list_bundle",
        by_bundle.total == 1
            && by_bundle.items.len() == 1
            && by_bundle.items[0].id == from_bundle.id
            && by_bundle.items[0].bundle.as_ref().map(|b| b.id) == Some(bundle_id),
        "listing by bundle must return only the session minted from it, got {} of {:?}",
        by_bundle.total,
        by_bundle.items.iter().map(|s| s.id).collect::<Vec<_>>()
    );
    let everywhere = store
        .list_sessions(None, None, PageRequest::default())
        .await
        .map_err(backend(S, "session_list_all"))?;
    ensure!(
        S,
        "session_list_all",
        everywhere.total > listed.total
            && everywhere
                .items
                .windows(2)
                .all(|w| w[0].created_at >= w[1].created_at),
        "listing without a vault must include every vault, newest first; got {} of {}",
        everywhere.total,
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
        max_session_ttl_secs: 8 * 3600,
        passthrough_hosts: vec![
            tokenless_core::host::HostPattern::parse("registry.npmjs.org").map_err(|e| {
                ConformanceFailure {
                    suite: S,
                    check: "settings_host",
                    detail: e.to_string(),
                }
            })?,
        ],
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

fn bundle(vault_id: VaultId, name: &str, mut rule_ids: Vec<RuleId>) -> AccessBundle {
    rule_ids.sort();
    AccessBundle {
        id: BundleId::new(),
        vault_id,
        name: name.to_string(),
        description: format!("{name} bundle"),
        rule_ids,
        created_by: "user:conformance".into(),
        created_at: at(0),
        updated_at: at(0),
    }
}

/// Access bundles: names unique per vault, rule lists replaced whole and
/// kept sorted, deleted rules dropped from every bundle, and the bundle a
/// session was minted from kept on the session.
pub async fn bundle_store_suite(store: &dyn PolicyStore) -> Result<(), ConformanceFailure> {
    const S: &str = "bundle_store";
    let v1 = vault("alpha", -20);
    let v2 = vault("beta", -10);
    for v in [&v1, &v2] {
        store
            .insert_vault(v.clone(), &[])
            .await
            .map_err(backend(S, "vault_insert"))?;
    }
    let cred = CredentialId::new();
    let mut rules = Vec::new();
    for name in ["one", "two", "three"] {
        let r = rule(v1.id, cred, name, true)?;
        store
            .insert_rule(r.clone(), &[])
            .await
            .map_err(backend(S, "rule_insert"))?;
        rules.push(r);
    }

    let review = bundle(v1.id, "review", vec![rules[0].id, rules[1].id]);
    let empty = bundle(v1.id, "empty", vec![]);
    let other = bundle(v2.id, "review", vec![]);
    for b in [&review, &empty, &other] {
        store
            .insert_bundle(b.clone(), &[])
            .await
            .map_err(backend(S, "insert"))?;
    }
    let got = store
        .get_bundle(&review.id)
        .await
        .map_err(backend(S, "get"))?;
    ensure!(
        S,
        "get_round_trip",
        got.as_ref() == Some(&review),
        "expected {review:?}, got {got:?}"
    );
    let got = store
        .get_bundle(&empty.id)
        .await
        .map_err(backend(S, "get_empty"))?;
    ensure!(
        S,
        "get_empty_round_trip",
        got.as_ref() == Some(&empty),
        "an empty bundle must round-trip with no rules, got {got:?}"
    );
    let by_name = store
        .get_bundle_by_name(&v2.id, "review")
        .await
        .map_err(backend(S, "get_by_name"))?;
    ensure!(
        S,
        "get_by_name_is_vault_scoped",
        by_name.as_ref().map(|b| b.id) == Some(other.id),
        "the name 'review' in vault beta is {}, got {by_name:?}",
        other.id
    );
    let none = store
        .get_bundle_by_name(&v1.id, "nope")
        .await
        .map_err(backend(S, "get_by_name_missing"))?;
    ensure!(S, "get_by_name_missing", none.is_none(), "got {none:?}");
    let dup = store
        .insert_bundle(bundle(v1.id, "review", vec![]), &[])
        .await;
    ensure!(
        S,
        "name_conflict",
        matches!(dup, Err(StoreError::Conflict { .. })),
        "a second 'review' in vault alpha must conflict, got {dup:?}"
    );

    let page = store
        .list_bundles(Some(&v1.id), PageRequest::new(None, None))
        .await
        .map_err(backend(S, "list"))?;
    let names: Vec<_> = page.items.iter().map(|b| b.name.as_str()).collect();
    ensure!(
        S,
        "list_by_name_in_vault",
        page.total == 2 && names == ["empty", "review"],
        "expected [empty, review] (total 2), got {names:?} (total {})",
        page.total
    );
    let every = store
        .list_bundles(None, PageRequest::new(None, None))
        .await
        .map_err(backend(S, "list_all"))?;
    let names: Vec<_> = every.items.iter().map(|b| b.name.as_str()).collect();
    ensure!(
        S,
        "list_across_vaults",
        every.total == 3 && names == ["empty", "review", "review"],
        "expected both vaults' bundles [empty, review, review] (total 3), got {names:?} (total {})",
        every.total
    );

    let mut renamed = review.clone();
    renamed.name = "code-review".into();
    renamed.description = "changed".into();
    renamed.rule_ids = vec![rules[1].id, rules[2].id];
    renamed.rule_ids.sort();
    renamed.updated_at = at(5);
    store
        .update_bundle(renamed.clone(), &[])
        .await
        .map_err(backend(S, "update"))?;
    let got = store
        .get_bundle(&review.id)
        .await
        .map_err(backend(S, "update_get"))?;
    ensure!(
        S,
        "update_replaces_rules",
        got.as_ref() == Some(&renamed),
        "expected {renamed:?}, got {got:?}"
    );
    let mut clash = empty.clone();
    clash.name = "code-review".into();
    let result = store.update_bundle(clash, &[]).await;
    ensure!(
        S,
        "update_name_conflict",
        matches!(result, Err(StoreError::Conflict { .. })),
        "renaming onto a taken name must conflict, got {result:?}"
    );
    let result = store
        .update_bundle(bundle(v1.id, "ghost", vec![]), &[])
        .await;
    ensure!(
        S,
        "update_missing",
        matches!(result, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {result:?}"
    );

    store
        .delete_rule(&rules[1].id, &[])
        .await
        .map_err(backend(S, "rule_delete"))?;
    let got = store
        .get_bundle(&review.id)
        .await
        .map_err(backend(S, "after_rule_delete"))?;
    ensure!(
        S,
        "rule_delete_leaves_bundles",
        got.map(|b| b.rule_ids) == Some(vec![rules[2].id]),
        "deleting rule {} must drop it from the bundle",
        rules[1].id
    );

    let mut minted = session(v1.id, 600, None);
    minted.bundle = Some(SessionBundle {
        id: review.id,
        name: "code-review".into(),
    });
    store
        .insert_session(minted.clone(), &[])
        .await
        .map_err(backend(S, "session_insert"))?;
    let got = store
        .get_session(&minted.id)
        .await
        .map_err(backend(S, "session_get"))?;
    ensure!(
        S,
        "session_keeps_bundle",
        got.as_ref() == Some(&minted),
        "expected {minted:?}, got {got:?}"
    );
    let mut expired = session(v1.id, -5, None);
    expired.bundle = minted.bundle.clone();
    store
        .insert_session(expired.clone(), &[])
        .await
        .map_err(backend(S, "expired_insert"))?;

    // Labels can be replaced after minting.
    let relabelled = BTreeMap::from([("ticket".to_string(), "T-1".to_string())]);
    store
        .update_session_labels(&minted.id, relabelled.clone(), &[])
        .await
        .map_err(backend(S, "labels"))?;
    let got = store
        .get_session(&minted.id)
        .await
        .map_err(backend(S, "labels_get"))?;
    ensure!(
        S,
        "labels_replaced",
        got.as_ref().map(|s| &s.labels) == Some(&relabelled),
        "expected {relabelled:?}, got {got:?}"
    );
    let missing = store
        .update_session_labels(&SessionId::new(), BTreeMap::new(), &[])
        .await;
    ensure!(
        S,
        "labels_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    let revoked = store
        .delete_bundle(&review.id, at(1), &[])
        .await
        .map_err(backend(S, "delete"))?;
    ensure!(
        S,
        "delete_revokes_live_sessions",
        revoked == 1,
        "only the live session minted from the bundle is revoked, got {revoked}"
    );
    let gone = store
        .get_bundle(&review.id)
        .await
        .map_err(backend(S, "delete_get"))?;
    ensure!(S, "delete", gone.is_none(), "got {gone:?}");
    let missing = store.delete_bundle(&review.id, at(1), &[]).await;
    ensure!(
        S,
        "delete_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    let got = store
        .get_session(&minted.id)
        .await
        .map_err(backend(S, "session_after_delete"))?;
    ensure!(
        S,
        "session_outlives_bundle",
        got.as_ref()
            .and_then(|s| s.bundle.as_ref())
            .map(|b| b.name.as_str())
            == Some("code-review")
            && got.as_ref().and_then(|s| s.revoked_at) == Some(at(1)),
        "a session keeps the bundle name it was minted with and is revoked: {got:?}"
    );
    let untouched = store
        .get_session(&expired.id)
        .await
        .map_err(backend(S, "expired_after_delete"))?;
    ensure!(
        S,
        "expired_session_untouched",
        untouched.and_then(|s| s.revoked_at).is_none(),
        "an expired session is not revoked"
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
    let session = SessionId::new();
    events[2] = events[2].clone().detail("session_id", session.to_string());
    events[3] = events[3].clone().target(format!("session:{session}"));
    // An event about another session belongs to that session, even when
    // this one's id appears in its details.
    events[4] = events[4]
        .clone()
        .target(format!("session:{}", SessionId::new()))
        .detail("session_id", session.to_string());
    let credential = CredentialId::new();
    events[0] = events[0]
        .clone()
        .detail("credential_id", credential.to_string());
    events[1] = events[1].clone().target(format!("credential:{credential}"));
    // An event about another service belongs to that service.
    events[2] = events[2]
        .clone()
        .target(format!("credential:{}", CredentialId::new()))
        .detail("credential_id", credential.to_string());
    sink.record(&events).await.map_err(backend(S, "record"))?;
    let by_credential = sink
        .query(&AuditQuery {
            credential_id: Some(credential),
            ..Default::default()
        })
        .await
        .map_err(backend(S, "query_credential"))?;
    ensure!(
        S,
        "query_credential",
        by_credential.total == 2
            && by_credential.items[0].id == events[1].id
            && by_credential.items[1].id == events[0].id,
        "expected the service's traffic and its own history, newest first, got {:?}",
        by_credential.items
    );
    let by_session = sink
        .query(&AuditQuery {
            session_id: Some(session),
            ..Default::default()
        })
        .await
        .map_err(backend(S, "query_session"))?;
    ensure!(
        S,
        "query_session",
        by_session.total == 2
            && by_session.items[0].id == events[3].id
            && by_session.items[1].id == events[2].id,
        "expected the session's traffic and its own history, newest first, got {:?}",
        by_session.items
    );
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
/// Deleting a vault removes what is in it, revokes its sessions and API
/// keys, and leaves other vaults alone.
pub async fn vault_deletion_suite<T>(store: &T) -> Result<(), ConformanceFailure>
where
    T: CredentialStore + PolicyStore + IdentityStore,
{
    const S: &str = "vault_deletion";
    let doomed = vault("doomed", -20);
    let kept = vault("kept", -10);
    let mut creds = Vec::new();
    for v in [&doomed, &kept] {
        PolicyStore::insert_vault(store, v.clone(), &[])
            .await
            .map_err(backend(S, "vault_insert"))?;
        let c = credential(v.id, "svc", -5);
        store
            .insert_credential(c.clone(), vec![1, 2, 3], &[])
            .await
            .map_err(backend(S, "credential_insert"))?;
        let r = rule(v.id, c.id, "r", true)?;
        store
            .insert_rule(r.clone(), &[])
            .await
            .map_err(backend(S, "rule_insert"))?;
        store
            .insert_bundle(bundle(v.id, "b", vec![r.id]), &[])
            .await
            .map_err(backend(S, "bundle_insert"))?;
        creds.push(c);
    }
    let live = session(doomed.id, 600, None);
    let expired = session(doomed.id, -5, None);
    let elsewhere = session(kept.id, 600, None);
    for s in [&live, &expired, &elsewhere] {
        store
            .insert_session(s.clone(), &[])
            .await
            .map_err(backend(S, "session_insert"))?;
    }
    let count = store
        .count_live_sessions(&doomed.id, at(0))
        .await
        .map_err(backend(S, "count"))?;
    ensure!(
        S,
        "count_live",
        count == 1,
        "expected 1 live session, got {count}"
    );
    let key = ApiKey {
        id: ApiKeyId::new(),
        name: "ci".into(),
        prefix: "cbk_vaultdel".into(),
        secret_hash: "hash".into(),
        vault_id: doomed.id,
        role: Role::Editor,
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

    let done = store
        .delete_vault(&doomed.id, at(1), &[])
        .await
        .map_err(backend(S, "delete"))?;
    let expected = VaultDeletion {
        credentials: 1,
        rules: 1,
        bundles: 1,
        sessions_revoked: 1,
        api_keys_revoked: 1,
    };
    ensure!(
        S,
        "counts",
        done == expected,
        "expected {expected:?}, got {done:?}"
    );
    let gone = PolicyStore::get_vault(store, &doomed.id)
        .await
        .map_err(backend(S, "vault_get"))?;
    ensure!(S, "vault_gone", gone.is_none(), "got {gone:?}");
    let cred = store
        .get_credential(&creds[0].id)
        .await
        .map_err(backend(S, "credential_get"))?;
    ensure!(S, "credential_gone", cred.is_none(), "got {cred:?}");
    let secret = store
        .load_secret_ciphertext(&creds[0].id)
        .await
        .map_err(backend(S, "secret_get"))?;
    ensure!(
        S,
        "secret_gone",
        secret.is_none(),
        "the ciphertext must go too"
    );
    let revoked = store
        .get_session(&live.id)
        .await
        .map_err(backend(S, "session_get"))?;
    ensure!(
        S,
        "session_revoked_not_deleted",
        revoked.and_then(|s| s.revoked_at) == Some(at(1)),
        "the session record stays, revoked, so its token is refused until it expires"
    );
    let key_after = store
        .get_api_key_by_prefix(&key.prefix)
        .await
        .map_err(backend(S, "key_get"))?;
    ensure!(
        S,
        "api_key_revoked",
        key_after.and_then(|k| k.revoked_at).is_some(),
        "keys bound to the vault are revoked"
    );
    let other = store
        .get_credential(&creds[1].id)
        .await
        .map_err(backend(S, "other_get"))?;
    let other_session = store
        .get_session(&elsewhere.id)
        .await
        .map_err(backend(S, "other_session"))?;
    ensure!(
        S,
        "other_vault_untouched",
        other.is_some() && other_session.and_then(|s| s.revoked_at).is_none(),
        "another vault's credential and session must be untouched"
    );
    let missing = store.delete_vault(&doomed.id, at(2), &[]).await;
    ensure!(
        S,
        "delete_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );
    Ok(())
}

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
    for role in [Role::Editor, Role::Viewer] {
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
            Action::UserRead,
            Action::UserManage,
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
        .authorize(&key(Role::Editor), Action::SessionMint, Some(&vault_a))
        .await;
    ensure!(
        S,
        "editor_can_mint",
        d == Decision::Allow,
        "an editor key must be able to mint in its vault, got {d:?}"
    );
    // A service bound to a vault stays in it, whatever role it holds.
    for role in [Role::Admin, Role::Editor] {
        let service = Principal::service("conformance", role, Some(vault_a));
        for (action, target) in [
            (Action::RuleRead, Some(&vault_b)),
            (Action::SessionMint, Some(&vault_b)),
            (Action::CredentialWrite, Some(&vault_b)),
            (Action::NodeManage, None),
            (Action::VaultCreate, None),
        ] {
            let d = authz.authorize(&service, action, target).await;
            ensure!(
                S,
                "service_vault_binding",
                matches!(d, Decision::Deny { .. }),
                "a service bound to one vault must not get {action} on {target:?} (role {role})"
            );
        }
    }
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
    for role in [Role::Editor, Role::Viewer] {
        let person = Principal {
            role,
            ..admin.clone()
        };
        for action in [Action::UserRead, Action::UserManage] {
            let d = authz.authorize(&person, action, None).await;
            ensure!(
                S,
                "user_management_is_admin_only",
                matches!(d, Decision::Deny { .. }),
                "a person with role {role} must not get {action}"
            );
        }
    }
    Ok(())
}

fn person(username: &str, role: Role, created_offset: i64) -> User {
    User {
        id: UserId::new(),
        username: username.into(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
        totp_secret_enc: Some(vec![1, 2, 3]),
        totp_last_step: None,
        role,
        created_at: at(created_offset),
        disabled_at: None,
    }
}

fn invite(token_hash: &str, role: Role, created_offset: i64, expires_offset: i64) -> Invite {
    Invite {
        id: InviteId::new(),
        token_hash: token_hash.into(),
        role,
        created_by: "user:conformance".into(),
        created_at: at(created_offset),
        expires_at: at(expires_offset),
        accepted_at: None,
        accepted_by: None,
        revoked_at: None,
    }
}

/// Role changes, disabling and invitations. Expects an empty store.
pub async fn user_management_suite(store: &dyn IdentityStore) -> Result<(), ConformanceFailure> {
    const S: &str = "user_management";
    let alice = person("alice", Role::Admin, -20);
    let bob = User {
        totp_secret_enc: None,
        ..person("bob", Role::Editor, -10)
    };
    for u in [&alice, &bob] {
        store
            .insert_user(u.clone(), &[])
            .await
            .map_err(backend(S, "insert"))?;
    }
    let listed = store
        .list_users(PageRequest::default())
        .await
        .map_err(backend(S, "list"))?;
    ensure!(
        S,
        "list",
        listed.total == 2 && listed.items.first().map(|u| u.id) == Some(bob.id),
        "expected 2 users newest first, got {:?}",
        listed.items.iter().map(|u| &u.username).collect::<Vec<_>>()
    );

    let got = store
        .get_user(&bob.id)
        .await
        .map_err(backend(S, "password_only"))?;
    ensure!(
        S,
        "password_only",
        got.as_ref() == Some(&bob),
        "a user without a TOTP secret must round-trip, got {got:?}"
    );
    store
        .update_user_access(&bob.id, Role::Viewer, None, &[])
        .await
        .map_err(backend(S, "change_role"))?;
    let got = store
        .get_user(&bob.id)
        .await
        .map_err(backend(S, "change_role"))?;
    ensure!(
        S,
        "change_role",
        got.map(|u| u.role) == Some(Role::Viewer),
        "role change was not stored"
    );

    for (role, disabled, check) in [
        (Role::Editor, None, "last_admin_demote"),
        (Role::Admin, Some(at(0)), "last_admin_disable"),
    ] {
        let res = store
            .update_user_access(&alice.id, role, disabled, &[])
            .await;
        ensure!(
            S,
            check,
            matches!(res, Err(StoreError::Conflict { .. })),
            "changing the only enabled admin must be Conflict, got {res:?}"
        );
        let got = store.get_user(&alice.id).await.map_err(backend(S, check))?;
        ensure!(
            S,
            check,
            got.is_some_and(|u| u.role == Role::Admin && u.disabled_at.is_none()),
            "a refused change must leave the admin unchanged"
        );
    }

    store
        .update_user_access(&bob.id, Role::Admin, None, &[])
        .await
        .map_err(backend(S, "promote"))?;
    store
        .insert_ui_session(
            UiSession {
                token_hash: "alice-session".into(),
                user_id: alice.id,
                created_at: at(-1),
                expires_at: at(100),
                step_up_at: None,
            },
            &[],
        )
        .await
        .map_err(backend(S, "disable"))?;
    store
        .update_user_access(&alice.id, Role::Admin, Some(at(1)), &[])
        .await
        .map_err(backend(S, "disable"))?;
    let got = store
        .get_user(&alice.id)
        .await
        .map_err(backend(S, "disable"))?;
    ensure!(
        S,
        "disable",
        got.and_then(|u| u.disabled_at) == Some(at(1)),
        "disabled time was not stored"
    );
    let session = store
        .get_ui_session("alice-session")
        .await
        .map_err(backend(S, "disable"))?;
    ensure!(
        S,
        "disable_ends_sessions",
        session.is_none(),
        "disabling a user must delete their UI sessions"
    );
    let res = store
        .update_user_access(&bob.id, Role::Admin, Some(at(2)), &[])
        .await;
    ensure!(
        S,
        "disabled_admins_do_not_count",
        matches!(res, Err(StoreError::Conflict { .. })),
        "a disabled admin must not count towards the last-admin check, got {res:?}"
    );
    let res = store
        .update_user_access(&UserId::new(), Role::Viewer, None, &[])
        .await;
    ensure!(
        S,
        "update_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "unknown user must be NotFound, got {res:?}"
    );

    let pending = invite("invite-1", Role::Editor, -5, 100);
    store
        .insert_invite(pending.clone(), &[])
        .await
        .map_err(backend(S, "invite_insert"))?;
    let res = store
        .insert_invite(invite("invite-1", Role::Viewer, 0, 100), &[])
        .await;
    ensure!(
        S,
        "invite_duplicate",
        matches!(res, Err(StoreError::Conflict { .. })),
        "a reused token hash must be Conflict, got {res:?}"
    );
    let got = store
        .get_invite_by_token_hash("invite-1")
        .await
        .map_err(backend(S, "invite_get"))?;
    ensure!(
        S,
        "invite_round_trip",
        got.as_ref() == Some(&pending),
        "invite did not round-trip: {got:?}"
    );

    let cases = [
        (person("carol", Role::Viewer, 0), "accept_wrong_role"),
        (person("carol", Role::Editor, 150), "accept_expired"),
    ];
    for (user, check) in cases {
        let accepted = store
            .accept_invite("invite-1", user.clone(), &[])
            .await
            .map_err(backend(S, check))?;
        let created = store.get_user(&user.id).await.map_err(backend(S, check))?;
        ensure!(
            S,
            check,
            !accepted && created.is_none(),
            "an invite must not be accepted with a different role or after expiry"
        );
    }
    let res = store
        .accept_invite("invite-1", person("bob", Role::Editor, 0), &[])
        .await;
    ensure!(
        S,
        "accept_taken_username",
        matches!(res, Err(StoreError::Conflict { .. })),
        "a taken username must be Conflict, got {res:?}"
    );
    let carol = person("carol", Role::Editor, 0);
    let accepted = store
        .accept_invite("invite-1", carol.clone(), &[])
        .await
        .map_err(backend(S, "accept"))?;
    let stored = store
        .get_invite_by_token_hash("invite-1")
        .await
        .map_err(backend(S, "accept"))?;
    let created = store
        .get_user(&carol.id)
        .await
        .map_err(backend(S, "accept"))?;
    ensure!(
        S,
        "accept",
        accepted
            && created.as_ref() == Some(&carol)
            && stored
                .as_ref()
                .is_some_and(|i| i.accepted_by == Some(carol.id) && i.accepted_at == Some(at(0))),
        "accepting must create the user and mark the invite (stored invite {stored:?})"
    );
    let again = store
        .accept_invite("invite-1", person("dave", Role::Editor, 1), &[])
        .await
        .map_err(backend(S, "accept_once"))?;
    ensure!(S, "accept_once", !again, "an invite must be single-use");
    let revoked = store
        .revoke_invite(&pending.id, at(2), &[])
        .await
        .map_err(backend(S, "revoke_accepted"))?;
    ensure!(
        S,
        "revoke_accepted",
        !revoked,
        "revoking an accepted invite must report no change"
    );

    let second = invite("invite-2", Role::Viewer, 5, 100);
    store
        .insert_invite(second.clone(), &[])
        .await
        .map_err(backend(S, "revoke"))?;
    let first = store
        .revoke_invite(&second.id, at(6), &[])
        .await
        .map_err(backend(S, "revoke"))?;
    let repeat = store
        .revoke_invite(&second.id, at(7), &[])
        .await
        .map_err(backend(S, "revoke"))?;
    ensure!(
        S,
        "revoke",
        first && !repeat,
        "revoke must report a change once (got {first}, then {repeat})"
    );
    let accepted = store
        .accept_invite("invite-2", person("erin", Role::Viewer, 8), &[])
        .await
        .map_err(backend(S, "accept_revoked"))?;
    ensure!(
        S,
        "accept_revoked",
        !accepted,
        "a revoked invite must not be accepted"
    );
    let res = store.revoke_invite(&InviteId::new(), at(0), &[]).await;
    ensure!(
        S,
        "revoke_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "unknown invite must be NotFound, got {res:?}"
    );
    let listed = store
        .list_invites(PageRequest::default())
        .await
        .map_err(backend(S, "invite_list"))?;
    ensure!(
        S,
        "invite_list",
        listed.total == 2 && listed.items.first().map(|i| i.id) == Some(second.id),
        "expected 2 invites newest first, got {:?}",
        listed.items
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
        totp_secret_enc: Some(vec![1, 2, 3]),
        totp_last_step: Some(10),
        role: Role::Admin,
        created_at: at(0),
        disabled_at: None,
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

    // A new password keeps the session that changed it and signs out the rest.
    for hash in ["keep", "drop"] {
        store
            .insert_ui_session(
                UiSession {
                    token_hash: hash.into(),
                    ..session.clone()
                },
                &[],
            )
            .await
            .map_err(backend(S, "password_sessions"))?;
    }
    store
        .set_user_password(&user.id, "new-hash", Some("keep"), &[])
        .await
        .map_err(backend(S, "password_set"))?;
    let changed = store
        .get_user(&user.id)
        .await
        .map_err(backend(S, "password_get"))?;
    let kept = store
        .get_ui_session("keep")
        .await
        .map_err(backend(S, "password_keep"))?;
    let dropped = store
        .get_ui_session("drop")
        .await
        .map_err(backend(S, "password_drop"))?;
    ensure!(
        S,
        "password_set",
        changed.as_ref().map(|u| u.password_hash.as_str()) == Some("new-hash")
            && kept.is_some()
            && dropped.is_none(),
        "a new password must be stored, keep the session that set it and end the others (user {changed:?}, kept {kept:?}, dropped {dropped:?})"
    );
    let missing = store
        .set_user_password(&UserId::new(), "h", None, &[])
        .await;
    ensure!(
        S,
        "password_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    store
        .set_user_totp(&user.id, None, None, &[])
        .await
        .map_err(backend(S, "totp_clear"))?;
    let cleared = store
        .get_user(&user.id)
        .await
        .map_err(backend(S, "totp_get"))?;
    store
        .set_user_totp(&user.id, Some(vec![9, 9]), Some(42), &[])
        .await
        .map_err(backend(S, "totp_set"))?;
    let set = store
        .get_user(&user.id)
        .await
        .map_err(backend(S, "totp_get"))?;
    ensure!(
        S,
        "totp_set",
        cleared
            .as_ref()
            .is_some_and(|u| u.totp_secret_enc.is_none() && u.totp_last_step.is_none())
            && set.as_ref().is_some_and(
                |u| u.totp_secret_enc == Some(vec![9, 9]) && u.totp_last_step == Some(42)
            ),
        "the authenticator must be removable and settable (cleared {cleared:?}, set {set:?})"
    );
    let missing = store.set_user_totp(&UserId::new(), None, None, &[]).await;
    ensure!(
        S,
        "totp_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "expected NotFound, got {missing:?}"
    );

    let key = ApiKey {
        id: ApiKeyId::new(),
        name: "ci".into(),
        prefix: "cbk_conformance".into(),
        secret_hash: "hash".into(),
        vault_id: VaultId::new(),
        role: Role::Editor,
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

    let missing = store
        .replace_key_material("absent", b"x".to_vec(), &[])
        .await;
    ensure!(
        S,
        "key_replace_missing",
        matches!(missing, Err(StoreError::NotFound { .. })),
        "replacing missing key material must be NotFound, got {missing:?}"
    );
    store
        .replace_key_material("k", b"rewrapped".to_vec(), &[])
        .await
        .map_err(backend(S, "key_replace"))?;
    let listed = store
        .list_ciphertexts()
        .await
        .map_err(backend(S, "ciphertext_list"))?;
    let entry = listed
        .iter()
        .find(|c| c.owner == CiphertextOwner::KeyMaterial { name: "k".into() })
        .cloned();
    ensure!(
        S,
        "ciphertext_list",
        entry.as_ref().map(|c| c.ciphertext.as_slice()) == Some(b"rewrapped".as_slice()),
        "list_ciphertexts must include key material as stored, got {entry:?}"
    );
    let Some(entry) = entry else {
        return Ok(());
    };
    let replaced = store
        .replace_ciphertexts(&[(entry.clone(), b"re-encrypted".to_vec())], &[])
        .await
        .map_err(backend(S, "ciphertext_replace"))?;
    // The same change again: the stored value is no longer the old one.
    let stale = store
        .replace_ciphertexts(&[(entry, b"stale write".to_vec())], &[])
        .await
        .map_err(backend(S, "ciphertext_replace"))?;
    let got = store
        .get_key_material("k")
        .await
        .map_err(backend(S, "key_get"))?;
    ensure!(
        S,
        "ciphertext_replace_if_unchanged",
        replaced == 1 && stale == 0 && got.as_deref() == Some(b"re-encrypted".as_slice()),
        "replace_ciphertexts must replace only unchanged values (replaced {replaced}, then {stale})"
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
