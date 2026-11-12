// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an [`SsoStore`] must do: providers with unique slugs, accounts
//! unique per provider subject, roles from groups that never re-enable a
//! disabled account, and the sign-in settings.

use tokenless_control::model::{
    OidcProvider, PasswordSignIn, RoleMapping, SignInSettings, SsoIdentity, User,
};
use tokenless_control::store::{
    AuditSink, CiphertextOwner, IdentityStore, NodeStore, SsoStore, StoredCiphertext,
};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Role;
use tokenless_core::ids::{OidcProviderId, UserId};

use crate::{at, backend, ConformanceFailure};

fn provider(slug: &str, created_offset: i64) -> OidcProvider {
    OidcProvider {
        id: OidcProviderId::new(),
        slug: slug.into(),
        name: format!("{slug} SSO"),
        issuer: format!("https://{slug}.example.test"),
        client_id: "tokenless".into(),
        client_secret_enc: Some(vec![9, 8, 7]),
        redirect_uri: "https://broker.example.test/api/v1/auth/oidc/callback".into(),
        scopes: vec!["profile".into()],
        groups_claim: "groups".into(),
        username_claim: "preferred_username".into(),
        role_mappings: vec![RoleMapping {
            group: "eng".into(),
            role: Role::Editor,
        }],
        enabled: true,
        created_at: at(created_offset),
        updated_at: at(created_offset),
    }
}

fn sso_user(username: &str, provider_id: OidcProviderId, subject: &str) -> User {
    User {
        id: UserId::new(),
        username: username.into(),
        password_hash: String::new(),
        totp_secret_enc: None,
        totp_last_step: None,
        role: Role::Viewer,
        created_at: at(0),
        disabled_at: None,
        sso: Some(SsoIdentity {
            provider_id,
            subject: subject.into(),
        }),
    }
}

async fn account<S: IdentityStore>(store: &S, id: &UserId) -> Result<User, ConformanceFailure> {
    store
        .get_user(id)
        .await
        .map_err(backend("sso_store", "get_user"))?
        .ok_or_else(|| ConformanceFailure {
            suite: "sso_store",
            check: "sso_role",
            detail: format!("account {id} vanished"),
        })
}

/// Providers, single sign-on accounts, roles from groups and the sign-in
/// settings. Expects an empty store.
pub async fn sso_store_suite<S>(store: &S) -> Result<(), ConformanceFailure>
where
    S: SsoStore + IdentityStore + NodeStore + AuditSink,
{
    const S: &str = "sso_store";
    let a = provider("alpha", -20);
    let b = provider("beta", -10);
    let created = AuditEvent::new(
        "user:conformance",
        "identity_provider.create",
        AuditOutcome::Success,
    )
    .target(format!("oidc_provider:{}", a.id));
    SsoStore::insert_oidc_provider(store, a.clone(), std::slice::from_ref(&created))
        .await
        .map_err(backend(S, "insert"))?;
    store
        .insert_oidc_provider(b.clone(), &[])
        .await
        .map_err(backend(S, "insert"))?;
    let audit = store
        .query(&Default::default())
        .await
        .map_err(backend(S, "audit"))?;
    ensure!(
        S,
        "insert_audited",
        audit.items.iter().any(|e| e.id == created.id),
        "the provider's audit event was not stored with it"
    );
    let res = store.insert_oidc_provider(provider("alpha", 0), &[]).await;
    ensure!(
        S,
        "slug_unique",
        matches!(res, Err(StoreError::Conflict { .. })),
        "a second provider with slug 'alpha' must be a Conflict, got {res:?}"
    );
    let got = store
        .get_oidc_provider(&a.id)
        .await
        .map_err(backend(S, "get"))?;
    ensure!(S, "get", got.as_ref() == Some(&a), "got {got:?}");
    let by_slug = store
        .get_oidc_provider_by_slug("beta")
        .await
        .map_err(backend(S, "get_by_slug"))?;
    ensure!(
        S,
        "get_by_slug",
        by_slug.as_ref() == Some(&b),
        "got {by_slug:?}"
    );
    ensure!(
        S,
        "get_missing",
        store
            .get_oidc_provider(&OidcProviderId::new())
            .await
            .map_err(backend(S, "get_missing"))?
            .is_none(),
        "an unknown provider must be None"
    );
    let listed = store
        .list_oidc_providers()
        .await
        .map_err(backend(S, "list"))?;
    let slugs: Vec<&str> = listed.iter().map(|p| p.slug.as_str()).collect();
    ensure!(
        S,
        "list_oldest_first",
        slugs == ["alpha", "beta"],
        "listed {slugs:?}"
    );

    // Replacing keeps the creation time and checks the slug.
    let mut renamed = a.clone();
    renamed.slug = "alpha-2".into();
    renamed.enabled = false;
    renamed.client_secret_enc = None;
    renamed.created_at = at(500);
    renamed.updated_at = at(5);
    store
        .update_oidc_provider(renamed.clone(), &[])
        .await
        .map_err(backend(S, "update"))?;
    let got = store
        .get_oidc_provider(&a.id)
        .await
        .map_err(backend(S, "update"))?;
    ensure!(
        S,
        "update",
        got.as_ref()
            == Some(&OidcProvider {
                created_at: a.created_at,
                ..renamed.clone()
            }),
        "after update got {got:?}"
    );
    let mut clash = renamed.clone();
    clash.slug = "beta".into();
    let res = store.update_oidc_provider(clash, &[]).await;
    ensure!(
        S,
        "update_slug_unique",
        matches!(res, Err(StoreError::Conflict { .. })),
        "renaming to a taken slug must be a Conflict, got {res:?}"
    );
    let res = store.update_oidc_provider(provider("gamma", 0), &[]).await;
    ensure!(
        S,
        "update_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "updating an unknown provider must be NotFound, got {res:?}"
    );

    // One account per provider subject; a provider with accounts stays.
    let ada = sso_user("ada", b.id, "subject-1");
    IdentityStore::insert_user(store, ada.clone(), &[])
        .await
        .map_err(backend(S, "insert_user"))?;
    let res = store
        .insert_user(sso_user("ada-2", b.id, "subject-1"), &[])
        .await;
    ensure!(
        S,
        "subject_unique",
        matches!(res, Err(StoreError::Conflict { .. })),
        "a second account for the same provider subject must be a Conflict, got {res:?}"
    );
    store
        .insert_user(sso_user("ada-elsewhere", a.id, "subject-1"), &[])
        .await
        .map_err(backend(S, "same_subject_other_provider"))?;
    let found = store
        .get_user_by_sso(&b.id, "subject-1")
        .await
        .map_err(backend(S, "get_user_by_sso"))?;
    ensure!(
        S,
        "get_user_by_sso",
        found.as_ref() == Some(&ada),
        "got {found:?}"
    );
    ensure!(
        S,
        "get_user_by_sso_missing",
        store
            .get_user_by_sso(&b.id, "subject-2")
            .await
            .map_err(backend(S, "get_user_by_sso"))?
            .is_none(),
        "an unknown subject must be None"
    );
    let res = store.delete_oidc_provider(&b.id, &[]).await;
    ensure!(
        S,
        "delete_with_users",
        matches!(res, Err(StoreError::Conflict { .. })),
        "deleting a provider with accounts must be a Conflict, got {res:?}"
    );
    ensure!(
        S,
        "delete_with_users_kept",
        store
            .get_oidc_provider(&b.id)
            .await
            .map_err(backend(S, "get"))?
            .is_some(),
        "a refused delete must leave the provider"
    );
    let lone = provider("lone", 0);
    store
        .insert_oidc_provider(lone.clone(), &[])
        .await
        .map_err(backend(S, "insert"))?;
    store
        .delete_oidc_provider(&lone.id, &[])
        .await
        .map_err(backend(S, "delete"))?;
    let res = store.delete_oidc_provider(&lone.id, &[]).await;
    ensure!(
        S,
        "delete_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "deleting it again must be NotFound, got {res:?}"
    );

    // The client secret is re-encrypted with every other secret.
    let ciphertexts = store
        .list_ciphertexts()
        .await
        .map_err(backend(S, "list_ciphertexts"))?;
    let secret = ciphertexts
        .iter()
        .find(|c| c.owner == CiphertextOwner::OidcClientSecret { id: b.id });
    ensure!(
        S,
        "secret_listed",
        secret.map(|c| c.ciphertext.as_slice()) == Some(&[9, 8, 7][..])
            && !ciphertexts
                .iter()
                .any(|c| c.owner == CiphertextOwner::OidcClientSecret { id: a.id }),
        "list_ciphertexts must hold beta's client secret and not alpha's removed one"
    );
    let old = StoredCiphertext {
        owner: CiphertextOwner::OidcClientSecret { id: b.id },
        ciphertext: vec![9, 8, 7],
    };
    let replaced = store
        .replace_ciphertexts(&[(old, vec![1, 1])], &[])
        .await
        .map_err(backend(S, "replace_ciphertexts"))?;
    let after = store
        .get_oidc_provider(&b.id)
        .await
        .map_err(backend(S, "get"))?
        .and_then(|p| p.client_secret_enc);
    ensure!(
        S,
        "secret_replaced",
        replaced == 1 && after.as_deref() == Some(&[1, 1][..]),
        "replace_ciphertexts replaced {replaced} and left {after:?}"
    );

    // Roles from groups: applied only while the account is enabled, and
    // never leaving no enabled admin.
    let changed = store
        .set_sso_role(&ada.id, Role::Admin, &[])
        .await
        .map_err(backend(S, "set_sso_role"))?;
    let now = account(store, &ada.id).await?;
    ensure!(
        S,
        "sso_role_set",
        changed && now.role == Role::Admin,
        "set_sso_role returned {changed} and left {:?}",
        now.role
    );
    let res = store.set_sso_role(&ada.id, Role::Viewer, &[]).await;
    ensure!(
        S,
        "sso_role_last_admin",
        matches!(res, Err(StoreError::Conflict { .. }))
            && account(store, &ada.id).await?.role == Role::Admin,
        "demoting the last enabled admin must be a Conflict that changes nothing, got {res:?}"
    );
    IdentityStore::insert_user(store, crate::person("local-admin", Role::Admin, 0), &[])
        .await
        .map_err(backend(S, "insert_user"))?;
    store
        .update_user_access(&ada.id, Role::Admin, Some(at(5)), &[])
        .await
        .map_err(backend(S, "update_user_access"))?;
    let changed = store
        .set_sso_role(&ada.id, Role::Editor, &[])
        .await
        .map_err(backend(S, "set_sso_role"))?;
    let now = account(store, &ada.id).await?;
    ensure!(
        S,
        "sso_role_keeps_disabled",
        !changed && now.disabled_at.is_some() && now.role == Role::Admin,
        "on a disabled account set_sso_role must return false and change nothing; got {changed}, disabled_at {:?}, role {:?}",
        now.disabled_at,
        now.role
    );
    let res = store.set_sso_role(&UserId::new(), Role::Viewer, &[]).await;
    ensure!(
        S,
        "sso_role_missing",
        matches!(res, Err(StoreError::NotFound { .. })),
        "an unknown account must be NotFound, got {res:?}"
    );

    // Sign-in settings.
    let defaults = store
        .get_sign_in_settings()
        .await
        .map_err(backend(S, "settings"))?;
    ensure!(
        S,
        "settings_default",
        defaults == SignInSettings::default(),
        "got {defaults:?}"
    );
    // Idle expiry off round-trips as off, not as the default.
    let admins_only = SignInSettings {
        password_sign_in: PasswordSignIn::AdminsOnly,
        idle_timeout_secs: None,
    };
    store
        .put_sign_in_settings(admins_only.clone(), &[])
        .await
        .map_err(backend(S, "settings"))?;
    let got = store
        .get_sign_in_settings()
        .await
        .map_err(backend(S, "settings"))?;
    ensure!(S, "settings_round_trip", got == admins_only, "got {got:?}");
    Ok(())
}
