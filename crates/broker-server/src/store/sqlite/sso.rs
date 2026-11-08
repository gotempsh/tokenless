// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`SsoStore`] on SQLite: providers, sign-ins in progress and the sign-in
//! settings (a row of `settings`).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use tokenless_control::model::{OidcProvider, OidcPurpose, OidcRequest, SignInSettings, User};
use tokenless_control::store::SsoStore;
use tokenless_control::StoreError;
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::OidcProviderId;

use super::{
    db, finish, from_json, get, get_id, get_opt_id, get_ts, to_json, to_u64, ts, user_from_row,
    SqliteStore,
};

fn provider_from_row(row: &SqliteRow) -> Result<OidcProvider, StoreError> {
    Ok(OidcProvider {
        id: get_id(row, "id")?,
        slug: get(row, "slug")?,
        name: get(row, "name")?,
        issuer: get(row, "issuer")?,
        client_id: get(row, "client_id")?,
        client_secret_enc: get(row, "client_secret_enc")?,
        redirect_uri: get(row, "redirect_uri")?,
        scopes: from_json("scopes", &get::<String>(row, "scopes")?)?,
        groups_claim: get(row, "groups_claim")?,
        username_claim: get(row, "username_claim")?,
        role_mappings: from_json("role_mappings", &get::<String>(row, "role_mappings")?)?,
        enabled: get::<i64>(row, "enabled")? != 0,
        created_at: get_ts(row, "created_at")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}

fn request_from_row(row: &SqliteRow) -> Result<OidcRequest, StoreError> {
    let purpose: String = get(row, "purpose")?;
    Ok(OidcRequest {
        state_hash: get(row, "state_hash")?,
        browser_hash: get(row, "browser_hash")?,
        provider_id: get_id(row, "provider_id")?,
        purpose: OidcPurpose::parse(&purpose).ok_or_else(|| {
            StoreError::backend("decode purpose", format!("unknown purpose '{purpose}'"))
        })?,
        nonce: get(row, "nonce")?,
        pkce_verifier: get(row, "pkce_verifier")?,
        ui_session_hash: get(row, "ui_session_hash")?,
        user_id: get_opt_id(row, "user_id")?,
        return_to: get(row, "return_to")?,
        created_at: get_ts(row, "created_at")?,
        expires_at: get_ts(row, "expires_at")?,
    })
}

#[async_trait]
impl SsoStore for SqliteStore {
    async fn insert_oidc_provider(
        &self,
        p: OidcProvider,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_oidc_provider").await?;
        sqlx::query("INSERT INTO oidc_providers (id, slug, name, issuer, client_id, client_secret_enc, redirect_uri, scopes, groups_claim, username_claim, role_mappings, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(p.id.to_string())
            .bind(&p.slug)
            .bind(&p.name)
            .bind(&p.issuer)
            .bind(&p.client_id)
            .bind(&p.client_secret_enc)
            .bind(&p.redirect_uri)
            .bind(to_json("scopes", &p.scopes)?)
            .bind(&p.groups_claim)
            .bind(&p.username_claim)
            .bind(to_json("role_mappings", &p.role_mappings)?)
            .bind(i64::from(p.enabled))
            .bind(ts(&p.created_at))
            .bind(ts(&p.updated_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert identity provider", "oidc_provider"))?;
        finish(tx, audit, "insert_oidc_provider").await
    }

    async fn get_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<Option<OidcProvider>, StoreError> {
        sqlx::query("SELECT * FROM oidc_providers WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get identity provider", "oidc_provider"))?
            .map(|r| provider_from_row(&r))
            .transpose()
    }

    async fn get_oidc_provider_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<OidcProvider>, StoreError> {
        sqlx::query("SELECT * FROM oidc_providers WHERE slug = ?")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get identity provider by slug", "oidc_provider"))?
            .map(|r| provider_from_row(&r))
            .transpose()
    }

    async fn list_oidc_providers(&self) -> Result<Vec<OidcProvider>, StoreError> {
        sqlx::query("SELECT * FROM oidc_providers ORDER BY created_at, id")
            .fetch_all(&self.pool)
            .await
            .map_err(db("list identity providers", "oidc_provider"))?
            .iter()
            .map(provider_from_row)
            .collect()
    }

    async fn update_oidc_provider(
        &self,
        p: OidcProvider,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_oidc_provider").await?;
        let result = sqlx::query("UPDATE oidc_providers SET slug = ?, name = ?, issuer = ?, client_id = ?, client_secret_enc = ?, redirect_uri = ?, scopes = ?, groups_claim = ?, username_claim = ?, role_mappings = ?, enabled = ?, updated_at = ? WHERE id = ?")
            .bind(&p.slug)
            .bind(&p.name)
            .bind(&p.issuer)
            .bind(&p.client_id)
            .bind(&p.client_secret_enc)
            .bind(&p.redirect_uri)
            .bind(to_json("scopes", &p.scopes)?)
            .bind(&p.groups_claim)
            .bind(&p.username_claim)
            .bind(to_json("role_mappings", &p.role_mappings)?)
            .bind(i64::from(p.enabled))
            .bind(ts(&p.updated_at))
            .bind(p.id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("update identity provider", "oidc_provider"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("oidc_provider", p.id));
        }
        finish(tx, audit, "update_oidc_provider").await
    }

    async fn delete_oidc_provider(
        &self,
        id: &OidcProviderId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("delete_oidc_provider").await?;
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE sso_provider_id = ?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db("count a provider's users", "user"))?;
        let users = to_u64(get::<i64>(&row, "n")?);
        if users > 0 {
            return Err(StoreError::Conflict {
                entity: "oidc_provider",
                detail: format!("{users} user(s) sign in with provider {id}"),
            });
        }
        let result = sqlx::query("DELETE FROM oidc_providers WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete identity provider", "oidc_provider"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("oidc_provider", id));
        }
        finish(tx, audit, "delete_oidc_provider").await
    }

    async fn get_user_by_sso(
        &self,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        sqlx::query("SELECT * FROM users WHERE sso_provider_id = ? AND sso_subject = ?")
            .bind(provider_id.to_string())
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get user by provider subject", "user"))?
            .map(|r| user_from_row(&r))
            .transpose()
    }

    async fn insert_oidc_request(
        &self,
        r: OidcRequest,
        max_pending: u64,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("insert_oidc_request").await?;
        let row = sqlx::query("SELECT COUNT(*) AS n FROM oidc_requests WHERE expires_at > ?")
            .bind(ts(&r.created_at))
            .fetch_one(&mut *tx)
            .await
            .map_err(db("count pending sign-ins", "oidc_request"))?;
        if to_u64(get::<i64>(&row, "n")?) >= max_pending {
            return Ok(false);
        }
        sqlx::query("INSERT INTO oidc_requests (state_hash, browser_hash, provider_id, purpose, nonce, pkce_verifier, ui_session_hash, user_id, return_to, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&r.state_hash)
            .bind(&r.browser_hash)
            .bind(r.provider_id.to_string())
            .bind(r.purpose.as_str())
            .bind(&r.nonce)
            .bind(&r.pkce_verifier)
            .bind(&r.ui_session_hash)
            .bind(r.user_id.map(|u| u.to_string()))
            .bind(&r.return_to)
            .bind(ts(&r.created_at))
            .bind(ts(&r.expires_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert sign-in request", "oidc_request"))?;
        finish(tx, &[], "insert_oidc_request").await?;
        Ok(true)
    }

    async fn take_oidc_request(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<OidcRequest>, StoreError> {
        let row = sqlx::query("DELETE FROM oidc_requests WHERE state_hash = ? RETURNING *")
            .bind(state_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("take sign-in request", "oidc_request"))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let request = request_from_row(&row)?;
        Ok((request.expires_at > now).then_some(request))
    }

    async fn delete_expired_oidc_requests(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM oidc_requests WHERE expires_at <= ?")
            .bind(ts(&now))
            .execute(&self.pool)
            .await
            .map_err(db("delete expired sign-in requests", "oidc_request"))?;
        Ok(result.rows_affected())
    }

    async fn get_sign_in_settings(&self) -> Result<SignInSettings, StoreError> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'sign_in'")
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get sign-in settings", "settings"))?;
        match row {
            Some(r) => from_json("sign_in", &get::<String>(&r, "value")?),
            None => Ok(SignInSettings::default()),
        }
    }

    async fn put_sign_in_settings(
        &self,
        settings: SignInSettings,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("put_sign_in_settings").await?;
        sqlx::query("INSERT INTO settings (key, value) VALUES ('sign_in', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(to_json("sign_in", &settings)?)
            .execute(&mut *tx)
            .await
            .map_err(db("put sign-in settings", "settings"))?;
        finish(tx, audit, "put_sign_in_settings").await
    }
}
