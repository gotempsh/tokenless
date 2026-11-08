// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::OidcProviderId;

use super::MemoryStore;
use crate::error::StoreError;
use crate::model::{OidcProvider, OidcRequest, SignInSettings, User};
use crate::store::SsoStore;

fn slug_taken(slug: &str) -> StoreError {
    StoreError::Conflict {
        entity: "oidc_provider",
        detail: format!("a provider with slug '{slug}' exists"),
    }
}

#[async_trait]
impl SsoStore for MemoryStore {
    async fn insert_oidc_provider(
        &self,
        provider: OidcProvider,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .oidc_providers
            .values()
            .any(|p| p.slug == provider.slug || p.id == provider.id)
        {
            return Err(slug_taken(&provider.slug));
        }
        inner.oidc_providers.insert(provider.id, provider);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_oidc_provider(
        &self,
        id: &OidcProviderId,
    ) -> Result<Option<OidcProvider>, StoreError> {
        Ok(self.lock()?.oidc_providers.get(id).cloned())
    }

    async fn get_oidc_provider_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<OidcProvider>, StoreError> {
        Ok(self
            .lock()?
            .oidc_providers
            .values()
            .find(|p| p.slug == slug)
            .cloned())
    }

    async fn list_oidc_providers(&self) -> Result<Vec<OidcProvider>, StoreError> {
        let mut all: Vec<_> = self.lock()?.oidc_providers.values().cloned().collect();
        all.sort_by_key(|p| (p.created_at, p.id.to_string()));
        Ok(all)
    }

    async fn update_oidc_provider(
        &self,
        provider: OidcProvider,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let Some(created_at) = inner.oidc_providers.get(&provider.id).map(|p| p.created_at) else {
            return Err(StoreError::not_found("oidc_provider", provider.id));
        };
        if inner
            .oidc_providers
            .values()
            .any(|p| p.slug == provider.slug && p.id != provider.id)
        {
            return Err(slug_taken(&provider.slug));
        }
        inner.oidc_providers.insert(
            provider.id,
            OidcProvider {
                created_at,
                ..provider
            },
        );
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn delete_oidc_provider(
        &self,
        id: &OidcProviderId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if !inner.oidc_providers.contains_key(id) {
            return Err(StoreError::not_found("oidc_provider", id));
        }
        let users = inner
            .users
            .values()
            .filter(|u| u.sso.as_ref().is_some_and(|s| s.provider_id == *id))
            .count();
        if users > 0 {
            return Err(StoreError::Conflict {
                entity: "oidc_provider",
                detail: format!("{users} user(s) sign in with provider {id}"),
            });
        }
        inner.oidc_providers.remove(id);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_user_by_sso(
        &self,
        provider_id: &OidcProviderId,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|u| {
                u.sso
                    .as_ref()
                    .is_some_and(|s| s.provider_id == *provider_id && s.subject == subject)
            })
            .cloned())
    }

    async fn insert_oidc_request(
        &self,
        request: OidcRequest,
        max_pending: u64,
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let pending = inner
            .oidc_requests
            .values()
            .filter(|r| r.expires_at > request.created_at)
            .count() as u64;
        if pending >= max_pending {
            return Ok(false);
        }
        if inner.oidc_requests.contains_key(&request.state_hash) {
            return Err(StoreError::Conflict {
                entity: "oidc_request",
                detail: "the state is already in use".into(),
            });
        }
        inner
            .oidc_requests
            .insert(request.state_hash.clone(), request);
        Ok(true)
    }

    async fn take_oidc_request(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<OidcRequest>, StoreError> {
        Ok(self
            .lock()?
            .oidc_requests
            .remove(state_hash)
            .filter(|r| r.expires_at > now))
    }

    async fn delete_expired_oidc_requests(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let mut inner = self.lock()?;
        let before = inner.oidc_requests.len();
        inner.oidc_requests.retain(|_, r| r.expires_at > now);
        Ok((before - inner.oidc_requests.len()) as u64)
    }

    async fn get_sign_in_settings(&self) -> Result<SignInSettings, StoreError> {
        Ok(self.lock()?.sign_in_settings.clone().unwrap_or_default())
    }

    async fn put_sign_in_settings(
        &self,
        settings: SignInSettings,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner.sign_in_settings = Some(settings);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }
}
