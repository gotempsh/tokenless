// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use tokenless_core::audit::AuditEvent;
use tokenless_core::authz::Role;
use tokenless_core::ids::{OidcProviderId, UserId};

use super::MemoryStore;
use crate::error::StoreError;
use crate::model::{OidcProvider, SignInSettings, User};
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

    async fn set_sso_role(
        &self,
        id: &UserId,
        role: Role,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let Some(user) = inner.users.get(id) else {
            return Err(StoreError::not_found("user", id));
        };
        if user.disabled_at.is_some() {
            return Ok(false);
        }
        let admins_left = inner
            .users
            .values()
            .filter(|u| {
                let r = if u.id == *id { role } else { u.role };
                r == Role::Admin && u.disabled_at.is_none()
            })
            .count();
        if admins_left == 0 {
            return Err(StoreError::Conflict {
                entity: "user",
                detail: format!("changing user {id} would leave no enabled admin"),
            });
        }
        if let Some(user) = inner.users.get_mut(id) {
            user.role = role;
        }
        inner.audit.extend_from_slice(audit);
        Ok(true)
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
