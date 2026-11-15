// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Summaries for list pages: enough about each record to tell them apart
//! and spot what needs attention, in one request.

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokenless_core::authz::Role;
use tokenless_core::ids::VaultId;

use super::{Caller, ControlPlane};
use crate::error::ControlError;
use crate::model::{CredentialMeta, Page, PageRequest, Vault};

/// How many of a vault's services an overview names.
pub const OVERVIEW_SERVICES: u64 = 4;

/// A vault with its first services, how many it has, its live sessions and
/// when a proxy last added one of its credentials.
#[derive(Debug, Clone, Serialize)]
pub struct VaultOverview {
    #[serde(flatten)]
    pub vault: Vault,
    /// The caller's role in the vault; `None` for an instance admin who
    /// oversees it without being a member, who sees no services until
    /// they join.
    pub my_role: Option<Role>,
    /// The first [`OVERVIEW_SERVICES`] services, in the vault's list order.
    pub services: Vec<CredentialMeta>,
    pub service_count: u64,
    pub live_sessions: u64,
    /// `None` when nothing was brokered yet, or the caller may not read the audit log.
    pub last_request_at: Option<DateTime<Utc>>,
}

impl ControlPlane {
    /// The caller's vaults, each with its overview. Each vault costs three
    /// indexed lookups: its first services, its live sessions and its newest
    /// brokered request, none of which grows with the vault's history.
    pub async fn vault_overviews(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<VaultOverview>, ControlError> {
        let vaults = self.policy.list_vaults(caller, page).await?;
        let roles = self.policy.my_vault_roles(caller).await?;
        let role_in = |id: &VaultId| roles.iter().find(|g| &g.vault_id == id).map(|g| g.role);
        let mut items = Vec::with_capacity(vaults.items.len());
        for vault in vaults.items {
            let my_role = role_in(&vault.id);
            items.push(self.vault_overview(caller, vault, my_role).await?);
        }
        Ok(Page {
            items,
            total: vaults.total,
            page: vaults.page,
            page_size: vaults.page_size,
        })
    }

    /// One vault's overview, for its own page.
    pub async fn vault_overview_by_id(
        &self,
        caller: &Caller,
        id: &VaultId,
    ) -> Result<VaultOverview, ControlError> {
        let vault = self.policy.get_vault(caller, id).await?;
        let my_role = self
            .policy
            .my_vault_roles(caller)
            .await?
            .into_iter()
            .find(|g| &g.vault_id == id)
            .map(|g| g.role);
        self.vault_overview(caller, vault, my_role).await
    }

    async fn vault_overview(
        &self,
        caller: &Caller,
        vault: Vault,
        my_role: Option<Role>,
    ) -> Result<VaultOverview, ControlError> {
        let id: VaultId = vault.id;
        // An instance admin overseeing a vault sees that it exists, its
        // sessions and its activity, not its contents.
        let services = match self
            .policy
            .list_credentials(
                caller,
                &id,
                PageRequest::new(Some(1), Some(OVERVIEW_SERVICES)),
            )
            .await
        {
            Ok(page) => page,
            Err(ControlError::Forbidden { .. }) if my_role.is_none() => Page {
                items: Vec::new(),
                total: 0,
                page: 1,
                page_size: OVERVIEW_SERVICES,
            },
            Err(e) => return Err(e),
        };
        let live_sessions = self.policy.live_sessions(caller, &id).await?;
        let last_request_at = match self.audit.latest_at(caller, &id, "proxy.inject").await {
            Ok(at) => at,
            Err(ControlError::Forbidden { .. }) => None,
            Err(e) => return Err(e),
        };
        Ok(VaultOverview {
            vault,
            my_role,
            service_count: services.total,
            services: services.items,
            live_sessions,
            last_request_at,
        })
    }
}
