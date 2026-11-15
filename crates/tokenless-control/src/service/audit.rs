// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditEvent;
use tokenless_core::authz::Action;
use tokenless_core::ids::VaultId;

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::model::{AuditQuery, Page, PageRequest};
use crate::store::AuditSink;

pub struct AuditService {
    sink: Arc<dyn AuditSink>,
    guard: Guard,
}

impl AuditService {
    pub fn new(sink: Arc<dyn AuditSink>, guard: Guard) -> Self {
        Self { sink, guard }
    }

    /// Vault-bound principals only ever see their own vault's events, and
    /// people the events of their vaults (an instance admin: all of them).
    pub async fn query(
        &self,
        caller: &Caller,
        vault_id: Option<VaultId>,
        action_prefix: Option<String>,
        page: PageRequest,
    ) -> Result<Page<AuditEvent>, ControlError> {
        self.query_events(
            caller,
            AuditQuery {
                vault_id,
                action_prefix,
                page,
                ..Default::default()
            },
        )
        .await
    }

    /// When the vault last recorded `action`, for a list page's summary.
    pub async fn latest_at(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        action: &str,
    ) -> Result<Option<DateTime<Utc>>, ControlError> {
        self.guard
            .check(caller, Action::AuditRead, Some(vault_id))
            .await?;
        Ok(self.sink.latest_at(vault_id, action).await?)
    }

    /// Like [`query`](Self::query), optionally narrowed to one proxy
    /// session or one service. A vault-bound caller only ever sees its vault.
    pub async fn query_events(
        &self,
        caller: &Caller,
        mut query: AuditQuery,
    ) -> Result<Page<AuditEvent>, ControlError> {
        if let Some(bound) = caller.principal.vault {
            query.vault_id = Some(bound);
        }
        match &query.vault_id {
            Some(vault) => {
                self.guard
                    .check(caller, Action::AuditRead, Some(vault))
                    .await?
            }
            None => {
                self.guard.check_list(caller, Action::AuditRead).await?;
                query.within = self.guard.vault_scope(caller, Action::AuditRead).await?;
            }
        }
        if let Some(prefix) = &query.action_prefix {
            if prefix.len() > 64 {
                return Err(ControlError::validation(
                    "action filter is longer than 64 characters",
                ));
            }
        }
        Ok(self.sink.query(&query).await?)
    }
}
