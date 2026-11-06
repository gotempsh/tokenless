// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use broker_core::audit::AuditEvent;
use broker_core::authz::Action;
use broker_core::ids::{SessionId, VaultId};

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

    /// Vault-bound principals only ever see their own vault's events.
    pub async fn query(
        &self,
        caller: &Caller,
        vault_id: Option<VaultId>,
        action_prefix: Option<String>,
        page: PageRequest,
    ) -> Result<Page<AuditEvent>, ControlError> {
        self.query_session(caller, vault_id, action_prefix, None, page)
            .await
    }

    /// Like [`query`](Self::query), optionally narrowed to one proxy session.
    pub async fn query_session(
        &self,
        caller: &Caller,
        vault_id: Option<VaultId>,
        action_prefix: Option<String>,
        session_id: Option<SessionId>,
        page: PageRequest,
    ) -> Result<Page<AuditEvent>, ControlError> {
        let vault_id = match (&caller.principal.vault, vault_id) {
            (Some(bound), _) => Some(*bound),
            (None, requested) => requested,
        };
        self.guard
            .check(caller, Action::AuditRead, vault_id.as_ref())
            .await?;
        if let Some(prefix) = &action_prefix {
            if prefix.len() > 64 {
                return Err(ControlError::validation(
                    "action filter is longer than 64 characters",
                ));
            }
        }
        Ok(self
            .sink
            .query(&AuditQuery {
                vault_id,
                action_prefix,
                session_id,
                page,
            })
            .await?)
    }
}
