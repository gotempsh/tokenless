// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::AlertId;

use super::{newest_first, MemoryStore};
use crate::error::StoreError;
use crate::model::{Alert, AlertFilter, Page, PageRequest};
use crate::store::AlertStore;

fn matches(alert: &Alert, filter: &AlertFilter) -> bool {
    (!filter.open_only || alert.acknowledged_at.is_none())
        && filter.vault_id.is_none_or(|v| alert.vault_id == Some(v))
        && filter
            .session_id
            .is_none_or(|s| alert.session_id == Some(s))
        && filter.kind.is_none_or(|k| alert.kind == k)
        && filter.within.covers(alert.vault_id.as_ref())
}

#[async_trait]
impl AlertStore for MemoryStore {
    async fn insert_alert(&self, alert: Alert, audit: &[AuditEvent]) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        if inner
            .alerts
            .values()
            .any(|a| a.dedup_key == alert.dedup_key)
        {
            return Ok(false);
        }
        inner.alerts.insert(alert.id, alert);
        inner.audit.extend_from_slice(audit);
        Ok(true)
    }

    async fn get_alert(&self, id: &AlertId) -> Result<Option<Alert>, StoreError> {
        Ok(self.lock()?.alerts.get(id).cloned())
    }

    async fn list_alerts(
        &self,
        filter: &AlertFilter,
        page: PageRequest,
    ) -> Result<Page<Alert>, StoreError> {
        let items: Vec<Alert> = self
            .lock()?
            .alerts
            .values()
            .filter(|a| matches(a, filter))
            .cloned()
            .collect();
        Ok(page.apply(&newest_first(items, |a| a.raised_at)))
    }

    async fn acknowledge_alert(
        &self,
        id: &AlertId,
        by: &str,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let alert = inner
            .alerts
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("alert", id))?;
        if alert.acknowledged_at.is_some() {
            return Ok(false);
        }
        alert.acknowledged_at = Some(at);
        alert.acknowledged_by = Some(by.to_string());
        inner.audit.extend_from_slice(audit);
        Ok(true)
    }
}
