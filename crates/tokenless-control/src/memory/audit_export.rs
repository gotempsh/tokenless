// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::AuditDestinationId;

use super::MemoryStore;
use crate::error::StoreError;
use crate::model::{AuditDestination, DeliveryState};
use crate::store::AuditExportStore;

fn name_taken(name: &str) -> StoreError {
    StoreError::Conflict {
        entity: "audit_destination",
        detail: format!("a destination named '{name}' exists"),
    }
}

fn missing(id: &AuditDestinationId) -> StoreError {
    StoreError::NotFound {
        entity: "audit_destination",
        id: id.to_string(),
    }
}

/// An event's sequence number is its position in the log, from 1.
fn to_seq(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
}

#[async_trait]
impl AuditExportStore for MemoryStore {
    async fn insert_audit_destination(
        &self,
        destination: AuditDestination,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .audit_destinations
            .values()
            .any(|d| d.name == destination.name || d.id == destination.id)
        {
            return Err(name_taken(&destination.name));
        }
        inner.audit_destinations.insert(destination.id, destination);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_audit_destination(
        &self,
        id: &AuditDestinationId,
    ) -> Result<Option<AuditDestination>, StoreError> {
        Ok(self.lock()?.audit_destinations.get(id).cloned())
    }

    async fn list_audit_destinations(&self) -> Result<Vec<AuditDestination>, StoreError> {
        let mut all: Vec<_> = self.lock()?.audit_destinations.values().cloned().collect();
        all.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(all)
    }

    async fn update_audit_destination(
        &self,
        destination: AuditDestination,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .audit_destinations
            .values()
            .any(|d| d.name == destination.name && d.id != destination.id)
        {
            return Err(name_taken(&destination.name));
        }
        let current = inner
            .audit_destinations
            .get_mut(&destination.id)
            .ok_or_else(|| missing(&destination.id))?;
        let delivery = std::mem::take(&mut current.delivery);
        *current = AuditDestination {
            created_at: current.created_at,
            delivery,
            ..destination
        };
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn delete_audit_destination(
        &self,
        id: &AuditDestinationId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner
            .audit_destinations
            .remove(id)
            .ok_or_else(|| missing(id))?;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn latest_audit_seq(&self) -> Result<u64, StoreError> {
        Ok(u64::try_from(self.lock()?.audit.len()).unwrap_or(u64::MAX))
    }

    async fn audit_events_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<(u64, AuditEvent)>, StoreError> {
        let inner = self.lock()?;
        let start = usize::try_from(after).unwrap_or(usize::MAX);
        Ok(inner
            .audit
            .iter()
            .enumerate()
            .skip(start)
            .take(limit)
            .map(|(i, e)| (to_seq(i), e.clone()))
            .collect())
    }

    async fn advance_audit_cursor(
        &self,
        id: &AuditDestinationId,
        from: u64,
        to: u64,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let Some(d) = inner.audit_destinations.get_mut(id) else {
            return Ok(false);
        };
        if d.delivery.cursor != from {
            return Ok(false);
        }
        d.delivery = DeliveryState {
            cursor: to,
            last_success_at: Some(at),
            last_attempt_at: Some(at),
            failing_since: None,
            last_error: None,
            consecutive_failures: 0,
            retry_until: None,
        };
        Ok(true)
    }

    async fn record_audit_delivery_failure(
        &self,
        id: &AuditDestinationId,
        from: u64,
        to: u64,
        error: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if let Some(d) = inner.audit_destinations.get_mut(id) {
            if d.delivery.cursor == from {
                d.delivery.retry_until = Some(to);
            }
            d.delivery.last_attempt_at = Some(at);
            d.delivery.failing_since.get_or_insert(at);
            d.delivery.last_error = Some(error.to_string());
            d.delivery.consecutive_failures = d.delivery.consecutive_failures.saturating_add(1);
        }
        Ok(())
    }

    async fn set_audit_cursor(
        &self,
        id: &AuditDestinationId,
        to: u64,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let d = inner
            .audit_destinations
            .get_mut(id)
            .ok_or_else(|| missing(id))?;
        d.delivery.cursor = to;
        d.delivery.failing_since = None;
        d.delivery.last_error = None;
        d.delivery.consecutive_failures = 0;
        d.delivery.retry_until = None;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }
}
