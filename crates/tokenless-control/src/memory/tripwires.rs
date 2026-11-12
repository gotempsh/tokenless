// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::{TripwireId, VaultId};

use super::{newest_first, MemoryStore};
use crate::error::StoreError;
use crate::model::{Page, PageRequest, Tripwire};
use crate::store::TripwireStore;

#[async_trait]
impl TripwireStore for MemoryStore {
    async fn insert_tripwire(
        &self,
        tripwire: Tripwire,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .tripwires
            .values()
            .any(|t| t.vault_id == tripwire.vault_id && t.name == tripwire.name)
        {
            return Err(StoreError::Conflict {
                entity: "tripwire",
                detail: format!(
                    "vault {} already has a tripwire named '{}'",
                    tripwire.vault_id, tripwire.name
                ),
            });
        }
        inner.tripwires.insert(tripwire.id, tripwire);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_tripwire(&self, id: &TripwireId) -> Result<Option<Tripwire>, StoreError> {
        Ok(self.lock()?.tripwires.get(id).cloned())
    }

    async fn list_tripwires(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Tripwire>, StoreError> {
        let items: Vec<Tripwire> = self
            .lock()?
            .tripwires
            .values()
            .filter(|t| &t.vault_id == vault_id)
            .cloned()
            .collect();
        Ok(page.apply(&newest_first(items, |t| t.created_at)))
    }

    async fn all_tripwires(&self, limit: u64) -> Result<Vec<Tripwire>, StoreError> {
        let items: Vec<Tripwire> = self.lock()?.tripwires.values().cloned().collect();
        let mut all = newest_first(items, |t| t.created_at);
        all.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(all)
    }

    async fn delete_tripwire(
        &self,
        id: &TripwireId,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        if inner.tripwires.remove(id).is_none() {
            return Ok(false);
        }
        inner.audit.extend_from_slice(audit);
        Ok(true)
    }

    async fn tripwire_tripped(&self, id: &TripwireId, at: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(t) = self.lock()?.tripwires.get_mut(id) {
            t.last_tripped_at = Some(at);
        }
        Ok(())
    }
}
