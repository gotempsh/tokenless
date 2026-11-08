// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Refreshing a secret the host mints itself (an installation token, an
//! OAuth access token) without two refreshers overwriting each other.
//!
//! The host owns the refresh: it decides when (before the secret's
//! `not_after`, or after the upstream refuses it) and mints the new value.
//! Tokenless stores it, write-only, and guarantees:
//!
//! * **Version fencing.** Each secret has a generation. A refresh names the
//!   generation it replaces; if another refresh got there first it fails
//!   with [`StoreError::StaleGeneration`] and nothing changes, so a slow
//!   refresher never overwrites a newer secret with an older one.
//! * **Idempotent retries.** A refresh carries a rotation id. Retrying it
//!   after a timeout returns the credential as the first attempt left it,
//!   instead of rotating twice.
//! * **Single flight.** [`CredentialRefresher`] runs one refresh per
//!   credential at a time in this process; the others wait for it and get
//!   its result. Across processes the fencing above decides.
//! * **Fail closed.** A refresh that fails writes nothing. The current
//!   secret stays until its `not_after`; after that the proxy refuses its
//!   requests (`credential_expired`) rather than sending a secret the
//!   upstream would refuse.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use chrono::{DateTime, Utc};
use tokenless_core::ids::CredentialId;

use super::policy::{PolicyService, RotateCredential};
use super::Caller;
use crate::error::{ControlError, StoreError};
use crate::model::CredentialMeta;

/// A secret the host minted.
#[derive(Clone)]
pub struct FreshSecret {
    pub fields: BTreeMap<String, String>,
    /// When it stops being valid upstream, if it does.
    pub not_after: Option<DateTime<Utc>>,
}

tokenless_core::redacted_debug!(FreshSecret { not_after; fields });

/// What a refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refreshed {
    /// This refresh stored a new secret.
    Rotated(CredentialMeta),
    /// The secret had already moved past the generation this refresh was
    /// for, so nothing was minted or stored, or what was minted was
    /// discarded: another refresh, here or elsewhere, stored a newer one.
    Superseded(CredentialMeta),
}

impl Refreshed {
    /// The credential as it is now.
    pub fn credential(&self) -> &CredentialMeta {
        match self {
            Refreshed::Rotated(meta) | Refreshed::Superseded(meta) => meta,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError<E: std::error::Error + 'static> {
    /// Minting failed; nothing was stored.
    #[error("refreshing credential {credential_id} failed while minting its new secret: {source}")]
    Mint {
        credential_id: CredentialId,
        #[source]
        source: E,
    },
    #[error(transparent)]
    Control(#[from] ControlError),
}

/// Runs one refresh per credential at a time; see the [module](self).
#[derive(Default)]
pub struct CredentialRefresher {
    in_flight: Mutex<HashMap<CredentialId, Arc<tokio::sync::Mutex<()>>>>,
}

impl CredentialRefresher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the secret of generation `stale_generation` (the one that
    /// is about to expire, or that the upstream refused) with what `mint`
    /// returns.
    ///
    /// Waits for a refresh of the same credential already running here.
    /// If the credential has moved past `stale_generation` by then,
    /// returns [`Refreshed::Superseded`] without calling `mint`. Otherwise
    /// calls `mint` with the credential and stores its secret fenced on
    /// `stale_generation`, retrying once with the same rotation id if the
    /// store fails, so a write that landed is not applied twice. If another
    /// process stored a newer secret meanwhile, the minted one is
    /// discarded and the result is [`Refreshed::Superseded`]; revoke it
    /// upstream if it can be.
    pub async fn refresh<F, Fut, E>(
        &self,
        policy: &PolicyService,
        caller: &Caller,
        id: &CredentialId,
        stale_generation: u64,
        mint: F,
    ) -> Result<Refreshed, RefreshError<E>>
    where
        F: FnOnce(CredentialMeta) -> Fut,
        Fut: Future<Output = Result<FreshSecret, E>>,
        E: std::error::Error + 'static,
    {
        let slot = self.slot(id);
        let result = {
            let _turn = slot.lock().await;
            self.refresh_now(policy, caller, id, stale_generation, mint)
                .await
        };
        self.release(id, slot);
        result
    }

    async fn refresh_now<F, Fut, E>(
        &self,
        policy: &PolicyService,
        caller: &Caller,
        id: &CredentialId,
        stale_generation: u64,
        mint: F,
    ) -> Result<Refreshed, RefreshError<E>>
    where
        F: FnOnce(CredentialMeta) -> Fut,
        Fut: Future<Output = Result<FreshSecret, E>>,
        E: std::error::Error + 'static,
    {
        let current = policy.get_credential(caller, id).await?;
        if current.secret_generation != stale_generation {
            return Ok(Refreshed::Superseded(current));
        }
        let fresh = mint(current).await.map_err(|source| RefreshError::Mint {
            credential_id: *id,
            source,
        })?;
        let request = RotateCredential {
            fields: fresh.fields,
            not_after: fresh.not_after,
            expected_generation: Some(stale_generation),
            rotation_id: Some(format!("refresh-{}", uuid::Uuid::new_v4())),
        };
        let mut attempt = policy.rotate_credential(caller, id, request.clone()).await;
        if let Err(ControlError::Store(StoreError::Backend { .. })) = &attempt {
            attempt = policy.rotate_credential(caller, id, request).await;
        }
        match attempt {
            Ok(meta) => Ok(Refreshed::Rotated(meta)),
            Err(ControlError::Store(StoreError::StaleGeneration { .. })) => Ok(
                Refreshed::Superseded(policy.get_credential(caller, id).await?),
            ),
            Err(e) => Err(e.into()),
        }
    }

    fn slot(&self, id: &CredentialId) -> Arc<tokio::sync::Mutex<()>> {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(*id)
            .or_default()
            .clone()
    }

    /// Forgets the credential's slot once nobody else holds it, so the map
    /// only holds refreshes in flight.
    fn release(&self, id: &CredentialId, slot: Arc<tokio::sync::Mutex<()>>) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The map's reference and ours; anyone else would have cloned it
        // under this lock.
        if Arc::strong_count(&slot) == 2 {
            in_flight.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::TimeDelta;
    use tokenless_core::authz::{Principal, Role};

    use super::*;
    use crate::service::testing::{services, vault_with_rule};
    use crate::ControlServices;

    #[derive(Debug, thiserror::Error)]
    #[error("the issuer is down")]
    struct IssuerDown;

    fn host() -> Caller {
        Caller::service(Principal::service("host", Role::Admin, None))
    }

    async fn credential(cs: &ControlServices) -> CredentialId {
        let host = host();
        let (vault, _) = vault_with_rule(cs, &host).await;
        cs.policy
            .list_credentials(&host, &vault, Default::default())
            .await
            .unwrap()
            .items[0]
            .id
    }

    fn fresh(token: &str, valid_for: TimeDelta) -> FreshSecret {
        FreshSecret {
            fields: [("token".to_string(), token.to_string())].into(),
            not_after: Some(Utc::now() + valid_for),
        }
    }

    async fn rotations(cs: &ControlServices) -> usize {
        cs.audit
            .query(
                &host(),
                None,
                Some("credential.rotate".into()),
                Default::default(),
            )
            .await
            .unwrap()
            .items
            .iter()
            .filter(|e| e.action == "credential.rotate")
            .count()
    }

    #[tokio::test]
    async fn concurrent_refreshes_mint_once() {
        let (_, cs) = services().await;
        let cs = Arc::new(cs);
        let id = credential(&cs).await;
        let refresher = Arc::new(CredentialRefresher::new());
        let minted = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (cs, refresher, minted) = (cs.clone(), refresher.clone(), minted.clone());
                tokio::spawn(async move {
                    refresher
                        .refresh(&cs.policy, &host(), &id, 1, |_| async move {
                            minted.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            Ok::<_, IssuerDown>(fresh("t2", TimeDelta::hours(1)))
                        })
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut rotated = 0;
        for task in tasks {
            let outcome = task.await.unwrap();
            assert_eq!(outcome.credential().secret_generation, 2);
            rotated += usize::from(matches!(outcome, Refreshed::Rotated(_)));
        }
        assert_eq!((minted.load(Ordering::SeqCst), rotated), (1, 1));
        assert_eq!(rotations(&cs).await, 1);
        assert!(refresher.in_flight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_slower_refresher_elsewhere_cannot_overwrite_a_newer_secret() {
        let (_, cs) = services().await;
        let cs = Arc::new(cs);
        let id = credential(&cs).await;
        // Two processes: separate refreshers, one store.
        let (here, elsewhere) = (CredentialRefresher::new(), CredentialRefresher::new());
        let (minting, finish) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        let slow = {
            let (cs, minting, finish) = (cs.clone(), minting.clone(), finish.clone());
            tokio::spawn(async move {
                elsewhere
                    .refresh(&cs.policy, &host(), &id, 1, |_| async move {
                        minting.notify_one();
                        finish.notified().await;
                        Ok::<_, IssuerDown>(fresh("old", TimeDelta::hours(2)))
                    })
                    .await
                    .unwrap()
            })
        };
        minting.notified().await;
        let fast = here
            .refresh(&cs.policy, &host(), &id, 1, |_| async {
                Ok::<_, IssuerDown>(fresh("new", TimeDelta::hours(1)))
            })
            .await
            .unwrap();
        assert!(matches!(fast, Refreshed::Rotated(_)));
        finish.notify_one();
        let slow = slow.await.unwrap();
        assert!(matches!(slow, Refreshed::Superseded(_)), "{slow:?}");
        // The fast refresher's secret (valid for one hour) is the one kept.
        let now = cs.policy.get_credential(&host(), &id).await.unwrap();
        assert_eq!(now.secret_generation, 2);
        assert!(now.not_after.unwrap() < Utc::now() + TimeDelta::minutes(90));
        assert_eq!(rotations(&cs).await, 1);
    }

    #[tokio::test]
    async fn a_failed_mint_stores_nothing_and_a_retried_rotation_applies_once() {
        let (_, cs) = services().await;
        let id = credential(&cs).await;
        let refresher = CredentialRefresher::new();
        let failed = refresher
            .refresh(&cs.policy, &host(), &id, 1, |_| async {
                Err::<FreshSecret, _>(IssuerDown)
            })
            .await;
        assert!(
            matches!(failed, Err(RefreshError::Mint { credential_id, .. }) if credential_id == id)
        );
        let meta = cs.policy.get_credential(&host(), &id).await.unwrap();
        assert_eq!((meta.secret_generation, rotations(&cs).await), (1, 0));

        // A rotation retried after its answer was lost is recognised.
        let rotate = RotateCredential {
            fields: [("token".to_string(), "t2".to_string())].into(),
            expected_generation: Some(1),
            rotation_id: Some("job-7".into()),
            ..Default::default()
        };
        for _ in 0..2 {
            let meta = cs
                .policy
                .rotate_credential(&host(), &id, rotate.clone())
                .await
                .unwrap();
            assert_eq!(meta.secret_generation, 2);
        }
        assert_eq!(rotations(&cs).await, 1);
        // Another rotation of generation 1 is stale.
        let stale = cs
            .policy
            .rotate_credential(
                &host(),
                &id,
                RotateCredential {
                    rotation_id: Some("job-8".into()),
                    ..rotate.clone()
                },
            )
            .await;
        assert!(matches!(
            stale,
            Err(ControlError::Store(StoreError::StaleGeneration {
                expected: 1,
                current: 2,
                ..
            }))
        ));
        let bad_id = cs
            .policy
            .rotate_credential(
                &host(),
                &id,
                RotateCredential {
                    rotation_id: Some("no spaces".into()),
                    expected_generation: None,
                    ..rotate
                },
            )
            .await;
        assert!(matches!(bad_id, Err(ControlError::Validation { .. })));
    }
}
