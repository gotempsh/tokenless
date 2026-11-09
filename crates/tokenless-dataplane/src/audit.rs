// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit pipeline: a bounded channel fed with `try_send` from the request
//! path, drained by a batcher that ships to the control plane.
//!
//! Saturation policy: when the channel is full the request path refuses to
//! inject (and counts the drop) rather than inject without a record. While
//! the control plane is unreachable the batcher keeps retrying the batch it
//! holds, the channel fills, and injection stops: fail closed.
//!
//! What this guarantees: an event counts as recorded once the control plane
//! has accepted its batch. Until then it lives only in this process, so a
//! crash loses up to `audit_capacity` queued events plus the batch being
//! shipped. A [shutdown](crate::DataPlane::shutdown) ships what is queued
//! and reports how many events it could not.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokenless_core::audit::AuditEvent;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::watch;
use tokio::time::{sleep, timeout_at, Instant};
use tracing::{debug, warn};

use crate::error::DataPlaneError;
use crate::metrics::Metrics;
use crate::shutdown::{stopping, Lifecycle};

#[async_trait]
pub trait AuditShipper: Send + Sync {
    async fn ship(&self, events: &[AuditEvent]) -> Result<(), DataPlaneError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRefused {
    Full,
    Closed,
}

#[derive(Clone)]
pub struct AuditPipeline {
    tx: mpsc::Sender<AuditEvent>,
    pending: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
}

/// The batcher's end of an [`AuditPipeline`].
pub struct AuditQueue {
    rx: mpsc::Receiver<AuditEvent>,
    pending: Arc<AtomicU64>,
}

impl AuditPipeline {
    pub fn new(capacity: usize, metrics: Arc<Metrics>) -> (Self, AuditQueue) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let pending = Arc::new(AtomicU64::new(0));
        (
            Self {
                tx,
                pending: pending.clone(),
                metrics,
            },
            AuditQueue { rx, pending },
        )
    }

    /// Never blocks. A refusal is counted in `audit_dropped_total`.
    pub fn try_record(&self, event: AuditEvent) -> Result<(), AuditRefused> {
        // Counted before it is queued, so the batcher never ships an event
        // it has not been counted for.
        self.pending.fetch_add(1, Ordering::Relaxed);
        let refused = match self.tx.try_send(event) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(_)) => {
                Metrics::inc(&self.metrics.audit_dropped_total);
                Err(AuditRefused::Full)
            }
            Err(TrySendError::Closed(_)) => {
                Metrics::inc(&self.metrics.audit_dropped_total);
                Err(AuditRefused::Closed)
            }
        };
        self.pending.fetch_sub(1, Ordering::Relaxed);
        refused
    }

    /// Events recorded and not yet shipped: queued, or in the batch being
    /// shipped.
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Relaxed)
    }
}

pub struct BatcherConfig {
    pub max_batch: usize,
    pub flush_interval: Duration,
}

/// Ships batches of up to `max_batch` events, each once it is full or
/// `flush_interval` after its first event; once the data plane is
/// stopping, as soon as an event is queued.
pub async fn run_batcher(
    queue: AuditQueue,
    shipper: Arc<dyn AuditShipper>,
    config: BatcherConfig,
    metrics: Arc<Metrics>,
    mut lifecycle: watch::Receiver<Lifecycle>,
) {
    let AuditQueue { mut rx, pending } = queue;
    let max = config.max_batch.max(1);
    let mut batch: Vec<AuditEvent> = Vec::with_capacity(max);
    loop {
        match rx.recv().await {
            Some(event) => batch.push(event),
            None => return,
        }
        let deadline = Instant::now() + config.flush_interval;
        while batch.len() < max {
            if *lifecycle.borrow() != Lifecycle::Running {
                // Ship what is queued now instead of waiting for more.
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
                continue;
            }
            tokio::select! {
                next = timeout_at(deadline, rx.recv()) => match next {
                    Ok(Some(event)) => batch.push(event),
                    Ok(None) | Err(_) => break,
                },
                () = stopping(&mut lifecycle) => {}
            }
        }
        let mut backoff = Duration::from_millis(200);
        loop {
            match shipper.ship(&batch).await {
                Ok(()) => {
                    pending.fetch_sub(batch.len() as u64, Ordering::Relaxed);
                    Metrics::add(&metrics.audit_shipped_total, batch.len() as u64);
                    debug!(events = batch.len(), "shipped audit batch");
                    break;
                }
                Err(e) => {
                    Metrics::inc(&metrics.audit_ship_failures_total);
                    warn!(events = batch.len(), error = %e, retry_in_ms = backoff.as_millis() as u64, "audit batch delivery failed");
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
        batch.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokenless_core::audit::AuditOutcome;

    use super::*;

    struct Collect(Mutex<Vec<usize>>);

    #[async_trait]
    impl AuditShipper for Collect {
        async fn ship(&self, events: &[AuditEvent]) -> Result<(), DataPlaneError> {
            if let Ok(mut v) = self.0.lock() {
                v.push(events.len());
            }
            Ok(())
        }
    }

    fn event() -> AuditEvent {
        AuditEvent::new("session:x", "proxy.inject", AuditOutcome::Success)
    }

    #[test]
    fn full_channel_refuses_and_counts() {
        let metrics = Arc::new(Metrics::default());
        let (pipeline, _rx) = AuditPipeline::new(2, metrics.clone());
        assert!(pipeline.try_record(event()).is_ok());
        assert!(pipeline.try_record(event()).is_ok());
        assert_eq!(pipeline.try_record(event()), Err(AuditRefused::Full));
        assert_eq!(pipeline.pending(), 2, "a refused event is not pending");
        assert_eq!(
            metrics
                .audit_dropped_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn batcher_groups_events() {
        let metrics = Arc::new(Metrics::default());
        let (pipeline, rx) = AuditPipeline::new(100, metrics.clone());
        for _ in 0..5 {
            pipeline.try_record(event()).unwrap();
        }
        drop(pipeline);
        let shipper = Arc::new(Collect(Mutex::new(vec![])));
        run_batcher(
            rx,
            shipper.clone(),
            BatcherConfig {
                max_batch: 3,
                flush_interval: Duration::from_millis(10),
            },
            metrics.clone(),
            watch::channel(Lifecycle::Running).1,
        )
        .await;
        assert_eq!(*shipper.0.lock().unwrap(), vec![3, 2]);
        assert_eq!(
            metrics
                .audit_shipped_total
                .load(std::sync::atomic::Ordering::Relaxed),
            5
        );
    }

    #[tokio::test]
    async fn pending_counts_events_until_their_batch_ships() {
        let metrics = Arc::new(Metrics::default());
        let (pipeline, queue) = AuditPipeline::new(100, metrics.clone());
        for _ in 0..3 {
            pipeline.try_record(event()).unwrap();
        }
        assert_eq!(pipeline.pending(), 3);
        let shipper = Arc::new(Collect(Mutex::new(vec![])));
        let (_lifecycle, running) = watch::channel(Lifecycle::Running);
        let batcher = tokio::spawn(run_batcher(
            queue,
            shipper.clone(),
            BatcherConfig {
                max_batch: 10,
                flush_interval: Duration::from_millis(10),
            },
            metrics,
            running,
        ));
        for _ in 0..100 {
            if pipeline.pending() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(pipeline.pending(), 0);
        assert_eq!(*shipper.0.lock().unwrap(), vec![3]);
        batcher.abort();
    }

    /// Once the data plane stops, an event ships without waiting out the
    /// flush interval.
    #[tokio::test]
    async fn a_stopping_data_plane_ships_at_once() {
        let metrics = Arc::new(Metrics::default());
        let (pipeline, queue) = AuditPipeline::new(100, metrics.clone());
        let shipper = Arc::new(Collect(Mutex::new(vec![])));
        let (lifecycle, rx) = watch::channel(Lifecycle::Running);
        let batcher = tokio::spawn(run_batcher(
            queue,
            shipper.clone(),
            BatcherConfig {
                max_batch: 10,
                flush_interval: Duration::from_secs(3600),
            },
            metrics,
            rx,
        ));
        pipeline.try_record(event()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pipeline.pending(), 1, "held for the flush interval");
        lifecycle.send_replace(Lifecycle::Draining);
        for _ in 0..100 {
            if pipeline.pending() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(pipeline.pending(), 0);
        pipeline.try_record(event()).unwrap();
        pipeline.try_record(event()).unwrap();
        for _ in 0..100 {
            if pipeline.pending() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(pipeline.pending(), 0, "no waiting once draining");
        batcher.abort();
    }
}
