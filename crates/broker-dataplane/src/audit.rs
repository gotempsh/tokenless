// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit pipeline: a bounded channel fed with `try_send` from the request
//! path, drained by a batcher that ships to the control plane.
//!
//! Saturation policy: when the channel is full the request path refuses to
//! inject (and counts the drop) rather than inject without a record. While
//! the control plane is unreachable the batcher keeps retrying the batch it
//! holds, the channel fills, and injection stops: fail closed.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use broker_core::audit::AuditEvent;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::time::{sleep, timeout_at, Instant};
use tracing::{debug, warn};

use crate::error::DataPlaneError;
use crate::metrics::Metrics;

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
    metrics: Arc<Metrics>,
}

impl AuditPipeline {
    pub fn new(capacity: usize, metrics: Arc<Metrics>) -> (Self, mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self { tx, metrics }, rx)
    }

    /// Never blocks. A refusal is counted in `audit_dropped_total`.
    pub fn try_record(&self, event: AuditEvent) -> Result<(), AuditRefused> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                Metrics::inc(&self.metrics.audit_dropped_total);
                Err(AuditRefused::Full)
            }
            Err(TrySendError::Closed(_)) => {
                Metrics::inc(&self.metrics.audit_dropped_total);
                Err(AuditRefused::Closed)
            }
        }
    }
}

pub struct BatcherConfig {
    pub max_batch: usize,
    pub flush_interval: Duration,
}

pub async fn run_batcher(
    mut rx: mpsc::Receiver<AuditEvent>,
    shipper: Arc<dyn AuditShipper>,
    config: BatcherConfig,
    metrics: Arc<Metrics>,
) {
    let max = config.max_batch.max(1);
    let mut batch: Vec<AuditEvent> = Vec::with_capacity(max);
    loop {
        match rx.recv().await {
            Some(event) => batch.push(event),
            None => return,
        }
        let deadline = Instant::now() + config.flush_interval;
        while batch.len() < max {
            match timeout_at(deadline, rx.recv()).await {
                Ok(Some(event)) => batch.push(event),
                Ok(None) | Err(_) => break,
            }
        }
        let mut backoff = Duration::from_millis(200);
        loop {
            match shipper.ship(&batch).await {
                Ok(()) => {
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

    use broker_core::audit::AuditOutcome;

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
}
