// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The policy source of an embedded data plane: the host process hands it
//! signed snapshots instead of the data plane streaming them from a node API.

use std::sync::{Arc, Mutex};

use broker_core::snapshot::SignedSnapshot;
use tokio::sync::watch;

use crate::error::DataPlaneError;
use crate::metrics::Metrics;
use crate::state::{apply, NodeKeys, SnapshotHandle};

/// Installs signed snapshots into an embedded data plane. Cheap to clone;
/// every clone installs into the same data plane.
#[derive(Clone)]
pub struct SnapshotInstaller {
    keys: Arc<NodeKeys>,
    handle: SnapshotHandle,
    changed: watch::Sender<u64>,
    metrics: Arc<Metrics>,
    /// Serializes installs: two hosts' tasks installing at once must not let
    /// an older snapshot replace a newer one between check and swap.
    installing: Arc<Mutex<()>>,
}

impl SnapshotInstaller {
    pub(crate) fn new(
        keys: Arc<NodeKeys>,
        handle: SnapshotHandle,
        changed: watch::Sender<u64>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            keys,
            handle,
            changed,
            metrics,
            installing: Arc::new(Mutex::new(())),
        }
    }

    /// Verifies `signed` exactly as a node does (signature, node id, a
    /// version above the one in force, a lease that has not run out) and
    /// puts it in force. Returns its version. A refused snapshot leaves the
    /// one in force untouched. Opening rules and minting interception
    /// certificates is CPU work; call it off latency-sensitive tasks.
    pub fn install(&self, signed: &SignedSnapshot) -> Result<u64, DataPlaneError> {
        // A panic while installing leaves no half-applied state (the swap is
        // the last step), so a poisoned lock is safe to take.
        let _installing = self
            .installing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        apply(
            signed,
            &self.keys,
            &self.handle,
            &self.changed,
            &self.metrics,
        )
    }

    /// Version of the snapshot in force, if any.
    pub fn version(&self) -> Option<u64> {
        self.handle.load().as_ref().map(|s| s.version)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use async_trait::async_trait;
    use broker_core::audit::AuditEvent;
    use broker_core::ids::RuleId;
    use broker_core::scope::Scope;
    use broker_core::session::{SessionClaims, SessionSigner};
    use chrono::Utc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::audit::AuditShipper;
    use crate::state::tests::Fixture;
    use crate::{DataPlane, DataPlaneConfig};

    #[derive(Default)]
    struct Collect(Mutex<Vec<AuditEvent>>);

    #[async_trait]
    impl AuditShipper for Collect {
        async fn ship(&self, events: &[AuditEvent]) -> Result<(), DataPlaneError> {
            if let Ok(mut v) = self.0.lock() {
                v.extend_from_slice(events);
            }
            Ok(())
        }
    }

    fn copy_keys(f: &Fixture) -> NodeKeys {
        NodeKeys {
            node_id: f.keys.node_id,
            seal_secret: f.keys.seal_secret.clone(),
            snapshot_key: f.keys.snapshot_key,
        }
    }

    fn config() -> DataPlaneConfig {
        DataPlaneConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            audit_flush_interval: Duration::from_millis(20),
            ..DataPlaneConfig::default()
        }
    }

    fn scope() -> Scope {
        Scope::parse("vault:test").unwrap()
    }

    /// Sends one CONNECT and returns the status line.
    async fn connect(dp: &DataPlane, target: &str, token: Option<&str>) -> String {
        let mut stream = TcpStream::connect(dp.local_addr()).await.unwrap();
        let auth = token
            .map(|t| format!("Proxy-Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        stream
            .write_all(
                format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn installs_verified_snapshots_and_refuses_the_rest() {
        let f = Fixture::new();
        let (dp, installer) =
            DataPlane::start_embedded(config(), copy_keys(&f), Arc::new(Collect::default()))
                .await
                .unwrap();
        assert_eq!(installer.version(), None);
        assert!(!dp.lease_valid());

        let rule = RuleId::new();
        assert_eq!(
            installer
                .install(&f.snapshot(3, vec![(rule, scope(), "api.example.com", "t")]))
                .unwrap(),
            3
        );
        assert_eq!(dp.snapshot_version(), Some(3));
        assert!(dp.lease_valid());

        // Same or older version: refused, version 3 stays in force.
        let stale = installer.install(&f.snapshot(3, vec![])).unwrap_err();
        assert!(matches!(
            stale,
            DataPlaneError::StaleSnapshot {
                received: 3,
                current: 3
            }
        ));
        // Another node's snapshot, or one signed by another key: refused.
        let other = Fixture::new();
        assert!(installer.install(&other.snapshot(9, vec![])).is_err());
        assert_eq!(installer.version(), Some(3));

        let metrics = dp.metrics().render();
        assert!(metrics.contains("snapshots_applied_total 1"), "{metrics}");
        assert!(metrics.contains("snapshots_rejected_total 2"), "{metrics}");
        dp.shutdown();
    }

    #[tokio::test]
    async fn refuses_traffic_until_a_snapshot_is_installed() {
        let f = Fixture::new();
        let (dp, _installer) =
            DataPlane::start_embedded(config(), copy_keys(&f), Arc::new(Collect::default()))
                .await
                .unwrap();
        let status = connect(&dp, "api.example.com:443", None).await;
        assert!(status.contains(" 503 "), "{status}");
        dp.shutdown();
    }

    #[tokio::test]
    async fn audit_events_go_to_the_hosts_shipper() {
        let f = Fixture::new();
        let shipper = Arc::new(Collect::default());
        let (dp, installer) = DataPlane::start_embedded(config(), copy_keys(&f), shipper.clone())
            .await
            .unwrap();
        let rule = RuleId::new();
        installer
            .install(&f.snapshot(1, vec![(rule, scope(), "api.example.com", "t")]))
            .unwrap();
        let claims = SessionClaims::new(
            scope(),
            vec![rule],
            60,
            None,
            BTreeMap::new(),
            Utc::now(),
            3600,
        )
        .unwrap();
        let token = SessionSigner::new(f.session_signer.clone())
            .sign(&claims)
            .unwrap();

        // Loopback is refused by the default egress policy, and audited.
        let status = connect(&dp, "127.0.0.1:9", Some(&token)).await;
        assert!(status.contains(" 403 "), "{status}");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let shipped = shipper.0.lock().unwrap().clone();
            if let Some(event) = shipped.iter().find(|e| e.action == "proxy.egress_blocked") {
                assert_eq!(event.actor, format!("node:{}", f.keys.node_id));
                assert_eq!(
                    event.detail.get("session_id"),
                    Some(&claims.jti.to_string())
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no audit event shipped: {shipped:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        dp.shutdown();
    }
}
