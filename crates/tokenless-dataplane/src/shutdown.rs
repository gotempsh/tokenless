// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stopping a data plane without losing what is in flight.
//!
//! [`DataPlane::shutdown`](crate::DataPlane::shutdown) moves through two
//! phases. While [`Lifecycle::Draining`] nothing new is accepted: the
//! listeners stop, a binding refuses new connections, and an intercepted,
//! idle proxy or MCP gateway connection closes once its requests in
//! flight have answered. Snapshots keep arriving, so a revocation still cuts traffic.
//! At the drain deadline it becomes [`Lifecycle::Closed`] and every tunnel
//! and streaming response still open is cut and audited as cut. The audit
//! queue ships what it holds without waiting for a full batch, gets one
//! last attempt of at most [`FINAL_AUDIT_SHIP`] after the cut, and what is
//! still unshipped then is reported, not hidden.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{sleep_until, Instant};
use tracing::{info, warn};

use crate::proxy::ProxyShared;

/// How long the audit queue gets, after open traffic is cut, to ship the
/// events the cuts recorded.
pub const FINAL_AUDIT_SHIP: Duration = Duration::from_secs(2);

/// How long traffic cut at the drain deadline gets to record its cut and
/// close before the drain reads what is left.
pub(crate) const CUT_SETTLE: Duration = Duration::from_millis(500);

/// Where the data plane is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Running,
    /// Nothing new starts; what is open may finish.
    Draining,
    /// Whatever is still open is cut.
    Closed,
}

/// Resolves once the data plane is no longer [`Lifecycle::Running`]; never
/// if its sender is gone without that happening.
pub(crate) async fn stopping(lifecycle: &mut watch::Receiver<Lifecycle>) {
    if lifecycle
        .wait_for(|l| *l != Lifecycle::Running)
        .await
        .is_err()
    {
        std::future::pending::<()>().await;
    }
}

/// Resolves once the data plane is [`Lifecycle::Closed`]; never if its
/// sender is gone without that happening.
pub(crate) async fn closed(lifecycle: &mut watch::Receiver<Lifecycle>) {
    if lifecycle
        .wait_for(|l| *l == Lifecycle::Closed)
        .await
        .is_err()
    {
        std::future::pending::<()>().await;
    }
}

/// What a shutdown left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Proxy, binding and MCP gateway connections, tunnels included,
    /// still open at the drain deadline and cut there.
    pub cut_connections: usize,
    /// Audit events recorded but not shipped when the data plane stopped.
    /// They are lost; the control plane never sees them.
    pub unshipped_audit_events: u64,
}

impl ShutdownReport {
    /// Nothing was cut and every audit event was shipped.
    pub fn clean(&self) -> bool {
        self.cut_connections == 0 && self.unshipped_audit_events == 0
    }
}

/// Drains `shared` until `deadline`, then cuts what is left and waits up to
/// [`FINAL_AUDIT_SHIP`] for the audit queue. The caller stops the accept
/// loops before and the remaining tasks after.
pub(crate) async fn drain(shared: &Arc<ProxyShared>, deadline: Instant) -> ShutdownReport {
    shared.lifecycle.send_replace(Lifecycle::Draining);
    info!(
        open_connections = open_connections(shared),
        "data plane draining"
    );
    wait_until(deadline, || open_connections(shared) == 0).await;
    let cut_connections = open_connections(shared);
    shared.lifecycle.send_replace(Lifecycle::Closed);
    if cut_connections > 0 {
        warn!(
            cut_connections,
            "drain deadline reached; cutting open connections"
        );
        // The cut tunnels and streams record their events as they unwind.
        wait_until(Instant::now() + CUT_SETTLE, || {
            open_connections(shared) == 0
        })
        .await;
    }
    wait_until(Instant::now() + FINAL_AUDIT_SHIP, || {
        shared.audit.pending() == 0
    })
    .await;
    let report = ShutdownReport {
        cut_connections,
        unshipped_audit_events: shared.audit.pending(),
    };
    if report.unshipped_audit_events > 0 {
        warn!(
            unshipped_audit_events = report.unshipped_audit_events,
            "data plane stopped with audit events it could not ship"
        );
    } else {
        info!(cut_connections, "data plane stopped");
    }
    report
}

/// Proxy and binding connections with their tunnels, and MCP gateway
/// connections.
fn open_connections(shared: &ProxyShared) -> usize {
    (shared.max_connections - shared.connections.available_permits())
        + (shared.max_connections - shared.gateway_connections.available_permits())
}

/// Polls `done` until it holds or `deadline` passes. Shutdown happens
/// once; a short poll keeps the counters it reads free of wakers.
async fn wait_until(deadline: Instant, mut done: impl FnMut() -> bool) {
    while !done() {
        let next = Instant::now() + Duration::from_millis(20);
        if next >= deadline {
            sleep_until(deadline).await;
            return;
        }
        sleep_until(next).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tokenless_core::audit::AuditEvent;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    use super::*;
    use crate::audit::AuditShipper;
    use crate::error::DataPlaneError;
    use crate::testing::{https_stream_upstream, running, running_with};

    /// A TCP upstream that echoes what it receives.
    async fn echo() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = conn.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    async fn echoes(stream: &mut TcpStream) -> bool {
        if stream.write_all(b"ping").await.is_err() {
            return false;
        }
        let mut buf = [0u8; 4];
        matches!(
            timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) && &buf == b"ping"
    }

    async fn closed(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 16];
        matches!(
            timeout(Duration::from_secs(2), stream.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    struct Collect(Mutex<Vec<AuditEvent>>);

    #[async_trait]
    impl AuditShipper for Collect {
        async fn ship(&self, events: &[AuditEvent]) -> Result<(), DataPlaneError> {
            if let Ok(mut all) = self.0.lock() {
                all.extend_from_slice(events);
            }
            Ok(())
        }
    }

    struct Unreachable;

    #[async_trait]
    impl AuditShipper for Unreachable {
        async fn ship(&self, _: &[AuditEvent]) -> Result<(), DataPlaneError> {
            Err(DataPlaneError::Control {
                method: "test".into(),
                path: "audit".into(),
                reason: "control plane unreachable".into(),
            })
        }
    }

    #[tokio::test]
    async fn a_drain_lets_open_tunnels_finish_and_accepts_nothing_new() {
        let r = running("api.example.com", vec![]).await;
        let upstream = echo().await;
        let mut tunnel = r.tunnel(&upstream).await;
        let (token, _) = r.bound_token("workload-1", 1, 600);
        let binding = r.bind("workload-1", vec![token]);
        let listener = r.dp.local_addr();

        let shutdown = tokio::spawn(r.dp.shutdown(Duration::from_secs(10)));
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(echoes(&mut tunnel).await, "an open tunnel keeps working");
        let (_workload, proxy_side) = tokio::io::duplex(1024);
        assert!(matches!(
            binding.serve(proxy_side).await,
            Err(DataPlaneError::ShuttingDown)
        ));
        if let Ok(mut late) = TcpStream::connect(listener).await {
            assert!(closed(&mut late).await, "the listener is not served");
        }

        let started = std::time::Instant::now();
        drop(tunnel);
        let report = timeout(Duration::from_secs(3), shutdown)
            .await
            .expect("the drain ends once the last tunnel closes")
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            report,
            ShutdownReport {
                cut_connections: 0,
                unshipped_audit_events: 0,
            }
        );
        assert!(report.clean());
    }

    #[tokio::test]
    async fn the_drain_deadline_cuts_what_is_left_and_ships_its_record() {
        let shipped = Arc::new(Collect(Mutex::new(Vec::new())));
        let r = running_with("api.example.com", vec![], 600, shipped.clone()).await;
        let upstream = echo().await;
        let mut tunnel = r.tunnel(&upstream).await;
        assert!(echoes(&mut tunnel).await);

        let report = r.dp.shutdown(Duration::from_millis(200)).await;
        assert_eq!(report.cut_connections, 1);
        assert_eq!(report.unshipped_audit_events, 0);
        assert!(closed(&mut tunnel).await, "the tunnel is cut");
        let events = shipped.0.lock().unwrap();
        let cut = events
            .iter()
            .find(|e| e.action == "proxy.tunnel_cut")
            .expect("the cut is audited and shipped before the plane stops");
        assert_eq!(
            cut.detail.get("reason").map(String::as_str),
            Some(crate::cut::SessionEnd::Shutdown.reason())
        );
    }

    /// The control plane is down: what could not ship is reported, not
    /// silently dropped.
    #[tokio::test]
    async fn audit_events_that_cannot_ship_are_reported() {
        let r = running_with("api.example.com", vec![], 600, Arc::new(Unreachable)).await;
        let upstream = echo().await;
        let tunnel = r.tunnel(&upstream).await;

        let report = r.dp.shutdown(Duration::from_millis(100)).await;
        assert_eq!(report.cut_connections, 1);
        assert!(
            report.unshipped_audit_events >= 1,
            "at least the cut is unshipped: {report:?}"
        );
        assert!(!report.clean());
        drop(tunnel);
    }

    /// An idle keep-alive connection has nothing in flight, so draining
    /// closes it at once instead of waiting out the deadline.
    #[tokio::test]
    async fn an_idle_intercepted_connection_closes_when_the_drain_starts() {
        let r = running("api.example.com", vec![]).await;
        let mut tls = r
            .intercepted("api.example.com:443", "api.example.com")
            .await;
        let started = std::time::Instant::now();
        let report = r.dp.shutdown(Duration::from_secs(10)).await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(report.cut_connections, 0);
        let mut buf = [0u8; 16];
        assert!(matches!(
            timeout(Duration::from_secs(2), tls.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        ));
    }

    /// Opens a gateway request to `target` that streams; returns the
    /// connection once the response head and first event arrived.
    async fn gateway_stream(r: &crate::testing::Running, target: &str) -> TcpStream {
        let gateway =
            r.dp.mcp_addr()
                .expect("the test plane runs the MCP gateway");
        let mut stream = TcpStream::connect(gateway).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /mcp/{target}/events HTTP/1.1\r\nHost: {gateway}\r\nAuthorization: Bearer {}\r\n\r\n",
                    r.token
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&seen).contains("hello") {
            let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
                .await
                .expect("the stream answers")
                .unwrap();
            assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&seen));
            seen.extend_from_slice(&buf[..n]);
        }
        assert!(
            String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&seen)
        );
        stream
    }

    const EVENT_STREAM: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n12\r\ndata: hello world\n\r\n";

    /// An event stream open through the MCP gateway is drained like a
    /// tunnel: it gets the drain time, then is cut and counted.
    #[tokio::test]
    async fn an_open_gateway_stream_is_drained_cut_and_counted() {
        let (port, root) = https_stream_upstream(EVENT_STREAM).await;
        let target = format!("localhost:{port}");
        let r = running(&target, vec![root]).await;
        let mut stream = gateway_stream(&r, &target).await;

        let started = std::time::Instant::now();
        let report = r.dp.shutdown(Duration::from_millis(500)).await;
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "the stream got the drain time: {:?}",
            started.elapsed()
        );
        assert_eq!(report.cut_connections, 1, "{report:?}");
        assert!(!report.clean());
        assert!(closed(&mut stream).await, "the stream is cut");
    }

    /// An idle keep-alive gateway connection closes when the drain starts.
    #[tokio::test]
    async fn an_idle_gateway_connection_closes_when_the_drain_starts() {
        let r = running("api.example.com", vec![]).await;
        let mut idle = TcpStream::connect(r.dp.mcp_addr().unwrap()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        let report = r.dp.shutdown(Duration::from_secs(10)).await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(report.cut_connections, 0);
        assert!(closed(&mut idle).await);
    }

    /// The stream cut at the deadline is audited as cut every time: the
    /// connection is not dropped before the stream's own cut records it.
    #[tokio::test]
    async fn a_gateway_stream_cut_at_the_deadline_is_always_audited() {
        let (port, root) = https_stream_upstream(EVENT_STREAM).await;
        let target = format!("localhost:{port}");
        let mut unaudited = 0;
        for _ in 0..10 {
            let shipped = Arc::new(Collect(Mutex::new(Vec::new())));
            let r = running_with(&target, vec![root.clone()], 600, shipped.clone()).await;
            let _stream = gateway_stream(&r, &target).await;
            let report = r.dp.shutdown(Duration::from_millis(100)).await;
            assert_eq!(report.cut_connections, 1, "{report:?}");
            assert_eq!(report.unshipped_audit_events, 0, "{report:?}");
            let audited = shipped
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.action == "proxy.tunnel_cut");
            if !audited {
                unaudited += 1;
            }
        }
        assert_eq!(unaudited, 0, "cut but not audited in {unaudited}/10 runs");
    }
}
