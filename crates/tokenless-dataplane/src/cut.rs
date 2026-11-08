// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cutting traffic that is already flowing when its session ends.
//!
//! A session is checked when a tunnel opens and on every request inside an
//! intercepted one, but a passthrough tunnel, an idle keep-alive connection
//! or a streaming body can outlive those checks. Each of them waits on
//! [`session_end`] next to its I/O and is dropped when it resolves: when a
//! snapshot lists the session as revoked, when the binding it came through
//! is revoked, when the snapshot lease runs out (revocations can no longer
//! arrive), or a grace period after the session expired
//! ([`OPEN_TRAFFIC_GRACE_SECS`](tokenless_core::session::OPEN_TRAFFIC_GRACE_SECS)).
//!
//! Expiry itself stops only new traffic: no new tunnel, no new request
//! inside an intercepted one. Its holder usually renews before it runs out
//! (`tokenless run` mints the next session first) and keeps using
//! connections it opened under the old one, which must not break at every
//! renewal. An intercepted connection is closed gracefully at expiry, once
//! its requests in flight have finished, so the client reconnects with its
//! current session; a passthrough tunnel and a streaming response run on
//! for up to the grace period. The control plane keeps a revoked session
//! in snapshots for that long after it expires, so revoking it still cuts
//! that traffic.
//!
//! Nothing is registered per session: every open tunnel holds a receiver of
//! the snapshot-change signal and its own deadline, so a new snapshot wakes
//! each open tunnel once, O(open tunnels), and opening one takes no lock.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use hyper::body::{Body, Frame, SizeHint};
use tokenless_core::ids::SessionId;
use tokenless_core::session::{open_traffic_deadline, SessionClaims};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};

use crate::binding::{BindingState, BindingWatch};
use crate::proxy::{BodyError, ProxyBody};
use crate::state::SnapshotHandle;

/// Why open traffic was cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    Revoked,
    /// The binding the traffic came through was revoked.
    BindingRevoked,
    /// The snapshot lease ran out, so a revocation could no longer arrive.
    LeaseExpired,
    /// The session expired longer ago than open traffic may outlive it.
    Expired,
}

impl SessionEnd {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Revoked => "the session was revoked",
            Self::BindingRevoked => "the binding it came through was revoked",
            Self::LeaseExpired => {
                "the policy lease expired (control plane unreachable), so revocations cannot arrive"
            }
            Self::Expired => {
                "the session it was opened under expired longer ago than open traffic may outlive it"
            }
        }
    }
}

/// What a tunnel needs to know when its session ends.
#[derive(Clone)]
pub(crate) struct SessionWatch {
    pub changes: watch::Receiver<u64>,
    pub snapshot: SnapshotHandle,
    pub jti: SessionId,
    /// When the traffic is cut even if nothing revokes it.
    pub deadline: DateTime<Utc>,
    pub binding: Option<BindingWatch>,
}

impl SessionWatch {
    pub fn new(
        changes: watch::Receiver<u64>,
        snapshot: SnapshotHandle,
        claims: &SessionClaims,
    ) -> Self {
        Self {
            changes,
            snapshot,
            jti: claims.jti,
            deadline: open_traffic_deadline(claims.exp),
            binding: None,
        }
    }

    /// Also ends when `binding`, the one the traffic came through, is revoked.
    pub fn through(mut self, binding: Option<&BindingState>) -> Self {
        self.binding = binding.map(BindingState::watch);
        self
    }
}

/// Resolves when the binding is revoked or gone; never without one.
async fn binding_revoked(binding: &mut Option<BindingWatch>) {
    match binding {
        Some(b) => {
            let _ = b.revoked.wait_for(|revoked| *revoked).await;
        }
        None => std::future::pending().await,
    }
}

/// Resolves at the session's expiry: the moment it may start nothing new.
pub(crate) async fn session_expiry(exp: DateTime<Utc>) {
    if let Ok(left) = (exp - Utc::now()).to_std() {
        tokio::time::sleep(left).await;
    }
}

/// Resolves when the session's open traffic must be cut; see the module
/// docs for why that is not its expiry.
pub(crate) async fn session_end(mut watch: SessionWatch) -> SessionEnd {
    loop {
        if watch.binding.as_ref().is_some_and(|b| *b.revoked.borrow()) {
            return SessionEnd::BindingRevoked;
        }
        let deadline = {
            let Some(current) = watch.snapshot.load_full() else {
                return SessionEnd::LeaseExpired;
            };
            if current.revoked.contains(&watch.jti) {
                return SessionEnd::Revoked;
            }
            if !current.lease_valid() {
                return SessionEnd::LeaseExpired;
            }
            let Ok(left) = (watch.deadline - Utc::now()).to_std() else {
                return SessionEnd::Expired;
            };
            if left.is_zero() {
                return SessionEnd::Expired;
            }
            (Instant::now() + left).min(Instant::from_std(current.lease_deadline))
        };
        tokio::select! {
            changed = watch.changes.changed() => {
                // The sender lives as long as the proxy; without it only the
                // deadline is left to wait for.
                if changed.is_err() {
                    sleep_until(deadline).await;
                }
            }
            () = sleep_until(deadline) => {}
            () = binding_revoked(&mut watch.binding) => return SessionEnd::BindingRevoked,
        }
    }
}

/// A streaming body was cut because its session ended.
#[derive(Debug, thiserror::Error)]
#[error("session {session_id} ended while its response was streaming: {}", end.reason())]
pub struct StreamCut {
    pub session_id: SessionId,
    pub end: SessionEnd,
}

/// A response body that ends with [`StreamCut`] when its session ends.
pub(crate) struct CutBody {
    inner: ProxyBody,
    session_id: SessionId,
    end: oneshot::Receiver<SessionEnd>,
    /// Aborted when the body finishes or is dropped.
    watcher: JoinHandle<()>,
    cut: bool,
}

impl CutBody {
    /// `on_cut` runs once if the body is cut while still being read.
    pub fn wrap(
        inner: ProxyBody,
        watch: SessionWatch,
        on_cut: impl FnOnce(SessionEnd) + Send + 'static,
    ) -> ProxyBody {
        let session_id = watch.jti;
        let (tx, end) = oneshot::channel();
        let watcher = tokio::spawn(async move {
            let end = session_end(watch).await;
            if tx.send(end).is_ok() {
                on_cut(end);
            }
        });
        http_body_util::BodyExt::boxed(Self {
            inner,
            session_id,
            end,
            watcher,
            cut: false,
        })
    }
}

impl Drop for CutBody {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

impl Body for CutBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.cut {
            return Poll::Ready(None);
        }
        if let Poll::Ready(Ok(end)) = Pin::new(&mut self.end).poll(cx) {
            self.cut = true;
            return Poll::Ready(Some(Err(Box::new(StreamCut {
                session_id: self.session_id,
                end,
            }))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.cut || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwapOption;
    use http_body_util::BodyExt;
    use tokenless_core::ids::RuleId;
    use tokenless_core::scope::Scope;
    use tokenless_core::session::OPEN_TRAFFIC_GRACE_SECS;
    use tokio::time::timeout;

    use super::*;
    use crate::metrics::Metrics;
    use crate::state::apply;
    use crate::state::tests::Fixture;

    fn claims(ttl_secs: u64) -> SessionClaims {
        SessionClaims::new(
            Scope::parse("vault:test").unwrap(),
            vec![RuleId::new()],
            ttl_secs,
            None,
            BTreeMap::new(),
            Utc::now(),
            3600,
        )
        .unwrap()
    }

    struct Setup {
        f: Fixture,
        handle: SnapshotHandle,
        changed: watch::Sender<u64>,
        metrics: Metrics,
    }

    fn setup() -> Setup {
        let f = Fixture::new();
        let handle: SnapshotHandle = Arc::new(ArcSwapOption::empty());
        let (changed, _) = watch::channel(0);
        let metrics = Metrics::default();
        apply(&f.snapshot(1, vec![]), &f.keys, &handle, &changed, &metrics).unwrap();
        Setup {
            f,
            handle,
            changed,
            metrics,
        }
    }

    #[tokio::test]
    async fn a_revoking_snapshot_ends_the_session_and_others_do_not() {
        let s = setup();
        let mine = claims(600);
        let end = tokio::spawn(session_end(SessionWatch::new(
            s.changed.subscribe(),
            s.handle.clone(),
            &mine,
        )));

        // A snapshot that revokes someone else: still running.
        let mut body = s.f.snapshot_body(2, vec![]);
        body.revoked_sessions = vec![SessionId::new()];
        apply(
            &s.f.sign(&body),
            &s.f.keys,
            &s.handle,
            &s.changed,
            &s.metrics,
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!end.is_finished());

        let mut body = s.f.snapshot_body(3, vec![]);
        body.revoked_sessions = vec![mine.jti];
        apply(
            &s.f.sign(&body),
            &s.f.keys,
            &s.handle,
            &s.changed,
            &s.metrics,
        )
        .unwrap();
        let end = timeout(Duration::from_secs(1), end).await.unwrap().unwrap();
        assert_eq!(end, SessionEnd::Revoked);
    }

    /// Expiry alone cuts nothing at once: the holder has usually renewed.
    #[tokio::test]
    async fn open_traffic_outlives_expiry() {
        let s = setup();
        let mine = claims(1);
        let end = timeout(
            Duration::from_secs(2),
            session_end(SessionWatch::new(
                s.changed.subscribe(),
                s.handle.clone(),
                &mine,
            )),
        )
        .await;
        assert!(end.is_err(), "{end:?}");
    }

    /// Claims that expired `ago` before now.
    fn expired(ago: chrono::TimeDelta) -> SessionClaims {
        let mut c = claims(600);
        c.exp = Utc::now() - ago;
        c
    }

    #[tokio::test]
    async fn open_traffic_is_cut_a_grace_period_after_expiry() {
        let s = setup();
        let grace = chrono::TimeDelta::seconds(OPEN_TRAFFIC_GRACE_SECS);
        let watch = |c: &SessionClaims| {
            session_end(SessionWatch::new(
                s.changed.subscribe(),
                s.handle.clone(),
                c,
            ))
        };

        let long_gone = expired(grace + chrono::TimeDelta::seconds(1));
        let end = timeout(Duration::from_millis(100), watch(&long_gone)).await;
        assert_eq!(end.unwrap(), SessionEnd::Expired);

        let nearly = expired(grace - chrono::TimeDelta::seconds(1));
        let end = timeout(Duration::from_secs(3), watch(&nearly)).await;
        assert_eq!(end.unwrap(), SessionEnd::Expired);
    }

    /// The control plane keeps a revoked session in snapshots for the grace
    /// period after it expires, and the data plane acts on it.
    #[tokio::test]
    async fn a_session_revoked_after_it_expired_still_cuts_its_traffic() {
        let s = setup();
        let mine = expired(chrono::TimeDelta::minutes(10));
        let end = tokio::spawn(session_end(SessionWatch::new(
            s.changed.subscribe(),
            s.handle.clone(),
            &mine,
        )));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!end.is_finished());

        let mut body = s.f.snapshot_body(2, vec![]);
        body.revoked_sessions = vec![mine.jti];
        apply(
            &s.f.sign(&body),
            &s.f.keys,
            &s.handle,
            &s.changed,
            &s.metrics,
        )
        .unwrap();
        let end = timeout(Duration::from_secs(1), end).await.unwrap().unwrap();
        assert_eq!(end, SessionEnd::Revoked);
    }

    #[tokio::test]
    async fn a_streaming_body_is_cut_when_its_session_is_revoked() {
        let s = setup();
        let mine = claims(600);
        // A body that sends one chunk and then stays open, like an event stream.
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(Bytes::from_static(b"event: one\n\n"))
            .await
            .unwrap();
        let inner = Channel(rx).boxed();
        let (cut_tx, cut_rx) = oneshot::channel();
        let mut body = CutBody::wrap(
            inner,
            SessionWatch::new(s.changed.subscribe(), s.handle.clone(), &mine),
            move |end| {
                let _ = cut_tx.send(end);
            },
        );
        let first = body.frame().await.unwrap().unwrap();
        assert_eq!(
            first.into_data().unwrap(),
            Bytes::from_static(b"event: one\n\n")
        );

        let mut revoking = s.f.snapshot_body(2, vec![]);
        revoking.revoked_sessions = vec![mine.jti];
        apply(
            &s.f.sign(&revoking),
            &s.f.keys,
            &s.handle,
            &s.changed,
            &s.metrics,
        )
        .unwrap();
        let cut = timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        let cut = cut.downcast::<StreamCut>().unwrap();
        assert_eq!(cut.end, SessionEnd::Revoked);
        assert_eq!(cut.session_id, mine.jti);
        assert!(body.frame().await.is_none());
        assert_eq!(cut_rx.await.unwrap(), SessionEnd::Revoked);
        drop(tx);
    }

    /// A body fed from a channel; open until the sender is dropped.
    struct Channel(tokio::sync::mpsc::Receiver<Bytes>);

    impl Body for Channel {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
            self.0
                .poll_recv(cx)
                .map(|chunk| chunk.map(|c| Ok(Frame::data(c))))
        }
    }

    #[tokio::test]
    async fn a_lapsed_lease_ends_the_session() {
        let s = setup();
        let mine = claims(600);
        let mut body = s.f.snapshot_body(2, vec![]);
        body.lease_secs = 1;
        apply(
            &s.f.sign(&body),
            &s.f.keys,
            &s.handle,
            &s.changed,
            &s.metrics,
        )
        .unwrap();
        let end = timeout(
            Duration::from_secs(3),
            session_end(SessionWatch::new(
                s.changed.subscribe(),
                s.handle.clone(),
                &mine,
            )),
        )
        .await
        .unwrap();
        assert_eq!(end, SessionEnd::LeaseExpired);
    }

    /// Open traffic through a running data plane, cut by a revoking snapshot.
    mod through_the_proxy {
        use std::time::Instant as StdInstant;

        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use super::*;
        use crate::testing::{running, running_for};
        use crate::DataPlane;

        /// How long a revocation may take to cut open traffic once the
        /// snapshot carrying it is installed.
        const CUT_BOUND: Duration = Duration::from_secs(1);

        /// Reads until the other side closes; returns how long that took.
        async fn until_closed(mut stream: impl AsyncRead + Unpin) -> Duration {
            let started = StdInstant::now();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => return started.elapsed(),
                    Ok(Ok(_)) => {}
                    Err(_) => panic!("the connection was not cut"),
                }
            }
        }

        fn cuts(dp: &DataPlane) -> u64 {
            dp.metrics()
                .tunnels_cut_total
                .load(std::sync::atomic::Ordering::Relaxed)
        }

        #[tokio::test]
        async fn revoking_cuts_a_passthrough_tunnel_mid_transfer() {
            let r = running("api.example.com", vec![]).await;
            // An upstream that streams without end, like a large download.
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = upstream.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let (mut conn, _) = upstream.accept().await.unwrap();
                let chunk = vec![7u8; 16 * 1024];
                while conn.write_all(&chunk).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });

            let mut stream = r.tunnel(&target).await;
            let mut buf = vec![0u8; 64 * 1024];
            let mut received = 0;
            while received < 64 * 1024 {
                received += stream.read(&mut buf).await.unwrap();
            }

            r.installer.install(&r.snapshot(2, vec![r.jti])).unwrap();
            let took = until_closed(stream).await;
            assert!(took < CUT_BOUND, "cut took {took:?}");
            assert_eq!(cuts(&r.dp), 1);
            r.dp.shutdown();
        }

        #[tokio::test]
        async fn revoking_cuts_an_idle_intercepted_connection() {
            let r = running("api.example.com", vec![]).await;
            let tls = r
                .intercepted("api.example.com:443", "api.example.com")
                .await;
            // Kept alive with nothing in flight.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Another session's revocation leaves it open.
            r.installer
                .install(&r.snapshot(2, vec![SessionId::new()]))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(cuts(&r.dp), 0);

            r.installer.install(&r.snapshot(3, vec![r.jti])).unwrap();
            let took = until_closed(tls).await;
            assert!(took < CUT_BOUND, "cut took {took:?}");
            assert_eq!(cuts(&r.dp), 1);
            r.dp.shutdown();
        }

        /// `tokenless run` renews before expiry and keeps relaying tunnels
        /// it opened under the old session; they must not break.
        #[tokio::test]
        async fn a_passthrough_tunnel_outlives_its_sessions_expiry() {
            let r = running_for("api.example.com", vec![], 1).await;
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = upstream.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let (mut conn, _) = upstream.accept().await.unwrap();
                let chunk = vec![7u8; 1024];
                while conn.write_all(&chunk).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });
            let mut stream = r.tunnel(&target).await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let mut buf = vec![0u8; 64 * 1024];
            let mut after = 0;
            while after < 8 * 1024 {
                let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0, "the tunnel closed after the session expired");
                after += n;
            }
            assert_eq!(cuts(&r.dp), 0);
            r.dp.shutdown();
        }

        /// An idle intercepted connection closes at expiry, so the client
        /// reconnects with its current session instead of being refused on
        /// its next request. That is not a cut.
        #[tokio::test]
        async fn an_idle_intercepted_connection_closes_at_expiry() {
            let r = running_for("api.example.com", vec![], 2).await;
            let tls = r
                .intercepted("api.example.com:443", "api.example.com")
                .await;
            let took = until_closed(tls).await;
            assert!(took < Duration::from_secs(3), "closed after {took:?}");
            assert_eq!(cuts(&r.dp), 0);
            r.dp.shutdown();
        }

        #[tokio::test]
        async fn a_request_in_flight_at_expiry_gets_its_answer() {
            use rustls::pki_types::CertificateDer;
            use tokio_rustls::TlsAcceptor;

            use crate::tls::leaf_server_config;

            // An upstream that answers two seconds after each request.
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let root = CertificateDer::from(cert.cert.der().to_vec());
            let server = leaf_server_config(
                "localhost",
                vec![root.clone()],
                cert.signing_key.serialize_der(),
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = TlsAcceptor::from(server.clone());
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                            .await;
                    });
                }
            });

            let target = format!("localhost:{port}");
            let r = running_for(&target, vec![root], 1).await;
            let mut tls = r.intercepted(&target, "localhost").await;
            tls.write_all(format!("GET /slow HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            // The session expires while the upstream is still answering.
            let mut response = Vec::new();
            let mut buf = [0u8; 1024];
            while !response.ends_with(b"done") {
                let n = timeout(Duration::from_secs(5), tls.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    n > 0,
                    "closed before the answer: {:?}",
                    String::from_utf8_lossy(&response)
                );
                response.extend_from_slice(&buf[..n]);
            }
            assert!(response.starts_with(b"HTTP/1.1 200"));
            // Then the connection closes, with nothing cut.
            until_closed(tls).await;
            assert_eq!(cuts(&r.dp), 0);
            r.dp.shutdown();
        }
    }
}
