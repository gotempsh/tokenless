// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::VecDeque;
use std::sync::Mutex;

use http_body_util::BodyExt;

use super::*;

const SECRET: &str = "sk-live-0123456789abcdef";

fn scrubber() -> Arc<Scrubber> {
    Scrubber::build(&[SECRET.to_string(), "Bearer sk-live-0123456789abcdef".into()])
        .unwrap()
        .unwrap()
}

/// A body that yields `chunks` one frame at a time.
struct Chunks(VecDeque<Bytes>);

impl Body for Chunks {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready(self.0.pop_front().map(|c| Ok(Frame::data(c))))
    }
}

fn chunked(chunks: Vec<Vec<u8>>) -> ProxyBody {
    Chunks(chunks.into_iter().map(Bytes::from).collect()).boxed()
}

async fn scrub(chunks: Vec<Vec<u8>>) -> (Vec<u8>, Scrubbed) {
    let done = Arc::new(Mutex::new(None));
    let seen = done.clone();
    let body = ScrubBody::wrap(chunked(chunks), scrubber(), move |s| {
        *seen.lock().unwrap() = Some(s);
    });
    let out = body.collect().await.unwrap().to_bytes().to_vec();
    let result = done.lock().unwrap().take().expect("reported once it ended");
    (out, result)
}

#[tokio::test]
async fn a_secret_split_across_chunks_is_masked_and_lengths_kept() {
    let text = format!(r#"{{"echo":"Bearer {SECRET}","again":"{SECRET}"}}"#);
    let bytes = text.as_bytes().to_vec();
    // Split everywhere a secret could be cut, one byte at a time too.
    for size in [1, 3, 7, 16, bytes.len()] {
        let chunks: Vec<Vec<u8>> = bytes.chunks(size).map(<[u8]>::to_vec).collect();
        let (out, done) = scrub(chunks).await;
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.len(), text.len(), "chunks of {size}");
        assert!(!out.contains("sk-live"), "chunks of {size}: {out}");
        assert_eq!(
            done,
            Scrubbed {
                masked: 2,
                truncated: false
            },
            "chunks of {size}"
        );
        assert!(out.starts_with(r#"{"echo":"*****"#), "{out}");
    }
}

#[tokio::test]
async fn a_body_without_secrets_is_untouched_and_reports_none() {
    let (out, done) = scrub(vec![b"plain ".to_vec(), b"answer".to_vec()]).await;
    assert_eq!(out, b"plain answer");
    assert_eq!(done.masked, 0);
}

#[tokio::test]
async fn past_the_limit_the_rest_passes_through_unread() {
    let big = vec![b'a'; usize::try_from(MAX_SCRUB_BODY).unwrap()];
    let (out, done) = scrub(vec![big, SECRET.as_bytes().to_vec()]).await;
    assert!(out.ends_with(SECRET.as_bytes()), "not read after the limit");
    assert!(done.truncated && done.masked == 0, "{done:?}");
}

#[test]
fn headers_are_masked_in_place() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-echo",
        HeaderValue::from_str(&format!("got {SECRET}")).unwrap(),
    );
    headers.insert("x-other", HeaderValue::from_static("fine"));
    assert_eq!(scrubber().mask_headers(&mut headers), 1);
    assert_eq!(
        headers["x-echo"],
        format!("got {}", "*".repeat(SECRET.len())).as_str()
    );
    assert_eq!(headers["x-other"], "fine");
}

#[test]
fn only_uncompressed_text_bodies_are_read() {
    let with = |pairs: &[(&'static str, &'static str)]| {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        body_skipped(&h)
    };
    assert_eq!(
        with(&[("content-type", "application/json; charset=utf-8")]),
        None
    );
    assert_eq!(with(&[("content-type", "text/event-stream")]), None);
    assert_eq!(with(&[("content-type", "application/problem+json")]), None);
    assert_eq!(with(&[]), None, "an untyped body may be text");
    assert_eq!(
        with(&[
            ("content-type", "application/json"),
            ("content-encoding", "gzip")
        ]),
        Some("compressed (gzip)".into())
    );
    assert_eq!(
        with(&[("content-type", "image/png")]),
        Some("not text".into())
    );
    assert_eq!(with(&[("content-encoding", "identity")]), None);
}

#[test]
fn no_secrets_no_scrubber() {
    assert!(Scrubber::build(&[]).unwrap().is_none());
}

mod through_the_proxy {
    use std::sync::atomic::Ordering;

    use tokenless_core::audit::AuditEvent;
    use tokenless_core::egress::EgressPolicy;
    use tokenless_core::scope::Scope;
    use tokenless_core::snapshot::SCRUBBED_ACTION;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::audit::AuditShipper;
    use crate::testing::{https_echo_authorization_upstream, running_with, Running};

    #[derive(Default)]
    struct Collect(Mutex<Vec<AuditEvent>>);

    #[async_trait::async_trait]
    impl AuditShipper for Collect {
        async fn ship(&self, events: &[AuditEvent]) -> Result<(), crate::DataPlaneError> {
            self.0.lock().unwrap().extend_from_slice(events);
            Ok(())
        }
    }

    fn install(r: &Running, version: u64, scrub: bool) {
        let mut body = r.f.snapshot_body(
            version,
            vec![(r.rule, Scope::parse("vault:test").unwrap(), &r.host, SECRET)],
        );
        body.egress = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        body.scrub_responses = scrub;
        r.installer.install(&r.f.sign(&body)).unwrap();
    }

    async fn echoed(r: &Running, target: &str) -> String {
        let mut tls = r.intercepted(target, "localhost").await;
        tls.write_all(
            format!("GET /whoami HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut answer = Vec::new();
        let _ = tls.read_to_end(&mut answer).await;
        String::from_utf8_lossy(&answer).into_owned()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_echoed_credential_reaches_the_agent_masked_and_is_recorded() {
        let (port, root) = https_echo_authorization_upstream().await;
        let target = format!("localhost:{port}");
        let audit = Arc::new(Collect::default());
        let r = running_with(&target, vec![root], 600, audit.clone()).await;

        install(&r, 2, true);
        let answer = echoed(&r, &target).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        // The fixture seals the token alone; a real rule seals the whole
        // header value too.
        let masked = format!("Bearer {}", "*".repeat(SECRET.len()));
        assert!(answer.ends_with(&masked), "{answer}");
        assert!(!answer.contains(SECRET), "{answer}");
        let mut reports = Vec::new();
        for _ in 0..100 {
            reports = audit
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.action == SCRUBBED_ACTION)
                .cloned()
                .collect();
            if !reports.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].detail["masked"], "1");
        assert!(reports[0].detail.values().all(|v| !v.contains(SECRET)));
        assert_eq!(
            r.dp.metrics()
                .responses_scrubbed_total
                .load(Ordering::Relaxed),
            1
        );

        // Turned off, the answer is passed on as it came.
        install(&r, 3, false);
        let answer = echoed(&r, &target).await;
        assert!(answer.ends_with(&format!("Bearer {SECRET}")), "{answer}");
    }
}
