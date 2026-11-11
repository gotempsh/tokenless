// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Masking a service's secrets in the responses to the requests the proxy
//! added them to, so an API that echoes the credential back (a debug
//! endpoint, an error that quotes the request, a key-introspection call)
//! does not hand it to the agent.
//!
//! Every byte of a secret becomes `*`, so lengths, and `Content-Length`,
//! stay as they were. Headers are always checked. A body is checked when
//! it is text (or says nothing of its type) and not compressed, for its
//! first [`MAX_SCRUB_BODY`] bytes; the rest passes through unread.
//!
//! Load: this runs on responses to requests that carried a credential.
//! One Aho-Corasick pass per frame over the frame and the last
//! (longest secret - 1) bytes of the one before, held back in case a
//! secret is split between them; nothing else is buffered or copied.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use hyper::body::{Body, Frame, SizeHint};

use crate::error::DataPlaneError;
use crate::proxy::{BodyError, ProxyBody};

/// Bytes of a body checked; the rest passes through unread.
pub const MAX_SCRUB_BODY: u64 = 8 * 1024 * 1024;

/// A rule's secrets, ready to find.
pub struct Scrubber {
    matcher: AhoCorasick,
    longest: usize,
}

impl Scrubber {
    pub fn build(values: &[String]) -> Result<Option<Arc<Self>>, DataPlaneError> {
        let Some(longest) = values.iter().map(String::len).max() else {
            return Ok(None);
        };
        let matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(values)
            .map_err(|e| {
                DataPlaneError::rejected(format!("a rule's secrets cannot be matched: {e}"))
            })?;
        Ok(Some(Arc::new(Self { matcher, longest })))
    }

    /// Masks every secret in `buf`; how many there were.
    pub fn mask(&self, buf: &mut [u8]) -> usize {
        let found: Vec<(usize, usize)> = self
            .matcher
            .find_iter(&*buf)
            .map(|m| (m.start(), m.end()))
            .collect();
        for &(start, end) in &found {
            buf[start..end].fill(b'*');
        }
        found.len()
    }

    /// Masks the secrets in every header value; how many there were.
    pub fn mask_headers(&self, headers: &mut HeaderMap) -> usize {
        let mut count = 0;
        for value in headers.values_mut() {
            if !self.matcher.is_match(value.as_bytes()) {
                continue;
            }
            let mut bytes = value.as_bytes().to_vec();
            count += self.mask(&mut bytes);
            // Only ASCII '*' replaced bytes, so it is still a valid value.
            if let Ok(masked) = HeaderValue::from_bytes(&bytes) {
                *value = masked;
            }
        }
        count
    }
}

/// Why a response body is not checked, if it is not.
pub fn body_skipped(headers: &HeaderMap) -> Option<String> {
    let encoding = headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty() && v != "identity");
    if let Some(encoding) = encoding {
        return Some(format!("compressed ({encoding})"));
    }
    let kind = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase());
    match kind {
        Some(kind) if !is_text(&kind) => Some("not text".into()),
        _ => None,
    }
}

fn is_text(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("").trim();
    essence.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "x-www-form-urlencoded",
            "graphql",
            "yaml",
            "ndjson",
        ]
        .iter()
        .any(|t| essence.contains(t))
}

/// What a body found, once it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scrubbed {
    pub masked: usize,
    /// Whether it went past [`MAX_SCRUB_BODY`], so its end was not read.
    pub truncated: bool,
}

/// A response body with the rule's secrets masked as it streams.
pub(crate) struct ScrubBody {
    inner: ProxyBody,
    scrubber: Arc<Scrubber>,
    /// Read but not yet passed on: the tail a secret may continue from.
    held: BytesMut,
    read: u64,
    masked: usize,
    truncated: bool,
    /// A trailers frame that waits for `held` to go first.
    trailers: Option<Frame<Bytes>>,
    ended: bool,
    on_end: Option<Box<dyn FnOnce(Scrubbed) + Send + Sync>>,
}

impl ScrubBody {
    pub fn wrap(
        inner: ProxyBody,
        scrubber: Arc<Scrubber>,
        on_end: impl FnOnce(Scrubbed) + Send + Sync + 'static,
    ) -> ProxyBody {
        http_body_util::BodyExt::boxed(Self {
            inner,
            scrubber,
            held: BytesMut::new(),
            read: 0,
            masked: 0,
            truncated: false,
            trailers: None,
            ended: false,
            on_end: Some(Box::new(on_end)),
        })
    }

    fn finish(&mut self) {
        if let Some(on_end) = self.on_end.take() {
            on_end(Scrubbed {
                masked: self.masked,
                truncated: self.truncated,
            });
        }
    }

    /// The next bytes to pass on from `data`, if any yet.
    fn take(&mut self, data: Bytes) -> Option<Bytes> {
        if self.truncated {
            return Some(data);
        }
        self.read = self.read.saturating_add(data.len() as u64);
        self.held.extend_from_slice(&data);
        self.masked += self.scrubber.mask(&mut self.held);
        if self.read >= MAX_SCRUB_BODY {
            self.truncated = true;
            return Some(self.held.split().freeze());
        }
        let keep = (self.scrubber.longest - 1).min(self.held.len());
        let out = self.held.split_to(self.held.len() - keep);
        (!out.is_empty()).then(|| out.freeze())
    }
}

impl Body for ScrubBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        loop {
            if self.ended {
                if !self.held.is_empty() {
                    let rest = self.held.split().freeze();
                    return Poll::Ready(Some(Ok(Frame::data(rest))));
                }
                if let Some(trailers) = self.trailers.take() {
                    return Poll::Ready(Some(Ok(trailers)));
                }
                self.finish();
                return Poll::Ready(None);
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => self.ended = true,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if let Some(out) = self.take(data) {
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                    Err(trailers) => {
                        self.trailers = Some(trailers);
                        self.ended = true;
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.held.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        // Masking keeps every length, so the inner body's hint still holds
        // for what is left, held bytes included.
        let inner = self.inner.size_hint();
        let held = self.held.len() as u64;
        let mut hint = SizeHint::new();
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(held));
        }
        hint.set_lower(inner.lower().saturating_add(held));
        hint
    }
}

impl Drop for ScrubBody {
    fn drop(&mut self) {
        // A reader that stopped early still gets the count so far.
        self.finish();
    }
}

#[cfg(test)]
mod tests;
