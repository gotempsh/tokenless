// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Redacting injected credentials from intercepted responses.
//!
//! An upstream may send back what it was sent: an echo endpoint, a token
//! check that returns its arguments, a debug route, an error page quoting
//! the request's headers. The client never holds the credential the proxy
//! injects, so a response carrying it back would hand it over. Every
//! intercepted response is scanned, headers and body, for the credential
//! material of the rule that served it, and each occurrence is overwritten.
//!
//! * What is looked for is built once per rule, when a snapshot is
//!   installed ([`Scrubber::for_rule`]): every header value as sent, the
//!   raw secrets behind it, a Basic `user:password` pair, and the base64 of
//!   each at every alignment. A character that encoders rewrite may appear
//!   as itself, percent-encoded, JSON-escaped (`\/`, `\uXXXX`) or as an
//!   HTML entity, in any mix.
//! * Bodies are streamed. Only bytes that could still begin a match are
//!   held back, never more than the longest encoded form, so a streaming
//!   response (SSE) waits only while its tail looks like the start of a
//!   credential.
//! * Redaction keeps the length (`[redacted]` padded with `*`), so
//!   `Content-Length` and the framing stay valid, and a response with
//!   nothing to redact is relayed byte for byte.
//! * What cannot be scanned is withheld, never relayed: the proxy asks for
//!   `identity` encoding and drops `Range` ([`prepare_request`]), and a
//!   compressed or partial response is refused ([`Withheld`]).
//!
//! Not covered: a credential the upstream transforms (hashes, truncates,
//! encrypts, or encodes in a way not listed above), or one an API lets the
//! client read back a piece at a time across several responses.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, IF_RANGE, RANGE, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokenless_core::ids::RuleId;
use tokenless_core::injection::InjectedHeaders;
use tracing::warn;
use zeroize::{Zeroize, Zeroizing};

use crate::metrics::Metrics;
use crate::proxy::{BodyError, ProxyBody};

/// Written over the start of each redacted occurrence; the rest of it is
/// filled with `*`, and one shorter than this is all `*`.
pub const REDACTED: &[u8] = b"[redacted]";
/// The longest encoded form of one credential the scanner holds back for.
/// Header values are at most 16 KiB and no character's widest encoding
/// is more than 12 bytes; this leaves room for both.
pub const MAX_PATTERN_BYTES: usize = 256 * 1024;
/// Forms tracked for one rule. A rule has a handful of headers and secrets,
/// each yielding a few forms; this is far above any real rule.
pub const MAX_PATTERNS: usize = 1024;
/// A secret shorter than this is not looked for on its own: it would match
/// ordinary text (a one-letter test token would redact every such letter),
/// and a credential that short protects nothing. The header value it was
/// sent in is still looked for when that is long enough.
pub const MIN_SECRET_LEN: usize = 6;
/// A base64 fragment shorter than this is not looked for on its own, for
/// the same reason.
const MIN_BASE64_CORE: usize = 8;

/// Why a rule's credential cannot be scanned for. The snapshot carrying it
/// is refused: the proxy never injects what it could not redact.
#[derive(Debug, thiserror::Error)]
pub enum ScrubberError {
    #[error(
        "an encoded form of the credential would be {bytes} bytes, more than the {MAX_PATTERN_BYTES} the response scanner holds back"
    )]
    TooLong { bytes: usize },
    #[error(
        "the credential has {count} encoded forms, more than the {MAX_PATTERNS} the response scanner tracks"
    )]
    TooMany { count: usize },
}

/// Why a response was withheld instead of relayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Withheld {
    #[error(
        "the upstream answered with a body in {coding} encoding although identity was requested, and a compressed body cannot be checked for the injected credential"
    )]
    Encoded { coding: &'static str },
    #[error(
        "the upstream answered 206 Partial Content although no range was requested, and a partial body cannot be checked for the injected credential"
    )]
    Partial,
}

/// One position of a pattern: the byte strings that may stand there.
struct Unit {
    alts: Vec<Box<[u8]>>,
}

/// One credential form, as a sequence of units.
struct Pattern {
    units: Vec<Unit>,
    max_len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct State {
    unit: u32,
    alt: u16,
    offset: u32,
}

/// Reused buffers for scanning, one per response.
#[derive(Default)]
pub struct Scratch {
    cur: Vec<State>,
    next: Vec<State>,
    matches: Vec<(usize, usize)>,
}

/// The credential forms of one rule, ready to scan responses for.
pub struct Scrubber {
    patterns: Vec<Pattern>,
    /// For each byte, the patterns that can begin with it.
    by_first: Vec<Vec<u16>>,
    max_len: usize,
}

impl std::fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scrubber")
            .field("patterns", &self.patterns.len())
            .field("max_len", &self.max_len)
            .finish_non_exhaustive()
    }
}

impl Drop for Scrubber {
    fn drop(&mut self) {
        for pattern in &mut self.patterns {
            for unit in &mut pattern.units {
                for alt in &mut unit.alts {
                    alt.as_mut().zeroize();
                }
            }
        }
    }
}

impl Default for Scrubber {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            by_first: vec![Vec::new(); 256],
            max_len: 0,
        }
    }
}

/// Unreserved in RFC 3986 and never rewritten by a JSON, HTML or URL
/// encoder: matched only as itself.
fn plain(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// Every form a character may take in a reflected response.
fn alternatives(c: char) -> Vec<Box<[u8]>> {
    let mut utf8 = [0u8; 4];
    let literal = c.encode_utf8(&mut utf8).as_bytes().to_vec();
    let mut alts: Vec<Vec<u8>> = vec![literal.clone()];
    if plain(c) {
        return alts.into_iter().map(Vec::into_boxed_slice).collect();
    }
    let percent = |upper: bool| -> Vec<u8> {
        literal
            .iter()
            .flat_map(|b| {
                if upper {
                    format!("%{b:02X}")
                } else {
                    format!("%{b:02x}")
                }
                .into_bytes()
            })
            .collect()
    };
    alts.push(percent(true));
    alts.push(percent(false));
    if c == ' ' {
        alts.push(b"+".to_vec());
    }
    let short = match c {
        '"' => Some(&br#"\""#[..]),
        '\\' => Some(&br"\\"[..]),
        '/' => Some(&br"\/"[..]),
        '\n' => Some(&br"\n"[..]),
        '\r' => Some(&br"\r"[..]),
        '\t' => Some(&br"\t"[..]),
        _ => None,
    };
    if let Some(short) = short {
        alts.push(short.to_vec());
    }
    let mut units = [0u16; 2];
    let units = c.encode_utf16(&mut units);
    alts.push(
        units
            .iter()
            .flat_map(|u| format!("\\u{u:04X}").into_bytes())
            .collect(),
    );
    alts.push(
        units
            .iter()
            .flat_map(|u| format!("\\u{u:04x}").into_bytes())
            .collect(),
    );
    let named = match c {
        '&' => Some("&amp;"),
        '<' => Some("&lt;"),
        '>' => Some("&gt;"),
        '"' => Some("&quot;"),
        '\'' => Some("&apos;"),
        _ => None,
    };
    if let Some(named) = named {
        alts.push(named.as_bytes().to_vec());
    }
    let code = u32::from(c);
    alts.push(format!("&#{code};").into_bytes());
    alts.push(format!("&#x{code:X};").into_bytes());
    alts.push(format!("&#x{code:x};").into_bytes());
    let mut unique: Vec<Box<[u8]>> = Vec::with_capacity(alts.len());
    for alt in alts {
        if !unique.iter().any(|u| **u == *alt) {
            unique.push(alt.into_boxed_slice());
        }
    }
    unique
}

impl Pattern {
    fn new(material: &str) -> Self {
        let mut units = Vec::new();
        let mut run = Vec::new();
        for c in material.chars() {
            if plain(c) {
                // Plain characters are ASCII: one byte each.
                run.push(c as u8);
                continue;
            }
            if !run.is_empty() {
                units.push(Unit {
                    alts: vec![std::mem::take(&mut run).into_boxed_slice()],
                });
            }
            units.push(Unit {
                alts: alternatives(c),
            });
        }
        if !run.is_empty() {
            units.push(Unit {
                alts: vec![run.into_boxed_slice()],
            });
        }
        let max_len = units
            .iter()
            .map(|u| u.alts.iter().map(|a| a.len()).max().unwrap_or(0))
            .sum();
        Self { units, max_len }
    }

    /// Runs the pattern from the start of `hay`. Returns the length of the
    /// longest complete match, and whether a longer one could still follow
    /// were `hay` to continue.
    fn run(&self, hay: &[u8], scratch: &mut Scratch) -> (Option<usize>, bool) {
        let Scratch { cur, next, .. } = scratch;
        cur.clear();
        let Some(first) = self.units.first() else {
            return (None, false);
        };
        for alt in 0..first.alts.len() {
            cur.push(State {
                unit: 0,
                alt: alt as u16,
                offset: 0,
            });
        }
        let mut full = None;
        for (i, &byte) in hay.iter().enumerate() {
            next.clear();
            for state in cur.iter() {
                let unit = state.unit as usize;
                let alt = &self.units[unit].alts[state.alt as usize];
                let offset = state.offset as usize;
                if alt.get(offset) != Some(&byte) {
                    continue;
                }
                if offset + 1 < alt.len() {
                    push_unique(
                        next,
                        State {
                            offset: state.offset + 1,
                            ..*state
                        },
                    );
                } else if unit + 1 == self.units.len() {
                    full = Some(i + 1);
                } else {
                    for alt in 0..self.units[unit + 1].alts.len() {
                        push_unique(
                            next,
                            State {
                                unit: state.unit + 1,
                                alt: alt as u16,
                                offset: 0,
                            },
                        );
                    }
                }
            }
            std::mem::swap(cur, next);
            if cur.is_empty() {
                return (full, false);
            }
        }
        (full, true)
    }
}

fn push_unique(states: &mut Vec<State>, state: State) {
    if !states.contains(&state) {
        states.push(state);
    }
}

fn push_material(materials: &mut Vec<Zeroizing<String>>, value: &str) {
    if value.len() >= MIN_SECRET_LEN && !materials.iter().any(|m| m.as_str() == value) {
        materials.push(Zeroizing::new(value.to_string()));
    }
}

/// What a header value as sent gives away beyond itself: the credential
/// after an auth scheme (`Bearer <token>`), and for `Basic` the decoded
/// `user:password` pair and the password. This covers a control plane that
/// does not list the raw secrets itself.
fn derive_from_header(value: &str, materials: &mut Vec<Zeroizing<String>>) {
    let Some((scheme, rest)) = value.split_once(' ') else {
        return;
    };
    let rest = rest.trim();
    if scheme.is_empty() || rest.is_empty() || !scheme.bytes().all(|b| b.is_ascii_graphic()) {
        return;
    }
    push_material(materials, rest);
    if !scheme.eq_ignore_ascii_case("basic") {
        return;
    }
    let Ok(decoded) = STANDARD.decode(rest).map(Zeroizing::new) else {
        return;
    };
    let Ok(pair) = std::str::from_utf8(&decoded) else {
        return;
    };
    if let Some((_, password)) = pair.split_once(':') {
        push_material(materials, pair);
        push_material(materials, password);
    }
}

/// The base64 fragments that appear wherever `value` is base64-encoded
/// inside a larger payload, at each of the three alignments, in the
/// standard and the URL-safe alphabet. Groups that would also encode
/// neighbouring bytes are dropped.
fn base64_cores(value: &str, materials: &mut Vec<Zeroizing<String>>) {
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for shift in 0..3 {
            let mut input = Zeroizing::new(vec![0u8; shift]);
            input.extend_from_slice(value.as_bytes());
            let encoded = Zeroizing::new(engine.encode(input.as_slice()));
            let start = if shift == 0 { 0 } else { 4 };
            let end = 4 * (input.len() / 3);
            if end > start && end - start >= MIN_BASE64_CORE {
                if let Some(core) = encoded.get(start..end) {
                    push_material(materials, core);
                }
            }
        }
    }
}

impl Scrubber {
    /// Everything a response must not carry for a rule whose sealed
    /// headers are `headers`: each header value not marked `fixed`, what
    /// those values give away ([`derive_from_header`]), the raw secrets the
    /// control plane lists, and the values of its substitutions.
    pub fn for_rule(headers: &InjectedHeaders) -> Result<Self, ScrubberError> {
        let mut materials = Vec::new();
        for header in headers.headers.iter().filter(|h| !h.fixed) {
            push_material(&mut materials, &header.value);
            derive_from_header(&header.value, &mut materials);
        }
        for secret in &headers.secrets {
            push_material(&mut materials, secret.expose());
        }
        for substitution in &headers.substitutions {
            push_material(&mut materials, &substitution.value);
        }
        let direct = materials.len();
        for i in 0..direct {
            let value = Zeroizing::new(materials[i].to_string());
            base64_cores(&value, &mut materials);
        }
        Self::from_materials(materials.iter().map(|m| m.as_str()))
    }

    /// A scrubber for these strings and their encodings; one shorter than
    /// [`MIN_SECRET_LEN`] is skipped.
    pub fn from_materials<'a>(
        materials: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ScrubberError> {
        let mut scrubber = Self::default();
        for material in materials {
            if material.len() < MIN_SECRET_LEN {
                continue;
            }
            let pattern = Pattern::new(material);
            if pattern.max_len > MAX_PATTERN_BYTES {
                return Err(ScrubberError::TooLong {
                    bytes: pattern.max_len,
                });
            }
            let index = u16::try_from(scrubber.patterns.len())
                .ok()
                .filter(|i| usize::from(*i) < MAX_PATTERNS)
                .ok_or(ScrubberError::TooMany {
                    count: scrubber.patterns.len() + 1,
                })?;
            if let Some(first) = pattern.units.first() {
                for alt in &first.alts {
                    if let Some(&byte) = alt.first() {
                        let list = &mut scrubber.by_first[usize::from(byte)];
                        if !list.contains(&index) {
                            list.push(index);
                        }
                    }
                }
            }
            scrubber.max_len = scrubber.max_len.max(pattern.max_len);
            scrubber.patterns.push(pattern);
        }
        Ok(scrubber)
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The most bytes a scan may hold back while waiting for more input.
    pub fn max_holdback(&self) -> usize {
        self.max_len.saturating_sub(1)
    }

    /// Finds the occurrences in `hay` (into `scratch.matches`, in order,
    /// not overlapping) and returns how much of `hay` is settled. Unless
    /// `at_end`, the rest may still begin an occurrence and must be scanned
    /// again with what follows.
    fn scan(&self, hay: &[u8], at_end: bool, scratch: &mut Scratch) -> usize {
        scratch.matches.clear();
        let mut pos = 0;
        while pos < hay.len() {
            let candidates = &self.by_first[usize::from(hay[pos])];
            if candidates.is_empty() {
                pos += 1;
                continue;
            }
            let mut longest = None;
            let mut open = false;
            for &index in candidates {
                let (full, more) = self.patterns[usize::from(index)].run(&hay[pos..], scratch);
                longest = longest.max(full);
                open |= more;
            }
            if open && !at_end {
                return pos;
            }
            match longest {
                Some(len) => {
                    scratch.matches.push((pos, pos + len));
                    pos += len;
                }
                None => pos += 1,
            }
        }
        hay.len()
    }

    /// Redacts every occurrence in a complete value, in place. Returns how
    /// many there were.
    pub fn redact_all(&self, value: &mut [u8], scratch: &mut Scratch) -> usize {
        self.scan(value, true, scratch);
        redact(value, &scratch.matches)
    }

    /// Redacts header values in place, and drops a header whose name
    /// carries the credential. Returns how many occurrences there were.
    pub fn redact_headers(&self, headers: &mut HeaderMap, scratch: &mut Scratch) -> usize {
        let mut count = 0;
        let mut doomed: Vec<HeaderName> = Vec::new();
        for name in headers.keys() {
            self.scan(name.as_str().as_bytes(), true, scratch);
            if !scratch.matches.is_empty() {
                count += scratch.matches.len();
                doomed.push(name.clone());
            }
        }
        for name in doomed {
            headers.remove(name);
        }
        for value in headers.values_mut() {
            self.scan(value.as_bytes(), true, scratch);
            if scratch.matches.is_empty() {
                continue;
            }
            let mut bytes = Zeroizing::new(value.as_bytes().to_vec());
            count += redact(&mut bytes, &scratch.matches);
            // Redaction writes printable ASCII over bytes of a valid value,
            // so the result is valid too; the fallback is never reached.
            let mut redacted = HeaderValue::from_bytes(&bytes)
                .unwrap_or_else(|_| HeaderValue::from_static("[redacted]"));
            redacted.set_sensitive(value.is_sensitive());
            *value = redacted;
        }
        count
    }
}

fn redact(buf: &mut [u8], matches: &[(usize, usize)]) -> usize {
    for &(start, end) in matches {
        if let Some(target) = buf.get_mut(start..end) {
            let marker = if target.len() >= REDACTED.len() {
                REDACTED
            } else {
                &[]
            };
            for (i, byte) in target.iter_mut().enumerate() {
                *byte = marker.get(i).copied().unwrap_or(b'*');
            }
        }
    }
    matches.len()
}

/// Makes the upstream answer in a form the scanner can read: identity
/// encoding, and the whole body rather than a range of it (a client
/// fetching a reflected credential a few bytes at a time would see no
/// complete occurrence to redact).
pub fn prepare_request(headers: &mut HeaderMap) {
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.remove(RANGE);
    headers.remove(IF_RANGE);
}

/// Content and transfer codings the scanner cannot read. Only known names
/// are reported: the header's own text is the upstream's and may carry
/// the very value being withheld.
fn coding_name(token: &str) -> &'static str {
    const KNOWN: &[&str] = &["gzip", "x-gzip", "deflate", "br", "zstd", "compress"];
    KNOWN
        .iter()
        .find(|known| token.eq_ignore_ascii_case(known))
        .copied()
        .unwrap_or("an unrecognised")
}

/// Whether a response must be withheld rather than scanned.
pub fn withhold(status: StatusCode, headers: &HeaderMap) -> Option<Withheld> {
    if status == StatusCode::PARTIAL_CONTENT {
        return Some(Withheld::Partial);
    }
    let codings = |name: HeaderName, allowed: &'static [&'static str]| {
        headers
            .get_all(name)
            .iter()
            .flat_map(|v| v.to_str().unwrap_or("\u{0}").split(','))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .find(|t| !allowed.iter().any(|a| t.eq_ignore_ascii_case(a)))
            .map(coding_name)
    };
    codings(CONTENT_ENCODING, &["identity"])
        .or_else(|| codings(TRANSFER_ENCODING, &["identity", "chunked"]))
        .map(|coding| Withheld::Encoded { coding })
}

/// Counts redactions and logs the first in a response. Never logs what
/// was redacted.
pub struct Redactions {
    metrics: Arc<Metrics>,
    rule_id: RuleId,
    host: String,
    logged: bool,
}

impl Redactions {
    pub fn new(metrics: Arc<Metrics>, rule_id: RuleId, host: String) -> Self {
        Self {
            metrics,
            rule_id,
            host,
            logged: false,
        }
    }

    fn record(&mut self, count: usize, location: &'static str) {
        if count == 0 {
            return;
        }
        Metrics::add(&self.metrics.credentials_redacted_total, count as u64);
        if !self.logged {
            self.logged = true;
            warn!(
                rule_id = %self.rule_id,
                host = %self.host,
                location,
                count,
                "redacted the injected credential from an upstream response that reflected it"
            );
        }
    }
}

/// Refuses a response that cannot be scanned, redacts its headers, and
/// wraps its body so every frame is redacted before it is relayed.
pub fn scrub_response(
    response: Response<ProxyBody>,
    scrubber: Arc<Scrubber>,
    mut redactions: Redactions,
) -> Result<Response<ProxyBody>, Withheld> {
    if let Some(withheld) = withhold(response.status(), response.headers()) {
        return Err(withheld);
    }
    let (mut parts, body) = response.into_parts();
    let mut scratch = Scratch::default();
    let count = scrubber.redact_headers(&mut parts.headers, &mut scratch);
    redactions.record(count, "headers");
    let body = ScrubBody {
        inner: body,
        scrubber,
        scratch,
        held: BytesMut::new(),
        trailers: None,
        ended: false,
        redactions,
    };
    Ok(Response::from_parts(parts, body.boxed()))
}

/// A response body relayed with the credential redacted. Holds back at
/// most [`Scrubber::max_holdback`] bytes; data the upstream ends or fails
/// on while still held back is never relayed unscanned.
pub struct ScrubBody {
    inner: ProxyBody,
    scrubber: Arc<Scrubber>,
    scratch: Scratch,
    held: BytesMut,
    trailers: Option<HeaderMap>,
    ended: bool,
    redactions: Redactions,
}

impl ScrubBody {
    /// Scans what is held and releases what is settled.
    fn release(&mut self, at_end: bool) -> Bytes {
        let settled = self.scrubber.scan(&self.held, at_end, &mut self.scratch);
        let count = redact(&mut self.held[..settled], &self.scratch.matches);
        self.redactions.record(count, "body");
        self.held.split_to(settled).freeze()
    }

    /// Takes one data frame. With nothing held and nothing to redact the
    /// frame is passed on as it is, without a copy.
    fn take(&mut self, data: Bytes) -> Bytes {
        if self.held.is_empty() {
            let settled = self.scrubber.scan(&data, false, &mut self.scratch);
            if self.scratch.matches.is_empty() {
                if settled < data.len() {
                    self.held.extend_from_slice(&data[settled..]);
                }
                return data.slice(..settled);
            }
        }
        self.held.extend_from_slice(&data);
        self.release(false)
    }
}

impl Body for ScrubBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        loop {
            if this.ended {
                if !this.held.is_empty() {
                    let out = this.release(true);
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.ended = true;
                    continue;
                }
                Poll::Ready(Some(Err(error))) => {
                    // What is held may be the start of the credential.
                    this.held.as_mut().zeroize();
                    this.held.clear();
                    this.ended = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(frame))) => frame,
            };
            match frame.into_data() {
                Ok(data) => {
                    let out = this.take(data);
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(out))));
                    }
                }
                Err(frame) => {
                    if let Ok(mut trailers) = frame.into_trailers() {
                        let count = this
                            .scrubber
                            .redact_headers(&mut trailers, &mut this.scratch);
                        this.redactions.record(count, "trailers");
                        this.trailers = Some(trailers);
                        this.ended = true;
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.held.is_empty()
            && self.trailers.is_none()
            && (self.ended || self.inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        // Redaction keeps lengths, so what is left is what is held plus
        // what the upstream has yet to send.
        let inner = self.inner.size_hint();
        let held = self.held.len() as u64;
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(held));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(held));
        }
        hint
    }
}

#[cfg(test)]
mod tests;
