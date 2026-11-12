// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, VecDeque};

use tokenless_core::injection::{InjectedHeader, InjectionSpec, SecretFields, SecretMaterial};

use super::*;

const BEARER: &str = "xoxb-test-0000";
const KEY: &str = "test+key/0000=";
const TOKEN: &str = "ghp_test0000aaaa";
const USER: &str = "test-user";
const PASSWORD: &str = "test-pass/0000";

fn rendered(spec: InjectionSpec, pairs: &[(&str, &str)]) -> InjectedHeaders {
    let fields = SecretFields::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
    );
    spec.render("test", &fields).unwrap()
}

fn bearer() -> InjectedHeaders {
    rendered(
        InjectionSpec::Bearer {
            field: "token".into(),
        },
        &[("token", BEARER)],
    )
}

fn header() -> InjectedHeaders {
    rendered(
        InjectionSpec::Header {
            name: "X-Api-Key".into(),
            field: "key".into(),
            prefix: Some("key=".into()),
        },
        &[("key", KEY)],
    )
}

fn basic_token() -> InjectedHeaders {
    rendered(
        InjectionSpec::BasicToken {
            username: "x-access-token".into(),
            password_field: "token".into(),
        },
        &[("token", TOKEN)],
    )
}

fn basic() -> InjectedHeaders {
    rendered(
        InjectionSpec::Basic {
            username_field: "user".into(),
            password_field: "pass".into(),
        },
        &[("user", USER), ("pass", PASSWORD)],
    )
}

fn scrubber(headers: &InjectedHeaders) -> Arc<Scrubber> {
    Arc::new(Scrubber::for_rule(headers).unwrap())
}

fn redacted(scrubber: &Scrubber, input: &str) -> (String, usize) {
    let mut bytes = input.as_bytes().to_vec();
    let count = scrubber.redact_all(&mut bytes, &mut Scratch::default());
    (String::from_utf8(bytes).unwrap(), count)
}

fn percent(value: &str, upper: bool) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else if upper {
                format!("%{b:02X}")
            } else {
                format!("%{b:02x}")
            }
        })
        .collect()
}

/// `value` base64-encoded inside a larger payload, at alignment `shift`.
fn embedded_base64(value: &str, shift: usize, engine: &impl Engine) -> String {
    let mut payload = b"lead".repeat(3)[..shift + 3].to_vec();
    payload.extend_from_slice(value.as_bytes());
    payload.extend_from_slice(b" and the rest of it");
    engine.encode(payload)
}

/// Every form `secret` may be reflected in.
fn reflections(secret: &str) -> Vec<String> {
    let mut forms = vec![
        secret.to_string(),
        percent(secret, true),
        percent(secret, false),
        serde_json::to_string(secret)
            .unwrap()
            .trim_matches('"')
            .to_string(),
        secret.replace('/', r"\/"),
        secret
            .chars()
            .map(|c| {
                if plain(c) {
                    c.to_string()
                } else {
                    format!("\\u{:04X}", u32::from(c))
                }
            })
            .collect(),
        secret
            .chars()
            .map(|c| {
                if plain(c) {
                    c.to_string()
                } else {
                    format!("&#x{:X};", u32::from(c))
                }
            })
            .collect(),
    ];
    for shift in 0..3 {
        forms.push(embedded_base64(secret, shift, &STANDARD));
        forms.push(embedded_base64(secret, shift, &URL_SAFE_NO_PAD));
    }
    forms.sort();
    forms.dedup();
    forms
}

/// Each form is found and overwritten, the surrounding bytes stay, the
/// length is unchanged, and no form of `secret` remains.
fn assert_never_survives(scrubber: &Scrubber, secret: &str) {
    for form in reflections(secret) {
        let input = format!("{{\"echo\":\"{form}\",\"ok\":true}}");
        let (output, count) = redacted(scrubber, &input);
        assert!(count >= 1, "{form} was not found");
        assert_eq!(output.len(), input.len(), "{form}");
        assert!(output.starts_with("{\"echo\":\""), "{output}");
        assert!(output.ends_with("\",\"ok\":true}"), "{output}");
        for other in reflections(secret) {
            assert!(!output.contains(&other), "{other} survived in {output}");
        }
    }
}

#[test]
fn every_delivery_format_is_redacted_in_every_form_it_is_reflected_in() {
    let s = scrubber(&bearer());
    assert_never_survives(&s, BEARER);
    assert_never_survives(&s, &format!("Bearer {BEARER}"));

    let s = scrubber(&header());
    assert_never_survives(&s, KEY);
    assert_never_survives(&s, &format!("key={KEY}"));

    let s = scrubber(&basic_token());
    let pair = format!("x-access-token:{TOKEN}");
    assert_never_survives(&s, TOKEN);
    assert_never_survives(&s, &pair);
    assert_never_survives(&s, &format!("Basic {}", STANDARD.encode(&pair)));

    let s = scrubber(&basic());
    let pair = format!("{USER}:{PASSWORD}");
    assert_never_survives(&s, PASSWORD);
    assert_never_survives(&s, &pair);
    assert_never_survives(&s, &format!("Basic {}", STANDARD.encode(&pair)));
}

#[test]
fn an_older_control_plane_without_listed_secrets_is_still_covered() {
    for (rendered, raw) in [
        (bearer(), BEARER),
        (basic_token(), TOKEN),
        (basic(), PASSWORD),
    ] {
        let headers = InjectedHeaders {
            headers: rendered.headers.clone(),
            substitutions: vec![],
            secrets: vec![],
        };
        assert_never_survives(&scrubber(&headers), raw);
    }
}

#[test]
fn a_mix_of_encodings_within_one_occurrence_is_redacted() {
    let s = scrubber(&header());
    for mixed in [
        r"test+key\/0000%3D",
        "test%2bkey&#47;0000&#x3d;",
        r"test+key/0000=",
    ] {
        let (output, count) = redacted(&s, &format!("x {mixed} y"));
        assert_eq!(count, 1, "{mixed}");
        assert!(!output.contains("0000"), "{output}");
    }
}

#[test]
fn substitution_values_and_variable_secrets_are_redacted() {
    let mut headers = InjectedHeaders {
        headers: vec![InjectedHeader::credential(
            "x-org",
            "org-var-secret-0000".into(),
        )],
        substitutions: vec![],
        secrets: vec![SecretMaterial::new("var-secret-0000")],
    };
    headers.substitutions = serde_json::from_str(
        r#"[{"placeholder":"PLACEHOLDER","value":"sub-secret-0000","locations":["body"]}]"#,
    )
    .unwrap();
    let s = scrubber(&headers);
    assert_never_survives(&s, "var-secret-0000");
    assert_never_survives(&s, "sub-secret-0000");
}

#[test]
fn fixed_headers_and_short_values_are_not_redacted() {
    let headers = InjectedHeaders {
        headers: vec![
            InjectedHeader::credential("authorization", format!("Bearer {BEARER}")),
            InjectedHeader::fixed("accept", "application/vnd.test+json".into()),
            InjectedHeader::fixed("x-api-version", "2024-01-01".into()),
        ],
        substitutions: vec![],
        secrets: vec![],
    };
    let s = scrubber(&headers);
    let body = "content-type: application/vnd.test+json; version 2024-01-01";
    assert_eq!(redacted(&s, body), (body.to_string(), 0));

    // `Bearer t`: the header value is looked for; a one-letter token on
    // its own is not, or every `t` would go.
    let s = scrubber(&InjectedHeaders {
        headers: vec![InjectedHeader::credential(
            "authorization",
            "Bearer t".into(),
        )],
        substitutions: vec![],
        secrets: vec![],
    });
    assert_eq!(redacted(&s, "text/plain"), ("text/plain".into(), 0));
    assert_eq!(redacted(&s, "a Bearer t b").0, "a ******** b");
}

#[test]
fn normal_responses_are_untouched_byte_for_byte() {
    let s = scrubber(&basic_token());
    let mut body = String::new();
    for i in 0..200 {
        body.push_str(&format!(
            "{{\"id\":{i},\"name\":\"xoxb-test-000\",\"note\":\"ghp_test0000aaa / x-access-token\"}}\n"
        ));
    }
    assert_eq!(redacted(&s, &body), (body.clone(), 0));
}

#[test]
fn redaction_keeps_the_length_and_marks_what_it_replaced() {
    let s = scrubber(&bearer());
    let (output, count) = redacted(&s, &format!("{BEARER}{BEARER}|{BEARER}"));
    assert_eq!(count, 3);
    assert_eq!(output, "[redacted]****[redacted]****|[redacted]****");
    let s = Scrubber::from_materials(["abcdef12"]).unwrap();
    assert_eq!(redacted(&s, "<abcdef12>").0, "<********>");
}

/// A body that yields its frames, then ends.
struct Frames(VecDeque<Result<Frame<Bytes>, BodyError>>);

impl Body for Frames {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready(self.get_mut().0.pop_front())
    }
}

fn data(parts: &[&[u8]]) -> Frames {
    Frames(
        parts
            .iter()
            .map(|p| Ok(Frame::data(Bytes::copy_from_slice(p))))
            .collect(),
    )
}

fn wrap(frames: Frames, scrubber: Arc<Scrubber>) -> ScrubBody {
    ScrubBody {
        inner: frames.boxed(),
        scrubber,
        scratch: Scratch::default(),
        held: BytesMut::new(),
        trailers: None,
        ended: false,
        redactions: Redactions::new(Arc::new(Metrics::default()), RuleId::new(), "test".into()),
    }
}

/// What a client reads: data frames, trailers, and the error if any.
async fn read(mut body: ScrubBody) -> (Vec<Bytes>, Option<HeaderMap>, Option<BodyError>) {
    let (mut out, mut trailers) = (Vec::new(), None);
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => match frame.into_data() {
                Ok(d) => out.push(d),
                Err(f) => trailers = f.into_trailers().ok(),
            },
            Err(e) => return (out, trailers, Some(e)),
        }
    }
    (out, trailers, None)
}

fn joined(frames: &[Bytes]) -> String {
    String::from_utf8(frames.iter().flat_map(|f| f.to_vec()).collect()).unwrap()
}

#[tokio::test]
async fn a_credential_split_across_frames_is_redacted_at_every_split() {
    let s = scrubber(&header());
    for form in [KEY.to_string(), percent(KEY, true), KEY.replace('/', r"\/")] {
        let body = format!("{{\"args\":{{\"token\":\"{form}\"}}}}");
        let (expected, count) = redacted(&s, &body);
        assert_eq!(count, 1);
        for split in 1..body.len() {
            let (a, b) = body.as_bytes().split_at(split);
            let (frames, _, error) = read(wrap(data(&[a, b]), s.clone())).await;
            assert!(error.is_none());
            assert_eq!(joined(&frames), expected, "split at {split}");
        }
        let bytes: Vec<&[u8]> = body.as_bytes().chunks(1).collect();
        let (frames, _, _) = read(wrap(data(&bytes), s.clone())).await;
        assert_eq!(joined(&frames), expected, "one byte per frame");
    }
}

#[tokio::test]
async fn only_a_possible_start_of_the_credential_is_held_back() {
    let s = scrubber(&bearer());
    let mut body = wrap(data(&[b"plain text, xoxb-te", b"rrific news"]), s.clone());
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(&first[..], b"plain text, ", "the prefix waits for more");
    let rest = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(
        &rest[..],
        b"xoxb-terrific news",
        "and is released unchanged"
    );

    // A frame with nothing that could start a match goes straight through.
    let frame = Bytes::from_static(b"nothing to see here");
    let mut body = wrap(
        Frames(VecDeque::from([Ok(Frame::data(frame.clone()))])),
        s.clone(),
    );
    let out = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(out.as_ptr(), frame.as_ptr(), "relayed without a copy");

    // A prefix still held when the body ends is released as it is.
    let (frames, _, _) = read(wrap(data(&[b"ends with xoxb-tes"]), s.clone())).await;
    assert_eq!(joined(&frames), "ends with xoxb-tes");
    assert!(s.max_holdback() < MAX_PATTERN_BYTES);
}

#[tokio::test]
async fn bytes_held_when_the_upstream_fails_are_never_released() {
    let s = scrubber(&bearer());
    let frames = Frames(VecDeque::from([
        Ok(Frame::data(Bytes::from_static(b"abc xoxb-test-00"))),
        Err::<Frame<Bytes>, BodyError>("upstream reset".into()),
    ]));
    let (out, _, error) = read(wrap(frames, s)).await;
    assert!(error.is_some());
    assert_eq!(joined(&out), "abc ");
}

#[tokio::test]
async fn trailers_are_redacted() {
    let s = scrubber(&bearer());
    let mut trailers = HeaderMap::new();
    trailers.insert("x-echo", HeaderValue::from_static("Bearer xoxb-test-0000"));
    let frames = Frames(VecDeque::from([
        Ok(Frame::data(Bytes::from_static(b"held xoxb-"))),
        Ok(Frame::trailers(trailers)),
    ]));
    let (out, trailers, _) = read(wrap(frames, s)).await;
    assert_eq!(joined(&out), "held xoxb-");
    let echo = trailers.unwrap().get("x-echo").unwrap().clone();
    assert!(!echo.to_str().unwrap().contains(BEARER), "{echo:?}");
}

#[test]
fn headers_and_redirects_are_redacted_and_a_header_named_after_it_is_dropped() {
    let s = scrubber(&bearer());
    let mut headers = HeaderMap::new();
    headers.insert(
        "location",
        HeaderValue::from_static("https://callback.test/done?token=xoxb-test-0000"),
    );
    headers.insert("x-echo", HeaderValue::from_static("Bearer xoxb-test-0000"));
    headers.insert("x-xoxb-test-0000", HeaderValue::from_static("1"));
    headers.insert("content-type", HeaderValue::from_static("text/plain"));
    let count = s.redact_headers(&mut headers, &mut Scratch::default());
    assert_eq!(count, 3);
    let location = headers.get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "https://callback.test/done?token=[redacted]****");
    assert!(!headers
        .get("x-echo")
        .unwrap()
        .to_str()
        .unwrap()
        .contains(BEARER));
    assert!(headers.get("x-xoxb-test-0000").is_none());
    assert_eq!(headers.get("content-type").unwrap(), "text/plain");
}

#[test]
fn compressed_and_partial_responses_are_withheld_without_echoing_the_header() {
    let with = |name: &'static str, value: &'static str| {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static(value));
        headers
    };
    for (value, coding) in [
        ("gzip", "gzip"),
        ("BR", "br"),
        ("identity, deflate", "deflate"),
    ] {
        assert_eq!(
            withhold(StatusCode::OK, &with("content-encoding", value)),
            Some(Withheld::Encoded { coding }),
            "{value}"
        );
    }
    let unknown = withhold(StatusCode::OK, &with("content-encoding", BEARER)).unwrap();
    assert!(!unknown.to_string().contains(BEARER), "{unknown}");
    assert!(
        unknown.to_string().contains("an unrecognised encoding"),
        "{unknown}"
    );
    assert_eq!(
        withhold(StatusCode::OK, &with("transfer-encoding", "gzip, chunked")),
        Some(Withheld::Encoded { coding: "gzip" })
    );
    assert_eq!(
        withhold(StatusCode::PARTIAL_CONTENT, &HeaderMap::new()),
        Some(Withheld::Partial)
    );
    assert_eq!(
        withhold(StatusCode::OK, &with("content-encoding", "identity")),
        None
    );
    assert_eq!(
        withhold(StatusCode::OK, &with("transfer-encoding", "chunked")),
        None
    );
    assert_eq!(withhold(StatusCode::OK, &HeaderMap::new()), None);
}

#[test]
fn the_request_asks_for_a_whole_identity_encoded_response() {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));
    headers.insert(RANGE, HeaderValue::from_static("bytes=0-4"));
    headers.insert(IF_RANGE, HeaderValue::from_static("\"etag\""));
    prepare_request(&mut headers);
    assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "identity");
    assert!(headers.get(RANGE).is_none() && headers.get(IF_RANGE).is_none());
}

#[test]
fn limits_refuse_what_cannot_be_scanned_for() {
    let long = "/".repeat(MAX_PATTERN_BYTES / 6 + 1);
    assert!(matches!(
        Scrubber::from_materials([long.as_str()]),
        Err(ScrubberError::TooLong { .. })
    ));
    let many: Vec<String> = (0..=MAX_PATTERNS)
        .map(|i| format!("material-{i}"))
        .collect();
    assert!(matches!(
        Scrubber::from_materials(many.iter().map(String::as_str)),
        Err(ScrubberError::TooMany { .. })
    ));
    assert!(Scrubber::from_materials(["", "short"]).unwrap().is_empty());
}

#[test]
fn a_scrubber_never_formats_what_it_looks_for() {
    let debug = format!("{:?}", scrubber(&bearer()));
    assert!(!debug.contains("xoxb"), "{debug}");
}

/// Real traffic through the intercepting proxy to an upstream that
/// reflects the injected credential in the ways this module covers.
mod end_to_end {
    use std::time::Duration;

    use tokenless_core::scope::Scope;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::testing::{https_listener, running, Running};

    /// The rule injects `Bearer <SECRET>`. It holds characters encoders
    /// rewrite.
    const SECRET: &str = "xoxb-test/0000+aaaa";

    fn json_escaped(value: &str) -> String {
        value.replace('/', r"\/")
    }

    /// Answers by path, reflecting the `Authorization` it received.
    async fn reflecting_upstream() -> (u16, rustls::pki_types::CertificateDer<'static>) {
        let (listener, server, root) = https_listener().await;
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
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let header = |wanted: &str| {
                        head.lines()
                            .find_map(|l| {
                                let (name, value) = l.split_once(':')?;
                                name.eq_ignore_ascii_case(wanted)
                                    .then(|| value.trim().to_string())
                            })
                            .unwrap_or_default()
                    };
                    let auth = header("authorization");
                    let token = auth.trim_start_matches("Bearer ").to_string();
                    let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                    let whole = |extra: &str, body: &[u8]| {
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
                            body.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(body);
                        out
                    };
                    let answer = match path.as_str() {
                        "/plain" => whole(
                            "",
                            format!("{{\"ok\":true,\"args\":{{\"token\":\"{token}\"}}}}")
                                .as_bytes(),
                        ),
                        "/headers" => whole(
                            &format!("X-Echo: {auth}\r\n"),
                            format!(
                                "{{\"headers\":{{\"Authorization\":\"{}\"}}}}",
                                json_escaped(&auth)
                            )
                            .as_bytes(),
                        ),
                        "/base64" => {
                            whole("", STANDARD.encode(format!("echo:{auth}")).as_bytes())
                        }
                        "/query" => whole("", percent(&token, false).as_bytes()),
                        "/redirect" => format!(
                            "HTTP/1.1 302 Found\r\nLocation: https://callback.test/cb?t={}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            percent(&token, true)
                        )
                        .into_bytes(),
                        "/gzip" => whole("Content-Encoding: gzip\r\n", b"\x1f\x8b not scanned"),
                        "/seen" => whole(
                            "",
                            format!(
                                "accept-encoding={};range={}",
                                header("accept-encoding"),
                                header("range")
                            )
                            .as_bytes(),
                        ),
                        "/chunked" => {
                            let body = format!("{{\"token\":\"{}\"}}", json_escaped(&token));
                            let _ = tls
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                                )
                                .await;
                            // Cut inside the token and inside its `\/`.
                            let mut start = 0;
                            for end in [14, 19, 20, 25, body.len()] {
                                let piece = &body[start..end];
                                let _ = tls
                                    .write_all(
                                        format!("{:x}\r\n{piece}\r\n", piece.len()).as_bytes(),
                                    )
                                    .await;
                                let _ = tls.flush().await;
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                start = end;
                            }
                            b"0\r\n\r\n".to_vec()
                        }
                        _ => whole("", b"hello, nothing secret here: xoxb-test and 0000"),
                    };
                    let _ = tls.write_all(&answer).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (port, root)
    }

    async fn plane() -> (Running, String) {
        let (port, root) = reflecting_upstream().await;
        let target = format!("localhost:{port}");
        let r = running(&target, vec![root]).await;
        let mut body = r.f.snapshot_body(
            2,
            vec![(r.rule, Scope::parse("vault:test").unwrap(), &target, SECRET)],
        );
        body.egress.block_private = false;
        r.installer.install(&r.f.sign(&body)).unwrap();
        (r, target)
    }

    /// The response's head, and its body with chunked framing removed.
    async fn get(r: &Running, target: &str, path: &str, extra: &str) -> (String, Vec<u8>) {
        let mut tls = r.intercepted(target, "localhost").await;
        tls.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {target}\r\n{extra}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut raw = Vec::new();
        let _ = tls.read_to_end(&mut raw).await;
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut body = raw[split..].to_vec();
        if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            let mut decoded = Vec::new();
            let mut rest = &body[..];
            while let Some(line) = rest.windows(2).position(|w| w == b"\r\n") {
                let size =
                    usize::from_str_radix(std::str::from_utf8(&rest[..line]).unwrap(), 16).unwrap();
                if size == 0 {
                    break;
                }
                decoded.extend_from_slice(&rest[line + 2..line + 2 + size]);
                rest = &rest[line + 2 + size + 2..];
            }
            body = decoded;
        }
        (head, body)
    }

    fn assert_clean(what: &str, text: &[u8]) {
        let text = String::from_utf8_lossy(text);
        for form in [
            SECRET.to_string(),
            json_escaped(SECRET),
            percent(SECRET, true),
            percent(SECRET, false),
            STANDARD.encode(format!("echo:Bearer {SECRET}")),
        ] {
            assert!(!text.contains(&form), "{what} carries {form}: {text}");
        }
        assert!(!text.contains("aaaa"), "{what} carries part of it: {text}");
    }

    #[tokio::test]
    async fn the_client_never_receives_the_credential_it_was_injected_with() {
        let (r, target) = plane().await;
        for path in [
            "/plain",
            "/headers",
            "/base64",
            "/query",
            "/chunked",
            "/redirect",
        ] {
            let (head, body) = get(&r, &target, path, "").await;
            assert!(
                head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.1 302"),
                "{path}: {head}"
            );
            assert_clean(&format!("{path} head"), head.as_bytes());
            assert_clean(&format!("{path} body"), &body);
            if path == "/redirect" {
                assert!(
                    head.to_ascii_lowercase()
                        .contains("location: https://callback.test/cb?t=[redacted]"),
                    "{head}"
                );
            } else {
                let body = String::from_utf8_lossy(&body);
                assert!(body.contains("[redacted]"), "{path}: {body}");
            }
        }
        r.dp.abort();
    }

    #[tokio::test]
    async fn a_normal_response_is_relayed_byte_for_byte() {
        let (r, target) = plane().await;
        let (head, body) = get(&r, &target, "/normal", "").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(
            head.to_ascii_lowercase().contains("content-length: 46"),
            "{head}"
        );
        assert_eq!(body, b"hello, nothing secret here: xoxb-test and 0000");
        // The upstream was asked for the whole body, unencoded.
        let (_, body) = get(
            &r,
            &target,
            "/seen",
            "Accept-Encoding: gzip, br\r\nRange: bytes=0-3\r\n",
        )
        .await;
        assert_eq!(
            String::from_utf8_lossy(&body),
            "accept-encoding=identity;range="
        );
        r.dp.abort();
    }

    #[tokio::test]
    async fn a_compressed_response_is_withheld_with_a_clear_502() {
        let (r, target) = plane().await;
        let (head, body) = get(&r, &target, "/gzip", "").await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("gzip encoding although identity was requested"),
            "{body}"
        );
        assert!(body.contains("withheld"), "{body}");
        assert!(!body.contains("not scanned"), "{body}");
        r.dp.abort();
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_reported_by_kind_only() {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let target = format!("localhost:{port}");
        let (_, root) = reflecting_upstream().await;
        let r = running(&target, vec![root]).await;
        let (head, body) = get(&r, &target, "/plain", "").await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("failed (unreachable)"), "{body}");
        assert!(
            !body.contains("TCP") && !body.to_lowercase().contains("refused"),
            "{body}"
        );
        r.dp.abort();
    }
}
