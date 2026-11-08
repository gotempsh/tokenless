// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The local session port: a loopback listener that adds the current
//! session to each proxy request and relays it to the data plane proxy.
//!
//! Only the request head is touched. Any `Proxy-Authorization` the client
//! sent is dropped and replaced, then the connection becomes a byte relay,
//! which is all a `CONNECT` tunnel needs. The proxy refuses plain-HTTP
//! requests itself, so the port does not need to understand them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::LauncherError;

/// Largest request head accepted before the port gives up on a client.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Concurrent connections; further clients wait for a slot.
pub const MAX_CONNECTIONS: usize = 256;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The `Proxy-Authorization` value for a session token, in the form the
/// proxy accepts (`http://<token>@host:port` produces the same).
pub fn proxy_authorization(token: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{token}:")))
}

/// Finds the end of the request head (the blank line), if it has arrived.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Rewrites a complete request head so it carries `authorization` as its
/// only `Proxy-Authorization` header.
pub fn rewrite_head(head: &[u8], authorization: &str) -> Result<Vec<u8>, &'static str> {
    let body = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or("request head is not terminated by a blank line")?;
    let mut lines = body
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line = lines.next().ok_or("empty request")?;
    if request_line
        .split(|b| *b == b' ')
        .filter(|p| !p.is_empty())
        .count()
        != 3
    {
        return Err("malformed request line");
    }
    let mut out = Vec::with_capacity(head.len() + authorization.len() + 32);
    out.extend_from_slice(request_line);
    out.extend_from_slice(b"\r\nProxy-Authorization: ");
    out.extend_from_slice(authorization.as_bytes());
    out.extend_from_slice(b"\r\n");
    for line in lines {
        let is_proxy_auth =
            line.len() >= 20 && line[..20].eq_ignore_ascii_case(b"proxy-authorization:");
        if !is_proxy_auth {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// The path agents fetch from the session port itself to learn what the
/// session reaches: `curl $TOKENLESS_PROXY/services`.
pub const SERVICES_PATH: &str = "/services";

/// Is this head an origin-form `GET /services`, meant for the port itself?
pub fn asks_for_services(head: &[u8]) -> bool {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let mut parts = line.split(|b| *b == b' ').filter(|p| !p.is_empty());
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return false;
    };
    let path = target.split(|b| *b == b'?').next().unwrap_or_default();
    method == b"GET" && path == SERVICES_PATH.as_bytes()
}

async fn reply_json(client: &mut TcpStream, json: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    let _ = client.write_all(response.as_bytes()).await;
}

async fn reply(client: &mut TcpStream, status: &str, message: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    );
    // The client may already be gone; there is nobody left to tell.
    let _ = client.write_all(response.as_bytes()).await;
}

async fn read_head(client: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&buf) {
            let rest = buf.split_off(end);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err("request head is larger than 16 KiB");
        }
        match client.read(&mut chunk).await {
            Ok(0) => return Err("client closed the connection before sending a request"),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err("reading the request failed"),
        }
    }
}

async fn handle(
    mut client: TcpStream,
    upstream: Arc<str>,
    auth: Arc<ArcSwap<String>>,
    services: Arc<ArcSwap<String>>,
) {
    let (head, rest) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(parts)) => parts,
        Ok(Err(reason)) => {
            debug!(reason, "session port: dropped a client");
            reply(
                &mut client,
                "400 Bad Request",
                &format!("tokenless session port: {reason}\n"),
            )
            .await;
            return;
        }
        Err(_) => return,
    };
    if asks_for_services(&head) {
        let listing = services.load_full();
        reply_json(&mut client, &listing).await;
        return;
    }
    let rewritten = match rewrite_head(&head, auth.load().as_str()) {
        Ok(h) => h,
        Err(reason) => {
            reply(
                &mut client,
                "400 Bad Request",
                &format!("tokenless session port: {reason}\n"),
            )
            .await;
            return;
        }
    };
    let connect =
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream.as_ref())).await;
    let mut proxy = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(proxy = %upstream, error = %e, "session port: cannot reach the proxy");
            reply(
                &mut client,
                "502 Bad Gateway",
                &format!("tokenless session port: cannot reach the proxy at {upstream}: {e}\n"),
            )
            .await;
            return;
        }
        Err(_) => {
            warn!(proxy = %upstream, "session port: timed out connecting to the proxy");
            reply(
                &mut client,
                "504 Gateway Timeout",
                &format!(
                    "tokenless session port: timed out connecting to the proxy at {upstream}\n"
                ),
            )
            .await;
            return;
        }
    };
    let _ = proxy.set_nodelay(true);
    if proxy.write_all(&rewritten).await.is_err() || proxy.write_all(&rest).await.is_err() {
        reply(
            &mut client,
            "502 Bad Gateway",
            "tokenless session port: the proxy closed the connection\n",
        )
        .await;
        return;
    }
    // Either side closing ends the relay; errors here are ordinary
    // disconnects, not failures worth reporting.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut proxy).await;
}

/// The session port adds a session to whatever reaches it, so it may only
/// listen where nothing but this machine can connect.
pub fn check_listen(listen: SocketAddr) -> Result<(), LauncherError> {
    if listen.ip().is_loopback() {
        return Ok(());
    }
    Err(LauncherError::config(format!(
        "the session port must listen on a loopback address, not {listen}: anyone who can reach it uses the session"
    )))
}

/// How long the proxy check waits for a connection and an answer.
const PROXY_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// What the proxy check sends: a `CONNECT` without a session. A tokenless
/// proxy answers it with 407, or with 503 while it has no policy, without
/// opening anything or writing to the audit log.
const PROXY_PROBE: &[u8] =
    b"CONNECT tokenless-proxy-check.invalid:443 HTTP/1.1\r\nHost: tokenless-proxy-check.invalid:443\r\n\r\n";

/// Checks a tokenless proxy answers at `address` before a session is
/// minted for it, so a proxy that isn't running is reported up front
/// instead of as every request the agent makes failing to connect. An open
/// port is not enough: a tailnet route, a load balancer or a port forward
/// accepts connections with nothing behind it, so the check asks the proxy
/// something and waits for its answer.
pub async fn check_proxy(address: &str) -> Result<(), LauncherError> {
    check_proxy_within(address, PROXY_CHECK_TIMEOUT).await
}

async fn check_proxy_within(address: &str, timeout: Duration) -> Result<(), LauncherError> {
    let unreachable = |reason: String| LauncherError::ProxyUnreachable {
        address: address.to_string(),
        reason,
    };
    let secs = timeout.as_secs_f32();
    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(unreachable(e.to_string())),
        Err(_) => return Err(unreachable(format!("connecting timed out after {secs} s"))),
    };
    let answer = match tokio::time::timeout(timeout, probe(&mut stream)).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(e)) => {
            return Err(unreachable(format!(
                "the connection was accepted, then failed without an answer ({e}): something forwards this address, but no tokenless proxy is behind it"
            )))
        }
        Err(_) => {
            return Err(unreachable(format!(
                "the connection was accepted, but nothing answered within {secs} s"
            )))
        }
    };
    proxy_answer(address, &answer)
}

/// Sends the probe and reads the answer's head (and the start of its body).
async fn probe(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.write_all(PROXY_PROBE).await?;
    let mut answer = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            if answer.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "closed by the other end",
                ));
            }
            return Ok(answer);
        }
        answer.extend_from_slice(&buf[..n]);
        // Not HTTP at all: no need to wait for more.
        if answer.len() >= 5 && !answer.starts_with(b"HTTP/") {
            return Ok(answer);
        }
        // The head is enough, except for a 503, whose first body line says
        // why the proxy refuses.
        if let Some(end) = head_end(&answer) {
            if answer.get(9..12) != Some(b"503".as_slice()) || answer.len() > end {
                return Ok(answer);
            }
        }
        if answer.len() >= 1024 {
            return Ok(answer);
        }
    }
}

/// Reads what answered the probe: a tokenless proxy, one that refuses all
/// traffic, or something that isn't a proxy.
fn proxy_answer(address: &str, answer: &[u8]) -> Result<(), LauncherError> {
    let text = String::from_utf8_lossy(answer);
    let status = text
        .strip_prefix("HTTP/1.")
        .and_then(|rest| rest.get(2..5))
        .and_then(|code| code.parse::<u16>().ok());
    match status {
        Some(503) => {
            let reason = text
                .split_once("\r\n\r\n")
                .map(|(_, body)| body.lines().next().unwrap_or_default().trim())
                .filter(|line| !line.is_empty())
                .unwrap_or("503 Service Unavailable");
            Err(LauncherError::ProxyRefusing {
                address: address.to_string(),
                reason: reason.to_string(),
            })
        }
        Some(_) => Ok(()),
        None => Err(LauncherError::ProxyUnreachable {
            address: address.to_string(),
            reason: "something answered, but not an HTTP proxy".into(),
        }),
    }
}

/// A running session port.
pub struct SessionPort {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl SessionPort {
    /// Binds `listen` (loopback only) and relays to the proxy at
    /// `upstream` (`host:port`), adding whatever `auth` holds at the time
    /// each connection arrives. `services` holds the JSON served at
    /// [`SERVICES_PATH`]: what the session reaches, never a secret; like
    /// `auth`, it changes when a renewal brings a session with other rules.
    pub async fn start(
        listen: SocketAddr,
        upstream: &str,
        auth: Arc<ArcSwap<String>>,
        services: Arc<ArcSwap<String>>,
    ) -> Result<Self, LauncherError> {
        check_listen(listen)?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(LauncherError::io(format!(
                "binding the session port on {listen}"
            )))?;
        let addr = listener
            .local_addr()
            .map_err(LauncherError::io("reading the session port address"))?;
        let upstream: Arc<str> = Arc::from(upstream);
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                let Ok(permit) = slots.clone().acquire_owned().await else {
                    return;
                };
                match listener.accept().await {
                    Ok((client, _)) => {
                        let _ = client.set_nodelay(true);
                        let upstream = upstream.clone();
                        let auth = auth.clone();
                        let services = services.clone();
                        tokio::spawn(async move {
                            handle(client, upstream, auth, services).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "session port: accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        Ok(Self { addr, task })
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for SessionPort {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener that answers every connection with `reply` (after reading
    /// the probe) and keeps it open, as a proxy does; or closes it at once
    /// when `reply` is `None`.
    async fn fake_proxy(reply: Option<&'static [u8]>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                if let Some(reply) = reply {
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(reply).await;
                    open.push(stream);
                }
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn a_proxy_that_answers_is_accepted() {
        let (up, task) = fake_proxy(Some(
            b"HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 0\r\n\r\n",
        ))
        .await;
        check_proxy(&up).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn an_open_port_with_no_proxy_behind_it_is_reported() {
        // What a tailnet route or port forward does when nothing listens
        // behind it: accept, then close.
        let (up, task) = fake_proxy(None).await;
        let shown = check_proxy(&up).await.unwrap_err().to_string();
        assert!(
            shown.contains(&up) && shown.contains("no tokenless proxy is behind it"),
            "{shown}"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_listener_that_never_answers_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = listener.local_addr().unwrap().to_string();
        let shown = check_proxy_within(&up, Duration::from_millis(200))
            .await
            .unwrap_err()
            .to_string();
        assert!(shown.contains("nothing answered within 0.2 s"), "{shown}");
        drop(listener);
    }

    #[tokio::test]
    async fn a_proxy_without_policy_says_why_it_refuses() {
        let (up, task) = fake_proxy(Some(
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 61\r\n\r\ndata plane has no policy snapshot yet; refusing all traffic\n",
        ))
        .await;
        let shown = check_proxy(&up).await.unwrap_err().to_string();
        assert!(
            shown.contains("refuses all traffic: data plane has no policy snapshot yet"),
            "{shown}"
        );
        task.abort();
    }

    #[tokio::test]
    async fn something_that_is_not_a_proxy_is_reported() {
        let (up, task) = fake_proxy(Some(b"SSH-2.0-OpenSSH_9.0\r\n")).await;
        let shown = check_proxy(&up).await.unwrap_err().to_string();
        assert!(shown.contains("not an HTTP proxy"), "{shown}");
        task.abort();
    }

    #[tokio::test]
    async fn a_proxy_that_is_not_running_is_reported_before_minting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = listener.local_addr().unwrap().to_string();
        drop(listener);
        let err = check_proxy(&up).await.unwrap_err();
        assert!(matches!(err, LauncherError::ProxyUnreachable { .. }));
        let shown = err.to_string();
        assert!(
            shown.contains(&up) && shown.contains("tokenless node run"),
            "{shown}"
        );
    }

    #[test]
    fn only_an_origin_form_get_of_services_is_answered_locally() {
        assert!(asks_for_services(
            b"GET /services HTTP/1.1\r\nHost: x\r\n\r\n"
        ));
        assert!(asks_for_services(b"GET /services?pretty HTTP/1.1\r\n\r\n"));
        assert!(!asks_for_services(
            b"GET http://api.example.com/services HTTP/1.1\r\n\r\n"
        ));
        assert!(!asks_for_services(
            b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n"
        ));
        assert!(!asks_for_services(b"POST /services HTTP/1.1\r\n\r\n"));
        assert!(!asks_for_services(b"GET /servicesx HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn authorization_matches_the_proxy_url_form() {
        let value = proxy_authorization("v4.public.abc");
        let decoded = STANDARD
            .decode(value.strip_prefix("Basic ").unwrap())
            .unwrap();
        assert_eq!(decoded, b"v4.public.abc:");
    }

    #[test]
    fn rewrite_replaces_any_client_proxy_authorization() {
        let head = b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nproxy-AUTHORIZATION: Basic Zm9vOmJhcg==\r\nUser-Agent: t\r\n\r\n";
        let out = String::from_utf8(rewrite_head(head, "Basic NEW").unwrap()).unwrap();
        assert_eq!(
            out,
            "CONNECT api.github.com:443 HTTP/1.1\r\nProxy-Authorization: Basic NEW\r\nHost: api.github.com:443\r\nUser-Agent: t\r\n\r\n"
        );
    }

    #[test]
    fn rewrite_rejects_garbage() {
        assert!(rewrite_head(b"CONNECT x\r\n\r\n", "a").is_err());
        assert!(rewrite_head(b"CONNECT x:443 HTTP/1.1\r\n", "a").is_err());
    }

    #[tokio::test]
    async fn refuses_non_loopback_listeners() {
        let auth = Arc::new(ArcSwap::from_pointee(String::new()));
        let err = SessionPort::start(
            "0.0.0.0:0".parse().unwrap(),
            "127.0.0.1:1",
            auth,
            Arc::new(ArcSwap::from_pointee(String::new())),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("loopback"), "{err}");
    }

    /// The port adds the current token and relays the tunnel both ways;
    /// a token swapped in later is used by later connections.
    #[tokio::test]
    async fn relays_with_the_current_token() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap().to_string();
        let fake_proxy = tokio::spawn(async move {
            let mut heads = Vec::new();
            for _ in 0..2 {
                let (mut conn, _) = upstream.accept().await.unwrap();
                let (head, _) = read_head(&mut conn).await.unwrap();
                heads.push(String::from_utf8(head).unwrap());
                conn.write_all(b"HTTP/1.1 200 Connection established\r\n\r\npong")
                    .await
                    .unwrap();
            }
            heads
        });
        let auth = Arc::new(ArcSwap::from_pointee(proxy_authorization("v4.public.one")));
        let port = SessionPort::start(
            "127.0.0.1:0".parse().unwrap(),
            &upstream_addr,
            auth.clone(),
            Arc::new(ArcSwap::from_pointee(String::new())),
        )
        .await
        .unwrap();
        for token in ["v4.public.one", "v4.public.two"] {
            auth.store(Arc::new(proxy_authorization(token)));
            let mut client = TcpStream::connect(port.addr).await.unwrap();
            client
                .write_all(
                    b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
                )
                .await
                .unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            assert!(got.ends_with(b"pong"), "{}", String::from_utf8_lossy(&got));
        }
        let heads = fake_proxy.await.unwrap();
        assert!(heads[0].contains(&proxy_authorization("v4.public.one")));
        assert!(heads[1].contains(&proxy_authorization("v4.public.two")));
    }

    /// `/services` answers with what the session reaches now, so a renewal
    /// that brings other rules shows in `session info` at once.
    #[tokio::test]
    async fn serves_the_current_services() {
        let auth = Arc::new(ArcSwap::from_pointee(proxy_authorization("t")));
        let services = Arc::new(ArcSwap::from_pointee(
            r#"{"bundle":"b","services":[]}"#.to_string(),
        ));
        let port = SessionPort::start(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1",
            auth,
            services.clone(),
        )
        .await
        .unwrap();
        let ask = || async {
            let mut client = TcpStream::connect(port.addr).await.unwrap();
            client
                .write_all(b"GET /services HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut got = String::new();
            client.read_to_string(&mut got).await.unwrap();
            got
        };
        assert!(ask().await.ends_with(r#"{"bundle":"b","services":[]}"#));
        services.store(Arc::new(
            r#"{"bundle":"b","services":[{"new":true}]}"#.to_string(),
        ));
        assert!(ask()
            .await
            .ends_with(r#"{"bundle":"b","services":[{"new":true}]}"#));
    }

    #[tokio::test]
    async fn explains_an_unreachable_proxy() {
        // Bind then drop to get a port nothing listens on.
        let free = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let auth = Arc::new(ArcSwap::from_pointee(proxy_authorization("t")));
        let port = SessionPort::start(
            "127.0.0.1:0".parse().unwrap(),
            &free.to_string(),
            auth,
            Arc::new(ArcSwap::from_pointee(String::new())),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(port.addr).await.unwrap();
        client
            .write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut got = String::new();
        client.read_to_string(&mut got).await.unwrap();
        assert!(got.starts_with("HTTP/1.1 502"), "{got}");
        assert!(got.contains("cannot reach the proxy"), "{got}");
    }
}
