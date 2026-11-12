// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real HTTP clients send the session port's password from the proxy URL
//! `run` gives them, and are refused without it. Each client is skipped
//! when it isn't installed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use broker_server::launcher::port::{proxy_authorization, PortPassword, SessionPort};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A stand-in for the data plane proxy: records each request head it gets
/// and refuses the tunnel, so the client stops there.
async fn recording_proxy() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                return;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let _ = conn
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    (addr, heads)
}

fn installed(program: &str) -> bool {
    std::process::Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Runs `program args` with `HTTPS_PROXY` (and the other names) set to
/// `proxy_url`; the request itself is expected to fail at the fake proxy.
async fn fetch_through(program: &str, args: &[&str], proxy_url: &str) {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env("NODE_USE_ENV_PROXY", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        command.env(name, proxy_url);
    }
    let _ = tokio::time::timeout(Duration::from_secs(20), command.status()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clients_send_the_port_password_from_the_proxy_url() {
    let clients: [(&str, &[&str]); 3] = [
        ("curl", &["-s", "-m", "10", "https://api.example.com/"]),
        (
            "node",
            &[
                "-e",
                "fetch('https://api.example.com/').catch(() => process.exit(1))",
            ],
        ),
        (
            "python3",
            &[
                "-c",
                "import urllib.request\ntry:\n    urllib.request.urlopen('https://api.example.com/', timeout=10)\nexcept Exception:\n    pass",
            ],
        ),
    ];
    let mut tried = Vec::new();
    for (program, args) in clients {
        if !installed(program) {
            eprintln!("{program} is not installed; skipping it");
            continue;
        }
        let (upstream, heads) = recording_proxy().await;
        let port = SessionPort::start(
            "127.0.0.1:0".parse().unwrap(),
            &upstream,
            Arc::new(ArcSwap::from_pointee(proxy_authorization("v4.public.t"))),
            Arc::new(ArcSwap::from_pointee(String::new())),
            Some(PortPassword::generate()),
        )
        .await
        .unwrap();

        // Without the password the port refuses it: nothing reaches the proxy.
        fetch_through(program, args, &format!("http://{}", port.addr)).await;
        assert!(
            heads.lock().unwrap().is_empty(),
            "{program} got through without the password"
        );

        // With the URL `run` sets, the request reaches the proxy carrying
        // the session, and the password goes no further than the port.
        fetch_through(program, args, &port.url()).await;
        let heads = heads.lock().unwrap().clone();
        let password = port
            .url()
            .split(':')
            .nth(2)
            .unwrap()
            .split('@')
            .next()
            .unwrap()
            .to_string();
        assert!(
            heads
                .iter()
                .any(|h| h.starts_with("CONNECT api.example.com:443")),
            "{program} did not send the port's password from the proxy URL: {heads:?}"
        );
        assert!(heads.iter().all(|h| !h.contains(&password)));
        assert!(heads
            .iter()
            .all(|h| h.contains(&proxy_authorization("v4.public.t"))));
        tried.push(program);
    }
    eprintln!("checked: {tried:?}");
}
