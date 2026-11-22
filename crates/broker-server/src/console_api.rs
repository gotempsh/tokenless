// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use broker_server::launcher::account::{
    management_base, session_or_public_request, ConsoleClient, SessionStore,
};
use broker_server::launcher::LauncherError;
use bytes::Bytes;
use clap::Subcommand;
use reqwest::Method;

use crate::{CliError, TerminalPrompter};

#[derive(Subcommand)]
pub enum Command {
    /// List HTTP methods and paths supported by this CLI version.
    Routes,
    /// Call a path relative to /api/v1. Writes the response body to stdout.
    Request {
        #[arg(value_parser = ["GET", "POST", "PUT", "PATCH", "DELETE"])]
        method: String,
        /// Example: /vaults or '/audit?page=2'.
        path: String,
        /// JSON request body file. Use - for stdin.
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,
        /// Call without a session, for public workflows such as invite acceptance.
        #[arg(long)]
        anonymous: bool,
        /// Use a proxy session bearer for /sessions/self or /sessions/revoke-self.
        #[arg(long, value_name = "FILE", conflicts_with = "anonymous")]
        session_token_file: Option<PathBuf>,
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
    },
}

fn input_json(path: PathBuf) -> Result<Bytes, CliError> {
    let input: Box<dyn Read> = if path.as_os_str() == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(&path).map_err(|source| CliError::Io {
            context: format!("opening JSON input {}", path.display()),
            source,
        })?)
    };
    // Axum's JSON extractor accepts at most 2 MiB.
    const MAX_JSON: u64 = 2 * 1024 * 1024;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    input
        .take(MAX_JSON + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            context: "reading management API JSON input".into(),
            source,
        })?;
    if bytes.len() as u64 > MAX_JSON {
        return Err(LauncherError::config("management API JSON input exceeds 2 MiB").into());
    }
    std::str::from_utf8(&bytes).map_err(|error| {
        LauncherError::config(format!(
            "JSON input must be UTF-8 (invalid byte at offset {})",
            error.valid_up_to()
        ))
    })?;
    serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| {
        LauncherError::config(format!(
            "could not read JSON input at line {}, column {}",
            e.line(),
            e.column()
        ))
    })?;
    Ok(Bytes::from_owner(bytes))
}

pub async fn run(command: Command) -> Result<ExitCode, CliError> {
    let io = |source| CliError::Io {
        context: "writing management API output".into(),
        source,
    };
    let Command::Request {
        method,
        path,
        input,
        anonymous,
        session_token_file,
        server,
    } = command
    else {
        let mut out = std::io::stdout().lock();
        for (path, methods) in broker_server::api::MANAGEMENT_ROUTES {
            for method in *methods {
                writeln!(out, "{} {path}", method.to_ascii_uppercase()).map_err(io)?;
            }
        }
        return Ok(ExitCode::SUCCESS);
    };

    let method = Method::from_bytes(method.as_bytes())
        .map_err(|_| LauncherError::config("invalid HTTP method"))?;
    let server = management_base(&server)?;
    let body = input.map(input_json).transpose()?;
    let has_input = body.is_some();
    let response = if anonymous || session_token_file.is_some() {
        let token = session_token_file
            .as_deref()
            .map(crate::read_token_file)
            .transpose()?;
        session_or_public_request(
            &server,
            method,
            &path,
            body,
            token.as_ref().map(|s| s.as_str()),
        )
        .await
    } else {
        let store = SessionStore::system();
        let client = ConsoleClient::open(&store, &server, &TerminalPrompter)?;
        // Older brokers end a sign-in by ID without sending a clearing cookie.
        let revokes_sign_in = method == Method::POST
            && path
                .split('?')
                .next()
                .and_then(|p| p.strip_prefix("/auth/sign-ins/"))
                .and_then(|p| p.strip_suffix("/revoke"))
                .is_some_and(|id| id.parse::<uuid::Uuid>().is_ok());
        let response = client
            .request(method, &path, body, "calling the management API")
            .await;
        if let Ok(reply) = &response {
            // The broker clears this cookie on logout. Forget only the sign-in it ended.
            let clears_session = reply
                .headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .any(|header| {
                    header
                        .to_str()
                        .ok()
                        .and_then(|cookie| cookie.split(';').next())
                        .and_then(|pair| pair.split_once('='))
                        == Some((tokenless_auth::cookie::SESSION_COOKIE, ""))
                });
            if clears_session
                || (revokes_sign_in
                    && matches!(client.me().await, Err(LauncherError::NotSignedIn { .. })))
            {
                store.forget(client.session())?;
            }
        }
        response
    };
    let mut response = response.map_err(|error| match error {
        // Older brokers include rejected JSON values in validation errors.
        LauncherError::Api {
            operation,
            status: 400,
            ref detail,
            ..
        } if has_input && detail.starts_with("bad request: invalid JSON body:") => {
            LauncherError::Api {
                operation,
                status: 400,
                title: "Bad Request".into(),
                detail: "check the JSON fields, types and values for this operation".into(),
            }
        }
        error => error,
    })?;
    let mut out = std::io::stdout().lock();
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        LauncherError::config(format!("reading broker response: {}", e.without_url()))
    })? {
        out.write_all(&chunk).map_err(io)?;
    }
    out.flush().map_err(io)?;
    Ok(ExitCode::SUCCESS)
}
