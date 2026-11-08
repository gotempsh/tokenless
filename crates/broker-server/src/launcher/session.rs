// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The session behind a session port. Either minted from a bundle, renewed
//! before it expires and ended when it stops, or a token someone handed
//! over, used as is until it expires.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use broker_control::model::ProxySession;
use broker_control::service::sessions::DiscoveredService;
use broker_core::ids::VaultId;
use chrono::{DateTime, Utc};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::client::{ApiClient, MintRequest, PortServices};
use super::port::proxy_authorization;
use super::LauncherError;

/// Tokens minted so far that have not expired, so they can be ended.
type Minted = Arc<Mutex<Vec<(DateTime<Utc>, Zeroizing<String>)>>>;

/// When to renew a session: a quarter of its lifetime before it expires,
/// between 10 seconds and 2 minutes, and never sooner than 5 seconds.
pub fn renew_in(now: DateTime<Utc>, expires_at: DateTime<Utc>, ttl_secs: u64) -> Duration {
    let margin = (ttl_secs / 4).clamp(10, 120);
    let left = (expires_at - now).num_seconds();
    let wait = left.saturating_sub(i64::try_from(margin).unwrap_or(i64::MAX));
    Duration::from_secs(u64::try_from(wait).unwrap_or(0).max(5))
}

fn remember(minted: &Minted, expires_at: DateTime<Utc>, token: &str) {
    if let Ok(mut tokens) = minted.lock() {
        let now = Utc::now();
        tokens.retain(|(exp, _)| *exp > now);
        tokens.push((expires_at, Zeroizing::new(token.to_string())));
    }
}

pub struct LiveSession {
    client: Arc<ApiClient>,
    /// The `Proxy-Authorization` value of the current session.
    pub auth: Arc<ArcSwap<String>>,
    /// The current session record.
    pub current: Arc<ArcSwap<ProxySession>>,
    /// The services the session reaches, as seen when it started. Empty if
    /// the broker could not be asked (the agent then gets no placeholders).
    pub services: Vec<DiscoveredService>,
    minted: Minted,
    /// Renews a minted session, or reports when a given one runs out.
    renewer: JoinHandle<()>,
}

impl LiveSession {
    pub async fn start(
        client: Arc<ApiClient>,
        vault: VaultId,
        request: MintRequest,
    ) -> Result<Self, LauncherError> {
        let first = client.mint(&vault, &request).await?;
        let auth = Arc::new(ArcSwap::from_pointee(proxy_authorization(&first.token)));
        let minted: Minted = Arc::new(Mutex::new(Vec::new()));
        remember(&minted, first.session.expires_at, &first.token);
        let services = match client.discover(&first.token).await {
            Ok(discovery) => discovery.services,
            Err(e) => {
                warn!(error = %e, "could not list the session's services; placeholders are not exported");
                Vec::new()
            }
        };
        let current = Arc::new(ArcSwap::from_pointee(first.session));
        let renewer = tokio::spawn(renew_loop(
            client.clone(),
            vault,
            request,
            auth.clone(),
            current.clone(),
            minted.clone(),
        ));
        Ok(Self {
            client,
            auth,
            current,
            services,
            minted,
            renewer,
        })
    }

    /// Uses a session token minted elsewhere (the console's New session,
    /// `session create`). It is checked before anything starts, never
    /// renewed and never ended here: it lasts until it expires or is
    /// revoked, like any token handed to an agent.
    pub async fn adopt(client: Arc<ApiClient>, token: &str) -> Result<Self, LauncherError> {
        let discovery = client.discover(token).await?;
        let auth = Arc::new(ArcSwap::from_pointee(proxy_authorization(token)));
        let expires_at = discovery.session.expires_at;
        let current = Arc::new(ArcSwap::from_pointee(discovery.session));
        let renewer = tokio::spawn(async move {
            let left = (expires_at - Utc::now()).to_std().unwrap_or_default();
            tokio::time::sleep(left).await;
            eprintln!(
                "tokenless: the session expired at {expires_at}, so the proxy now refuses requests; create a new one"
            );
        });
        Ok(Self {
            client,
            auth,
            current,
            services: discovery.services,
            minted: Arc::new(Mutex::new(Vec::new())),
            renewer,
        })
    }

    /// What the session port serves at `/services`: the bundle and the
    /// services it reaches, with no token and no secret.
    pub fn services_json(&self) -> String {
        let current = self.current.load();
        serde_json::to_string(&PortServices {
            bundle: current.bundle.as_ref().map(|b| b.name.clone()),
            services: self.services.clone(),
        })
        .unwrap_or_else(|_| r#"{"bundle":null,"services":[]}"#.to_string())
    }

    /// Stops renewing and ends every unexpired session it minted. Returns
    /// how many were ended; failures are reported and do not stop the rest.
    pub async fn end(self) -> usize {
        self.renewer.abort();
        let tokens = match self.minted.lock() {
            Ok(mut tokens) => std::mem::take(&mut *tokens),
            Err(_) => Vec::new(),
        };
        let mut ended = 0;
        for (expires_at, token) in tokens {
            if expires_at <= Utc::now() {
                continue;
            }
            match self.client.revoke_self(&token).await {
                Ok(session) => {
                    info!(session_id = %session.id, "session ended");
                    ended += 1;
                }
                Err(e) => {
                    eprintln!("tokenless: could not end a session, it stays valid until {expires_at}: {e}");
                }
            }
        }
        ended
    }
}

async fn renew_loop(
    client: Arc<ApiClient>,
    vault: VaultId,
    request: MintRequest,
    auth: Arc<ArcSwap<String>>,
    current: Arc<ArcSwap<ProxySession>>,
    minted: Minted,
) {
    let mut backoff = Duration::from_secs(5);
    let mut wait = renew_in(Utc::now(), current.load().expires_at, request.ttl_secs);
    loop {
        tokio::time::sleep(wait).await;
        match client.mint(&vault, &request).await {
            Ok(next) => {
                let previous = current.load().id;
                remember(&minted, next.session.expires_at, &next.token);
                auth.store(Arc::new(proxy_authorization(&next.token)));
                info!(previous = %previous, session_id = %next.session.id, expires_at = %next.session.expires_at, "session renewed");
                wait = renew_in(Utc::now(), next.session.expires_at, request.ttl_secs);
                current.store(Arc::new(next.session));
                backoff = Duration::from_secs(5);
            }
            Err(e) => {
                let expires_at = current.load().expires_at;
                let expired = expires_at <= Utc::now();
                warn!(error = %e, expired, "session renewal failed; retrying");
                eprintln!(
                    "tokenless: renewing the session failed (retrying in {}s){}: {e}",
                    backoff.as_secs(),
                    if expired {
                        ", and the current one has expired, so requests are refused".to_string()
                    } else {
                        format!("; the current one is valid until {expires_at}")
                    }
                );
                wait = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_leaves_a_bounded_margin() {
        let now = Utc::now();
        let at = |secs| now + chrono::Duration::seconds(secs);
        // 15-minute session: renew 2 minutes before it ends.
        assert_eq!(renew_in(now, at(900), 900), Duration::from_secs(780));
        // 60-second session: a quarter, but at least 10 seconds.
        assert_eq!(renew_in(now, at(60), 60), Duration::from_secs(45));
        assert_eq!(renew_in(now, at(20), 20), Duration::from_secs(10));
        // Already past the margin: retry soon, never in a tight loop.
        assert_eq!(renew_in(now, at(3), 900), Duration::from_secs(5));
        assert_eq!(renew_in(now, at(-30), 900), Duration::from_secs(5));
    }
}
