// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The session behind a session port. Either minted from a bundle, renewed
//! before it expires and ended when it stops, or a token someone handed
//! over, used as is until it expires.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use tokenless_control::model::ProxySession;
use tokenless_control::service::sessions::DiscoveredService;
use tokenless_core::ids::VaultId;
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
    /// What the session port serves at `/services`, kept current: a
    /// renewal mints from the bundle again, so it may reach other services.
    listing: Arc<ArcSwap<String>>,
    minted: Minted,
    /// How a minted session is renewed; `None` for a given one.
    renewal: Option<Arc<Renewal>>,
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
        let listing = Arc::new(ArcSwap::from_pointee(listing_json(
            &first.session,
            &services,
        )));
        let current = Arc::new(ArcSwap::from_pointee(first.session));
        let renewal = Arc::new(Renewal {
            client: client.clone(),
            vault,
            request,
            auth: auth.clone(),
            current: current.clone(),
            listing: listing.clone(),
            minted: minted.clone(),
        });
        let renewer = tokio::spawn(renew_loop(renewal.clone()));
        Ok(Self {
            client,
            auth,
            current,
            services,
            listing,
            minted,
            renewal: Some(renewal),
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
        let listing = Arc::new(ArcSwap::from_pointee(listing_json(
            &discovery.session,
            &discovery.services,
        )));
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
            listing,
            minted: Arc::new(Mutex::new(Vec::new())),
            renewal: None,
            renewer,
        })
    }

    /// What the session port serves at `/services`, kept current across
    /// renewals.
    pub fn listing(&self) -> Arc<ArcSwap<String>> {
        self.listing.clone()
    }

    /// Renews a minted session now instead of when it is due. A given
    /// session cannot be renewed here.
    pub async fn renew_now(&self) -> Result<(), LauncherError> {
        match &self.renewal {
            Some(renewal) => renewal.once().await.map(|_| ()),
            None => Err(LauncherError::config(
                "a given session token is used as is; create a new session to renew it",
            )),
        }
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

/// The bundle and the services a session reaches, as the session port
/// serves them: no token and no secret.
fn listing_json(session: &ProxySession, services: &[DiscoveredService]) -> String {
    serde_json::to_string(&PortServices {
        bundle: session.bundle.as_ref().map(|b| b.name.clone()),
        services: services.to_vec(),
    })
    .unwrap_or_else(|_| r#"{"bundle":null,"services":[]}"#.to_string())
}

/// What renewing a minted session needs, and where it puts the result.
struct Renewal {
    client: Arc<ApiClient>,
    vault: VaultId,
    request: MintRequest,
    auth: Arc<ArcSwap<String>>,
    current: Arc<ArcSwap<ProxySession>>,
    listing: Arc<ArcSwap<String>>,
    minted: Minted,
}

impl Renewal {
    /// Mints the next session from the bundle and switches to it. Returns
    /// when the new one expires.
    async fn once(&self) -> Result<DateTime<Utc>, LauncherError> {
        let previous = self.current.load().id;
        let request = MintRequest {
            renews: Some(previous),
            ..self.request.clone()
        };
        let next = self.client.mint(&self.vault, &request).await?;
        remember(&self.minted, next.session.expires_at, &next.token);
        self.auth.store(Arc::new(proxy_authorization(&next.token)));
        info!(previous = %previous, session_id = %next.session.id, expires_at = %next.session.expires_at, "session renewed");
        // The bundle may hold other services by now; what the agent can ask
        // about follows. Placeholders already exported to its environment
        // cannot change.
        match self.client.discover(&next.token).await {
            Ok(discovery) => {
                self.listing
                    .store(Arc::new(listing_json(&next.session, &discovery.services)));
            }
            Err(e) => {
                warn!(error = %e, "could not list the renewed session's services; keeping the previous list");
            }
        }
        let expires_at = next.session.expires_at;
        self.current.store(Arc::new(next.session));
        Ok(expires_at)
    }
}

async fn renew_loop(renewal: Arc<Renewal>) {
    let ttl_secs = renewal.request.ttl_secs;
    let mut backoff = Duration::from_secs(5);
    let mut wait = renew_in(Utc::now(), renewal.current.load().expires_at, ttl_secs);
    loop {
        tokio::time::sleep(wait).await;
        match renewal.once().await {
            Ok(expires_at) => {
                wait = renew_in(Utc::now(), expires_at, ttl_secs);
                backoff = Duration::from_secs(5);
            }
            // The session was revoked: cut off by a proxy, or ended by a
            // person. Minting another would undo that.
            Err(e @ LauncherError::Api { status: 409, .. }) => {
                warn!(error = %e, "session revoked; not renewing it");
                eprintln!(
                    "tokenless: the session was revoked, so it is not renewed and the proxy refuses requests; stop this and start a new one once you have looked at why: {e}"
                );
                return;
            }
            Err(e) => {
                let expires_at = renewal.current.load().expires_at;
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
