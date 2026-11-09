// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit export: sends audit events to webhook receivers an admin names,
//! such as a SIEM's HTTP input.
//!
//! The audit log is the outbox. Each destination keeps a cursor, the
//! sequence number of the last event it has been sent, and a sender posts
//! the events after it in order, in batches, moving the cursor only once
//! the receiver answers 2xx. A failed batch is retried from the same
//! cursor with backoff, so nothing is skipped or reordered, and a receiver
//! that was down gets everything when it is back. Delivery is at least
//! once: every event carries its id and sequence number for deduplication.
//!
//! Requests are signed the Standard Webhooks way
//! ([`tokenless_auth::webhook`]). Sending records no audit events of its own,
//! which would feed itself; failures go to the log and to the
//! destination's status.

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokenless_auth::webhook;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{AuditDestinationId, VaultId};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{info, warn};
use url::Url;
use zeroize::Zeroizing;

use super::sso::oidc::check_url;
use super::{AuditRecorder, Caller, Guard};
use crate::cipher::{KeyScope, SecretCipher};
use crate::error::{ControlError, StoreError};
use crate::model::{
    AuditDestination, AuditFilter, DeliveryState, PayloadFormat, MAX_AUDIT_DESTINATIONS,
};
use crate::store::{AuditExportStore, PolicyStore};

/// The most events in one request.
pub const BATCH_EVENTS: usize = 500;
/// The most bytes in one request body, unless a single event is larger.
pub const MAX_BODY: usize = 1024 * 1024;
/// How often the sender looks for new events.
pub const POLL: StdDuration = StdDuration::from_secs(1);
/// After how long of failing a destination shows as failing, not retrying.
pub const FAILING_AFTER_SECS: i64 = 15 * 60;
/// The longest wait between retries.
pub const MAX_BACKOFF: StdDuration = StdDuration::from_secs(300);
/// Batches one pass sends before letting the others have a turn.
const BATCHES_PER_PASS: usize = 20;
/// How much of a receiver's error is kept.
const MAX_ERROR_LEN: usize = 500;
const MAX_ACTION_PREFIXES: usize = 20;
const MAX_VAULT_FILTERS: usize = 50;
/// Headers the sender sets itself, which a destination cannot override.
const RESERVED_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "content-type",
    "host",
    "transfer-encoding",
    "user-agent",
];

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One request to a receiver.
#[derive(Clone)]
pub struct WebhookRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

tokenless_core::redacted_debug!(WebhookRequest { url; headers, body });

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{reason}")]
pub struct WebhookError {
    pub reason: String,
}

/// How the control plane reaches webhook receivers. The server supplies one
/// over HTTPS with timeouts; tests supply a fake.
#[async_trait]
pub trait WebhookTransport: Send + Sync {
    /// POSTs the request and returns the status the receiver answered.
    async fn post(&self, request: WebhookRequest) -> Result<u16, WebhookError>;
}

/// For a control plane that sends no webhooks.
pub struct DisabledWebhookTransport;

#[async_trait]
impl WebhookTransport for DisabledWebhookTransport {
    async fn post(&self, _request: WebhookRequest) -> Result<u16, WebhookError> {
        Err(WebhookError {
            reason: "this control plane sends no webhooks".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// API shapes
// ---------------------------------------------------------------------------

/// Where a destination stands, as the console shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Every event so far has been sent.
    UpToDate,
    /// Events are waiting and are being sent.
    Sending,
    /// The last attempt failed; it is being retried.
    Retrying,
    /// Failing for longer than [`FAILING_AFTER_SECS`].
    Failing,
    /// Paused by an admin.
    Paused,
}

/// A destination as the API shows it: never the signing secret or the
/// auth header's value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditDestinationView {
    pub id: AuditDestinationId,
    pub name: String,
    pub url: String,
    pub format: PayloadFormat,
    pub auth_header_name: Option<String>,
    pub has_auth_header: bool,
    pub filter: AuditFilter,
    pub paused: bool,
    pub status: DeliveryStatus,
    /// Events recorded after the cursor: not sent yet (or not looked at,
    /// when the filter passes over them).
    pub behind: u64,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub failing_since: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuditDestinationView {
    fn new(d: &AuditDestination, latest: u64, now: DateTime<Utc>) -> Self {
        let behind = latest.saturating_sub(d.delivery.cursor);
        let status = if d.paused {
            DeliveryStatus::Paused
        } else if let Some(since) = d.delivery.failing_since {
            if now - since >= Duration::seconds(FAILING_AFTER_SECS) {
                DeliveryStatus::Failing
            } else {
                DeliveryStatus::Retrying
            }
        } else if behind > 0 {
            DeliveryStatus::Sending
        } else {
            DeliveryStatus::UpToDate
        };
        Self {
            id: d.id,
            name: d.name.clone(),
            url: d.url.clone(),
            format: d.format,
            auth_header_name: d.auth_header_name.clone(),
            has_auth_header: d.auth_header_value_enc.is_some(),
            filter: d.filter.clone(),
            paused: d.paused,
            status,
            behind,
            last_success_at: d.delivery.last_success_at,
            last_attempt_at: d.delivery.last_attempt_at,
            failing_since: d.delivery.failing_since,
            last_error: d.delivery.last_error.clone(),
            consecutive_failures: d.delivery.consecutive_failures,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// A destination's settings, to create one or replace them.
#[derive(Clone, Deserialize)]
pub struct AuditDestinationInput {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub format: PayloadFormat,
    /// With `auth_header_value`, one extra header sent with every request.
    #[serde(default)]
    pub auth_header_name: Option<String>,
    /// Write-only. On a replace, leaving it out keeps the stored value as
    /// long as the name is unchanged.
    #[serde(default)]
    pub auth_header_value: Option<String>,
    /// Remove the stored auth header.
    #[serde(default)]
    pub clear_auth_header: bool,
    #[serde(default)]
    pub filter: AuditFilter,
}

tokenless_core::redacted_debug!(AuditDestinationInput {
    name, url, format, auth_header_name, clear_auth_header, filter;
    auth_header_value
});

/// Where a new destination's first batch starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartAt {
    /// After the newest event: only what happens from now on.
    #[default]
    Now,
    /// From the oldest event, sending the whole history first.
    Oldest,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateAuditDestination {
    #[serde(flatten)]
    pub destination: AuditDestinationInput,
    #[serde(default)]
    pub start_at: StartAt,
}

/// A new destination and its signing secret, shown this once.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreatedAuditDestination {
    pub destination: AuditDestinationView,
    pub signing_secret: String,
}

tokenless_core::redacted_debug!(CreatedAuditDestination { destination; signing_secret });

/// A replaced signing secret, shown this once.
#[derive(Clone, Serialize, Deserialize)]
pub struct RotatedSigningSecret {
    pub signing_secret: String,
}

tokenless_core::redacted_debug!(RotatedSigningSecret { ; signing_secret });

/// What a test request got back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryTest {
    pub delivered: bool,
    pub status: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedEvents {
    pub skipped: u64,
}

/// What one delivery pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryPass {
    /// Requests that got a 2xx.
    pub batches: usize,
    /// Events sent in them.
    pub events: usize,
    /// Events the filter passed over.
    pub passed_over: usize,
    /// Why the pass stopped early, when a request failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Backoff {
    failures: u32,
    next_at: Instant,
}

fn backoff_delay(failures: u32) -> StdDuration {
    let exp = failures.saturating_sub(1).min(16);
    StdDuration::from_secs(1u64 << exp).min(MAX_BACKOFF)
}

/// A receiver's scheme, host and port, for audit details and logs. Some
/// receivers carry an ingest token in the path or query (it cannot always go
/// in a header), and the audit log is readable beyond the admins who manage
/// destinations, and is itself exported.
fn origin(url: &str) -> String {
    Url::parse(url)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|_| "an unreadable URL".to_string())
}

/// `reason` with the receiver's URL cut down to its [`origin`], wherever a
/// transport quoted it, as typed or normalized: a failure is logged, kept as
/// the destination's last error and shown to whoever sends a test.
fn without_url(reason: String, url: &str) -> String {
    let mut forms = vec![url.to_string()];
    if let Ok(parsed) = Url::parse(url) {
        forms.push(parsed.to_string());
    }
    // The longer first, so a form that contains another goes whole.
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    let short = origin(url);
    forms
        .iter()
        .filter(|f| !f.is_empty() && **f != short)
        .fold(reason, |r, f| r.replace(f.as_str(), &short))
}

fn validation(message: impl Into<String>) -> ControlError {
    ControlError::validation(message)
}

fn secret_aad(id: &AuditDestinationId) -> Vec<u8> {
    format!("audit-destination-secret|{id}").into_bytes()
}

fn header_aad(id: &AuditDestinationId) -> Vec<u8> {
    format!("audit-destination-header|{id}").into_bytes()
}

fn check_name(value: &str) -> Result<String, ControlError> {
    let v = value.trim();
    if v.is_empty() || v.chars().count() > 60 || v.chars().any(char::is_control) {
        return Err(validation("name must be 1-60 characters"));
    }
    Ok(v.to_string())
}

fn check_destination_url(value: &str) -> Result<String, ControlError> {
    let raw = value.trim();
    if raw.len() > 2048 {
        return Err(validation("url must be at most 2048 characters"));
    }
    let url = check_url("url", raw).map_err(|e| {
        validation(format!(
            "{e}; put a receiver's token in the auth header, not the URL"
        ))
    })?;
    Ok(url.to_string())
}

fn check_header_name(value: &str) -> Result<String, ControlError> {
    let v = value.trim();
    let token = !v.is_empty()
        && v.len() <= 64
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c));
    if !token {
        return Err(validation(format!(
            "auth header name '{v}' must be 1-64 characters of letters, digits and !#$%&'*+-.^_`|~"
        )));
    }
    let lower = v.to_ascii_lowercase();
    if RESERVED_HEADERS.contains(&lower.as_str()) || lower.starts_with("webhook-") {
        return Err(validation(format!(
            "auth header '{v}' is set by tokenless itself; use another header"
        )));
    }
    Ok(v.to_string())
}

fn check_header_value(value: &str) -> Result<&str, ControlError> {
    let v = value.trim();
    let ok = !v.is_empty()
        && v.len() <= 4096
        && v.chars().all(|c| c == '\t' || (' '..='~').contains(&c));
    if !ok {
        return Err(validation(
            "auth header value must be 1-4096 printable ASCII characters",
        ));
    }
    Ok(v)
}

fn check_action_prefix(value: &str) -> Result<String, ControlError> {
    let v = value.trim();
    let ok = (1..=64).contains(&v.len())
        && v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_');
    if !ok {
        return Err(validation(format!(
            "action prefix '{v}' must be 1-64 characters of a-z, 0-9, '.' and '_', such as 'credential.' or 'proxy.inject'"
        )));
    }
    Ok(v.to_string())
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_ERROR_LEN {
        let mut end = MAX_ERROR_LEN;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}

/// An event as a receiver gets it: the audit record and its sequence number.
#[derive(Serialize)]
struct Exported<'a> {
    seq: u64,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

/// The events of one request, already serialized, and the cursor range
/// they cover.
struct Batch {
    from: u64,
    to: u64,
    lines: Vec<Vec<u8>>,
    passed_over: usize,
    /// [`filter_fingerprint`] of the filter that chose the lines.
    filter: Option<String>,
}

impl Batch {
    /// The same for every attempt at the same events: the range, and the
    /// filter that chose them from it. A retry after pausing, renaming or a
    /// new secret keeps it; a retry under another filter carries other
    /// events from the same range, so it gets another.
    fn id(&self, destination: &AuditDestinationId) -> String {
        match &self.filter {
            Some(f) => format!("{destination}.{}-{}.{f}", self.from + 1, self.to),
            None => format!("{destination}.{}-{}", self.from + 1, self.to),
        }
    }
}

/// A short, stable name for a filter, `None` for the empty one that matches
/// everything. The lists are sorted first, so the order an admin typed them
/// in does not matter.
fn filter_fingerprint(filter: &AuditFilter) -> Option<String> {
    if filter.action_prefixes.is_empty()
        && filter.outcomes.is_empty()
        && filter.vault_ids.is_empty()
    {
        return None;
    }
    let lists: [Vec<String>; 3] = [
        filter.action_prefixes.clone(),
        filter
            .outcomes
            .iter()
            .map(|o| o.as_str().to_string())
            .collect(),
        filter.vault_ids.iter().map(ToString::to_string).collect(),
    ];
    let mut hash = Sha256::new();
    for mut list in lists {
        list.sort();
        for item in list {
            hash.update(item.as_bytes());
            hash.update([0]);
        }
        hash.update([1]);
    }
    let digest = hash.finalize();
    Some(format!("f{}", hex::encode(&digest[..6])))
}

fn body(format: PayloadFormat, batch_id: &str, lines: &[Vec<u8>]) -> Vec<u8> {
    let size: usize = lines.iter().map(|l| l.len() + 1).sum();
    let mut out = Vec::with_capacity(size + 128);
    match format {
        PayloadFormat::Json => {
            out.extend_from_slice(br#"{"type":"tokenless.audit","version":1,"batch_id":"#);
            // A batch id is the destination id and two numbers: no escaping.
            out.push(b'"');
            out.extend_from_slice(batch_id.as_bytes());
            out.extend_from_slice(br#"","events":["#);
            for (i, line) in lines.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(line);
            }
            out.extend_from_slice(b"]}");
        }
        PayloadFormat::Ndjson => {
            for line in lines {
                out.extend_from_slice(line);
                out.push(b'\n');
            }
        }
    }
    out
}

#[derive(Clone)]
pub struct AuditExportService {
    store: Arc<dyn AuditExportStore>,
    policy: Arc<dyn PolicyStore>,
    cipher: Arc<dyn SecretCipher>,
    guard: Guard,
    recorder: AuditRecorder,
    transport: Arc<dyn WebhookTransport>,
    backoff: Arc<Mutex<HashMap<AuditDestinationId, Backoff>>>,
}

impl AuditExportService {
    pub fn new(
        store: Arc<dyn AuditExportStore>,
        policy: Arc<dyn PolicyStore>,
        cipher: Arc<dyn SecretCipher>,
        guard: Guard,
        recorder: AuditRecorder,
        transport: Arc<dyn WebhookTransport>,
    ) -> Self {
        Self {
            store,
            policy,
            cipher,
            guard,
            recorder,
            transport,
            backoff: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn destination(&self, id: &AuditDestinationId) -> Result<AuditDestination, ControlError> {
        self.store
            .get_audit_destination(id)
            .await?
            .ok_or_else(|| ControlError::not_found("audit destination", id))
    }

    async fn view(&self, d: &AuditDestination) -> Result<AuditDestinationView, ControlError> {
        let latest = self.store.latest_audit_seq().await?;
        Ok(AuditDestinationView::new(d, latest, Utc::now()))
    }

    /// Admin-only, like identity providers.
    pub async fn list(&self, caller: &Caller) -> Result<Vec<AuditDestinationView>, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        let latest = self.store.latest_audit_seq().await?;
        let now = Utc::now();
        Ok(self
            .store
            .list_audit_destinations()
            .await?
            .iter()
            .map(|d| AuditDestinationView::new(d, latest, now))
            .collect())
    }

    pub async fn get(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
    ) -> Result<AuditDestinationView, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        let d = self.destination(id).await?;
        self.view(&d).await
    }

    async fn check_filter(&self, filter: &AuditFilter) -> Result<AuditFilter, ControlError> {
        if filter.action_prefixes.len() > MAX_ACTION_PREFIXES {
            return Err(validation(format!(
                "at most {MAX_ACTION_PREFIXES} action prefixes"
            )));
        }
        let mut action_prefixes: Vec<String> = Vec::new();
        for p in &filter.action_prefixes {
            let p = check_action_prefix(p)?;
            if !action_prefixes.contains(&p) {
                action_prefixes.push(p);
            }
        }
        let mut outcomes: Vec<AuditOutcome> = Vec::new();
        for o in &filter.outcomes {
            if !outcomes.contains(o) {
                outcomes.push(*o);
            }
        }
        if filter.vault_ids.len() > MAX_VAULT_FILTERS {
            return Err(validation(format!("at most {MAX_VAULT_FILTERS} vaults")));
        }
        let mut vault_ids: Vec<VaultId> = Vec::new();
        for v in &filter.vault_ids {
            if vault_ids.contains(v) {
                continue;
            }
            if self.policy.get_vault(v).await?.is_none() {
                return Err(validation(format!(
                    "vault {v} in the filter does not exist"
                )));
            }
            vault_ids.push(*v);
        }
        Ok(AuditFilter {
            action_prefixes,
            outcomes,
            vault_ids,
        })
    }

    /// Checks the settings and works out the auth header: the stored one is
    /// kept only while its name is unchanged and no new value is given.
    async fn checked(
        &self,
        id: AuditDestinationId,
        req: &AuditDestinationInput,
        current: Option<&AuditDestination>,
    ) -> Result<(String, String, Option<String>, Option<Vec<u8>>, AuditFilter), ControlError> {
        let name = check_name(&req.name)?;
        let url = check_destination_url(&req.url)?;
        let filter = self.check_filter(&req.filter).await?;
        let header_name = req
            .auth_header_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(check_header_name)
            .transpose()?;
        let value = req
            .auth_header_value
            .as_deref()
            .filter(|v| !v.trim().is_empty());
        let header = match (req.clear_auth_header, header_name, value) {
            (true, None, None) => (None, None),
            (true, _, _) => {
                return Err(validation(
                    "send a new auth header or clear_auth_header, not both",
                ))
            }
            // Leaving the name out removes the header.
            (false, None, None) => (None, None),
            (false, None, Some(_)) => {
                return Err(validation("auth_header_value needs an auth_header_name"))
            }
            (false, Some(name), Some(value)) => {
                let value = check_header_value(value)?;
                let enc = self
                    .cipher
                    .encrypt(KeyScope::Instance, value.as_bytes(), &header_aad(&id))
                    .await?;
                (Some(name), Some(enc))
            }
            (false, Some(name), None) => match current {
                Some(c)
                    if c.auth_header_name.as_deref() == Some(name.as_str())
                        && c.auth_header_value_enc.is_some() =>
                {
                    (Some(name), c.auth_header_value_enc.clone())
                }
                _ => return Err(validation(format!("auth header '{name}' needs a value"))),
            },
        };
        Ok((name, url, header.0, header.1, filter))
    }

    pub async fn create(
        &self,
        caller: &Caller,
        req: CreateAuditDestination,
    ) -> Result<CreatedAuditDestination, ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        if self.store.list_audit_destinations().await?.len() >= MAX_AUDIT_DESTINATIONS {
            return Err(validation(format!(
                "an instance sends to at most {MAX_AUDIT_DESTINATIONS} audit destinations"
            )));
        }
        let id = AuditDestinationId::new();
        let (name, url, auth_header_name, auth_header_value_enc, filter) =
            self.checked(id, &req.destination, None).await?;
        let secret = Zeroizing::new(webhook::new_secret());
        let signing_secret_enc = self
            .cipher
            .encrypt(KeyScope::Instance, secret.as_bytes(), &secret_aad(&id))
            .await?;
        let cursor = match req.start_at {
            StartAt::Now => self.store.latest_audit_seq().await?,
            StartAt::Oldest => 0,
        };
        let now = Utc::now();
        let destination = AuditDestination {
            id,
            name,
            url,
            format: req.destination.format,
            auth_header_name,
            auth_header_value_enc,
            signing_secret_enc,
            filter,
            paused: false,
            created_at: now,
            updated_at: now,
            delivery: DeliveryState {
                cursor,
                ..DeliveryState::default()
            },
        };
        let event = AuditEvent::new(caller.actor(), "audit_export.create", AuditOutcome::Success)
            .target(format!("audit_destination:{id}"))
            .detail("name", destination.name.clone())
            .detail("url", origin(&destination.url))
            .detail(
                "start_at",
                match req.start_at {
                    StartAt::Now => "now",
                    StartAt::Oldest => "oldest",
                },
            );
        match self
            .store
            .insert_audit_destination(destination.clone(), &[event])
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict { .. }) => {
                return Err(ControlError::Conflict {
                    message: format!("an audit destination named '{}' exists", destination.name),
                })
            }
            Err(e) => return Err(e.into()),
        }
        info!(destination = %destination.name, url = %origin(&destination.url), "audit destination added");
        Ok(CreatedAuditDestination {
            destination: self.view(&destination).await?,
            signing_secret: secret.to_string(),
        })
    }

    pub async fn update(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
        req: AuditDestinationInput,
    ) -> Result<AuditDestinationView, ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        let current = self.destination(id).await?;
        let (name, url, auth_header_name, auth_header_value_enc, filter) =
            self.checked(*id, &req, Some(&current)).await?;
        let updated = AuditDestination {
            name,
            url,
            format: req.format,
            auth_header_name,
            auth_header_value_enc,
            filter,
            updated_at: Utc::now(),
            ..current.clone()
        };
        let event = AuditEvent::new(caller.actor(), "audit_export.update", AuditOutcome::Success)
            .target(format!("audit_destination:{id}"))
            .detail("name", updated.name.clone())
            .detail("url", origin(&updated.url));
        let view = self.store_update(updated, &[event]).await?;
        // New settings are usually the fix for a failing receiver: try them
        // now, not after the last backoff ran out.
        self.forget_backoff(id);
        Ok(view)
    }

    async fn store_update(
        &self,
        updated: AuditDestination,
        audit: &[AuditEvent],
    ) -> Result<AuditDestinationView, ControlError> {
        match self
            .store
            .update_audit_destination(updated.clone(), audit)
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict { .. }) => {
                return Err(ControlError::Conflict {
                    message: format!("an audit destination named '{}' exists", updated.name),
                })
            }
            Err(StoreError::NotFound { .. }) => {
                return Err(ControlError::not_found("audit destination", updated.id))
            }
            Err(e) => return Err(e.into()),
        }
        // Delivery state is the store's; read it back for the view.
        let stored = self.destination(&updated.id).await?;
        self.view(&stored).await
    }

    pub async fn delete(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
    ) -> Result<(), ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        let current = self.destination(id).await?;
        let event = AuditEvent::new(caller.actor(), "audit_export.delete", AuditOutcome::Success)
            .target(format!("audit_destination:{id}"))
            .detail("name", current.name.clone());
        match self.store.delete_audit_destination(id, &[event]).await {
            Ok(()) => {}
            Err(StoreError::NotFound { .. }) => {
                return Err(ControlError::not_found("audit destination", id))
            }
            Err(e) => return Err(e.into()),
        }
        self.forget_backoff(id);
        info!(destination = %current.name, "audit destination removed");
        Ok(())
    }

    pub async fn set_paused(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
        paused: bool,
    ) -> Result<AuditDestinationView, ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        let current = self.destination(id).await?;
        let action = if paused {
            "audit_export.pause"
        } else {
            "audit_export.resume"
        };
        let event = AuditEvent::new(caller.actor(), action, AuditOutcome::Success)
            .target(format!("audit_destination:{id}"))
            .detail("name", current.name.clone());
        let updated = AuditDestination {
            paused,
            updated_at: Utc::now(),
            ..current
        };
        let view = self.store_update(updated, &[event]).await?;
        if !paused {
            // Resuming means now, not after the last backoff ran out.
            self.forget_backoff(id);
        }
        Ok(view)
    }

    pub async fn rotate_secret(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
    ) -> Result<RotatedSigningSecret, ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        let current = self.destination(id).await?;
        let secret = Zeroizing::new(webhook::new_secret());
        let signing_secret_enc = self
            .cipher
            .encrypt(KeyScope::Instance, secret.as_bytes(), &secret_aad(id))
            .await?;
        let event = AuditEvent::new(
            caller.actor(),
            "audit_export.rotate_secret",
            AuditOutcome::Success,
        )
        .target(format!("audit_destination:{id}"))
        .detail("name", current.name.clone());
        let updated = AuditDestination {
            signing_secret_enc,
            updated_at: Utc::now(),
            ..current
        };
        self.store_update(updated, &[event]).await?;
        // As for new settings: a receiver that refused the old signature
        // may take the new one.
        self.forget_backoff(id);
        Ok(RotatedSigningSecret {
            signing_secret: secret.to_string(),
        })
    }

    /// Moves the cursor to the newest event, dropping the backlog for this
    /// destination. Only ever an admin's explicit choice.
    pub async fn skip_to_now(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
    ) -> Result<SkippedEvents, ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        let current = self.destination(id).await?;
        let latest = self.store.latest_audit_seq().await?;
        let skipped = latest.saturating_sub(current.delivery.cursor);
        let event = AuditEvent::new(caller.actor(), "audit_export.skip", AuditOutcome::Success)
            .target(format!("audit_destination:{id}"))
            .detail("name", current.name.clone())
            .detail("skipped", skipped.to_string());
        // The skip's own event lands after `latest` and is sent as usual.
        match self.store.set_audit_cursor(id, latest, &[event]).await {
            Ok(()) => {}
            Err(StoreError::NotFound { .. }) => {
                return Err(ControlError::not_found("audit destination", id))
            }
            Err(e) => return Err(e.into()),
        }
        self.forget_backoff(id);
        warn!(destination = %current.name, skipped, "audit destination skipped its backlog");
        Ok(SkippedEvents { skipped })
    }

    /// Sends one made-up event, without touching the cursor, so an admin
    /// can check the receiver before real events go.
    pub async fn test(
        &self,
        caller: &Caller,
        id: &AuditDestinationId,
    ) -> Result<DeliveryTest, ControlError> {
        self.guard
            .check(caller, Action::AuditExportManage, None)
            .await?;
        let d = self.destination(id).await?;
        let sample = AuditEvent::new(caller.actor(), "audit_export.test", AuditOutcome::Success)
            .target(format!("audit_destination:{id}"))
            .detail("note", "a test event; it is not in the audit log");
        let line = serde_json::to_vec(&Exported {
            seq: 0,
            event: &sample,
        })
        .map_err(|e| validation(format!("could not encode the test event: {e}")))?;
        let batch_id = format!("{id}.test-{}", sample.id);
        let outcome = self.send(&d, &batch_id, &[line]).await;
        let (result, recorded) = match outcome {
            Ok(status) => (
                DeliveryTest {
                    delivered: true,
                    status: Some(status),
                    error: None,
                },
                AuditOutcome::Success,
            ),
            Err(SendError::Status(status)) => (
                DeliveryTest {
                    delivered: false,
                    status: Some(status),
                    error: Some(format!("the receiver answered {status}")),
                },
                AuditOutcome::Failure,
            ),
            Err(SendError::Other(reason)) => (
                DeliveryTest {
                    delivered: false,
                    status: None,
                    error: Some(truncate(reason)),
                },
                AuditOutcome::Failure,
            ),
        };
        let mut event = AuditEvent::new(caller.actor(), "audit_export.test", recorded)
            .target(format!("audit_destination:{id}"))
            .detail("name", d.name.clone());
        if let Some(status) = result.status {
            event = event.detail("status", status.to_string());
        }
        self.recorder.record(event).await;
        Ok(result)
    }

    // -- Delivery -----------------------------------------------------------

    fn forget_backoff(&self, id: &AuditDestinationId) {
        if let Ok(mut b) = self.backoff.lock() {
            b.remove(id);
        }
    }

    fn due(&self, id: &AuditDestinationId, now: Instant) -> bool {
        self.backoff
            .lock()
            .map(|b| b.get(id).is_none_or(|x| x.next_at <= now))
            .unwrap_or(true)
    }

    fn note_result(&self, id: &AuditDestinationId, failed: bool) {
        let Ok(mut b) = self.backoff.lock() else {
            return;
        };
        if failed {
            let failures = b.get(id).map_or(1, |x| x.failures.saturating_add(1));
            b.insert(
                *id,
                Backoff {
                    failures,
                    next_at: Instant::now() + backoff_delay(failures),
                },
            );
        } else {
            b.remove(id);
        }
    }

    /// The events after the cursor that fit one request: up to
    /// [`BATCH_EVENTS`], and up to [`MAX_BODY`] bytes unless the first alone
    /// is larger. Events the filter passes over still move the cursor.
    ///
    /// A retry stops where the failed batch did, so it is the same batch
    /// under the same ID even when newer events were written meanwhile.
    /// Events are numbered in commit order, so the events up to that point
    /// are still the first ones after the cursor.
    async fn next_batch(&self, d: &AuditDestination) -> Result<Option<Batch>, ControlError> {
        let from = d.delivery.cursor;
        let mut events = self.store.audit_events_after(from, BATCH_EVENTS).await?;
        if let Some(until) = d.delivery.retry_until.filter(|&until| until > from) {
            events.retain(|(seq, _)| *seq <= until);
        }
        if events.is_empty() {
            return Ok(None);
        }
        let mut batch = Batch {
            from,
            to: from,
            lines: Vec::new(),
            passed_over: 0,
            filter: filter_fingerprint(&d.filter),
        };
        let mut size = 0usize;
        for (seq, event) in &events {
            if !d.filter.matches(event) {
                batch.to = *seq;
                batch.passed_over += 1;
                continue;
            }
            let line = serde_json::to_vec(&Exported { seq: *seq, event })
                .map_err(|e| validation(format!("could not encode audit event {seq}: {e}")))?;
            if !batch.lines.is_empty() && size + line.len() + 1 > MAX_BODY {
                break;
            }
            size += line.len() + 1;
            batch.lines.push(line);
            batch.to = *seq;
        }
        Ok(Some(batch))
    }

    async fn send(
        &self,
        d: &AuditDestination,
        batch_id: &str,
        lines: &[Vec<u8>],
    ) -> Result<u16, SendError> {
        let fail = |e: ControlError| SendError::Other(e.to_string());
        let secret = self
            .cipher
            .decrypt(&d.signing_secret_enc, &secret_aad(&d.id))
            .await
            .map_err(fail)?;
        let secret = std::str::from_utf8(&secret)
            .map_err(|_| SendError::Other("the stored signing secret is not text".into()))?;
        let body = body(d.format, batch_id, lines);
        let timestamp = Utc::now().timestamp();
        let signature = webhook::sign(secret, batch_id, timestamp, &body)
            .map_err(|e| SendError::Other(format!("could not sign the request: {e}")))?;
        let mut headers = vec![
            (
                "content-type".to_string(),
                d.format.content_type().to_string(),
            ),
            (webhook::ID_HEADER.to_string(), batch_id.to_string()),
            (webhook::TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
            (webhook::SIGNATURE_HEADER.to_string(), signature),
        ];
        if let (Some(name), Some(enc)) = (&d.auth_header_name, &d.auth_header_value_enc) {
            let value = self
                .cipher
                .decrypt(enc, &header_aad(&d.id))
                .await
                .map_err(fail)?;
            let value = String::from_utf8(value.to_vec())
                .map_err(|_| SendError::Other("the stored auth header is not text".into()))?;
            headers.push((name.clone(), value));
        }
        let status = self
            .transport
            .post(WebhookRequest {
                url: d.url.clone(),
                headers,
                body,
            })
            .await
            .map_err(|e| SendError::Other(without_url(e.reason, &d.url)))?;
        if (200..300).contains(&status) {
            Ok(status)
        } else {
            Err(SendError::Status(status))
        }
    }

    /// Sends what is waiting for one destination: batch after batch until
    /// it is caught up, a request fails, or [`BATCHES_PER_PASS`] went.
    /// Nothing happens for a paused or deleted destination.
    pub async fn deliver(&self, id: &AuditDestinationId) -> Result<DeliveryPass, ControlError> {
        let mut pass = DeliveryPass::default();
        for _ in 0..BATCHES_PER_PASS {
            let Some(d) = self.store.get_audit_destination(id).await? else {
                break;
            };
            if d.paused {
                break;
            }
            let Some(batch) = self.next_batch(&d).await? else {
                break;
            };
            if !batch.lines.is_empty() {
                let batch_id = batch.id(&d.id);
                if let Err(e) = self.send(&d, &batch_id, &batch.lines).await {
                    let reason = truncate(match e {
                        SendError::Status(status) => format!("the receiver answered {status}"),
                        SendError::Other(reason) => reason,
                    });
                    warn!(
                        destination = %d.name,
                        batch = %batch_id,
                        error = %reason,
                        "audit export failed; it will be retried"
                    );
                    self.store
                        .record_audit_delivery_failure(
                            id,
                            batch.from,
                            batch.to,
                            &reason,
                            Utc::now(),
                        )
                        .await?;
                    pass.error = Some(reason);
                    break;
                }
            }
            if !self
                .store
                .advance_audit_cursor(id, batch.from, batch.to, Utc::now())
                .await?
            {
                // Skipped or deleted meanwhile; the next pass starts over.
                break;
            }
            if !batch.lines.is_empty() {
                pass.batches += 1;
                pass.events += batch.lines.len();
            }
            pass.passed_over += batch.passed_over;
        }
        Ok(pass)
    }

    /// Delivers to every destination for as long as the server runs: looks
    /// for new events every [`POLL`], runs one pass per destination that
    /// has some, at most one at a time per destination, and waits out the
    /// backoff after a failure. Dropping the future stops every pass.
    pub async fn run(&self) {
        let mut passes: JoinSet<AuditDestinationId> = JoinSet::new();
        let mut running: HashSet<AuditDestinationId> = HashSet::new();
        loop {
            while let Some(done) = passes.try_join_next() {
                if let Ok(id) = done {
                    running.remove(&id);
                }
            }
            if let Err(e) = self.dispatch(&mut passes, &mut running).await {
                warn!(error = %e, "audit export could not look for new events");
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn dispatch(
        &self,
        passes: &mut JoinSet<AuditDestinationId>,
        running: &mut HashSet<AuditDestinationId>,
    ) -> Result<(), ControlError> {
        let destinations = self.store.list_audit_destinations().await?;
        if destinations.is_empty() {
            return Ok(());
        }
        let latest = self.store.latest_audit_seq().await?;
        let now = Instant::now();
        for d in destinations {
            if d.paused
                || d.delivery.cursor >= latest
                || running.contains(&d.id)
                || !self.due(&d.id, now)
            {
                continue;
            }
            running.insert(d.id);
            let service = self.clone();
            passes.spawn(async move {
                let failed = match service.deliver(&d.id).await {
                    Ok(pass) => pass.error.is_some(),
                    Err(e) => {
                        warn!(destination = %d.name, error = %e, "audit export pass failed");
                        true
                    }
                };
                service.note_result(&d.id, failed);
                d.id
            });
        }
        Ok(())
    }
}

enum SendError {
    /// The receiver answered something other than 2xx.
    Status(u16),
    Other(String),
}
