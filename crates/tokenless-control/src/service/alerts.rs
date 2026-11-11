// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Alerts: the audit signals from the proxies that someone should look at
//! now. Each one is also an `alert.raised` audit event, so an audit
//! destination (a webhook) carries it out of tokenless.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{AlertId, NodeId, SessionId};
use tokenless_core::snapshot::{QuarantinePolicy, QUARANTINE_ACTION, TRIPWIRE_ACTION};
use tracing::{error, warn};

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::model::{
    Alert, AlertFilter, AlertKind, AlertSettings, Node, Page, PageRequest, RefusalThreshold,
};
use crate::store::{AlertStore, PolicyStore};

/// Sessions whose signals are tracked at once. Past it, the oldest refusal
/// windows are dropped first; a session not tracked raises no refusal or
/// second-proxy alert until there is room.
pub const MAX_TRACKED_SESSIONS: usize = 10_000;

/// How many open alerts there are, the newest, and when each signal last
/// fired, for a banner and the settings page.
#[derive(Debug, Clone, Serialize)]
pub struct AlertSummary {
    pub open: u64,
    pub latest: Option<Alert>,
    pub last_raised: Vec<LastRaised>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LastRaised {
    pub kind: AlertKind,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: DateTime<Utc>,
    refusals: u32,
    /// Raised in this window already, so a session refused on and on
    /// tries to store its alert once per window rather than per refusal.
    alerted: bool,
}

#[derive(Debug, Clone)]
struct FirstProxy {
    node_id: NodeId,
    name: String,
}

/// What the control plane remembers about recent sessions between audit
/// batches. In memory: a restart forgets it, which can only delay an alert.
#[derive(Default)]
struct Signals {
    refusals: HashMap<SessionId, Window>,
    first_proxy: HashMap<SessionId, FirstProxy>,
}

impl Signals {
    /// Makes room for one more session in `refusals`, dropping windows that
    /// can no longer count; false when there is still none.
    fn room_for_refusals(&mut self, now: DateTime<Utc>) -> bool {
        if self.refusals.len() < MAX_TRACKED_SESSIONS {
            return true;
        }
        let oldest = now - TimeDelta::seconds(i64::from(RefusalThreshold::MAX_WINDOW_SECS));
        self.refusals.retain(|_, w| w.start > oldest);
        self.refusals.len() < MAX_TRACKED_SESSIONS
    }
}

pub struct AlertService {
    alerts: Arc<dyn AlertStore>,
    policy: Arc<dyn PolicyStore>,
    guard: Guard,
    signals: Mutex<Signals>,
}

impl RefusalThreshold {
    pub const MIN_REFUSALS: u32 = QuarantinePolicy::MIN_REFUSALS;
    pub const MAX_REFUSALS: u32 = QuarantinePolicy::MAX_REFUSALS;
    pub const MIN_WINDOW_SECS: u32 = QuarantinePolicy::MIN_WINDOW_SECS;
    pub const MAX_WINDOW_SECS: u32 = QuarantinePolicy::MAX_WINDOW_SECS;
}

impl AlertSettings {
    pub fn validate(&self) -> Result<(), ControlError> {
        if let Some(t) = self.refusals {
            let refusals = RefusalThreshold::MIN_REFUSALS..=RefusalThreshold::MAX_REFUSALS;
            let window = RefusalThreshold::MIN_WINDOW_SECS..=RefusalThreshold::MAX_WINDOW_SECS;
            if !refusals.contains(&t.refusals) || !window.contains(&t.window_secs) {
                return Err(ControlError::validation(format!(
                    "an alert after {} refusals in {}s is out of range: refusals must be {}-{} and the window {}-{} seconds, or alerts.refusals null to turn it off",
                    t.refusals,
                    t.window_secs,
                    refusals.start(),
                    refusals.end(),
                    window.start(),
                    window.end()
                )));
            }
        }
        Ok(())
    }

    /// Whether going from `before` to `self` raises fewer alerts: a signal
    /// turned off, more refusals, or the same refusals over a shorter window.
    pub fn loosens(&self, before: &AlertSettings) -> bool {
        let refusals = match (before.refusals, self.refusals) {
            (Some(_), None) => true,
            (None, _) => false,
            (Some(b), Some(a)) => a.refusals > b.refusals || a.window_secs < b.window_secs,
        };
        refusals || (before.new_proxy && !self.new_proxy)
    }
}

fn short(id: &SessionId) -> String {
    id.to_string().chars().take(8).collect()
}

fn session_of(event: &AuditEvent) -> Option<SessionId> {
    event.detail.get("session_id")?.parse().ok()
}

/// The labels a session carried, so an alert says which agent it was.
fn labels_of(event: &AuditEvent) -> impl Iterator<Item = (String, String)> + '_ {
    event
        .detail
        .iter()
        .filter(|(k, _)| k.starts_with("label."))
        .map(|(k, v)| (k.clone(), v.clone()))
}

impl AlertService {
    pub fn new(alerts: Arc<dyn AlertStore>, policy: Arc<dyn PolicyStore>, guard: Guard) -> Self {
        Self {
            alerts,
            policy,
            guard,
            signals: Mutex::new(Signals::default()),
        }
    }

    /// Looks at a batch of audit events a proxy reported, already recorded,
    /// and raises the alerts they call for. A failure is logged: the events
    /// are in the audit log either way.
    pub async fn observe(&self, node: &Node, events: &[AuditEvent]) {
        let settings = match self.policy.get_settings().await {
            Ok(s) => s.alerts,
            Err(e) => {
                error!(node_id = %node.id, error = %e, "could not read alert settings; using the defaults");
                AlertSettings::default()
            }
        };
        for alert in self.signals(node, events, &settings) {
            let (kind, session) = (alert.kind, alert.session_id);
            if let Err(e) = self.raise(node, alert).await {
                error!(node_id = %node.id, kind = kind.as_str(), session_id = ?session, error = %e, "failed to raise an alert");
            }
        }
    }

    /// The alerts `events` raise, updating what is remembered about their
    /// sessions. No I/O, so the lock is never held across an await.
    fn signals(&self, node: &Node, events: &[AuditEvent], settings: &AlertSettings) -> Vec<Alert> {
        let mut raised = Vec::new();
        let mut signals = self.signals.lock().unwrap_or_else(PoisonError::into_inner);
        for event in events {
            let Some(session) = session_of(event) else {
                continue;
            };
            let alert = |kind: AlertKind, summary: String| {
                let mut detail: BTreeMap<String, String> = labels_of(event).collect();
                detail.insert("node".into(), node.name.clone());
                Alert {
                    id: AlertId::new(),
                    kind,
                    dedup_key: format!("{}:{session}", kind.as_str()),
                    summary,
                    vault_id: event.vault_id,
                    session_id: Some(session),
                    node_id: Some(node.id),
                    detail,
                    raised_at: Utc::now(),
                    acknowledged_at: None,
                    acknowledged_by: None,
                }
            };

            if event.action == TRIPWIRE_ACTION {
                let mut a = alert(
                    AlertKind::Tripwire,
                    format!(
                        "Session {} sent tripwire '{}' to {} through proxy '{}': someone took it from the agent's machine. The session was cut off and revoked.",
                        short(&session),
                        event.detail.get("tripwire").map_or("?", String::as_str),
                        event.detail.get("host").map_or("a host", String::as_str),
                        node.name,
                    ),
                );
                for key in ["tripwire", "tripwire_id", "found_in", "host"] {
                    if let Some(v) = event.detail.get(key) {
                        a.detail.insert(key.into(), v.clone());
                    }
                }
                raised.push(a);
                continue;
            }

            if event.action == QUARANTINE_ACTION {
                let mut a = alert(
                    AlertKind::Quarantine,
                    format!(
                        "Session {} was cut off by proxy '{}' after {} refusals in {}s, and revoked.",
                        short(&session),
                        node.name,
                        event.detail.get("refusals").map_or("repeated", String::as_str),
                        event.detail.get("window_secs").map_or("?", String::as_str),
                    ),
                );
                for key in ["refusals", "window_secs"] {
                    if let Some(v) = event.detail.get(key) {
                        a.detail.insert(key.into(), v.clone());
                    }
                }
                raised.push(a);
                continue;
            }

            if settings.new_proxy {
                match signals.first_proxy.get(&session) {
                    Some(first) if first.node_id != node.id => {
                        let mut a = alert(
                            AlertKind::NewProxy,
                            format!(
                                "Session {} was used through proxy '{}' after first using '{}': its token may have been copied off the machine.",
                                short(&session),
                                node.name,
                                first.name
                            ),
                        );
                        a.detail.insert("first_node".into(), first.name.clone());
                        a.detail
                            .insert("first_node_id".into(), first.node_id.to_string());
                        raised.push(a);
                    }
                    Some(_) => {}
                    None if signals.first_proxy.len() < MAX_TRACKED_SESSIONS => {
                        signals.first_proxy.insert(
                            session,
                            FirstProxy {
                                node_id: node.id,
                                name: node.name.clone(),
                            },
                        );
                    }
                    None => {
                        warn!(session_id = %session, limit = MAX_TRACKED_SESSIONS, "too many sessions tracked to tell which proxy this one first used");
                    }
                }
            }

            if let (Some(threshold), AuditOutcome::Denied) = (settings.refusals, event.outcome) {
                let window = TimeDelta::seconds(i64::from(threshold.window_secs));
                if !signals.refusals.contains_key(&session) && !signals.room_for_refusals(event.at)
                {
                    warn!(session_id = %session, limit = MAX_TRACKED_SESSIONS, "too many sessions tracked to count this one's refusals");
                    continue;
                }
                let fresh = Window {
                    start: event.at,
                    refusals: 0,
                    alerted: false,
                };
                let w = signals.refusals.entry(session).or_insert(fresh);
                if event.at - w.start > window {
                    *w = fresh;
                }
                w.refusals = w.refusals.saturating_add(1);
                // At or past it: a threshold lowered mid-window still fires.
                if w.refusals >= threshold.refusals && !w.alerted {
                    w.alerted = true;
                    let mut a =
                        alert(
                            AlertKind::Refusals,
                            format!(
                            "Session {} was refused {} times within {}s; the last was {} to {}.",
                            short(&session),
                            threshold.refusals,
                            threshold.window_secs,
                            event.action,
                            event.detail.get("host").map_or("an unknown host", String::as_str),
                        ),
                        );
                    a.detail
                        .insert("refusals".into(), threshold.refusals.to_string());
                    a.detail
                        .insert("window_secs".into(), threshold.window_secs.to_string());
                    raised.push(a);
                }
            }
        }
        raised
    }

    /// Records `alert` unless the same signal already raised one for its
    /// session, with an `alert.raised` audit event.
    async fn raise(&self, node: &Node, alert: Alert) -> Result<(), ControlError> {
        let mut event = AuditEvent::new(
            format!("node:{}", node.id),
            "alert.raised",
            AuditOutcome::Success,
        )
        .target(format!("alert:{}", alert.id))
        .detail("kind", alert.kind.as_str())
        .detail("summary", alert.summary.clone())
        .detail("node", node.name.clone());
        if let Some(vault) = alert.vault_id {
            event = event.vault(vault);
        }
        if let Some(session) = alert.session_id {
            event = event.detail("session_id", session.to_string());
        }
        let (kind, session) = (alert.kind, alert.session_id);
        if self.alerts.insert_alert(alert, &[event]).await? {
            warn!(node_id = %node.id, kind = kind.as_str(), session_id = ?session, "alert raised");
        }
        Ok(())
    }

    /// Newest first. A vault-bound caller only sees its vault's alerts.
    pub async fn list(
        &self,
        caller: &Caller,
        mut filter: AlertFilter,
        page: PageRequest,
    ) -> Result<Page<Alert>, ControlError> {
        if let Some(bound) = caller.principal.vault {
            filter.vault_id = Some(bound);
        }
        self.guard
            .check(caller, Action::AuditRead, filter.vault_id.as_ref())
            .await?;
        Ok(self.alerts.list_alerts(&filter, page).await?)
    }

    pub async fn summary(&self, caller: &Caller) -> Result<AlertSummary, ControlError> {
        let open = self
            .list(
                caller,
                AlertFilter {
                    open_only: true,
                    ..AlertFilter::default()
                },
                PageRequest::new(Some(1), Some(1)),
            )
            .await?;
        let mut last_raised = Vec::new();
        for kind in AlertKind::ALL {
            let newest = self
                .list(
                    caller,
                    AlertFilter {
                        kind: Some(kind),
                        ..AlertFilter::default()
                    },
                    PageRequest::new(Some(1), Some(1)),
                )
                .await?;
            if let Some(a) = newest.items.into_iter().next() {
                last_raised.push(LastRaised {
                    kind,
                    at: a.raised_at,
                });
            }
        }
        Ok(AlertSummary {
            open: open.total,
            latest: open.items.into_iter().next(),
            last_raised,
        })
    }

    /// Marks an alert seen. Acknowledging one already acknowledged leaves
    /// who did it first.
    pub async fn acknowledge(&self, caller: &Caller, id: &AlertId) -> Result<Alert, ControlError> {
        let alert = self
            .alerts
            .get_alert(id)
            .await?
            .ok_or_else(|| ControlError::not_found("alert", id))?;
        if let Some(bound) = caller.principal.vault {
            if alert.vault_id != Some(bound) {
                return Err(ControlError::not_found("alert", id));
            }
        }
        self.guard
            .check(caller, Action::AlertAcknowledge, alert.vault_id.as_ref())
            .await?;
        let mut event = AuditEvent::new(caller.actor(), "alert.acknowledge", AuditOutcome::Success)
            .target(format!("alert:{id}"))
            .detail("kind", alert.kind.as_str());
        if let Some(vault) = alert.vault_id {
            event = event.vault(vault);
        }
        self.alerts
            .acknowledge_alert(id, caller.actor(), Utc::now(), &[event])
            .await?;
        self.alerts
            .get_alert(id)
            .await?
            .ok_or_else(|| ControlError::not_found("alert", id))
    }
}

#[cfg(test)]
mod tests;
