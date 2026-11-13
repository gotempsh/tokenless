// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A person's sign-ins: the console tabs and CLI logins holding a session
//! of theirs. They list and revoke their own, or sign out everywhere else;
//! an admin signs someone out everywhere.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{SignInId, UserId};
use tracing::info;

use super::{AuthService, SessionAuth};
use crate::error::ControlError;
use crate::model::{Page, PageRequest, SignInScope, UiSession};
use crate::service::Caller;

/// What kind of client holds a sign-in, from its `User-Agent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInClient {
    /// `tokenless login`.
    Cli,
    Browser,
    /// It sent no `User-Agent`.
    Unknown,
}

impl SignInClient {
    pub fn of(user_agent: Option<&str>) -> Self {
        match user_agent {
            None => SignInClient::Unknown,
            Some(ua) if ua.starts_with("tokenless/") => SignInClient::Cli,
            Some(_) => SignInClient::Browser,
        }
    }
}

/// A short name for the client behind `user_agent`, such as "Firefox on
/// macOS" or "tokenless CLI 0.4.0".
pub fn describe_client(user_agent: Option<&str>) -> String {
    const BROWSERS: [(&str, &str); 5] = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ];
    const SYSTEMS: [(&str, &str); 8] = [
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android"),
        ("Windows", "Windows"),
        ("Macintosh", "macOS"),
        ("Mac OS X", "macOS"),
        ("CrOS", "ChromeOS"),
        ("Linux", "Linux"),
    ];
    let Some(ua) = user_agent else {
        return "unknown client".into();
    };
    if let Some(version) = ua.strip_prefix("tokenless/") {
        return format!("tokenless CLI {version}");
    }
    let find = |table: &[(&str, &'static str)]| {
        table
            .iter()
            .find(|(marker, _)| ua.contains(marker))
            .map(|(_, name)| *name)
    };
    match (find(&BROWSERS), find(&SYSTEMS)) {
        (Some(browser), Some(system)) => format!("{browser} on {system}"),
        (Some(browser), None) => browser.to_string(),
        (None, Some(system)) => format!("a browser on {system}"),
        (None, None) => ua
            .split_whitespace()
            .next()
            .unwrap_or(ua)
            .chars()
            .take(40)
            .collect(),
    }
}

/// One sign-in as its owner (or an admin) sees it; never its token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    pub id: SignInId,
    pub client: SignInClient,
    /// What signed in, for people: "Firefox on macOS".
    pub device: String,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// `launch` when it only starts sessions (`tokenless login`).
    pub scope: SignInScope,
    /// The sign-in that asked.
    pub current: bool,
}

impl SignIn {
    fn from_session(s: UiSession, current: Option<&SignInId>) -> Self {
        Self {
            client: SignInClient::of(s.user_agent.as_deref()),
            device: describe_client(s.user_agent.as_deref()),
            current: current == Some(&s.id),
            id: s.id,
            user_agent: s.user_agent,
            created_at: s.created_at,
            last_used_at: s.last_used_at,
            expires_at: s.expires_at,
            scope: s.scope,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInsRevoked {
    pub revoked: u64,
}

/// The time before which an unused sign-in has gone idle.
pub(super) fn idle_cutoff(
    idle_timeout_secs: Option<u64>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let secs = i64::try_from(idle_timeout_secs?).ok()?;
    Some(now - Duration::seconds(secs))
}

/// `7200` as "2 hours", `300` as "5 minutes".
pub(super) fn idle_words(secs: u64) -> String {
    let (n, unit) = match secs {
        s if s >= 86_400 && s % 86_400 == 0 => (s / 86_400, "day"),
        s if s >= 3600 && s % 3600 == 0 => (s / 3600, "hour"),
        s if s % 60 == 0 => (s / 60, "minute"),
        s => (s, "second"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

impl AuthService {
    async fn live_sign_ins(
        &self,
        user_id: &UserId,
        current: Option<&SignInId>,
        page: PageRequest,
    ) -> Result<Page<SignIn>, ControlError> {
        let now = Utc::now();
        let idle = self.sso.get_sign_in_settings().await?.idle_timeout_secs;
        let page = self
            .identity
            .list_ui_sessions(user_id, now, idle_cutoff(idle, now), page)
            .await?;
        Ok(Page {
            items: page
                .items
                .into_iter()
                .map(|s| SignIn::from_session(s, current))
                .collect(),
            total: page.total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    /// The signed-in person's sign-ins, newest first, the current one
    /// marked.
    pub async fn sign_ins(
        &self,
        auth: &SessionAuth,
        page: PageRequest,
    ) -> Result<Page<SignIn>, ControlError> {
        self.live_sign_ins(&auth.user.id, Some(&auth.sign_in_id), page)
            .await
    }

    /// Ends one of the signed-in person's sign-ins; the current one too,
    /// which signs them out. `NotFound` when they have no such sign-in.
    pub async fn revoke_sign_in(
        &self,
        auth: &SessionAuth,
        id: &SignInId,
    ) -> Result<(), ControlError> {
        let event = AuditEvent::new(
            auth.caller.actor(),
            "auth.sign_in_revoke",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", auth.user.id))
        .detail("sign_in", id.to_string());
        if !self
            .identity
            .delete_user_ui_session(&auth.user.id, id, &[event])
            .await?
        {
            return Err(ControlError::not_found("sign-in", id));
        }
        info!(user_id = %auth.user.id, sign_in = %id, "sign-in revoked by its owner");
        Ok(())
    }

    /// Ends every sign-in of the signed-in person but this one.
    pub async fn sign_out_elsewhere(
        &self,
        auth: &SessionAuth,
    ) -> Result<SignInsRevoked, ControlError> {
        let event = AuditEvent::new(
            auth.caller.actor(),
            "auth.sign_out_elsewhere",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", auth.user.id))
        .detail("kept", auth.sign_in_id.to_string());
        let revoked = self
            .identity
            .delete_user_ui_sessions(&auth.user.id, Some(&auth.token_hash), &[event])
            .await?;
        info!(user_id = %auth.user.id, revoked, "signed out everywhere else");
        Ok(SignInsRevoked { revoked })
    }

    /// Someone's sign-ins, for an admin.
    pub async fn user_sign_ins(
        &self,
        caller: &Caller,
        user_id: &UserId,
        page: PageRequest,
    ) -> Result<Page<SignIn>, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        self.identity
            .get_user(user_id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", user_id))?;
        self.live_sign_ins(user_id, None, page).await
    }

    /// Signs someone out everywhere, for an admin: a lost laptop, a
    /// suspected break-in. Their next request has to sign in again.
    pub async fn revoke_user_sign_ins(
        &self,
        caller: &Caller,
        user_id: &UserId,
    ) -> Result<SignInsRevoked, ControlError> {
        self.guard.check(caller, Action::UserManage, None).await?;
        let user = self
            .identity
            .get_user(user_id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", user_id))?;
        let event = AuditEvent::new(
            caller.actor(),
            "user.sign_ins_revoke",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", user.id))
        .detail("username", user.username.clone());
        let revoked = self
            .identity
            .delete_user_ui_sessions(&user.id, None, &[event])
            .await?;
        info!(user_id = %user.id, by = %caller.actor(), revoked, "user signed out everywhere by an admin");
        Ok(SignInsRevoked { revoked })
    }
}

#[cfg(test)]
mod tests;
