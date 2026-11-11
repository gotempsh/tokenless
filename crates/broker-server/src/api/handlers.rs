// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Thin HTTP handlers: authenticate, parse, call a service, shape the reply.
//! Authorisation, step-up and audit logging live in the services so that an
//! embedding control plane gets them too.

use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_auth::cookie::clear_session_cookie;
use tokenless_control::model::{
    AuditQuery, Page, PageRequest, SessionCursor, SessionListing, Settings,
};
use tokenless_control::service::auth::{
    AuthService, ChangePassword, CreateApiKey, DisableAuthenticator, EnableAuthenticator,
    LoginRequest, StepUpProof, TotpEnrollment, UserSummary,
};
use tokenless_control::service::bundles::{CreateBundle, UpdateBundle};
use tokenless_control::service::policy::{
    CreateCredential, CreateRule, RotateCredential, UpdateRule,
};
use tokenless_control::service::sessions::MintSession;
use tokenless_control::service::sso::SsoSignIn;
use tokenless_control::service::users::{
    AcceptInviteRequest, CreateInvite, InviteInfo, InviteIssued, UpdateUser,
};
use tokenless_control::service::variables::{CreateVariable, ReplaceVariable};
use tokenless_core::ids::{
    ApiKeyId, BundleId, CredentialId, InviteId, NodeId, RuleId, SessionId, UserId, VariableId,
    VaultId,
};
use tokenless_core::substitution::Substitution;
use tokenless_core::variables::CustomHeader;

use super::{ApiJson, ApiQuery, AppState, Authed};
use crate::error::ApiError;

type ApiResult<T> = Result<T, ApiError>;
type St = State<Arc<AppState>>;

fn parse_id<T: FromStr>(kind: &str, raw: &str) -> ApiResult<T> {
    raw.parse()
        .map_err(|_| ApiError::bad_request(format!("'{raw}' is not a valid {kind} id")))
}

#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

impl PageQuery {
    fn request(&self) -> PageRequest {
        PageRequest::new(self.page, self.page_size)
    }
}

/// A page of sessions; `active=true` keeps the live ones (neither revoked
/// nor expired). `after_created_at` with `after_id` (the last session of
/// the previous page) continues after it, so sessions minted or ended in
/// between neither repeat nor skip a row the way `page` can.
#[derive(Debug, Default, Deserialize)]
pub struct SessionPageQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    #[serde(default)]
    pub active: bool,
    pub after_created_at: Option<DateTime<Utc>>,
    pub after_id: Option<String>,
}

impl SessionPageQuery {
    fn request(&self) -> PageRequest {
        PageRequest::new(self.page, self.page_size)
    }

    fn listing(&self) -> ApiResult<SessionListing> {
        let after = match (&self.after_created_at, &self.after_id) {
            (Some(created_at), Some(id)) => Some(SessionCursor {
                created_at: *created_at,
                id: parse_id("session", id)?,
            }),
            (None, None) => None,
            _ => {
                return Err(ApiError::bad_request(
                    "after_created_at and after_id go together: pass the last session's created_at and id, or neither",
                ))
            }
        };
        Ok(SessionListing {
            active: self.active,
            after,
        })
    }
}

pub async fn not_found() -> ApiError {
    ApiError::Control(tokenless_control::ControlError::not_found(
        "route",
        "requested path",
    ))
}

// ----- sign-in and the account ------------------------------------------

#[derive(Serialize)]
pub struct SessionInfo {
    user: UserSummary,
    csrf_token: String,
    expires_at: DateTime<Utc>,
    step_up_at: Option<DateTime<Utc>>,
    /// The provider the person signs in and steps up with, when they use
    /// single sign-on.
    #[serde(skip_serializing_if = "Option::is_none")]
    sso: Option<SsoSignIn>,
}

pub async fn login(State(s): St, ApiJson(req): ApiJson<LoginRequest>) -> ApiResult<Response> {
    let outcome = s.control.auth.login(req).await?;
    let cookie = HeaderValue::from_str(&AuthService::session_cookie(&outcome))
        .map_err(|_| ApiError::bad_request("could not encode session cookie"))?;
    let body = SessionInfo {
        user: outcome.user.clone(),
        csrf_token: outcome.csrf_token.clone(),
        expires_at: outcome.expires_at,
        step_up_at: Some(Utc::now()),
        sso: None,
    };
    let mut response = Json(body).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

fn require_session(authed: &Authed) -> ApiResult<&tokenless_control::service::auth::SessionAuth> {
    authed.session.as_ref().ok_or_else(|| ApiError::Forbidden {
        reason: "this endpoint requires an interactive UI session, not an API key".into(),
    })
}

pub async fn logout(State(s): St, authed: Authed) -> ApiResult<Response> {
    let session = require_session(&authed)?;
    s.control.auth.logout(session).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie())
            .map_err(|_| ApiError::bad_request("could not encode session cookie"))?,
    );
    Ok(response)
}

pub async fn me(State(s): St, authed: Authed) -> ApiResult<Json<SessionInfo>> {
    let session = require_session(&authed)?;
    Ok(Json(SessionInfo {
        user: session.user.clone(),
        csrf_token: s.control.auth.csrf_token(&session.token_hash),
        expires_at: session.expires_at,
        step_up_at: session.caller.step_up_at,
        sso: s
            .control
            .sso
            .sign_in_of(session.user.sso_provider_id.as_ref())
            .await,
    }))
}

#[derive(Serialize)]
pub struct StepUpResponse {
    step_up_at: DateTime<Utc>,
}

pub async fn step_up(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<StepUpProof>,
) -> ApiResult<Json<StepUpResponse>> {
    let session = require_session(&authed)?;
    let at = s.control.auth.step_up(session, &req).await?;
    Ok(Json(StepUpResponse { step_up_at: at }))
}

/// Changes the signed-in person's password; other sessions of the account
/// end, this one stays.
pub async fn change_password(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<ChangePassword>,
) -> ApiResult<StatusCode> {
    let session = require_session(&authed)?;
    s.control.auth.change_password(session, &req).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A new authenticator secret for the signed-in person to add to an app.
/// Nothing is stored until `/auth/authenticator` confirms it with a code.
pub async fn authenticator_enrollment(
    State(s): St,
    authed: Authed,
) -> ApiResult<Json<TotpEnrollment>> {
    let session = require_session(&authed)?;
    Ok(Json(
        s.control.auth.new_totp_enrollment(&session.user.username)?,
    ))
}

pub async fn enable_authenticator(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<EnableAuthenticator>,
) -> ApiResult<Json<UserSummary>> {
    let session = require_session(&authed)?;
    Ok(Json(
        s.control.auth.enable_authenticator(session, &req).await?,
    ))
}

pub async fn disable_authenticator(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<DisableAuthenticator>,
) -> ApiResult<Json<UserSummary>> {
    let session = require_session(&authed)?;
    Ok(Json(
        s.control.auth.disable_authenticator(session, &req).await?,
    ))
}

// ----- vaults ------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateVaultRequest {
    name: String,
}

pub async fn create_vault(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<CreateVaultRequest>,
) -> ApiResult<impl IntoResponse> {
    let vault = s
        .control
        .policy
        .create_vault(&authed.caller, &req.name)
        .await?;
    Ok((StatusCode::CREATED, Json(vault)))
}

pub async fn list_vaults(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .policy
            .list_vaults(&authed.caller, q.request())
            .await?,
    ))
}

/// The caller's vaults with what a list shows of each: first services,
/// live sessions, last request.
pub async fn vault_overviews(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .vault_overviews(&authed.caller, q.request())
            .await?,
    ))
}

pub async fn vault_overview(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(
        s.control.vault_overview_by_id(&authed.caller, &id).await?,
    ))
}

pub async fn get_vault(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(s.control.policy.get_vault(&authed.caller, &id).await?))
}

#[derive(Deserialize, Default)]
pub struct DeleteVaultQuery {
    #[serde(default)]
    force: bool,
}

/// `DELETE /vaults/{id}[?force=true]`: removes the vault and everything in
/// it; `force` also ends live sessions instead of refusing.
pub async fn delete_vault(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiQuery(q): ApiQuery<DeleteVaultQuery>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(
        s.control
            .policy
            .delete_vault(&authed.caller, &id, q.force)
            .await?,
    ))
}

// ----- templates ---------------------------------------------------------

pub async fn list_templates(State(s): St, authed: Authed) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.control.policy.list_templates(&authed.caller).await?))
}

pub async fn get_template(
    State(s): St,
    authed: Authed,
    Path((template_id, version)): Path<(String, u32)>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .policy
            .get_template(&authed.caller, &template_id, version)
            .await?,
    ))
}

#[derive(Deserialize)]
pub struct ImportTemplateRequest {
    yaml: String,
}

pub async fn import_template(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<ImportTemplateRequest>,
) -> ApiResult<impl IntoResponse> {
    let t = s
        .control
        .policy
        .import_template(&authed.caller, &req.yaml)
        .await?;
    Ok((StatusCode::CREATED, Json(t)))
}

pub async fn approve_template(
    State(s): St,
    authed: Authed,
    Path((template_id, version)): Path<(String, u32)>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .policy
            .approve_template(&authed.caller, &template_id, version)
            .await?,
    ))
}

// ----- credentials (write-only) -------------------------------------------

pub async fn create_credential(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<CreateCredential>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    let meta = s
        .control
        .policy
        .create_credential(&authed.caller, &id, req)
        .await?;
    Ok((StatusCode::CREATED, Json(meta)))
}

pub async fn list_credentials(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(
        s.control
            .policy
            .list_credentials(&authed.caller, &id, q.request())
            .await?,
    ))
}

pub async fn get_credential(
    State(s): St,
    authed: Authed,
    Path(credential_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: CredentialId = parse_id("credential", &credential_id)?;
    Ok(Json(
        s.control.policy.get_credential(&authed.caller, &id).await?,
    ))
}

pub async fn rotate_credential(
    State(s): St,
    authed: Authed,
    Path(credential_id): Path<String>,
    ApiJson(req): ApiJson<RotateCredential>,
) -> ApiResult<impl IntoResponse> {
    let id: CredentialId = parse_id("credential", &credential_id)?;
    Ok(Json(
        s.control
            .policy
            .rotate_credential(&authed.caller, &id, req)
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomHeadersRequest {
    custom_headers: Vec<CustomHeader>,
}

pub async fn update_custom_headers(
    State(s): St,
    authed: Authed,
    Path(credential_id): Path<String>,
    ApiJson(req): ApiJson<CustomHeadersRequest>,
) -> ApiResult<impl IntoResponse> {
    let id: CredentialId = parse_id("credential", &credential_id)?;
    Ok(Json(
        s.control
            .policy
            .update_custom_headers(&authed.caller, &id, req.custom_headers)
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstitutionsRequest {
    substitutions: Vec<Substitution>,
}

pub async fn update_substitutions(
    State(s): St,
    authed: Authed,
    Path(credential_id): Path<String>,
    ApiJson(req): ApiJson<SubstitutionsRequest>,
) -> ApiResult<impl IntoResponse> {
    let id: CredentialId = parse_id("credential", &credential_id)?;
    Ok(Json(
        s.control
            .policy
            .update_substitutions(&authed.caller, &id, req.substitutions)
            .await?,
    ))
}

pub async fn list_variables(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .variables
            .list(&authed.caller, q.request())
            .await?,
    ))
}

pub async fn create_variable(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<CreateVariable>,
) -> ApiResult<impl IntoResponse> {
    let created = s.control.variables.create(&authed.caller, req).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// Replaces a variable's value. There is no endpoint that returns one.
pub async fn replace_variable(
    State(s): St,
    authed: Authed,
    Path(variable_id): Path<String>,
    ApiJson(req): ApiJson<ReplaceVariable>,
) -> ApiResult<impl IntoResponse> {
    let id: VariableId = parse_id("variable", &variable_id)?;
    Ok(Json(
        s.control
            .variables
            .replace_value(&authed.caller, &id, req.value)
            .await?,
    ))
}

pub async fn delete_variable(
    State(s): St,
    authed: Authed,
    Path(variable_id): Path<String>,
) -> ApiResult<StatusCode> {
    let id: VariableId = parse_id("variable", &variable_id)?;
    s.control.variables.delete(&authed.caller, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Runs the template's validation request with the stored credential.
/// Returns the outcome (status only), never the response body.
pub async fn validate_credential(
    State(s): St,
    authed: Authed,
    Path(credential_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: CredentialId = parse_id("credential", &credential_id)?;
    Ok(Json(
        s.control
            .policy
            .validate_credential(&authed.caller, &id)
            .await?,
    ))
}

pub async fn delete_credential(
    State(s): St,
    authed: Authed,
    Path(credential_id): Path<String>,
) -> ApiResult<StatusCode> {
    let id: CredentialId = parse_id("credential", &credential_id)?;
    s.control
        .policy
        .delete_credential(&authed.caller, &id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- rules -------------------------------------------------------------

pub async fn create_rule(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<CreateRule>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    let rule = s
        .control
        .policy
        .create_rule(&authed.caller, &id, req)
        .await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn list_rules(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(
        s.control
            .policy
            .list_rules(&authed.caller, &id, q.request())
            .await?,
    ))
}

pub async fn get_rule(
    State(s): St,
    authed: Authed,
    Path(rule_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: RuleId = parse_id("rule", &rule_id)?;
    Ok(Json(s.control.policy.get_rule(&authed.caller, &id).await?))
}

pub async fn update_rule(
    State(s): St,
    authed: Authed,
    Path(rule_id): Path<String>,
    ApiJson(req): ApiJson<UpdateRule>,
) -> ApiResult<impl IntoResponse> {
    let id: RuleId = parse_id("rule", &rule_id)?;
    Ok(Json(
        s.control
            .policy
            .update_rule(&authed.caller, &id, req)
            .await?,
    ))
}

pub async fn delete_rule(
    State(s): St,
    authed: Authed,
    Path(rule_id): Path<String>,
) -> ApiResult<StatusCode> {
    let id: RuleId = parse_id("rule", &rule_id)?;
    s.control.policy.delete_rule(&authed.caller, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn session_bearer(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.trim_start().starts_with("v4.public."))
        .ok_or_else(|| {
            ApiError::Control(tokenless_control::ControlError::Unauthenticated {
                reason: "send the proxy session token as 'Authorization: Bearer v4.public...'"
                    .into(),
            })
        })
}

/// `POST /sessions/revoke-self` with `Authorization: Bearer <session token>`.
/// Holding the token is the only credential needed to end that session.
pub async fn revoke_own_session(
    State(s): St,
    headers: axum::http::HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let token = session_bearer(&headers)?;
    Ok(Json(s.control.sessions.revoke_self(token).await?))
}

/// `GET /sessions/self` with `Authorization: Bearer <session token>`: the
/// services this session can reach and the placeholders they accept.
pub async fn discover_own_session(
    State(s): St,
    headers: axum::http::HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let token = session_bearer(&headers)?;
    Ok(Json(s.control.sessions.discover_self(token).await?))
}

// ----- access bundles ----------------------------------------------------

pub async fn create_bundle(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<CreateBundle>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    let bundle = s.control.bundles.create(&authed.caller, &id, req).await?;
    Ok((StatusCode::CREATED, Json(bundle)))
}

/// Access bundles across every vault the caller can see.
pub async fn list_all_bundles(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .bundles
            .list_all(&authed.caller, q.request())
            .await?,
    ))
}

pub async fn list_bundles(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(
        s.control
            .bundles
            .list(&authed.caller, &id, q.request())
            .await?,
    ))
}

pub async fn get_bundle(
    State(s): St,
    authed: Authed,
    Path(bundle_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: BundleId = parse_id("access bundle", &bundle_id)?;
    Ok(Json(s.control.bundles.get(&authed.caller, &id).await?))
}

pub async fn update_bundle(
    State(s): St,
    authed: Authed,
    Path(bundle_id): Path<String>,
    ApiJson(req): ApiJson<UpdateBundle>,
) -> ApiResult<impl IntoResponse> {
    let id: BundleId = parse_id("access bundle", &bundle_id)?;
    Ok(Json(
        s.control.bundles.update(&authed.caller, &id, req).await?,
    ))
}

pub async fn delete_bundle(
    State(s): St,
    authed: Authed,
    Path(bundle_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: BundleId = parse_id("access bundle", &bundle_id)?;
    Ok(Json(s.control.bundles.delete(&authed.caller, &id).await?))
}

// ----- proxy sessions ----------------------------------------------------

pub async fn mint_session(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<MintSession>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    let minted = s.control.sessions.mint(&authed.caller, &id, req).await?;
    Ok((StatusCode::CREATED, Json(minted)))
}

/// `GET /vaults/{id}/sessions/limits`: the lifetimes a new session may have.
pub async fn session_limits(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(s.control.sessions.limits(&authed.caller, &id).await?))
}

pub async fn list_sessions(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiQuery(q): ApiQuery<SessionPageQuery>,
) -> ApiResult<impl IntoResponse> {
    let id: VaultId = parse_id("vault", &vault_id)?;
    Ok(Json(
        s.control
            .sessions
            .list(&authed.caller, &id, q.listing()?, q.request())
            .await?,
    ))
}

/// Sessions across every vault the caller can see.
pub async fn list_all_sessions(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<SessionPageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .sessions
            .list_all(&authed.caller, q.listing()?, q.request())
            .await?,
    ))
}

/// Sessions minted from one access bundle.
pub async fn list_bundle_sessions(
    State(s): St,
    authed: Authed,
    Path(bundle_id): Path<String>,
    ApiQuery(q): ApiQuery<SessionPageQuery>,
) -> ApiResult<impl IntoResponse> {
    let id: BundleId = parse_id("access bundle", &bundle_id)?;
    Ok(Json(
        s.control
            .sessions
            .list_for_bundle(&authed.caller, &id, q.listing()?, q.request())
            .await?,
    ))
}

pub async fn get_session(
    State(s): St,
    authed: Authed,
    Path(session_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: SessionId = parse_id("session", &session_id)?;
    Ok(Json(s.control.sessions.get(&authed.caller, &id).await?))
}

/// What a session reaches, for the people who manage it.
pub async fn session_services(
    State(s): St,
    authed: Authed,
    Path(session_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: SessionId = parse_id("session", &session_id)?;
    Ok(Json(
        s.control.sessions.services(&authed.caller, &id).await?,
    ))
}

pub async fn revoke_session(
    State(s): St,
    authed: Authed,
    Path(session_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: SessionId = parse_id("session", &session_id)?;
    Ok(Json(s.control.sessions.revoke(&authed.caller, &id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSessionRequest {
    labels: std::collections::BTreeMap<String, String>,
}

/// `PATCH /sessions/{id}`: replaces the session's labels.
pub async fn update_session(
    State(s): St,
    authed: Authed,
    Path(session_id): Path<String>,
    ApiJson(req): ApiJson<UpdateSessionRequest>,
) -> ApiResult<impl IntoResponse> {
    let id: SessionId = parse_id("session", &session_id)?;
    Ok(Json(
        s.control
            .sessions
            .update_labels(&authed.caller, &id, req.labels)
            .await?,
    ))
}

// ----- API keys ----------------------------------------------------------

#[derive(Serialize)]
pub struct CreatedApiKey {
    /// Shown exactly once; only a hash is stored.
    api_key: String,
    key: tokenless_control::model::ApiKey,
}

pub async fn create_api_key(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<CreateApiKey>,
) -> ApiResult<impl IntoResponse> {
    let (api_key, key) = s.control.auth.create_api_key(&authed.caller, req).await?;
    Ok((StatusCode::CREATED, Json(CreatedApiKey { api_key, key })))
}

pub async fn list_api_keys(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .auth
            .list_api_keys(&authed.caller, q.request())
            .await?,
    ))
}

pub async fn revoke_api_key(
    State(s): St,
    authed: Authed,
    Path(api_key_id): Path<String>,
) -> ApiResult<StatusCode> {
    let id: ApiKeyId = parse_id("api key", &api_key_id)?;
    s.control.auth.revoke_api_key(&authed.caller, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- people --------------------------------------------------------------

pub async fn list_users(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<UserSummary>>> {
    Ok(Json(
        s.control
            .users
            .list_users(&authed.caller, q.request())
            .await?,
    ))
}

pub async fn update_user(
    State(s): St,
    authed: Authed,
    Path(user_id): Path<String>,
    ApiJson(req): ApiJson<UpdateUser>,
) -> ApiResult<Json<UserSummary>> {
    let id: UserId = parse_id("user", &user_id)?;
    Ok(Json(
        s.control
            .users
            .update_user(&authed.caller, &id, req)
            .await?,
    ))
}

pub async fn list_invites(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .users
            .list_invites(&authed.caller, q.request())
            .await?,
    ))
}

pub async fn create_invite(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<CreateInvite>,
) -> ApiResult<(StatusCode, Json<InviteIssued>)> {
    let issued = s.control.users.create_invite(&authed.caller, req).await?;
    Ok((StatusCode::CREATED, Json(issued)))
}

pub async fn revoke_invite(
    State(s): St,
    authed: Authed,
    Path(invite_id): Path<String>,
) -> ApiResult<StatusCode> {
    let id: InviteId = parse_id("invite", &invite_id)?;
    s.control.users.revoke_invite(&authed.caller, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct InviteTokenRequest {
    invite_token: String,
}

/// Unauthenticated: what an invite token offers. The token travels in the
/// body, never the URL, so it stays out of access logs.
pub async fn inspect_invite(
    State(s): St,
    ApiJson(req): ApiJson<InviteTokenRequest>,
) -> ApiResult<Json<InviteInfo>> {
    Ok(Json(
        s.control.users.inspect_invite(&req.invite_token).await?,
    ))
}

#[derive(Deserialize)]
pub struct InviteTotpRequest {
    invite_token: String,
    username: String,
}

pub async fn invite_totp(
    State(s): St,
    ApiJson(req): ApiJson<InviteTotpRequest>,
) -> ApiResult<Json<TotpEnrollment>> {
    Ok(Json(
        s.control
            .users
            .invite_totp(&req.invite_token, &req.username)
            .await?,
    ))
}

pub async fn accept_invite(
    State(s): St,
    ApiJson(req): ApiJson<AcceptInviteRequest>,
) -> ApiResult<(StatusCode, Json<UserSummary>)> {
    let user = s.control.users.accept_invite(req).await?;
    Ok((StatusCode::CREATED, Json(user)))
}

// ----- audit -------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditParams {
    vault_id: Option<String>,
    action_prefix: Option<String>,
    session_id: Option<String>,
    credential_id: Option<String>,
    page: Option<u64>,
    page_size: Option<u64>,
}

pub async fn query_audit(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<AuditParams>,
) -> ApiResult<Json<Page<tokenless_core::audit::AuditEvent>>> {
    let vault_id = q
        .vault_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| parse_id::<VaultId>("vault", v))
        .transpose()?;
    let prefix = q.action_prefix.filter(|p| !p.is_empty());
    let session_id = q
        .session_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| parse_id::<SessionId>("session", v))
        .transpose()?;
    let credential_id = q
        .credential_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| parse_id::<CredentialId>("credential", v))
        .transpose()?;
    Ok(Json(
        s.control
            .audit
            .query_events(
                &authed.caller,
                AuditQuery {
                    vault_id,
                    action_prefix: prefix,
                    session_id,
                    credential_id,
                    page: PageRequest::new(q.page, q.page_size),
                },
            )
            .await?,
    ))
}

// ----- nodes -------------------------------------------------------------

pub async fn list_nodes(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        s.control
            .nodes
            .list_nodes(&authed.caller, q.request())
            .await?,
    ))
}

#[derive(Default, Deserialize)]
pub struct JoinTokenRequest {
    ttl_secs: Option<u64>,
}

pub async fn create_join_token(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<JoinTokenRequest>,
) -> ApiResult<impl IntoResponse> {
    let issued = s
        .control
        .nodes
        .create_join_token(&authed.caller, req.ttl_secs)
        .await?;
    Ok((StatusCode::CREATED, Json(issued)))
}

pub async fn get_node(
    State(s): St,
    authed: Authed,
    Path(node_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id: NodeId = parse_id("node", &node_id)?;
    Ok(Json(s.control.nodes.get_node(&authed.caller, &id).await?))
}

pub async fn revoke_node(
    State(s): St,
    authed: Authed,
    Path(node_id): Path<String>,
) -> ApiResult<StatusCode> {
    let id: NodeId = parse_id("node", &node_id)?;
    s.control.nodes.revoke_node(&authed.caller, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- settings and CA ---------------------------------------------------

pub async fn get_settings(State(s): St, authed: Authed) -> ApiResult<Json<Settings>> {
    Ok(Json(s.control.policy.get_settings(&authed.caller).await?))
}

pub async fn put_settings(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<Settings>,
) -> ApiResult<Json<Settings>> {
    Ok(Json(
        s.control.policy.put_settings(&authed.caller, req).await?,
    ))
}

/// The interception CA certificate clients must trust. A public
/// certificate, so no authentication is required.
pub async fn interception_ca(State(s): St) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-pem-file"),
        )],
        s.control.nodes.interception_ca_cert_pem(),
    )
}
