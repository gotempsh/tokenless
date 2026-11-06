// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management HTTP API (`/api/v1`) used by the UI and automation.

mod console;
mod extract;
mod handlers;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{header, HeaderName, HeaderValue};
use axum::routing::{get, post, put};
use axum::Router;
use broker_control::ControlPlane;
use tower::Layer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::{SetResponseHeader, SetResponseHeaderLayer};

pub use extract::{ApiJson, ApiQuery, Authed};

pub struct AppState {
    pub control: Arc<ControlPlane>,
}

fn api_routes() -> Router<Arc<AppState>> {
    use handlers::*;
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/step-up", post(step_up))
        .route("/auth/password", post(change_password))
        .route(
            "/auth/authenticator/enrollment",
            post(authenticator_enrollment),
        )
        .route("/auth/authenticator", post(enable_authenticator))
        .route("/auth/authenticator/remove", post(disable_authenticator))
        .route("/vaults", get(list_vaults).post(create_vault))
        .route("/vaults/{vault_id}", get(get_vault).delete(delete_vault))
        .route(
            "/vaults/{vault_id}/credentials",
            get(list_credentials).post(create_credential),
        )
        .route(
            "/vaults/{vault_id}/rules",
            get(list_rules).post(create_rule),
        )
        .route(
            "/vaults/{vault_id}/sessions",
            get(list_sessions).post(mint_session),
        )
        .route(
            "/vaults/{vault_id}/bundles",
            get(list_bundles).post(create_bundle),
        )
        .route(
            "/bundles/{bundle_id}",
            get(get_bundle).patch(update_bundle).delete(delete_bundle),
        )
        .route("/templates", get(list_templates))
        .route("/templates/import", post(import_template))
        .route("/templates/{template_id}/{version}", get(get_template))
        .route(
            "/templates/{template_id}/{version}/approve",
            post(approve_template),
        )
        .route(
            "/credentials/{credential_id}",
            get(get_credential).delete(delete_credential),
        )
        .route(
            "/credentials/{credential_id}/secret",
            put(rotate_credential),
        )
        .route(
            "/credentials/{credential_id}/headers",
            put(update_custom_headers),
        )
        .route(
            "/credentials/{credential_id}/substitutions",
            put(update_substitutions),
        )
        .route("/variables", get(list_variables).post(create_variable))
        .route(
            "/variables/{variable_id}",
            put(replace_variable).delete(delete_variable),
        )
        .route(
            "/credentials/{credential_id}/validate",
            post(validate_credential),
        )
        .route(
            "/rules/{rule_id}",
            get(get_rule).patch(update_rule).delete(delete_rule),
        )
        .route("/bundles", get(list_all_bundles))
        .route("/bundles/{bundle_id}/sessions", get(list_bundle_sessions))
        .route("/sessions", get(list_all_sessions))
        .route("/sessions/revoke-self", post(revoke_own_session))
        .route("/sessions/self", get(discover_own_session))
        .route(
            "/sessions/{session_id}",
            axum::routing::patch(update_session),
        )
        .route("/sessions/{session_id}/revoke", post(revoke_session))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route(
            "/api-keys/{api_key_id}",
            axum::routing::delete(revoke_api_key),
        )
        .route("/users", get(list_users))
        .route("/users/{user_id}", axum::routing::patch(update_user))
        .route("/invites", get(list_invites).post(create_invite))
        .route("/invites/inspect", post(inspect_invite))
        .route("/invites/totp", post(invite_totp))
        .route("/invites/accept", post(accept_invite))
        .route("/invites/{invite_id}", axum::routing::delete(revoke_invite))
        .route("/audit", get(query_audit))
        .route("/nodes", get(list_nodes))
        .route("/nodes/join-tokens", post(create_join_token))
        .route("/nodes/{node_id}", get(get_node))
        .route("/nodes/{node_id}/revoke", post(revoke_node))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/ca/interception.pem", get(interception_ca))
        .fallback(not_found)
        // Nothing the API returns may be cached: several responses carry
        // one-time credentials and the rest describe security state.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

const UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// The UI bundle, with `index.html` as the fallback for client-side routes.
///
/// Every response must be revalidated (`no-cache`, answered with a 304
/// when unchanged): a cached `index.html` keeps pointing at the previous
/// build's scripts, so an upgraded broker would show the old UI.
fn ui_service(dir: PathBuf) -> SetResponseHeader<ServeDir<ServeFile>, HeaderValue> {
    let index = dir.join("index.html");
    SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
        .layer(ServeDir::new(dir).fallback(ServeFile::new(index)))
}

/// Whether `serve` has a console to show without `--ui-dir`.
pub fn console_embedded() -> bool {
    console::embedded()
}

/// Builds the full router: `/api/v1`, plus the console: from `ui_dir` when
/// it is set, otherwise the one compiled into the binary, if any.
pub fn router(state: Arc<AppState>, ui_dir: Option<PathBuf>) -> Router {
    let mut app = Router::new().nest("/api/v1", api_routes());
    if let Some(dir) = ui_dir {
        app = app.fallback_service(ui_service(dir));
    } else if console::embedded() {
        app = app.fallback(console::serve);
    }
    app.layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(UI_CSP),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    ))
    .with_state(state)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    async fn fetch(dir: &std::path::Path, path: &str) -> (StatusCode, Option<String>) {
        let response = ui_service(dir.to_path_buf())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_owned());
        (response.status(), cache)
    }

    #[tokio::test]
    async fn ui_responses_are_always_revalidated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/index-abc.js"), "1").unwrap();

        for path in ["/", "/assets/index-abc.js", "/vaults/some-client-route"] {
            let (status, cache) = fetch(dir.path(), path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(cache.as_deref(), Some("no-cache"), "{path}");
        }
    }
}
