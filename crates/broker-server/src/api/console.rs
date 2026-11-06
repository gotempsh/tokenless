// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management console compiled into the binary.
//!
//! `broker-ui/dist` is embedded when it exists at build time (release
//! builds run `bun run build` first), so a downloaded binary serves its
//! console with no files beside it. `--ui-dir` still overrides it. A build
//! made without the bundle serves the API only.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::{EmbeddedFile, RustEmbed};

#[derive(RustEmbed)]
#[folder = "../../broker-ui/dist/"]
#[allow_missing = true]
struct Bundle;

/// Whether this binary was built with the console in it.
pub fn embedded() -> bool {
    Bundle::get("index.html").is_some()
}

/// Serves a file of the bundle, with `index.html` for anything else
/// (client-side routes). Like `--ui-dir`, every response must be
/// revalidated, answered with a 304 when the ETag still matches, so an
/// upgraded broker never shows the previous console.
pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    let file = if path.is_empty() || path.split('/').any(|s| s == "..") {
        None
    } else {
        Bundle::get(path)
    };
    let Some(file) = file.or_else(|| Bundle::get("index.html")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    respond(&file, &headers)
}

fn respond(file: &EmbeddedFile, headers: &HeaderMap) -> Response {
    let etag = format!("\"{}\"", hex::encode(file.metadata.sha256_hash()));
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    let mut response = if fresh {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut r = Body::from(file.data.clone().into_owned()).into_response();
        if let Ok(v) = HeaderValue::from_str(file.metadata.mimetype()) {
            r.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        r
    };
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    async fn get(path: &str, if_none_match: Option<&str>) -> Response {
        let mut req = Request::get(path);
        if let Some(tag) = if_none_match {
            req = req.header(header::IF_NONE_MATCH, tag);
        }
        axum::Router::new()
            .fallback(serve)
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn content_type(r: &Response) -> &str {
        r.headers()[header::CONTENT_TYPE].to_str().unwrap()
    }

    #[tokio::test]
    async fn embedded_console_is_served_and_revalidated() {
        if !embedded() {
            println!("broker-ui/dist was not built before this test binary; skipping");
            return;
        }
        for path in ["/", "/index.html", "/some/client/route"] {
            let r = get(path, None).await;
            assert_eq!(r.status(), StatusCode::OK, "{path}");
            assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache", "{path}");
            assert!(content_type(&r).starts_with("text/html"), "{path}");
        }
        let etag = get("/", None).await.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            get("/", Some(&etag)).await.status(),
            StatusCode::NOT_MODIFIED
        );
        assert_eq!(get("/", Some("\"stale\"")).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn parent_segments_never_leave_the_bundle() {
        if !embedded() {
            println!("broker-ui/dist was not built before this test binary; skipping");
            return;
        }
        // Answered with the console's index, never a file outside the bundle.
        let r = get("/../../Cargo.toml", None).await;
        assert!(content_type(&r).starts_with("text/html"));
    }
}
