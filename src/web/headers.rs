use axum::extract::{Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::app::AppState;

const STYLESHEET: &str = include_str!("../../assets/doorward.css");

/// The page policy; `form_target` is one more origin a form may post or be redirected to.
pub fn content_security_policy(form_target: Option<&str>) -> String {
    let target = form_target
        .map(|origin| format!(" {origin}"))
        .unwrap_or_default();
    format!(
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'{target}; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

/// Adds the browser-page headers to every response of an HTML route.
pub async fn security_headers(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let https = state.config.https_public();
    let headers = response.headers_mut();
    if https {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    // A policy a handler set itself (the consent page) is kept.
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        // The policy text is ASCII, so the fallback is never taken; it is the strictest policy.
        let policy = HeaderValue::from_str(&content_security_policy(None))
            .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'"));
        headers.insert(CONTENT_SECURITY_POLICY, policy);
    }
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}

/// The stylesheet, compiled into the binary.
pub async fn stylesheet() -> Response {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        STYLESHEET,
    )
        .into_response()
}
