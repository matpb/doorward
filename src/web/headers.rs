use std::sync::OnceLock;

use axum::extract::{Path, RawQuery, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::app::AppState;

const STYLESHEET: &str = include_str!("../../assets/doorward.css");
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The page policy; `form_target` is one more origin a form may post or be redirected to.
pub fn content_security_policy(form_target: Option<&str>) -> String {
    let target = form_target
        .map(|origin| format!(" {origin}"))
        .unwrap_or_default();
    format!(
        "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
         form-action 'self'{target}; frame-ancestors 'none'; base-uri 'none'"
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
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// The first 8 bytes of the SHA-256 of the stylesheet, in lowercase hex.
fn stylesheet_digest() -> &'static str {
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| hex::encode(&Sha256::digest(STYLESHEET.as_bytes())[..8]))
}

/// The address the pages link the stylesheet at, with its version.
pub fn stylesheet_href() -> &'static str {
    static HREF: OnceLock<String> = OnceLock::new();
    HREF.get_or_init(|| format!("/assets/doorward.css?v={}", stylesheet_digest()))
}

/// The stylesheet, compiled in. Its current version is cached for a year.
pub async fn stylesheet(RawQuery(query): RawQuery) -> Response {
    let versioned =
        query.as_deref().and_then(|query| query.strip_prefix("v=")) == Some(stylesheet_digest());
    let cache = if versioned { IMMUTABLE } else { "no-cache" };
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (CACHE_CONTROL, cache),
        ],
        STYLESHEET,
    )
        .into_response()
}

/// A font compiled into the binary, by its file name. Any other name answers 404.
pub async fn font(Path(name): Path<String>) -> Response {
    let bytes: &'static [u8] = match name.as_str() {
        "atkinson-hyperlegible-mono-latin-ext-wght-normal.woff2" => include_bytes!(
            "../../assets/fonts/atkinson-hyperlegible-mono-latin-ext-wght-normal.woff2"
        ),
        "atkinson-hyperlegible-mono-latin-wght-normal.woff2" => {
            include_bytes!("../../assets/fonts/atkinson-hyperlegible-mono-latin-wght-normal.woff2")
        }
        "atkinson-hyperlegible-next-latin-ext-wght-normal.woff2" => include_bytes!(
            "../../assets/fonts/atkinson-hyperlegible-next-latin-ext-wght-normal.woff2"
        ),
        "atkinson-hyperlegible-next-latin-wght-normal.woff2" => {
            include_bytes!("../../assets/fonts/atkinson-hyperlegible-next-latin-wght-normal.woff2")
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (CONTENT_TYPE, "font/woff2"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (CACHE_CONTROL, IMMUTABLE),
        ],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    /// The digest of the stylesheet, computed here from the file rather than from the code.
    fn expected_digest() -> String {
        let digest = Sha256::digest(include_bytes!("../../assets/doorward.css"));
        hex::encode(&digest[..8])
    }

    /// The body of a response as bytes.
    async fn body_of(response: Response) -> Vec<u8> {
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec()
    }

    /// The value of a header of a response, as text.
    fn header_of(response: &Response, name: &str) -> Option<String> {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().expect("ascii").to_owned())
    }

    #[test]
    fn the_page_policy_is_exactly_the_agreed_one() {
        assert_eq!(
            content_security_policy(None),
            "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        );
        assert_eq!(
            content_security_policy(Some("https://app.example.com")),
            "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
             form-action 'self' https://app.example.com; frame-ancestors 'none'; base-uri 'none'"
        );
    }

    #[test]
    fn the_stylesheet_href_carries_the_first_eight_bytes_of_its_digest() {
        assert_eq!(
            stylesheet_href(),
            format!("/assets/doorward.css?v={}", expected_digest())
        );
        let version = stylesheet_href().rsplit('=').next().expect("a version");
        assert_eq!(version.len(), 16, "the version is 16 hex characters");
        assert!(
            version
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[tokio::test]
    async fn the_stylesheet_asked_for_by_its_version_is_cached_for_a_year() {
        let query = Some(format!("v={}", expected_digest()));
        let response = stylesheet(RawQuery(query)).await;
        assert_eq!(
            header_of(&response, "cache-control").as_deref(),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(
            header_of(&response, "content-type").as_deref(),
            Some("text/css; charset=utf-8")
        );
        assert_eq!(
            header_of(&response, "x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            body_of(response).await,
            include_bytes!("../../assets/doorward.css")
        );
    }

    #[tokio::test]
    async fn any_other_stylesheet_request_must_revalidate() {
        let digest = expected_digest();
        for query in [
            None,
            Some(String::new()),
            Some("v=0000000000000000".to_owned()),
            Some(format!("v={digest}&x=1")),
            Some(format!("x=1&v={digest}")),
            Some(format!("v={}", digest.to_uppercase())),
        ] {
            let shown = format!("{query:?}");
            let response = stylesheet(RawQuery(query)).await;
            assert_eq!(
                header_of(&response, "cache-control").as_deref(),
                Some("no-cache"),
                "the stylesheet for {shown} must revalidate"
            );
        }
    }

    #[tokio::test]
    async fn each_font_is_served_as_woff2_for_a_year() {
        for (name, file) in [
            (
                "atkinson-hyperlegible-mono-latin-ext-wght-normal.woff2",
                &include_bytes!(
                    "../../assets/fonts/atkinson-hyperlegible-mono-latin-ext-wght-normal.woff2"
                )[..],
            ),
            (
                "atkinson-hyperlegible-mono-latin-wght-normal.woff2",
                &include_bytes!(
                    "../../assets/fonts/atkinson-hyperlegible-mono-latin-wght-normal.woff2"
                )[..],
            ),
            (
                "atkinson-hyperlegible-next-latin-ext-wght-normal.woff2",
                &include_bytes!(
                    "../../assets/fonts/atkinson-hyperlegible-next-latin-ext-wght-normal.woff2"
                )[..],
            ),
            (
                "atkinson-hyperlegible-next-latin-wght-normal.woff2",
                &include_bytes!(
                    "../../assets/fonts/atkinson-hyperlegible-next-latin-wght-normal.woff2"
                )[..],
            ),
        ] {
            let response = font(Path(name.to_owned())).await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            assert_eq!(
                header_of(&response, "content-type").as_deref(),
                Some("font/woff2"),
                "{name}"
            );
            assert_eq!(
                header_of(&response, "x-content-type-options").as_deref(),
                Some("nosniff"),
                "{name}"
            );
            assert_eq!(
                header_of(&response, "cache-control").as_deref(),
                Some("public, max-age=31536000, immutable"),
                "{name}"
            );
            let body = body_of(response).await;
            assert!(body.starts_with(b"wOF2"), "{name} must be a woff2 file");
            assert_eq!(body, file, "{name} must be served exactly as its file");
        }
    }

    #[tokio::test]
    async fn a_name_that_is_not_a_font_is_a_bare_404() {
        for name in [
            "nope.woff2",
            "atkinson-hyperlegible-next-latin-wght-normal",
            "OFL-Atkinson-Hyperlegible-Next.txt",
            "../doorward.css",
            "",
        ] {
            let response = font(Path(name.to_owned())).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{name:?}");
            assert_eq!(header_of(&response, "content-type"), None, "{name:?}");
            assert!(body_of(response).await.is_empty(), "{name:?}");
        }
    }
}
