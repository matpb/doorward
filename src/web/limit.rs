//! The limiter's wiring: the route classes, the middlewares that answer a limited request, the 429
//! answers, and the hold of an open MCP request.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, RETRY_AFTER};
use axum::http::{Extensions, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::{Frame, SizeHint};
use maud::html;
use serde_json::json;

use crate::app::AppState;
use crate::clock::Clock;
use crate::rate::{Class, Key};

use super::address::client_address;
use super::page;

/// The class of a request by method and path.
pub fn class_of(method: &Method, path: &str) -> Class {
    let post = *method == Method::POST;
    let segments: Vec<&str> = path.split('/').collect();
    match segments.as_slice() {
        ["", "oauth", "token" | "register"] if post => Class::Oauth,
        ["", "oauth", "authorize"] if matches!(*method, Method::GET | Method::HEAD) => Class::Oauth,
        ["", "login" | "setup" | "forgot"] | ["", "account", "password"] if post => {
            Class::Credentials
        }
        ["", "invite" | "reset", _] | ["", "account", "disconnect", _] if post => {
            Class::Credentials
        }
        _ => Class::General,
    }
}

/// The socket address of the request, unspecified when the server recorded none.
pub fn peer_of(extensions: &Extensions) -> IpAddr {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip())
}

/// The gateway clock in nanoseconds since the Unix epoch, clamped to the range of `u64`.
pub fn now_nanos(clock: &dyn Clock) -> u64 {
    let nanos = clock
        .now()
        .unix_timestamp_nanos()
        .clamp(0, i128::from(u64::MAX));
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Takes the request's bucket for its address and class; `Err` gives the seconds to wait.
/// `/healthz` from a loopback address with no `X-Forwarded-For` header takes no bucket.
fn admit(state: &AppState, request: &Request) -> Result<(), u64> {
    let path = request.uri().path();
    let peer = peer_of(request.extensions());
    let address = client_address(peer, request.headers(), &state.config.trusted_proxies);
    let forwarded = request.headers().contains_key("x-forwarded-for");
    if path == "/healthz" && address.is_loopback() && !forwarded {
        return Ok(());
    }
    let class = class_of(request.method(), path);
    let now = now_nanos(state.clock.as_ref());
    state.limiter.take(class, Key::address(address), now)
}

/// Runs before the pages and their security headers; a limited request gets the HTML error page.
pub async fn pages_by_address(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let browser = accepts_html(&request);
    match admit(&state, &request) {
        Ok(()) => next.run(request).await,
        Err(wait) => page_limited(wait, browser),
    }
}

/// True when an `Accept` header of the request names text/html.
fn accepts_html(request: &Request) -> bool {
    request
        .headers()
        .get_all(ACCEPT)
        .iter()
        .any(|value| value.to_str().is_ok_and(|text| text.contains("text/html")))
}

/// Runs before the JSON and asset routes; a limited request gets the JSON 429.
pub async fn api_by_address(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    match admit(&state, &request) {
        Ok(()) => next.run(request).await,
        Err(wait) => json_limited(wait),
    }
}

/// The HTML 429 of a page. A browser also gets the sentence that says when to try again.
fn page_limited(wait: u64, browser: bool) -> Response {
    let body = if browser {
        html! {
            h1 { "Too many requests" }
            p.lede { "Try again in a moment." }
        }
    } else {
        html! { h1 { "Too many requests" } }
    };
    retry_after(
        page(
            StatusCode::TOO_MANY_REQUESTS,
            "error",
            "Too many requests",
            body,
        ),
        wait,
    )
}

/// The JSON 429 of the token, register, metadata and asset routes.
pub fn json_limited(wait: u64) -> Response {
    let body = json!({
        "error": "too_many_requests",
        "error_description": "Too many requests. Try again later.",
    });
    retry_after(
        (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response(),
        wait,
    )
}

/// Adds `Retry-After` (at least 1 second) and `Cache-Control: no-store` to a refusal.
pub fn retry_after(mut response: Response, wait: u64) -> Response {
    let headers = response.headers_mut();
    headers.insert(RETRY_AFTER, HeaderValue::from(wait.max(1)));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A window of `minutes`, in seconds, at least 1.
pub fn window_seconds(minutes: u64) -> u64 {
    minutes.saturating_mul(60).max(1)
}

/// A response body that keeps its guard until the body ends or is dropped.
struct Held<G> {
    inner: Body,
    _guard: G,
}

impl<G: Unpin> http_body::Body for Held<G> {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Keeps `guard` until the body of `response` ends or is dropped; the response is otherwise unchanged.
pub fn hold<G: Unpin + Send + 'static>(response: Response, guard: G) -> Response {
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(Held {
            inner: body,
            _guard: guard,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::body::to_bytes;
    use http_body::Body as _;

    use crate::config::Limits;
    use crate::rate::Limiter;

    #[test]
    fn every_route_of_the_table_has_its_class() {
        let cases: &[(Method, &str, Class)] = &[
            (Method::POST, "/oauth/token", Class::Oauth),
            (Method::POST, "/oauth/register", Class::Oauth),
            (Method::GET, "/oauth/authorize", Class::Oauth),
            (Method::HEAD, "/oauth/authorize", Class::Oauth),
            (Method::POST, "/login", Class::Credentials),
            (Method::POST, "/setup", Class::Credentials),
            (Method::POST, "/forgot", Class::Credentials),
            (Method::POST, "/invite/abc", Class::Credentials),
            (Method::POST, "/reset/abc", Class::Credentials),
            (Method::POST, "/account/password", Class::Credentials),
            (Method::POST, "/account/disconnect/abc", Class::Credentials),
            (Method::GET, "/login", Class::General),
            (Method::POST, "/oauth/authorize", Class::General),
            (Method::GET, "/oauth/token", Class::General),
            (Method::POST, "/login/", Class::General),
            (Method::POST, "/invite", Class::General),
            (Method::POST, "/invite/a/b", Class::General),
            (Method::POST, "/account/disconnect", Class::General),
            (Method::POST, "/oauth/token/x", Class::General),
            (Method::GET, "/healthz", Class::General),
            (Method::POST, "/healthz", Class::General),
            (Method::GET, "/", Class::General),
            (Method::GET, "/admin/users", Class::General),
        ];
        for (method, path, want) in cases {
            assert_eq!(class_of(method, path), *want, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn a_held_body_keeps_its_exact_size_and_its_bytes() {
        let limiter = Arc::new(Limiter::new(&Limits::default()));
        let open = limiter.open(1).expect("the first open request");
        let value = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
        let expected = serde_json::to_vec(&value).expect("json");
        let response = hold(Json(value).into_response(), open);
        assert_eq!(
            response.body().size_hint().exact(),
            Some(expected.len() as u64),
            "the size hint is the body length"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        assert_eq!(bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn a_request_that_accepts_html_is_a_browser_request() {
        let request = |accept: Option<&str>| {
            let mut builder = Request::builder();
            if let Some(accept) = accept {
                builder = builder.header(ACCEPT, accept);
            }
            builder.body(Body::empty()).expect("request")
        };
        assert!(accepts_html(&request(Some(
            "text/html,application/xhtml+xml"
        ))));
        assert!(!accepts_html(&request(Some("application/json"))));
        assert!(!accepts_html(&request(Some("*/*"))));
        assert!(!accepts_html(&request(None)));
    }

    #[tokio::test]
    async fn a_limited_page_tells_a_browser_when_to_try_again_and_no_one_else() {
        let browser = page_limited(3, true);
        assert_eq!(browser.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(browser.headers()[RETRY_AFTER].to_str().expect("ascii"), "3");
        let text = String::from_utf8(
            to_bytes(browser.into_body(), usize::MAX)
                .await
                .expect("the body")
                .to_vec(),
        )
        .expect("utf-8");
        assert!(text.contains("<h1>Too many requests</h1>"), "{text}");
        assert!(
            text.contains("<p class=\"lede\">Try again in a moment.</p>"),
            "{text}"
        );

        let plain = page_limited(3, false);
        let text = String::from_utf8(
            to_bytes(plain.into_body(), usize::MAX)
                .await
                .expect("the body")
                .to_vec(),
        )
        .expect("utf-8");
        assert!(text.contains("<h1>Too many requests</h1>"), "{text}");
        assert!(!text.contains("Try again"), "{text}");
    }

    #[test]
    fn a_window_is_its_minutes_in_seconds_and_at_least_one() {
        assert_eq!(window_seconds(7), 420);
        assert_eq!(window_seconds(0), 1);
    }

    #[test]
    fn a_held_response_keeps_its_slot_until_it_is_dropped() {
        let limits = Limits {
            mcp_open: 1,
            ..Default::default()
        };
        let limiter = Arc::new(Limiter::new(&limits));
        let open = limiter.open(7).expect("the first open request");
        let response = hold(Json(json!({})).into_response(), open);
        assert!(
            limiter.open(7).is_none(),
            "the held response keeps the only slot"
        );
        drop(response);
        assert!(
            limiter.open(7).is_some(),
            "dropping the response frees the slot"
        );
    }

    /// Sets its flag when it is dropped.
    struct Guard(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_held_body_keeps_its_guard_until_it_is_dropped() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let response = hold(Response::new(body), Guard(Arc::clone(&released)));
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        drop(response);
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_finished_body_releases_its_guard() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let response = hold(
            Response::new(Body::from("abc")),
            Guard(Arc::clone(&released)),
        );
        let bytes = to_bytes(response.into_body(), 16).await.expect("the body");
        assert_eq!(&bytes[..], b"abc");
        assert!(released.load(std::sync::atomic::Ordering::SeqCst));
    }
}
