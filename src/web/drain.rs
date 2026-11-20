//! The outermost layer: reads what a route left unread of a request body before its answer leaves.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::CONTENT_LENGTH;
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Body as _, Frame, SizeHint};
use tokio::time::timeout;

use crate::app::AppState;

/// The longest the gateway keeps reading an unread request body before it answers anyway.
const DRAIN_LIMIT: Duration = Duration::from_secs(2);

/// A request body that, when dropped before its end, moves the rest of itself into `slot`.
struct Tracked {
    inner: Body,
    slot: Arc<Mutex<Option<Body>>>,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        if self.inner.is_end_stream() {
            return;
        }
        let rest = std::mem::replace(&mut self.inner, Body::empty());
        // A poisoned slot is left empty.
        if let Ok(mut slot) = self.slot.lock() {
            *slot = Some(rest);
        }
    }
}

impl http_body::Body for Tracked {
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

/// Runs outside every other layer. A request whose declared body is over the limit is passed on
/// as it is. Otherwise a body the route left unread is drained before the answer leaves.
pub async fn unread_body(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let limit = state.config.limits.body_bytes;
    if declared_length(&request).is_some_and(|length| length > limit) {
        return next.run(request).await;
    }
    let slot = Arc::new(Mutex::new(None));
    let (parts, body) = request.into_parts();
    let tracked = Body::new(Tracked {
        inner: body,
        slot: Arc::clone(&slot),
    });
    let response = next.run(Request::from_parts(parts, tracked)).await;
    let unread = slot.lock().ok().and_then(|mut rest| rest.take());
    if let Some(rest) = unread {
        // The timeout is the drain's limit; what is still unread is left to the close.
        let _ = timeout(DRAIN_LIMIT, discard(rest, limit)).await;
    }
    response
}

/// The `Content-Length` of the request, when it is a number.
fn declared_length(request: &Request) -> Option<u64> {
    request
        .headers()
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Reads and discards frames until the body ends, a read fails, or `limit` bytes are discarded.
async fn discard(mut rest: Body, limit: u64) {
    let mut discarded: u64 = 0;
    while discarded < limit {
        match poll_fn(|cx| Pin::new(&mut rest).poll_frame(cx)).await {
            Some(Ok(frame)) => {
                discarded += frame.data_ref().map_or(0, |data| data.len() as u64);
            }
            // Nothing more can be read from a body that ended or failed.
            Some(Err(_)) | None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;

    #[tokio::test]
    async fn a_body_dropped_unread_is_kept_in_the_slot() {
        let slot = Arc::new(Mutex::new(None));
        let tracked = Tracked {
            inner: Body::from("abcdef"),
            slot: Arc::clone(&slot),
        };
        drop(tracked);
        let kept = slot
            .lock()
            .expect("the slot is not poisoned")
            .take()
            .expect("the unread body is kept");
        let bytes = to_bytes(kept, usize::MAX).await.expect("the kept body");
        assert_eq!(bytes.as_ref(), b"abcdef");
    }

    #[tokio::test]
    async fn a_body_read_to_its_end_leaves_the_slot_empty() {
        let slot = Arc::new(Mutex::new(None));
        let tracked = Tracked {
            inner: Body::from("abcdef"),
            slot: Arc::clone(&slot),
        };
        let bytes = to_bytes(Body::new(tracked), usize::MAX)
            .await
            .expect("the body");
        assert_eq!(bytes.as_ref(), b"abcdef");
        assert!(
            slot.lock().expect("the slot is not poisoned").is_none(),
            "a body read to its end is not kept"
        );
    }

    #[tokio::test]
    async fn the_size_hint_and_the_bytes_pass_through_unchanged() {
        let slot = Arc::new(Mutex::new(None));
        let tracked = Tracked {
            inner: Body::from("abcdef"),
            slot: Arc::clone(&slot),
        };
        assert_eq!(tracked.size_hint().exact(), Some(6));
        assert!(!tracked.is_end_stream(), "unread bytes remain");
        let bytes = to_bytes(Body::new(tracked), usize::MAX)
            .await
            .expect("the body");
        assert_eq!(bytes.as_ref(), b"abcdef");
    }
}
