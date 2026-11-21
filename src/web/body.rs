//! Reads a request body under a size limit and a time limit, and the answer to a body that is late.

use std::time::Duration;

use axum::body::{Body, Bytes, to_bytes};
use axum::http::StatusCode;
use axum::http::header::CONNECTION;
use axum::response::{IntoResponse, Response};

/// Why a request body was not read in full.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The body is over the limit, or its stream failed.
    TooLarge,
    /// The body did not end within the time limit.
    TimedOut,
}

/// Reads `body` in full, at most `limit` bytes, and gives up after `seconds`.
pub async fn read(body: Body, limit: usize, seconds: u64) -> Result<Bytes, ReadError> {
    match tokio::time::timeout(Duration::from_secs(seconds), to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(ReadError::TooLarge),
        Err(_) => Err(ReadError::TimedOut),
    }
}

/// The answer to a body that was late: 408, no body, and the connection closed.
pub fn timed_out() -> Response {
    (StatusCode::REQUEST_TIMEOUT, [(CONNECTION, "close")]).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures_util::stream;

    #[tokio::test]
    async fn a_body_within_the_limit_is_read_whole() {
        let bytes = read(Body::from("hello"), 5, 1).await.expect("read");
        assert_eq!(bytes.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_too_large() {
        let err = read(Body::from("hello!"), 5, 1)
            .await
            .expect_err("too large");
        assert_eq!(err, ReadError::TooLarge);
    }

    #[tokio::test]
    async fn a_body_that_never_ends_times_out() {
        let body = Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>());
        let err = read(body, 1024, 1).await.expect_err("timed out");
        assert_eq!(err, ReadError::TimedOut);
    }

    #[tokio::test]
    async fn a_timed_out_answer_is_408_with_no_body_and_connection_close() {
        let response = timed_out();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers()[CONNECTION], "close");
        assert_eq!(response.headers().len(), 1, "only Connection is set");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        assert!(bytes.is_empty(), "the 408 has no body");
    }
}
