//! Statement 48: the Origin check on `/mcp` and `/{slug}`, its refusal and its log line.

use std::sync::{Mutex, PoisonError};

use axum::extract::{Request, State};
use axum::http::header::ORIGIN;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use time::{Duration, OffsetDateTime};

use crate::app::AppState;
use crate::mcp;

/// Most distinct values remembered for the log line.
const LOG_KEYS: usize = 64;
/// Most log lines printed in one window, whatever the values.
const LOG_LINES: usize = 20;
/// Bytes of a value shown in the log line.
const LOG_SHOWN: usize = 200;
/// A value is logged again once this much time has passed; a window lasts as long.
const LOG_WINDOW: Duration = Duration::minutes(1);

static LOG: Mutex<Log> = Mutex::new(Log::new());

/// What the log remembers: the values printed, and the budget of the current window.
pub(super) struct Log {
    /// Each value printed with its time; the least recently printed come first.
    seen: Vec<(String, OffsetDateTime)>,
    /// When the current window opened, at its first printed line.
    window: Option<OffsetDateTime>,
    /// Lines printed in the current window.
    lines: usize,
    /// Refusals past the budget of the last window, not yet reported.
    dropped: u64,
}

impl Log {
    pub(super) const fn new() -> Log {
        Log {
            seen: Vec::new(),
            window: None,
            lines: 0,
            dropped: 0,
        }
    }

    /// The lines to print for a refusal of `shown` at `now`. Nothing when the value was printed
    /// within the minute; past the window's budget the refusal is counted and not remembered.
    pub(super) fn record(&mut self, shown: &str, now: OffsetDateTime) -> Vec<String> {
        let last = self
            .seen
            .iter()
            .find(|(value, _)| value == shown)
            .map(|(_, at)| *at);
        if last.is_some_and(|at| now - at < LOG_WINDOW) {
            return Vec::new();
        }
        let mut lines = Vec::new();
        if self.window.is_none_or(|start| now - start >= LOG_WINDOW) {
            if self.dropped > 0 {
                lines.push(format!(
                    "doorward: {} more refused Origin values were not shown",
                    self.dropped
                ));
            }
            self.dropped = 0;
            self.window = Some(now);
            self.lines = 0;
        }
        if self.lines >= LOG_LINES {
            self.dropped = self.dropped.saturating_add(1);
            return lines;
        }
        self.lines += 1;
        lines.push(format!(
            "doorward: refused an Origin that is not allowed: {shown}"
        ));
        self.seen.retain(|(value, _)| value != shown);
        if self.seen.len() >= LOG_KEYS {
            self.seen.remove(0);
        }
        self.seen.push((shown.to_owned(), now));
        lines
    }

    #[cfg(test)]
    pub(super) fn remembered(&self) -> usize {
        self.seen.len()
    }
}

/// True when the request may go on: it has no Origin, or exactly one, equal to `own` or to an
/// entry of `extra`.
pub fn allowed(headers: &HeaderMap, own: &str, extra: &[String]) -> bool {
    let mut values = headers.get_all(ORIGIN).iter();
    let Some(value) = values.next() else {
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    let bytes = value.as_bytes();
    bytes == own.as_bytes() || extra.iter().any(|entry| entry.as_bytes() == bytes)
}

/// Runs before every other check on `/mcp` and `/{slug}`, for every method.
pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if allowed(
        request.headers(),
        &state.config.public_url,
        &state.config.allowed_origins,
    ) {
        return next.run(request).await;
    }
    refusal(request.headers(), state.clock.now())
}

/// The 403 of a refused Origin, and its log line when the value is due at `now`.
pub fn refusal(headers: &HeaderMap, now: OffsetDateTime) -> Response {
    let shown = shown_value(&origin_bytes(headers));
    let lines = LOG
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .record(&shown, now);
    for line in lines {
        eprintln!("{line}");
    }
    mcp::answer::error(StatusCode::FORBIDDEN, None, -32000, "Origin not allowed")
}

/// The Origin values of a request, joined with ", " in the order they arrived.
fn origin_bytes(headers: &HeaderMap) -> Vec<u8> {
    let values: Vec<&[u8]> = headers
        .get_all(ORIGIN)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    values.join(&b", "[..])
}

/// The bytes as a refusal shows them: the first 200, each byte outside visible ASCII as `?`.
pub fn shown_value(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(LOG_SHOWN)
        .map(|&byte| {
            if byte.is_ascii_graphic() {
                char::from(byte)
            } else {
                '?'
            }
        })
        .collect()
}
