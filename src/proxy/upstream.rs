//! The gateway's HTTP client for upstream servers: one request, the relay rule, a capped body.

use std::fmt;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};

use super::budget::Reservation;
use crate::app::AppState;
use crate::db::DbError;
use crate::report;
use crate::servers;

const USER_AGENT_VALUE: &str = concat!("doorward/", env!("CARGO_PKG_VERSION"));

/// The most time a list of tools may take on a miss, whichever endpoint asks.
pub(crate) const LIST_LIMIT: Duration = Duration::from_secs(10);

/// Writes the one line of a fault on the server `slug` and returns its phrase for the activity detail.
/// A database cause was written where it arose, so it writes nothing here.
pub fn fail(slug: &str, cause: Cause) -> String {
    let fault = Fault(cause);
    match cause {
        Cause::Written => {}
        Cause::SecretUnreadable => report::failure(&format!("server {slug}"), &fault),
        _ => report::failure(&format!("upstream {slug}"), &fault),
    }
    fault.to_string()
}

/// What the gateway needs to contact one server.
#[derive(Clone)]
pub struct Target {
    pub server_id: i64,
    pub slug: String,
    pub url: String,
    pub secret: Option<(HeaderName, HeaderValue)>,
}

#[derive(Debug)]
pub enum TargetError {
    Db(DbError),
    /// Stored, but it cannot be opened or is not a valid header.
    Secret,
}

/// None when no server has the id. The sealed text is read in `db.call`, opened outside it.
pub async fn target(state: &AppState, server_id: i64) -> Result<Option<Target>, TargetError> {
    let stored = state
        .db
        .call(move |conn| servers::load_upstream(conn, server_id))
        .await
        .map_err(TargetError::Db)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let secret = stored
        .sealed_secret
        .map(|sealed| open_header(state, server_id, &stored.secret_header_name, &sealed))
        .transpose()?;
    Ok(Some(Target {
        server_id,
        slug: stored.slug,
        url: stored.upstream_url,
        secret,
    }))
}

/// The secret header of a stored value; every failure is the same error, so no text leaks.
fn open_header(
    state: &AppState,
    server_id: i64,
    name: &str,
    sealed: &str,
) -> Result<(HeaderName, HeaderValue), TargetError> {
    let value =
        servers::open_secret(&state.keys, server_id, sealed).map_err(|_| TargetError::Secret)?;
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| TargetError::Secret)?;
    let value = HeaderValue::from_str(&value).map_err(|_| TargetError::Secret)?;
    Ok((name, value))
}

/// Why an upstream answer could not be used. Its phrase is the one the log and the activity row carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    NoConnection,
    NoAnswerInTime,
    Status(u16),
    WrongContentType,
    TooLarge,
    NotJson,
    NotMcp,
    /// The stored secret of the server cannot be opened; the gateway's fault, not the upstream's.
    SecretUnreadable,
    /// The answer memory budget is used up; the gateway's condition, not the upstream's.
    Busy,
    /// A database error, already written to standard error where it arose.
    Written,
}

/// An upstream fault and its cause. The client always gets the same 502; the cause goes to the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault(pub Cause);

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Cause::NoConnection => f.write_str("no connection"),
            Cause::NoAnswerInTime => f.write_str("no answer in time"),
            Cause::Status(code) => write!(f, "the upstream answered {code}"),
            Cause::WrongContentType => f.write_str("an answer of the wrong content type"),
            Cause::TooLarge => f.write_str("an answer over the size limit"),
            Cause::NotJson => f.write_str("an answer that is not valid JSON"),
            Cause::NotMcp => f.write_str("an answer that is not an MCP answer"),
            Cause::SecretUnreadable => f.write_str("the stored secret cannot be opened"),
            Cause::Busy => f.write_str("the answer memory budget is exhausted"),
            Cause::Written => f.write_str("the database could not be read"),
        }
    }
}

pub struct Outgoing {
    pub method: Method,
    /// Sent as given; the caller has already filtered them.
    pub headers: HeaderMap,
    pub body: Bytes,
    /// False only for the lock-down probe.
    pub with_secret: bool,
}

/// Sends one request to the stored URL, with the secret when `with_secret`.
/// Err only when no response headers arrive within `limits.upstream_timeout_seconds`.
pub async fn send(
    state: &AppState,
    target: &Target,
    outgoing: Outgoing,
) -> Result<reqwest::Response, Fault> {
    let Outgoing {
        method,
        mut headers,
        body,
        with_secret,
    } = outgoing;
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    if with_secret && let Some((name, value)) = &target.secret {
        headers.insert(name.clone(), value.clone());
    }
    let request = state
        .http
        .request(method, target.url.as_str())
        .headers(headers)
        .body(body);
    match tokio::time::timeout(time_limit(state), request.send()).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(err)) if err.is_timeout() => Err(Fault(Cause::NoAnswerInTime)),
        Ok(Err(_)) => Err(Fault(Cause::NoConnection)),
        Err(_) => Err(Fault(Cause::NoAnswerInTime)),
    }
}

/// What a relayed answer is: JSON, an event stream, or no body.
#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    Json,
    Stream,
    Empty,
}

/// The relay rule: statuses 200, 202, 400, 404 and 405 with a JSON or event-stream body, or with
/// no body. A 202, or a declared Content-Length 0, is an empty answer whatever its type.
pub fn accept(response: &reqwest::Response) -> Result<Kind, Fault> {
    let status = response.status().as_u16();
    if !matches!(status, 200 | 202 | 400 | 404 | 405) {
        return Err(Fault(Cause::Status(status)));
    }
    let headers = response.headers();
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok());
    if status == 202 || declared == Some(0) {
        return Ok(Kind::Empty);
    }
    let Some(content_type) = headers.get(CONTENT_TYPE) else {
        return if declared.is_none() {
            Ok(Kind::Empty)
        } else {
            Err(Fault(Cause::WrongContentType))
        };
    };
    let essence = content_type
        .to_str()
        .ok()
        .and_then(|text| text.split(';').next())
        .map(|essence| essence.trim().to_ascii_lowercase());
    match essence.as_deref() {
        Some("application/json") => Ok(Kind::Json),
        Some("text/event-stream") => Ok(Kind::Stream),
        _ => Err(Fault(Cause::WrongContentType)),
    }
}

/// The whole body, at most `cap` bytes, within `limits.upstream_timeout_seconds`.
/// `held` covers the bytes read.
pub async fn body(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    held: &mut Reservation,
) -> Result<Bytes, Fault> {
    read_body(state, response, cap, held)
        .await
        .map_err(BodyError::into_fault)
}

/// Why a body was not read: a fault with its cause, or more bytes than the cap allows.
pub(crate) enum BodyError {
    Fault(Cause),
    TooLarge,
}

impl BodyError {
    pub(crate) fn into_fault(self) -> Fault {
        match self {
            BodyError::Fault(cause) => Fault(cause),
            BodyError::TooLarge => Fault(Cause::TooLarge),
        }
    }
}

/// Reads under the cap and the time limit, setting `held` to the bytes read before each chunk is fed.
/// `feed` returns true to stop early; the result is the number of bytes read.
pub(crate) async fn read_stream<F>(
    state: &AppState,
    mut response: reqwest::Response,
    cap: u64,
    held: &mut Reservation,
    mut feed: F,
) -> Result<u64, BodyError>
where
    F: FnMut(&[u8]) -> bool,
{
    let read = async {
        let mut total: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| BodyError::Fault(Cause::NoConnection))?
        {
            total = total.saturating_add(chunk.len() as u64);
            if total > cap {
                return Err(BodyError::TooLarge);
            }
            if !held.set(usize::try_from(total).unwrap_or(usize::MAX)) {
                // The read is abandoned, so the bytes it held go back to the budget now.
                held.set(0);
                return Err(BodyError::Fault(Cause::Busy));
            }
            if feed(chunk.as_ref()) {
                break;
            }
        }
        Ok::<u64, BodyError>(total)
    };
    match tokio::time::timeout(time_limit(state), read).await {
        Ok(result) => result,
        Err(_) => Err(BodyError::Fault(Cause::NoAnswerInTime)),
    }
}

/// The whole body, read under the cap and the time limit.
pub(crate) async fn read_body(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    held: &mut Reservation,
) -> Result<Bytes, BodyError> {
    let mut bytes: Vec<u8> = Vec::new();
    read_stream(state, response, cap, held, |chunk| {
        bytes.extend_from_slice(chunk);
        false
    })
    .await?;
    Ok(Bytes::from(bytes))
}

/// `limits.upstream_timeout_seconds` as a duration.
pub(crate) fn time_limit(state: &AppState) -> Duration {
    Duration::from_secs(state.config.limits.upstream_timeout_seconds)
}
