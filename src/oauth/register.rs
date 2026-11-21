//! `POST /oauth/register`: dynamic client registration, rate limited per address.

use std::net::{IpAddr, Ipv4Addr};

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use serde_json::{Map, Value, json};

use crate::app::AppState;
use crate::crypto::random_token;
use crate::report;
use crate::web::body::{ReadError, read, timed_out};
use crate::web::limit;
use crate::web::stall::Peer;
use crate::web::{client_address, throttle_key};

use super::uri;

const BODY_LIMIT: usize = 16 * 1024;
const JSON_TYPE: &str = "application/json";
const DEFAULT_NAME: &str = "Unnamed client";
const NAME_LIMIT: usize = 100;
const MAX_REDIRECT_URIS: usize = 10;
const HOUR_SECONDS: i64 = 3600;
const WEEK_SECONDS: i64 = 7 * 24 * 3600;
/// The window of the registration limits, in seconds: the Retry-After of a limited registration.
const HOUR_WAIT: u64 = 3600;

/// Why a registration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Metadata,
    RedirectUri,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Metadata => "invalid_client_metadata",
            Refusal::RedirectUri => "invalid_redirect_uri",
        }
    }
}

/// The metadata that passed the checks, ready to store.
#[derive(Debug, PartialEq, Eq)]
pub struct Registration {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

/// What the one transaction decided.
#[derive(Debug)]
pub enum Decision {
    Created(Value),
    Limited,
    Refused(Refusal),
}

/// Every answer carries `Cache-Control: no-store`. Nothing here reads a cookie.
pub async fn post_register(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !is_json(&parts.headers) {
        return refuse(Refusal::Metadata);
    }
    let bytes = match read(body, BODY_LIMIT, state.config.limits.body_read_seconds).await {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge) => return refuse(Refusal::Metadata),
        Err(ReadError::TimedOut) => return timed_out(),
    };
    let Some(object) = parse_object(&bytes) else {
        return refuse(Refusal::Metadata);
    };
    let peer = peer_ip(&parts);
    let address = throttle_key(client_address(
        peer,
        &parts.headers,
        &state.config.trusted_proxies,
    ));
    let checked = check_metadata(&object);
    let now = state.clock.now().unix_timestamp();
    let limit = i64::try_from(state.config.limits.dcr_per_hour).unwrap_or(i64::MAX);
    let unused = i64::try_from(state.config.limits.unused_registrations).unwrap_or(i64::MAX);
    let decided = state
        .db
        .call(move |conn| register_bounded(conn, &address, limit, unused, now, checked))
        .await;
    match decided {
        Ok(Decision::Created(body)) => answer(StatusCode::CREATED, body),
        Ok(Decision::Limited) => limit::json_limited(HOUR_WAIT),
        Ok(Decision::Refused(refusal)) => refuse(refusal),
        Err(err) => {
            report::failure("client registration", &err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CACHE_CONTROL, "no-store")],
            )
                .into_response()
        }
    }
}

/// A JSON answer with the no-store header.
fn answer(status: StatusCode, body: Value) -> Response {
    (status, [(CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

fn refuse(refusal: Refusal) -> Response {
    answer(StatusCode::BAD_REQUEST, json!({"error": refusal.code()}))
}

/// The media type before any `;`, compared without regard to letter case.
pub fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(JSON_TYPE))
}

/// The body as a JSON object, or None.
pub fn parse_object(bytes: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice::<Value>(bytes).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// The socket address of the request, unspecified when the server recorded none.
fn peer_ip(parts: &Parts) -> IpAddr {
    parts
        .extensions
        .get::<ConnectInfo<Peer>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.0.ip())
}

/// The redirect addresses first, then the name: the first refusal in that order decides.
pub fn check_metadata(object: &Map<String, Value>) -> Result<Registration, Refusal> {
    let redirect_uris = redirect_uris(object)?;
    let client_name = client_name(object)?;
    Ok(Registration {
        client_name,
        redirect_uris,
    })
}

fn redirect_uris(object: &Map<String, Value>) -> Result<Vec<String>, Refusal> {
    let Some(Value::Array(items)) = object.get("redirect_uris") else {
        return Err(Refusal::Metadata);
    };
    if items.is_empty() || items.len() > MAX_REDIRECT_URIS {
        return Err(Refusal::Metadata);
    }
    items.iter().map(redirect_uri).collect()
}

fn redirect_uri(item: &Value) -> Result<String, Refusal> {
    let Some(text) = item.as_str() else {
        return Err(Refusal::Metadata);
    };
    if uri::parse(text).is_some() {
        return Ok(text.to_owned());
    }
    if text.contains('#') || text.contains('*') || text.starts_with("http://") {
        Err(Refusal::RedirectUri)
    } else {
        Err(Refusal::Metadata)
    }
}

fn client_name(object: &Map<String, Value>) -> Result<String, Refusal> {
    match object.get("client_name") {
        None => Ok(DEFAULT_NAME.to_owned()),
        Some(Value::String(text)) => plain_name(text),
        Some(_) => Err(Refusal::Metadata),
    }
}

/// The trimmed name, or the default when nothing is left of it.
fn plain_name(text: &str) -> Result<String, Refusal> {
    let name = text.trim();
    if name.is_empty() {
        return Ok(DEFAULT_NAME.to_owned());
    }
    if name.chars().count() > NAME_LIMIT || !is_plain_text(name) {
        return Err(Refusal::Metadata);
    }
    Ok(name.to_owned())
}

/// False for control characters and for the invisible and direction characters.
pub(crate) fn is_plain_text(text: &str) -> bool {
    text.chars().all(is_plain_char)
}

/// False for a control character and for an invisible or direction character.
pub(crate) fn is_plain_char(c: char) -> bool {
    !c.is_control() && !is_invisible(c)
}

/// The soft hyphen, the invisible joiners and fillers, the direction marks and the line separators.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
    )
}

/// One transaction: the attempt is counted first; then the refusal or the new client is decided.
/// As `register_bounded`, with no bound on the registrations that were never used.
pub fn register_in(
    conn: &mut Connection,
    address: &str,
    limit: i64,
    now: i64,
    checked: Result<Registration, Refusal>,
) -> rusqlite::Result<Decision> {
    register_bounded(conn, address, limit, i64::MAX, now, checked)
}

/// As `register_in`, and keeps at most `unused_bound` registrations that were never used.
pub fn register_bounded(
    conn: &mut Connection,
    address: &str,
    limit: i64,
    unused_bound: i64,
    now: i64,
    checked: Result<Registration, Refusal>,
) -> rusqlite::Result<Decision> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM dcr_attempts WHERE at < ?1",
        params![now - HOUR_SECONDS],
    )?;
    let counted: i64 = tx.query_row(
        "SELECT COUNT(*) FROM dcr_attempts WHERE address = ?1",
        params![address],
        |row| row.get(0),
    )?;
    if counted >= limit {
        tx.commit()?;
        return Ok(Decision::Limited);
    }
    tx.execute(
        "INSERT INTO dcr_attempts (address, at) VALUES (?1, ?2)",
        params![address, now],
    )?;
    let registration = match checked {
        Ok(registration) => registration,
        Err(refusal) => {
            tx.commit()?;
            return Ok(Decision::Refused(refusal));
        }
    };
    let created = insert_client(&tx, &registration, now, unused_bound)?;
    tx.commit()?;
    Ok(Decision::Created(created))
}

/// Drops unused registrations older than a week, makes room under the bound, then stores the new
/// one and returns its answer.
fn insert_client(
    tx: &Transaction<'_>,
    registration: &Registration,
    now: i64,
    unused_bound: i64,
) -> rusqlite::Result<Value> {
    tx.execute(
        "DELETE FROM oauth_clients WHERE used_at IS NULL AND created_at < ?1",
        params![now - WEEK_SECONDS],
    )?;
    make_room(tx, unused_bound)?;
    let client_id = random_token("dcr_");
    let stored_uris = Value::from(registration.redirect_uris.clone()).to_string();
    tx.execute(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![client_id, registration.client_name, stored_uris, now],
    )?;
    Ok(json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "redirect_uris": registration.redirect_uris,
        "client_name": registration.client_name,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }))
}

/// Deletes the oldest unused registrations until one more fits under `bound`. Used ones stay.
fn make_room(tx: &Transaction<'_>, bound: i64) -> rusqlite::Result<()> {
    let unused: i64 = tx.query_row(
        "SELECT COUNT(*) FROM oauth_clients WHERE used_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    let excess = unused - bound + 1;
    if excess > 0 {
        tx.execute(
            "DELETE FROM oauth_clients WHERE rowid IN (SELECT rowid FROM oauth_clients \
             WHERE used_at IS NULL ORDER BY created_at, rowid LIMIT ?1)",
            params![excess],
        )?;
    }
    Ok(())
}
