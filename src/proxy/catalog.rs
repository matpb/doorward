//! The tool catalog: the upstream's tool list as the gateway fetches it, and what is stored of it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::budget::Reservation;
use super::sse::sse_events;
use super::upstream::{
    self, BodyError, Cause, Fault, Kind, Outgoing, Target, read_body, read_stream, time_limit,
};
use crate::app::AppState;
use crate::audit::{self, Event};
use crate::mcp::json::parse_strict;
use crate::report;

const MAX_PAGES: usize = 20;
const NAME_LIMIT: usize = 128;
const APPEARED_LIMIT: usize = 50;
pub(super) const STATELESS: &str = "2026-07-28";
pub(super) const SESSION: &str = "2025-11-25";
const ACCEPTS: &str = "application/json, text/event-stream";
const UNAVAILABLE: &str = "The last refresh failed: the upstream did not answer with a tool list.";
const TOO_LARGE: &str = "The last refresh failed: the tool list is larger than the limit.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshError {
    Unavailable,
    TooLarge,
    /// The answer memory budget is used up; the stored refresh error is left as it was.
    Busy,
    Db,
}

/// A failed fetch: the refresh error, and the upstream cause the log names.
#[derive(Debug, Clone, Copy)]
struct Failure {
    error: RefreshError,
    cause: Option<Cause>,
}

impl Failure {
    fn upstream(cause: Cause) -> Failure {
        let error = match cause {
            Cause::Busy => RefreshError::Busy,
            _ => RefreshError::Unavailable,
        };
        Failure {
            error,
            cause: Some(cause),
        }
    }

    fn too_large() -> Failure {
        Failure {
            error: RefreshError::TooLarge,
            cause: Some(Cause::TooLarge),
        }
    }
}

/// What one request answered.
enum Reply {
    /// A JSON-RPC result, and the size of the answer it came in.
    Result(Value, u64),
    /// Status 401 or 403.
    Denied(u16),
    /// The answer is over the cap.
    TooLarge,
    /// A fault with its cause, or an answer that is not a JSON-RPC result.
    Other(Cause),
}

fn id() -> Value {
    json!(1)
}

fn mcp_version() -> HeaderName {
    HeaderName::from_static("mcp-protocol-version")
}

fn mcp_session() -> HeaderName {
    HeaderName::from_static("mcp-session-id")
}

/// The headers of one request of the sequence, for the stateless or the session form.
pub(super) fn request_headers(
    version: &'static str,
    method: Option<&'static str>,
    session: Option<&HeaderValue>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static(ACCEPTS));
    headers.insert(mcp_version(), HeaderValue::from_static(version));
    if let Some(method) = method {
        headers.insert(
            HeaderName::from_static("mcp-method"),
            HeaderValue::from_static(method),
        );
    }
    if let Some(session) = session {
        headers.insert(mcp_session(), session.clone());
    }
    headers
}

/// The tools/list request, in the stateless form (with its version in `_meta`) or the session form.
fn list_body(stateless: bool, cursor: Option<&str>) -> Value {
    let mut params = if stateless {
        json!({"_meta": {"io.modelcontextprotocol/protocolVersion": STATELESS}})
    } else {
        json!({})
    };
    if let Some(cursor) = cursor {
        params["cursor"] = json!(cursor);
    }
    json!({"jsonrpc": "2.0", "id": id(), "method": "tools/list", "params": params})
}

/// The initialize request of the session form.
fn init_body() -> Value {
    json!({"jsonrpc": "2.0", "id": id(), "method": "initialize", "params": {
        "protocolVersion": SESSION,
        "capabilities": {},
        "clientInfo": {"name": "doorward", "version": env!("CARGO_PKG_VERSION")},
    }})
}

/// Sends one JSON-RPC request. Also returns the session id the answer carries, if any.
async fn post(
    state: &AppState,
    target: &Target,
    body: &Value,
    headers: HeaderMap,
    with_secret: bool,
    cap: u64,
    user: Option<i64>,
) -> (Reply, Option<HeaderValue>) {
    let outgoing = Outgoing {
        method: Method::POST,
        headers,
        body: Bytes::from(body.to_string()),
        with_secret,
    };
    let response = match upstream::send(state, target, outgoing).await {
        Ok(response) => response,
        Err(Fault(cause)) => return (Reply::Other(cause), None),
    };
    let session = response.headers().get(mcp_session()).cloned();
    let status = response.status().as_u16();
    if matches!(status, 401 | 403) {
        return (Reply::Denied(status), session);
    }
    let mut page = state.links.budget().reservation(user);
    let reply = match upstream::accept(&response) {
        Ok(Kind::Json) => match read_body(state, response, cap, &mut page).await {
            Ok(bytes) => reply_of(&bytes, &id()),
            Err(BodyError::TooLarge) => Reply::TooLarge,
            Err(BodyError::Fault(cause)) => Reply::Other(cause),
        },
        Ok(Kind::Stream) => stream_reply(state, response, cap, &id(), &mut page).await,
        Ok(Kind::Empty) => Reply::Other(Cause::NotMcp),
        Err(Fault(cause)) => Reply::Other(cause),
    };
    (reply, session)
}

/// The whole answer to request `expected` in one JSON-RPC message (a result or an error);
/// None for any other message.
pub(crate) fn answer_of(value: Value, expected: &Value) -> Option<Value> {
    let object = value.as_object()?;
    if object.get("id") != Some(expected) {
        return None;
    }
    (object.contains_key("result") || object.contains_key("error")).then_some(value)
}

/// The reply of an answer: its result, or an error for an error or any other shape.
fn reply_of_answer(mut answer: Value, size: u64) -> Reply {
    if answer.get("error").is_some() {
        return Reply::Other(Cause::NotMcp);
    }
    match answer
        .as_object_mut()
        .and_then(|object| object.remove("result"))
    {
        Some(result) => Reply::Result(result, size),
        None => Reply::Other(Cause::NotMcp),
    }
}

/// The reply of a JSON body to request `expected`: a result, or the cause of its refusal.
fn reply_of(bytes: &[u8], expected: &Value) -> Reply {
    let Ok(value) = parse_strict(bytes) else {
        return Reply::Other(Cause::NotJson);
    };
    match answer_of(value, expected) {
        Some(answer) => reply_of_answer(answer, bytes.len() as u64),
        None => Reply::Other(Cause::NotMcp),
    }
}

/// Reads an event stream until its answer to request `expected` is complete, under the cap and
/// the time limit. The whole answer and the bytes read; a stream that ends without it is a Fault.
pub(crate) async fn stream_answer(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    expected: &Value,
    held: &mut Reservation,
) -> Result<(Value, u64), BodyError> {
    let mut pending: Vec<u8> = Vec::new();
    let mut found: Option<Value> = None;
    let read = read_stream(state, response, cap, held, |chunk| {
        pending.extend_from_slice(chunk);
        let (events, used) = sse_events(&pending);
        pending.drain(..used);
        for data in events {
            let answer = parse_strict(&data)
                .ok()
                .and_then(|value| answer_of(value, expected));
            if answer.is_some() {
                found = answer;
                return true;
            }
        }
        false
    })
    .await?;
    found
        .map(|answer| (answer, read))
        .ok_or(BodyError::Fault(Cause::NotMcp))
}

/// The reply of an event stream that answers request `expected`.
async fn stream_reply(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    expected: &Value,
    held: &mut Reservation,
) -> Reply {
    match stream_answer(state, response, cap, expected, held).await {
        Ok((answer, total)) => reply_of_answer(answer, total),
        Err(BodyError::TooLarge) => Reply::TooLarge,
        Err(BodyError::Fault(cause)) => Reply::Other(cause),
    }
}

/// The page's tools and its next cursor; None when the result has another shape.
fn page_of(result: &Value) -> Option<(Vec<Value>, Option<String>)> {
    let tools = result.get("tools")?.as_array()?.clone();
    let next = match result.get("nextCursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return None,
    };
    Some((tools, next))
}

/// Pages through tools/list. None when the first answer is not a JSON-RPC result. `held` covers the
/// bytes of every page so far.
async fn list_pages(
    state: &AppState,
    target: &Target,
    stateless: bool,
    session: Option<&HeaderValue>,
    with_secret: bool,
    user: Option<i64>,
    held: &mut Reservation,
) -> Result<Option<Vec<Value>>, Failure> {
    let limit = state.config.limits.tools_list_bytes;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut used: u64 = 0;
    for page in 0..MAX_PAGES {
        let headers = if stateless {
            request_headers(STATELESS, Some("tools/list"), None)
        } else {
            request_headers(SESSION, None, session)
        };
        let body = list_body(stateless, cursor.as_deref());
        let cap = limit.saturating_sub(used);
        let (reply, _) = post(state, target, &body, headers, with_secret, cap, user).await;
        let (result, size) = match reply {
            Reply::Result(result, size) => (result, size),
            Reply::TooLarge => return Err(Failure::too_large()),
            // The budget's refusal is the gateway's, so it is no reason to try the session form.
            Reply::Other(Cause::Busy) => return Err(Failure::upstream(Cause::Busy)),
            _ if page == 0 => return Ok(None),
            Reply::Denied(code) => return Err(Failure::upstream(Cause::Status(code))),
            Reply::Other(cause) => return Err(Failure::upstream(cause)),
        };
        let (page_tools, next) = page_of(&result).ok_or(Failure::upstream(Cause::NotMcp))?;
        tools.extend(page_tools);
        used = used.saturating_add(size);
        if !held.set(usize::try_from(used).unwrap_or(usize::MAX)) {
            return Err(Failure::upstream(Cause::Busy));
        }
        match next {
            None => return Ok(Some(tools)),
            Some(next) => cursor = Some(next),
        }
    }
    Err(Failure::too_large())
}

/// Closes a session with DELETE. Best effort: the answer does not change the result.
pub(super) async fn close_session(
    state: &AppState,
    target: &Target,
    session: &HeaderValue,
    with_secret: bool,
) {
    let closing = Outgoing {
        method: Method::DELETE,
        headers: request_headers(SESSION, None, Some(session)),
        body: Bytes::new(),
        with_secret,
    };
    let _closed = upstream::send(state, target, closing).await;
}

/// The session form: initialize, the notification, the list, then DELETE of the session.
async fn session_tools(
    state: &AppState,
    target: &Target,
    user: Option<i64>,
    held: &mut Reservation,
) -> Result<Vec<Value>, Failure> {
    let limit = state.config.limits.tools_list_bytes;
    let (reply, session) = post(
        state,
        target,
        &init_body(),
        request_headers(SESSION, None, None),
        true,
        limit,
        user,
    )
    .await;
    match reply {
        Reply::Result(..) => {}
        Reply::TooLarge => return Err(Failure::too_large()),
        Reply::Denied(code) => return Err(Failure::upstream(Cause::Status(code))),
        Reply::Other(cause) => return Err(Failure::upstream(cause)),
    }
    let notified = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    post(
        state,
        target,
        &notified,
        request_headers(SESSION, None, session.as_ref()),
        true,
        limit,
        user,
    )
    .await;
    let listed = list_pages(state, target, false, session.as_ref(), true, user, held).await;
    if let Some(session) = session.as_ref() {
        close_session(state, target, session, true).await;
    }
    listed?.ok_or(Failure::upstream(Cause::NotMcp))
}

/// Asks the upstream for its tools: the stateless form first, then the session form.
async fn fetch(
    state: &AppState,
    target: &Target,
    user: Option<i64>,
    held: &mut Reservation,
) -> Result<Vec<Value>, Failure> {
    if let Some(tools) = list_pages(state, target, true, None, true, user, held).await? {
        return Ok(tools);
    }
    session_tools(state, target, user, held).await
}

/// Asks the upstream for its tools as the gateway itself, within one time limit, and replaces the catalog.
/// A failure writes the server's fixed message and leaves the stored tools as they were.
pub async fn refresh(
    state: &AppState,
    target: &Target,
    user: Option<i64>,
) -> Result<Vec<String>, RefreshError> {
    refresh_within(state, target, time_limit(state), user).await
}

/// As `refresh`, with `limit` as the time the upstream may take.
pub async fn refresh_within(
    state: &AppState,
    target: &Target,
    limit: Duration,
    user: Option<i64>,
) -> Result<Vec<String>, RefreshError> {
    // Held until the parsed list is stored, which is when the gateway no longer needs its bytes.
    let mut held = state.links.budget().reservation(user);
    let fetched = match tokio::time::timeout(limit, fetch(state, target, user, &mut held)).await {
        Ok(result) => result,
        Err(_) => Err(Failure::upstream(Cause::NoAnswerInTime)),
    };
    match fetched {
        Ok(tools) => store(state, target.server_id, tools).await,
        Err(failure) => {
            if let Some(cause) = failure.cause {
                report::failure(&format!("upstream {}", target.slug), &Fault(cause));
            }
            fail(state, target.server_id, failure.error).await?;
            Err(failure.error)
        }
    }
}

async fn store(
    state: &AppState,
    server_id: i64,
    tools: Vec<Value>,
) -> Result<Vec<String>, RefreshError> {
    let now = state.clock.now().unix_timestamp();
    state
        .db
        .call(move |conn| {
            replace(conn, server_id, &tools, now)?;
            names(conn, server_id)
        })
        .await
        .map_err(|err| {
            report::failure("tool catalog", &err);
            RefreshError::Db
        })
}

/// Writes the fixed message of a failed refresh. The stored tools are not touched.
pub async fn fail(
    state: &AppState,
    server_id: i64,
    error: RefreshError,
) -> Result<(), RefreshError> {
    let message = match error {
        RefreshError::Unavailable => UNAVAILABLE,
        RefreshError::TooLarge => TOO_LARGE,
        RefreshError::Busy => return Ok(()),
        RefreshError::Db => return Err(RefreshError::Db),
    };
    state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET catalog_error = ?1 WHERE id = ?2",
                params![message, server_id],
            )
        })
        .await
        .map(|_| ())
        .map_err(|err| {
            report::failure("tool catalog", &err);
            RefreshError::Db
        })
}

/// The lock-down probe without the secret: stateless tools/list, then the session initialize.
/// Returns "ok" for a refusal, "open" for a JSON-RPC result, and "unknown" otherwise.
pub async fn lockdown(state: &AppState, target: &Target) -> &'static str {
    let limit = state.config.limits.tools_list_bytes;
    let headers = request_headers(STATELESS, Some("tools/list"), None);
    let (reply, _) = post(
        state,
        target,
        &list_body(true, None),
        headers,
        false,
        limit,
        None,
    )
    .await;
    match reply {
        Reply::Result(..) => return "open",
        Reply::Denied(_) => return "ok",
        _ => {}
    }
    let (reply, session) = post(
        state,
        target,
        &init_body(),
        request_headers(SESSION, None, None),
        false,
        limit,
        None,
    )
    .await;
    if let (Reply::Result(..), Some(session)) = (&reply, session.as_ref()) {
        close_session(state, target, session, false).await;
    }
    match reply {
        Reply::Result(..) => "open",
        Reply::Denied(_) => "ok",
        _ => "unknown",
    }
}

/// True while a miss refresh stamped at `last` holds the next one off. A stamp later than `now`, from a
/// clock stepped back, holds nothing off.
pub fn held_off(last: Option<i64>, now: i64, every: i64) -> bool {
    last.is_some_and(|stamp| stamp <= now && now - stamp < every)
}

/// The miss refreshes of each server: a miss waits for the one in flight.
#[derive(Default)]
pub struct Misses {
    servers: Mutex<HashMap<i64, Arc<AsyncMutex<Option<i64>>>>>,
}

impl Misses {
    /// The server's slot, which holds the start of its last miss refresh while the caller keeps it.
    pub async fn lock(&self, server_id: i64) -> OwnedMutexGuard<Option<i64>> {
        let slot = {
            let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(servers.entry(server_id).or_default())
        };
        slot.lock_owned().await
    }
}

/// The stored tool names of the server, in catalog order.
pub fn names(conn: &Connection, server_id: i64) -> rusqlite::Result<Vec<String>> {
    let mut statement =
        conn.prepare("SELECT name FROM tool_catalog WHERE server_id = ?1 ORDER BY position")?;
    let rows = statement.query_map(params![server_id], |row| row.get(0))?;
    rows.collect()
}

/// The stored definitions of the server, in catalog order.
pub fn definitions(conn: &Connection, server_id: i64) -> rusqlite::Result<Vec<(String, String)>> {
    let mut statement = conn.prepare(
        "SELECT name, definition FROM tool_catalog WHERE server_id = ?1 ORDER BY position",
    )?;
    let rows = statement.query_map(params![server_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

/// The tools the catalog keeps, as name and definition text: named, at most 128 bytes, first of each name.
fn kept_tools(tools: &[Value]) -> Vec<(&str, String)> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut kept = Vec::new();
    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.is_empty() || name.len() > NAME_LIMIT || !seen.insert(name) {
            continue;
        }
        kept.push((name, tool.to_string()));
    }
    kept
}

/// Replaces the server's tools in one IMMEDIATE transaction and returns the names that were new.
/// Writes nothing when the stored tools already equal `tools` and the last refresh succeeded.
pub fn replace(
    conn: &mut Connection,
    server_id: i64,
    tools: &[Value],
    now: i64,
) -> rusqlite::Result<Vec<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (slug, had_success, clean): (String, bool, bool) = tx.query_row(
        "SELECT slug, catalog_at IS NOT NULL, catalog_error IS NULL FROM servers WHERE id = ?1",
        params![server_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let kept = kept_tools(tools);
    let stored = definitions(&tx, server_id)?;
    let unchanged = clean
        && had_success
        && stored.len() == kept.len()
        && stored
            .iter()
            .zip(&kept)
            .all(|((name, text), (kept_name, kept_text))| {
                name.as_str() == *kept_name && text.as_str() == kept_text.as_str()
            });
    if unchanged {
        return Ok(Vec::new());
    }
    let before: HashSet<String> = stored.into_iter().map(|(name, _)| name).collect();
    tx.execute(
        "DELETE FROM tool_catalog WHERE server_id = ?1",
        params![server_id],
    )?;
    let mut added = Vec::new();
    for (position, (name, text)) in kept.iter().enumerate() {
        tx.execute(
            "INSERT INTO tool_catalog (server_id, position, name, definition) \
             VALUES (?1, ?2, ?3, ?4)",
            params![server_id, position as i64, name, text],
        )?;
        if !before.contains(*name) {
            added.push((*name).to_owned());
        }
    }
    tx.execute(
        "UPDATE servers SET catalog_at = ?1, catalog_error = NULL WHERE id = ?2",
        params![now, server_id],
    )?;
    if had_success {
        for name in added.iter().take(APPEARED_LIMIT) {
            let row = Event {
                kind: "tool_appeared",
                server_id: Some(server_id),
                server_slug: &slug,
                tool: name,
                ..Default::default()
            };
            audit::record(&tx, now, &row)?;
        }
    }
    tx.commit()?;
    Ok(added)
}
