//! The tool catalog: the upstream's tool list as the gateway fetches it, and what is stored of it.

use std::collections::HashSet;

use axum::body::Bytes;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::{Value, json};

use super::sse::sse_events;
use super::upstream::{
    self, BodyError, Fault, Kind, Outgoing, Target, read_body, read_stream, time_limit,
};
use crate::app::AppState;
use crate::audit::{self, Event};
use crate::mcp::json::parse_strict;

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
    Db,
}

/// What one request answered.
enum Reply {
    /// A JSON-RPC result, and the size of the answer it came in.
    Result(Value, u64),
    /// Status 401 or 403.
    Denied,
    /// The answer is over the cap.
    TooLarge,
    /// A fault, another status or type, or an answer that is not a JSON-RPC result.
    Other,
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
) -> (Reply, Option<HeaderValue>) {
    let outgoing = Outgoing {
        method: Method::POST,
        headers,
        body: Bytes::from(body.to_string()),
        with_secret,
    };
    let response = match upstream::send(state, target, outgoing).await {
        Ok(response) => response,
        Err(Fault) => return (Reply::Other, None),
    };
    let session = response.headers().get(mcp_session()).cloned();
    if matches!(response.status().as_u16(), 401 | 403) {
        return (Reply::Denied, session);
    }
    let reply = match upstream::accept(&response) {
        Ok(Kind::Json) => match read_body(state, response, cap).await {
            Ok(bytes) => reply_of(&bytes, &id()),
            Err(BodyError::TooLarge) => Reply::TooLarge,
            Err(BodyError::Fault) => Reply::Other,
        },
        Ok(Kind::Stream) => stream_reply(state, response, cap, &id()).await,
        _ => Reply::Other,
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

/// The reply of an answer: its result, or Other for an error or any other shape.
fn reply_of_answer(mut answer: Value, size: u64) -> Reply {
    if answer.get("error").is_some() {
        return Reply::Other;
    }
    match answer
        .as_object_mut()
        .and_then(|object| object.remove("result"))
    {
        Some(result) => Reply::Result(result, size),
        None => Reply::Other,
    }
}

/// The reply of a JSON body to request `expected`.
fn reply_of(bytes: &[u8], expected: &Value) -> Reply {
    match parse_strict(bytes)
        .ok()
        .and_then(|value| answer_of(value, expected))
    {
        Some(answer) => reply_of_answer(answer, bytes.len() as u64),
        None => Reply::Other,
    }
}

/// Reads an event stream until its answer to request `expected` is complete, under the cap and
/// the time limit. The whole answer and the bytes read; a stream that ends without it is a Fault.
pub(crate) async fn stream_answer(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    expected: &Value,
) -> Result<(Value, u64), BodyError> {
    let mut pending: Vec<u8> = Vec::new();
    let mut found: Option<Value> = None;
    let read = read_stream(state, response, cap, |chunk| {
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
    found.map(|answer| (answer, read)).ok_or(BodyError::Fault)
}

/// The reply of an event stream that answers request `expected`.
async fn stream_reply(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    expected: &Value,
) -> Reply {
    match stream_answer(state, response, cap, expected).await {
        Ok((answer, total)) => reply_of_answer(answer, total),
        Err(BodyError::TooLarge) => Reply::TooLarge,
        Err(BodyError::Fault) => Reply::Other,
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

/// Pages through tools/list. None when the first answer is not a JSON-RPC result.
async fn list_pages(
    state: &AppState,
    target: &Target,
    stateless: bool,
    session: Option<&HeaderValue>,
    with_secret: bool,
) -> Result<Option<Vec<Value>>, RefreshError> {
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
        let (reply, _) = post(state, target, &body, headers, with_secret, cap).await;
        let (result, size) = match reply {
            Reply::Result(result, size) => (result, size),
            Reply::TooLarge => return Err(RefreshError::TooLarge),
            _ if page == 0 => return Ok(None),
            _ => return Err(RefreshError::Unavailable),
        };
        let (page_tools, next) = page_of(&result).ok_or(RefreshError::Unavailable)?;
        tools.extend(page_tools);
        used = used.saturating_add(size);
        match next {
            None => return Ok(Some(tools)),
            Some(next) => cursor = Some(next),
        }
    }
    Err(RefreshError::TooLarge)
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
async fn session_tools(state: &AppState, target: &Target) -> Result<Vec<Value>, RefreshError> {
    let limit = state.config.limits.tools_list_bytes;
    let (reply, session) = post(
        state,
        target,
        &init_body(),
        request_headers(SESSION, None, None),
        true,
        limit,
    )
    .await;
    match reply {
        Reply::Result(..) => {}
        Reply::TooLarge => return Err(RefreshError::TooLarge),
        _ => return Err(RefreshError::Unavailable),
    }
    let notified = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    post(
        state,
        target,
        &notified,
        request_headers(SESSION, None, session.as_ref()),
        true,
        limit,
    )
    .await;
    let listed = list_pages(state, target, false, session.as_ref(), true).await;
    if let Some(session) = session.as_ref() {
        close_session(state, target, session, true).await;
    }
    listed?.ok_or(RefreshError::Unavailable)
}

/// Asks the upstream for its tools: the stateless form first, then the session form.
async fn fetch(state: &AppState, target: &Target) -> Result<Vec<Value>, RefreshError> {
    if let Some(tools) = list_pages(state, target, true, None, true).await? {
        return Ok(tools);
    }
    session_tools(state, target).await
}

/// Asks the upstream for its tools as the gateway itself, within one time limit, and replaces the catalog.
/// A failure writes the server's fixed message and leaves the stored tools as they were.
pub async fn refresh(state: &AppState, target: &Target) -> Result<Vec<String>, RefreshError> {
    let fetched = match tokio::time::timeout(time_limit(state), fetch(state, target)).await {
        Ok(result) => result,
        Err(_) => Err(RefreshError::Unavailable),
    };
    match fetched {
        Ok(tools) => store(state, target.server_id, tools).await,
        Err(error) => {
            fail(state, target.server_id, error).await?;
            Err(error)
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
        .map_err(|_| RefreshError::Db)
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
        .map_err(|_| RefreshError::Db)
}

/// The lock-down probe without the secret: stateless tools/list, then the session initialize.
/// Returns "ok" for a refusal, "open" for a JSON-RPC result, and "unknown" otherwise.
pub async fn lockdown(state: &AppState, target: &Target) -> &'static str {
    let limit = state.config.limits.tools_list_bytes;
    let headers = request_headers(STATELESS, Some("tools/list"), None);
    let (reply, _) = post(state, target, &list_body(true, None), headers, false, limit).await;
    match reply {
        Reply::Result(..) => return "open",
        Reply::Denied => return "ok",
        _ => {}
    }
    let (reply, session) = post(
        state,
        target,
        &init_body(),
        request_headers(SESSION, None, None),
        false,
        limit,
    )
    .await;
    if let (Reply::Result(..), Some(session)) = (&reply, session.as_ref()) {
        close_session(state, target, session, false).await;
    }
    match reply {
        Reply::Result(..) => "open",
        Reply::Denied => "ok",
        _ => "unknown",
    }
}

/// The stored tool names of the server, in catalog order.
pub fn names(conn: &Connection, server_id: i64) -> rusqlite::Result<Vec<String>> {
    let mut statement =
        conn.prepare("SELECT name FROM tool_catalog WHERE server_id = ?1 ORDER BY position")?;
    let rows = statement.query_map(params![server_id], |row| row.get(0))?;
    rows.collect()
}

/// Replaces the server's tools in one IMMEDIATE transaction and returns the names that were new.
/// After the first refresh of a server, each new name gets a `tool_appeared` row, at most 50.
pub fn replace(
    conn: &mut Connection,
    server_id: i64,
    tools: &[Value],
    now: i64,
) -> rusqlite::Result<Vec<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (slug, had_success): (String, bool) = tx.query_row(
        "SELECT slug, catalog_at IS NOT NULL FROM servers WHERE id = ?1",
        params![server_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let before: HashSet<String> = names(&tx, server_id)?.into_iter().collect();
    tx.execute(
        "DELETE FROM tool_catalog WHERE server_id = ?1",
        params![server_id],
    )?;
    let mut seen: HashSet<&str> = HashSet::new();
    let mut added = Vec::new();
    let mut position: i64 = 0;
    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.is_empty() || name.len() > NAME_LIMIT || !seen.insert(name) {
            continue;
        }
        tx.execute(
            "INSERT INTO tool_catalog (server_id, position, name, definition) \
             VALUES (?1, ?2, ?3, ?4)",
            params![server_id, position, name, tool.to_string()],
        )?;
        position += 1;
        if !before.contains(name) {
            added.push(name.to_owned());
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
