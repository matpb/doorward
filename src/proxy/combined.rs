//! The gateway's own MCP server on `/mcp`: its methods, and tools/list across the user's servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::future::join_all;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::{Instant, timeout, timeout_at};

use super::budget::Reservation;
use super::catalog::{self, RefreshError, SESSION, STATELESS};
use super::combined_stream::{self, Call};
use super::handle::{
    INVALID, NOT_LISTED, Owed, TOOL_LIMIT, answer_for, bare, cut, not_allowed, resolve_server,
};
use super::intake::{Intake, intake};
use super::links::{self, Answer, Ask, Owner};
use super::stream::{ACCESS_LOST, CHECK_FAILED, Owned, detail_of};
use super::upstream::{
    self, Cause, Fault, Kind, LIST_LIMIT, TargetError, budget_refused, time_limit,
};
use crate::app::AppState;
use crate::audit::{self, OwnedEvent};
use crate::custom_headers::Resolved;
use crate::db::DbError;
use crate::mcp::answer;
use crate::mcp::message::{
    Decision, Generation, Message, Shape, Switches, decide, meta_version, param,
};
use crate::oauth::guard::{Caller, Recheck, combined_still_valid_at};
use crate::policy;
use crate::report;
use crate::servers::valid_slug;
use crate::web::limit::hold;

/// The most pages one upstream list may take.
const MAX_PAGES: usize = 20;
/// The longest name a listed tool may have: `{slug}__{name}`.
const MERGED_LIMIT: usize = 128;
/// The revisions the endpoint supports under the stateless rules, newest first.
const SUPPORTED: [&str; 4] = [STATELESS, SESSION, "2025-06-18", "2025-03-26"];
/// The revisions a session initialize may answer with, newest first.
const REVISIONS: [&str; 3] = [SESSION, "2025-06-18", "2025-03-26"];
const LABEL: &str = "mcp";
/// The row detail of a call whose stateless request headers do not match the stored definition.
const HEADER_MISMATCH: &str = "the request headers do not match the call";
const TTL_MS: i64 = 60_000;
const ALL: Switches = Switches {
    resources: true,
    prompts: true,
};

/// The proxy's gates: one list at a time per user, and the miss refreshes of each server.
#[derive(Default)]
pub struct Turns {
    gates: Mutex<HashMap<i64, Arc<AsyncMutex<()>>>>,
    pub misses: catalog::Misses,
}

impl Turns {
    fn lock(&self) -> MutexGuard<'_, HashMap<i64, Arc<AsyncMutex<()>>>> {
        self.gates.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A user's turn. The gate is dropped from the table once no turn or wait holds it.
pub struct Turn {
    turns: Arc<Turns>,
    user: i64,
    gate: Arc<AsyncMutex<()>>,
    held: Option<OwnedMutexGuard<()>>,
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.held = None;
        let mut gates = self.turns.lock();
        // The table and this turn hold the gate; any other turn or wait holds one more.
        if gates
            .get(&self.user)
            .is_some_and(|gate| Arc::strong_count(gate) == 2)
        {
            gates.remove(&self.user);
        }
    }
}

/// Waits until no other list of `user` runs, then holds the user's turn.
pub async fn enter(turns: &Arc<Turns>, user: i64) -> Turn {
    let gate = Arc::clone(
        turns
            .lock()
            .entry(user)
            .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
    );
    let mut turn = Turn {
        turns: Arc::clone(turns),
        user,
        gate,
        held: None,
    };
    let waiting = Arc::clone(&turn.gate);
    turn.held = Some(waiting.lock_owned().await);
    turn
}

/// The log lines of this process, kept for the tests that check what was logged.
#[cfg(test)]
pub(crate) static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Writes one log line. A line names a server slug and a count, never a tool.
fn note(line: String) {
    #[cfg(test)]
    NOTES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(line.clone());
    report::failure("tool list", &line);
}

/// Answers one request of `/mcp` for a caller that passed the bearer check.
pub async fn handle(state: &AppState, caller: Caller, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if parts.method != Method::POST {
        return not_allowed();
    }
    post(state, &Arc::new(caller), &parts.headers, body).await
}

async fn post(state: &AppState, caller: &Arc<Caller>, headers: &HeaderMap, body: Body) -> Response {
    let Intake { message, bytes } = match intake(state, headers, body).await {
        Ok(intake) => intake,
        Err(refusal) => return refusal,
    };
    if headers.contains_key("mcp-session-id") {
        return bare(StatusCode::NOT_FOUND);
    }
    let null = Value::Null;
    let id = message.id.as_ref().unwrap_or(&null);
    if let Some(requested) = unsupported(&message) {
        return respond(
            StatusCode::BAD_REQUEST,
            &json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {"supported": SUPPORTED, "requested": requested},
            }}),
        );
    }
    if message.shape == Shape::Response {
        return answer::error(
            StatusCode::BAD_REQUEST,
            message.id.as_ref(),
            -32600,
            INVALID,
        );
    }
    if !matches!(decide(&message, ALL), Decision::Forward) {
        return match message.shape {
            Shape::Request => answer::method_not_found(&message),
            _ => bare(StatusCode::ACCEPTED),
        };
    }
    if message.shape == Shape::Notification {
        return bare(StatusCode::ACCEPTED);
    }
    match (message.generation, message.method.as_deref()) {
        (Generation::Session, Some("initialize")) => result(id, initialize(&message)),
        (Generation::Session, Some("ping")) => result(id, json!({})),
        (Generation::Stateless, Some("server/discover")) => result(id, discover()),
        (_, Some("tools/list")) => list(state, caller, headers, &message).await,
        (_, Some("tools/call")) => call(state, caller, headers, &message, &bytes).await,
        _ => answer::method_not_found(&message),
    }
}

/// The stateless revision of a message when the endpoint does not support it.
fn unsupported(message: &Message) -> Option<&str> {
    if message.generation != Generation::Stateless {
        return None;
    }
    let requested = meta_version(&message.value).and_then(Value::as_str)?;
    (!SUPPORTED.contains(&requested)).then_some(requested)
}

fn initialize(message: &Message) -> Value {
    let requested = param(&message.value, "protocolVersion").and_then(Value::as_str);
    let revision = REVISIONS
        .iter()
        .copied()
        .find(|revision| Some(*revision) == requested)
        .unwrap_or(SESSION);
    json!({
        "protocolVersion": revision,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": server_info(),
    })
}

fn discover() -> Value {
    json!({
        "supportedVersions": SUPPORTED,
        "capabilities": {"tools": {}},
        "serverInfo": server_info(),
        "_meta": {"io.modelcontextprotocol/serverInfo": server_info()},
        "cacheScope": "private",
        "resultType": "complete",
    })
}

fn server_info() -> Value {
    json!({"name": "doorward", "version": env!("CARGO_PKG_VERSION")})
}

/// The parts of a tools/call body the upstream may see, borrowed from the body bytes.
#[derive(Deserialize)]
struct CallBody<'a> {
    #[serde(borrow)]
    params: Option<CallParams<'a>>,
}

/// The raw arguments, and the `_meta` of the request, of a tools/call.
#[derive(Deserialize)]
struct CallParams<'a> {
    #[serde(borrow)]
    arguments: Option<&'a RawValue>,
    #[serde(rename = "_meta")]
    meta: Option<Value>,
}

/// The server a slug names, as one database read gives it for a call.
struct Found {
    server: Assigned,
    assigned: bool,
    definition: Option<String>,
}

/// The text a result that asks for input is replaced with.
const ASKED: &str = "This tool asked for input that this endpoint does not relay.";
/// The detail of a call whose caller is not assigned to the server.
const NOT_ASSIGNED: &str = "the server is not assigned";

/// Each server the caller is assigned to with its custom headers resolved from the request. A header the
/// request sends unusably on any of them is refused for the whole request, before any upstream.
async fn resolutions(
    state: &AppState,
    user: i64,
    headers: &HeaderMap,
    id: Option<&Value>,
) -> Result<HashMap<i64, Resolved>, Response> {
    let ids = match state.db.call(move |conn| assigned_ids(conn, user)).await {
        Ok(ids) => ids,
        Err(err) => {
            report::failure("assigned servers", &err);
            return Err(bare(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
    let mut resolved = HashMap::new();
    for server_id in ids {
        match resolve_server(state, server_id, headers).await {
            Ok(Resolved::Bad) => {
                return Err(answer::error(StatusCode::BAD_REQUEST, id, -32600, INVALID));
            }
            Ok(outcome) => {
                resolved.insert(server_id, outcome);
            }
            Err(err) => return Err(resolve_failed(&err)),
        }
    }
    Ok(resolved)
}

/// The 500 of a server's headers that cannot be read; the database error is written where it arose.
fn resolve_failed(err: &DbError) -> Response {
    report::failure("custom headers", err);
    bare(StatusCode::INTERNAL_SERVER_ERROR)
}

/// The server ids the user is assigned to.
fn assigned_ids(conn: &Connection, user: i64) -> rusqlite::Result<Vec<i64>> {
    let mut statement = conn.prepare("SELECT server_id FROM user_servers WHERE user_id = ?1")?;
    statement
        .query_map(params![user], |row| row.get(0))?
        .collect()
}

/// tools/call: the name is split and checked against the caller's servers, rules and catalog, then sent
/// through the caller's link. A refused call never reaches an upstream.
async fn call(
    state: &AppState,
    caller: &Arc<Caller>,
    headers: &HeaderMap,
    message: &Message,
    bytes: &Bytes,
) -> Response {
    let null = Value::Null;
    let id = message.id.as_ref().unwrap_or(&null);
    let Some(name) = message.tool.as_deref() else {
        return answer::error(
            StatusCode::BAD_REQUEST,
            message.id.as_ref(),
            -32600,
            INVALID,
        );
    };
    let body = match serde_json::from_slice::<CallBody>(bytes) {
        Ok(body) => body,
        Err(_) => {
            return answer::error(
                StatusCode::BAD_REQUEST,
                message.id.as_ref(),
                -32600,
                INVALID,
            );
        }
    };
    let resolved = match resolutions(state, caller.user_id, headers, message.id.as_ref()).await {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };
    let started = std::time::Instant::now();
    let Some((slug, tool)) = split(name) else {
        return deny_call(state, caller, started, id, name, None, NOT_LISTED).await;
    };
    let user = caller.user_id;
    let (lookup_slug, lookup_tool) = (slug.to_owned(), tool.to_owned());
    let found = match state
        .db
        .call(move |conn| lookup(conn, user, &lookup_slug, &lookup_tool))
        .await
    {
        Ok(found) => found,
        Err(err) => {
            report::failure("server", &err);
            return bare(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let Some(found) = found else {
        return deny_call(state, caller, started, id, name, None, NOT_LISTED).await;
    };
    let server_id = found.server.server_id;
    let row = Some((server_id, slug, tool));
    if !found.assigned {
        return deny_call(state, caller, started, id, name, row, NOT_ASSIGNED).await;
    }
    let verdict = policy::decide(&found.server.rules, user, server_id, tool);
    if !verdict.allowed {
        let detail = format!("rule {}", verdict.rule.unwrap_or_default());
        return deny_call(state, caller, started, id, name, row, &detail).await;
    }
    let user_headers = match resolved.get(&server_id) {
        Some(Resolved::Ready(user_headers)) => user_headers.as_slice(),
        _ => {
            let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
            return unavailable(owed, slug, Cause::NoConnection).await;
        }
    };
    let definition = match found.definition {
        Some(definition) => definition,
        None => match refetch(state, caller, &found.server, tool, started, user_headers).await {
            Ok(Some(definition)) => definition,
            Ok(None) => {
                return deny_call(state, caller, started, id, name, row, NOT_LISTED).await;
            }
            Err(refusal) => return refusal,
        },
    };
    let target = match upstream::target(state, server_id).await {
        Ok(Some(target)) => target,
        Ok(None) => {
            let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
            return unavailable(owed, slug, Cause::NoConnection).await;
        }
        Err(TargetError::Secret) => {
            let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
            return unavailable(owed, slug, Cause::SecretUnreadable).await;
        }
        Err(TargetError::Db(err)) => {
            report::failure("server", &err);
            return bare(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let owner = Owner {
        user_id: user,
        family_id: caller.family_id,
    };
    let stateless = match state
        .links
        .stateless_with(state, owner, &target, user_headers)
        .await
    {
        Ok(stateless) => stateless,
        Err(Fault(cause)) => {
            let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
            return unavailable(owed, slug, cause).await;
        }
    };
    let has_mcp_header = match serde_json::from_str::<Value>(&definition) {
        Ok(stored) => has_header_key(&stored),
        Err(_) => true,
    };
    if stateless && has_mcp_header {
        return deny_call(state, caller, started, id, name, row, HEADER_MISMATCH).await;
    }
    let arguments = body.params.as_ref().and_then(|params| params.arguments);
    let progress_token = body
        .params
        .as_ref()
        .and_then(|params| params.meta.as_ref())
        .and_then(|meta| meta.get("progressToken"));
    let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
    let ask = Ask::Call {
        name: tool,
        arguments,
        progress_token,
    };
    let client_stateless = message.generation == Generation::Stateless;
    let sent = match state
        .links
        .send_with(state, owner, &target, ask, user_headers)
        .await
    {
        Ok(Answer::Sent(sent)) => sent,
        Ok(Answer::Refused {
            status,
            answer,
            held,
        }) => {
            let (reply, outcome) = reissue(id, &answer, client_stateless);
            let detail = detail_of(&answer, outcome);
            match combined_still_valid_at(state, caller, server_id, caller.admitted).await {
                Recheck::Live => {}
                Recheck::Lost => {
                    owed.settle("refused", ACCESS_LOST).await;
                    return answer::unknown_tool(id, name);
                }
                Recheck::Failed => return check_failed(owed).await,
            }
            owed.settle(outcome, detail).await;
            let status = if client_stateless {
                status
            } else {
                StatusCode::OK
            };
            return hold(respond(status, &reply), held);
        }
        Err(Fault(cause)) => return unavailable(owed, slug, cause).await,
    };
    if sent.kind == Kind::Stream {
        owed.hand_over();
        let call = Call {
            owned: owned_of(state, caller, started, slug, server_id),
            tool: tool.to_owned(),
            name: name.to_owned(),
            upstream_id: sent.id,
            client_id: id.clone(),
            stateless: client_stateless,
        };
        return streamed(combined_stream::relay(call, sent.response));
    }
    let cap = state.config.limits.tools_list_bytes;
    let mut held = state.links.budget().reservation(Some(caller.user_id));
    let upstream_answer = match links::read(state, sent, cap, &mut held).await {
        Ok(upstream_answer) => upstream_answer,
        Err(Fault(cause)) => return unavailable(owed, slug, cause).await,
    };
    let (reply, outcome) = reissue(id, &upstream_answer, client_stateless);
    let detail = detail_of(&upstream_answer, outcome);
    match combined_still_valid_at(state, caller, server_id, caller.admitted).await {
        Recheck::Live => {}
        Recheck::Lost => {
            owed.settle("refused", ACCESS_LOST).await;
            return answer::unknown_tool(id, name);
        }
        Recheck::Failed => return check_failed(owed).await,
    }
    owed.settle(outcome, detail).await;
    hold(respond(StatusCode::OK, &reply), held)
}

/// The server a slug names with the caller's assignment, rules and stored definition of `tool`, in one read.
fn lookup(conn: &Connection, user: i64, slug: &str, tool: &str) -> rusqlite::Result<Option<Found>> {
    let server_id = conn
        .query_row(
            "SELECT id FROM servers WHERE slug = ?1",
            params![slug],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(server_id) = server_id else {
        return Ok(None);
    };
    let assigned = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM user_servers WHERE user_id = ?1 AND server_id = ?2)",
        params![user, server_id],
        |row| row.get::<_, bool>(0),
    )?;
    let rules = policy::load(conn, user, server_id)?;
    let definition = definition_of(conn, server_id, tool)?;
    Ok(Some(Found {
        server: Assigned {
            server_id,
            slug: slug.to_owned(),
            rules,
        },
        assigned,
        definition,
    }))
}

/// The stored definition of `tool` on the server, if any.
fn definition_of(
    conn: &Connection,
    server_id: i64,
    tool: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT definition FROM tool_catalog WHERE server_id = ?1 AND name = ?2",
        params![server_id, tool],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

/// The definition of `tool` after a miss refresh, which waits for one in flight and runs in its own task.
/// None when the refresh is held off, failed, or the tool is still absent.
async fn refetch(
    state: &AppState,
    caller: &Arc<Caller>,
    server: &Assigned,
    tool: &str,
    started: std::time::Instant,
    user_headers: &[(HeaderName, HeaderValue)],
) -> Result<Option<String>, Response> {
    let server_id = server.server_id;
    let mut last = state.turns.misses.lock(server_id).await;
    let tool_name = tool.to_owned();
    match state
        .db
        .call(move |conn| definition_of(conn, server_id, &tool_name))
        .await
    {
        Ok(Some(definition)) => return Ok(Some(definition)),
        Ok(None) => {}
        Err(err) => {
            report::failure("tool catalog", &err);
            return Err(bare(StatusCode::INTERNAL_SERVER_ERROR));
        }
    }
    let now = state.clock.now().unix_timestamp();
    let every = i64::try_from(state.config.limits.catalog_refresh_seconds).unwrap_or(i64::MAX);
    if catalog::held_off(*last, now, every) {
        return Ok(None);
    }
    *last = Some(now);
    let owner = Owner {
        user_id: caller.user_id,
        family_id: caller.family_id,
    };
    let task_state = state.clone();
    let slug = server.slug.clone();
    let tool_name = tool.to_owned();
    let headers = user_headers.to_vec();
    let refresh = tokio::spawn(async move {
        let found = refresh_list(&task_state, owner, &slug, server_id, &tool_name, &headers).await;
        *last = Some(task_state.clock.now().unix_timestamp());
        found
    });
    match refresh.await {
        Ok(Refetch::Definition(definition)) => Ok(definition),
        Ok(Refetch::Refused) => Ok(None),
        Ok(Refetch::Busy) => {
            let owed = Owed::of(
                owned_of(state, caller, started, &server.slug, server_id),
                tool,
            );
            Err(unavailable(owed, &server.slug, Cause::BusyBeforeSend).await)
        }
        Ok(Refetch::Database) => Err(bare(StatusCode::INTERNAL_SERVER_ERROR)),
        Err(_) => Ok(None),
    }
}

/// What one miss refresh found: the tool's definition, a refused list, a list the budget refused, or a
/// database error.
enum Refetch {
    Definition(Option<String>),
    Refused,
    Busy,
    Database,
}

/// One miss refresh: the server's list through the caller's link, stored, and the tool's definition from it.
async fn refresh_list(
    state: &AppState,
    owner: Owner,
    slug: &str,
    server_id: i64,
    tool: &str,
    user_headers: &[(HeaderName, HeaderValue)],
) -> Refetch {
    let deadline = Instant::now() + time_limit(state).min(LIST_LIMIT);
    let fetched = match fetch(state, owner, server_id, deadline, user_headers).await {
        Ok(fetched) => fetched,
        Err(cause) => {
            refuse(state, slug, server_id, cause).await;
            return if budget_refused(cause) {
                Refetch::Busy
            } else {
                Refetch::Refused
            };
        }
    };
    // `fetched.held` is dropped when this function returns, after the list is stored.
    let tools = fetched.tools;
    let now = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| store(conn, vec![(server_id, tools)], now))
        .await
    {
        Ok(stored) => Refetch::Definition(
            stored
                .into_iter()
                .flatten()
                .find(|(name, _)| name.as_str() == tool)
                .map(|(_, definition)| definition),
        ),
        Err(err) => {
            report::failure("tool catalog", &err);
            Refetch::Database
        }
    }
}

/// What the row of an allowed call needs after its handler returns: the server, the caller and the start.
fn owned_of(
    state: &AppState,
    caller: &Arc<Caller>,
    started: std::time::Instant,
    slug: &str,
    server_id: i64,
) -> Owned {
    Owned {
        state: state.clone(),
        slug: slug.to_owned(),
        server_id,
        caller: Arc::clone(caller),
        started,
    }
}

/// The HTTP answer of a relayed stream: the event-stream type and the inert-content headers, no session id.
fn streamed(body: Body) -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "text/event-stream"),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (CONTENT_SECURITY_POLICY, "sandbox"),
        ],
        body,
    )
        .into_response()
}

/// The 502 of a call whose upstream cannot answer, with its row written as unavailable and the phrase
/// of its cause as the detail.
async fn unavailable(owed: Owed, slug: &str, cause: Cause) -> Response {
    let phrase = upstream::fail(slug, cause);
    owed.settle("unavailable", &phrase).await;
    answer_for(slug, cause, true)
}

/// The answer when the access check could not be made: the call is recorded unavailable.
async fn check_failed(owed: Owed) -> Response {
    owed.settle("unavailable", CHECK_FAILED).await;
    answer::unavailable(LABEL)
}

/// A refused tools/call: one deny row with its detail, and the one answer every refusal gets. A name
/// that names no server has no server in its row, under the label `mcp`, and the name as sent.
async fn deny_call(
    state: &AppState,
    caller: &Caller,
    started: std::time::Instant,
    id: &Value,
    name: &str,
    server: Option<(i64, &str, &str)>,
    detail: &str,
) -> Response {
    let (server_id, slug, tool) = match server {
        Some((server_id, slug, tool)) => (Some(server_id), slug, tool),
        None => (None, LABEL, name),
    };
    let event = OwnedEvent {
        kind: "tool_call".to_owned(),
        user_id: Some(caller.user_id),
        user_email: caller.user_email.clone(),
        server_id,
        server_slug: slug.to_owned(),
        tool: cut(tool, TOOL_LIMIT),
        client: caller.client_name.clone(),
        decision: "deny".to_owned(),
        outcome: "refused".to_owned(),
        detail: detail.to_owned(),
        duration_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)),
    };
    if let Err(err) = audit::record_refused_now(state, event).await {
        report::failure("activity row", &err);
    }
    answer::unknown_tool(id, name)
}

/// The upstream's answer under the client's id, and the outcome of its row. A result that asks for
/// input becomes a tool error; a stateless client's result is marked complete, a session client's is not.
pub(super) fn reissue(id: &Value, answer: &Value, stateless: bool) -> (Value, &'static str) {
    let (member, body, outcome) = match answer.get("result") {
        Some(result) => {
            let (result, outcome) = result_for_client(result, stateless);
            ("result", result, outcome)
        }
        None => (
            "error",
            answer.get("error").cloned().unwrap_or(Value::Null),
            "error",
        ),
    };
    let mut reply = Map::new();
    reply.insert("jsonrpc".to_owned(), json!("2.0"));
    reply.insert("id".to_owned(), id.clone());
    reply.insert(member.to_owned(), body);
    (Value::Object(reply), outcome)
}

/// A result as the client gets it: one that asks for input is replaced by a tool error, and resultType is
/// set to complete for a stateless client and removed for a session client.
fn result_for_client(result: &Value, stateless: bool) -> (Value, &'static str) {
    let asks = result
        .get("resultType")
        .is_some_and(|kind| kind.as_str() != Some("complete"));
    let (mut value, outcome) = if asks {
        (
            json!({"content": [{"type": "text", "text": ASKED}], "isError": true}),
            "error",
        )
    } else {
        (result.clone(), "ok")
    };
    if let Value::Object(object) = &mut value {
        if stateless {
            object.insert("resultType".to_owned(), json!("complete"));
        } else {
            object.remove("resultType");
        }
    }
    (value, outcome)
}

/// tools/list: the caller's tools across the servers it is assigned to now, under one turn and deadline.
async fn list(
    state: &AppState,
    caller: &Caller,
    headers: &HeaderMap,
    message: &Message,
) -> Response {
    let null = Value::Null;
    let id = message.id.as_ref().unwrap_or(&null);
    if param(&message.value, "cursor").is_some_and(|cursor| !cursor.is_null()) {
        return answer::error(StatusCode::OK, Some(id), -32602, "Invalid params");
    }
    let resolved = match resolutions(state, caller.user_id, headers, message.id.as_ref()).await {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };
    let limit = time_limit(state).min(LIST_LIMIT);
    let turn = match timeout(limit, enter(&state.turns, caller.user_id)).await {
        Ok(turn) => turn,
        Err(_) => return answer::unavailable(LABEL),
    };
    let deadline = Instant::now() + limit;
    let built = collect(state, caller, deadline, &resolved).await;
    drop(turn);
    match built {
        Ok((tools, holds)) if message.generation == Generation::Stateless => hold(
            result(
                id,
                json!({"tools": tools, "resultType": "complete", "ttlMs": TTL_MS, "cacheScope": "private"}),
            ),
            holds,
        ),
        Ok((tools, holds)) => hold(result(id, json!({"tools": tools})), holds),
        Err(refusal) => refusal,
    }
}

/// The listed tools of the caller's servers and the reservations of their upstream bytes, or the answer
/// that refuses the list.
async fn collect(
    state: &AppState,
    caller: &Caller,
    deadline: Instant,
    resolved: &HashMap<i64, Resolved>,
) -> Result<(Vec<Value>, Vec<Reservation>), Response> {
    let user = caller.user_id;
    let assigned = match state.db.call(move |conn| assigned(conn, user)).await {
        Ok(assigned) => assigned,
        Err(err) => {
            report::failure("assigned servers", &err);
            return Err(bare(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
    if assigned.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let owner = Owner {
        user_id: caller.user_id,
        family_id: caller.family_id,
    };
    let outcomes = join_all(assigned.iter().map(|server| async move {
        match resolved.get(&server.server_id) {
            Some(Resolved::Ready(user_headers)) => {
                Some(fetch(state, owner, server.server_id, deadline, user_headers).await)
            }
            _ => None,
        }
    }))
    .await;
    let mut fetched: Vec<(usize, Fetched)> = Vec::new();
    let mut only_budget = true;
    for (position, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            None => only_budget = false,
            Some(Ok(list)) => fetched.push((position, list)),
            Some(Err(cause)) => {
                if budget_refused(cause) {
                    note(format!(
                        "tools/list: {} left out, the answer memory budget is exhausted",
                        assigned[position].slug
                    ));
                } else {
                    only_budget = false;
                }
                refuse(
                    state,
                    &assigned[position].slug,
                    assigned[position].server_id,
                    cause,
                )
                .await
            }
        }
    }
    if fetched.is_empty() {
        return Err(if only_budget {
            answer::busy()
        } else {
            answer::unavailable(LABEL)
        });
    }
    let now = state.clock.now().unix_timestamp();
    let jobs: Vec<(i64, Vec<Value>)> = fetched
        .iter_mut()
        .map(|(position, list)| {
            (
                assigned[*position].server_id,
                std::mem::take(&mut list.tools),
            )
        })
        .collect();
    let stored = match state.db.call(move |conn| store(conn, jobs, now)).await {
        Ok(stored) => stored,
        Err(err) => {
            report::failure("tool catalog", &err);
            return Err(bare(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
    let candidates: Vec<Candidate> = fetched
        .iter()
        .zip(stored)
        .map(|((position, list), definitions)| {
            candidate(&assigned[*position], user, list.stateless, &definitions)
        })
        .collect();
    let admitted = admit(&candidates, state.config.limits.tools_list_bytes);
    let tools = candidates
        .into_iter()
        .zip(admitted)
        .filter(|(_, keep)| *keep)
        .flat_map(|(candidate, _)| candidate.entries)
        .collect();
    let holds = fetched.into_iter().map(|(_, list)| list.held).collect();
    Ok((tools, holds))
}

/// A server the caller is assigned to now, with the caller's rules on it.
struct Assigned {
    server_id: i64,
    slug: String,
    rules: Vec<policy::Rule>,
}

/// One server's tools as the upstream answered them, whether its link is stateless, and the reservation
/// of the bytes they came in.
struct Fetched {
    tools: Vec<Value>,
    stateless: bool,
    held: Reservation,
}

/// The entries one server lists, and their size in bytes.
struct Candidate {
    slug: String,
    entries: Vec<Value>,
    bytes: u64,
}

/// The servers the user is assigned to now, by slug, with the user's rules on each.
fn assigned(conn: &Connection, user: i64) -> rusqlite::Result<Vec<Assigned>> {
    let mut statement = conn.prepare(
        "SELECT s.id, s.slug FROM user_servers us JOIN servers s ON s.id = us.server_id \
         WHERE us.user_id = ?1 ORDER BY s.slug",
    )?;
    let rows: Vec<(i64, String)> = statement
        .query_map(params![user], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|(server_id, slug)| {
            Ok(Assigned {
                server_id,
                slug,
                rules: policy::load(conn, user, server_id)?,
            })
        })
        .collect()
}

/// Stores each fetched list, then reads back its stored definitions, in one call.
fn store(
    conn: &mut Connection,
    jobs: Vec<(i64, Vec<Value>)>,
    now: i64,
) -> rusqlite::Result<Vec<Vec<(String, String)>>> {
    let mut stored = Vec::with_capacity(jobs.len());
    for (server_id, tools) in jobs {
        catalog::replace(conn, server_id, &tools, now)?;
        stored.push(catalog::definitions(conn, server_id)?);
    }
    Ok(stored)
}

/// The entries a stored server lists; the tools it leaves out are counted in the log.
fn candidate(
    server: &Assigned,
    user: i64,
    stateless: bool,
    definitions: &[(String, String)],
) -> Candidate {
    let mut entries = Vec::new();
    let mut left_out = 0usize;
    for (name, definition) in definitions {
        match listed(
            &server.slug,
            name,
            definition,
            &server.rules,
            user,
            server.server_id,
            stateless,
        ) {
            Some(entry) => entries.push(entry),
            None => left_out += 1,
        }
    }
    if left_out > 0 {
        note(format!(
            "tools/list: {} left {left_out} tool(s) out",
            server.slug
        ));
    }
    let bytes = entries
        .iter()
        .map(|entry| u64::try_from(entry.to_string().len()).unwrap_or(u64::MAX))
        .sum();
    Candidate {
        slug: server.slug.clone(),
        entries,
        bytes,
    }
}

/// The entry a stored tool lists as, or None when it is left out: its name, its merged length,
/// the caller's rules, and no x-mcp-header key on a stateless link.
fn listed(
    slug: &str,
    name: &str,
    definition: &str,
    rules: &[policy::Rule],
    user: i64,
    server_id: i64,
    stateless: bool,
) -> Option<Value> {
    let merged = format!("{slug}__{name}");
    if !valid_name(name)
        || merged.len() > MERGED_LIMIT
        || !policy::decide(rules, user, server_id, name).allowed
    {
        return None;
    }
    let mut tool: Value = serde_json::from_str(definition).ok()?;
    if stateless && has_header_key(&tool) {
        return None;
    }
    tool.as_object_mut()?
        .insert("name".to_owned(), Value::String(merged));
    Some(tool)
}

/// The server slug and the tool of a merged name, split at the first `__`; None when it has no `__`,
/// a prefix that is not a valid slug, a tool outside `^[A-Za-z0-9_.-]+$`, or more than 128 bytes.
pub(super) fn split(name: &str) -> Option<(&str, &str)> {
    if name.len() > MERGED_LIMIT {
        return None;
    }
    let (slug, tool) = name.split_once("__")?;
    (valid_slug(slug) && valid_name(tool)).then_some((slug, tool))
}

/// True for `^[A-Za-z0-9_.-]+$`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// True when an object anywhere in `value` has the key x-mcp-header.
fn has_header_key(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::Object(map) => {
                if map.contains_key("x-mcp-header") {
                    return true;
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    false
}

/// Which candidates fit the byte limit, smallest first; the others are logged and left out.
fn admit(candidates: &[Candidate], limit: u64) -> Vec<bool> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&index| candidates[index].bytes);
    let mut admitted = vec![false; candidates.len()];
    let mut total: u64 = 0;
    for index in order {
        let bytes = candidates[index].bytes;
        if total.saturating_add(bytes) <= limit {
            total += bytes;
            admitted[index] = true;
        } else {
            note(format!(
                "tools/list: {} left out, its tools are over the size limit",
                candidates[index].slug
            ));
        }
    }
    admitted
}

/// One server's tools, or the cause its list failed with, the deadline included.
async fn fetch(
    state: &AppState,
    owner: Owner,
    server_id: i64,
    deadline: Instant,
    user_headers: &[(HeaderName, HeaderValue)],
) -> Result<Fetched, Cause> {
    match timeout_at(deadline, fetch_pages(state, owner, server_id, user_headers)).await {
        Ok(fetched) => fetched,
        Err(_) => Err(Cause::NoAnswerInTime),
    }
}

/// Every page of the server's list through the caller's link, within the byte limit and the page limit.
/// Passing the page limit is reported as too large.
async fn fetch_pages(
    state: &AppState,
    owner: Owner,
    server_id: i64,
    user_headers: &[(HeaderName, HeaderValue)],
) -> Result<Fetched, Cause> {
    let target = match upstream::target(state, server_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return Err(Cause::NoConnection),
        Err(TargetError::Secret) => return Err(Cause::SecretUnreadable),
        Err(TargetError::Db(err)) => {
            report::failure("server", &err);
            return Err(Cause::Written);
        }
    };
    let limit = state.config.limits.tools_list_bytes;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut used: u64 = 0;
    let mut stateless = false;
    let mut held = state.links.budget().reservation(Some(owner.user_id));
    for page in 0..MAX_PAGES {
        let sent = match state
            .links
            .send_with(
                state,
                owner,
                &target,
                Ask::List {
                    cursor: cursor.as_deref(),
                },
                user_headers,
            )
            .await
        {
            Ok(Answer::Sent(sent)) => sent,
            Ok(Answer::Refused { status, .. }) => return Err(Cause::Status(status.as_u16())),
            Err(Fault(cause)) => return Err(cause),
        };
        if page == 0 {
            stateless = sent.stateless;
        }
        let mut page_held = state.links.budget().reservation(Some(owner.user_id));
        let reply = links::read(state, sent, limit.saturating_sub(used), &mut page_held)
            .await
            .map_err(|Fault(cause)| cause)?;
        // The page's bytes are counted by `held` below, so its own reservation goes first.
        drop(page_held);
        used = used.saturating_add(u64::try_from(reply.to_string().len()).unwrap_or(u64::MAX));
        if !held.set(usize::try_from(used).unwrap_or(usize::MAX)) {
            return Err(Cause::Busy);
        }
        let result = reply.get("result").ok_or(Cause::NotMcp)?;
        let page_tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or(Cause::NotMcp)?;
        tools.extend(page_tools.iter().cloned());
        cursor = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(next)) => Some(next.clone()),
            Some(_) => return Err(Cause::NotMcp),
        };
        if cursor.is_none() {
            return Ok(Fetched {
                tools,
                stateless,
                held,
            });
        }
    }
    Err(Cause::TooLarge)
}

/// Logs the fault of a failed list and records it as the server's refresh error.
async fn refuse(state: &AppState, slug: &str, server_id: i64, cause: Cause) {
    upstream::fail(slug, cause);
    let error = match cause {
        Cause::TooLarge => RefreshError::TooLarge,
        // The gateway's own causes store no refresh error: the upstream was not silent.
        Cause::SecretUnreadable | Cause::Written | Cause::Busy | Cause::BusyBeforeSend => return,
        _ => RefreshError::Unavailable,
    };
    // catalog::fail reports its own database error.
    let _ = catalog::fail(state, server_id, error).await;
}

/// A JSON-RPC result with the inert-content headers of the server path's own answers.
fn result(id: &Value, result: Value) -> Response {
    respond(
        StatusCode::OK,
        &json!({"jsonrpc": "2.0", "id": id, "result": result}),
    )
}

fn respond(status: StatusCode, body: &Value) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (
            status,
            [
                (CONTENT_TYPE, "application/json"),
                (X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (CONTENT_SECURITY_POLICY, "sandbox"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
