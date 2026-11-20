//! The gateway's own MCP server on `/mcp`: its methods, and tools/list across the user's servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::future::join_all;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::{Instant, timeout, timeout_at};

use super::catalog::{self, RefreshError, SESSION, STATELESS};
use super::handle::{INVALID, NO_METHOD, Owed, TOOL_LIMIT, bare, cut, not_allowed};
use super::intake::{Intake, intake};
use super::links::{self, Ask, Owner};
use super::stream::Owned;
use super::upstream::{self, Fault, TargetError, time_limit};
use crate::app::AppState;
use crate::audit::{self, OwnedEvent};
use crate::mcp::answer;
use crate::mcp::message::{
    Decision, Generation, Message, Shape, Switches, decide, meta_version, param,
};
use crate::oauth::guard::{Caller, combined_still_valid};
use crate::policy;
use crate::servers::valid_slug;

/// The longest a whole tools/list may take, the wait for its turn included.
const LIST_LIMIT: Duration = Duration::from_secs(10);
/// The most pages one upstream list may take.
const MAX_PAGES: usize = 20;
/// The longest name a listed tool may have: `{slug}__{name}`.
const MERGED_LIMIT: usize = 128;
/// The revisions the endpoint supports under the stateless rules, newest first.
const SUPPORTED: [&str; 4] = [STATELESS, SESSION, "2025-06-18", "2025-03-26"];
/// The revisions a session initialize may answer with, newest first.
const REVISIONS: [&str; 3] = [SESSION, "2025-06-18", "2025-03-26"];
const LABEL: &str = "mcp";
const TTL_MS: i64 = 60_000;
const ALL: Switches = Switches {
    resources: true,
    prompts: true,
};

/// One list at a time per user: the gate of each user with a list running or waiting.
#[derive(Default)]
pub struct Turns {
    gates: Mutex<HashMap<i64, Arc<AsyncMutex<()>>>>,
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
    eprintln!("doorward: {line}");
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
            Shape::Request => answer::error(StatusCode::OK, message.id.as_ref(), -32601, NO_METHOD),
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
        (_, Some("tools/list")) => list(state, caller, &message).await,
        (_, Some("tools/call")) => call(state, caller, &message, &bytes).await,
        _ => answer::error(StatusCode::OK, message.id.as_ref(), -32601, NO_METHOD),
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

/// tools/call: the name is split and checked against the caller's servers, rules and catalog, then sent
/// through the caller's link. A refused call never reaches an upstream.
async fn call(
    state: &AppState,
    caller: &Arc<Caller>,
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
    let started = std::time::Instant::now();
    let Some((slug, tool)) = split(name) else {
        return deny_call(state, caller, started, id, name, None).await;
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
            eprintln!("doorward: the call cannot read its server: {err}");
            return bare(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let Some(found) = found else {
        return deny_call(state, caller, started, id, name, None).await;
    };
    let server_id = found.server.server_id;
    let row = Some((server_id, slug, tool));
    if !found.assigned {
        return deny_call(state, caller, started, id, name, row).await;
    }
    let definition = match found.definition {
        Some(definition) => definition,
        None => match refetch(state, caller, &found.server, tool).await {
            Ok(Some(definition)) => definition,
            Ok(None) => return deny_call(state, caller, started, id, name, row).await,
            Err(refusal) => return refusal,
        },
    };
    if !policy::decide(&found.server.rules, user, server_id, tool).allowed {
        return deny_call(state, caller, started, id, name, row).await;
    }
    let target = match upstream::target(state, server_id).await {
        Ok(Some(target)) => target,
        Ok(None) | Err(TargetError::Secret) => {
            let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
            return unavailable(owed, slug).await;
        }
        Err(TargetError::Db(err)) => {
            eprintln!("doorward: the server cannot be read: {err}");
            return bare(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let owner = Owner {
        user_id: user,
        family_id: caller.family_id,
    };
    let stateless = match state.links.stateless(state, owner, &target).await {
        Ok(stateless) => stateless,
        Err(Fault) => {
            let owed = Owed::of(owned_of(state, caller, started, slug, server_id), tool);
            return unavailable(owed, slug).await;
        }
    };
    let has_mcp_header = match serde_json::from_str::<Value>(&definition) {
        Ok(stored) => has_header_key(&stored),
        Err(_) => true,
    };
    if stateless && has_mcp_header {
        return deny_call(state, caller, started, id, name, row).await;
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
    let sent = match state.links.send(state, owner, &target, ask).await {
        Ok(sent) => sent,
        Err(Fault) => return unavailable(owed, slug).await,
    };
    let cap = state.config.limits.tools_list_bytes;
    let upstream_answer = match links::read(state, sent, cap).await {
        Ok(upstream_answer) => upstream_answer,
        Err(Fault) => return unavailable(owed, slug).await,
    };
    let client_stateless = message.generation == Generation::Stateless;
    let (reply, outcome) = reissue(id, &upstream_answer, client_stateless);
    if !combined_still_valid(state, caller, server_id).await {
        owed.settle("refused").await;
        return answer::unknown_tool(id, name);
    }
    owed.settle(outcome).await;
    respond(StatusCode::OK, &reply)
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
    let definition = conn
        .query_row(
            "SELECT definition FROM tool_catalog WHERE server_id = ?1 AND name = ?2",
            params![server_id, tool],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
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

/// One refresh of the server's catalog through the caller's link, for a tool the catalog lacks. Returns
/// the stored definition of `tool` after it; None when the refresh failed or the tool is still absent.
async fn refetch(
    state: &AppState,
    caller: &Caller,
    server: &Assigned,
    tool: &str,
) -> Result<Option<String>, Response> {
    let deadline = Instant::now() + time_limit(state).min(LIST_LIMIT);
    let Some(fetched) = fetch(state, caller, server, deadline).await else {
        refuse(state, server).await;
        return Ok(None);
    };
    let now = state.clock.now().unix_timestamp();
    let server_id = server.server_id;
    let tools = fetched.tools;
    match state
        .db
        .call(move |conn| store(conn, vec![(server_id, tools)], now))
        .await
    {
        Ok(stored) => Ok(stored
            .into_iter()
            .flatten()
            .find(|(name, _)| name.as_str() == tool)
            .map(|(_, definition)| definition)),
        Err(err) => {
            eprintln!("doorward: the tool catalog cannot be stored: {err}");
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
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

/// The 502 of a call whose upstream cannot answer, with its row written as unavailable.
async fn unavailable(owed: Owed, slug: &str) -> Response {
    owed.settle("unavailable").await;
    answer::unavailable(slug)
}

/// A refused tools/call: one deny row and the one answer every refusal gets. A name that names no
/// server has no server in its row, under the label `mcp`, and the name as sent.
async fn deny_call(
    state: &AppState,
    caller: &Caller,
    started: std::time::Instant,
    id: &Value,
    name: &str,
    server: Option<(i64, &str, &str)>,
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
        detail: String::new(),
        duration_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)),
    };
    if let Err(err) = audit::record_now(state, event).await {
        eprintln!("doorward: the activity row cannot be written: {err}");
    }
    answer::unknown_tool(id, name)
}

/// The upstream's answer under the client's id, and the outcome of its row. A result that asks for
/// input becomes a tool error; a stateless client's result is marked complete, a session client's is not.
fn reissue(id: &Value, answer: &Value, stateless: bool) -> (Value, &'static str) {
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
async fn list(state: &AppState, caller: &Caller, message: &Message) -> Response {
    let null = Value::Null;
    let id = message.id.as_ref().unwrap_or(&null);
    if param(&message.value, "cursor").is_some_and(|cursor| !cursor.is_null()) {
        return answer::error(StatusCode::OK, Some(id), -32602, "Invalid params");
    }
    let limit = time_limit(state).min(LIST_LIMIT);
    let turn = match timeout(limit, enter(&state.turns, caller.user_id)).await {
        Ok(turn) => turn,
        Err(_) => return answer::unavailable(LABEL),
    };
    let deadline = Instant::now() + limit;
    let built = collect(state, caller, deadline).await;
    drop(turn);
    match built {
        Ok(tools) if message.generation == Generation::Stateless => result(
            id,
            json!({"tools": tools, "resultType": "complete", "ttlMs": TTL_MS, "cacheScope": "private"}),
        ),
        Ok(tools) => result(id, json!({"tools": tools})),
        Err(refusal) => refusal,
    }
}

/// The listed tools of the caller's servers, or the answer that refuses the list.
async fn collect(
    state: &AppState,
    caller: &Caller,
    deadline: Instant,
) -> Result<Vec<Value>, Response> {
    let user = caller.user_id;
    let assigned = match state.db.call(move |conn| assigned(conn, user)).await {
        Ok(assigned) => assigned,
        Err(err) => {
            eprintln!("doorward: the assigned servers cannot be read: {err}");
            return Err(bare(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
    if assigned.is_empty() {
        return Ok(Vec::new());
    }
    let outcomes = join_all(
        assigned
            .iter()
            .map(|server| fetch(state, caller, server, deadline)),
    )
    .await;
    let mut fetched: Vec<(usize, Fetched)> = Vec::new();
    for (position, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Some(list) => fetched.push((position, list)),
            None => refuse(state, &assigned[position]).await,
        }
    }
    if fetched.is_empty() {
        return Err(answer::unavailable(LABEL));
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
            eprintln!("doorward: the tool catalog cannot be stored: {err}");
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
    Ok(candidates
        .into_iter()
        .zip(admitted)
        .filter(|(_, keep)| *keep)
        .flat_map(|(candidate, _)| candidate.entries)
        .collect())
}

/// A server the caller is assigned to now, with the caller's rules on it.
struct Assigned {
    server_id: i64,
    slug: String,
    rules: Vec<policy::Rule>,
}

/// One server's tools as the upstream answered them, and whether its link is stateless.
struct Fetched {
    tools: Vec<Value>,
    stateless: bool,
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

/// One server's tools, or None when its list fails or the deadline cuts it.
async fn fetch(
    state: &AppState,
    caller: &Caller,
    server: &Assigned,
    deadline: Instant,
) -> Option<Fetched> {
    timeout_at(deadline, fetch_pages(state, caller, server))
        .await
        .ok()
        .flatten()
}

/// Every page of the server's list through the caller's link, within the byte limit and the page limit.
async fn fetch_pages(state: &AppState, caller: &Caller, server: &Assigned) -> Option<Fetched> {
    let target = match upstream::target(state, server.server_id).await {
        Ok(Some(target)) => target,
        Ok(None) | Err(TargetError::Secret) => return None,
        Err(TargetError::Db(err)) => {
            eprintln!("doorward: the server cannot be read: {err}");
            return None;
        }
    };
    let owner = Owner {
        user_id: caller.user_id,
        family_id: caller.family_id,
    };
    let limit = state.config.limits.tools_list_bytes;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    let mut used: u64 = 0;
    let mut stateless = false;
    for page in 0..MAX_PAGES {
        let sent = state
            .links
            .send(
                state,
                owner,
                &target,
                Ask::List {
                    cursor: cursor.as_deref(),
                },
            )
            .await
            .ok()?;
        if page == 0 {
            stateless = sent.stateless;
        }
        let reply = links::read(state, sent, limit.saturating_sub(used))
            .await
            .ok()?;
        used = used.saturating_add(u64::try_from(reply.to_string().len()).unwrap_or(u64::MAX));
        let result = reply.get("result")?;
        tools.extend(result.get("tools")?.as_array()?.iter().cloned());
        cursor = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(next)) => Some(next.clone()),
            Some(_) => return None,
        };
        if cursor.is_none() {
            return Some(Fetched { tools, stateless });
        }
    }
    None
}

/// Records a failed refresh of the server's catalog and logs the server's slug.
async fn refuse(state: &AppState, server: &Assigned) {
    if catalog::fail(state, server.server_id, RefreshError::Unavailable)
        .await
        .is_err()
    {
        eprintln!(
            "doorward: the failed refresh of {} cannot be recorded",
            server.slug
        );
    }
    note(format!(
        "tools/list: {} left out, its upstream did not answer with a tool list",
        server.slug
    ));
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
