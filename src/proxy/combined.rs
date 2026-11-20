//! The gateway's own MCP server on `/mcp`: its methods, and tools/list across the user's servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::future::join_all;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::{Instant, timeout, timeout_at};

use super::catalog::{self, RefreshError, SESSION, STATELESS};
use super::handle::{INVALID, NO_METHOD, bare, not_allowed};
use super::intake::{Intake, intake};
use super::links::{self, Ask, Owner};
use super::upstream::{self, TargetError, time_limit};
use crate::app::AppState;
use crate::mcp::answer;
use crate::mcp::message::{
    Decision, Generation, Message, Shape, Switches, decide, meta_version, param,
};
use crate::oauth::guard::Caller;
use crate::policy;

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
    post(state, &caller, &parts.headers, body).await
}

async fn post(state: &AppState, caller: &Caller, headers: &HeaderMap, body: Body) -> Response {
    let Intake { message, .. } = match intake(state, headers, body).await {
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
