//! The gateway as an MCP client of each upstream: one kept link per token family and server.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rusqlite::params;
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;

use super::catalog::{self, SESSION, STATELESS, request_headers};
use super::sse::sse_events;
use super::upstream::{
    self, BodyError, Cause, Fault, Kind, Outgoing, Target, read_body, read_stream, time_limit,
};
use crate::app::AppState;
use crate::crypto::token_hash;
use crate::mcp::json::parse_strict;
use crate::report;

/// Links kept at once, over all owners.
const MAX_LINKS: usize = 10_000;
/// Links kept for one user.
const MAX_PER_USER: usize = 256;
/// The longest a handshake may take, whatever the upstream time limit is.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
/// The session revisions a session link may speak, newest first.
const REVISIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];
const SESSION_ID_LIMIT: usize = 256;
/// The request ids of the handshake: the probe, then initialize. A link numbers its requests from 3.
const PROBE_ID: u64 = 1;
const INITIALIZE_ID: u64 = 2;
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";

/// How the gateway speaks to one upstream on one link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Form {
    /// Revision 2026-07-28: no session, version in `_meta` and headers.
    Stateless,
    /// A session revision the upstream answered, and its session id when it gave one.
    Session {
        revision: &'static str,
        id: Option<HeaderValue>,
    },
}

/// Who a link belongs to. Links are never shared across families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Owner {
    pub user_id: i64,
    pub family_id: i64,
}

/// What the gateway asks an upstream. Nothing else of a client's request is ever sent.
pub enum Ask<'a> {
    /// One page of tools/list.
    List { cursor: Option<&'a str> },
    /// tools/call: the tool's own name, the client's arguments byte for byte, its progress token.
    Call {
        name: &'a str,
        arguments: Option<&'a RawValue>,
        progress_token: Option<&'a Value>,
    },
}

/// An upstream answer not yet read: HTTP 200 with a JSON or event-stream body.
pub struct Sent {
    pub response: reqwest::Response,
    pub id: Value,
    pub kind: Kind,
    /// True when the link that sent the request speaks the stateless form.
    pub stateless: bool,
}

/// What an upstream sent for one request: an answer to read, or a JSON-RPC error with HTTP 400 or 404.
pub enum Answer {
    Sent(Sent),
    Refused { status: StatusCode, answer: Value },
}

/// The kept links, keyed by (family, server), with their bounds.
pub struct Links {
    inner: Arc<Inner>,
}

impl Default for Links {
    fn default() -> Self {
        Self::new()
    }
}

impl Links {
    pub fn new() -> Self {
        Self::with_limits(MAX_LINKS, MAX_PER_USER)
    }

    fn with_limits(total_limit: usize, user_limit: usize) -> Self {
        Links {
            inner: Arc::new(Inner {
                table: Mutex::new(Table::default()),
                generations: AtomicU64::new(0),
                total_limit,
                user_limit,
            }),
        }
    }

    /// Test-only bounds: the total and the per-user limit.
    #[cfg(test)]
    pub(crate) fn with_bounds(total: usize, per_user: usize) -> Self {
        Self::with_limits(total, per_user)
    }

    /// Sends `ask` on the owner's link to `target`, making the link first when needed. A tools/call
    /// that the upstream refuses with a JSON-RPC error keeps the link and is returned as `Refused`.
    pub async fn send(
        &self,
        state: &AppState,
        owner: Owner,
        target: &Target,
        ask: Ask<'_>,
    ) -> Result<Answer, Fault> {
        let key = (owner.family_id, target.server_id);
        let relays = matches!(ask, Ask::Call { .. });
        let mut retried = false;
        loop {
            let link = self.link_for(state, owner, key, target).await?;
            let id = link.next_id();
            let outgoing = outgoing(&link.form, &ask, id)?;
            let response = upstream::send(state, target, outgoing).await?;
            match response.status().as_u16() {
                404 if link.session_id().is_some() && !retried => {
                    self.inner.drop_link(key, link.generation);
                    retried = true;
                }
                200 => {
                    let stateless = matches!(link.form, Form::Stateless);
                    return match upstream::accept(&response) {
                        Ok(kind @ (Kind::Json | Kind::Stream)) => Ok(Answer::Sent(Sent {
                            response,
                            id: json!(id),
                            kind,
                            stateless,
                        })),
                        Ok(Kind::Empty) => Err(Fault(Cause::NotMcp)),
                        Err(fault) => Err(fault),
                    };
                }
                400 | 404 => {
                    let status = response.status();
                    if relays && let Some(answer) = refusal(state, response, &json!(id)).await {
                        return Ok(Answer::Refused { status, answer });
                    }
                    if status == StatusCode::BAD_REQUEST
                        && self.inner.drop_link(key, link.generation)
                        && let Some(session) = link.session_id()
                    {
                        close_later(state, owned_target(target), session.clone());
                    }
                    return Err(Fault(Cause::Status(status.as_u16())));
                }
                _ => return Err(Fault(Cause::Status(response.status().as_u16()))),
            }
        }
    }

    /// True when the owner's link to `target` speaks the stateless form; makes the link first when needed.
    pub async fn stateless(
        &self,
        state: &AppState,
        owner: Owner,
        target: &Target,
    ) -> Result<bool, Fault> {
        let key = (owner.family_id, target.server_id);
        let link = self.link_for(state, owner, key, target).await?;
        Ok(matches!(link.form, Form::Stateless))
    }

    /// The owner's usable link for `key`, or one made now.
    async fn link_for(
        &self,
        state: &AppState,
        owner: Owner,
        key: (i64, i64),
        target: &Target,
    ) -> Result<Arc<Link>, Fault> {
        match self.inner.usable(key, target) {
            Some(link) => Ok(link),
            None => self.make(state, owner, key, target).await,
        }
    }

    /// The number of links kept (for tests and the bound).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .entries
            .values()
            .filter(|entry| entry.link.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Makes the link for `key` in a spawned task that the requester waits for.
    async fn make(
        &self,
        state: &AppState,
        owner: Owner,
        key: (i64, i64),
        target: &Target,
    ) -> Result<Arc<Link>, Fault> {
        let gate = self.inner.gate(key, owner.user_id);
        let inner = Arc::clone(&self.inner);
        let state = state.clone();
        let target = owned_target(target);
        let task = tokio::spawn(async move {
            let _turn = gate.lock_owned().await;
            if let Some(link) = inner.usable(key, &target) {
                return Ok(link);
            }
            let form = match timeout(
                time_limit(&state).min(HANDSHAKE_LIMIT),
                handshake(&state, &target),
            )
            .await
            {
                Ok(form) => form?,
                Err(_) => return Err(Fault(Cause::NoAnswerInTime)),
            };
            inner.install(&state, key, owner, &target, form)
        });
        let made = match task.await {
            Ok(made) => made,
            Err(_) => Err(Fault(Cause::NoConnection)),
        };
        self.inner.tidy(key);
        made
    }
}

#[cfg(test)]
impl Links {
    /// The generation of the link the owner holds for the server, if it holds one.
    pub(crate) fn generation_of(&self, owner: Owner, server_id: i64) -> Option<u64> {
        self.inner
            .lock()
            .entries
            .get(&(owner.family_id, server_id))
            .and_then(|entry| entry.link.as_ref())
            .map(|link| link.generation)
    }

    /// Runs the drop of the owner's link for the server when it is still `generation`.
    pub(crate) fn drop_generation(&self, owner: Owner, server_id: i64, generation: u64) -> bool {
        self.inner
            .drop_link((owner.family_id, server_id), generation)
    }
}

/// One link, as made. It keeps the target's URL and a digest of its secret, never the target.
struct Link {
    generation: u64,
    url: String,
    secret: Option<Vec<u8>>,
    form: Form,
    /// The last request id this link used.
    requests: AtomicU64,
}

impl Link {
    /// The next request id of this link: its own sequence, after the handshake's ids.
    fn next_id(&self) -> u64 {
        self.requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn session_id(&self) -> Option<&HeaderValue> {
        match &self.form {
            Form::Stateless => None,
            Form::Session { id, .. } => id.as_ref(),
        }
    }

    fn serves(&self, target: &Target) -> bool {
        self.url == target.url && self.secret == digest(target.secret.as_ref())
    }
}

/// The row of one (family, server) key. `gate` is held while its link is made.
struct Entry {
    user_id: i64,
    gate: Arc<AsyncMutex<()>>,
    link: Option<Arc<Link>>,
    /// The tick of the last use, for least recently used.
    used: u64,
}

#[derive(Default)]
struct Table {
    entries: HashMap<(i64, i64), Entry>,
    clock: u64,
}

impl Table {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
}

struct Inner {
    table: Mutex<Table>,
    generations: AtomicU64,
    total_limit: usize,
    user_limit: usize,
}

impl Inner {
    /// The table lock. It is never held across an await.
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The link for `key` when it serves `target`; a link for another target is dropped unused.
    fn usable(&self, key: (i64, i64), target: &Target) -> Option<Arc<Link>> {
        let mut table = self.lock();
        let tick = table.tick();
        let entry = table.entries.get_mut(&key)?;
        let held = entry.link.as_ref()?;
        if held.serves(target) {
            let held = Arc::clone(held);
            entry.used = tick;
            return Some(held);
        }
        entry.link = None;
        None
    }

    /// The gate of `key`, made with its row when there is none.
    fn gate(&self, key: (i64, i64), user_id: i64) -> Arc<AsyncMutex<()>> {
        let mut table = self.lock();
        let entry = table.entries.entry(key).or_insert_with(|| Entry {
            user_id,
            gate: Arc::new(AsyncMutex::new(())),
            link: None,
            used: 0,
        });
        Arc::clone(&entry.gate)
    }

    /// Drops the link of `key` when it is still generation `generation`; true when dropped.
    fn drop_link(&self, key: (i64, i64), generation: u64) -> bool {
        let mut table = self.lock();
        let dropped = match table.entries.get_mut(&key) {
            Some(entry)
                if entry
                    .link
                    .as_ref()
                    .is_some_and(|link| link.generation == generation) =>
            {
                entry.link = None;
                true
            }
            _ => false,
        };
        tidy_locked(&mut table, key);
        dropped
    }

    /// Removes the row of `key` when it holds no link and nobody waits on its gate.
    fn tidy(&self, key: (i64, i64)) {
        tidy_locked(&mut self.lock(), key);
    }

    /// Stores a made link and drops the least recently used links over the bounds.
    /// The sessions of the dropped links are closed in the background.
    fn install(
        &self,
        state: &AppState,
        key: (i64, i64),
        owner: Owner,
        target: &Target,
        form: Form,
    ) -> Result<Arc<Link>, Fault> {
        let generation = self.generations.fetch_add(1, Ordering::Relaxed) + 1;
        let link = Arc::new(Link {
            generation,
            url: target.url.clone(),
            secret: digest(target.secret.as_ref()),
            form,
            requests: AtomicU64::new(INITIALIZE_ID),
        });
        let mut table = self.lock();
        if let Some(session) = link.session_id()
            && table.entries.iter().any(|(other, entry)| {
                other.1 == key.1
                    && *other != key
                    && entry.link.as_ref().and_then(|held| held.session_id()) == Some(session)
            })
        {
            return Err(Fault(Cause::NotMcp));
        }
        let tick = table.tick();
        let entry = table.entries.entry(key).or_insert_with(|| Entry {
            user_id: owner.user_id,
            gate: Arc::new(AsyncMutex::new(())),
            link: None,
            used: 0,
        });
        entry.link = Some(Arc::clone(&link));
        entry.used = tick;
        let dropped = evict(
            &mut table,
            key,
            owner.user_id,
            self.total_limit,
            self.user_limit,
        );
        drop(table);
        for (server_id, held) in dropped {
            close_evicted(state, server_id, held);
        }
        Ok(link)
    }
}

/// Removes the row of `key` when it holds no link and nobody else holds its gate.
fn tidy_locked(table: &mut Table, key: (i64, i64)) {
    let idle = table
        .entries
        .get(&key)
        .is_some_and(|entry| entry.link.is_none() && Arc::strong_count(&entry.gate) == 1);
    if idle {
        table.entries.remove(&key);
    }
}

/// Takes links out of the table, least recently used first, until the owner has at most
/// `user_limit` and the table at most `total_limit`. The link of `keep` is never taken.
fn evict(
    table: &mut Table,
    keep: (i64, i64),
    user_id: i64,
    total_limit: usize,
    user_limit: usize,
) -> Vec<(i64, Arc<Link>)> {
    let mut dropped = Vec::new();
    while linked(table, Some(user_id)) > user_limit {
        let Some(key) = least_used(table, keep, Some(user_id)) else {
            break;
        };
        dropped.extend(take_link(table, key));
    }
    while linked(table, None) > total_limit {
        let Some(key) = least_used(table, keep, None) else {
            break;
        };
        dropped.extend(take_link(table, key));
    }
    dropped
}

/// How many links the table holds, for one user or for all.
fn linked(table: &Table, user_id: Option<i64>) -> usize {
    table
        .entries
        .values()
        .filter(|entry| entry.link.is_some() && user_id.is_none_or(|id| entry.user_id == id))
        .count()
}

/// The least recently used key with a link, other than `keep`, for one user or for all.
fn least_used(table: &Table, keep: (i64, i64), user_id: Option<i64>) -> Option<(i64, i64)> {
    table
        .entries
        .iter()
        .filter(|(key, entry)| {
            **key != keep && entry.link.is_some() && user_id.is_none_or(|id| entry.user_id == id)
        })
        .min_by_key(|(_, entry)| entry.used)
        .map(|(key, _)| *key)
}

/// The link of `key` taken out of the table, with its server id; the emptied row is removed.
fn take_link(table: &mut Table, key: (i64, i64)) -> Option<(i64, Arc<Link>)> {
    let link = table.entries.get_mut(&key)?.link.take();
    tidy_locked(table, key);
    link.map(|link| (key.1, link))
}

/// Closes one dropped session in the background, best effort: the answer does not matter.
fn close_later(state: &AppState, target: Target, session: HeaderValue) {
    let state = state.clone();
    tokio::spawn(async move {
        catalog::close_session(&state, &target, &session, target.secret.is_some()).await;
    });
}

/// Closes an evicted session in the background, with the secret, and only at the target the
/// server row has now when the link still serves it. No DELETE otherwise.
fn close_evicted(state: &AppState, server_id: i64, link: Arc<Link>) {
    let state = state.clone();
    tokio::spawn(async move {
        let Some(session) = link.session_id().cloned() else {
            return;
        };
        match upstream::target(&state, server_id).await {
            Ok(Some(target)) if link.serves(&target) => {
                catalog::close_session(&state, &target, &session, true).await;
            }
            Ok(_) => {}
            Err(err) => report::failure("evicted upstream session", &format!("{err:?}")),
        }
    });
}

fn owned_target(target: &Target) -> Target {
    Target {
        server_id: target.server_id,
        slug: target.slug.clone(),
        url: target.url.clone(),
        secret: target.secret.clone(),
    }
}

/// SHA-256 of a secret header's name and value; None when the target has no secret.
fn digest(secret: Option<&(HeaderName, HeaderValue)>) -> Option<Vec<u8>> {
    let (name, value) = secret?;
    let mut hash = Sha256::new();
    hash.update(name.as_str().as_bytes());
    hash.update([0u8]);
    hash.update(value.as_bytes());
    Some(hash.finalize().to_vec())
}

/// True for 1 to 256 bytes of visible ASCII.
fn visible_id(id: &HeaderValue) -> bool {
    let bytes = id.as_bytes();
    (1..=SESSION_ID_LIMIT).contains(&bytes.len())
        && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
}

fn client_info() -> Value {
    json!({"name": "doorward", "version": env!("CARGO_PKG_VERSION")})
}

/// The `_meta` of a request: the progress token when it is a string or integer, and for a
/// stateless request the protocol version, client capabilities and client info.
fn meta(stateless: bool, progress_token: Option<&Value>) -> Map<String, Value> {
    let mut meta = Map::new();
    if let Some(token) = progress_token
        && (token.is_string() || token.is_i64() || token.is_u64())
    {
        meta.insert("progressToken".to_owned(), token.clone());
    }
    if stateless {
        meta.insert(META_VERSION.to_owned(), json!(STATELESS));
        meta.insert(CLIENT_CAPABILITIES.to_owned(), json!({}));
        meta.insert(CLIENT_INFO.to_owned(), client_info());
    }
    meta
}

#[derive(Serialize)]
struct Envelope<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

#[derive(Serialize)]
struct ListParams<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    #[serde(rename = "_meta", skip_serializing_if = "Map::is_empty")]
    meta: Map<String, Value>,
}

#[derive(Serialize)]
struct CallParams<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<&'a RawValue>,
    #[serde(rename = "_meta", skip_serializing_if = "Map::is_empty")]
    meta: Map<String, Value>,
}

/// One JSON-RPC request body with request id `id`.
fn envelope<P: Serialize>(id: u64, method: &str, params: P) -> Result<Bytes, Fault> {
    let body = Envelope {
        jsonrpc: "2.0",
        id,
        method,
        params,
    };
    match serde_json::to_vec(&body) {
        Ok(bytes) => Ok(Bytes::from(bytes)),
        Err(err) => {
            report::failure("upstream request", &err);
            Err(Fault(Cause::NoConnection))
        }
    }
}

/// The request for a link: headers from nothing, and the body built from the ask alone.
fn outgoing(form: &Form, ask: &Ask<'_>, id: u64) -> Result<Outgoing, Fault> {
    let stateless = matches!(form, Form::Stateless);
    let (version, session) = match form {
        Form::Stateless => (STATELESS, None),
        Form::Session {
            revision,
            id: session_id,
        } => (*revision, session_id.as_ref()),
    };
    let method = match ask {
        Ask::List { .. } => "tools/list",
        Ask::Call { .. } => "tools/call",
    };
    let mut headers = request_headers(version, stateless.then_some(method), session);
    let body = match ask {
        Ask::List { cursor } => envelope(
            id,
            method,
            ListParams {
                cursor: *cursor,
                meta: meta(stateless, None),
            },
        )?,
        Ask::Call {
            name,
            arguments,
            progress_token,
        } => {
            if stateless {
                let value = HeaderValue::from_str(name).map_err(|_| Fault(Cause::NoConnection))?;
                headers.insert(HeaderName::from_static("mcp-name"), value);
            }
            envelope(
                id,
                method,
                CallParams {
                    name,
                    arguments: *arguments,
                    meta: meta(stateless, *progress_token),
                },
            )?
        }
    };
    Ok(Outgoing {
        method: Method::POST,
        headers,
        body,
        with_secret: true,
    })
}

/// One answer of the handshake: its status, its session id header, and its whole answer when it has one.
struct Exchange {
    status: u16,
    session: Option<HeaderValue>,
    answer: Option<Value>,
    /// Why there is no answer, when the status is 200.
    reason: Cause,
}

/// The handshake: the stateless probe, then, when the probe has no result, initialize and
/// the initialized notice. A transport fault at any step is a Fault.
async fn handshake(state: &AppState, target: &Target) -> Result<Form, Fault> {
    let cap = state.config.limits.tools_list_bytes;
    let probe_id = PROBE_ID;
    let probe = exchange(
        state,
        target,
        request_headers(STATELESS, Some("server/discover"), None),
        envelope(
            probe_id,
            "server/discover",
            json!({"_meta": meta(true, None)}),
        )?,
        probe_id,
        cap,
    )
    .await?;
    if probe.status == 200
        && probe
            .answer
            .as_ref()
            .is_some_and(|answer| answer.get("result").is_some())
    {
        return Ok(Form::Stateless);
    }
    let init_id = INITIALIZE_ID;
    let init = exchange(
        state,
        target,
        request_headers(SESSION, None, None),
        envelope(
            init_id,
            "initialize",
            json!({"protocolVersion": SESSION, "capabilities": {}, "clientInfo": client_info()}),
        )?,
        init_id,
        cap,
    )
    .await?;
    let answer = match (init.status, init.answer) {
        (200, Some(answer)) => answer,
        (200, None) => return Err(Fault(init.reason)),
        (status, _) => return Err(Fault(Cause::Status(status))),
    };
    let revision = revision_of(&answer)?;
    let session = match init.session {
        None => None,
        Some(id) if visible_id(&id) => Some(id),
        Some(_) => return Err(Fault(Cause::NotMcp)),
    };
    if let Some(id) = &session
        && session_recorded(state, target.server_id, id).await?
    {
        return Err(Fault(Cause::NotMcp));
    }
    let notice =
        Bytes::from(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());
    send_post(
        state,
        target,
        request_headers(revision, None, session.as_ref()),
        notice,
    )
    .await?;
    Ok(Form::Session {
        revision,
        id: session,
    })
}

/// The revision an initialize result answers with, from the known ones.
fn revision_of(answer: &Value) -> Result<&'static str, Fault> {
    let version = answer["result"]["protocolVersion"]
        .as_str()
        .ok_or(Fault(Cause::NotMcp))?;
    REVISIONS
        .iter()
        .copied()
        .find(|revision| *revision == version)
        .ok_or(Fault(Cause::NotMcp))
}

/// True when upstream_sessions already holds the id for the server, whoever owns it.
async fn session_recorded(
    state: &AppState,
    server_id: i64,
    id: &HeaderValue,
) -> Result<bool, Fault> {
    let hash = token_hash(id.to_str().map_err(|_| Fault(Cause::NotMcp))?);
    let recorded = state
        .db
        .call(move |conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM upstream_sessions \
                 WHERE server_id = ?1 AND id_hash = ?2)",
                params![server_id, hash],
                |row| row.get::<_, bool>(0),
            )
        })
        .await;
    match recorded {
        Ok(found) => Ok(found),
        Err(err) => {
            report::failure("upstream sessions", &err);
            Err(Fault(Cause::NoConnection))
        }
    }
}

async fn send_post(
    state: &AppState,
    target: &Target,
    headers: HeaderMap,
    body: Bytes,
) -> Result<reqwest::Response, Fault> {
    let outgoing = Outgoing {
        method: Method::POST,
        headers,
        body,
        with_secret: true,
    };
    upstream::send(state, target, outgoing).await
}

/// One handshake request. The answer is read only for HTTP 200 with a JSON or event-stream body.
async fn exchange(
    state: &AppState,
    target: &Target,
    headers: HeaderMap,
    body: Bytes,
    id: u64,
    cap: u64,
) -> Result<Exchange, Fault> {
    let response = send_post(state, target, headers, body).await?;
    let status = response.status().as_u16();
    let session = response.headers().get("mcp-session-id").cloned();
    if status != 200 {
        return Ok(Exchange {
            status,
            session,
            answer: None,
            reason: Cause::NotMcp,
        });
    }
    let (answer, reason) = match upstream::accept(&response) {
        Ok(kind @ (Kind::Json | Kind::Stream)) => {
            match read_answer(state, response, kind, cap, &json!(id)).await? {
                Ok(answer) => (Some(answer), Cause::NotMcp),
                Err(cause) => (None, cause),
            }
        }
        Ok(Kind::Empty) => (None, Cause::NotMcp),
        Err(Fault(cause)) => (None, cause),
    };
    Ok(Exchange {
        status,
        session,
        answer,
        reason,
    })
}

/// The whole answer of a 400 or 404 JSON body that is a JSON-RPC error to `id`: `jsonrpc` 2.0, no `result`,
/// and an `error` with an integer code and a string message. None for any other body, or one over the cap.
async fn refusal(state: &AppState, response: reqwest::Response, id: &Value) -> Option<Value> {
    if !matches!(upstream::accept(&response), Ok(Kind::Json)) {
        return None;
    }
    let cap = state.config.limits.tools_list_bytes;
    let bytes = upstream::body(state, response, cap).await.ok()?;
    let value = parse_strict(&bytes).ok()?;
    let object = value.as_object()?;
    let error = object.get("error")?.as_object()?;
    let well_formed = object.get("jsonrpc") == Some(&json!("2.0"))
        && object.get("id") == Some(id)
        && !object.contains_key("result")
        && error.get("code").is_some_and(Value::is_i64)
        && error.get("message").is_some_and(Value::is_string);
    well_formed.then_some(value)
}

/// The whole answer to request `id` in a body of the given kind, or the cause it is not one.
async fn read_answer(
    state: &AppState,
    response: reqwest::Response,
    kind: Kind,
    cap: u64,
    id: &Value,
) -> Result<Result<Value, Cause>, Fault> {
    match kind {
        Kind::Json => {
            let bytes = read_body(state, response, cap)
                .await
                .map_err(BodyError::into_fault)?;
            Ok(match parse_strict(&bytes) {
                Ok(value) => whole_answer(value, id).ok_or(Cause::NotMcp),
                Err(_) => Err(Cause::NotJson),
            })
        }
        Kind::Stream => Ok(stream_answer(state, response, cap, id)
            .await?
            .ok_or(Cause::NotMcp)),
        Kind::Empty => Ok(Err(Cause::NotMcp)),
    }
}

/// The first whole answer to request `id` in an event stream, read under the cap and the time limit.
async fn stream_answer(
    state: &AppState,
    response: reqwest::Response,
    cap: u64,
    id: &Value,
) -> Result<Option<Value>, Fault> {
    let mut pending: Vec<u8> = Vec::new();
    let mut found: Option<Value> = None;
    let read = read_stream(state, response, cap, |chunk| {
        pending.extend_from_slice(chunk);
        let (events, used) = sse_events(&pending);
        pending.drain(..used);
        for data in events {
            if let Some(answer) = parse_strict(&data)
                .ok()
                .and_then(|value| whole_answer(value, id))
            {
                found = Some(answer);
                return true;
            }
        }
        false
    })
    .await;
    match read {
        Ok(_) => Ok(found),
        Err(err) => Err(err.into_fault()),
    }
}

/// The value when it is an object with `id` equal to `expected` and exactly one of `result` and `error`.
fn whole_answer(value: Value, expected: &Value) -> Option<Value> {
    let object = value.as_object()?;
    if object.get("id") != Some(expected) {
        return None;
    }
    (object.contains_key("result") != object.contains_key("error")).then_some(value)
}

/// Reads the answer to `sent.id`: an object with that id and exactly one of `result` and `error`.
pub async fn read(state: &AppState, sent: Sent, cap: u64) -> Result<Value, Fault> {
    let Sent {
        response, id, kind, ..
    } = sent;
    read_answer(state, response, kind, cap, &id)
        .await?
        .map_err(Fault)
}
