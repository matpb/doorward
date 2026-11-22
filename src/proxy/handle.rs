//! The relay of one request on `/{slug}`: the POST order, GET and DELETE, and the upstream answer.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::http::header::CACHE_CONTROL;
use axum::http::header::{
    ACCEPT, ALLOW, CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::budget::Reservation;
use super::catalog;
use super::intake::{Intake, intake};
use super::sessions;
use super::stream::{self, ACCESS_LOST, CHECK_FAILED, Owned, Watch};
use super::upstream::{
    self, Cause, Fault, Kind, LIST_LIMIT, Outgoing, Target, TargetError, time_limit,
};
use super::values;
use crate::app::AppState;
use crate::custom_headers::Resolved;
use crate::mcp::answer;
use crate::mcp::json::parse_strict;
use crate::mcp::message::{
    Decision, Generation, Message, Shape, Switches, decide, stateless_version,
};
use crate::oauth::guard::{self, Caller, Recheck, still_valid, still_valid_at};
use crate::policy;
use crate::report;
use crate::servers;
use crate::web::limit::hold;

const MCP_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("mcp-protocol-version");
const MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_METHOD: HeaderName = HeaderName::from_static("mcp-method");
const MCP_NAME: HeaderName = HeaderName::from_static("mcp-name");
pub(super) const INVALID: &str = "Invalid request";
pub(super) const PARSE: &str = "Parse error";
const SESSION_LIMIT: usize = 256;
pub(super) const TOOL_LIMIT: usize = 128;
/// The detail of a call whose name the tool list lacks.
pub(super) const NOT_LISTED: &str = "not in the tool list";

/// What one request needs: its server, its caller, when it started, and what the bearer check reads
/// again when a buffered answer arrives: the request's headers and its peer address.
pub(super) struct Ctx<'a> {
    pub state: &'a AppState,
    pub slug: &'a str,
    pub server_id: i64,
    pub caller: Arc<Caller>,
    pub started: Instant,
    pub headers: HeaderMap,
    pub peer: IpAddr,
}

impl Ctx<'_> {
    /// An owned copy of the context, for a relay that outlives the handler.
    fn owned(&self) -> Owned {
        Owned {
            state: self.state.clone(),
            slug: self.slug.to_owned(),
            server_id: self.server_id,
            caller: Arc::clone(&self.caller),
            started: self.started,
        }
    }
}

/// The client's session id, checked against the caller's recorded sessions.
struct Session {
    id: String,
    header: HeaderValue,
}

/// What the client sent in Mcp-Session-Id.
enum Sent {
    Absent,
    Refused,
    Id(String, HeaderValue),
}

/// Steps 1 to 10 of the POST order. Every refusal answers before any upstream contact.
pub(super) async fn post(ctx: &Ctx<'_>, headers: &HeaderMap, body: Body) -> Response {
    let Intake { message, bytes } = match intake(ctx.state, headers, body).await {
        Ok(intake) => intake,
        Err(refusal) => return refusal,
    };
    let session = if message.method.as_deref() == Some("initialize") {
        None
    } else {
        match caller_session(ctx, headers).await {
            Ok(session) => session,
            Err(refusal) => return refusal,
        }
    };
    if message.shape == Shape::Response && session.is_none() {
        return answer::error(
            StatusCode::BAD_REQUEST,
            message.id.as_ref(),
            -32600,
            INVALID,
        );
    }
    let switches = match switches(ctx).await {
        Ok(switches) => switches,
        Err(refusal) => return refusal,
    };
    if message.shape != Shape::Response {
        match decide(&message, switches) {
            Decision::Forward => {}
            Decision::EmptyList(key) => {
                return match message.shape {
                    Shape::Request => answer::empty_list(&message, key),
                    _ => bare(StatusCode::ACCEPTED),
                };
            }
            Decision::MethodNotFound => {
                return match message.shape {
                    Shape::Request => answer::method_not_found(&message),
                    _ => bare(StatusCode::ACCEPTED),
                };
            }
        }
    }
    let call = if message.method.as_deref() == Some("tools/call") {
        match message.tool.clone() {
            Some(name) => Some(name),
            None => {
                return answer::error(
                    StatusCode::BAD_REQUEST,
                    message.id.as_ref(),
                    -32600,
                    INVALID,
                );
            }
        }
    } else {
        None
    };
    let target = match target(ctx, call.as_deref()).await {
        Ok(target) => target,
        Err(refusal) => return refusal,
    };
    let user_headers = match declared_headers(ctx, headers, message.id.as_ref(), &target).await {
        Ok(user_headers) => user_headers,
        Err(refused) => return refused.response,
    };
    if let Some(name) = call.as_deref() {
        match refusal_of(ctx, &target, name, &user_headers).await {
            Ok(None) => {}
            Ok(Some(detail)) => {
                record(ctx, name, "deny", "refused", &detail).await;
                let null = Value::Null;
                return answer::unknown_tool(message.id.as_ref().unwrap_or(&null), name);
            }
            Err(refusal) => return refusal,
        }
    }
    let mut upstream_headers = outgoing_headers(
        headers,
        message.generation == Generation::Stateless,
        message.method.as_deref(),
        session.as_ref().map(|session| &session.header),
    );
    upstream_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let outgoing = Outgoing {
        method: Method::POST,
        headers: upstream_headers,
        body: bytes,
        with_secret: true,
        user_headers,
    };
    let owed = call.as_deref().map(|name| Owed::new(ctx, name));
    match upstream::send(ctx.state, &target, outgoing).await {
        Ok(response) => relay_post(ctx, &message, owed, switches, response).await,
        Err(Fault(cause)) => fault(ctx, owed, cause).await,
    }
}

/// GET and DELETE: 405 under the stateless rules or without a session; else relayed for the caller's session.
pub(super) async fn get_or_delete(ctx: &Ctx<'_>, method: &Method, headers: &HeaderMap) -> Response {
    let (version, clean) = version_of(headers);
    if !clean {
        return answer::error(StatusCode::BAD_REQUEST, None, -32600, INVALID);
    }
    if stateless_version(version) || !headers.contains_key(MCP_SESSION_ID) {
        return not_allowed();
    }
    let session = match caller_session(ctx, headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return not_allowed(),
        Err(refusal) => return refusal,
    };
    let target = match target(ctx, None).await {
        Ok(target) => target,
        Err(refusal) => return refusal,
    };
    let user_headers = match declared_headers(ctx, headers, None, &target).await {
        Ok(user_headers) => user_headers,
        Err(refused) if refused.withheld && *method == Method::DELETE => {
            forget(ctx, session.id).await;
            return relayed(StatusCode::NO_CONTENT, None, Body::empty(), None);
        }
        Err(refused) => return refused.response,
    };
    let outgoing = Outgoing {
        method: method.clone(),
        headers: outgoing_headers(headers, false, None, Some(&session.header)),
        body: Bytes::new(),
        with_secret: true,
        user_headers,
    };
    let sent = upstream::send(ctx.state, &target, outgoing).await;
    if *method == Method::DELETE {
        forget(ctx, session.id).await;
    }
    match sent {
        Ok(response) if *method == Method::GET => relay_get(ctx, response),
        Ok(response)
            if *method == Method::DELETE && response.status() == StatusCode::NO_CONTENT =>
        {
            relayed(StatusCode::NO_CONTENT, None, Body::empty(), None)
        }
        Ok(response) => relay_plain(ctx, response).await,
        Err(Fault(cause)) => unavailable_for(ctx, cause),
    }
}

/// The answer without a body, with the two inert-content headers.
pub(super) fn bare(status: StatusCode) -> Response {
    let mut response = status.into_response();
    inert(&mut response);
    response
}

/// The 405 of GET and DELETE outside a session, which names the one allowed method.
pub(super) fn not_allowed() -> Response {
    let mut response = bare(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static("POST"));
    response
}

fn inert(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox"));
}

/// A relayed answer: its status, its one content type, the session id when given, the inert headers.
fn relayed(
    status: StatusCode,
    content_type: Option<&'static str>,
    body: Body,
    session: Option<HeaderValue>,
) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    if let Some(content_type) = content_type {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    if let Some(session) = session {
        response.headers_mut().insert(MCP_SESSION_ID, session);
    }
    inert(&mut response);
    response
}

/// The MCP-Protocol-Version value when it is sent once and visible, and whether the header is clean
/// (absent, or sent once and visible).
pub(super) fn version_of(headers: &HeaderMap) -> (Option<&str>, bool) {
    let mut values = headers.get_all(MCP_PROTOCOL_VERSION).iter();
    match (values.next(), values.next()) {
        (None, _) => (None, true),
        (Some(value), None) if visible(value.as_bytes(), usize::MAX) => (value.to_str().ok(), true),
        _ => (None, false),
    }
}

/// The one Mcp-Session-Id, when it is 1 to 256 visible ASCII characters.
fn sent_session(headers: &HeaderMap) -> Sent {
    let mut values = headers.get_all(MCP_SESSION_ID).iter();
    match (values.next(), values.next()) {
        (None, _) => Sent::Absent,
        (Some(value), None) if visible(value.as_bytes(), SESSION_LIMIT) => match value.to_str() {
            Ok(text) => Sent::Id(text.to_owned(), value.clone()),
            Err(_) => Sent::Refused,
        },
        _ => Sent::Refused,
    }
}

/// True for 1 to `limit` bytes, all visible ASCII.
fn visible(bytes: &[u8], limit: usize) -> bool {
    !bytes.is_empty()
        && bytes.len() <= limit
        && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
}

/// The client's session, when it sent one and it is recorded for this caller. The refusal is the 404.
async fn caller_session(ctx: &Ctx<'_>, headers: &HeaderMap) -> Result<Option<Session>, Response> {
    let (id, header) = match sent_session(headers) {
        Sent::Absent => return Ok(None),
        Sent::Refused => return Err(bare(StatusCode::NOT_FOUND)),
        Sent::Id(id, header) => (id, header),
    };
    if belongs(ctx, id.clone()).await? {
        Ok(Some(Session { id, header }))
    } else {
        Err(bare(StatusCode::NOT_FOUND))
    }
}

async fn belongs(ctx: &Ctx<'_>, id: String) -> Result<bool, Response> {
    let server = ctx.server_id;
    let caller = Arc::clone(&ctx.caller);
    match ctx
        .state
        .db
        .call(move |conn| sessions::belongs(conn, server, &id, &caller))
        .await
    {
        Ok(found) => Ok(found),
        Err(err) => {
            report::failure("upstream sessions", &err);
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

async fn forget(ctx: &Ctx<'_>, id: String) {
    let server = ctx.server_id;
    if let Err(err) = ctx
        .state
        .db
        .call(move |conn| sessions::forget(conn, server, &id))
        .await
    {
        report::failure("upstream session", &err);
    }
}

/// The switches of the server row; a missing row is refused like an unusable upstream.
async fn switches(ctx: &Ctx<'_>) -> Result<Switches, Response> {
    let server = ctx.server_id;
    match ctx
        .state
        .db
        .call(move |conn| servers::load(conn, server))
        .await
    {
        Ok(Some(row)) => Ok(Switches {
            resources: row.pass_resources,
            prompts: row.pass_prompts,
        }),
        Ok(None) => Err(answer::unavailable(ctx.slug)),
        Err(err) => {
            report::failure("server", &err);
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// The upstream of the server, as the proxy opens it. Neither a missing row nor a bad secret is sent on;
/// a bad secret is the gateway's fault, written and recorded against the call, if there is one.
async fn target(ctx: &Ctx<'_>, call: Option<&str>) -> Result<Target, Response> {
    match upstream::target(ctx.state, ctx.server_id).await {
        Ok(Some(target)) => Ok(target),
        Ok(None) => Err(answer::unavailable(ctx.slug)),
        Err(TargetError::Secret) => {
            let phrase = upstream::fail(ctx.slug, Cause::SecretUnreadable);
            if let Some(name) = call {
                record(ctx, name, "allow", "unavailable", &phrase).await;
            }
            Err(answer::unavailable(ctx.slug))
        }
        Err(TargetError::Db(err)) => {
            report::failure("server", &err);
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// The answer that stops a request before any upstream; `withheld` when the caller's values are missing,
/// locked or unopenable.
struct Refused {
    response: Response,
    withheld: bool,
}

impl Refused {
    fn other(response: Response) -> Refused {
        Refused {
            response,
            withheld: false,
        }
    }

    fn withheld(response: Response) -> Refused {
        Refused {
            response,
            withheld: true,
        }
    }
}

/// The custom headers this request carries to the server, opened for the address of `target`.
async fn declared_headers(
    ctx: &Ctx<'_>,
    client: &HeaderMap,
    id: Option<&Value>,
    target: &Target,
) -> Result<Vec<(HeaderName, HeaderValue)>, Refused> {
    let reached = values::resolve(
        ctx.state,
        &ctx.caller,
        client,
        ctx.server_id,
        Some(&target.url),
    )
    .await;
    let reached = match reached {
        Ok(reached) => reached,
        Err(err) => {
            report::failure("custom headers", &err);
            return Err(Refused::other(bare(StatusCode::INTERNAL_SERVER_ERROR)));
        }
    };
    match (reached.resolved, reached.name) {
        (Resolved::Ready(headers), _) => Ok(headers),
        (Resolved::Bad, _) => Err(Refused::other(answer::error(
            StatusCode::BAD_REQUEST,
            id,
            -32600,
            INVALID,
        ))),
        (Resolved::Missing { header }, Some(name)) => Err(Refused::withheld(missing_header(
            ctx.state,
            &name,
            reached.store,
            &header,
        ))),
        (Resolved::Locked, Some(name)) => Err(Refused::withheld(reconnect(&name))),
        (Resolved::Unopenable, Some(name)) => Err(Refused::withheld(unopenable(ctx.state, &name))),
        (Resolved::Missing { .. } | Resolved::Locked | Resolved::Unopenable, None) => {
            Err(Refused::other(answer::unavailable(ctx.slug)))
        }
    }
}

/// The text of a request whose connection cannot open the user's key.
pub(super) fn reconnect_text(server: &str) -> String {
    format!("Reconnect this app to use {server}")
}

/// The text of a request whose stored value is held but does not open.
pub(super) fn unopenable_text(state: &AppState, server: &str) -> String {
    format!(
        "Your stored credentials for {server} cannot be opened. Store them again at {}/account",
        state.config.public_url
    )
}

/// The text of a request whose required header has no value.
pub(super) fn missing_text(state: &AppState, server: &str, store: bool, header: &str) -> String {
    if store {
        format!(
            "{server} needs your credentials. Add them at {}/account",
            state.config.public_url
        )
    } else {
        format!("{server} needs the header {header} from this app")
    }
}

fn refusal_403(message: &str) -> Response {
    let mut response = answer::error(StatusCode::FORBIDDEN, None, -32000, message);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The 403 of a request whose connection cannot open the user's key.
fn reconnect(server: &str) -> Response {
    refusal_403(&reconnect_text(server))
}

/// The 403 of a request whose stored value does not open.
fn unopenable(state: &AppState, server: &str) -> Response {
    refusal_403(&unopenable_text(state, server))
}

/// The 403 of a request whose required header has no value: the account page's address when values can
/// be stored there, else the header's name.
fn missing_header(state: &AppState, server: &str, store: bool, header: &str) -> Response {
    refusal_403(&missing_text(state, server, store, header))
}

/// True when `name` is in the server's catalog. A miss refreshes it unless a miss refresh of the server
/// started within `catalog_refresh_seconds`; a miss that waited for a refresh reads the catalog again.
async fn listed(
    ctx: &Ctx<'_>,
    target: &Target,
    name: &str,
    user_headers: &[(HeaderName, HeaderValue)],
) -> Result<bool, Response> {
    if stored(ctx, name).await? {
        return Ok(true);
    }
    let mut last = ctx.state.turns.misses.lock(ctx.server_id).await;
    if stored(ctx, name).await? {
        return Ok(true);
    }
    let now = ctx.state.clock.now().unix_timestamp();
    let every = i64::try_from(ctx.state.config.limits.catalog_refresh_seconds).unwrap_or(i64::MAX);
    if catalog::held_off(*last, now, every) {
        return Ok(false);
    }
    *last = Some(now);
    let state = ctx.state.clone();
    let target = target.clone();
    let user = ctx.caller.user_id;
    let headers = user_headers.to_vec();
    let refresh = tokio::spawn(async move {
        let limit = time_limit(&state).min(LIST_LIMIT);
        let outcome = catalog::refresh_within(&state, &target, limit, Some(user), &headers).await;
        *last = Some(state.clock.now().unix_timestamp());
        outcome
    });
    match refresh.await {
        Ok(Ok(fresh)) => Ok(fresh.iter().any(|known| known == name)),
        Ok(Err(catalog::RefreshError::Busy)) => {
            let phrase = Fault(Cause::Busy).to_string();
            record(ctx, name, "allow", "unavailable", &phrase).await;
            Err(answer::busy())
        }
        _ => Ok(false),
    }
}

/// True when the stored catalog of the server has `name`.
async fn stored(ctx: &Ctx<'_>, name: &str) -> Result<bool, Response> {
    let server = ctx.server_id;
    match ctx
        .state
        .db
        .call(move |conn| catalog::names(conn, server))
        .await
    {
        Ok(names) => Ok(names.iter().any(|known| known == name)),
        Err(err) => {
            report::failure("tool catalog", &err);
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// The stored rules that can match the caller on this server. A rule that cannot be read is an internal error.
async fn rules_of(ctx: &Ctx<'_>) -> Result<Vec<policy::Rule>, Response> {
    let user = ctx.caller.user_id;
    let server = ctx.server_id;
    match ctx
        .state
        .db
        .call(move |conn| policy::load(conn, user, server))
        .await
    {
        Ok(rules) => Ok(rules),
        Err(err) => {
            report::failure("tool rules", &err);
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// Why a tools/call is refused, as its row says it; None when it may go on.
/// Rules are read before the catalog, so a refused call never refreshes it.
async fn refusal_of(
    ctx: &Ctx<'_>,
    target: &Target,
    name: &str,
    user_headers: &[(HeaderName, HeaderValue)],
) -> Result<Option<String>, Response> {
    let rules = rules_of(ctx).await?;
    let verdict = policy::decide(&rules, ctx.caller.user_id, ctx.server_id, name);
    if !verdict.allowed {
        return Ok(Some(format!("rule {}", verdict.rule.unwrap_or_default())));
    }
    if listed(ctx, target, name, user_headers).await? {
        Ok(None)
    } else {
        Ok(Some(NOT_LISTED.to_owned()))
    }
}

/// Removes from a tools/list result every tool the caller may not use, and every entry without a name; true when one was removed.
async fn hide_refused(ctx: &Ctx<'_>, value: &mut Value) -> Result<bool, Response> {
    let rules = rules_of(ctx).await?;
    let (user, server) = (ctx.caller.user_id, ctx.server_id);
    let Some(tools) = value
        .pointer_mut("/result/tools")
        .and_then(Value::as_array_mut)
    else {
        return Ok(false);
    };
    let before = tools.len();
    tools.retain(|tool| {
        tool.get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| policy::decide(&rules, user, server, name).allowed)
    });
    Ok(tools.len() != before)
}

/// The headers sent upstream: built from nothing, with the client's allowed ones copied.
fn outgoing_headers(
    client: &HeaderMap,
    stateless: bool,
    method: Option<&str>,
    session: Option<&HeaderValue>,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    copy_all(client, &mut out, &ACCEPT);
    if let Some(version) = client.get(MCP_PROTOCOL_VERSION) {
        out.insert(MCP_PROTOCOL_VERSION, version.clone());
    }
    if stateless {
        copy_all(client, &mut out, &MCP_METHOD);
        if matches!(
            method,
            Some("tools/call" | "prompts/get" | "resources/read")
        ) {
            copy_all(client, &mut out, &MCP_NAME);
        }
        for (name, value) in client {
            if name.as_str().starts_with("mcp-param-") {
                out.append(name.clone(), value.clone());
            }
        }
    } else if let Some(session) = session {
        out.insert(MCP_SESSION_ID, session.clone());
    }
    out
}

fn copy_all(from: &HeaderMap, to: &mut HeaderMap, name: &HeaderName) {
    for value in from.get_all(name) {
        to.append(name.clone(), value.clone());
    }
}

/// The relay of a POST answer: the JSON and stream rules, and the three rewritten methods. A rewritten
/// answer is never a tools/call, so `owed` is None on that path.
async fn relay_post(
    ctx: &Ctx<'_>,
    message: &Message,
    owed: Option<Owed>,
    switches: Switches,
    response: reqwest::Response,
) -> Response {
    let status = response.status();
    let issued = response.headers().get(MCP_SESSION_ID).cloned();
    let kind = match upstream::accept(&response) {
        Ok(kind) => kind,
        Err(Fault(cause)) => return fault(ctx, owed, cause).await,
    };
    let method = message.method.as_deref().unwrap_or("");
    let rewritten = message.shape == Shape::Request
        && matches!(method, "initialize" | "server/discover" | "tools/list");
    if matches!(kind, Kind::Empty) {
        if message.shape == Shape::Request && matches!(status.as_u16(), 200 | 202) {
            return fault(ctx, owed, Cause::NotMcp).await;
        }
        if let Some(owed) = owed {
            owed.settle("error", "").await;
        }
        return relayed(status, None, Body::empty(), None);
    }
    if matches!(kind, Kind::Stream) && !rewritten {
        let watch = Watch {
            call: owed.as_ref().map(|owed| owed.tool.clone()),
            id: message.id.clone().unwrap_or(Value::Null),
            at: Some(ctx.caller.admitted),
        };
        if let Some(owed) = owed {
            owed.hand_over();
        }
        let body = stream::relay(ctx.owned(), response, watch);
        return relayed(status, Some("text/event-stream"), body, None);
    }
    let id = message.id.clone().unwrap_or(Value::Null);
    let mut held = ctx
        .state
        .links
        .budget()
        .reservation(Some(ctx.caller.user_id));
    let (mut value, raw) = match read_answer(ctx, response, kind, &id, &mut held).await {
        Ok(read) => read,
        Err(Fault(cause)) => return fault(ctx, owed, cause).await,
    };
    match still_valid_at(ctx.state, &ctx.caller, ctx.slug, ctx.caller.admitted).await {
        Recheck::Live => {}
        Recheck::Lost => return access_lost(ctx, owed, &id).await,
        Recheck::Failed => return check_failed(ctx, owed).await,
    }
    if !rewritten {
        if let Some(owed) = owed {
            let (outcome, detail) = stream::settled_by(&value);
            owed.settle(outcome, detail).await;
        }
        return hold(
            relayed(
                status,
                Some("application/json"),
                Body::from(raw.unwrap_or_default()),
                None,
            ),
            held,
        );
    }
    let stateless = message.generation == Generation::Stateless;
    let mut changed = trim_capabilities(&mut value, method, switches);
    if method == "tools/list" {
        if stateless {
            changed |= set_private(&mut value);
        }
        match first_page(&value, &message.value) {
            Ok(Some(tools)) => replace_catalog(ctx, tools).await,
            Ok(None) => {}
            Err(Fault(cause)) => return fault(ctx, owed, cause).await,
        }
        match hide_refused(ctx, &mut value).await {
            Ok(removed) => changed |= removed,
            Err(refusal) => return refusal,
        }
    }
    let session =
        if method == "initialize" && status == StatusCode::OK && value.get("result").is_some() {
            record_session(ctx, issued).await
        } else {
            None
        };
    let body = match raw {
        Some(raw) if !changed => raw,
        _ => Bytes::from(value.to_string()),
    };
    hold(
        relayed(status, Some("application/json"), Body::from(body), session),
        held,
    )
}

/// Reads an answer as a JSON object: a body under the cap, or the matching answer of a stream. `held`
/// covers the bytes read.
async fn read_answer(
    ctx: &Ctx<'_>,
    response: reqwest::Response,
    kind: Kind,
    id: &Value,
    held: &mut Reservation,
) -> Result<(Value, Option<Bytes>), Fault> {
    let cap = ctx.state.config.limits.tools_list_bytes;
    match kind {
        Kind::Stream => {
            let (answer, _) = catalog::stream_answer(ctx.state, response, cap, id, held)
                .await
                .map_err(upstream::BodyError::into_fault)?;
            Ok((answer, None))
        }
        _ => {
            let bytes = upstream::body(ctx.state, response, cap, held).await?;
            let value = parse_strict(&bytes).map_err(|_| Fault(Cause::NotJson))?;
            if !value.is_object() {
                return Err(Fault(Cause::NotMcp));
            }
            Ok((value, Some(bytes)))
        }
    }
}

/// The 502 of a fault, or the 503 of a used-up budget, with the one line the fault writes.
fn unavailable_for(ctx: &Ctx<'_>, cause: Cause) -> Response {
    upstream::fail(ctx.slug, cause);
    answer_for(ctx.slug, cause, false)
}

/// The answer to an upstream fault: 503 while the answer memory budget is used up, else 502. A call that
/// was sent gets the 503 that says so; a call refused before it was sent gets the plain busy answer.
pub(super) fn answer_for(slug: &str, cause: Cause, call: bool) -> Response {
    match cause {
        Cause::Busy if call => answer::busy_after_call(),
        Cause::Busy | Cause::BusyBeforeSend => answer::busy(),
        _ => answer::unavailable(slug),
    }
}

/// A GET answer: a 200 event stream is relayed as a watched stream, a 405 without its body. Any other
/// answer is a fault.
fn relay_get(ctx: &Ctx<'_>, response: reqwest::Response) -> Response {
    let status = response.status();
    match upstream::accept(&response) {
        Ok(Kind::Stream) if status == StatusCode::OK => {
            let watch = Watch {
                call: None,
                id: Value::Null,
                at: None,
            };
            let body = stream::relay(ctx.owned(), response, watch);
            relayed(status, Some("text/event-stream"), body, None)
        }
        Ok(_) if status == StatusCode::METHOD_NOT_ALLOWED => {
            relayed(status, None, Body::empty(), None)
        }
        Ok(Kind::Json) => unavailable_for(ctx, Cause::WrongContentType),
        Ok(Kind::Empty) => unavailable_for(ctx, Cause::NotMcp),
        Ok(Kind::Stream) => unavailable_for(ctx, Cause::Status(status.as_u16())),
        Err(Fault(cause)) => unavailable_for(ctx, cause),
    }
}

/// A DELETE answer: the JSON or stream as it is, with no upstream header.
async fn relay_plain(ctx: &Ctx<'_>, response: reqwest::Response) -> Response {
    let status = response.status();
    match upstream::accept(&response) {
        Err(Fault(cause)) => unavailable_for(ctx, cause),
        Ok(Kind::Empty) => relayed(status, None, Body::empty(), None),
        Ok(Kind::Stream) => {
            let watch = Watch {
                call: None,
                id: Value::Null,
                at: None,
            };
            let body = stream::relay(ctx.owned(), response, watch);
            relayed(status, Some("text/event-stream"), body, None)
        }
        Ok(Kind::Json) => {
            let cap = ctx.state.config.limits.tools_list_bytes;
            let mut held = ctx
                .state
                .links
                .budget()
                .reservation(Some(ctx.caller.user_id));
            match upstream::body(ctx.state, response, cap, &mut held).await {
                Ok(bytes) => match parse_strict(&bytes) {
                    Ok(value) if value.is_object() => {
                        match still_valid(ctx.state, &ctx.caller, ctx.slug).await {
                            Recheck::Live => {}
                            Recheck::Lost => return access_lost(ctx, None, &Value::Null).await,
                            Recheck::Failed => return check_failed(ctx, None).await,
                        }
                        hold(
                            relayed(status, Some("application/json"), Body::from(bytes), None),
                            held,
                        )
                    }
                    Ok(_) => unavailable_for(ctx, Cause::NotMcp),
                    Err(_) => unavailable_for(ctx, Cause::NotJson),
                },
                Err(Fault(cause)) => unavailable_for(ctx, cause),
            }
        }
    }
}

/// The fault answer: the 502 with its one line; a tools/call that faults is recorded as allowed and
/// unavailable, with the phrase of the fault as its detail.
async fn fault(ctx: &Ctx<'_>, owed: Option<Owed>, cause: Cause) -> Response {
    let phrase = upstream::fail(ctx.slug, cause);
    let call = owed.is_some();
    if let Some(owed) = owed {
        owed.settle("unavailable", &phrase).await;
    }
    answer_for(ctx.slug, cause, call)
}

/// The answer to a request whose caller lost access while it was awaited. A tools/call answers the
/// refusal of an unknown tool, as /mcp does; any other method answers the bearer check's own refusal.
async fn access_lost(ctx: &Ctx<'_>, owed: Option<Owed>, id: &Value) -> Response {
    if let Some(owed) = owed {
        let name = owed.tool.clone();
        owed.settle("refused", ACCESS_LOST).await;
        return answer::unknown_tool(id, &name);
    }
    match guard::check(
        ctx.state,
        ctx.peer,
        &ctx.headers,
        guard::Target::Server(ctx.slug),
    )
    .await
    {
        Err(refusal) => refusal.into_response(),
        Ok(_) => answer::unavailable(ctx.slug),
    }
}

/// The answer when the access check could not be made: the call is recorded unavailable.
async fn check_failed(ctx: &Ctx<'_>, owed: Option<Owed>) -> Response {
    if let Some(owed) = owed {
        owed.settle("unavailable", CHECK_FAILED).await;
    }
    answer::unavailable(ctx.slug)
}

/// Removes the switched-off capabilities of an initialize or server/discover result, and on a
/// discover the listChanged and subscribe members; true when it changed.
fn trim_capabilities(value: &mut Value, method: &str, switches: Switches) -> bool {
    if !matches!(method, "initialize" | "server/discover") {
        return false;
    }
    let Some(capabilities) = value
        .get_mut("result")
        .and_then(|result| result.get_mut("capabilities"))
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    let mut changed = false;
    if !switches.resources {
        changed |= capabilities.remove("resources").is_some();
    }
    if !switches.prompts {
        changed |= capabilities.remove("prompts").is_some();
    }
    if !switches.resources && !switches.prompts {
        changed |= capabilities.remove("completions").is_some();
    }
    changed |= capabilities.remove("tasks").is_some();
    if method == "server/discover" {
        for (group, member) in [
            ("tools", "listChanged"),
            ("prompts", "listChanged"),
            ("resources", "listChanged"),
            ("resources", "subscribe"),
        ] {
            changed |= drop_member(capabilities, group, member);
        }
    }
    changed
}

/// Removes `member` from the object under `group`; true when it was there.
fn drop_member(capabilities: &mut Map<String, Value>, group: &str, member: &str) -> bool {
    capabilities
        .get_mut(group)
        .and_then(Value::as_object_mut)
        .is_some_and(|object| object.remove(member).is_some())
}

/// Sets cacheScope to private on a result; true when it changed.
fn set_private(value: &mut Value) -> bool {
    let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) else {
        return false;
    };
    if result.get("cacheScope") == Some(&json!("private")) {
        return false;
    }
    result.insert("cacheScope".to_owned(), json!("private"));
    true
}

/// The tools of a tools/list result that replaces the catalog. A cursor of null is no cursor, on
/// the request or in the result.
fn first_page(answer: &Value, request: &Value) -> Result<Option<Vec<Value>>, Fault> {
    let Some(result) = answer.get("result") else {
        return Ok(None);
    };
    let has_cursor = request
        .get("params")
        .and_then(|params| params.get("cursor"))
        .is_some_and(|cursor| !cursor.is_null());
    let has_next = result
        .get("nextCursor")
        .is_some_and(|cursor| !cursor.is_null());
    if has_cursor || has_next {
        return Ok(None);
    }
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(Fault(Cause::NotMcp))?;
    Ok(Some(tools.clone()))
}

async fn replace_catalog(ctx: &Ctx<'_>, tools: Vec<Value>) {
    let server = ctx.server_id;
    let now = ctx.state.clock.now().unix_timestamp();
    if let Err(err) = ctx
        .state
        .db
        .call(move |conn| catalog::replace(conn, server, &tools, now))
        .await
    {
        report::failure("tool catalog", &err);
    }
}

/// Records the upstream's session id for this caller. Its header passes only when it was new.
async fn record_session(ctx: &Ctx<'_>, issued: Option<HeaderValue>) -> Option<HeaderValue> {
    let issued = issued?;
    if !visible(issued.as_bytes(), SESSION_LIMIT) {
        return None;
    }
    let text = issued.to_str().ok()?.to_owned();
    let server = ctx.server_id;
    let caller = Arc::clone(&ctx.caller);
    let now = ctx.state.clock.now().unix_timestamp();
    match ctx
        .state
        .db
        .call(move |conn| sessions::record(conn, server, &text, &caller, now))
        .await
    {
        Ok(true) => Some(issued),
        Ok(false) => None,
        Err(err) => {
            report::failure("upstream session", &err);
            None
        }
    }
}

/// One tool_call row. A failed write is reported and never changes the answer.
async fn record(ctx: &Ctx<'_>, tool: &str, decision: &str, outcome: &str, detail: &str) {
    stream::record(&ctx.owned(), tool, decision, outcome, detail).await;
}

/// The detail of the row of a call whose client left before the answer.
const LEFT: &str = "the client left before the answer";

/// The activity row a tools/call owes once it went upstream. Dropped unsettled, because the client
/// left, it writes the row from its own task.
pub(super) struct Owed {
    ctx: Option<Owned>,
    tool: String,
}

impl Owed {
    fn new(ctx: &Ctx<'_>, tool: &str) -> Owed {
        Owed::of(ctx.owned(), tool)
    }

    pub(super) fn of(owned: Owned, tool: &str) -> Owed {
        Owed {
            ctx: Some(owned),
            tool: tool.to_owned(),
        }
    }

    /// Writes the row with `outcome` and `detail` in its own task and waits for it, so a dropped waiter
    /// writes nothing more.
    pub(super) async fn settle(mut self, outcome: &str, detail: &str) {
        let Some(owned) = self.ctx.take() else {
            return;
        };
        let tool = std::mem::take(&mut self.tool);
        let (outcome, detail) = (outcome.to_owned(), detail.to_owned());
        let written = tokio::spawn(async move {
            stream::record(&owned, &tool, "allow", &outcome, &detail).await;
        });
        if let Err(err) = written.await {
            report::failure("activity row", &err);
        }
    }

    /// Gives the row to the stream relay, which writes it when the stream ends.
    pub(super) fn hand_over(mut self) {
        self.ctx = None;
    }
}

impl Drop for Owed {
    // Unsettled only when the handler was dropped, so the client left before the answer.
    fn drop(&mut self) {
        let Some(owned) = self.ctx.take() else {
            return;
        };
        let tool = std::mem::take(&mut self.tool);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    stream::record(&owned, &tool, "allow", "error", LEFT).await;
                });
            }
            Err(err) => report::failure("activity row", &err),
        }
    }
}

/// `text` cut to at most `limit` bytes, on a character boundary.
pub(super) fn cut(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_owned()
}
