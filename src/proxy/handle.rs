//! The relay of one request on `/{slug}`: the POST order, GET and DELETE, and the upstream answer.

use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, Bytes, to_bytes};
use axum::http::header::{
    ACCEPT, ALLOW, CONTENT_ENCODING, CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::catalog;
use super::sessions;
use super::stream::{self, Owned, Watch};
use super::upstream::{self, Fault, Kind, Outgoing, Target, TargetError};
use crate::app::AppState;
use crate::mcp::answer;
use crate::mcp::headers::{HeaderRefusal, check_stateless};
use crate::mcp::json::{JsonRefusal, parse_strict};
use crate::mcp::message::{
    Decision, Generation, Message, Refusal, Shape, Switches, classify, decide, stateless_version,
};
use crate::oauth::guard::Caller;
use crate::policy;
use crate::servers;

const MCP_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("mcp-protocol-version");
const MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_METHOD: HeaderName = HeaderName::from_static("mcp-method");
const MCP_NAME: HeaderName = HeaderName::from_static("mcp-name");
const INVALID: &str = "Invalid request";
const PARSE: &str = "Parse error";
const NO_METHOD: &str = "Method not found";
const SESSION_LIMIT: usize = 256;
pub(super) const TOOL_LIMIT: usize = 128;

/// What one request needs: its server, its caller, and when it started.
pub(super) struct Ctx<'a> {
    pub state: &'a AppState,
    pub slug: &'a str,
    pub server_id: i64,
    pub caller: Arc<Caller>,
    pub started: Instant,
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
    if headers.contains_key(CONTENT_ENCODING) || !utf8_only(headers) {
        return answer::error(StatusCode::BAD_REQUEST, None, -32600, INVALID);
    }
    let limit = usize::try_from(ctx.state.config.limits.body_bytes).unwrap_or(usize::MAX);
    let bytes = match to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(_) => return bare(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let value = match parse_strict(&bytes) {
        Ok(value) => value,
        Err(JsonRefusal::Encoding) => {
            return answer::error(StatusCode::BAD_REQUEST, None, -32600, INVALID);
        }
        Err(JsonRefusal::Syntax) => {
            return answer::error(StatusCode::BAD_REQUEST, None, -32700, PARSE);
        }
    };
    let (version, clean) = version_of(headers);
    let message = match classify(value, version) {
        Ok(message) => message,
        Err(Refusal::InvalidRequest) => {
            return answer::error(StatusCode::BAD_REQUEST, None, -32600, INVALID);
        }
    };
    if !clean && message.generation == Generation::Session {
        return answer::error(
            StatusCode::BAD_REQUEST,
            message.id.as_ref(),
            -32600,
            INVALID,
        );
    }
    if let Err(HeaderRefusal(text)) = check_stateless(headers, &message) {
        return answer::error(StatusCode::BAD_REQUEST, message.id.as_ref(), -32020, &text);
    }
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
                    Shape::Request => {
                        answer::error(StatusCode::OK, message.id.as_ref(), -32601, NO_METHOD)
                    }
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
    let target = match target(ctx).await {
        Ok(target) => target,
        Err(refusal) => return refusal,
    };
    if let Some(name) = call.as_deref() {
        let permitted = match listed(ctx, &target, name).await {
            Ok(true) => allowed(ctx, name).await,
            other => other,
        };
        match permitted {
            Ok(true) => {}
            Ok(false) => {
                record(ctx, name, "deny", "refused").await;
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
    };
    let owed = call.as_deref().map(|name| Owed::new(ctx, name));
    match upstream::send(ctx.state, &target, outgoing).await {
        Ok(response) => relay_post(ctx, &message, owed, switches, response).await,
        Err(Fault) => fault(ctx, owed).await,
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
    let target = match target(ctx).await {
        Ok(target) => target,
        Err(refusal) => return refusal,
    };
    let outgoing = Outgoing {
        method: method.clone(),
        headers: outgoing_headers(headers, false, None, Some(&session.header)),
        body: Bytes::new(),
        with_secret: true,
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
        Err(Fault) => answer::unavailable(ctx.slug),
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

/// The client's Content-Type values are all readable and name no charset but UTF-8.
fn utf8_only(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_TYPE).iter().all(|value| {
        let Ok(text) = value.to_str() else {
            return false;
        };
        text.split(';')
            .skip(1)
            .filter_map(|param| param.split_once('='))
            .filter(|(key, _)| key.trim().eq_ignore_ascii_case("charset"))
            .all(|(_, charset)| {
                charset
                    .trim()
                    .trim_matches('"')
                    .eq_ignore_ascii_case("utf-8")
            })
    })
}

/// The MCP-Protocol-Version value when it is sent once and visible, and whether the header is clean
/// (absent, or sent once and visible).
fn version_of(headers: &HeaderMap) -> (Option<&str>, bool) {
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
            eprintln!("doorward: the upstream sessions cannot be read: {err}");
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
        eprintln!("doorward: the upstream session cannot be forgotten: {err}");
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
            eprintln!("doorward: the server cannot be read: {err}");
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// The upstream of the server, as the proxy opens it. Neither a missing row nor a bad secret is sent on.
async fn target(ctx: &Ctx<'_>) -> Result<Target, Response> {
    match upstream::target(ctx.state, ctx.server_id).await {
        Ok(Some(target)) => Ok(target),
        Ok(None) | Err(TargetError::Secret) => Err(answer::unavailable(ctx.slug)),
        Err(TargetError::Db(err)) => {
            eprintln!("doorward: the server cannot be read: {err}");
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// True when `name` is in the server's catalog. A miss refreshes the catalog once; a failed refresh is a miss.
async fn listed(ctx: &Ctx<'_>, target: &Target, name: &str) -> Result<bool, Response> {
    let server = ctx.server_id;
    let names = match ctx
        .state
        .db
        .call(move |conn| catalog::names(conn, server))
        .await
    {
        Ok(names) => names,
        Err(err) => {
            eprintln!("doorward: the tool catalog cannot be read: {err}");
            return Err(bare(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };
    if names.iter().any(|known| known == name) {
        return Ok(true);
    }
    Ok(match catalog::refresh(ctx.state, target).await {
        Ok(fresh) => fresh.iter().any(|known| known == name),
        Err(_) => false,
    })
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
            eprintln!("doorward: the tool rules cannot be read: {err}");
            Err(bare(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// True when the caller's rules allow the tool `name` on this server.
async fn allowed(ctx: &Ctx<'_>, name: &str) -> Result<bool, Response> {
    let rules = rules_of(ctx).await?;
    Ok(policy::decide(&rules, ctx.caller.user_id, ctx.server_id, name).allowed)
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
        Err(Fault) => return fault(ctx, owed).await,
    };
    let method = message.method.as_deref().unwrap_or("");
    let rewritten = message.shape == Shape::Request
        && matches!(method, "initialize" | "server/discover" | "tools/list");
    if matches!(kind, Kind::Empty) {
        if message.shape == Shape::Request && matches!(status.as_u16(), 200 | 202) {
            return fault(ctx, owed).await;
        }
        if let Some(owed) = owed {
            owed.settle("error").await;
        }
        return relayed(status, None, Body::empty(), None);
    }
    if matches!(kind, Kind::Stream) && !rewritten {
        let watch = Watch {
            call: owed.as_ref().map(|owed| owed.tool.clone()),
            id: message.id.clone().unwrap_or(Value::Null),
        };
        if let Some(owed) = owed {
            owed.hand_over();
        }
        let body = stream::relay(ctx.owned(), response, watch);
        return relayed(status, Some("text/event-stream"), body, None);
    }
    let id = message.id.clone().unwrap_or(Value::Null);
    let (mut value, raw) = match read_answer(ctx, response, kind, &id).await {
        Ok(read) => read,
        Err(Fault) => return fault(ctx, owed).await,
    };
    if !rewritten {
        if let Some(owed) = owed {
            owed.settle(stream::outcome_of(&value)).await;
        }
        return relayed(
            status,
            Some("application/json"),
            Body::from(raw.unwrap_or_default()),
            None,
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
            Err(Fault) => return fault(ctx, owed).await,
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
    relayed(status, Some("application/json"), Body::from(body), session)
}

/// Reads an answer as a JSON object: a body under the cap, or the matching answer of a stream.
async fn read_answer(
    ctx: &Ctx<'_>,
    response: reqwest::Response,
    kind: Kind,
    id: &Value,
) -> Result<(Value, Option<Bytes>), Fault> {
    let cap = ctx.state.config.limits.tools_list_bytes;
    match kind {
        Kind::Stream => {
            let (answer, _) = catalog::stream_answer(ctx.state, response, cap, id)
                .await
                .map_err(|_| Fault)?;
            Ok((answer, None))
        }
        _ => {
            let bytes = upstream::body(ctx.state, response, cap).await?;
            let value = parse_strict(&bytes).map_err(|_| Fault)?;
            if !value.is_object() {
                return Err(Fault);
            }
            Ok((value, Some(bytes)))
        }
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
            };
            let body = stream::relay(ctx.owned(), response, watch);
            relayed(status, Some("text/event-stream"), body, None)
        }
        Ok(_) if status == StatusCode::METHOD_NOT_ALLOWED => {
            relayed(status, None, Body::empty(), None)
        }
        _ => answer::unavailable(ctx.slug),
    }
}

/// A DELETE answer: the JSON or stream as it is, with no upstream header.
async fn relay_plain(ctx: &Ctx<'_>, response: reqwest::Response) -> Response {
    let status = response.status();
    match upstream::accept(&response) {
        Err(Fault) => answer::unavailable(ctx.slug),
        Ok(Kind::Empty) => relayed(status, None, Body::empty(), None),
        Ok(Kind::Stream) => {
            let watch = Watch {
                call: None,
                id: Value::Null,
            };
            let body = stream::relay(ctx.owned(), response, watch);
            relayed(status, Some("text/event-stream"), body, None)
        }
        Ok(Kind::Json) => {
            let cap = ctx.state.config.limits.tools_list_bytes;
            match upstream::body(ctx.state, response, cap).await {
                Ok(bytes) if parse_strict(&bytes).is_ok_and(|value| value.is_object()) => {
                    relayed(status, Some("application/json"), Body::from(bytes), None)
                }
                _ => answer::unavailable(ctx.slug),
            }
        }
    }
}

/// The fault answer; a tools/call that faults is recorded as allowed and unavailable.
async fn fault(ctx: &Ctx<'_>, owed: Option<Owed>) -> Response {
    if let Some(owed) = owed {
        owed.settle("unavailable").await;
    }
    answer::unavailable(ctx.slug)
}

/// Removes the switched-off capabilities of an initialize or server/discover result; true when it changed.
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
    changed
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
    let tools = result.get("tools").and_then(Value::as_array).ok_or(Fault)?;
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
        eprintln!("doorward: the tool catalog cannot be stored: {err}");
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
            eprintln!("doorward: the upstream session cannot be recorded: {err}");
            None
        }
    }
}

/// One tool_call row. A failed write is reported and never changes the answer.
async fn record(ctx: &Ctx<'_>, tool: &str, decision: &str, outcome: &str) {
    stream::record(&ctx.owned(), tool, decision, outcome, "").await;
}

/// The detail of the row of a call whose client left before the answer.
const LEFT: &str = "the client left before the answer";

/// The activity row a tools/call owes once it went upstream. Dropped unsettled, because the client
/// left, it writes the row from its own task.
struct Owed {
    ctx: Option<Owned>,
    tool: String,
}

impl Owed {
    fn new(ctx: &Ctx<'_>, tool: &str) -> Owed {
        Owed {
            ctx: Some(ctx.owned()),
            tool: tool.to_owned(),
        }
    }

    /// Writes the row with `outcome` in its own task and waits for it, so a dropped waiter writes nothing more.
    async fn settle(mut self, outcome: &str) {
        let Some(owned) = self.ctx.take() else {
            return;
        };
        let tool = std::mem::take(&mut self.tool);
        let outcome = outcome.to_owned();
        let written = tokio::spawn(async move {
            stream::record(&owned, &tool, "allow", &outcome, "").await;
        });
        if let Err(err) = written.await {
            eprintln!("doorward: the activity row cannot be written: {err}");
        }
    }

    /// Gives the row to the stream relay, which writes it when the stream ends.
    fn hand_over(mut self) {
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
            Err(err) => eprintln!("doorward: the activity row cannot be written: {err}"),
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
