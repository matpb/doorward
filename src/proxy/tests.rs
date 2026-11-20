//! Upstream client and catalog tests, against small upstreams that each test starts on 127.0.0.1.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use axum::response::Response;
use futures_util::StreamExt;
use futures_util::stream;
use rusqlite::params;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::catalog::{self, RefreshError};
use super::upstream::{self, Fault, Kind, Outgoing, Target, TargetError};
use crate::app::AppState;
use crate::cimd::UnavailableCimd;
use crate::clock::SystemClock;
use crate::config::Config;
use crate::crypto::{Keys, PasswordHasher};
use crate::db::Db;
use crate::servers;

const UNAVAILABLE: &str = "The last refresh failed: the upstream did not answer with a tool list.";
const TOO_LARGE: &str = "The last refresh failed: the tool list is larger than the limit.";
const SECRET_NAME: &str = "x-upstream-secret";
const SECRET_VALUE: &str = "s3cret";

/// What a test upstream saw of one request.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    /// Lower-case names, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn rpc(&self) -> String {
        self.json()["method"].as_str().unwrap_or("").to_owned()
    }
}

/// How a test upstream answers one request.
pub enum Plan {
    Reply(Response),
    /// Answers after the wait.
    Late(Duration, Response),
    /// Never answers.
    Silent,
}

type Script = Arc<dyn Fn(&Seen) -> Plan + Send + Sync>;
type Answerer = Box<dyn Fn(&Seen) -> Plan + Send + Sync>;

#[derive(Clone)]
struct Shared {
    script: Script,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// An upstream on 127.0.0.1 that answers with its script and stops when dropped.
pub struct TestUpstream {
    pub url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: JoinHandle<()>,
}

impl TestUpstream {
    pub async fn start(script: impl Fn(&Seen) -> Plan + Send + Sync + 'static) -> TestUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let shared = Shared {
            script: Arc::new(script),
            seen: Arc::clone(&seen),
        };
        let app = Router::new().fallback(handle).with_state(shared);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        TestUpstream {
            url: format!("http://{address}/mcp"),
            seen,
            task,
        }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen requests").clone()
    }
}

impl Drop for TestUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(State(shared): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default();
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let seen = Seen {
        method: parts.method.as_str().to_owned(),
        headers,
        body: bytes,
    };
    shared
        .seen
        .lock()
        .expect("seen requests")
        .push(seen.clone());
    match (shared.script)(&seen) {
        Plan::Reply(response) => response,
        Plan::Late(wait, response) => {
            tokio::time::sleep(wait).await;
            response
        }
        Plan::Silent => std::future::pending().await,
    }
}

/// An answer with the given status, session id, content type and body.
pub fn answer(status: u16, session: Option<&str>, content_type: Option<&str>, body: &str) -> Plan {
    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    Plan::Reply(builder.body(Body::from(body.to_owned())).expect("response"))
}

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn tool(name: &str) -> Value {
    json!({"name": name, "inputSchema": {"type": "object"}})
}

/// A stateless upstream: answers tools/list in the stateless form with `tools`, and 400 otherwise.
fn stateless(tools: Vec<Value>) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    paged(vec![tools])
}

/// How a test upstream frames its JSON-RPC answers.
#[derive(Clone, Copy)]
enum Shape {
    Json,
    /// An event stream; `crlf` ends its lines with CRLF and `split` puts the answer over two data lines.
    Stream {
        crlf: bool,
        split: bool,
    },
}

/// The message as `shape` frames it, with the given status and session id.
fn reply(shape: Shape, status: u16, session: Option<&str>, message: &Value) -> Plan {
    match shape {
        Shape::Json => answer(
            status,
            session,
            Some("application/json"),
            &message.to_string(),
        ),
        Shape::Stream { crlf, split } => answer(
            status,
            session,
            Some("text/event-stream"),
            &as_stream(message, crlf, split),
        ),
    }
}

/// The message as an event stream: a comment, a notification event, then the message.
fn as_stream(message: &Value, crlf: bool, split: bool) -> String {
    let eol = if crlf { "\r\n" } else { "\n" };
    let notice = json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"level": "info", "data": "starting"}});
    let text = message.to_string();
    let data = match (split, text.find(',')) {
        (true, Some(comma)) => format!("data: {}{eol}data: {}", &text[..comma], &text[comma..]),
        _ => format!("data: {text}"),
    };
    format!(": keep-alive{eol}data: {notice}{eol}{eol}{data}{eol}{eol}")
}

/// An event stream that sends `events` and then stays open.
fn open_stream(events: String) -> Plan {
    let head =
        stream::iter(vec![Ok::<Bytes, io::Error>(Bytes::from(events))]).chain(stream::pending());
    Plan::Reply(
        Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(head))
            .expect("response"),
    )
}

/// Delays every answer of `script` by `wait`.
fn delayed(
    wait: Duration,
    script: impl Fn(&Seen) -> Plan + Send + Sync + 'static,
) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    move |seen: &Seen| match script(seen) {
        Plan::Reply(response) => Plan::Late(wait, response),
        other => other,
    }
}

/// A stateless upstream that pages its tool list; page k is asked with cursor `c{k}`.
fn paged(pages: Vec<Vec<Value>>) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    paged_as(pages, Shape::Json)
}

/// `paged`, with its answers framed as `shape`.
fn paged_as(
    pages: Vec<Vec<Value>>,
    shape: Shape,
) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    move |seen: &Seen| {
        if seen.header("mcp-protocol-version") != Some("2026-07-28") || seen.rpc() != "tools/list" {
            return answer(400, None, None, "");
        }
        let request = seen.json();
        let index = match request["params"]["cursor"].as_str() {
            None => 0,
            Some(cursor) => cursor
                .strip_prefix('c')
                .and_then(|number| number.parse::<usize>().ok())
                .unwrap_or(usize::MAX),
        };
        let Some(page) = pages.get(index) else {
            return answer(400, None, None, "");
        };
        let mut result = json!({"tools": page, "resultType": "complete"});
        if index + 1 < pages.len() {
            result["nextCursor"] = json!(format!("c{}", index + 1));
        }
        reply(shape, 200, None, &rpc_result(&request["id"], result))
    }
}

/// A session-style upstream: refuses the stateless form, issues session `s1` on initialize.
fn session_style(tools: Vec<Value>) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    session_style_as(tools, Shape::Json)
}

/// `session_style`, with its answers framed as `shape`.
fn session_style_as(
    tools: Vec<Value>,
    shape: Shape,
) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    move |seen: &Seen| {
        let request = seen.json();
        let id = request["id"].clone();
        if seen.method == "DELETE" {
            let status = if seen.header("mcp-session-id") == Some("s1") {
                200
            } else {
                404
            };
            return answer(status, None, None, "");
        }
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        match seen.rpc().as_str() {
            "initialize" => reply(
                shape,
                200,
                Some("s1"),
                &rpc_result(
                    &id,
                    json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
                ),
            ),
            _ if seen.header("mcp-session-id") != Some("s1") => answer(400, None, None, ""),
            "notifications/initialized" => answer(202, None, None, ""),
            "tools/list" => reply(
                shape,
                200,
                None,
                &rpc_result(&id, json!({"tools": tools.clone()})),
            ),
            _ => answer(404, None, None, ""),
        }
    }
}

/// An upstream that answers every request with the same status, type and body.
fn always(
    status: u16,
    content_type: Option<&'static str>,
    body: &'static str,
) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    move |_: &Seen| answer(status, None, content_type, body)
}

/// An upstream that answers every request with a JSON-RPC error.
fn rpc_error() -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    move |seen: &Seen| {
        let error = json!({"jsonrpc": "2.0", "id": seen.json()["id"].clone(),
            "error": {"code": -32601, "message": "Method not found"}});
        answer(200, None, Some("application/json"), &error.to_string())
    }
}

/// An upstream that answers the secret-protected probe with a result and refuses anything else.
fn gated(tools: Vec<Value>) -> impl Fn(&Seen) -> Plan + Send + Sync + 'static {
    let open = stateless(tools);
    move |seen: &Seen| {
        if seen.header(SECRET_NAME) == Some(SECRET_VALUE) {
            open(seen)
        } else {
            answer(401, None, None, "")
        }
    }
}

/// A port that nothing listens on.
async fn closed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    format!("http://127.0.0.1:{port}/mcp")
}

/// A gateway state in a temporary directory, with one server row.
pub struct Fixture {
    pub state: AppState,
    pub server_id: i64,
    _dir: tempfile::TempDir,
}

pub async fn fixture() -> Fixture {
    fixture_with(|_| {}).await
}

pub async fn fixture_with(edit: impl FnOnce(&mut Config)) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary directory");
    let mut config = Config {
        public_url: "http://localhost".to_owned(),
        listen: "127.0.0.1:0".parse().expect("address"),
        database: dir.path().join("doorward.db"),
        key_file: Some(dir.path().join("doorward.key")),
        trusted_proxies: Vec::new(),
        lifetimes: Default::default(),
        limits: Default::default(),
        mail: Default::default(),
    };
    edit(&mut config);
    let db = Db::open(&config.database).expect("database");
    let keys = Keys::load(&config, None).expect("keys");
    let hasher = PasswordHasher::new().await.expect("hasher");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("http client");
    let state = AppState {
        config,
        db,
        clock: Arc::new(SystemClock),
        cimd: Arc::new(UnavailableCimd),
        keys: Arc::new(keys),
        hasher: Arc::new(hasher),
        setup_code: None,
        http,
        reset_requests: Arc::new(Semaphore::new(1)),
    };
    let server_id = state
        .db
        .call(|conn| {
            conn.execute(
                "INSERT INTO servers (name, slug, upstream_url, created_at) \
                 VALUES ('demo', 'demo', 'http://127.0.0.1:9/mcp', 0)",
                [],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .expect("server row");
    Fixture {
        state,
        server_id,
        _dir: dir,
    }
}

fn target_at(fixture: &Fixture, url: &str) -> Target {
    Target {
        server_id: fixture.server_id,
        slug: "demo".to_owned(),
        url: url.to_owned(),
        secret: None,
    }
}

fn secret_target_at(fixture: &Fixture, url: &str) -> Target {
    Target {
        secret: Some((
            HeaderName::from_static(SECRET_NAME),
            HeaderValue::from_static(SECRET_VALUE),
        )),
        ..target_at(fixture, url)
    }
}

fn post(headers: HeaderMap, body: &str) -> Outgoing {
    Outgoing {
        method: Method::POST,
        headers,
        body: Bytes::from(body.to_owned()),
        with_secret: true,
    }
}

async fn names(state: &AppState, server_id: i64) -> Vec<String> {
    state
        .db
        .call(move |conn| catalog::names(conn, server_id))
        .await
        .expect("catalog names")
}

async fn catalog_error(state: &AppState, server_id: i64) -> Option<String> {
    state
        .db
        .call(move |conn| {
            conn.query_row(
                "SELECT catalog_error FROM servers WHERE id = ?1",
                params![server_id],
                |row| row.get(0),
            )
        })
        .await
        .expect("catalog error")
}

/// The tool names of the `tool_appeared` activity rows, oldest first.
async fn appeared(state: &AppState) -> Vec<String> {
    state
        .db
        .call(|conn| {
            let mut statement =
                conn.prepare("SELECT tool FROM activity WHERE kind = 'tool_appeared' ORDER BY id")?;
            let rows = statement.query_map([], |row| row.get(0))?;
            rows.collect()
        })
        .await
        .expect("activity rows")
}

async fn store_secret(fixture: &Fixture, value: &str) {
    let sealed = servers::seal(&fixture.state.keys, fixture.server_id, value).expect("seal");
    let id = fixture.server_id;
    fixture
        .state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET secret_header_name = ?1, secret_header_value = ?2 \
                 WHERE id = ?3",
                params![SECRET_NAME, sealed, id],
            )
        })
        .await
        .expect("store the secret");
}

async fn set_url(fixture: &Fixture, url: &str) {
    let url = url.to_owned();
    let id = fixture.server_id;
    fixture
        .state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
                params![url, id],
            )
        })
        .await
        .expect("set the address");
}

#[tokio::test(flavor = "multi_thread")]
async fn send_sends_the_secret_and_only_the_headers_it_is_given() {
    let up = TestUpstream::start(|_| answer(200, None, Some("application/json"), "{}")).await;
    let fixture = fixture().await;
    let target = secret_target_at(&fixture, &up.url);
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        HeaderName::from_static("x-extra"),
        HeaderValue::from_static("yes"),
    );
    let response = upstream::send(&fixture.state, &target, post(headers, "{}"))
        .await
        .expect("the upstream answers");
    assert_eq!(response.status().as_u16(), 200);
    let seen = up.seen();
    let request = seen.first().expect("one request");
    assert_eq!(request.header(SECRET_NAME), Some(SECRET_VALUE));
    assert_eq!(
        request.header("user-agent"),
        Some(concat!("doorward/", env!("CARGO_PKG_VERSION")))
    );
    assert_eq!(request.header("x-extra"), Some("yes"));
    assert_eq!(request.header("accept"), Some("application/json"));
    assert!(request.header("authorization").is_none());
    assert!(request.header("cookie").is_none());
    let allowed = [
        "host",
        "content-length",
        "accept",
        "user-agent",
        SECRET_NAME,
        "x-extra",
    ];
    for (name, _) in &request.headers {
        assert!(
            allowed.contains(&name.as_str()),
            "{name} is not a header the gateway sends"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn send_without_the_secret_leaves_the_secret_header_out() {
    let up = TestUpstream::start(|_| answer(200, None, Some("application/json"), "{}")).await;
    let fixture = fixture().await;
    let target = secret_target_at(&fixture, &up.url);
    upstream::send(&fixture.state, &target, {
        let mut outgoing = post(HeaderMap::new(), "{}");
        outgoing.with_secret = false;
        outgoing
    })
    .await
    .expect("the upstream answers");
    let seen = up.seen();
    let request = seen.first().expect("one request");
    assert!(
        request.header(SECRET_NAME).is_none(),
        "the probe must carry no secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_secret_becomes_the_header_of_the_target() {
    let fixture = fixture().await;
    store_secret(&fixture, SECRET_VALUE).await;
    let found = upstream::target(&fixture.state, fixture.server_id)
        .await
        .expect("the target loads")
        .expect("the server exists");
    let (name, value) = found.secret.expect("the secret is opened");
    assert_eq!(name.as_str(), SECRET_NAME);
    assert_eq!(value.to_str().ok(), Some(SECRET_VALUE));
    assert_eq!(found.slug, "demo");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_that_cannot_be_opened_is_refused_and_nothing_is_sent() {
    let up = TestUpstream::start(|_| answer(200, None, Some("application/json"), "{}")).await;
    let fixture = fixture().await;
    store_secret(&fixture, SECRET_VALUE).await;
    set_url(&fixture, &up.url).await;
    let id = fixture.server_id;
    fixture
        .state
        .db
        .call(move |conn| {
            let sealed: String = conn.query_row(
                "SELECT secret_header_value FROM servers WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )?;
            let mut bytes = sealed.into_bytes();
            let index = bytes.len() - 5;
            bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
            let changed = String::from_utf8(bytes).unwrap_or_default();
            conn.execute(
                "UPDATE servers SET secret_header_value = ?1 WHERE id = ?2",
                params![changed, id],
            )
        })
        .await
        .expect("tamper with the sealed text");
    let refused = upstream::target(&fixture.state, fixture.server_id).await;
    assert!(
        matches!(refused, Err(TargetError::Secret)),
        "a secret that cannot be opened must be refused"
    );
    assert!(up.seen().is_empty(), "no request may reach the upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_server_has_no_target() {
    let fixture = fixture().await;
    let found = upstream::target(&fixture.state, fixture.server_id + 100)
        .await
        .expect("the lookup works");
    assert!(found.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_port_is_a_fault() {
    let fixture = fixture().await;
    let url = closed_url().await;
    let result = upstream::send(
        &fixture.state,
        &target_at(&fixture, &url),
        post(HeaderMap::new(), "{}"),
    )
    .await;
    assert!(matches!(result, Err(Fault)), "a closed port is a fault");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_never_answers_is_a_fault_in_time() {
    let up = TestUpstream::start(|_| Plan::Silent).await;
    let fixture = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let started = Instant::now();
    let result = upstream::send(
        &fixture.state,
        &target_at(&fixture, &up.url),
        post(HeaderMap::new(), "{}"),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(Fault)), "silence is a fault");
    assert!(
        elapsed >= Duration::from_secs(1),
        "the limit of one second must be waited out, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the fault must come within the limit plus a margin, took {elapsed:?}"
    );
}

/// Each row: status, content type, body, and the kind `accept` must give.
const CASES: &[(u16, Option<&str>, &str, &str)] = &[
    (200, Some("application/json"), "{}", "json"),
    (200, Some("application/json; charset=utf-8"), "{}", "json"),
    (200, Some("text/event-stream"), "data: {}\n\n", "stream"),
    (202, None, "", "empty"),
    (400, Some("application/json"), "{}", "json"),
    (404, Some("application/json"), "{}", "json"),
    (405, Some("application/json"), "{}", "json"),
    (200, Some("text/html"), "<script>1</script>", "fault"),
    (301, None, "", "fault"),
    (302, None, "", "fault"),
    (401, Some("application/json"), "{}", "fault"),
    (403, Some("application/json"), "{}", "fault"),
    (500, Some("application/json"), "{}", "fault"),
    (503, Some("application/json"), "{}", "fault"),
    (204, None, "", "fault"),
    (200, None, "hello", "fault"),
    (200, None, "", "empty"),
    (418, Some("application/json"), "{}", "fault"),
];

#[tokio::test(flavor = "multi_thread")]
async fn accept_relays_json_and_streams_and_refuses_the_rest() {
    let up = TestUpstream::start(|seen| {
        let case = seen.json()["case"].as_u64().unwrap_or(0) as usize;
        match CASES.get(case) {
            Some((status, content_type, body, _)) => answer(*status, None, *content_type, body),
            None => answer(500, None, None, ""),
        }
    })
    .await;
    let fixture = fixture().await;
    let target = target_at(&fixture, &up.url);
    for (index, (status, _, _, expected)) in CASES.iter().enumerate() {
        let outgoing = post(HeaderMap::new(), &format!(r#"{{"case":{index}}}"#));
        let response = upstream::send(&fixture.state, &target, outgoing)
            .await
            .expect("the upstream answers");
        let label = match upstream::accept(&response) {
            Ok(Kind::Json) => "json",
            Ok(Kind::Stream) => "stream",
            Ok(Kind::Empty) => "empty",
            Err(_) => "fault",
        };
        assert_eq!(
            label, *expected,
            "status {status} of case {index} must be accepted as {expected}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn body_refuses_what_passes_the_cap_and_keeps_what_fits() {
    let up = sized_upstream().await;
    let fixture = fixture().await;
    let target = target_at(&fixture, &up.url);
    for (size, cap, expect_ok) in [(101, 100, false), (100, 100, true)] {
        let response = upstream::send(
            &fixture.state,
            &target,
            post(HeaderMap::new(), &format!(r#"{{"size":{size}}}"#)),
        )
        .await
        .expect("headers arrive");
        let read = upstream::body(&fixture.state, response, cap).await;
        if expect_ok {
            let bytes = read.expect("a body that fits is read");
            assert_eq!(bytes.len(), size);
        } else {
            assert!(
                matches!(read, Err(Fault)),
                "{size} bytes pass a cap of {cap}"
            );
        }
    }
}

/// An upstream that answers with a body of the `size` the request asks for.
async fn sized_upstream() -> TestUpstream {
    TestUpstream::start(|seen| {
        let size = seen.json()["size"].as_u64().unwrap_or(0) as usize;
        answer(200, None, Some("application/json"), &"x".repeat(size))
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_stalls_is_a_fault_after_the_time_limit() {
    let up = TestUpstream::start(|_| {
        let head = stream::iter(vec![Ok::<Bytes, io::Error>(Bytes::from_static(b"{"))])
            .chain(stream::pending());
        Plan::Reply(
            Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from_stream(head))
                .expect("response"),
        )
    })
    .await;
    let fixture = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let response = upstream::send(
        &fixture.state,
        &target_at(&fixture, &up.url),
        post(HeaderMap::new(), "{}"),
    )
    .await
    .expect("headers arrive");
    let started = Instant::now();
    let read = upstream::body(&fixture.state, response, 1000).await;
    assert!(matches!(read, Err(Fault)), "a stalled body is a fault");
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_upstream_gives_its_tools_in_its_own_order() {
    let up = TestUpstream::start(stateless(vec![tool("beta"), tool("alpha")])).await;
    let fixture = fixture().await;
    let names_seen = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert_eq!(names_seen, vec!["beta", "alpha"]);
    assert_eq!(names(&fixture.state, fixture.server_id).await, names_seen);
    assert_eq!(up.seen().len(), 1, "a stateless upstream needs one request");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_upstream_is_initialized_listed_and_closed_with_the_secret() {
    let up = TestUpstream::start(session_style(vec![tool("alpha")])).await;
    let fixture = fixture().await;
    let names_seen = catalog::refresh(&fixture.state, &secret_target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert_eq!(names_seen, vec!["alpha"]);
    let seen = up.seen();
    let rpc: Vec<String> = seen
        .iter()
        .map(|request| format!("{} {}", request.method, request.rpc()))
        .collect();
    assert_eq!(
        rpc,
        vec![
            "POST tools/list",
            "POST initialize",
            "POST notifications/initialized",
            "POST tools/list",
            "DELETE ",
        ],
        "stateless form, then initialize, the notification, the list and the DELETE"
    );
    assert!(seen[1].header("mcp-session-id").is_none());
    for request in &seen[2..] {
        assert_eq!(
            request.header("mcp-session-id"),
            Some("s1"),
            "{} must carry the issued session",
            request.method
        );
    }
    for request in &seen {
        assert_eq!(
            request.header(SECRET_NAME),
            Some(SECRET_VALUE),
            "every request of the sequence must carry the secret"
        );
        assert!(request.header("authorization").is_none());
        assert!(request.header("cookie").is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_pages_are_stored_whole() {
    let up = TestUpstream::start(paged(vec![
        vec![tool("a"), tool("b")],
        vec![tool("c"), tool("d")],
        vec![tool("e")],
    ]))
    .await;
    let fixture = fixture().await;
    let names_seen = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert_eq!(names_seen, vec!["a", "b", "c", "d", "e"]);
    assert_eq!(up.seen().len(), 3, "one request per page");
}

#[tokio::test(flavor = "multi_thread")]
async fn more_than_twenty_pages_is_too_large_and_keeps_the_catalog() {
    let fixture = fixture().await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let pages: Vec<Vec<Value>> = (0..25)
        .map(|index| vec![tool(&format!("t{index}"))])
        .collect();
    let up = TestUpstream::start(paged(pages)).await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::TooLarge));
    assert_eq!(up.seen().len(), 20, "at most 20 pages are asked for");
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
    assert_eq!(
        catalog_error(&fixture.state, fixture.server_id)
            .await
            .as_deref(),
        Some(TOO_LARGE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn more_than_the_byte_limit_in_total_is_too_large_and_keeps_the_catalog() {
    let fixture = fixture_with(|config| config.limits.tools_list_bytes = 500).await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let long = "n".repeat(200);
    let up = TestUpstream::start(paged(vec![
        vec![tool(&format!("{long}1"))],
        vec![tool(&format!("{long}2"))],
        vec![tool(&format!("{long}3"))],
    ]))
    .await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::TooLarge));
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_fetch_keeps_the_catalog_and_a_later_success_clears_the_error() {
    let fixture = fixture().await;
    let good = TestUpstream::start(stateless(vec![tool("alpha"), tool("beta")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &good.url))
        .await
        .expect("the first refresh");
    let down = closed_url().await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &down)).await;
    assert_eq!(result, Err(RefreshError::Unavailable), "a stopped upstream");
    assert_eq!(
        names(&fixture.state, fixture.server_id).await,
        vec!["alpha", "beta"]
    );
    assert_eq!(
        catalog_error(&fixture.state, fixture.server_id)
            .await
            .as_deref(),
        Some(UNAVAILABLE)
    );
    let answers: Vec<(&str, Answerer)> = vec![
        ("unauthorized", Box::new(always(401, None, ""))),
        (
            "garbage",
            Box::new(always(200, Some("application/json"), "not json at all")),
        ),
        ("json-rpc error", Box::new(rpc_error())),
        (
            "wrong type",
            Box::new(always(200, Some("text/html"), "<p>x</p>")),
        ),
    ];
    for (what, script) in answers {
        let up = TestUpstream::start(script).await;
        let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
        assert_eq!(result, Err(RefreshError::Unavailable), "{what}");
        assert_eq!(
            names(&fixture.state, fixture.server_id).await,
            vec!["alpha", "beta"],
            "{what} keeps the catalog"
        );
    }
    let later = catalog::refresh(&fixture.state, &target_at(&fixture, &good.url)).await;
    assert!(later.is_ok());
    assert_eq!(catalog_error(&fixture.state, fixture.server_id).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn replace_leaves_out_bad_names_and_keeps_the_upstream_order() {
    let fixture = fixture().await;
    let id = fixture.server_id;
    let edge = "e".repeat(128);
    let tools = vec![
        json!({"name": "keep1"}),
        json!({"name": 5}),
        json!({"description": "no name"}),
        json!({"name": "n".repeat(129)}),
        json!({"name": ""}),
        json!({"name": "keep2"}),
        json!({"name": "keep1", "description": "second"}),
        json!({"name": edge}),
    ];
    let added = fixture
        .state
        .db
        .call(move |conn| catalog::replace(conn, id, &tools, 10))
        .await
        .expect("replace");
    assert_eq!(added, vec!["keep1", "keep2", edge.as_str()]);
    assert_eq!(
        names(&fixture.state, id).await,
        vec!["keep1", "keep2", edge.as_str()]
    );
    let stored: String = fixture
        .state
        .db
        .call(move |conn| {
            conn.query_row(
                "SELECT definition FROM tool_catalog WHERE server_id = ?1 AND name = 'keep1'",
                params![id],
                |row| row.get(0),
            )
        })
        .await
        .expect("the definition");
    assert_eq!(
        stored, r#"{"name":"keep1"}"#,
        "the first of two equal names is kept"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_refresh_writes_no_tool_appeared_rows() {
    let fixture = fixture().await;
    let up = TestUpstream::start(stateless(vec![tool("alpha")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert!(appeared(&fixture.state).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_name_on_a_later_refresh_writes_one_row() {
    let fixture = fixture().await;
    let first = TestUpstream::start(stateless(vec![tool("alpha"), tool("beta")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &first.url))
        .await
        .expect("the first refresh");
    let second = TestUpstream::start(stateless(vec![tool("alpha"), tool("gamma")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &second.url))
        .await
        .expect("the second refresh");
    assert_eq!(appeared(&fixture.state).await, vec!["gamma"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn at_most_fifty_tool_appeared_rows_are_written_per_refresh() {
    let fixture = fixture().await;
    let first = TestUpstream::start(stateless(vec![tool("t0")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &first.url))
        .await
        .expect("the first refresh");
    let many: Vec<Value> = (0..=60).map(|index| tool(&format!("t{index}"))).collect();
    let second = TestUpstream::start(stateless(many)).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &second.url))
        .await
        .expect("the second refresh");
    assert_eq!(appeared(&fixture.state).await.len(), 50);
}

#[tokio::test(flavor = "multi_thread")]
async fn lockdown_reads_a_refusal_as_ok_a_result_as_open_and_silence_as_unknown() {
    let fixture = fixture().await;
    let refused = TestUpstream::start(gated(vec![tool("a")])).await;
    let verdict =
        catalog::lockdown(&fixture.state, &secret_target_at(&fixture, &refused.url)).await;
    assert_eq!(verdict, "ok", "a refusal without the secret is ok");
    assert!(
        refused
            .seen()
            .iter()
            .all(|request| request.header(SECRET_NAME).is_none()),
        "the probe must never carry the secret"
    );
    let open = TestUpstream::start(stateless(vec![tool("a")])).await;
    let verdict = catalog::lockdown(&fixture.state, &secret_target_at(&fixture, &open.url)).await;
    assert_eq!(verdict, "open");
    assert!(
        open.seen()
            .iter()
            .all(|request| request.header(SECRET_NAME).is_none())
    );
    let down = closed_url().await;
    let verdict = catalog::lockdown(&fixture.state, &target_at(&fixture, &down)).await;
    assert_eq!(verdict, "unknown");
    let broken = TestUpstream::start(always(500, None, "")).await;
    let verdict = catalog::lockdown(&fixture.state, &target_at(&fixture, &broken.url)).await;
    assert_eq!(verdict, "unknown");
}

#[tokio::test(flavor = "multi_thread")]
async fn lockdown_of_a_session_only_upstream_is_open_and_closes_its_probe_session() {
    let fixture = fixture().await;
    let up = TestUpstream::start(session_style(vec![tool("a")])).await;
    let verdict = catalog::lockdown(&fixture.state, &secret_target_at(&fixture, &up.url)).await;
    assert_eq!(verdict, "open");
    let seen = up.seen();
    let rpc: Vec<String> = seen
        .iter()
        .map(|request| format!("{} {}", request.method, request.rpc()))
        .collect();
    assert_eq!(rpc, vec!["POST tools/list", "POST initialize", "DELETE "]);
    assert_eq!(seen[2].header("mcp-session-id"), Some("s1"));
    assert!(
        seen.iter()
            .all(|request| request.header(SECRET_NAME).is_none()),
        "the probe never carries the secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_lockdown_probe_carries_the_secret_of_a_target_that_has_one() {
    let fixture = fixture().await;
    let cases: Vec<(&str, Answerer, &str)> = vec![
        (
            "session only",
            Box::new(session_style(vec![tool("a")])),
            "open",
        ),
        (
            "refused at both forms",
            Box::new(|seen: &Seen| {
                answer(
                    if seen.rpc() == "initialize" { 401 } else { 400 },
                    None,
                    None,
                    "",
                )
            }),
            "ok",
        ),
        (
            "stateless open",
            Box::new(stateless(vec![tool("a")])),
            "open",
        ),
        (
            "refused with the secret",
            Box::new(gated(vec![tool("a")])),
            "ok",
        ),
        ("broken", Box::new(always(500, None, "")), "unknown"),
    ];
    for (what, script, verdict) in cases {
        let up = TestUpstream::start(script).await;
        let found = catalog::lockdown(&fixture.state, &secret_target_at(&fixture, &up.url)).await;
        assert_eq!(found, verdict, "{what}");
        assert!(
            up.seen()
                .iter()
                .all(|request| request.header(SECRET_NAME).is_none()),
            "{what}: the probe never carries the secret"
        );
    }
    let down = closed_url().await;
    let found = catalog::lockdown(&fixture.state, &secret_target_at(&fixture, &down)).await;
    assert_eq!(found, "unknown", "a stopped upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_upstream_answering_event_streams_is_stored() {
    let framings = [(false, false), (true, false), (false, true)];
    for (crlf, split) in framings {
        let up = TestUpstream::start(session_style_as(
            vec![tool("alpha")],
            Shape::Stream { crlf, split },
        ))
        .await;
        let fixture = fixture().await;
        let names_seen = catalog::refresh(&fixture.state, &secret_target_at(&fixture, &up.url))
            .await
            .expect("the refresh");
        assert_eq!(names_seen, vec!["alpha"], "crlf {crlf}, split {split}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_upstream_answering_an_event_stream_is_stored() {
    let fixture = fixture().await;
    let up = TestUpstream::start(paged_as(
        vec![vec![tool("s1"), tool("s2")]],
        Shape::Stream {
            crlf: true,
            split: true,
        },
    ))
    .await;
    let names_seen = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert_eq!(names_seen, vec!["s1", "s2"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_stays_open_after_a_notification_is_unavailable_in_time() {
    let fixture = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let notice = json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"data": "starting"}});
    let events = format!(": keep-alive\ndata: {notice}\n\n");
    let up = TestUpstream::start(move |_| open_stream(events.clone())).await;
    let started = Instant::now();
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the time limit ends the wait"
    );
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
    assert_eq!(
        catalog_error(&fixture.state, fixture.server_id)
            .await
            .as_deref(),
        Some(UNAVAILABLE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_larger_than_the_byte_limit_before_its_answer_is_too_large() {
    let fixture = fixture_with(|config| config.limits.tools_list_bytes = 500).await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let notice = json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"data": "x".repeat(1000)}});
    let body = format!("data: {notice}\n\n");
    let up =
        TestUpstream::start(move |_| answer(200, None, Some("text/event-stream"), &body)).await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::TooLarge));
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
    assert_eq!(
        catalog_error(&fixture.state, fixture.server_id)
            .await
            .as_deref(),
        Some(TOO_LARGE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_whose_answer_is_an_error_is_unavailable() {
    let fixture = fixture().await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let up = TestUpstream::start(always(
        200,
        Some("text/event-stream"),
        "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}\n\n",
    ))
    .await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::Unavailable));
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
}

#[test]
fn sse_splitter_reads_lf_and_crlf_events() {
    let text = "data: {\"a\":1}\n\ndata: {\"b\":2}\r\n\r\n";
    let (events, used) = catalog::sse_events(text.as_bytes());
    assert_eq!(events, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
    assert_eq!(used, text.len());
}

#[test]
fn sse_splitter_skips_comments_and_other_fields() {
    let text = ": hello\nevent: message\nid: 7\nretry: 5\ndata: x\n\n";
    let (events, used) = catalog::sse_events(text.as_bytes());
    assert_eq!(events, vec![b"x".to_vec()]);
    assert_eq!(used, text.len());
}

#[test]
fn sse_splitter_joins_data_lines_and_drops_one_space() {
    let (events, _) = catalog::sse_events(b"data: a\ndata:b\n\n");
    assert_eq!(events, vec![b"a\nb".to_vec()]);
    let (events, _) = catalog::sse_events(b"data:  a\n\n");
    assert_eq!(events, vec![b" a".to_vec()], "only one space is dropped");
}

#[test]
fn sse_splitter_keeps_an_open_event_for_later() {
    let first = "data: {\"a\":1}\n\n";
    let text = format!("{first}data: {{\"b\"");
    let (events, used) = catalog::sse_events(text.as_bytes());
    assert_eq!(events, vec![b"{\"a\":1}".to_vec()]);
    assert_eq!(used, first.len());
    for unfinished in ["data: {\"a\":1}", "data: {\"a\":1}\n"] {
        let (events, used) = catalog::sse_events(unfinished.as_bytes());
        assert!(events.is_empty(), "{unfinished:?} has no blank line");
        assert_eq!(used, 0);
    }
}

#[test]
fn sse_splitter_emits_nothing_for_empty_input_or_events_without_data() {
    assert_eq!(catalog::sse_events(b""), (Vec::new(), 0));
    let (events, used) = catalog::sse_events(b"event: ping\n\n");
    assert!(events.is_empty());
    assert_eq!(used, "event: ping\n\n".len());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_that_runs_past_one_time_limit_is_unavailable_and_keeps_the_catalog() {
    let fixture = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let pages: Vec<Vec<Value>> = (0..6)
        .map(|index| vec![tool(&format!("p{index}"))])
        .collect();
    let up = TestUpstream::start(delayed(Duration::from_millis(300), paged(pages.clone()))).await;
    let started = Instant::now();
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "one limit covers all the pages"
    );
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
    assert_eq!(
        catalog_error(&fixture.state, fixture.server_id)
            .await
            .as_deref(),
        Some(UNAVAILABLE)
    );
    let patient = self::fixture().await;
    let slow = TestUpstream::start(delayed(Duration::from_millis(300), paged(pages))).await;
    let all = catalog::refresh(&patient.state, &target_at(&patient, &slow.url))
        .await
        .expect("the same upstream fits a longer limit");
    assert_eq!(all, vec!["p0", "p1", "p2", "p3", "p4", "p5"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn send_hands_back_a_redirect_and_does_not_follow_it() {
    let second = TestUpstream::start(|_| answer(200, None, Some("application/json"), "{}")).await;
    let location = second.url.clone();
    let first = TestUpstream::start(move |_| {
        Plan::Reply(
            Response::builder()
                .status(302)
                .header(header::LOCATION, location.as_str())
                .body(Body::empty())
                .expect("response"),
        )
    })
    .await;
    let fixture = fixture().await;
    let response = upstream::send(
        &fixture.state,
        &target_at(&fixture, &first.url),
        post(HeaderMap::new(), "{}"),
    )
    .await
    .expect("the upstream answers");
    assert_eq!(response.status().as_u16(), 302);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(second.url.as_str())
    );
    assert!(second.seen().is_empty(), "the redirect is not followed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_result_for_another_id_is_not_the_tool_list() {
    let fixture = fixture().await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let up = TestUpstream::start(|seen: &Seen| {
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            let listed = rpc_result(&json!(7), json!({"tools": [tool("wrong")]}));
            answer(200, None, Some("application/json"), &listed.to_string())
        } else {
            answer(400, None, None, "")
        }
    })
    .await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::Unavailable));
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
    assert_eq!(
        catalog_error(&fixture.state, fixture.server_id)
            .await
            .as_deref(),
        Some(UNAVAILABLE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stream_answer_taken_is_the_one_to_request_one() {
    let fixture = fixture().await;
    let body = format!(
        "data: {}\n\ndata: {}\n\n",
        rpc_result(&json!(2), json!({"tools": [tool("wrong")]})),
        rpc_result(&json!(1), json!({"tools": [tool("right")]})),
    );
    let up = TestUpstream::start(move |seen: &Seen| {
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            answer(200, None, Some("text/event-stream"), &body)
        } else {
            answer(400, None, None, "")
        }
    })
    .await;
    let names_seen = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert_eq!(names_seen, vec!["right"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_403_is_a_refusal_at_either_form() {
    let fixture = fixture().await;
    let forbidden = TestUpstream::start(always(403, None, "")).await;
    let verdict = catalog::lockdown(&fixture.state, &target_at(&fixture, &forbidden.url)).await;
    assert_eq!(verdict, "ok", "403 to the stateless form");
    let session = TestUpstream::start(|seen: &Seen| {
        answer(
            if seen.rpc() == "initialize" { 403 } else { 400 },
            None,
            None,
            "",
        )
    })
    .await;
    let verdict = catalog::lockdown(&fixture.state, &target_at(&fixture, &session.url)).await;
    assert_eq!(verdict, "ok", "403 to initialize");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_later_page_does_not_start_the_session_form() {
    let fixture = fixture().await;
    let previous = TestUpstream::start(stateless(vec![tool("old")])).await;
    catalog::refresh(&fixture.state, &target_at(&fixture, &previous.url))
        .await
        .expect("the first refresh");
    let up = TestUpstream::start(|seen: &Seen| {
        if seen.header("mcp-protocol-version") != Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        match seen.json()["params"]["cursor"].as_str() {
            None => {
                let id = seen.json()["id"].clone();
                let page = json!({"tools": [tool("a")], "nextCursor": "c1"});
                answer(
                    200,
                    None,
                    Some("application/json"),
                    &rpc_result(&id, page).to_string(),
                )
            }
            Some(_) => answer(500, None, None, ""),
        }
    })
    .await;
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::Unavailable));
    assert_eq!(names(&fixture.state, fixture.server_id).await, vec!["old"]);
    assert!(
        up.seen()
            .iter()
            .all(|request| request.rpc() != "initialize"),
        "a session is not tried after a first page succeeded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_answers_and_stays_open_is_read_only_until_the_answer() {
    let fixture = fixture_with(|config| config.limits.upstream_timeout_seconds = 5).await;
    let listed = rpc_result(&json!(1), json!({"tools": [tool("alpha")]}));
    let events = format!("data: {listed}\n\n");
    let up = TestUpstream::start(move |seen: &Seen| {
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            open_stream(events.clone())
        } else {
            answer(400, None, None, "")
        }
    })
    .await;
    let started = Instant::now();
    let names_seen = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url))
        .await
        .expect("the refresh");
    assert_eq!(names_seen, vec!["alpha"]);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the answer ends the wait"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_error_answer_in_a_stream_ends_the_wait() {
    let fixture = fixture_with(|config| config.limits.upstream_timeout_seconds = 5).await;
    let refused = json!({"jsonrpc": "2.0", "id": 1,
        "error": {"code": -32601, "message": "Method not found"}});
    let events = format!("data: {refused}\n\n");
    let up = TestUpstream::start(move |seen: &Seen| {
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            open_stream(events.clone())
        } else {
            answer(400, None, None, "")
        }
    })
    .await;
    let started = Instant::now();
    let result = catalog::refresh(&fixture.state, &target_at(&fixture, &up.url)).await;
    assert_eq!(result, Err(RefreshError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the error answer ends the wait"
    );
}
