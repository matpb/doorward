use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use base64::Engine as _;
use futures_util::StreamExt;
use futures_util::stream;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

const STATELESS_VERSION: &str = "2026-07-28";
const SESSION_VERSIONS: [&str; 3] = ["2025-03-26", "2025-06-18", "2025-11-25"];
const DEFAULT_SESSION_VERSION: &str = "2025-11-25";
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const SESSION_METHODS: [&str; 8] = [
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
];
const STATELESS_METHODS: [&str; 7] = [
    "server/discover",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
];
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// The params key that carries the echoed header value from the request to `call_result`.
const ECHO_KEY: &str = "__echo_header";

type Chunk = Result<Bytes, io::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    Session,
    Stateless,
    Both,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Normal,
    /// tools/call answers as SSE: `steps` progress notifications `interval_ms` apart, then the result.
    Progress {
        steps: u32,
        interval_ms: u64,
    },
    /// tools/call is accepted and never answered; every other method is normal.
    Hang,
    /// tools/call answers as SSE: first a request to the client, then, 100 ms later, the result.
    ServerRequest,
    /// Every POST answers 200 application/json with the body `not json at all`.
    Garbage,
    /// Notifications are answered 202 with `text/plain; charset=UTF-8` and an empty body, as the TypeScript SDK does.
    #[allow(dead_code)]
    TypeScriptNotices,
    /// initialize and server/discover declare listChanged and subscribe in their capabilities.
    #[allow(dead_code)]
    DeclaresFlags,
    /// tools/call answers 400 application/json with a JSON-RPC error -32021 that carries data.
    #[allow(dead_code)]
    RefusesCalls,
    /// Every request answers 307 with this Location.
    Redirect(String),
    /// tools/call answers "called: <tool> <value>", the value being the request header named here, or empty.
    #[allow(dead_code)]
    EchoHeader(String),
    /// Normal, plus `Set-Cookie: upstream=1; Path=/` and `WWW-Authenticate: Basic realm="up"` on every response.
    SetCookie,
    /// Every POST answers 200 `text/html` with the body `<script>alert(1)</script>`.
    WrongContentType,
    /// Tool names match case-insensitively after trimming whitespace and removing U+200B, U+200C, U+200D, U+FEFF.
    LenientNames,
    /// JSON-RPC method names match case-insensitively.
    LenientMethods,
    /// Session style only: every `initialize` returns the session id `fixed-session`.
    ReuseSessionId,
    /// initialize and server/discover declare a tasks capability next to the usual ones.
    #[allow(dead_code)]
    DeclaresTasks,
    /// tools/call answers 200 application/json after `millis` milliseconds.
    #[allow(dead_code)]
    Delayed {
        millis: u64,
    },
    /// tools/call answers 200 application/json whose text is `bytes` characters long.
    #[allow(dead_code)]
    Oversized {
        bytes: usize,
    },
    /// tools/call answers with `isError` true.
    #[allow(dead_code)]
    ToolErrors,
    /// tools/list answers 200 application/json after `millis` milliseconds.
    #[allow(dead_code)]
    SlowListing {
        millis: u64,
    },
    /// tools/list is accepted and never answered; every other method is normal.
    #[allow(dead_code)]
    HangListing,
    /// Every tool's input schema carries an x-mcp-header key.
    #[allow(dead_code)]
    HeaderKeyed,
    /// initialize and server/discover declare a completions capability.
    #[allow(dead_code)]
    DeclaresCompletions,
    /// tools/call answers 200 application/json of about `bytes` bytes: the first half is sent, then the
    /// rest waits until `FakeUpstream::release`.
    #[allow(dead_code)]
    HeldAnswer {
        bytes: usize,
    },
    /// tools/call answers 200 text/event-stream with one event of about `bytes` bytes: its first 4096
    /// bytes are sent, then the rest waits until `FakeUpstream::release`.
    #[allow(dead_code)]
    HeldStream {
        bytes: usize,
    },
}

/// The bytes a held stream sends before it waits.
const HELD_STREAM_HEAD: usize = 4096;

#[derive(Clone, Debug)]
pub struct UpstreamOptions {
    pub generation: Generation,
    pub tools: Vec<String>,
    pub require_header: Option<(String, String)>,
    pub mode: Mode,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        UpstreamOptions {
            generation: Generation::Both,
            tools: vec!["echo".into(), "search".into(), "delete_db".into()],
            require_header: None,
            mode: Mode::Normal,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Recorded {
    pub http_method: String,
    /// Path plus "?query" when a query is present.
    pub path: String,
    /// Lower-cased names, arrival order, duplicates kept.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub rpc_method: Option<String>,
    pub tool: Option<String>,
}

impl Recorded {
    fn capture(method: &Method, uri: &Uri, headers: &HeaderMap, body: Vec<u8>) -> Recorded {
        let parsed: Option<Value> = serde_json::from_slice(&body).ok();
        let rpc_method = match &parsed {
            Some(Value::Object(message)) => message
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        };
        let tool = if rpc_method.as_deref() == Some("tools/call") {
            parsed
                .as_ref()
                .and_then(|message| message.get("params"))
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };
        let headers = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        Recorded {
            http_method: method.as_str().to_string(),
            path: uri
                .path_and_query()
                .map_or("/", |pq| pq.as_str())
                .to_string(),
            headers,
            body,
            rpc_method,
            tool,
        }
    }

    /// First value of the header; the name is compared lower-case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == wanted)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of the header, in arrival order.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(n, _)| *n == wanted)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

struct Store {
    options: UpstreamOptions,
    requests: Vec<Recorded>,
    sessions: HashSet<String>,
    sessions_started: u64,
    /// Held answers that have begun, and the gate their tails wait for.
    held_begun: usize,
    gate: watch::Sender<bool>,
}

struct Shared {
    state: Mutex<Store>,
}

pub struct FakeUpstream {
    url: String,
    shared: Arc<Shared>,
    stop: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

impl FakeUpstream {
    /// Binds 127.0.0.1 on a free port and starts serving.
    pub async fn start(options: UpstreamOptions) -> FakeUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let shared = Arc::new(Shared {
            state: Mutex::new(Store {
                options,
                requests: Vec::new(),
                sessions: HashSet::new(),
                sessions_started: 0,
                held_begun: 0,
                gate: watch::channel(false).0,
            }),
        });
        let router = Router::new().fallback(handle).with_state(shared.clone());
        let (stop, stopped) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .expect("serve fake upstream");
        });
        FakeUpstream {
            url: format!("http://127.0.0.1:{port}/mcp"),
            shared,
            stop: Some(stop),
            server: Some(server),
        }
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.lock().requests.clone()
    }

    pub fn rpc_count(&self, rpc_method: &str) -> usize {
        self.lock()
            .requests
            .iter()
            .filter(|r| r.rpc_method.as_deref() == Some(rpc_method))
            .count()
    }

    pub fn calls_to(&self, tool: &str) -> usize {
        self.lock()
            .requests
            .iter()
            .filter(|r| r.tool.as_deref() == Some(tool))
            .count()
    }

    pub fn clear(&self) {
        self.lock().requests.clear();
    }

    pub fn set_mode(&self, mode: Mode) {
        self.lock().options.mode = mode;
    }

    pub fn set_tools(&self, tools: &[&str]) {
        self.lock().options.tools = tools.iter().map(|t| t.to_string()).collect();
    }

    /// Lets every held answer send its tail. Answers that begin later are not held.
    #[allow(dead_code)]
    pub fn release(&self) {
        self.lock().gate.send_replace(true);
    }

    /// How many held answers have begun.
    #[allow(dead_code)]
    pub fn held_begun(&self) -> usize {
        self.lock().held_begun
    }

    /// Waits until `count` held answers have begun; false when `within` passes first.
    #[allow(dead_code)]
    pub async fn wait_held(&self, count: usize, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while self.held_begun() < count {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    /// Closes the listener, then waits briefly for open connections to finish.
    pub async fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut server) = self.server.take() {
            match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
                Ok(joined) => joined.expect("fake upstream task"),
                Err(_) => server.abort(),
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.shared.state.lock().expect("fake upstream state")
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

enum Reply {
    Now(Response),
    Delayed {
        wait: Duration,
        message: Value,
    },
    Progress {
        steps: u32,
        interval: Duration,
        message: Value,
    },
    ServerRequest {
        message: Value,
    },
    Hang,
    /// The head is sent at once and the tail after the gate opens.
    Held {
        head: Bytes,
        tail: Bytes,
        content_type: &'static str,
    },
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let (bytes, too_large) = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => (bytes.to_vec(), false),
        Err(_) => (Vec::new(), true),
    };
    let recorded = Recorded::capture(&parts.method, &parts.uri, &parts.headers, bytes);
    let (reply, set_cookie) = {
        let mut state = shared.state.lock().expect("fake upstream state");
        state.requests.push(recorded.clone());
        let set_cookie = matches!(state.options.mode, Mode::SetCookie);
        let reply = if too_large {
            Reply::Now(status_only(StatusCode::PAYLOAD_TOO_LARGE))
        } else {
            route(&mut state, &recorded)
        };
        (reply, set_cookie)
    };
    let mut response = match reply {
        Reply::Now(response) => response,
        Reply::Delayed { wait, message } => {
            tokio::time::sleep(wait).await;
            json_response(StatusCode::OK, &message)
        }
        Reply::Progress {
            steps,
            interval,
            message,
        } => progress_response(steps, interval, message),
        Reply::ServerRequest { message } => server_request_response(message),
        Reply::Hang => std::future::pending().await,
        Reply::Held {
            head,
            tail,
            content_type,
        } => held_response(&shared, head, tail, content_type),
    };
    if set_cookie {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static("upstream=1; Path=/"),
        );
        response.headers_mut().append(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"up\""),
        );
    }
    response
}

fn route(state: &mut Store, rec: &Recorded) -> Reply {
    let options = state.options.clone();
    if let Some((name, value)) = &options.require_header
        && !rec.header_all(name).contains(&value.as_str())
    {
        return Reply::Now(json_response(StatusCode::UNAUTHORIZED, &json!({})));
    }
    if let Mode::Redirect(location) = &options.mode {
        return Reply::Now(redirect_response(location));
    }
    match rec.http_method.as_str() {
        "POST" => post(state, rec, &options),
        "GET" => get(state, rec, &options),
        "DELETE" => delete(state, rec, &options),
        _ => Reply::Now(status_only(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

fn post(state: &mut Store, rec: &Recorded, options: &UpstreamOptions) -> Reply {
    match &options.mode {
        Mode::Garbage => {
            return Reply::Now(text_response(
                StatusCode::OK,
                "application/json",
                "not json at all",
            ));
        }
        Mode::WrongContentType => {
            return Reply::Now(text_response(
                StatusCode::OK,
                "text/html",
                "<script>alert(1)</script>",
            ));
        }
        _ => {}
    }
    let message = match rec.json() {
        Some(Value::Object(message)) => message,
        _ => return Reply::Now(invalid_request()),
    };
    let stateless = match options.generation {
        Generation::Session => false,
        Generation::Stateless => true,
        Generation::Both => {
            rec.header_all("mcp-protocol-version")
                .contains(&STATELESS_VERSION)
                || meta_of(&message).is_some_and(|meta| meta.contains_key(META_VERSION))
        }
    };
    if stateless {
        stateless_post(rec, options, &message)
    } else {
        session_post(state, rec, options, &message)
    }
}

fn session_post(
    state: &mut Store,
    rec: &Recorded,
    options: &UpstreamOptions,
    message: &Map<String, Value>,
) -> Reply {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let lenient = matches!(options.mode, Mode::LenientMethods);
    let client_answer = !message.contains_key("method")
        && (message.contains_key("result") || message.contains_key("error"));
    let id = match message.get("id").cloned() {
        Some(id) if !client_answer => id,
        _ => {
            return Reply::Now(match check_session(state, rec) {
                Ok(_) => accepted(options),
                Err(code) => status_only(code),
            });
        }
    };
    if known_method(&SESSION_METHODS, method, lenient) == Some("initialize") {
        return Reply::Now(initialize(state, options, id, &params));
    }
    let Some(method) = known_method(&SESSION_METHODS, method, lenient) else {
        return Reply::Now(rpc_error(id, -32601, "Method not found"));
    };
    if let Err(code) = check_session(state, rec) {
        return Reply::Now(status_only(code));
    }
    answer(
        options,
        id,
        method,
        &with_echo(&params, rec, options),
        false,
    )
}

fn stateless_post(
    rec: &Recorded,
    options: &UpstreamOptions,
    message: &Map<String, Value>,
) -> Reply {
    let id = message.get("id").cloned();
    let id_value = id.clone().unwrap_or(Value::Null);
    let body_method = message.get("method").and_then(Value::as_str);
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let meta_version = meta_of(message)
        .and_then(|meta| meta.get(META_VERSION))
        .and_then(Value::as_str);
    let header_version = rec.header_all("mcp-protocol-version").first().copied();
    let supported = supported_versions(options.generation);
    match meta_version.or(header_version) {
        None => return Reply::Now(version_error(id_value, &supported, "")),
        Some(requested) if !supported.contains(&requested) => {
            return Reply::Now(version_error(id_value, &supported, requested));
        }
        Some(_) => {}
    }
    let lenient = matches!(options.mode, Mode::LenientMethods);
    let method = known_method(&STATELESS_METHODS, body_method.unwrap_or(""), lenient);
    let needs_name = matches!(
        method,
        Some("tools/call" | "resources/read" | "prompts/get")
    );
    let expected_name = method.and_then(|m| name_param(m, &params));
    // A notification may omit the version from its body; then only the method header is compared.
    let version_problem = if meta_version.is_some() || id.is_some() {
        header_problem(rec, "MCP-Protocol-Version", meta_version)
    } else {
        None
    };
    let problem = version_problem
        .or_else(|| header_problem(rec, "Mcp-Method", body_method))
        .or_else(|| {
            if needs_name {
                header_problem(rec, "Mcp-Name", expected_name)
            } else {
                None
            }
        });
    if let Some(detail) = problem {
        let error = json!({
            "code": -32020,
            "message": format!("Header mismatch: {detail}"),
        });
        return Reply::Now(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"jsonrpc": "2.0", "id": id_value, "error": error}),
        ));
    }
    let Some(id) = id else {
        return Reply::Now(accepted(options));
    };
    let Some(method) = method else {
        return Reply::Now(rpc_error(id, -32601, "Method not found"));
    };
    answer(options, id, method, &with_echo(&params, rec, options), true)
}

fn get(state: &mut Store, rec: &Recorded, options: &UpstreamOptions) -> Reply {
    if options.generation == Generation::Stateless {
        return Reply::Now(status_only(StatusCode::METHOD_NOT_ALLOWED));
    }
    if let Err(code) = check_session(state, rec) {
        return Reply::Now(status_only(code));
    }
    let open = stream::iter(vec![Ok::<Bytes, io::Error>(Bytes::from_static(
        b": open\n\n",
    ))])
    .chain(stream::pending::<Chunk>());
    Reply::Now(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(open))
            .expect("open stream response"),
    )
}

fn delete(state: &mut Store, rec: &Recorded, options: &UpstreamOptions) -> Reply {
    if options.generation == Generation::Stateless {
        return Reply::Now(status_only(StatusCode::METHOD_NOT_ALLOWED));
    }
    match check_session(state, rec) {
        Ok(session) => {
            state.sessions.remove(&session);
            Reply::Now(status_only(StatusCode::OK))
        }
        Err(code) => Reply::Now(status_only(code)),
    }
}

/// The session id of a request, or the status to answer with when it has no live session.
fn check_session(state: &Store, rec: &Recorded) -> Result<String, StatusCode> {
    match rec.header("mcp-session-id") {
        None => Err(StatusCode::BAD_REQUEST),
        Some(id) if state.sessions.contains(id) => Ok(id.to_string()),
        Some(_) => Err(StatusCode::NOT_FOUND),
    }
}

fn initialize(state: &mut Store, options: &UpstreamOptions, id: Value, params: &Value) -> Response {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    let version = if SESSION_VERSIONS.contains(&requested) {
        requested
    } else {
        DEFAULT_SESSION_VERSION
    };
    let session_id = if matches!(options.mode, Mode::ReuseSessionId) {
        "fixed-session".to_string()
    } else {
        state.sessions_started += 1;
        format!("sess-{}", state.sessions_started)
    };
    state.sessions.insert(session_id.clone());
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": version,
            "capabilities": with_declared(options, if matches!(options.mode, Mode::DeclaresFlags) {
                declared_capabilities()
            } else {
                json!({"tools": {"listChanged": false}, "resources": {}, "prompts": {}})
            }),
            "serverInfo": {"name": "fake-upstream", "version": "0"},
        },
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("Mcp-Session-Id", session_id)
        .body(Body::from(body.to_string()))
        .expect("initialize response")
}

/// Turns a known method into its canonical spelling, optionally ignoring ASCII case.
fn known_method(known: &[&'static str], method: &str, lenient: bool) -> Option<&'static str> {
    known.iter().copied().find(|k| {
        if lenient {
            k.eq_ignore_ascii_case(method)
        } else {
            *k == method
        }
    })
}

fn answer(
    options: &UpstreamOptions,
    id: Value,
    method: &str,
    params: &Value,
    stateless: bool,
) -> Reply {
    if method == "tools/list" {
        match &options.mode {
            Mode::HangListing => return Reply::Hang,
            Mode::SlowListing { millis } => {
                return Reply::Delayed {
                    wait: Duration::from_millis(*millis),
                    message: dispatch(id, method, params, options, stateless),
                };
            }
            _ => {}
        }
    }
    if method == "tools/call" {
        match &options.mode {
            Mode::Hang => return Reply::Hang,
            Mode::RefusesCalls => {
                let error = json!({
                    "code": -32021,
                    "message": "MissingRequiredClientCapabilityError",
                    "data": {"requiredCapabilities": {"sampling": {}}},
                });
                return Reply::Now(text_response(
                    StatusCode::BAD_REQUEST,
                    "application/json; charset=utf-8",
                    &json!({"jsonrpc": "2.0", "id": id, "error": error}).to_string(),
                ));
            }
            Mode::Progress { steps, interval_ms } => {
                return Reply::Progress {
                    steps: *steps,
                    interval: Duration::from_millis(*interval_ms),
                    message: dispatch(id, method, params, options, stateless),
                };
            }
            Mode::ServerRequest => {
                return Reply::ServerRequest {
                    message: dispatch(id, method, params, options, stateless),
                };
            }
            Mode::Delayed { millis } => {
                return Reply::Delayed {
                    wait: Duration::from_millis(*millis),
                    message: dispatch(id, method, params, options, stateless),
                };
            }
            Mode::Oversized { bytes } => {
                let text = "x".repeat(*bytes);
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"content": [{"type": "text", "text": text}], "isError": false},
                });
                return Reply::Now(json_response(StatusCode::OK, &body));
            }
            Mode::HeldAnswer { bytes } => {
                let body = held_result(id, *bytes).into_bytes();
                let (head, tail) = body.split_at(body.len() / 2);
                return Reply::Held {
                    head: Bytes::copy_from_slice(head),
                    tail: Bytes::copy_from_slice(tail),
                    content_type: "application/json",
                };
            }
            Mode::HeldStream { bytes } => {
                let event = format!("data: {}\n\n", held_result(id, *bytes)).into_bytes();
                let (head, tail) = event.split_at(HELD_STREAM_HEAD.min(event.len()));
                return Reply::Held {
                    head: Bytes::copy_from_slice(head),
                    tail: Bytes::copy_from_slice(tail),
                    content_type: "text/event-stream",
                };
            }
            _ => {}
        }
    }
    Reply::Now(json_response(
        StatusCode::OK,
        &dispatch(id, method, params, options, stateless),
    ))
}

/// A tools/call result whose text is `bytes` characters long, as JSON text.
fn held_result(id: Value, bytes: usize) -> String {
    let text = "x".repeat(bytes);
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"content": [{"type": "text", "text": text}], "isError": false},
    })
    .to_string()
}

/// A response whose head is sent now and whose tail follows once the upstream's gate opens.
fn held_response(
    shared: &Shared,
    head: Bytes,
    tail: Bytes,
    content_type: &'static str,
) -> Response {
    let gate = {
        let mut state = shared.state.lock().expect("fake upstream state");
        state.held_begun += 1;
        state.gate.subscribe()
    };
    let rest = stream::once(async move {
        let mut gate = gate;
        let _ = gate.wait_for(|open| *open).await;
        Ok::<Bytes, io::Error>(tail)
    });
    let body = stream::once(async move { Ok::<Bytes, io::Error>(head) }).chain(rest);
    let mut response = Response::new(Body::from_stream(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn dispatch(
    id: Value,
    method: &str,
    params: &Value,
    options: &UpstreamOptions,
    stateless: bool,
) -> Value {
    match outcome(method, params, options, stateless) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => rpc_error_value(id, code, &message),
    }
}

fn outcome(
    method: &str,
    params: &Value,
    options: &UpstreamOptions,
    stateless: bool,
) -> Result<Value, (i64, String)> {
    let mut result = match method {
        "server/discover" => json!({
            "supportedVersions": supported_versions(options.generation),
            "capabilities": with_declared(options, if matches!(options.mode, Mode::DeclaresFlags) {
                declared_capabilities()
            } else {
                json!({"tools": {}, "resources": {}, "prompts": {}})
            }),
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "fake-upstream", "version": "0"}},
            "ttlMs": 3600000,
            "cacheScope": "public",
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools_json(options)}),
        "tools/call" => call_result(params, options)?,
        "resources/list" => json!({"resources": [{"uri": "file:///secret.txt", "name": "secret"}]}),
        "resources/read" => {
            json!({"contents": [{"uri": "file:///secret.txt", "text": "TOP-SECRET"}]})
        }
        "prompts/list" => json!({"prompts": [{"name": "greet"}]}),
        "prompts/get" => {
            json!({"messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}]})
        }
        _ => return Err((-32601, "Method not found".to_string())),
    };
    if stateless {
        let object = result.as_object_mut().expect("result object");
        object.insert("resultType".into(), json!("complete"));
        if matches!(method, "tools/list" | "resources/list" | "prompts/list") {
            object.insert("ttlMs".into(), json!(300000));
            object.insert("cacheScope".into(), json!("public"));
        }
    }
    Ok(result)
}

/// Echo mode: the value of the request header rides in the params of a tools/call.
fn with_echo(params: &Value, rec: &Recorded, options: &UpstreamOptions) -> Value {
    let mut params = params.clone();
    if let Mode::EchoHeader(name) = &options.mode
        && let Value::Object(object) = &mut params
    {
        object.insert(ECHO_KEY.into(), json!(rec.header_all(name).join(",")));
    }
    params
}

fn call_result(params: &Value, options: &UpstreamOptions) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let lenient = matches!(options.mode, Mode::LenientNames);
    match options
        .tools
        .iter()
        .find(|tool| same_name(tool, name, lenient))
    {
        Some(tool) => {
            let failed = matches!(options.mode, Mode::ToolErrors);
            let text = if failed {
                format!("failed: {tool}")
            } else if let Some(echoed) = params.get(ECHO_KEY).and_then(Value::as_str) {
                format!("called: {tool} {echoed}")
            } else {
                format!("called: {tool}")
            };
            Ok(json!({
                "content": [{"type": "text", "text": text}],
                "isError": failed,
            }))
        }
        None => Err((-32602, format!("Unknown tool: {name}"))),
    }
}

fn same_name(configured: &str, requested: &str, lenient: bool) -> bool {
    if lenient {
        normalize_name(configured) == normalize_name(requested)
    } else {
        configured == requested
    }
}

fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
        .collect::<String>()
        .trim()
        .to_lowercase()
}

fn tools_json(options: &UpstreamOptions) -> Vec<Value> {
    let keyed = matches!(options.mode, Mode::HeaderKeyed);
    options
        .tools
        .iter()
        .map(|name| {
            let mut schema = json!({"type": "object", "properties": {"text": {"type": "string"}}});
            if keyed {
                schema["x-mcp-header"] = json!("Region");
            }
            json!({
                "name": name,
                "description": "fake tool",
                "inputSchema": schema,
            })
        })
        .collect()
}

/// `capabilities` with the tasks or completions member added when the mode declares it.
fn with_declared(options: &UpstreamOptions, mut capabilities: Value) -> Value {
    if matches!(options.mode, Mode::DeclaresTasks) {
        capabilities["tasks"] = json!({"list": {}, "cancel": {}});
    }
    if matches!(options.mode, Mode::DeclaresCompletions) {
        capabilities["completions"] = json!({});
    }
    capabilities
}

/// The capabilities of `Mode::DeclaresFlags`: the four flags, with one other member in each group.
fn declared_capabilities() -> Value {
    json!({
        "tools": {"listChanged": true, "extra": 1},
        "resources": {"listChanged": true, "subscribe": true, "extra": true},
        "prompts": {"listChanged": true},
    })
}

fn supported_versions(generation: Generation) -> Vec<&'static str> {
    match generation {
        Generation::Session => Vec::new(),
        Generation::Stateless => vec![STATELESS_VERSION],
        Generation::Both => vec![STATELESS_VERSION, "2025-11-25"],
    }
}

fn meta_of(message: &Map<String, Value>) -> Option<&Map<String, Value>> {
    message.get("params")?.get("_meta")?.as_object()
}

/// The value the Mcp-Name header must carry for this method, if any.
fn name_param<'a>(method: &str, params: &'a Value) -> Option<&'a str> {
    match method {
        "tools/call" | "prompts/get" => params.get("name").and_then(Value::as_str),
        "resources/read" => params.get("uri").and_then(Value::as_str),
        _ => None,
    }
}

/// Describes the first problem with a required header, or None when it matches the body.
fn header_problem(rec: &Recorded, name: &str, expected: Option<&str>) -> Option<String> {
    let values = rec.header_all(name);
    match values.as_slice() {
        [] => Some(format!("{name} missing")),
        [value] => match (decode_header(value), expected) {
            (Some(actual), Some(wanted)) if actual == wanted => None,
            _ => Some(format!("{name} does not match the body")),
        },
        _ => Some(format!("{name} repeated")),
    }
}

/// Decodes the `=?base64?...?=` form; plain values pass through unchanged.
fn decode_header(value: &str) -> Option<String> {
    match value
        .strip_prefix("=?base64?")
        .and_then(|rest| rest.strip_suffix("?="))
    {
        Some(encoded) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok()),
        None => Some(value.to_string()),
    }
}

fn progress_response(steps: u32, interval: Duration, message: Value) -> Response {
    let final_event = format!("data: {message}\n\n");
    let events = stream::unfold(0u32, move |index| {
        let final_event = final_event.clone();
        async move {
            if index > steps {
                return None;
            }
            if index > 0 {
                tokio::time::sleep(interval).await;
            }
            let event = if index < steps {
                let progress = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progress": index + 1, "total": steps, "progressToken": "t"},
                });
                format!("data: {progress}\n\n")
            } else {
                final_event
            };
            Some((Ok::<Bytes, io::Error>(Bytes::from(event)), index + 1))
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(events))
        .expect("progress response")
}

/// The request the server-request mode sends before the result.
const SERVER_REQUEST: &str = r#"data: {"jsonrpc":"2.0","id":"srv-1","method":"elicitation/create","params":{"message":"confirm?","requestedSchema":{"type":"object","properties":{}}}}"#;

fn server_request_response(message: Value) -> Response {
    let request = Ok::<Bytes, io::Error>(Bytes::from(format!("{SERVER_REQUEST}\n\n")));
    let result = format!("data: {message}\n\n");
    let events = stream::iter(vec![request]).chain(stream::once(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<Bytes, io::Error>(Bytes::from(result))
    }));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(events))
        .expect("server request response")
}

/// The answer to a notification: 202 with no body, or as the TypeScript SDK sends it.
fn accepted(options: &UpstreamOptions) -> Response {
    match options.mode {
        Mode::TypeScriptNotices => {
            text_response(StatusCode::ACCEPTED, "text/plain; charset=UTF-8", "")
        }
        _ => status_only(StatusCode::ACCEPTED),
    }
}

fn invalid_request() -> Response {
    text_response(
        StatusCode::BAD_REQUEST,
        "application/json",
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#,
    )
}

fn version_error(id: Value, supported: &[&str], requested: &str) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {"supported": supported, "requested": requested},
            },
        }),
    )
}

fn rpc_error(id: Value, code: i64, message: &str) -> Response {
    json_response(StatusCode::OK, &rpc_error_value(id, code, message))
}

fn rpc_error_value(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    text_response(status, "application/json", &body.to_string())
}

fn text_response(status: StatusCode, content_type: &str, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body.to_string()))
        .expect("text response")
}

fn redirect_response(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .expect("redirect response")
}

fn status_only(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}
