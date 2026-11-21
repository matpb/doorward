use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::net::SocketAddr;

use base64::Engine as _;
use reqwest::header::{CONTENT_TYPE, HeaderMap};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

const STATELESS_VERSION: &str = "2026-07-28";
const SESSION_VERSION: &str = "2025-11-25";
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const GET_BODY_WINDOW: Duration = Duration::from_millis(300);

#[derive(Clone, Debug)]
pub struct SseEvent {
    /// Time since the request was sent, when the event's data was fully received.
    pub at: Duration,
    pub data: Value,
}

#[derive(Debug)]
pub struct McpReply {
    pub status: u16,
    pub headers: HeaderMap,
    /// Raw body text; for SSE the whole stream text.
    pub body: String,
    /// The JSON body, or the last SSE data that has "id" and ("result" or "error").
    pub json: Option<Value>,
    /// Empty unless the response was text/event-stream.
    pub events: Vec<SseEvent>,
}

impl McpReply {
    fn failed() -> McpReply {
        McpReply {
            status: 0,
            headers: HeaderMap::new(),
            body: String::new(),
            json: None,
            events: Vec::new(),
        }
    }

    pub fn result(&self) -> Option<&Value> {
        self.json.as_ref()?.get("result")
    }

    pub fn error_code(&self) -> Option<i64> {
        self.json.as_ref()?.get("error")?.get("code")?.as_i64()
    }

    pub fn error_message(&self) -> Option<String> {
        self.json
            .as_ref()?
            .get("error")?
            .get("message")?
            .as_str()
            .map(str::to_string)
    }

    pub fn tool_names(&self) -> Vec<String> {
        self.result()
            .and_then(|result| result.get("tools"))
            .and_then(Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool.get("name")?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn text(&self) -> Option<String> {
        self.result()?
            .get("content")?
            .get(0)?
            .get("text")?
            .as_str()
            .map(str::to_string)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name)?.to_str().ok().map(str::to_string)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Style {
    Session,
    Stateless,
}

pub struct McpClient {
    url: String,
    token: Option<String>,
    style: Style,
    http: reqwest::Client,
    session: Mutex<Option<String>>,
    next_id: AtomicU64,
    timeout: Mutex<Duration>,
}

impl McpClient {
    /// A client speaking the session style (revision 2025-11-25).
    pub fn session(url: &str, token: Option<&str>) -> McpClient {
        McpClient::new(url, token, Style::Session)
    }

    /// A client speaking the stateless style (revision 2026-07-28).
    pub fn stateless(url: &str, token: Option<&str>) -> McpClient {
        McpClient::new(url, token, Style::Stateless)
    }

    fn new(url: &str, token: Option<&str>, style: Style) -> McpClient {
        McpClient {
            url: url.to_string(),
            token: token.map(str::to_string),
            style,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http client"),
            session: Mutex::new(None),
            next_id: AtomicU64::new(1),
            timeout: Mutex::new(DEFAULT_TIMEOUT),
        }
    }

    /// Sends initialize, stores the Mcp-Session-Id, then sends notifications/initialized.
    pub async fn initialize(&self) -> McpReply {
        let reply = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": SESSION_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "0"},
                }),
            )
            .await;
        if let Some(id) = reply.header("mcp-session-id") {
            self.set_session_id(Some(id.as_str()));
        }
        self.notify("notifications/initialized", Value::Null).await;
        reply
    }

    /// Sends server/discover with the id "discover-1".
    pub async fn discover(&self) -> McpReply {
        self.send_rpc(Some(json!("discover-1")), "server/discover", json!({}))
            .await
    }

    pub async fn list_tools(&self) -> McpReply {
        self.request("tools/list", json!({})).await
    }

    /// A stateless tools/list sent with extra headers, such as X-Forwarded-For.
    /// Unused by harness_upstream, which includes this file by path.
    #[allow(dead_code)]
    pub async fn list_tools_with(&self, headers: &[(&str, &str)]) -> McpReply {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": with_meta(json!({})),
        });
        let mut all = vec![
            ("MCP-Protocol-Version", STATELESS_VERSION),
            ("Mcp-Method", "tools/list"),
        ];
        all.extend_from_slice(headers);
        self.raw(body.to_string().as_bytes(), &all).await
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> McpReply {
        self.request("tools/call", json!({"name": name, "arguments": arguments}))
            .await
    }

    /// Sends a request well formed for this client's style.
    pub async fn request(&self, method: &str, params: Value) -> McpReply {
        let params = if params.is_null() { json!({}) } else { params };
        let id = json!(self.next_id.fetch_add(1, Ordering::SeqCst));
        self.send_rpc(Some(id), method, params).await
    }

    /// Sends a notification (no id) well formed for this client's style.
    pub async fn notify(&self, method: &str, params: Value) -> McpReply {
        self.send_rpc(None, method, params).await
    }

    /// POSTs exactly these bytes; adds Authorization, Content-Type and Accept unless overridden.
    pub async fn raw(&self, body: &[u8], headers: &[(&str, &str)]) -> McpReply {
        let overrides = |name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        let mut builder = self.http.post(&self.url).body(body.to_vec());
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }
        if !overrides("content-type") {
            builder = builder.header("Content-Type", "application/json");
        }
        if !overrides("accept") {
            builder = builder.header("Accept", "application/json, text/event-stream");
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        self.exchange(builder, None).await
    }

    /// GETs the endpoint; returns after the headers and up to 300 ms of body.
    pub async fn get(&self) -> McpReply {
        let mut builder = self
            .http
            .get(&self.url)
            .header("Accept", "text/event-stream");
        builder = self.with_auth_and_session(builder);
        let window = tokio::time::Instant::now() + GET_BODY_WINDOW;
        self.exchange(builder, Some(window)).await
    }

    pub async fn delete(&self) -> McpReply {
        let builder = self.with_auth_and_session(self.http.delete(&self.url));
        self.exchange(builder, None).await
    }

    /// Sends `method` with no body and these extra headers; reads the body for at most 300 ms.
    /// Unused by harness_upstream, which includes this file by path.
    #[allow(dead_code)]
    pub async fn bodiless(&self, method: reqwest::Method, headers: &[(&str, &str)]) -> McpReply {
        let mut builder = self.with_auth_and_session(self.http.request(method, &self.url));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let window = tokio::time::Instant::now() + GET_BODY_WINDOW;
        self.exchange(builder, Some(window)).await
    }

    pub fn session_id(&self) -> Option<String> {
        self.session.lock().expect("session lock").clone()
    }

    pub fn set_session_id(&self, id: Option<&str>) {
        *self.session.lock().expect("session lock") = id.map(str::to_string);
    }

    /// Per-request timeout; a timed-out request answers status 0 with an empty body.
    pub fn set_timeout(&self, d: Duration) {
        *self.timeout.lock().expect("timeout lock") = d;
    }

    async fn send_rpc(&self, id: Option<Value>, method: &str, params: Value) -> McpReply {
        let mut message = Map::new();
        message.insert("jsonrpc".into(), json!("2.0"));
        if let Some(id) = id {
            message.insert("id".into(), id);
        }
        message.insert("method".into(), json!(method));
        let mut builder = self.http.post(&self.url);
        match self.style {
            Style::Session => {
                if !params.is_null() {
                    message.insert("params".into(), params);
                }
                builder = self.with_auth_and_session(builder);
            }
            Style::Stateless => {
                let name = stateless_name(method, &params).map(encode_header_value);
                message.insert("params".into(), with_meta(params));
                builder = builder
                    .header("MCP-Protocol-Version", STATELESS_VERSION)
                    .header("Mcp-Method", method);
                if let Some(name) = name {
                    builder = builder.header("Mcp-Name", name);
                }
                builder = self.with_auth(builder);
            }
        }
        let body = Value::Object(message).to_string();
        builder = builder
            .header(CONTENT_TYPE, "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(body.into_bytes());
        self.exchange(builder, None).await
    }

    fn with_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    /// Adds the session headers once a session exists; the stateless style sends none.
    fn with_auth_and_session(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut builder = self.with_auth(builder);
        if self.style == Style::Session
            && let Some(id) = self.session_id()
        {
            builder = builder
                .header("Mcp-Session-Id", id)
                .header("MCP-Protocol-Version", SESSION_VERSION);
        }
        builder
    }

    async fn exchange(
        &self,
        builder: reqwest::RequestBuilder,
        window: Option<tokio::time::Instant>,
    ) -> McpReply {
        let timeout = *self.timeout.lock().expect("timeout lock");
        match read_reply(builder.timeout(timeout), window).await {
            Ok(reply) => reply,
            // Timeouts and transport errors both answer status 0.
            Err(_) => McpReply::failed(),
        }
    }
}

/// The value of Mcp-Name for the methods that carry one; non-ASCII values are base64 encoded.
fn stateless_name(method: &str, params: &Value) -> Option<String> {
    match method {
        "tools/call" | "prompts/get" => params.get("name")?.as_str().map(str::to_string),
        "resources/read" => params.get("uri")?.as_str().map(str::to_string),
        _ => None,
    }
}

fn encode_header_value(value: String) -> String {
    if value.is_ascii() {
        value
    } else {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        format!("=?base64?{encoded}?=")
    }
}

/// Merges the three protocol _meta keys into params.
fn with_meta(params: Value) -> Value {
    let mut map = match params {
        Value::Object(map) => map,
        Value::Null => Map::new(),
        _ => panic!("stateless params must be a JSON object"),
    };
    let meta = map
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("_meta must be a JSON object");
    meta.insert(META_VERSION.into(), json!(STATELESS_VERSION));
    meta.insert(
        "io.modelcontextprotocol/clientCapabilities".into(),
        json!({}),
    );
    meta.insert(
        "io.modelcontextprotocol/clientInfo".into(),
        json!({"name": "test-client", "version": "0"}),
    );
    Value::Object(map)
}

async fn read_reply(
    builder: reqwest::RequestBuilder,
    window: Option<tokio::time::Instant>,
) -> Result<McpReply, reqwest::Error> {
    let started = Instant::now();
    let mut response = builder.send().await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let sse = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    let mut body = Vec::new();
    let mut parser = SseParser::default();
    loop {
        let chunk = match window {
            Some(deadline) => match tokio::time::timeout_at(deadline, response.chunk()).await {
                Ok(chunk) => chunk?,
                // The body window ended; keep what has arrived.
                Err(_) => break,
            },
            None => response.chunk().await?,
        };
        let Some(chunk) = chunk else { break };
        if sse {
            parser.feed(&chunk, started.elapsed());
        }
        body.extend_from_slice(&chunk);
    }
    let events = parser.events;
    let text = String::from_utf8_lossy(&body).into_owned();
    let json: Option<Value> = if sse {
        events
            .iter()
            .rev()
            .find(|e| is_rpc_response(&e.data))
            .map(|e| e.data.clone())
    } else {
        serde_json::from_str(&text).ok()
    };
    Ok(McpReply {
        status,
        headers,
        body: text,
        json,
        events,
    })
}

fn is_rpc_response(data: &Value) -> bool {
    data.get("id").is_some() && (data.get("result").is_some() || data.get("error").is_some())
}

#[derive(Default)]
struct SseParser {
    partial: Vec<u8>,
    data: Vec<String>,
    events: Vec<SseEvent>,
}

impl SseParser {
    fn feed(&mut self, bytes: &[u8], at: Duration) {
        self.partial.extend_from_slice(bytes);
        while let Some(end) = self.partial.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = self.partial.drain(..=end).collect();
            let text = String::from_utf8_lossy(&raw);
            let line = text.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                self.dispatch(at);
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.data
                    .push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
        }
    }

    fn dispatch(&mut self, at: Duration) {
        if self.data.is_empty() {
            return;
        }
        let text = self.data.join("\n");
        self.data.clear();
        let data = serde_json::from_str(&text).unwrap_or(Value::String(text));
        self.events.push(SseEvent { at, data });
    }
}

/// How long a stalled client waits for the status line of its answer.
#[allow(dead_code)]
const STATUS_WAIT: Duration = Duration::from_secs(30);

/// Sends a stateless tools/call for `echo` on `/{slug}` through a socket whose receive buffer is 4 KiB,
/// and reads the status line of the answer only. The socket comes back open, so the client can stall.
#[allow(dead_code)]
pub async fn stalled_call(
    addr: SocketAddr,
    slug: &str,
    token: &str,
    id: u64,
) -> (TcpStream, String) {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"hi"}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    );
    let request = format!(
        "POST /{slug} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: echo\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let socket = TcpSocket::new_v4().expect("socket");
    socket.set_recv_buffer_size(4096).expect("receive buffer");
    let mut stream = socket.connect(addr).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send the call");
    let mut line = Vec::new();
    tokio::time::timeout(STATUS_WAIT, async {
        loop {
            let byte = stream.read_u8().await.expect("the status line");
            line.push(byte);
            if byte == b'\n' {
                break;
            }
        }
    })
    .await
    .expect("the status line arrives");
    (stream, String::from_utf8_lossy(&line).into_owned())
}
