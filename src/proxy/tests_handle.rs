//! The `/{slug}` handler over real HTTP: a gateway on 127.0.0.1, and a scripted upstream behind it.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::response::Response;
use futures_util::{Stream, StreamExt, stream};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::catalog;
use super::tests::{Plan, Seen, TestUpstream};
use crate::app::{Deps, assemble, serve};
use crate::cimd::UnavailableCimd;
use crate::clock::Clock;
use crate::config::{Config, Lifetimes, Limits};
use crate::crypto::{Keys, PasswordHasher};
use crate::oauth::families::{self, NewFamily};
use crate::servers;

pub(super) const SECRET_NAME: &str = "x-upstream-secret";
pub(super) const SECRET: &str = "s3cret-for-demo";
pub(super) const BOB: &str = "bob@example.com";
pub(super) const CAROL: &str = "carol@example.com";
pub(super) const CLIENT: &str = "Example Client";
const INERT: [(&str, &str); 2] = [
    ("x-content-type-options", "nosniff"),
    ("content-security-policy", "sandbox"),
];
const UNAVAILABLE: &str = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Upstream demo is unavailable"}}"#;
const CLOSED_PORT: &str = "http://127.0.0.1:9/mcp";

/// The reply of one request: status, every header in order, and the body text.
pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: String,
}

impl Reply {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub(super) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    pub(super) fn error_code(&self) -> Option<i64> {
        self.json()["error"]["code"].as_i64()
    }

    pub(super) fn error_message(&self) -> Option<String> {
        self.json()["error"]["message"].as_str().map(str::to_owned)
    }

    /// The text of a tools/call result.
    pub(super) fn text_of_call(&self) -> Option<String> {
        self.json()["result"]["content"][0]["text"]
            .as_str()
            .map(str::to_owned)
    }

    pub(super) fn assert_inert(&self, what: &str) {
        for (name, value) in INERT {
            assert_eq!(self.header(name), Some(value), "{what} must carry {name}");
        }
    }
}

/// One row of the tool-call activity log.
#[derive(Debug, PartialEq)]
pub(super) struct Row {
    pub(super) user_id: Option<i64>,
    pub(super) email: String,
    pub(super) server_id: Option<i64>,
    pub(super) slug: String,
    pub(super) tool: String,
    pub(super) client: String,
    pub(super) decision: String,
    pub(super) outcome: String,
    pub(super) detail: String,
    pub(super) duration: Option<i64>,
}

/// The gateway's clock: the real time at start, then only the moves a test makes.
pub(super) struct SetClock(AtomicI64);

impl SetClock {
    pub(super) fn set(&self, at: i64) {
        self.0.store(at, Ordering::SeqCst);
    }
}

impl Clock for SetClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("instant")
    }
}

/// A started gateway, its database and its key file in one temporary directory.
pub(super) struct Gw {
    pub(super) base: String,
    pub(super) db: PathBuf,
    pub(super) config: Config,
    pub(super) http: reqwest::Client,
    pub(super) clock: Arc<SetClock>,
    _dir: TempDir,
}

pub(super) fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

impl Gw {
    pub(super) async fn start(edit: impl FnOnce(&mut Config)) -> Gw {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = dir.path().join("doorward.db");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let base = format!("http://{address}");
        let mut config = Config {
            public_url: base.clone(),
            listen: address,
            database: db.clone(),
            key_file: Some(dir.path().join("doorward.key")),
            trusted_proxies: Vec::new(),
            shared_client_address: false,
            allowed_origins: Vec::new(),
            lifetimes: Lifetimes::default(),
            limits: Limits::default(),
            mail: Default::default(),
        };
        edit(&mut config);
        Keys::load(&config, None).expect("keys");
        let hasher = PasswordHasher::new().await.expect("hasher");
        let clock = Arc::new(SetClock(AtomicI64::new(now())));
        let deps = Deps {
            clock: clock.clone(),
            cimd: Arc::new(UnavailableCimd),
        };
        let gateway = assemble(config.clone(), deps, Arc::new(hasher))
            .await
            .expect("build");
        tokio::spawn(serve(
            listener,
            gateway.router,
            std::time::Duration::from_secs(30),
            std::future::pending(),
        ));
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("client");
        Gw {
            base,
            db,
            config,
            http,
            clock,
            _dir: dir,
        }
    }

    pub(super) fn conn(&self) -> Connection {
        let conn = Connection::open(&self.db).expect("connection");
        conn.busy_timeout(Duration::from_secs(5)).expect("timeout");
        conn
    }

    pub(super) fn keys(&self) -> Keys {
        Keys::load(&self.config, None).expect("keys")
    }

    pub(super) fn add_user(&self, email: &str) -> i64 {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
            params![email],
        )
        .expect("user");
        conn.last_insert_rowid()
    }

    /// A server row; the secret is sealed the way the admin page seals it.
    pub(super) fn add_server(
        &self,
        slug: &str,
        url: &str,
        secret: Option<&str>,
        switches: (bool, bool),
    ) -> i64 {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO servers (name, slug, upstream_url, secret_header_name, \
             pass_resources, pass_prompts, created_at) VALUES (?1, ?1, ?2, ?3, ?4, ?5, 0)",
            params![slug, url, SECRET_NAME, switches.0, switches.1],
        )
        .expect("server");
        let id = conn.last_insert_rowid();
        if let Some(value) = secret {
            let sealed = servers::seal(&self.keys(), id, value).expect("seal");
            conn.execute(
                "UPDATE servers SET secret_header_value = ?1 WHERE id = ?2",
                params![sealed, id],
            )
            .expect("secret");
        }
        id
    }

    pub(super) fn set_url(&self, server: i64, url: &str) {
        self.conn()
            .execute(
                "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
                params![url, server],
            )
            .expect("address");
    }

    pub(super) fn grant(&self, user: i64, server: i64) {
        self.conn()
            .execute(
                "INSERT INTO user_servers (user_id, server_id) VALUES (?1, ?2)",
                params![user, server],
            )
            .expect("assignment");
    }

    /// A new token family of `user` on `server`, and its access token.
    pub(super) fn token(&self, user: i64, server: i64) -> String {
        let conn = self.conn();
        let epoch: i64 = conn
            .query_row(
                "SELECT auth_epoch FROM users WHERE id = ?1",
                params![user],
                |row| row.get(0),
            )
            .expect("epoch");
        let new = NewFamily {
            user_id: user,
            server_id: Some(server),
            client_id: "dcr_test",
            client_name: CLIENT,
            auth_epoch: epoch,
        };
        let family = families::create(&conn, &new, now(), 90).expect("family");
        families::mint_pair(&conn, family, now(), &Lifetimes::default())
            .expect("pair")
            .access_token
    }

    /// Replaces the server's catalog with `names`, as a successful refresh would.
    pub(super) fn seed(&self, server: i64, names: &[&str]) {
        let tools: Vec<Value> = names.iter().map(|name| json!({"name": name})).collect();
        let mut conn = self.conn();
        catalog::replace(&mut conn, server, &tools, now()).expect("catalog");
    }

    /// The catalog names of the server, in position order.
    pub(super) fn catalog_names(&self, server: i64) -> Vec<String> {
        catalog::names(&self.conn(), server).expect("names")
    }

    /// A stored rule written straight to the table: `user` None is everyone, `tool` None is the server.
    pub(super) fn add_rule(
        &self,
        user: Option<i64>,
        effect: &str,
        server: i64,
        tool: Option<&str>,
    ) {
        self.conn()
            .execute(
                "INSERT INTO rules (user_id, effect, server_id, tool, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                params![user, effect, server, tool],
            )
            .expect("rule");
    }

    /// Sends one request; `headers` are added as given.
    pub(super) async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        headers: Vec<(&str, String)>,
        body: Option<String>,
    ) -> Reply {
        let mut builder = self.http.request(method, format!("{}{path}", self.base));
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }
        let response = builder.send().await.expect("request");
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let body = response.text().await.expect("body");
        Reply {
            status,
            headers,
            body,
        }
    }

    /// A POST to `/{slug}` with the headers and body the test gives.
    pub(super) async fn post(
        &self,
        slug: &str,
        token: &str,
        headers: Vec<(&str, String)>,
        body: String,
    ) -> Reply {
        self.send(
            reqwest::Method::POST,
            &format!("/{slug}"),
            Some(token),
            headers,
            Some(body),
        )
        .await
    }

    /// Every row of one table, each cell as text.
    pub(super) fn dump(&self, table: &str) -> String {
        let conn = self.conn();
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table}"))
            .expect("dump");
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                let mut cells = Vec::new();
                for index in 0..columns {
                    let cell: rusqlite::types::Value = row.get(index)?;
                    cells.push(format!("{cell:?}"));
                }
                Ok(cells.join("|"))
            })
            .expect("rows");
        rows.map(|row| row.expect("row"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(super) fn tool_calls(&self) -> Vec<Row> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT user_id, user_email, server_id, server_slug, tool, client, decision, \
                 outcome, detail, duration_ms FROM activity WHERE kind = 'tool_call' ORDER BY id",
            )
            .expect("activity");
        let rows = statement
            .query_map([], |row| {
                Ok(Row {
                    user_id: row.get(0)?,
                    email: row.get(1)?,
                    server_id: row.get(2)?,
                    slug: row.get(3)?,
                    tool: row.get(4)?,
                    client: row.get(5)?,
                    decision: row.get(6)?,
                    outcome: row.get(7)?,
                    detail: row.get(8)?,
                    duration: row.get(9)?,
                })
            })
            .expect("rows");
        rows.map(|row| row.expect("row")).collect()
    }

    pub(super) fn session_rows(&self) -> i64 {
        self.conn()
            .query_row("SELECT COUNT(*) FROM upstream_sessions", [], |row| {
                row.get(0)
            })
            .expect("count")
    }
}

/// What the scripted upstream does with each request.
#[derive(Clone)]
pub(super) enum Mode {
    /// JSON answers, with these extra headers on each.
    Json(Vec<(&'static str, &'static str)>),
    /// JSON answers, and notifications answered 202 as the TypeScript SDK does: text/plain, no body.
    TypeScript,
    /// JSON answers whose initialize and server/discover results declare listChanged and subscribe.
    Declares,
    /// JSON answers whose stateless tools/list also lists this tool, which the session form does not.
    StatelessOnly(&'static str),
    /// Event streams with a notice first; the answer is the last event. Extra headers on each.
    Stream(Vec<(&'static str, &'static str)>),
    /// A notice, then the answer one second later.
    Progress,
    /// Answers as the inner mode does, with the headers held back for the wait.
    Held(Duration, Box<Mode>),
    /// A notice and then no answer; the stream stays open.
    StreamNoAnswer,
    /// JSON answers with this exact body.
    Raw(&'static str),
    /// This status, content type and body, for every request.
    Status(u16, Option<&'static str>, &'static str),
    /// A 302 to another address.
    Redirect,
    /// Headers at once, then a JSON body that never ends.
    Stalled,
    /// Never answers.
    Silent,
    /// A JSON answer whose result is this many bytes long.
    Oversize(usize),
    /// JSON answers that carry this Mcp-Session-Id on every answer.
    Issued(String),
    /// JSON answers whose initialize issues the next counter-based id: sess-1, sess-2, and so on.
    Counted(Arc<AtomicUsize>),
    /// JSON answers with this status and body, each carrying the session id sess-1.
    Session(u16, &'static str),
    /// Event streams for every POST and GET: each chunk after its wait, then the tail. The body
    /// counts itself in `closed` when the server drops it.
    Chunks {
        chunks: Vec<(u64, String)>,
        tail: Tail,
        closed: Arc<AtomicUsize>,
    },
    /// An event stream that repeats one 64 KiB notice for ever, for a client that does not read.
    Endless { closed: Arc<AtomicUsize> },
}

/// What a scripted stream does after its last chunk.
#[derive(Clone, Copy)]
pub(super) enum Tail {
    /// The body ends.
    Close,
    /// The body stays open and silent.
    Hang,
}

/// A body stream that counts itself in `closed` when the server drops it.
struct Watched {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>,
    closed: Arc<AtomicUsize>,
}

impl Stream for Watched {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

/// The JSON-RPC answer the scripted upstream gives to a request, or None for a notification
/// or a response.
fn rpc_answer(seen: &Seen, tools: &[String]) -> Option<Value> {
    let request = seen.json();
    let method = request.get("method")?.as_str()?;
    let id = request.get("id")?.clone();
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "fake", "version": "0"},
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools.iter()
            .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
            .collect::<Vec<_>>()}),
        "tools/call" => {
            let name = request["params"]["name"].as_str().unwrap_or("");
            json!({"content": [{"type": "text", "text": format!("called: {name}")}]})
        }
        "server/discover" => json!({
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "cacheScope": "public",
        }),
        _ => {
            return Some(json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}}));
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// A reply with a status, optional content type and session id, extra headers and a body.
fn build(
    status: u16,
    content_type: Option<&str>,
    session: Option<&str>,
    extra: &[(&str, &str)],
    body: Body,
) -> Plan {
    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    match builder.body(body) {
        Ok(response) => Plan::Reply(response),
        Err(_) => Plan::Silent,
    }
}

/// One server-sent event carrying `data`.
pub(super) fn frame(data: &Value) -> Bytes {
    Bytes::from(format!("data: {data}\n\n"))
}

pub(super) fn notice() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"level": "info", "data": "working"}})
}

/// The answers the upstream gives to GET and DELETE, whatever the mode.
fn stream_or_close(seen: &Seen) -> Option<Plan> {
    match seen.method.as_str() {
        "DELETE" => Some(build(200, None, None, &[], Body::empty())),
        "GET" => Some(build(
            200,
            Some("text/event-stream"),
            None,
            &[],
            Body::from(": open\n\n"),
        )),
        _ => None,
    }
}

/// The capabilities of `Mode::Declares`: the four flags, with one other member in each group.
fn declared_capabilities() -> Value {
    json!({
        "tools": {"listChanged": true, "extra": 1},
        "resources": {"listChanged": true, "subscribe": true, "extra": true},
        "prompts": {"listChanged": true},
    })
}

/// How the scripted upstream answers one request under `mode`.
fn respond(mode: &Mode, tools: &[String], seen: &Seen) -> Plan {
    let message = rpc_answer(seen, tools);
    let session = (seen.rpc() == "initialize").then(|| match mode {
        Mode::Counted(next) => format!("sess-{}", next.fetch_add(1, Ordering::SeqCst) + 1),
        _ => "sess-1".to_owned(),
    });
    match mode {
        Mode::Json(extra) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(202, None, None, &[], Body::empty()),
                Some(message) => build(
                    200,
                    Some("application/json"),
                    session.as_deref(),
                    extra,
                    Body::from(message.to_string()),
                ),
            },
        },
        Mode::Declares => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(202, None, None, &[], Body::empty()),
                Some(mut message) => {
                    if let Some(capabilities) = message.pointer_mut("/result/capabilities") {
                        *capabilities = declared_capabilities();
                    }
                    build(
                        200,
                        Some("application/json"),
                        session.as_deref(),
                        &[],
                        Body::from(message.to_string()),
                    )
                }
            },
        },
        Mode::StatelessOnly(extra) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(202, None, None, &[], Body::empty()),
                Some(mut message) => {
                    let stateless = seen.header("mcp-protocol-version") == Some("2026-07-28");
                    if let Some(listed) = message
                        .pointer_mut("/result/tools")
                        .and_then(Value::as_array_mut)
                        && seen.rpc() == "tools/list"
                        && stateless
                    {
                        listed.push(json!({"name": extra, "inputSchema": {"type": "object"}}));
                    }
                    build(
                        200,
                        Some("application/json"),
                        session.as_deref(),
                        &[],
                        Body::from(message.to_string()),
                    )
                }
            },
        },
        Mode::TypeScript => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(
                    202,
                    Some("text/plain; charset=UTF-8"),
                    None,
                    &[],
                    Body::empty(),
                ),
                Some(message) => build(
                    200,
                    Some("application/json"),
                    session.as_deref(),
                    &[],
                    Body::from(message.to_string()),
                ),
            },
        },
        Mode::Stream(extra) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(202, None, None, &[], Body::empty()),
                Some(message) => {
                    let events = vec![
                        Ok::<Bytes, io::Error>(Bytes::from(": keep-alive\n\n")),
                        Ok(frame(&notice())),
                        Ok(frame(&message)),
                    ];
                    build(
                        200,
                        Some("text/event-stream"),
                        session.as_deref(),
                        extra,
                        Body::from_stream(stream::iter(events)),
                    )
                }
            },
        },
        Mode::Held(wait, inner) => match respond(inner, tools, seen) {
            Plan::Reply(response) => Plan::Late(*wait, response),
            other => other,
        },
        Mode::Progress => match message {
            None => build(202, None, None, &[], Body::empty()),
            Some(message) => {
                let first = vec![Ok::<Bytes, io::Error>(frame(&notice()))];
                let last = stream::once(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok::<Bytes, io::Error>(frame(&message))
                });
                build(
                    200,
                    Some("text/event-stream"),
                    None,
                    &[],
                    Body::from_stream(stream::iter(first).chain(last)),
                )
            }
        },
        Mode::StreamNoAnswer => {
            let first = vec![Ok::<Bytes, io::Error>(frame(&notice()))];
            build(
                200,
                Some("text/event-stream"),
                None,
                &[],
                Body::from_stream(stream::iter(first).chain(stream::pending())),
            )
        }
        Mode::Raw(body) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => build(200, Some("application/json"), None, &[], Body::from(*body)),
        },
        Mode::Status(status, content_type, body) => {
            build(*status, *content_type, None, &[], Body::from(*body))
        }
        Mode::Redirect => build(
            302,
            None,
            None,
            &[("location", "http://127.0.0.1:9/elsewhere")],
            Body::empty(),
        ),
        Mode::Stalled => {
            let head = vec![Ok::<Bytes, io::Error>(Bytes::from_static(b"{\"jsonrpc\":"))];
            build(
                200,
                Some("application/json"),
                None,
                &[],
                Body::from_stream(stream::iter(head).chain(stream::pending())),
            )
        }
        Mode::Issued(id) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(202, None, None, &[], Body::empty()),
                Some(message) => build(
                    200,
                    Some("application/json"),
                    Some(id.as_str()),
                    &[],
                    Body::from(message.to_string()),
                ),
            },
        },
        Mode::Counted(_) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => match message {
                None => build(202, None, None, &[], Body::empty()),
                Some(message) => build(
                    200,
                    Some("application/json"),
                    session.as_deref(),
                    &[],
                    Body::from(message.to_string()),
                ),
            },
        },
        Mode::Session(status, body) => match stream_or_close(seen) {
            Some(plan) => plan,
            None => build(
                *status,
                Some("application/json"),
                Some("sess-1"),
                &[],
                Body::from(*body),
            ),
        },
        Mode::Chunks {
            chunks,
            tail,
            closed,
        } => {
            if seen.method == "DELETE" {
                return build(200, None, None, &[], Body::empty());
            }
            let steps = stream::iter(chunks.clone()).then(|(wait, text)| async move {
                tokio::time::sleep(Duration::from_millis(wait)).await;
                Ok::<Bytes, io::Error>(Bytes::from(text))
            });
            let inner: Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>> = match tail {
                Tail::Close => Box::pin(steps),
                Tail::Hang => Box::pin(steps.chain(stream::pending())),
            };
            let watched = Watched {
                inner,
                closed: Arc::clone(closed),
            };
            build(
                200,
                Some("text/event-stream"),
                None,
                &[],
                Body::from_stream(watched),
            )
        }
        Mode::Endless { closed } => {
            if seen.method == "DELETE" {
                return build(200, None, None, &[], Body::empty());
            }
            let event = frame(&json!({"jsonrpc": "2.0", "method": "notifications/message",
                "params": {"level": "info", "data": "x".repeat(64 * 1024)}}));
            let inner: Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>> =
                Box::pin(stream::repeat(event).map(Ok::<Bytes, io::Error>));
            let watched = Watched {
                inner,
                closed: Arc::clone(closed),
            };
            build(
                200,
                Some("text/event-stream"),
                None,
                &[],
                Body::from_stream(watched),
            )
        }
        Mode::Silent => Plan::Silent,
        Mode::Oversize(size) => build(
            200,
            Some("application/json"),
            None,
            &[],
            Body::from(format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"pad":"{}"}}}}"#,
                "x".repeat(*size)
            )),
        ),
    }
}

/// A scripted upstream whose behaviour the test changes between requests.
pub(super) struct Fake {
    up: TestUpstream,
    mode: Arc<Mutex<Mode>>,
    names: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    pub(super) async fn start(tools: &[&str]) -> Fake {
        let mode = Arc::new(Mutex::new(Mode::Json(Vec::new())));
        let names = Arc::new(Mutex::new(
            tools
                .iter()
                .map(|tool| (*tool).to_owned())
                .collect::<Vec<_>>(),
        ));
        let (shared_mode, shared_names) = (Arc::clone(&mode), Arc::clone(&names));
        let up = TestUpstream::start(move |seen: &Seen| {
            let mode = shared_mode.lock().expect("mode").clone();
            let names = shared_names.lock().expect("names").clone();
            respond(&mode, &names, seen)
        })
        .await;
        Fake { up, mode, names }
    }

    pub(super) fn set(&self, mode: Mode) {
        *self.mode.lock().expect("mode") = mode;
    }

    pub(super) fn set_tools(&self, tools: &[&str]) {
        *self.names.lock().expect("names") = tools.iter().map(|tool| (*tool).to_owned()).collect();
    }

    pub(super) fn url(&self) -> String {
        self.up.url.clone()
    }

    pub(super) fn seen(&self) -> Vec<Seen> {
        self.up.seen()
    }

    pub(super) fn count(&self) -> usize {
        self.up.seen().len()
    }

    /// How many requests carried this JSON-RPC method.
    pub(super) fn calls(&self, method: &str) -> usize {
        self.up
            .seen()
            .iter()
            .filter(|seen| seen.rpc() == method)
            .count()
    }
}

/// A gateway with bob assigned to `demo`, a scripted upstream behind it, and a token for bob.
pub(super) struct Demo {
    pub(super) gw: Gw,
    pub(super) fake: Fake,
    pub(super) server: i64,
    pub(super) bob: i64,
    pub(super) token: String,
}

pub(super) async fn demo_with(edit: impl FnOnce(&mut Config), switches: (bool, bool)) -> Demo {
    let gw = Gw::start(edit).await;
    let fake = Fake::start(&["echo", "search"]).await;
    let server = gw.add_server("demo", &fake.url(), Some(SECRET), switches);
    let bob = gw.add_user(BOB);
    gw.grant(bob, server);
    let token = gw.token(bob, server);
    Demo {
        gw,
        fake,
        server,
        bob,
        token,
    }
}

pub(super) async fn demo() -> Demo {
    demo_with(|_| {}, (false, false)).await
}

/// The headers of a session-rules request, with `session` when given.
pub(super) fn session_headers(session: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2025-11-25".to_owned()),
    ];
    if let Some(session) = session {
        headers.push(("mcp-session-id", session.to_owned()));
    }
    headers
}

/// The headers of a stateless request for `method`, with `name` as Mcp-Name when given.
pub(super) fn stateless_headers(method: &str, name: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2026-07-28".to_owned()),
        ("mcp-method", method.to_owned()),
    ];
    if let Some(name) = name {
        headers.push(("mcp-name", name.to_owned()));
    }
    headers
}

pub(super) fn session_body(id: i64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

pub(super) fn stateless_body(id: i64, method: &str, params: Value) -> String {
    let mut params = params;
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}});
    session_body(id, method, params)
}

pub(super) fn initialize_body() -> String {
    session_body(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}),
    )
}

pub(super) fn call_body(id: i64, name: &str) -> String {
    session_body(id, "tools/call", json!({"name": name, "arguments": {}}))
}

/// A POST to demo with session headers and `body`.
pub(super) async fn session_post(demo: &Demo, session: Option<&str>, body: String) -> Reply {
    demo.gw
        .post("demo", &demo.token, session_headers(session), body)
        .await
}

/// Initializes bob's session on `demo` and returns the session id.
pub(super) async fn initialized(demo: &Demo) -> String {
    let reply = session_post(demo, None, initialize_body()).await;
    assert_eq!(reply.status, 200, "initialize must be relayed");
    reply
        .header("mcp-session-id")
        .expect("initialize must relay the session id")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_upstream_sees_only_the_allowed_headers() {
    let demo = demo().await;
    let noise = [
        ("cookie", "a=b"),
        ("last-event-id", "7"),
        ("forwarded", "for=203.0.113.9"),
        ("x-forwarded-for", "203.0.113.9"),
        ("x-forwarded-host", "example.com"),
        ("x-real-ip", "203.0.113.9"),
        ("via", "1.1 example"),
        ("x-custom-1", "1"),
        ("x-custom-2", "2"),
        ("x-custom-3", "3"),
        ("x-custom-4", "4"),
        ("x-custom-5", "5"),
        ("x-custom-6", "6"),
        ("x-custom-7", "7"),
        ("mcp-param-region", "eu"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "echo"),
        ("x-trace", "t"),
        ("referer", "https://example.com/x"),
    ];
    let mut headers = session_headers(None);
    headers.extend(
        noise
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    headers.push(("host", "example.com".to_owned()));
    headers.push(("origin", demo.gw.config.public_url.clone()));
    let reply = demo
        .gw
        .post("demo", &demo.token, headers, initialize_body())
        .await;
    assert_eq!(reply.status, 200, "the initialize must be relayed");
    let seen = demo.fake.seen();
    let request = seen.last().expect("the upstream must see the request");
    let allowed = [
        "content-type",
        "accept",
        "mcp-protocol-version",
        "user-agent",
        SECRET_NAME,
        "host",
        "content-length",
    ];
    for (name, _) in &request.headers {
        assert!(
            allowed.contains(&name.as_str()),
            "{name} must not reach the upstream"
        );
    }
    assert_eq!(
        request.header(SECRET_NAME),
        Some(SECRET),
        "the secret is sent"
    );
    assert_eq!(
        request.header("user-agent"),
        Some(concat!("doorward/", env!("CARGO_PKG_VERSION"))),
        "the gateway sends its own user agent"
    );
    assert!(
        request
            .header("host")
            .is_some_and(|host| host.starts_with("127.0.0.1:")),
        "the upstream sees the upstream's host, not the client's"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_headers_pass_and_mcp_name_is_not_sent_for_tools_list() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let mut headers = stateless_headers("tools/call", Some("echo"));
    headers.push(("mcp-param-region", "eu".to_owned()));
    headers.push(("cookie", "a=b".to_owned()));
    let body = stateless_body(1, "tools/call", json!({"name": "echo", "arguments": {}}));
    let reply = demo.gw.post("demo", &demo.token, headers, body).await;
    assert_eq!(reply.status, 200, "the stateless call must be relayed");
    let call = demo
        .fake
        .seen()
        .into_iter()
        .find(|seen| seen.rpc() == "tools/call")
        .expect("the call must reach the upstream");
    assert_eq!(call.header("mcp-method"), Some("tools/call"));
    assert_eq!(call.header("mcp-name"), Some("echo"));
    assert_eq!(call.header("mcp-param-region"), Some("eu"));
    assert_eq!(
        call.header("cookie"),
        None,
        "a cookie never reaches the upstream"
    );

    let headers = stateless_headers("tools/list", Some("echo"));
    let body = stateless_body(2, "tools/list", json!({}));
    let reply = demo.gw.post("demo", &demo.token, headers, body).await;
    assert_eq!(reply.status, 200, "the stateless list must be relayed");
    let list = demo
        .fake
        .seen()
        .into_iter()
        .rfind(|seen| seen.rpc() == "tools/list")
        .expect("the list must reach the upstream");
    assert_eq!(
        list.header("mcp-name"),
        None,
        "Mcp-Name is not sent for tools/list"
    );
    assert_eq!(list.header("mcp-method"), Some("tools/list"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_that_cannot_be_opened_sends_nothing() {
    let demo = demo().await;
    demo.gw
        .conn()
        .execute(
            "UPDATE servers SET secret_header_value = 'v1.not-a-secret' WHERE id = ?1",
            params![demo.server],
        )
        .expect("corrupt");
    let before = demo.fake.count();
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 502, "an unopenable secret is a fault");
    assert_eq!(reply.body, UNAVAILABLE);
    assert_eq!(
        demo.fake.count(),
        before,
        "no request may leave without the secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_fault_answers_the_same_502_with_no_upstream_header() {
    let demo = demo_with(
        |config| config.limits.upstream_timeout_seconds = 1,
        (false, false),
    )
    .await;
    let cases = [
        Mode::Status(500, None, "internal"),
        Mode::Status(401, None, ""),
        Mode::Status(403, None, ""),
        Mode::Redirect,
        Mode::Status(200, Some("text/html"), "<p>hi</p>"),
        Mode::Status(200, Some("application/json"), "not json at all"),
        Mode::Status(200, Some("application/json"), "[1,2]"),
        Mode::Status(200, None, ""),
        Mode::Stalled,
        Mode::Silent,
        Mode::Oversize(5 * 1024 * 1024),
    ];
    for mode in cases {
        demo.fake.set(mode);
        let reply = session_post(&demo, None, initialize_body()).await;
        assert_eq!(reply.status, 502, "every fault is a 502");
        assert_eq!(reply.body, UNAVAILABLE, "every fault has the same body");
        assert_eq!(reply.header("content-type"), Some("application/json"));
        for name in ["set-cookie", "www-authenticate", "location", "x-upstream"] {
            assert_eq!(reply.header(name), None, "{name} must not reach the client");
        }
        reply.assert_inert("a fault");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_upstream_is_the_same_502() {
    let demo = demo().await;
    demo.gw.set_url(demo.server, CLOSED_PORT);
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 502);
    assert_eq!(reply.body, UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_body_cap_is_exact() {
    let demo = demo_with(|config| config.limits.body_bytes = 512, (false, false)).await;
    let base = session_body(1, "ping", json!({"pad": ""}));
    let at_cap = format!("{base}{}", " ".repeat(512 - base.len()));
    assert_eq!(at_cap.len(), 512);
    let reply = session_post(&demo, None, at_cap).await;
    assert_eq!(reply.status, 200, "a body exactly at the cap is accepted");
    let over = format!("{base}{}", " ".repeat(513 - base.len()));
    let before = demo.fake.count();
    let reply = session_post(&demo, None, over).await;
    assert_eq!(reply.status, 413, "a body one byte over the cap is 413");
    assert_eq!(reply.body, "", "the 413 has an empty body");
    reply.assert_inert("the 413");
    assert_eq!(demo.fake.count(), before, "a refused body reaches nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn content_encoding_and_a_non_utf8_charset_are_refused() {
    let demo = demo().await;
    let before = demo.fake.count();
    let mut headers = session_headers(None);
    headers.push(("content-encoding", "gzip".to_owned()));
    let reply = demo
        .gw
        .post("demo", &demo.token, headers, initialize_body())
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));
    assert_eq!(reply.error_message().as_deref(), Some("Invalid request"));

    let mut headers = session_headers(None);
    headers[0] = (
        "content-type",
        "application/json; charset=utf-16".to_owned(),
    );
    let reply = demo
        .gw
        .post("demo", &demo.token, headers, initialize_body())
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));

    let mut headers = session_headers(None);
    headers[0] = ("content-type", "application/json; Charset=UTF-8".to_owned());
    let reply = demo
        .gw
        .post("demo", &demo.token, headers, initialize_body())
        .await;
    assert_eq!(reply.status, 200, "utf-8 in any case is accepted");
    assert_eq!(
        demo.fake.count(),
        before + 1,
        "only the accepted request is sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_byte_order_mark_is_refused() {
    let demo = demo().await;
    let before = demo.fake.count();
    let body = format!("\u{feff}{}", initialize_body());
    let reply = session_post(&demo, None, body).await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_json_is_a_parse_error_and_the_gateway_answers_the_next_request() {
    let demo = demo().await;
    let before = demo.fake.count();
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    let bodies = [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\ud800"}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"} x"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"method":"ping""#.to_owned(),
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{deep}}}"#),
    ];
    for body in bodies {
        let reply = session_post(&demo, None, body).await;
        assert_eq!(reply.status, 400, "a malformed body is a 400");
        assert_eq!(reply.error_code(), Some(-32700));
        assert_eq!(reply.error_message().as_deref(), Some("Parse error"));
        assert_eq!(
            reply.json()["id"],
            Value::Null,
            "the id is null before a message is read"
        );
    }
    assert_eq!(demo.fake.count(), before, "malformed bodies reach nothing");
    let reply = session_post(&demo, None, session_body(2, "ping", json!({}))).await;
    assert_eq!(reply.status, 200, "the gateway answers the next request");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_array_is_refused_under_both_generations() {
    let demo = demo().await;
    let before = demo.fake.count();
    let batch = format!("[{}]", session_body(1, "ping", json!({})));
    let reply = session_post(&demo, None, batch.clone()).await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));
    let reply = demo
        .gw
        .post("demo", &demo.token, stateless_headers("ping", None), batch)
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_protocol_version_is_refused_under_each_rule() {
    let demo = demo().await;
    let before = demo.fake.count();
    let mut headers = session_headers(None);
    headers.push(("mcp-protocol-version", "2025-11-25".to_owned()));
    let reply = demo
        .gw
        .post("demo", &demo.token, headers, initialize_body())
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600), "session rules: -32600");

    let mut headers = stateless_headers("ping", None);
    headers.push(("mcp-protocol-version", "2026-07-28".to_owned()));
    let body = stateless_body(1, "ping", json!({}));
    let reply = demo.gw.post("demo", &demo.token, headers, body).await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32020), "stateless rules: -32020");
    assert_eq!(
        reply.error_message().as_deref(),
        Some("Header mismatch: MCP-Protocol-Version")
    );
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_method_and_name_headers_must_match_the_body() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let before = demo.fake.count();
    let body = stateless_body(1, "tools/call", json!({"name": "echo", "arguments": {}}));
    let mut no_method = stateless_headers("tools/call", Some("echo"));
    no_method.retain(|(name, _)| *name != "mcp-method");
    let mut method_twice = stateless_headers("tools/call", Some("echo"));
    method_twice.push(("mcp-method", "tools/call".to_owned()));
    let mut no_name = stateless_headers("tools/call", None);
    no_name.retain(|(name, _)| *name != "mcp-name");
    let mut name_twice = stateless_headers("tools/call", Some("echo"));
    name_twice.push(("mcp-name", "echo".to_owned()));
    let cases = [
        (no_method, "Mcp-Method"),
        (method_twice, "Mcp-Method"),
        (stateless_headers("tools/list", Some("echo")), "Mcp-Method"),
        (no_name, "Mcp-Name"),
        (stateless_headers("tools/call", Some("search")), "Mcp-Name"),
        (name_twice, "Mcp-Name"),
    ];
    for (headers, label) in cases {
        let reply = demo
            .gw
            .post("demo", &demo.token, headers, body.clone())
            .await;
        assert_eq!(reply.status, 400, "a header mismatch is a 400");
        assert_eq!(reply.error_code(), Some(-32020));
        assert_eq!(
            reply.error_message(),
            Some(format!("Header mismatch: {label}")),
            "the message names the header"
        );
        assert_eq!(reply.json()["id"], json!(1), "the id is the request's id");
    }
    assert_eq!(demo.fake.count(), before, "a mismatch reaches nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_base64_name_is_decoded_before_it_is_compared() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let body = stateless_body(1, "tools/call", json!({"name": "echo", "arguments": {}}));
    let good = stateless_headers("tools/call", Some("=?base64?ZWNobw==?="));
    let reply = demo.gw.post("demo", &demo.token, good, body.clone()).await;
    assert_eq!(reply.status, 200, "the base64 form of echo is accepted");
    assert_eq!(reply.text_of_call().as_deref(), Some("called: echo"));
    let wrong = stateless_headers("tools/call", Some("=?base64?c2VhcmNo?="));
    let reply = demo.gw.post("demo", &demo.token, wrong, body).await;
    assert_eq!(reply.status, 400, "a base64 name that differs is refused");
    assert_eq!(reply.error_code(), Some(-32020));
}

#[tokio::test(flavor = "multi_thread")]
async fn methods_outside_the_allowlist_are_not_found() {
    let demo = demo().await;
    let before = demo.fake.count();
    for method in [
        "sampling/createMessage",
        "Tools/Call",
        "tools/call ",
        "tasks/list",
        "tasks/get",
    ] {
        let reply = session_post(&demo, None, session_body(7, method, json!({}))).await;
        assert_eq!(reply.status, 200, "{method:?} is answered in the body");
        assert_eq!(reply.error_code(), Some(-32601), "{method:?} is not found");
        assert_eq!(reply.json()["id"], json!(7));
    }
    assert_eq!(demo.fake.count(), before, "refused methods reach nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_parameter_is_not_found() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let before = demo.fake.count();
    let body = session_body(3, "tools/call", json!({"name": "echo", "task": {"ttl": 1}}));
    let reply = session_post(&demo, None, body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.error_code(), Some(-32601));
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_without_an_id_or_a_string_name_is_refused_without_an_activity_row() {
    let demo = demo().await;
    let before = demo.fake.count();
    let no_id = json!({"jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "echo"}})
    .to_string();
    let reply = session_post(&demo, None, no_id).await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));
    for params in [json!({"name": 5}), json!({}), json!({"name": null})] {
        let reply = session_post(&demo, None, session_body(4, "tools/call", params)).await;
        assert_eq!(reply.status, 400, "a call without a string name is a 400");
        assert_eq!(reply.error_code(), Some(-32600));
        assert_eq!(reply.json()["id"], json!(4));
    }
    assert_eq!(demo.fake.count(), before);
    assert!(
        demo.gw.tool_calls().is_empty(),
        "a refused call writes no activity row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_response_without_a_session_or_under_stateless_rules_is_refused() {
    let demo = demo().await;
    let before = demo.fake.count();
    let answer = json!({"jsonrpc": "2.0", "id": 5, "result": {}}).to_string();
    let reply = session_post(&demo, None, answer).await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32600));
    let body = json!({"jsonrpc": "2.0", "id": 5, "result": {}, "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}})
    .to_string();
    let reply = demo
        .gw
        .post("demo", &demo.token, stateless_headers("ping", None), body)
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(
        reply.error_code(),
        Some(-32600),
        "a stateless response is -32600"
    );
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_notice_answered_202_as_text_is_relayed_empty() {
    let demo = demo().await;
    demo.fake.set(Mode::TypeScript);
    let session = initialized(&demo).await;
    let before = demo.fake.count();
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string();
    let reply = session_post(&demo, Some(&session), note).await;
    assert_eq!(reply.status, 202, "a 202 notice answer is accepted");
    assert_eq!(reply.body, "", "the upstream's body is never relayed");
    assert_eq!(
        reply.header("content-type"),
        None,
        "no content type is sent"
    );
    reply.assert_inert("the 202");
    assert_eq!(
        demo.fake.count(),
        before + 1,
        "the notice reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notice_answered_200_with_no_body_keeps_the_upstream_status() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Status(200, Some("text/plain"), ""));
    let before = demo.fake.count();
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string();
    let reply = session_post(&demo, Some(&session), note).await;
    assert_eq!(reply.status, 200, "an empty notice answer keeps its status");
    assert_eq!(reply.body, "");
    assert_eq!(
        reply.header("content-type"),
        None,
        "no content type is sent"
    );
    assert_eq!(
        demo.fake.count(),
        before + 1,
        "the notice reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_answer_to_a_request_is_a_502_with_a_null_id() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    demo.fake
        .set(Mode::Status(202, Some("text/plain; charset=UTF-8"), ""));
    let reply = session_post(&demo, Some(&session), session_body(6, "ping", json!({}))).await;
    assert_eq!(
        reply.status, 502,
        "an empty answer to a request is unavailable"
    );
    assert_eq!(
        reply.json(),
        json!({"jsonrpc": "2.0", "id": null,
            "error": {"code": -32000, "message": "Upstream demo is unavailable"}})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_methods_the_server_does_not_implement_are_404() {
    let demo = demo().await;
    let before = demo.fake.count();
    for method in [
        "ping",
        "initialize",
        "logging/setLevel",
        "resources/subscribe",
        "tasks/get",
        "no/such",
    ] {
        let reply = demo
            .gw
            .post(
                "demo",
                &demo.token,
                stateless_headers(method, None),
                stateless_body(7, method, json!({})),
            )
            .await;
        assert_eq!(reply.status, 404, "stateless {method:?} is 404");
        assert_eq!(reply.error_code(), Some(-32601), "stateless {method:?}");
        assert_eq!(reply.error_message().as_deref(), Some("Method not found"));
        assert_eq!(reply.json()["id"], json!(7), "the id is the request's id");
        reply.assert_inert("the 404");
    }
    assert_eq!(demo.fake.count(), before, "refused methods reach nothing");
    for method in ["resources/subscribe", "tasks/get", "no/such"] {
        let reply = session_post(&demo, None, session_body(8, method, json!({}))).await;
        assert_eq!(reply.status, 200, "session {method:?} stays 200");
        assert_eq!(reply.error_code(), Some(-32601), "session {method:?}");
        assert_eq!(reply.json()["id"], json!(8));
    }
    assert_eq!(demo.fake.count(), before, "refused methods reach nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_body_without_a_protocol_version_is_invalid_params() {
    let demo = demo().await;
    let before = demo.fake.count();
    let headers = stateless_headers("tools/list", None);
    let bodies = [
        session_body(3, "tools/list", json!({})),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).to_string(),
        session_body(
            3,
            "tools/list",
            json!({"_meta": {
                "io.modelcontextprotocol/clientInfo": {},
                "io.modelcontextprotocol/clientCapabilities": {},
            }}),
        ),
        session_body(
            3,
            "tools/list",
            json!({"_meta": {"io.modelcontextprotocol/protocolVersion": 20260728}}),
        ),
    ];
    for body in bodies {
        let reply = demo
            .gw
            .post("demo", &demo.token, headers.clone(), body)
            .await;
        assert_eq!(reply.status, 400, "a body without the version is a 400");
        assert_eq!(reply.error_code(), Some(-32602));
        assert_eq!(
            reply.error_message().as_deref(),
            Some("Invalid params: missing _meta, protocol version or client capabilities")
        );
        assert_eq!(reply.json()["id"], json!(3), "the id is the request's id");
    }
    let mismatched = stateless_headers("tools/call", None);
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            mismatched,
            session_body(3, "tools/list", json!({})),
        )
        .await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "the missing version is judged before the Mcp-Method header"
    );
    assert_eq!(demo.fake.count(), before, "a refused body reaches nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_request_without_client_capabilities_is_invalid_params() {
    let demo = demo().await;
    let before = demo.fake.count();
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"}});
    for method in ["server/discover", "tools/list"] {
        let body = json!({"jsonrpc": "2.0", "id": 11, "method": method,
            "params": {"_meta": meta}})
        .to_string();
        let reply = demo
            .gw
            .post("demo", &demo.token, stateless_headers(method, None), body)
            .await;
        assert_eq!(reply.status, 400, "{method} without client capabilities");
        assert_eq!(reply.error_code(), Some(-32602));
        assert_eq!(
            reply.error_message().as_deref(),
            Some("Invalid params: missing _meta, protocol version or client capabilities")
        );
        assert_eq!(reply.json()["id"], json!(11), "the id is the request's");
    }
    assert_eq!(demo.fake.count(), before, "the upstream sees no request");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_capabilities_that_are_not_an_object_are_invalid_params() {
    let demo = demo().await;
    let before = demo.fake.count();
    for capabilities in [json!("x"), json!(null), json!([]), json!(true)] {
        let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities});
        let body = json!({"jsonrpc": "2.0", "id": 12, "method": "tools/list",
            "params": {"_meta": meta}})
        .to_string();
        let reply = demo
            .gw
            .post(
                "demo",
                &demo.token,
                stateless_headers("tools/list", None),
                body,
            )
            .await;
        assert_eq!(reply.status, 400, "{capabilities} is not an object");
        assert_eq!(reply.error_code(), Some(-32602));
        assert_eq!(reply.json()["id"], json!(12));
    }
    assert_eq!(demo.fake.count(), before, "the upstream sees no request");
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_client_capabilities_without_client_info_are_accepted() {
    let demo = demo().await;
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}});
    for method in ["server/discover", "tools/list"] {
        let body = json!({"jsonrpc": "2.0", "id": 13, "method": method,
            "params": {"_meta": meta}})
        .to_string();
        let reply = demo
            .gw
            .post("demo", &demo.token, stateless_headers(method, None), body)
            .await;
        assert_eq!(
            reply.status, 200,
            "{method} with empty capabilities is answered"
        );
        assert!(
            reply.json()["result"].is_object(),
            "{method} answers a result"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_notification_without_client_capabilities_is_still_accepted() {
    let demo = demo().await;
    let before = demo.fake.count();
    let body = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}})
    .to_string();
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("notifications/cancelled", None),
            body,
        )
        .await;
    assert_eq!(
        reply.status, 202,
        "a notification needs no client capabilities"
    );
    assert_eq!(
        demo.fake.count(),
        before + 1,
        "the notification is forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_notification_needs_no_metadata() {
    let demo = demo().await;
    let bodies = [
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled"}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 1, "_meta": {}}}),
    ];
    for value in bodies {
        let before = demo.fake.count();
        let body = value.to_string();
        let reply = demo
            .gw
            .post(
                "demo",
                &demo.token,
                stateless_headers("notifications/cancelled", None),
                body.clone(),
            )
            .await;
        assert_eq!(reply.status, 202, "{body} is accepted");
        assert_eq!(demo.fake.count(), before + 1, "{body} is forwarded once");
        let seen = demo.fake.seen();
        let forwarded = seen.last().expect("one forwarded request");
        assert_eq!(forwarded.body, body.as_bytes(), "forwarded byte-equal");
    }
    let before = demo.fake.count();
    let request = json!({"jsonrpc": "2.0", "id": 15, "method": "tools/list"}).to_string();
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            request,
        )
        .await;
    assert_eq!(reply.status, 400, "a request with no _meta is refused");
    assert_eq!(reply.error_code(), Some(-32602));
    assert_eq!(reply.json()["id"], json!(15));
    assert_eq!(demo.fake.count(), before, "the upstream sees no request");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_notification_version_is_checked_when_present() {
    let demo = demo().await;
    let before = demo.fake.count();
    let different = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}}})
    .to_string();
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("notifications/cancelled", None),
            different,
        )
        .await;
    assert_eq!(reply.status, 400, "a different version is refused");
    assert_eq!(reply.error_code(), Some(-32020));
    assert_eq!(
        reply.error_message().as_deref(),
        Some("Header mismatch: MCP-Protocol-Version")
    );
    for version in [json!(7), json!(null), json!(true), json!([]), json!({})] {
        let body = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": version}}})
        .to_string();
        let reply = demo
            .gw
            .post(
                "demo",
                &demo.token,
                stateless_headers("notifications/cancelled", None),
                body,
            )
            .await;
        assert_eq!(reply.status, 400, "{version} is not a version string");
        assert_eq!(reply.error_code(), Some(-32602));
        assert_eq!(
            reply.error_message().as_deref(),
            Some("Invalid params: missing _meta, protocol version or client capabilities")
        );
        assert!(reply.json()["id"].is_null(), "a notification has no id");
    }
    assert_eq!(
        demo.fake.count(),
        before,
        "the upstream sees no notification"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_notification_keeps_the_method_header_rule() {
    let demo = demo().await;
    let before = demo.fake.count();
    let body = json!({"jsonrpc": "2.0", "method": "notifications/cancelled"}).to_string();
    let mut missing = stateless_headers("notifications/cancelled", None);
    missing.retain(|(name, _)| *name != "mcp-method");
    let other = stateless_headers("notifications/progress", None);
    for headers in [missing, other] {
        let reply = demo
            .gw
            .post("demo", &demo.token, headers, body.clone())
            .await;
        assert_eq!(reply.status, 400, "the Mcp-Method header must match");
        assert_eq!(reply.error_code(), Some(-32020));
        assert_eq!(
            reply.error_message().as_deref(),
            Some("Header mismatch: Mcp-Method")
        );
    }
    assert_eq!(
        demo.fake.count(),
        before,
        "the upstream sees no notification"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_meta_version_that_differs_from_the_header_stays_32020() {
    let demo = demo().await;
    let before = demo.fake.count();
    let body = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25", "io.modelcontextprotocol/clientCapabilities": {}}}})
    .to_string();
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            body,
        )
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32020));
    assert_eq!(
        reply.error_message().as_deref(),
        Some("Header mismatch: MCP-Protocol-Version")
    );
    assert_eq!(reply.json()["id"], json!(4));
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_subscriptions_listen_is_refused_without_an_upstream_request() {
    let demo = demo().await;
    demo.fake.set(Mode::Stalled);
    let before = demo.fake.count();
    let body = stateless_body(9, "subscriptions/listen", json!({"notifications": {}}));
    let reply = timeout(
        Duration::from_secs(1),
        demo.gw.post(
            "demo",
            &demo.token,
            stateless_headers("subscriptions/listen", None),
            body,
        ),
    )
    .await
    .expect("the refusal is answered within one second");
    assert_eq!(reply.status, 404, "a stateless subscriptions/listen is 404");
    assert_eq!(reply.error_code(), Some(-32601));
    assert_eq!(reply.json()["id"], json!(9), "the id is the request's");
    assert_eq!(demo.fake.count(), before, "the upstream sees no request");

    let reply = timeout(
        Duration::from_secs(1),
        session_post(
            &demo,
            None,
            session_body(10, "subscriptions/listen", json!({"notifications": {}})),
        ),
    )
    .await
    .expect("the session refusal is answered within one second");
    assert_eq!(
        reply.status, 200,
        "a session subscriptions/listen stays 200"
    );
    assert_eq!(reply.error_code(), Some(-32601));
    assert_eq!(demo.fake.count(), before, "the upstream sees no request");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_discover_does_not_advertise_listchanged_or_subscribe() {
    let demo = demo_with(|_| {}, (true, true)).await;
    demo.fake.set(Mode::Declares);
    let body = stateless_body(2, "server/discover", json!({}));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("server/discover", None),
            body,
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json()["result"]["capabilities"],
        json!({"tools": {"extra": 1}, "resources": {"extra": true}, "prompts": {}}),
        "the four flags are gone and every other member is kept"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_initialize_keeps_the_listchanged_and_subscribe_flags() {
    let demo = demo_with(|_| {}, (true, true)).await;
    demo.fake.set(Mode::Declares);
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json()["result"]["capabilities"],
        declared_capabilities(),
        "the session initialize is relayed unchanged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_two_line_json_answer_is_a_prompt_502() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Status(
        200,
        Some("application/json"),
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{}}\n",
    ));
    let reply = timeout(
        Duration::from_secs(2),
        session_post(&demo, Some(&session), session_body(6, "ping", json!({}))),
    )
    .await
    .expect("the answer comes promptly");
    assert_eq!(reply.status, 502, "two JSON values are not one answer");
    assert_eq!(
        reply.json(),
        json!({"jsonrpc": "2.0", "id": null,
            "error": {"code": -32000, "message": "Upstream demo is unavailable"}})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_listed_only_on_the_stateless_form_is_called_through() {
    let demo = demo().await;
    demo.fake.set(Mode::StatelessOnly("extra"));
    let listed = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            stateless_body(1, "tools/list", json!({})),
        )
        .await;
    assert_eq!(listed.status, 200, "the stateless list is relayed");
    let listed_json = listed.json();
    let names: Vec<&str> = listed_json["result"]["tools"]
        .as_array()
        .expect("the tool list")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(
        names.contains(&"extra"),
        "the stateless list holds extra, got {names:?}"
    );
    let call = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/call", Some("extra")),
            stateless_body(2, "tools/call", json!({"name": "extra", "arguments": {}})),
        )
        .await;
    assert_eq!(call.status, 200, "the call is relayed");
    assert_eq!(call.text_of_call().as_deref(), Some("called: extra"));
    assert_eq!(
        demo.fake.calls("tools/call"),
        1,
        "the call reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_response_with_the_callers_session_reaches_the_upstream() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let before = demo.fake.count();
    let answer = json!({"jsonrpc": "2.0", "id": 9, "result": {}}).to_string();
    let reply = session_post(&demo, Some(&session), answer).await;
    assert_eq!(reply.status, 202, "the upstream's 202 is relayed");
    assert_eq!(
        demo.fake.count(),
        before + 1,
        "the response reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notification_that_is_not_forwarded_is_answered_202() {
    let demo = demo().await;
    let before = demo.fake.count();
    let note = json!({"jsonrpc": "2.0", "method": "sampling/notify"}).to_string();
    let reply = session_post(&demo, None, note).await;
    assert_eq!(reply.status, 202);
    assert_eq!(reply.body, "");
    reply.assert_inert("the 202");
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_list_is_answered_by_the_gateway() {
    let demo = demo().await;
    let before = demo.fake.count();
    let reply = session_post(&demo, None, session_body(3, "resources/list", json!({}))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({"jsonrpc": "2.0", "id": 3, "result": {"resources": []}})
    );
    assert_eq!(demo.fake.count(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_missing_from_the_catalog_refreshes_once_then_is_unknown() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let lists = demo.fake.calls("tools/list");
    let reply = session_post(&demo, None, call_body(6, "nope")).await;
    assert_eq!(reply.status, 200, "an unknown tool is answered in the body");
    assert_eq!(reply.error_code(), Some(-32602));
    assert_eq!(reply.error_message().as_deref(), Some("Unknown tool: nope"));
    assert_eq!(reply.json()["id"], json!(6));
    assert_eq!(
        demo.fake.calls("tools/list") - lists,
        1,
        "a miss refreshes the catalog exactly once"
    );
    assert_eq!(
        demo.fake.calls("tools/call"),
        0,
        "the upstream never sees the call"
    );
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 1, "one activity row for the refused call");
    assert_eq!(rows[0].tool, "nope");
    assert_eq!(rows[0].decision, "deny");
    assert_eq!(rows[0].outcome, "refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn names_that_only_look_alike_are_unknown() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    for name in [
        "Echo",
        " echo",
        "echo ",
        "ec\u{200b}ho",
        "\u{0435}cho",
        "echo\u{feff}",
    ] {
        let reply = session_post(&demo, None, call_body(1, name)).await;
        assert_eq!(reply.error_code(), Some(-32602), "{name:?} is unknown");
    }
    assert_eq!(
        demo.fake.calls("tools/call"),
        0,
        "the upstream never sees a look-alike"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_the_upstream_gained_is_called_without_a_manual_refresh() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    demo.fake.set_tools(&["echo", "gamma"]);
    let lists = demo.fake.calls("tools/list");
    let reply = session_post(&demo, None, call_body(2, "gamma")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.text_of_call().as_deref(), Some("called: gamma"));
    assert_eq!(
        demo.fake.calls("tools/list") - lists,
        1,
        "exactly one refresh"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_id_is_recorded_only_from_a_relayed_initialize() {
    let demo = demo().await;
    demo.fake
        .set(Mode::Json(vec![("mcp-session-id", "other-1")]));
    let reply = session_post(&demo, None, session_body(1, "tools/list", json!({}))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("mcp-session-id"),
        None,
        "a list never relays a session id"
    );
    let reply = session_post(
        &demo,
        Some("other-1"),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 404, "an id from a list is not a session");
    assert_eq!(demo.gw.session_rows(), 0, "nothing was recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_belongs_to_one_user_family_and_server() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let carol = demo.gw.add_user(CAROL);
    demo.gw.grant(carol, demo.server);
    let carol_token = demo.gw.token(carol, demo.server);
    let other_family = demo.gw.token(demo.bob, demo.server);
    let other = demo
        .gw
        .add_server("other", &demo.fake.url(), None, (false, false));
    demo.gw.grant(demo.bob, other);
    let other_token = demo.gw.token(demo.bob, other);

    let before = demo.fake.count();
    let checks = [
        (carol_token, "demo", session.clone()),
        (other_family, "demo", session.clone()),
        (other_token, "other", session.clone()),
        (demo.token.clone(), "demo", "invented-session".to_owned()),
    ];
    for (token, slug, id) in checks {
        let reply = demo
            .gw
            .post(
                slug,
                &token,
                session_headers(Some(&id)),
                session_body(2, "tools/list", json!({})),
            )
            .await;
        assert_eq!(reply.status, 404, "a POST with {id:?} must be 404");
        let reply = demo
            .gw
            .send(
                reqwest::Method::GET,
                &format!("/{slug}"),
                Some(&token),
                vec![("mcp-session-id", id.clone())],
                None,
            )
            .await;
        assert_eq!(reply.status, 404, "a GET with {id:?} must be 404");
        let reply = demo
            .gw
            .send(
                reqwest::Method::DELETE,
                &format!("/{slug}"),
                Some(&token),
                vec![("mcp-session-id", id.clone())],
                None,
            )
            .await;
        assert_eq!(reply.status, 404, "a DELETE with {id:?} must be 404");
    }
    let mut repeated = session_headers(Some(&session));
    repeated.push(("mcp-session-id", session.clone()));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            repeated,
            session_body(2, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 404, "a repeated session header is 404");
    assert_eq!(
        demo.fake.count(),
        before,
        "refused sessions reach no upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_id_issued_twice_is_relayed_without_the_header_and_not_rebound() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let carol = demo.gw.add_user(CAROL);
    demo.gw.grant(carol, demo.server);
    let carol_token = demo.gw.token(carol, demo.server);
    let reply = demo
        .gw
        .post(
            "demo",
            &carol_token,
            session_headers(None),
            initialize_body(),
        )
        .await;
    assert_eq!(reply.status, 200, "the second initialize is relayed");
    assert_eq!(
        reply.header("mcp-session-id"),
        None,
        "the id is not relayed twice"
    );
    let reply = demo
        .gw
        .post(
            "demo",
            &carol_token,
            session_headers(Some(&session)),
            session_body(2, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 404, "carol does not own bob's id");
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(3, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 200, "bob's session keeps working");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_session_id_on_initialize_never_reaches_the_upstream() {
    let demo = demo().await;
    let reply = session_post(&demo, Some("planted"), initialize_body()).await;
    assert_eq!(reply.status, 200, "the initialize is relayed");
    let init = demo
        .fake
        .seen()
        .into_iter()
        .find(|seen| seen.rpc() == "initialize")
        .expect("the initialize reaches the upstream");
    assert_eq!(
        init.header("mcp-session-id"),
        None,
        "the planted id is dropped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_forgets_the_session_even_when_the_upstream_faults() {
    let demo = demo_with(
        |config| config.limits.upstream_timeout_seconds = 1,
        (false, false),
    )
    .await;
    let session = initialized(&demo).await;
    let reply = demo
        .gw
        .send(
            reqwest::Method::DELETE,
            "/demo",
            Some(&demo.token),
            vec![("mcp-session-id", session.clone())],
            None,
        )
        .await;
    assert_eq!(reply.status, 200, "the DELETE is relayed");
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(
        reply.status, 404,
        "the next request on the ended session is 404"
    );

    let session = initialized(&demo).await;
    demo.fake.set(Mode::Status(500, None, ""));
    let reply = demo
        .gw
        .send(
            reqwest::Method::DELETE,
            "/demo",
            Some(&demo.token),
            vec![("mcp-session-id", session.clone())],
            None,
        )
        .await;
    assert_eq!(reply.status, 502, "a DELETE the upstream fails is a 502");
    demo.fake.set(Mode::Json(Vec::new()));
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(3, "tools/list", json!({})),
    )
    .await;
    assert_eq!(
        reply.status, 404,
        "the session is forgotten despite the fault"
    );

    let session = initialized(&demo).await;
    demo.fake.set(Mode::Silent);
    let reply = demo
        .gw
        .send(
            reqwest::Method::DELETE,
            "/demo",
            Some(&demo.token),
            vec![("mcp-session-id", session.clone())],
            None,
        )
        .await;
    assert_eq!(reply.status, 502, "a DELETE without an answer is a 502");
    demo.fake.set(Mode::Json(Vec::new()));
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(4, "tools/list", json!({})),
    )
    .await;
    assert_eq!(
        reply.status, 404,
        "the session is forgotten when no answer came"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stored_row_holds_no_session_id_in_the_clear() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    assert_eq!(demo.gw.session_rows(), 1, "the session is recorded");
    let rows = demo.gw.dump("upstream_sessions");
    assert!(
        !rows.contains(&session),
        "the stored row must not hold the id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn set_cookie_www_authenticate_location_and_unknown_headers_never_pass() {
    let extra = [
        ("set-cookie", "upstream=1; Path=/"),
        ("www-authenticate", "Basic realm=\"up\""),
        ("location", "http://127.0.0.1:9/elsewhere"),
        ("x-unknown", "1"),
    ];
    let demo = demo().await;
    demo.fake.set(Mode::Json(extra.to_vec()));
    let init = session_post(&demo, None, initialize_body()).await;
    assert_eq!(init.status, 200);
    let session = init.header("mcp-session-id").map(str::to_owned);
    let call = session_post(&demo, session.as_deref(), call_body(2, "echo")).await;
    assert_eq!(call.status, 200);
    for reply in [&init, &call] {
        for (name, _) in extra {
            assert_eq!(reply.header(name), None, "{name} must not pass on JSON");
        }
    }
    demo.fake.set(Mode::Stream(extra.to_vec()));
    let reply = session_post(&demo, None, call_body(3, "echo")).await;
    assert_eq!(reply.status, 200);
    for (name, _) in extra {
        assert_eq!(reply.header(name), None, "{name} must not pass on a stream");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_400_404_and_405_json_bodies_are_relayed_byte_for_byte() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"nope"}}"#;
    for status in [400, 404, 405] {
        demo.fake
            .set(Mode::Status(status, Some("application/json"), body));
        let reply = session_post(&demo, None, call_body(1, "echo")).await;
        assert_eq!(reply.status, status, "{status} is relayed");
        assert_eq!(reply.body, body, "the body is relayed byte for byte");
        assert_eq!(reply.header("content-type"), Some("application/json"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_are_trimmed_per_switch_as_json_and_as_a_stream() {
    let demo = demo_with(|_| {}, (false, true)).await;
    let reply = session_post(&demo, None, initialize_body()).await;
    let caps = &reply.json()["result"]["capabilities"];
    assert!(
        caps.get("resources").is_none(),
        "resources is removed while off"
    );
    assert!(caps.get("prompts").is_some(), "prompts stays while on");
    assert!(caps.get("tools").is_some());

    demo.fake.set(Mode::Stream(Vec::new()));
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let caps = &reply.json()["result"]["capabilities"];
    assert!(caps.get("resources").is_none(), "a stream is trimmed too");
    assert!(caps.get("prompts").is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn with_both_switches_on_the_upstream_bytes_are_unchanged() {
    let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{},"resources":{},"prompts":{}}}}"#;
    let demo = demo_with(|_| {}, (true, true)).await;
    demo.fake.set(Mode::Raw(raw));
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(
        reply.body, raw,
        "nothing is removed, so nothing is re-serialised"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_list_carries_cache_scope_private() {
    let demo = demo().await;
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"}],"cacheScope":"public"}}"#,
    ));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            stateless_body(1, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["result"]["cacheScope"], "private");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_list_replaces_the_catalog_unless_there_is_a_cursor_or_a_next_cursor() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["old"]);
    demo.fake.set_tools(&["alpha", "beta"]);
    let reply = session_post(&demo, None, session_body(1, "tools/list", json!({}))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        demo.gw.catalog_names(demo.server),
        ["alpha", "beta"],
        "the first page replaces the catalog"
    );
    let lists = demo.fake.calls("tools/list");
    let reply = session_post(&demo, None, call_body(2, "alpha")).await;
    assert_eq!(reply.text_of_call().as_deref(), Some("called: alpha"));
    assert_eq!(
        demo.fake.calls("tools/list"),
        lists,
        "a replaced name needs no refresh"
    );

    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"gamma"}]}}"#,
    ));
    let reply = session_post(
        &demo,
        None,
        session_body(3, "tools/list", json!({"cursor": "c1"})),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        demo.gw.catalog_names(demo.server),
        ["alpha", "beta"],
        "a cursor leaves the catalog alone"
    );

    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delta"}],"nextCursor":"n"}}"#,
    ));
    let reply = session_post(&demo, None, session_body(4, "tools/list", json!({}))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        demo.gw.catalog_names(demo.server),
        ["alpha", "beta"],
        "a nextCursor leaves the catalog alone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_list_answered_as_a_stream_that_never_answers_is_a_502_in_time() {
    let demo = demo_with(
        |config| config.limits.upstream_timeout_seconds = 1,
        (false, false),
    )
    .await;
    demo.fake.set(Mode::StreamNoAnswer);
    let started = Instant::now();
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            stateless_body(1, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 502, "a list that never answers is a fault");
    assert_eq!(reply.body, UNAVAILABLE);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the fault comes within the time limit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_list_answered_as_a_stream_is_relayed_as_json_and_replaces_the_catalog() {
    let demo = demo().await;
    demo.fake.set(Mode::Stream(Vec::new()));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            stateless_body(1, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(reply.json()["result"]["cacheScope"], "private");
    assert_eq!(demo.gw.catalog_names(demo.server), ["echo", "search"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_answered_as_a_stream_reaches_the_client_before_the_end() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    demo.fake.set(Mode::Progress);
    let started = Instant::now();
    let mut response = demo
        .gw
        .http
        .post(format!("{}/demo", demo.gw.base))
        .bearer_auth(&demo.token)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .body(call_body(1, "echo"))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let first = response
        .chunk()
        .await
        .expect("chunk")
        .expect("a first event");
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "the first event arrives before the upstream sends the last one"
    );
    assert!(String::from_utf8_lossy(&first).contains("notifications/message"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_get_and_delete_are_405_and_a_session_get_without_the_header_is_405() {
    let demo = demo().await;
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let stateless = vec![("mcp-protocol-version", "2026-07-28".to_owned())];
        let reply = demo
            .gw
            .send(method.clone(), "/demo", Some(&demo.token), stateless, None)
            .await;
        assert_eq!(reply.status, 405, "{method} under stateless rules is 405");
        assert_eq!(reply.header("allow"), Some("POST"));
        reply.assert_inert("the 405");
        let reply = demo
            .gw
            .send(method.clone(), "/demo", Some(&demo.token), Vec::new(), None)
            .await;
        assert_eq!(reply.status, 405, "{method} without a session is 405");
        assert_eq!(reply.header("allow"), Some("POST"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_get_reaches_the_upstream_with_the_session() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let reply = demo
        .gw
        .send(
            reqwest::Method::GET,
            "/demo",
            Some(&demo.token),
            vec![
                ("mcp-session-id", session.clone()),
                ("accept", "text/event-stream".to_owned()),
            ],
            None,
        )
        .await;
    assert_eq!(reply.status, 200, "the GET is relayed");
    assert_eq!(reply.header("content-type"), Some("text/event-stream"));
    let get = demo
        .fake
        .seen()
        .into_iter()
        .find(|seen| seen.method == "GET")
        .expect("the GET reaches the upstream");
    assert_eq!(get.header("mcp-session-id"), Some(session.as_str()));
    assert_eq!(get.header(SECRET_NAME), Some(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn activity_rows_hold_ok_error_unavailable_and_refused_calls() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let reply = session_post(&demo, None, call_body(1, "echo")).await;
    assert_eq!(reply.status, 200);
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}"#,
    ));
    let reply = session_post(&demo, None, call_body(2, "echo")).await;
    assert_eq!(reply.status, 200);
    demo.fake.set(Mode::Status(
        400,
        Some("application/json"),
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"x"}}"#,
    ));
    let reply = session_post(&demo, None, call_body(3, "echo")).await;
    assert_eq!(reply.status, 400);
    demo.fake.set(Mode::Status(500, None, ""));
    let reply = session_post(&demo, None, call_body(4, "echo")).await;
    assert_eq!(reply.status, 502);
    demo.fake.set(Mode::Json(Vec::new()));
    let reply = session_post(&demo, None, call_body(5, "gone")).await;
    assert_eq!(reply.error_code(), Some(-32602));

    let rows = demo.gw.tool_calls();
    let outcomes: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|row| {
            (
                row.tool.as_str(),
                row.decision.as_str(),
                row.outcome.as_str(),
            )
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            ("echo", "allow", "ok"),
            ("echo", "allow", "error"),
            ("echo", "allow", "error"),
            ("echo", "allow", "unavailable"),
            ("gone", "deny", "refused"),
        ]
    );
    for row in &rows {
        assert_eq!(row.user_id, Some(demo.bob));
        assert_eq!(row.email, BOB);
        assert_eq!(row.server_id, Some(demo.server));
        assert_eq!(row.slug, "demo");
        assert_eq!(row.client, CLIENT);
        assert!(
            row.duration.is_some_and(|ms| ms >= 0),
            "a duration is recorded"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn arguments_and_results_are_in_no_activity_row() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"CANARY-result"}]}}"#,
    ));
    let body = session_body(
        1,
        "tools/call",
        json!({"name": "echo", "arguments": {"text": "CANARY-args"}}),
    );
    let reply = session_post(&demo, None, body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(demo.gw.tool_calls().len(), 1);
    let dump = demo.gw.dump("activity");
    assert!(!dump.contains("CANARY-args"), "arguments are not stored");
    assert!(!dump.contains("CANARY-result"), "results are not stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_multi_byte_tool_name_is_cut_at_a_character_boundary_under_128_bytes() {
    let demo = demo().await;
    // U+20AC is 3 bytes: 128 is inside the 43rd character, so the cut must step back to 126.
    let name = "\u{20ac}".repeat(100);
    assert_eq!(name.len(), 300);
    let reply = session_post(&demo, None, call_body(1, &name)).await;
    assert_eq!(reply.error_code(), Some(-32602));
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].tool.len(),
        126,
        "the stored name is cut to 42 whole characters"
    );
    assert!(name.starts_with(&rows[0].tool));
}

/// Initializes as `token` on `demo` and returns the session id the client was given.
async fn initialize_as(demo: &Demo, token: &str) -> String {
    let reply = demo
        .gw
        .post("demo", token, session_headers(None), initialize_body())
        .await;
    assert_eq!(reply.status, 200, "initialize must be relayed");
    reply
        .header("mcp-session-id")
        .expect("initialize must relay a new session id")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_upstream_gets_one_plain_json_content_type() {
    let demo = demo().await;
    let headers = vec![
        (
            "content-type",
            "application/json; charset=\"UTF-8\"; x=y".to_owned(),
        ),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2025-11-25".to_owned()),
    ];
    let reply = demo
        .gw
        .post("demo", &demo.token, headers, initialize_body())
        .await;
    assert_eq!(reply.status, 200);
    let init = demo
        .fake
        .seen()
        .into_iter()
        .find(|seen| seen.rpc() == "initialize")
        .expect("the initialize reaches the upstream");
    assert_eq!(init.header("content-type"), Some("application/json"));
    assert_eq!(
        init.headers
            .iter()
            .filter(|(name, _)| name == "content-type")
            .count(),
        1,
        "exactly one content-type reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_get_carries_no_content_type() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let reply = demo
        .gw
        .send(
            reqwest::Method::GET,
            "/demo",
            Some(&demo.token),
            vec![
                ("mcp-session-id", session.clone()),
                ("content-type", "text/plain".to_owned()),
                ("accept", "text/event-stream".to_owned()),
            ],
            None,
        )
        .await;
    assert_eq!(reply.status, 200, "the GET is relayed");
    let get = demo
        .fake
        .seen()
        .into_iter()
        .find(|seen| seen.method == "GET")
        .expect("the GET reaches the upstream");
    assert_eq!(
        get.header("content-type"),
        None,
        "a GET has no content-type"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_or_invisible_version_on_get_or_delete_is_400_before_any_upstream_contact() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let before = demo.fake.count();
    let versions: [Vec<(&str, String)>; 2] = [
        vec![
            ("mcp-protocol-version", "2025-11-25".to_owned()),
            ("mcp-protocol-version", "2025-11-25".to_owned()),
        ],
        vec![("mcp-protocol-version", "2025 11-25".to_owned())],
    ];
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        for version in &versions {
            for with_session in [false, true] {
                let mut headers = version.clone();
                if with_session {
                    headers.push(("mcp-session-id", session.clone()));
                }
                let reply = demo
                    .gw
                    .send(method.clone(), "/demo", Some(&demo.token), headers, None)
                    .await;
                assert_eq!(reply.status, 400, "{method} with a non-clean version");
                assert_eq!(reply.error_code(), Some(-32600));
                assert_eq!(reply.error_message().as_deref(), Some("Invalid request"));
            }
        }
    }
    assert_eq!(demo.fake.count(), before, "no request reaches the upstream");
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 200, "the session still works afterwards");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delete_answered_204_is_relayed_and_the_session_is_forgotten() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Status(204, None, ""));
    let reply = demo
        .gw
        .send(
            reqwest::Method::DELETE,
            "/demo",
            Some(&demo.token),
            vec![("mcp-session-id", session.clone())],
            None,
        )
        .await;
    assert_eq!(reply.status, 204, "a 204 to a DELETE is a success");
    assert_eq!(reply.body, "", "the 204 has an empty body");
    reply.assert_inert("the 204");
    demo.fake.set(Mode::Json(Vec::new()));
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 404, "the session is forgotten after the 204");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_204_to_a_post_or_a_get_is_still_the_502() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Status(204, None, ""));
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 502, "a 204 to a POST is a fault");
    assert_eq!(reply.body, UNAVAILABLE);
    let reply = demo
        .gw
        .send(
            reqwest::Method::GET,
            "/demo",
            Some(&demo.token),
            vec![("mcp-session-id", session.clone())],
            None,
        )
        .await;
    assert_eq!(reply.status, 502, "a 204 to a GET is a fault");
    assert_eq!(reply.body, UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_null_next_cursor_and_a_null_request_cursor_mean_no_cursor() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["old"]);
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"gamma"}],"nextCursor":null}}"#,
    ));
    let reply = session_post(&demo, None, session_body(1, "tools/list", json!({}))).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        demo.gw.catalog_names(demo.server),
        ["gamma"],
        "a null nextCursor is no next page"
    );

    demo.gw.seed(demo.server, &["old"]);
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"delta"}]}}"#,
    ));
    let reply = session_post(
        &demo,
        None,
        session_body(2, "tools/list", json!({"cursor": null})),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        demo.gw.catalog_names(demo.server),
        ["delta"],
        "a null request cursor is no cursor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_token_initializing_again_with_the_same_id_relays_it_again() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 200, "the second initialize is relayed");
    assert_eq!(
        reply.header("mcp-session-id"),
        Some(session.as_str()),
        "the owner's own id is relayed again"
    );
    assert_eq!(demo.gw.session_rows(), 1, "the id is still one row");
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(3, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 200, "the session works");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_family_keeps_its_32_newest_sessions_and_other_users_are_untouched() {
    let demo = demo().await;
    demo.fake.set(Mode::Counted(Arc::new(AtomicUsize::new(0))));
    let carol = demo.gw.add_user(CAROL);
    demo.gw.grant(carol, demo.server);
    let carol_token = demo.gw.token(carol, demo.server);
    let carol_session = initialize_as(&demo, &carol_token).await;
    let mut bob_ids = Vec::new();
    for _ in 0..33 {
        bob_ids.push(initialize_as(&demo, &demo.token).await);
    }
    assert_eq!(
        demo.gw.session_rows(),
        33,
        "carol's one session and bob's newest 32"
    );
    let reply = session_post(
        &demo,
        Some(&bob_ids[0]),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 404, "the oldest of bob's sessions is pruned");
    let reply = session_post(
        &demo,
        Some(&bob_ids[32]),
        session_body(3, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 200, "the newest of bob's sessions works");
    let reply = demo
        .gw
        .post(
            "demo",
            &carol_token,
            session_headers(Some(&carol_session)),
            session_body(4, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 200, "carol's session survives bob's churn");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_upstream_session_id_is_dropped_and_nothing_is_recorded() {
    let demo = demo().await;
    for issued in ["x".repeat(300), "ab cd".to_owned()] {
        demo.fake.set(Mode::Issued(issued.clone()));
        let reply = session_post(&demo, None, initialize_body()).await;
        assert_eq!(reply.status, 200, "the initialize is relayed");
        assert_eq!(
            reply.header("mcp-session-id"),
            None,
            "the malformed id {issued:?} is dropped"
        );
    }
    assert_eq!(demo.gw.session_rows(), 0, "no row is recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_refresh_never_lets_an_unknown_tool_through() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    demo.fake.set(Mode::Status(500, None, "internal"));
    let reply = session_post(&demo, None, call_body(6, "nope")).await;
    assert_eq!(reply.status, 200, "an unknown tool is answered in the body");
    assert_eq!(reply.error_code(), Some(-32602));
    assert_eq!(reply.error_message().as_deref(), Some("Unknown tool: nope"));
    assert_eq!(
        demo.fake.calls("tools/call"),
        0,
        "a failed refresh sends no call upstream"
    );
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 1, "one refused row");
    assert_eq!(rows[0].decision, "deny");
    assert_eq!(rows[0].outcome, "refused");

    demo.gw.set_url(demo.server, CLOSED_PORT);
    let reply = session_post(&demo, None, call_body(7, "nope")).await;
    assert_eq!(
        reply.status, 200,
        "a stopped upstream still answers the unknown tool"
    );
    assert_eq!(reply.error_code(), Some(-32602));
    assert_eq!(reply.error_message().as_deref(), Some("Unknown tool: nope"));
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 2, "a second refused row");
    assert_eq!(rows[1].decision, "deny");
    assert_eq!(rows[1].outcome, "refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_is_never_sent_upstream_under_the_stateless_rules() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let mut headers = stateless_headers("tools/list", None);
    headers.push(("mcp-session-id", session.clone()));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            headers,
            stateless_body(2, "tools/list", json!({})),
        )
        .await;
    assert_eq!(reply.status, 200, "the stateless list is answered");
    let list = demo
        .fake
        .seen()
        .into_iter()
        .find(|seen| seen.rpc() == "tools/list")
        .expect("the list reaches the upstream");
    assert_eq!(
        list.header("mcp-session-id"),
        None,
        "a stateless request never carries the session id upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_get_or_delete_is_405_even_with_a_valid_session() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let before = demo.fake.count();
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let headers = vec![
            ("mcp-protocol-version", "2026-07-28".to_owned()),
            ("mcp-session-id", session.clone()),
        ];
        let reply = demo
            .gw
            .send(method.clone(), "/demo", Some(&demo.token), headers, None)
            .await;
        assert_eq!(reply.status, 405, "{method} under stateless rules is 405");
        assert_eq!(reply.header("allow"), Some("POST"));
        reply.assert_inert("the 405");
    }
    assert_eq!(demo.fake.count(), before, "no request reaches the upstream");
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 200, "the session still works afterwards");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_is_recorded_only_from_a_200_initialize() {
    let demo = demo().await;
    demo.fake.set(Mode::Session(
        400,
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}"#,
    ));
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 400, "the upstream's status is relayed");
    assert_eq!(
        reply.header("mcp-session-id"),
        None,
        "a 400 answer relays no session id"
    );
    assert_eq!(demo.gw.session_rows(), 0, "no session is recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_is_recorded_only_from_an_initialize_with_a_result() {
    let demo = demo().await;
    demo.fake.set(Mode::Session(
        200,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"nope"}}"#,
    ));
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 200, "the error answer is relayed");
    assert_eq!(
        reply.header("mcp-session-id"),
        None,
        "an error answer relays no session id"
    );
    assert_eq!(demo.gw.session_rows(), 0, "no session is recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_rules_list_is_relayed_byte_for_byte_without_cache_scope() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let raw = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}"#;
    demo.fake.set(Mode::Raw(raw));
    let reply = session_post(
        &demo,
        Some(&session),
        session_body(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, raw, "the list is relayed unchanged");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_of_256_characters_is_kept_and_one_of_257_is_dropped() {
    let demo = demo().await;
    let kept = "s".repeat(256);
    demo.fake.set(Mode::Issued(kept.clone()));
    let reply = session_post(&demo, None, initialize_body()).await;
    assert_eq!(reply.status, 200, "the initialize is relayed");
    assert_eq!(
        reply.header("mcp-session-id"),
        Some(kept.as_str()),
        "a 256-character id is relayed"
    );
    assert_eq!(demo.gw.session_rows(), 1, "and recorded");
    demo.fake.set(Mode::Json(Vec::new()));
    let reply = session_post(&demo, Some(&kept), session_body(2, "tools/list", json!({}))).await;
    assert_eq!(
        reply.status, 200,
        "the 256-character id works on the next request"
    );

    let dropped = "t".repeat(257);
    demo.fake.set(Mode::Issued(dropped));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            session_headers(None),
            initialize_body(),
        )
        .await;
    assert_eq!(reply.status, 200, "the initialize is relayed");
    assert_eq!(
        reply.header("mcp-session-id"),
        None,
        "a 257-character id is dropped"
    );
    assert_eq!(demo.gw.session_rows(), 1, "and nothing more is recorded");

    let before = demo.fake.count();
    let reply = session_post(
        &demo,
        Some(&"c".repeat(257)),
        session_body(3, "tools/list", json!({})),
    )
    .await;
    assert_eq!(reply.status, 404, "a client-sent 257-character id is 404");
    assert_eq!(demo.fake.count(), before, "and reaches no upstream");
}

/// The tool names of a tools/list answer, in order.
fn listed_names(reply: &Reply) -> Vec<String> {
    reply.json()["result"]["tools"]
        .as_array()
        .expect("a tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name").to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_call_is_refused_as_unknown_and_never_reaches_the_upstream() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo", "delete_db"]);
    demo.gw
        .add_rule(None, "deny", demo.server, Some("delete_db"));
    let reply = session_post(&demo, None, call_body(4, "delete_db")).await;
    assert_eq!(reply.status, 200, "a refused call is answered in the body");
    assert_eq!(reply.error_code(), Some(-32602));
    assert_eq!(
        reply.error_message().as_deref(),
        Some("Unknown tool: delete_db")
    );
    assert_eq!(reply.json()["id"], json!(4));
    let reply = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/call", Some("delete_db")),
            stateless_body(
                5,
                "tools/call",
                json!({"name": "delete_db", "arguments": {}}),
            ),
        )
        .await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "the stateless call is refused too"
    );
    assert_eq!(
        demo.fake.calls("tools/call"),
        0,
        "the upstream never sees the denied call"
    );
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 2, "one activity row for each refused call");
    for row in &rows {
        assert_eq!(row.tool, "delete_db");
        assert_eq!(row.decision, "deny");
        assert_eq!(row.outcome, "refused");
    }
    let reply = session_post(&demo, None, call_body(6, "echo")).await;
    assert_eq!(
        reply.text_of_call().as_deref(),
        Some("called: echo"),
        "an allowed tool still reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_tool_is_absent_from_both_generations_and_the_catalog_keeps_it() {
    let demo = demo().await;
    demo.fake.set_tools(&["echo", "search", "delete_db"]);
    demo.gw
        .add_rule(None, "deny", demo.server, Some("delete_db"));
    let session = session_post(&demo, None, session_body(2, "tools/list", json!({}))).await;
    assert_eq!(session.status, 200);
    assert_eq!(
        listed_names(&session),
        ["echo", "search"],
        "the session list lacks the denied tool"
    );
    let stateless = demo
        .gw
        .post(
            "demo",
            &demo.token,
            stateless_headers("tools/list", None),
            stateless_body(3, "tools/list", json!({})),
        )
        .await;
    assert_eq!(stateless.status, 200);
    assert_eq!(
        listed_names(&stateless),
        ["echo", "search"],
        "the stateless list lacks the denied tool"
    );
    assert_eq!(
        demo.gw.catalog_names(demo.server),
        ["echo", "search", "delete_db"],
        "the stored catalog is not filtered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_tool_is_absent_from_a_later_page_of_a_list() {
    let demo = demo().await;
    demo.gw
        .add_rule(None, "deny", demo.server, Some("delete_db"));
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"},{"name":"delete_db"}],"nextCursor":"n"}}"#,
    ));
    let first = session_post(&demo, None, session_body(2, "tools/list", json!({}))).await;
    assert_eq!(
        listed_names(&first),
        ["echo"],
        "the first page lacks the denied tool"
    );
    demo.fake.set(Mode::Raw(
        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_db"},{"name":"search"}]}}"#,
    ));
    let second = session_post(
        &demo,
        None,
        session_body(3, "tools/list", json!({"cursor": "n"})),
    )
    .await;
    assert_eq!(second.status, 200);
    assert_eq!(
        listed_names(&second),
        ["search"],
        "a later page lacks the denied tool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_that_cannot_be_read_is_an_internal_error_and_never_an_allow() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    demo.gw
        .conn()
        .execute_batch("DROP TABLE rules")
        .expect("drop");
    let reply = session_post(&demo, None, call_body(2, "echo")).await;
    assert_eq!(reply.status, 500, "the call is an internal error");
    assert_eq!(
        demo.fake.calls("tools/call"),
        0,
        "the upstream never sees the call"
    );
    let reply = session_post(&demo, None, session_body(3, "tools/list", json!({}))).await;
    assert_eq!(reply.status, 500, "the list is an internal error");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_that_cannot_be_read_answers_like_a_failed_rule_read_and_never_allows() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    demo.gw
        .conn()
        .execute_batch("DROP TABLE tool_switches")
        .expect("the switch table is dropped");
    let rules = demo_with(|_| {}, (false, false)).await;
    rules.gw.seed(rules.server, &["echo"]);
    rules
        .gw
        .conn()
        .execute_batch("DROP TABLE rules")
        .expect("the rules table is dropped");
    let reply = session_post(&demo, None, call_body(2, "echo")).await;
    let failed = session_post(&rules, None, call_body(2, "echo")).await;
    assert_eq!(reply.status, 500, "the call is an internal error");
    assert_eq!(
        (reply.status, &reply.body),
        (failed.status, &failed.body),
        "a failed switch read answers the call as a failed rule read does"
    );
    assert_eq!(
        demo.fake.calls("tools/call"),
        0,
        "the upstream never sees the call"
    );
    let reply = session_post(&demo, None, session_body(3, "tools/list", json!({}))).await;
    let failed = session_post(&rules, None, session_body(3, "tools/list", json!({}))).await;
    assert_eq!(reply.status, 500, "the list is an internal error");
    assert_eq!(
        (reply.status, &reply.body),
        (failed.status, &failed.body),
        "a failed switch read answers the list as a failed rule read does"
    );
    assert!(
        !reply.body.contains("echo"),
        "no tool may be listed when the switches cannot be read"
    );
    assert_eq!(
        demo.fake.calls("tools/list"),
        rules.fake.calls("tools/list"),
        "the upstream sees the list exactly as it does when the rules cannot be read"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_entry_without_a_string_name_is_removed_from_every_page_under_no_rules() {
    let demo = demo().await;
    let page = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"description":"no name"},{"name":"echo"},{"name":7}]}}"#;
    demo.fake.set(Mode::Raw(page));
    let first = session_post(&demo, None, session_body(2, "tools/list", json!({}))).await;
    assert_eq!(first.status, 200);
    assert_eq!(
        first.json()["result"]["tools"],
        json!([{"name": "echo"}]),
        "the first page holds only the named tool"
    );
    let with_cursor = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"description":"no name"},{"name":"echo"},{"name":7}],"nextCursor":"n"}}"#;
    demo.fake.set(Mode::Raw(with_cursor));
    let later = session_post(
        &demo,
        None,
        session_body(3, "tools/list", json!({"cursor": "c1"})),
    )
    .await;
    assert_eq!(later.status, 200);
    assert_eq!(
        later.json()["result"]["tools"],
        json!([{"name": "echo"}]),
        "a later page holds only the named tool"
    );
}

/// Sends one complete POST to `/demo` on a raw connection, then closes it 100 ms later unread.
async fn abandon(gw: &Gw, token: &str, session: &str, body: &str) {
    let mut stream = TcpStream::connect(gw.config.listen)
        .await
        .expect("the gateway accepts a connection");
    let request = format!(
        "POST /demo HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         MCP-Protocol-Version: 2025-11-25\r\nMcp-Session-Id: {session}\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request is written");
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(stream);
}

/// The tool_call rows, polled for up to 3 seconds until there are `wanted` of them.
async fn wait_for_rows(gw: &Gw, wanted: usize) -> Vec<Row> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let rows = gw.tool_calls();
        if rows.len() >= wanted || Instant::now() >= deadline {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_is_recorded_when_the_client_leaves_before_the_answer() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Held(
        Duration::from_secs(1),
        Box::new(Mode::Json(Vec::new())),
    ));
    abandon(&demo.gw, &demo.token, &session, &call_body(2, "echo")).await;
    let rows = wait_for_rows(&demo.gw, 1).await;
    assert_eq!(
        demo.fake.calls("tools/call"),
        1,
        "the upstream must have received the call once"
    );
    assert_eq!(
        rows.len(),
        1,
        "exactly one tool_call row must be written when the client left, got {rows:?}"
    );
    let row = &rows[0];
    assert_eq!(
        row.user_id,
        Some(demo.bob),
        "the row must be recorded under bob"
    );
    assert_eq!(row.email, BOB);
    assert_eq!(row.server_id, Some(demo.server));
    assert_eq!(row.slug, "demo");
    assert_eq!(row.tool, "echo");
    assert_eq!(row.decision, "allow", "the row must have decision allow");
    assert_eq!(row.outcome, "error", "the row must have outcome error");
    assert_eq!(
        row.detail, "the client left before the answer",
        "the row must say that the client left"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        demo.gw.tool_calls().len(),
        1,
        "the row must still be the only one 500 ms later"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_open_request_slot_is_freed_when_the_client_leaves() {
    let demo = demo_with(|config| config.limits.mcp_open = 1, (false, false)).await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Held(
        Duration::from_secs(30),
        Box::new(Mode::Json(Vec::new())),
    ));
    abandon(&demo.gw, &demo.token, &session, &call_body(2, "echo")).await;
    let deadline = Instant::now() + Duration::from_secs(3);
    while demo.fake.calls("tools/call") < 1 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        demo.fake.calls("tools/call"),
        1,
        "the upstream must have received the abandoned call"
    );
    demo.fake.set(Mode::Json(Vec::new()));
    let deadline = Instant::now() + Duration::from_secs(3);
    let reply = loop {
        let reply = session_post(&demo, Some(&session), call_body(3, "echo")).await;
        if reply.status == 200 || Instant::now() >= deadline {
            break reply;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(
        reply.status, 200,
        "another request of the user must be answered within 3 seconds of the client leaving"
    );
    assert_eq!(
        reply.text_of_call(),
        Some("called: echo".to_string()),
        "the request after the client left must answer its result"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_that_is_answered_has_exactly_one_row() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let reply = session_post(&demo, Some(&session), call_body(2, "echo")).await;
    assert_eq!(reply.status, 200, "an ordinary call must answer 200");
    assert_eq!(
        reply.text_of_call(),
        Some("called: echo".to_string()),
        "an ordinary call must answer the upstream's result"
    );
    demo.fake.set(Mode::Status(500, None, ""));
    let reply = session_post(&demo, Some(&session), call_body(3, "echo")).await;
    assert_eq!(
        reply.status, 502,
        "a call the upstream fails must answer 502"
    );
    let rows = demo.gw.tool_calls();
    let outcomes: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|row| {
            (
                row.tool.as_str(),
                row.decision.as_str(),
                row.outcome.as_str(),
            )
        })
        .collect();
    assert_eq!(
        outcomes,
        [("echo", "allow", "ok"), ("echo", "allow", "unavailable")],
        "each answered call must leave exactly one row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_call_still_writes_its_own_single_row() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    demo.fake.set(Mode::Progress);
    let reply = session_post(&demo, Some(&session), call_body(2, "echo")).await;
    assert_eq!(reply.status, 200, "a streamed call must answer 200");
    let rows = demo.gw.tool_calls();
    assert_eq!(
        rows.len(),
        1,
        "a streamed call must leave exactly one row, got {rows:?}"
    );
    assert_eq!(
        rows[0].decision, "allow",
        "the row must have decision allow"
    );
    assert_eq!(rows[0].outcome, "ok", "the row must have outcome ok");
}
