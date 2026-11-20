//! The upstream links, against scripted upstreams on 127.0.0.1: the gateway as an MCP client.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue};
use axum::response::Response;
use futures_util::future::join_all;
use rusqlite::params;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::time::timeout;

use super::links::{Ask, Links, Owner, read};
use super::tests::{Fixture, Plan, Seen, TestUpstream, answer, fixture, fixture_with};
use super::upstream::{self, Fault, Target};
use crate::app::AppState;
use crate::crypto::token_hash;
use crate::oauth::families::{self, NewFamily};
use crate::servers;

const CAP: u64 = 1 << 20;
const SECRET_NAME: &str = "x-upstream-secret";
const SECRET_VALUE: &str = "s3cret";

/// What the fake upstream does with each request.
#[derive(Clone)]
struct Behave {
    /// Answers server/discover with a result, as a stateless upstream does.
    discover: bool,
    /// Serves the session form: initialize issues a session id and tool requests need it.
    sessions: bool,
    /// The protocolVersion of the initialize answer.
    revision: &'static str,
    /// The session id every initialize gets; None issues s1, s2, and so on.
    fixed_id: Option<String>,
    /// How long each initialize answer waits, at the start.
    wait: Duration,
    /// How long each server/discover answer waits, at the start.
    probe_wait: Duration,
    /// Answers notifications/initialized with 202 and text/plain, as the TypeScript SDK does.
    text_notices: bool,
}

impl Default for Behave {
    /// A session-style upstream at revision 2025-11-25 that issues s1, s2, and so on.
    fn default() -> Self {
        Behave {
            discover: false,
            sessions: true,
            revision: "2025-11-25",
            fixed_id: None,
            wait: Duration::ZERO,
            probe_wait: Duration::ZERO,
            text_notices: false,
        }
    }
}

impl Behave {
    /// A stateless upstream: server/discover has a result and no session is used.
    fn stateless() -> Self {
        Behave {
            discover: true,
            sessions: false,
            ..Behave::default()
        }
    }
}

/// What the fake has issued and holds, and the status it answers tool requests with.
#[derive(Default)]
struct Ledger {
    issued: u64,
    live: HashSet<String>,
    calls_status: Option<u16>,
    /// How long each server/discover answer waits now.
    probe_wait: Duration,
    /// How long each initialize answer waits now.
    init_wait: Duration,
}

/// A scripted upstream with its ledger, which the test can change while it runs.
struct Up {
    up: TestUpstream,
    book: Arc<Mutex<Ledger>>,
}

impl Up {
    fn url(&self) -> &str {
        &self.up.url
    }

    fn seen(&self) -> Vec<Seen> {
        self.up.seen()
    }

    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.book.lock().expect("ledger")
    }

    /// How many requests of one kind arrived: a JSON-RPC method, or DELETE.
    fn count(&self, kind: &str) -> usize {
        self.seen()
            .iter()
            .filter(|seen| kind_of(seen) == kind)
            .count()
    }

    /// The bodies of the requests of one kind, in arrival order.
    fn bodies(&self, kind: &str) -> Vec<String> {
        self.seen()
            .iter()
            .filter(|seen| kind_of(seen) == kind)
            .map(|seen| String::from_utf8_lossy(&seen.body).into_owned())
            .collect()
    }

    /// The Mcp-Session-Id of each request of one kind, in arrival order.
    fn sessions(&self, kind: &str) -> Vec<Option<String>> {
        self.seen()
            .iter()
            .filter(|seen| kind_of(seen) == kind)
            .map(|seen| seen.header("mcp-session-id").map(str::to_owned))
            .collect()
    }
}

fn kind_of(seen: &Seen) -> String {
    if seen.method == "DELETE" {
        "DELETE".to_owned()
    } else {
        seen.rpc()
    }
}

async fn start(behave: Behave) -> Up {
    let book = Arc::new(Mutex::new(Ledger {
        probe_wait: behave.probe_wait,
        init_wait: behave.wait,
        ..Ledger::default()
    }));
    let shared = Arc::clone(&book);
    let up = TestUpstream::start(move |seen: &Seen| {
        let wait = {
            let ledger = shared.lock().expect("ledger");
            match seen.rpc().as_str() {
                "server/discover" => ledger.probe_wait,
                "initialize" => ledger.init_wait,
                _ => Duration::ZERO,
            }
        };
        let plan = respond(&behave, &shared, seen);
        match plan {
            Plan::Reply(response) if !wait.is_zero() => Plan::Late(wait, response),
            other => other,
        }
    })
    .await;
    Up { up, book }
}

/// A stateless upstream whose tools/list and tools/call answers come from `tools`; discover is fixed.
async fn stateless_with(tools: impl Fn(&Seen) -> Plan + Send + Sync + 'static) -> TestUpstream {
    TestUpstream::start(move |seen: &Seen| {
        if seen.rpc() == "server/discover" {
            let body = result_of(
                seen.json()["id"].clone(),
                json!({"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}),
            );
            return json_plan(&body);
        }
        tools(seen)
    })
    .await
}

fn respond(behave: &Behave, book: &Mutex<Ledger>, seen: &Seen) -> Plan {
    let mut ledger = book.lock().expect("ledger");
    if seen.method == "DELETE" {
        if let Some(session) = seen.header("mcp-session-id") {
            ledger.live.remove(session);
        }
        return plan(200, None, None);
    }
    let id = seen.json()["id"].clone();
    match seen.rpc().as_str() {
        "server/discover" if behave.discover => plan(
            200,
            None,
            Some(&result_of(
                id,
                json!({"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}),
            )),
        ),
        "initialize" if behave.sessions => {
            let session = match &behave.fixed_id {
                Some(fixed) => fixed.clone(),
                None => {
                    ledger.issued += 1;
                    format!("s{}", ledger.issued)
                }
            };
            ledger.live.insert(session.clone());
            let body = result_of(
                id,
                json!({"protocolVersion": behave.revision, "capabilities": {}}),
            );
            Plan::Reply(build(200, Some(&session), Some(&body)))
        }
        "notifications/initialized" if behave.text_notices => {
            answer(202, None, Some("text/plain; charset=UTF-8"), "")
        }
        "notifications/initialized" => plan(202, None, None),
        "tools/list" | "tools/call" => {
            if let Some(status) = ledger.calls_status {
                return plan(status, None, None);
            }
            if behave.sessions {
                match seen.header("mcp-session-id") {
                    None => return plan(400, None, None),
                    Some(session) if !ledger.live.contains(session) => {
                        return plan(404, None, None);
                    }
                    Some(_) => {}
                }
            }
            let result = if seen.rpc() == "tools/list" {
                json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]})
            } else {
                json!({"content": [{"type": "text", "text": "ok"}]})
            };
            plan(200, None, Some(&result_of(id, result)))
        }
        _ => plan(200, None, Some(&error_of(id))),
    }
}

fn result_of(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_of(id: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}})
}

fn build(status: u16, session: Option<&str>, body: Option<&Value>) -> Response {
    let mut builder = Response::builder().status(status);
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let text = match body {
        Some(body) => {
            builder = builder.header("content-type", "application/json");
            body.to_string()
        }
        None => String::new(),
    };
    builder.body(Body::from(text)).expect("response")
}

fn plan(status: u16, session: Option<&str>, body: Option<&Value>) -> Plan {
    Plan::Reply(build(status, session, body))
}

fn json_plan(body: &Value) -> Plan {
    answer(200, None, Some("application/json"), &body.to_string())
}

fn stream_plan(text: &str) -> Plan {
    answer(200, None, Some("text/event-stream"), text)
}

fn target_at(fx: &Fixture, url: &str) -> Target {
    Target {
        server_id: fx.server_id,
        slug: "demo".to_owned(),
        url: url.to_owned(),
        secret: None,
    }
}

fn owned(user_id: i64, family_id: i64) -> Owner {
    Owner { user_id, family_id }
}

fn list() -> Ask<'static> {
    Ask::List { cursor: None }
}

fn echo(arguments: Option<&RawValue>) -> Ask<'_> {
    Ask::Call {
        name: "echo",
        arguments,
        progress_token: None,
    }
}

/// Sends one request on the owner's link and reads its answer.
async fn ask(
    links: &Links,
    state: &AppState,
    owner: Owner,
    target: &Target,
    request: Ask<'_>,
) -> Result<Value, Fault> {
    let sent = links.send(state, owner, target, request).await?;
    read(state, sent, CAP).await
}

/// A port that nothing listens on.
async fn closed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    format!("http://127.0.0.1:{port}/mcp")
}

/// Polls until the upstream has seen `count` requests of `kind`, or fails at the deadline.
async fn wait_for(up: &Up, kind: &str, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while up.count(kind) < count {
        assert!(Instant::now() < deadline, "the upstream did not see {kind}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_families_on_one_upstream_never_share_a_session() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("family 1 lists");
    ask(&links, &fx.state, owned(1, 2), &target, list())
        .await
        .expect("family 2 lists");
    assert_eq!(up.count("initialize"), 2);
    assert_eq!(
        up.sessions("tools/list"),
        vec![Some("s1".to_owned()), Some("s2".to_owned())]
    );
    assert_eq!(links.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_upstream_is_probed_once_and_never_initialized() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("lists");
    let methods: Vec<String> = up.seen().iter().map(kind_of).collect();
    assert_eq!(methods, vec!["server/discover", "tools/list"]);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_upstream_that_answers_its_notice_as_text_is_usable() {
    let up = start(Behave {
        text_notices: true,
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    let listed = ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("the list is answered after a text notice");
    assert_eq!(
        listed["result"]["tools"][0]["name"], "echo",
        "the upstream's tool is listed"
    );
    assert_eq!(up.count("notifications/initialized"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_upstream_is_initialized_once_and_its_notice_is_sent() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("lists");
    let methods: Vec<String> = up.seen().iter().map(kind_of).collect();
    assert_eq!(
        methods,
        vec![
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/list",
        ]
    );
    assert_eq!(up.count("initialize"), 1);
    assert_eq!(up.count("notifications/initialized"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_is_down_is_a_fault_and_keeps_no_link() {
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, &closed_url().await);
    let result = ask(&links, &fx.state, owned(1, 1), &target, list()).await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_with_a_space_or_of_300_bytes_is_a_fault() {
    let fx = fixture().await;
    let spaced = start(Behave {
        fixed_id: Some("a b".to_owned()),
        ..Behave::default()
    })
    .await;
    let links = Links::new();
    let result = ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, spaced.url()),
        list(),
    )
    .await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);

    let long = start(Behave {
        fixed_id: Some("x".repeat(300)),
        ..Behave::default()
    })
    .await;
    let result = ask(
        &links,
        &fx.state,
        owned(1, 2),
        &target_at(&fx, long.url()),
        list(),
    )
    .await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_of_256_bytes_is_kept() {
    let fx = fixture().await;
    let up = start(Behave {
        fixed_id: Some("x".repeat(256)),
        ..Behave::default()
    })
    .await;
    let links = Links::new();
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        list(),
    )
    .await
    .expect("a 256 byte id lists");
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_initialize_with_an_unknown_revision_is_a_fault() {
    let up = start(Behave {
        revision: "1999-01-01",
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let result = ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        list(),
    )
    .await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_link_speaks_the_revision_the_upstream_answered() {
    let up = start(Behave {
        revision: "2025-06-18",
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        list(),
    )
    .await
    .expect("lists");
    let versions: Vec<Option<String>> = up
        .seen()
        .iter()
        .filter(|seen| kind_of(seen) != "server/discover")
        .map(|seen| seen.header("mcp-protocol-version").map(str::to_owned))
        .collect();
    assert_eq!(
        versions,
        vec![
            Some("2025-11-25".to_owned()),
            Some("2025-06-18".to_owned()),
            Some("2025-06-18".to_owned()),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_the_upstream_gave_to_another_family_is_a_fault_for_the_second() {
    let up = start(Behave {
        fixed_id: Some("same".to_owned()),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first family lists");
    let second = ask(&links, &fx.state, owned(1, 2), &target, list()).await;
    assert!(matches!(second, Err(Fault)));
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_already_recorded_for_the_server_is_a_fault() {
    let up = start(Behave {
        fixed_id: Some("recorded".to_owned()),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let server = fx.server_id;
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO users (email, password_hash, role, created_at) \
                 VALUES ('kept@example.com', 'hash', 'user', 0)",
                [],
            )?;
            let user = conn.last_insert_rowid();
            let family = families::create(
                conn,
                &NewFamily {
                    user_id: user,
                    server_id: Some(server),
                    client_id: "dcr_test",
                    client_name: "kept",
                    auth_epoch: 0,
                },
                0,
                90,
            )?;
            conn.execute(
                "INSERT INTO upstream_sessions (server_id, id_hash, user_id, family_id, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                params![server, token_hash("recorded"), user, family],
            )?;
            Ok(())
        })
        .await
        .expect("recorded session");
    let links = Links::new();
    let result = ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        list(),
    )
    .await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_concurrent_first_sends_make_one_link() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    let sent = join_all((0..10).map(|_| links.send(&fx.state, owned(1, 1), &target, list()))).await;
    for result in sent {
        let sent = result.expect("sent");
        read(&fx.state, sent, CAP).await.expect("answered");
    }
    assert_eq!(up.count("initialize"), 1);
    assert_eq!(up.count("tools/list"), 10);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repointed_server_never_receives_the_old_session() {
    let first = start(Behave {
        fixed_id: Some("from-first".to_owned()),
        ..Behave::default()
    })
    .await;
    let second = start(Behave {
        fixed_id: Some("from-second".to_owned()),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, first.url()),
        list(),
    )
    .await
    .expect("first lists");
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, second.url()),
        list(),
    )
    .await
    .expect("second lists");
    assert_eq!(
        second.sessions("tools/list"),
        vec![Some("from-second".to_owned())]
    );
    assert!(
        second
            .seen()
            .iter()
            .all(|seen| seen.header("mcp-session-id") != Some("from-first"))
    );
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_request_carries_its_own_id() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first list makes the link");
    let (first, second, third) = tokio::join!(
        ask(&links, &fx.state, owned(1, 1), &target, echo(None)),
        ask(&links, &fx.state, owned(1, 1), &target, echo(None)),
        ask(&links, &fx.state, owned(1, 1), &target, list()),
    );
    first.expect("first call");
    second.expect("second call");
    third.expect("third list");
    let ids: Vec<String> = up
        .seen()
        .iter()
        .map(|seen| seen.json()["id"].to_string())
        .collect();
    let distinct: HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), 5);
    assert_eq!(distinct.len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn call_arguments_arrive_byte_for_byte() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let raw = RawValue::from_string(r#"{"n": 12345678901234567890123, "b": 1, "a": 2}"#.to_owned())
        .expect("raw arguments");
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        echo(Some(&*raw)),
    )
    .await
    .expect("call answered");
    let bodies = up.bodies("tools/call");
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains(r#""arguments":{"n": 12345678901234567890123, "b": 1, "a": 2}"#));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_progress_token_that_is_an_object_is_not_sent() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    let object = json!({"a": 1});
    let integer = json!(7);
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target,
        Ask::Call {
            name: "echo",
            arguments: None,
            progress_token: Some(&object),
        },
    )
    .await
    .expect("object token call");
    ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target,
        Ask::Call {
            name: "echo",
            arguments: None,
            progress_token: Some(&integer),
        },
    )
    .await
    .expect("integer token call");
    let bodies = up.bodies("tools/call");
    assert_eq!(bodies.len(), 2);
    assert!(!bodies[0].contains("progressToken"));
    assert!(bodies[1].contains(r#""progressToken":7"#));
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_carry_only_the_listed_headers() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let mut target = target_at(&fx, up.url());
    target.secret = Some((
        HeaderName::from_static(SECRET_NAME),
        HeaderValue::from_static(SECRET_VALUE),
    ));
    ask(&links, &fx.state, owned(1, 1), &target, echo(None))
        .await
        .expect("call answered");
    const LISTED: [&str; 9] = [
        "content-type",
        "accept",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
        SECRET_NAME,
        "host",
        "content-length",
        "user-agent",
    ];
    for seen in up.seen() {
        for (name, _) in &seen.headers {
            assert!(LISTED.contains(&name.as_str()), "unlisted header {name}");
        }
    }
    let call = up
        .seen()
        .into_iter()
        .find(|seen| kind_of(seen) == "tools/call")
        .expect("a call arrived");
    assert_eq!(call.header("mcp-name"), Some("echo"));
    assert_eq!(call.header("mcp-method"), Some("tools/call"));
    assert_eq!(call.header("mcp-protocol-version"), Some("2026-07-28"));
    assert!(call.header("authorization").is_none());
    assert!(call.header(SECRET_NAME) == Some(SECRET_VALUE));
}

#[tokio::test(flavor = "multi_thread")]
async fn forgotten_session_is_remade_once_for_ten_concurrent_calls() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first link");
    up.ledger().live.clear();
    let answers =
        join_all((0..10).map(|_| ask(&links, &fx.state, owned(1, 1), &target, echo(None)))).await;
    for answer in answers {
        answer.expect("call answered");
    }
    assert_eq!(up.count("initialize"), 2);
    assert_eq!(
        up.sessions("tools/call")
            .iter()
            .filter(|session| session.as_deref() == Some("s2"))
            .count(),
        10
    );
    assert_eq!(up.count("DELETE"), 0);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn twenty_server_errors_keep_the_link() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first link");
    up.ledger().calls_status = Some(500);
    for _ in 0..20 {
        let result = ask(&links, &fx.state, owned(1, 1), &target, echo(None)).await;
        assert!(matches!(result, Err(Fault)));
    }
    assert_eq!(up.count("initialize"), 1);
    assert_eq!(up.count("server/discover"), 1);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_404_after_the_remade_session_is_a_fault() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first link");
    up.ledger().calls_status = Some(404);
    let answered = timeout(
        Duration::from_secs(5),
        ask(&links, &fx.state, owned(1, 1), &target, echo(None)),
    )
    .await
    .expect("the retry is bounded");
    assert!(matches!(answered, Err(Fault)));
    assert_eq!(up.count("tools/call"), 2);
    assert_eq!(up.count("initialize"), 2);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_404_is_not_retried() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first list");
    up.ledger().calls_status = Some(404);
    let result = ask(&links, &fx.state, owned(1, 1), &target, echo(None)).await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(up.count("tools/call"), 1);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_400_drops_the_link_closes_it_once_and_the_next_send_probes_again() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("first list");
    up.ledger().calls_status = Some(400);
    let result = ask(&links, &fx.state, owned(1, 1), &target, echo(None)).await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);
    wait_for(&up, "DELETE", 1).await;
    assert_eq!(up.count("DELETE"), 1);
    up.ledger().calls_status = None;
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("list after the drop");
    assert_eq!(up.count("server/discover"), 2);
    assert_eq!(up.count("initialize"), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_for_another_id_is_a_fault() {
    let up =
        stateless_with(|_: &Seen| json_plan(&result_of(json!(999), json!({"tools": []})))).await;
    let fx = fixture().await;
    let links = Links::new();
    let sent = links
        .send(&fx.state, owned(1, 1), &target_at(&fx, &up.url), list())
        .await
        .expect("sent");
    assert!(matches!(read(&fx.state, sent, CAP).await, Err(Fault)));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_object_with_both_result_and_error_is_a_fault() {
    let up = stateless_with(|seen: &Seen| {
        json_plan(&json!({"jsonrpc": "2.0", "id": seen.json()["id"].clone(),
            "result": {"tools": []}, "error": {"code": -1, "message": "both"}}))
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let sent = links
        .send(&fx.state, owned(1, 1), &target_at(&fx, &up.url), list())
        .await
        .expect("sent");
    assert!(matches!(read(&fx.state, sent, CAP).await, Err(Fault)));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_array_is_a_fault() {
    let up = stateless_with(|seen: &Seen| {
        json_plan(&json!([result_of(
            seen.json()["id"].clone(),
            json!({"tools": []})
        )]))
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let sent = links
        .send(&fx.state, owned(1, 1), &target_at(&fx, &up.url), list())
        .await
        .expect("sent");
    assert!(matches!(read(&fx.state, sent, CAP).await, Err(Fault)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_answer_comes_after_a_request_and_a_notification() {
    let up = stateless_with(|seen: &Seen| {
        let id = seen.json()["id"].clone();
        let body = format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\n",
            json!({"jsonrpc": "2.0", "id": "upstream-1", "method": "sampling/createMessage", "params": {}}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "p", "progress": 1}}),
            result_of(id, json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]})),
        );
        stream_plan(&body)
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let sent = links
        .send(&fx.state, owned(1, 1), &target_at(&fx, &up.url), list())
        .await
        .expect("sent");
    let answer = read(&fx.state, sent, CAP).await.expect("the answer");
    assert_eq!(answer["id"], json!(3));
    assert_eq!(answer["result"]["tools"][0]["name"], json!("echo"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_per_user_bound_drops_that_users_oldest() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::with_bounds(3, 2);
    let target = target_at(&fx, up.url());
    for family in [1, 2, 3] {
        ask(&links, &fx.state, owned(1, family), &target, list())
            .await
            .expect("lists");
        assert!(links.len() <= 3);
    }
    assert_eq!(links.len(), 2);
    assert_eq!(up.count("server/discover"), 3);
    ask(&links, &fx.state, owned(1, 2), &target, list())
        .await
        .expect("family 2 is kept");
    assert_eq!(up.count("server/discover"), 3);
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("family 1 probes again");
    assert_eq!(up.count("server/discover"), 4);
    assert_eq!(links.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_total_bound_keeps_len_at_three() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::with_bounds(3, 2);
    let target = target_at(&fx, up.url());
    for user in 1..=5 {
        ask(&links, &fx.state, owned(user, user), &target, list())
            .await
            .expect("lists");
        assert!(links.len() <= 3);
    }
    assert_eq!(links.len(), 3);
    assert_eq!(up.count("server/discover"), 5);
    ask(&links, &fx.state, owned(5, 5), &target, list())
        .await
        .expect("the newest is kept");
    assert_eq!(up.count("server/discover"), 5);
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("the oldest probes again");
    assert_eq!(up.count("server/discover"), 6);
    assert_eq!(links.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_link_does_not_hold_up_another_link() {
    let slow = start(Behave {
        wait: Duration::from_millis(2000),
        ..Behave::default()
    })
    .await;
    let fast = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Arc::new(Links::new());
    let slow_target = target_at(&fx, slow.url());
    let fast_target = target_at(&fx, fast.url());
    let slow_task = {
        let links = Arc::clone(&links);
        let state = fx.state.clone();
        tokio::spawn(async move { ask(&links, &state, owned(1, 1), &slow_target, list()).await })
    };
    let answered = timeout(
        Duration::from_millis(1000),
        ask(&links, &fx.state, owned(2, 2), &fast_target, list()),
    )
    .await;
    match answered {
        Ok(result) => {
            result.expect("the fast link answers");
        }
        Err(_) => panic!("the fast link waited for the slow handshake"),
    }
    assert!(!slow_task.is_finished());
    slow_task
        .await
        .expect("the slow task")
        .expect("the slow link answers");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fault_names_no_session_id() {
    let up = start(Behave {
        fixed_id: Some("leaky id".to_owned()),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let result = ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        list(),
    )
    .await;
    match result {
        Err(fault) => {
            let text = format!("{fault:?}");
            assert_eq!(text, "Fault");
            assert!(!text.contains("leaky"));
        }
        Ok(_) => panic!("a session id with a space is a fault"),
    }
}

/// Points the fixture's server row at `url` and gives it the shared secret header.
async fn point_server_at(fx: &Fixture, url: &str) {
    let sealed = servers::seal(&fx.state.keys, fx.server_id, SECRET_VALUE).expect("seal");
    let (url, id) = (url.to_owned(), fx.server_id);
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET upstream_url = ?1, secret_header_name = ?2, \
                 secret_header_value = ?3 WHERE id = ?4",
                params![url, SECRET_NAME, sealed, id],
            )
        })
        .await
        .expect("the server row");
}

/// Changes only the URL of the fixture's server row.
async fn repoint_server(fx: &Fixture, url: &str) {
    let (url, id) = (url.to_owned(), fx.server_id);
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
                params![url, id],
            )
        })
        .await
        .expect("the server row");
}

/// The target the gateway loads for the fixture's server row.
async fn server_target(fx: &Fixture) -> Target {
    upstream::target(&fx.state, fx.server_id)
        .await
        .expect("the target")
        .expect("the server row")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_links_ids_do_not_depend_on_other_links() {
    let up = start(Behave::stateless()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    for _ in 0..5 {
        ask(&links, &fx.state, owned(1, 1), &target, list())
            .await
            .expect("family 1 lists");
    }
    ask(&links, &fx.state, owned(2, 2), &target, list())
        .await
        .expect("family 2 lists");
    let ids: Vec<Value> = up
        .bodies("tools/list")
        .iter()
        .map(|body| serde_json::from_str::<Value>(body).expect("a JSON body")["id"].clone())
        .collect();
    assert_eq!(
        ids,
        vec![json!(3), json!(4), json!(5), json!(6), json!(7), json!(3),]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_evicted_session_is_closed_with_the_secret() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    point_server_at(&fx, up.url()).await;
    let links = Links::with_bounds(1, 1);
    let target = server_target(&fx).await;
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("the first family lists");
    ask(&links, &fx.state, owned(2, 2), &target, list())
        .await
        .expect("the second family lists and evicts the first");
    wait_for(&up, "DELETE", 1).await;
    let deletes: Vec<Seen> = up
        .seen()
        .into_iter()
        .filter(|seen| kind_of(seen) == "DELETE")
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].header("mcp-session-id"), Some("s1"));
    assert_eq!(deletes[0].header(SECRET_NAME), Some(SECRET_VALUE));
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_evicted_session_of_a_repointed_server_is_not_closed() {
    let first = start(Behave {
        fixed_id: Some("from-first".to_owned()),
        ..Behave::default()
    })
    .await;
    let second = start(Behave {
        fixed_id: Some("from-second".to_owned()),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    point_server_at(&fx, first.url()).await;
    let links = Links::with_bounds(1, 1);
    let old = server_target(&fx).await;
    ask(&links, &fx.state, owned(1, 1), &old, list())
        .await
        .expect("the first family lists on the first upstream");
    repoint_server(&fx, second.url()).await;
    let new = server_target(&fx).await;
    ask(&links, &fx.state, owned(2, 2), &new, list())
        .await
        .expect("the second family lists on the second upstream");
    // The eviction close runs in the background; this waits for it to finish.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        first
            .sessions("DELETE")
            .iter()
            .all(|session| session.as_deref() != Some("from-first"))
    );
    assert!(
        second
            .sessions("DELETE")
            .iter()
            .all(|session| session.as_deref() != Some("from-first"))
    );
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_slower_than_the_deadline_is_a_fault() {
    let up = start(Behave {
        probe_wait: Duration::from_millis(700),
        wait: Duration::from_millis(700),
        ..Behave::default()
    })
    .await;
    let fx = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    let started = Instant::now();
    let result = ask(&links, &fx.state, owned(1, 1), &target, list()).await;
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(Fault)));
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1500),
        "answered after {elapsed:?}"
    );
    assert_eq!(links.len(), 0);
    {
        let mut ledger = up.ledger();
        ledger.probe_wait = Duration::ZERO;
        ledger.init_wait = Duration::ZERO;
    }
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("the next send makes the link");
    assert_eq!(links.len(), 1);
}

/// A target for the fixture's server with the shared header name and `value`.
fn target_with_secret(fx: &Fixture, url: &str, value: &'static str) -> Target {
    Target {
        secret: Some((
            HeaderName::from_static(SECRET_NAME),
            HeaderValue::from_static(value),
        )),
        ..target_at(fx, url)
    }
}

/// The `params._meta` of a recorded request body, when it has one.
fn meta_of(body: &str) -> Option<Value> {
    serde_json::from_str::<Value>(body).expect("a JSON body")["params"]
        .get("_meta")
        .cloned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_secret_makes_a_new_link() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let first = target_with_secret(&fx, up.url(), "1");
    let second = target_with_secret(&fx, up.url(), "2");
    ask(&links, &fx.state, owned(1, 1), &first, list())
        .await
        .expect("the first secret lists");
    ask(&links, &fx.state, owned(1, 1), &second, list())
        .await
        .expect("the second secret lists");
    assert_eq!(up.count("initialize"), 2);
    let lists: Vec<Seen> = up
        .seen()
        .into_iter()
        .filter(|seen| kind_of(seen) == "tools/list")
        .collect();
    assert_eq!(lists.len(), 2);
    assert_eq!(lists[1].header(SECRET_NAME), Some("2"));
    assert_eq!(lists[1].header("mcp-session-id"), Some("s2"));
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_drop_leaves_the_newer_link() {
    let up = start(Behave::default()).await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    let owner = owned(1, 1);
    ask(&links, &fx.state, owner, &target, list())
        .await
        .expect("the first link");
    let first = links
        .generation_of(owner, fx.server_id)
        .expect("the first link is kept");
    assert!(links.drop_generation(owner, fx.server_id, first));
    ask(&links, &fx.state, owner, &target, list())
        .await
        .expect("the second link");
    let second = links
        .generation_of(owner, fx.server_id)
        .expect("the second link is kept");
    assert_ne!(first, second);
    assert!(!links.drop_generation(owner, fx.server_id, first));
    assert_eq!(links.generation_of(owner, fx.server_id), Some(second));
    ask(&links, &fx.state, owner, &target, list())
        .await
        .expect("the newer link still answers");
    assert_eq!(up.count("server/discover"), 2);
    assert_eq!(up.count("initialize"), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_of_257_bytes_is_a_fault() {
    let up = start(Behave {
        fixed_id: Some("x".repeat(257)),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let result = ask(
        &links,
        &fx.state,
        owned(1, 1),
        &target_at(&fx, up.url()),
        list(),
    )
    .await;
    assert!(matches!(result, Err(Fault)));
    assert_eq!(links.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_request_carries_the_version_capabilities_and_client_info() {
    let fx = fixture().await;
    let links = Links::new();
    let up = start(Behave::stateless()).await;
    let target = target_at(&fx, up.url());
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("a stateless list");
    ask(&links, &fx.state, owned(1, 1), &target, echo(None))
        .await
        .expect("a stateless call");
    let expected = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {
            "name": "doorward",
            "version": env!("CARGO_PKG_VERSION"),
        },
    });
    let list_body = up.bodies("tools/list").remove(0);
    let call_body = up.bodies("tools/call").remove(0);
    assert_eq!(meta_of(&list_body), Some(expected.clone()));
    assert_eq!(meta_of(&call_body), Some(expected));

    let session = start(Behave::default()).await;
    let target = target_at(&fx, session.url());
    let token = json!("tok-7");
    ask(&links, &fx.state, owned(2, 2), &target, list())
        .await
        .expect("a session list");
    ask(
        &links,
        &fx.state,
        owned(2, 2),
        &target,
        Ask::Call {
            name: "echo",
            arguments: None,
            progress_token: Some(&token),
        },
    )
    .await
    .expect("a session call");
    let session_list = session.bodies("tools/list").remove(0);
    let session_call = session.bodies("tools/call").remove(0);
    assert_eq!(meta_of(&session_list), None);
    assert_eq!(
        meta_of(&session_call),
        Some(json!({"progressToken": "tok-7"}))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_requester_still_finishes_the_handshake() {
    let up = start(Behave {
        wait: Duration::from_millis(100),
        ..Behave::default()
    })
    .await;
    let fx = fixture().await;
    let links = Links::new();
    let target = target_at(&fx, up.url());
    for _ in 0..20 {
        let _left = timeout(
            Duration::from_millis(20),
            ask(&links, &fx.state, owned(1, 1), &target, list()),
        )
        .await;
    }
    ask(&links, &fx.state, owned(1, 1), &target, list())
        .await
        .expect("a normal send after the dropped ones");
    assert_eq!(up.count("initialize"), 1);
    assert_eq!(links.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_makes_each_link_once_and_tells_its_form() {
    let fx = fixture().await;
    let links = Links::new();
    let stateless_up = start(Behave::stateless()).await;
    let stateless_target = target_at(&fx, stateless_up.url());
    assert!(
        links
            .stateless(&fx.state, owned(1, 1), &stateless_target)
            .await
            .expect("the stateless form"),
        "a stateless upstream's link must tell the stateless form"
    );
    assert!(
        links
            .stateless(&fx.state, owned(1, 1), &stateless_target)
            .await
            .expect("the stateless form"),
        "the same link tells the same form again"
    );
    assert_eq!(
        stateless_up.count("server/discover"),
        1,
        "the stateless link is made with one probe"
    );
    assert_eq!(stateless_up.count("initialize"), 0);

    let session_up = start(Behave::default()).await;
    let session_target = target_at(&fx, session_up.url());
    assert!(
        !links
            .stateless(&fx.state, owned(1, 2), &session_target)
            .await
            .expect("the session form"),
        "a session upstream's link must not tell the stateless form"
    );
    assert!(
        !links
            .stateless(&fx.state, owned(1, 2), &session_target)
            .await
            .expect("the session form"),
        "the same session link tells the session form again"
    );
    assert_eq!(
        session_up.count("initialize"),
        1,
        "the session link is made with one initialize"
    );
    assert_eq!(links.len(), 2, "one link per owner and server");
}
