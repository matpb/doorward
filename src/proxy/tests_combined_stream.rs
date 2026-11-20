//! The combined endpoint's relay of a streamed tools/call, over a fixture gateway and scripted upstreams.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use futures_util::{StreamExt, stream};
use rusqlite::params;
use serde_json::{Value, json};
use tokio::time::timeout;

use super::combined::handle;
use super::tests::{Fixture, Plan, Seen, TestUpstream, answer, fixture, fixture_with};
use crate::app::AppState;
use crate::config::Lifetimes;
use crate::crypto::token_hash;
use crate::oauth::families::{self, NewFamily};
use crate::oauth::guard::Caller;

/// One row of the tool_call activity: tool, decision, outcome and detail.
type Row = (String, String, String, String);

/// Counts a scripted body that was dropped, which is when its connection was closed.
struct Closed(Arc<AtomicUsize>);

impl Drop for Closed {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// An event stream that sends each step's text after its wait in milliseconds, then stays open when
/// `hang` and ends otherwise.
fn scripted(steps: Vec<(u64, String)>, hang: bool, closed: &Arc<AtomicUsize>) -> Plan {
    let guard = Closed(Arc::clone(closed));
    let body = stream::unfold(
        (steps.into_iter(), guard),
        move |(mut steps, guard)| async move {
            match steps.next() {
                Some((wait, text)) => {
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    Some((Ok::<Bytes, io::Error>(Bytes::from(text)), (steps, guard)))
                }
                None if hang => std::future::pending().await,
                None => None,
            }
        },
    );
    Plan::Reply(
        Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(body))
            .expect("response"),
    )
}

/// A stateless upstream: `tools` as its list, and `call` as its answer to each tools/call.
async fn upstream(
    tools: &[&str],
    call: impl Fn(&Seen) -> Plan + Send + Sync + 'static,
) -> TestUpstream {
    let listed: Vec<Value> = tools.iter().map(|name| tool(name)).collect();
    TestUpstream::start(move |seen: &Seen| match seen.rpc().as_str() {
        "server/discover" => reply(seen, discover()),
        "tools/list" => reply(seen, json!({"tools": listed.clone()})),
        "tools/call" => call(seen),
        _ => reply(seen, json!({})),
    })
    .await
}

/// The JSON answer of `seen` with `result`.
fn reply(seen: &Seen, result: Value) -> Plan {
    let id = seen.json()["id"].clone();
    answer(
        200,
        None,
        Some("application/json"),
        &json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
    )
}

fn tool(name: &str) -> Value {
    json!({"name": name, "inputSchema": {"type": "object"}})
}

fn discover() -> Value {
    json!({
        "supportedVersions": ["2026-07-28"],
        "capabilities": {"tools": {}},
        "cacheScope": "public",
        "resultType": "complete",
    })
}

/// One server-sent event carrying `value`.
fn event(value: &Value) -> String {
    format!("data: {value}\n\n")
}

fn progress(n: u64) -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": n, "total": 3, "progressToken": "t"}})
}

/// A progress notification whose message is `size` bytes long.
fn padded_progress(size: usize) -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"message": "x".repeat(size)}})
}

/// The answer to request `id` that echoes.
fn echo_answer(id: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": "called: echo"}]}})
}

/// The answer the client of call 41 gets for `result`.
fn for_41(result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 41, "result": result})
}

fn echo_for_41() -> Value {
    for_41(json!({"content": [{"type": "text", "text": "called: echo"}]}))
}

fn unavailable_for_41() -> Value {
    json!({"jsonrpc": "2.0", "id": 41, "error": {"code": -32000, "message": "Upstream demo is unavailable"}})
}

fn refusal_for_41(name: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 41, "error": {"code": -32602, "message": format!("Unknown tool: {name}")}})
}

/// A session-style tools/call of `name` with id 41.
fn call_of(name: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call", "params": {"name": name, "arguments": {}}})
}

/// The same call as a stateless client sends it, with its headers.
fn stateless_post(name: &str) -> Request {
    let body = json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call", "params": {
        "name": name,
        "arguments": {},
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}},
    }});
    let headers = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", name),
    ];
    post(&body, &headers)
}

/// A POST to `/mcp` with `headers` and the body `value`.
fn post(value: &Value, headers: &[(&str, &str)]) -> Request {
    let mut builder = Request::builder().method("POST").uri("/mcp");
    for (name, header) in headers {
        builder = builder.header(*name, *header);
    }
    builder
        .body(Body::from(value.to_string()))
        .expect("request")
}

/// Points the fixture's server at `up`, assigns user 1 to it, and gives the user's combined caller.
async fn setup(fx: &Fixture, up: &TestUpstream) -> Caller {
    let (url, server) = (up.url.clone(), fx.server_id);
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
                params![url, server],
            )?;
            conn.execute(
                "INSERT INTO users (id, email, password_hash, role, created_at) \
                 VALUES (1, 'user1@example.com', 'hash', 'user', 0)",
                [],
            )?;
            conn.execute(
                "INSERT INTO user_servers (user_id, server_id) VALUES (1, ?1)",
                params![server],
            )?;
            Ok(())
        })
        .await
        .expect("the server and the user");
    combined_caller(&fx.state).await
}

/// A combined token family of user 1, and the caller its access token gives.
async fn combined_caller(state: &AppState) -> Caller {
    let now = state.clock.now().unix_timestamp();
    let (family_id, access) = state
        .db
        .call(move |conn| {
            let epoch: i64 =
                conn.query_row("SELECT auth_epoch FROM users WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
            let new = NewFamily {
                user_id: 1,
                server_id: None,
                client_id: "dcr_test",
                client_name: "test client",
                auth_epoch: epoch,
            };
            let family_id = families::create(conn, &new, now, 90)?;
            let pair = families::mint_pair(conn, family_id, now, &Lifetimes::default())?;
            Ok((family_id, pair.access_token))
        })
        .await
        .expect("a combined token");
    Caller {
        user_id: 1,
        user_email: "user1@example.com".to_owned(),
        family_id,
        server_id: None,
        client_name: "test client".to_owned(),
        token_hash: token_hash(&access),
    }
}

/// Another caller of the same family as `caller`, so both share one upstream link.
fn same(caller: &Caller) -> Caller {
    Caller {
        user_id: caller.user_id,
        user_email: caller.user_email.clone(),
        family_id: caller.family_id,
        server_id: None,
        client_name: caller.client_name.clone(),
        token_hash: caller.token_hash.clone(),
    }
}

/// A session tools/list through `caller`, so the catalog and the link exist before a timed call.
async fn prime(state: &AppState, caller: Caller) {
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let response = handle(state, caller, post(&list, &[])).await;
    assert_eq!(response.status().as_u16(), 200, "the list must be answered");
    to_bytes(response.into_body(), 1 << 22)
        .await
        .expect("the list body");
}

/// Removes the assignment of user 1 to the fixture's server.
async fn unassign(state: &AppState, server_id: i64) {
    state
        .db
        .call(move |conn| {
            conn.execute(
                "DELETE FROM user_servers WHERE user_id = 1 AND server_id = ?1",
                params![server_id],
            )
        })
        .await
        .expect("the unassignment");
}

/// A streamed answer read to its end: its status, its headers, and each chunk with its arrival.
struct Streamed {
    status: u16,
    headers: HeaderMap,
    chunks: Vec<(Instant, Bytes)>,
}

impl Streamed {
    fn text(&self) -> String {
        let bytes: Vec<u8> = self
            .chunks
            .iter()
            .flat_map(|(_, chunk)| chunk.iter().copied())
            .collect();
        String::from_utf8(bytes).expect("a UTF-8 stream")
    }

    /// The parsed data of each event, each of which must be exactly an `event: message` line and a data line.
    fn events(&self) -> Vec<Value> {
        let text = self.text();
        text.split("\n\n")
            .filter(|block| !block.is_empty())
            .map(|block| {
                let lines: Vec<&str> = block.split('\n').collect();
                assert_eq!(
                    lines.len(),
                    2,
                    "one event line and one data line: {block:?}"
                );
                assert_eq!(lines[0], "event: message", "the event line of {block:?}");
                let data = lines[1].strip_prefix("data: ").expect("a data line");
                serde_json::from_str(data).expect("the data is JSON")
            })
            .collect()
    }
}

/// Reads a response body to its end, within ten seconds, keeping each chunk's arrival time.
async fn read(response: Response) -> Streamed {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut data = response.into_body().into_data_stream();
    let mut chunks = Vec::new();
    let reading = async {
        while let Some(chunk) = data.next().await {
            chunks.push((Instant::now(), chunk.expect("a body chunk")));
        }
    };
    timeout(Duration::from_secs(10), reading)
        .await
        .expect("the stream must end within ten seconds");
    Streamed {
        status,
        headers,
        chunks,
    }
}

/// The tool_call rows, oldest first.
async fn rows(state: &AppState) -> Vec<Row> {
    state
        .db
        .call(|conn| {
            let mut statement = conn.prepare(
                "SELECT tool, decision, outcome, detail FROM activity \
                 WHERE kind = 'tool_call' ORDER BY id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<Row>>>()
        })
        .await
        .expect("the activity rows")
}

/// The tool_call rows, polled for up to 3 seconds until there are `wanted` of them.
async fn wait_for_rows(state: &AppState, wanted: usize) -> Vec<Row> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let found = rows(state).await;
        if found.len() >= wanted || Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The row of an allowed call of `tool` that ends as `outcome`.
fn row(tool: &str, outcome: &str, detail: &str) -> Row {
    (
        tool.to_owned(),
        "allow".to_owned(),
        outcome.to_owned(),
        detail.to_owned(),
    )
}

/// Every kind of line the relay must drop, then two progress notifications, the answer under the
/// client's upstream `id`, and one more progress notification after it.
fn mixed_stream(id: &Value) -> String {
    [
        event(&json!({"jsonrpc": "2.0", "id": "srv-9", "method": "elicitation/create", "params": {}})),
        format!(
            "event: message\n{}",
            event(&json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "text"}}))
        ),
        format!(
            "id: 7\nretry: 5\n: a comment\n{}",
            event(&json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}}))
        ),
        "data: {not json\n\n".to_owned(),
        "data: [1, 2]\n\n".to_owned(),
        event(&json!({"jsonrpc": "2.0", "id": 999, "result": {"content": []}})),
        event(&progress(1)),
        event(&progress(2)),
        event(&echo_answer(id)),
        event(&progress(3)),
    ]
    .concat()
}

#[tokio::test(flavor = "multi_thread")]
async fn only_progress_and_the_answer_reach_the_client() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let text = mixed_stream(&seen.json()["id"]);
        let steps = text
            .as_bytes()
            .chunks(37)
            .map(|piece| (0, String::from_utf8_lossy(piece).into_owned()))
            .collect();
        scripted(steps, true, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(streamed.status, 200, "the streamed call must be answered");
    let text = streamed.text();
    assert!(
        !text.lines().any(|line| line.starts_with("id:")
            || line.starts_with("retry:")
            || line.starts_with(':')),
        "no id, retry or comment line may reach the client: {text}"
    );
    assert!(
        !text.contains(r#""id":"srv-9""#),
        "the upstream request id must not reach the client: {text}"
    );
    assert_eq!(
        streamed.events(),
        vec![progress(1), progress(2), echo_for_41()],
        "the client gets two progress notifications and the answer, nothing else"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "ok", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_progress_reaches_the_client_before_a_slow_answer() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        scripted(
            vec![(0, event(&progress(1))), (400, event(&echo_answer(&id)))],
            false,
            &closed,
        )
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(streamed.events(), vec![progress(1), echo_for_41()]);
    let first = streamed.chunks.first().expect("the progress chunk").0;
    let last = streamed.chunks.last().expect("the answer chunk").0;
    assert!(
        last.duration_since(first) >= Duration::from_millis(300),
        "the progress must arrive at least 300 ms before the answer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_ends_without_an_answer_is_unavailable() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |_: &Seen| {
        scripted(vec![(0, event(&progress(1)))], false, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(
        streamed.events(),
        vec![progress(1), unavailable_for_41()],
        "the last event names the server as unavailable"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "unavailable", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_event_over_the_cap_ends_the_stream_as_unavailable() {
    let fx = fixture_with(|config| config.limits.tools_list_bytes = 1024).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |_: &Seen| {
        scripted(
            vec![(0, event(&progress(1))), (0, event(&padded_progress(2000)))],
            true,
            &closed,
        )
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(
        streamed.events(),
        vec![progress(1), unavailable_for_41()],
        "an event over the cap ends the stream"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "unavailable", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn silence_past_the_time_limit_ends_the_stream_as_unavailable() {
    let fx = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |_: &Seen| {
        scripted(vec![(0, event(&progress(1)))], true, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(streamed.events(), vec![progress(1), unavailable_for_41()]);
    assert_eq!(rows(&fx.state).await, vec![row("echo", "unavailable", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn comment_lines_keep_a_quiet_stream_open_until_its_answer() {
    let fx = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        let mut steps: Vec<(u64, String)> =
            (0..6).map(|_| (400, ": ping\n\n".to_owned())).collect();
        steps.push((100, event(&echo_answer(&id))));
        scripted(steps, false, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(streamed.events(), vec![echo_for_41()]);
    assert_eq!(rows(&fx.state).await, vec![row("echo", "ok", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_unassigned_before_the_answer_gets_the_refusal() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        scripted(vec![(300, event(&echo_answer(&id)))], false, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    prime(&fx.state, same(&caller)).await;
    let state = &fx.state;
    let (streamed, ()) = tokio::join!(
        async {
            let response = handle(state, caller, post(&call_of("demo__echo"), &[])).await;
            read(response).await
        },
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            unassign(state, fx.server_id).await;
        },
    );
    assert_eq!(
        streamed.events(),
        vec![refusal_for_41("demo__echo")],
        "the answer the upstream held is replaced by the refusal"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "refused", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_unassigned_mid_stream_ends_it_within_two_and_a_half_seconds() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        scripted(
            vec![(0, event(&progress(1))), (5000, event(&echo_answer(&id)))],
            false,
            &closed,
        )
    })
    .await;
    let caller = setup(&fx, &up).await;
    prime(&fx.state, same(&caller)).await;
    let state = &fx.state;
    let started = Instant::now();
    let (streamed, ()) = tokio::join!(
        async {
            let response = handle(state, caller, post(&call_of("demo__echo"), &[])).await;
            read(response).await
        },
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            unassign(state, fx.server_id).await;
        },
    );
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "the stream must end within 2.5 seconds, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        streamed.events(),
        vec![progress(1)],
        "no answer event may follow the refusal"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "refused", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_still_assigned_user_keeps_a_two_and_a_half_second_stream() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        scripted(
            vec![(0, event(&progress(1))), (2500, event(&echo_answer(&id)))],
            false,
            &closed,
        )
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(streamed.events(), vec![progress(1), echo_for_41()]);
    assert_eq!(rows(&fx.state).await, vec![row("echo", "ok", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_drops_the_stream_closes_the_upstream_and_writes_error() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let watch = Arc::clone(&closed);
    let up = upstream(&["echo"], move |_: &Seen| {
        scripted(vec![(0, event(&progress(1)))], true, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let response = handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await;
    let mut data = response.into_body().into_data_stream();
    let first = data
        .next()
        .await
        .expect("the progress chunk")
        .expect("a body chunk");
    assert!(String::from_utf8_lossy(&first).contains("notifications/progress"));
    drop(data);
    let deadline = Instant::now() + Duration::from_secs(2);
    while watch.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the upstream connection must be closed within 2 seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        wait_for_rows(&fx.state, 1).await,
        vec![row("echo", "error", "the client closed the stream")]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_result_asking_for_input_is_a_tool_error_and_resulttype_follows_the_client() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["ask", "done"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        let result = match seen.json()["params"]["name"].as_str() {
            Some("ask") => json!({"resultType": "input_required", "content": [{"type": "text", "text": "needs input"}]}),
            _ => json!({"resultType": "complete", "content": [{"type": "text", "text": "done"}]}),
        };
        let answer = json!({"jsonrpc": "2.0", "id": id, "result": result});
        scripted(vec![(0, event(&answer))], true, &closed)
    })
    .await;
    let session = setup(&fx, &up).await;
    let asked =
        read(handle(&fx.state, same(&session), post(&call_of("demo__ask"), &[])).await).await;
    assert_eq!(
        asked.events(),
        vec![for_41(json!({
            "content": [{"type": "text", "text": "This tool asked for input that this endpoint does not relay."}],
            "isError": true,
        }))],
        "a session client gets the tool error with no resultType"
    );
    let stateless =
        read(handle(&fx.state, same(&session), stateless_post("demo__done")).await).await;
    assert_eq!(
        stateless.events(),
        vec![for_41(
            json!({"resultType": "complete", "content": [{"type": "text", "text": "done"}]})
        )],
        "a stateless client's streamed result is marked complete"
    );
    let plain =
        read(handle(&fx.state, same(&session), post(&call_of("demo__done"), &[])).await).await;
    assert_eq!(
        plain.events(),
        vec![for_41(
            json!({"content": [{"type": "text", "text": "done"}]})
        )],
        "a session client's streamed result has no resultType"
    );
    assert_eq!(
        rows(&fx.state).await,
        vec![
            row("ask", "error", ""),
            row("done", "ok", ""),
            row("done", "ok", ""),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_answer_carries_the_inert_headers_and_no_session_id() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        scripted(vec![(0, event(&echo_answer(&id)))], false, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(streamed.status, 200, "the streamed call must be answered");
    let header = |name: &str| {
        streamed
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(header("content-type").as_deref(), Some("text/event-stream"));
    assert_eq!(header("x-content-type-options").as_deref(), Some("nosniff"));
    assert_eq!(
        header("content-security-policy").as_deref(),
        Some("sandbox")
    );
    assert_eq!(
        header("mcp-session-id"),
        None,
        "no session id on the stream"
    );
    assert_eq!(header("set-cookie"), None, "no cookie on the stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn each_streamed_call_writes_exactly_one_row() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo", "gone", "ask"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        match seen.json()["params"]["name"].as_str() {
            Some("echo") => scripted(vec![(0, event(&echo_answer(&id)))], true, &closed),
            Some("gone") => scripted(vec![(0, event(&progress(1)))], false, &closed),
            _ => {
                let answer = json!({"jsonrpc": "2.0", "id": id, "result": {"resultType": "input_required", "content": []}});
                scripted(vec![(0, event(&answer))], true, &closed)
            }
        }
    })
    .await;
    let caller = setup(&fx, &up).await;
    for name in ["demo__echo", "demo__gone", "demo__ask"] {
        let response = handle(&fx.state, same(&caller), post(&call_of(name), &[])).await;
        let streamed = read(response).await;
        assert_eq!(
            streamed
                .headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream"),
            "{name} must be relayed as a stream"
        );
    }
    assert_eq!(
        rows(&fx.state).await,
        vec![
            row("echo", "ok", ""),
            row("gone", "unavailable", ""),
            row("ask", "error", ""),
        ],
        "three streamed calls write three rows, one each"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_progress_method_with_an_id_is_an_upstream_request_and_is_dropped() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        let request = json!({"jsonrpc": "2.0", "id": 99, "method": "notifications/progress", "params": {"progress": 5, "total": 9, "progressToken": "t"}});
        scripted(
            vec![
                (0, event(&request)),
                (0, event(&progress(1))),
                (0, event(&echo_answer(&id))),
            ],
            true,
            &closed,
        )
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    let text = streamed.text();
    assert!(
        !text.contains("99"),
        "an upstream request with a progress method must not reach the client: {text}"
    );
    assert_eq!(
        streamed.events(),
        vec![progress(1), echo_for_41()],
        "the client gets one progress notification and the answer"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "ok", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_with_both_result_and_error_is_not_the_answer() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        let both = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"content": [{"type": "text", "text": "called: echo"}]},
            "error": {"code": -32000, "message": "boom"},
        });
        scripted(vec![(0, event(&both))], false, &closed)
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(
        streamed.events(),
        vec![unavailable_for_41()],
        "an object with both members is not the answer, so no result reaches the client"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "unavailable", "")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_whose_final_message_is_an_upstream_error_reaches_the_client_with_its_id() {
    let fx = fixture().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let up = upstream(&["echo"], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        let error = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32021,
            "message": "MissingRequiredClientCapabilityError",
            "data": {"requiredCapabilities": {"sampling": {}}}}});
        scripted(
            vec![(0, event(&progress(1))), (0, event(&error))],
            false,
            &closed,
        )
    })
    .await;
    let caller = setup(&fx, &up).await;
    let streamed = read(handle(&fx.state, caller, post(&call_of("demo__echo"), &[])).await).await;
    assert_eq!(
        streamed.events(),
        vec![
            progress(1),
            json!({"jsonrpc": "2.0", "id": 41, "error": {"code": -32021,
                "message": "MissingRequiredClientCapabilityError",
                "data": {"requiredCapabilities": {"sampling": {}}}}}),
        ],
        "the error reaches the client under its own id"
    );
    assert_eq!(rows(&fx.state).await, vec![row("echo", "error", "")]);
}
