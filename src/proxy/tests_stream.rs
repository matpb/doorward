//! The watched relay of an event stream over real HTTP, on the fixtures of `tests_handle`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use rusqlite::params;
use serde_json::{Value, json};

use super::sse::sse_events;
use super::stream::{Framing, Observed, Observer, outcome_of};
use super::tests_handle::{
    CAROL, Demo, Gw, Mode, Reply, Row, Tail, call_body, demo, demo_with, initialize_body,
    initialized, notice, now, session_body, session_headers,
};
use crate::accounts::session;
use crate::crypto::token_hash;
use crate::oauth::families;

/// One server-sent event carrying `data`.
fn event(data: &Value) -> String {
    format!("data: {data}\n\n")
}

/// The answer to request `id` with `result`, as an event.
fn answer_event(id: i64, result: Value) -> String {
    event(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// The error answer to request `id`, as an event.
fn error_event(id: i64) -> String {
    event(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "x"}}))
}

/// The text of a tools/call result, as the upstream sends it.
fn echo_result() -> Value {
    json!({"content": [{"type": "text", "text": "called: echo"}]})
}

/// A stream of `chunks`, each after its wait in milliseconds, then `tail`.
fn script(chunks: Vec<(u64, String)>, tail: Tail, closed: &Arc<AtomicUsize>) -> Mode {
    Mode::Chunks {
        chunks,
        tail,
        closed: Arc::clone(closed),
    }
}

/// A stream that sends one notice and then stays silent.
fn silent(closed: &Arc<AtomicUsize>) -> Mode {
    script(vec![(0, event(&notice()))], Tail::Hang, closed)
}

/// Sends a request to `/demo` with `token`, and returns the response unread.
async fn open(
    gw: &Gw,
    token: &str,
    method: reqwest::Method,
    headers: Vec<(&str, String)>,
    body: Option<String>,
) -> reqwest::Response {
    let mut request = gw
        .http
        .request(method, format!("{}/demo", gw.base))
        .bearer_auth(token);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    request.send().await.expect("request")
}

/// Reads the body to its end, with the instant each chunk arrived.
async fn drain(response: &mut reqwest::Response) -> Vec<(Instant, Bytes)> {
    let mut chunks = Vec::new();
    while let Some(chunk) = response.chunk().await.expect("chunk") {
        chunks.push((Instant::now(), chunk));
    }
    chunks
}

/// The bytes of drained chunks, in order.
fn joined(chunks: &[(Instant, Bytes)]) -> Vec<u8> {
    chunks
        .iter()
        .flat_map(|(_, chunk)| chunk.iter().copied())
        .collect()
}

/// Polls `ready` every 20 ms until it holds or `within` has passed.
async fn wait_until(within: Duration, ready: impl Fn() -> bool) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ready()
}

/// The activity rows once `count` exist, or the rows there are when `within` has passed.
async fn rows_within(gw: &Gw, count: usize, within: Duration) -> Vec<Row> {
    wait_until(within, || gw.tool_calls().len() >= count).await;
    gw.tool_calls()
}

/// The detail text of every tool-call row, in order.
fn details(gw: &Gw) -> Vec<String> {
    let conn = gw.conn();
    let mut statement = conn
        .prepare("SELECT detail FROM activity WHERE kind = 'tool_call' ORDER BY id")
        .expect("details");
    let rows = statement.query_map([], |row| row.get(0)).expect("rows");
    rows.map(|row| row.expect("row")).collect()
}

/// Whether the upstream has seen its response body dropped at least once.
fn seen_closed(counter: &AtomicUsize) -> bool {
    counter.load(Ordering::SeqCst) >= 1
}

/// One way of ending bob's access to the server while his stream is open.
#[derive(Clone, Copy)]
enum Cut {
    Disable,
    Revoke,
    Reset,
    Expire,
    Unassign,
}

/// Applies `how` to `user`, whose access token is `token`, on the server of `demo`.
fn cut(demo: &Demo, user: i64, token: &str, how: Cut) {
    let conn = demo.gw.conn();
    match how {
        Cut::Disable => {
            conn.execute("UPDATE users SET disabled = 1 WHERE id = ?1", params![user])
                .expect("disable");
        }
        Cut::Revoke => {
            let family: i64 = conn
                .query_row(
                    "SELECT family_id FROM access_tokens WHERE token_hash = ?1",
                    params![token_hash(token)],
                    |row| row.get(0),
                )
                .expect("family");
            families::revoke(&conn, family, now()).expect("revoke");
        }
        Cut::Reset => session::revoke_all(&conn, user).expect("reset"),
        Cut::Expire => demo.gw.clock.set(now() + 7200),
        Cut::Unassign => {
            conn.execute(
                "DELETE FROM user_servers WHERE user_id = ?1 AND server_id = ?2",
                params![user, demo.server],
            )
            .expect("unassign");
        }
    }
}

/// Bob's streamed call on `demo`, open on a silent upstream: the stream is open when this returns.
async fn open_call(demo: &Demo, closed: &Arc<AtomicUsize>) -> reqwest::Response {
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(demo).await;
    demo.fake.set(silent(closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    assert_eq!(response.status().as_u16(), 200, "the call must be answered");
    let first = response.chunk().await.expect("chunk").expect("the notice");
    assert!(String::from_utf8_lossy(&first).contains("notifications/message"));
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_call_writes_one_ok_row_and_none_while_it_is_open() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![(0, event(&notice())), (300, answer_event(1, echo_result()))],
        Tail::Close,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let first = response.chunk().await.expect("chunk").expect("the notice");
    assert!(String::from_utf8_lossy(&first).contains("notifications/message"));
    assert!(
        demo.gw.tool_calls().is_empty(),
        "no row may exist while the stream is still open"
    );
    drain(&mut response).await;
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 1, "one row per streamed call");
    assert_eq!(rows[0].tool, "echo");
    assert_eq!(rows[0].decision, "allow");
    assert_eq!(rows[0].outcome, "ok");
    assert_eq!(rows[0].user_id, Some(demo.bob));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_call_ending_with_a_json_rpc_error_writes_error() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake
        .set(script(vec![(0, error_event(1))], Tail::Close, &closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    drain(&mut response).await;
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "error");
}

#[tokio::test(flavor = "multi_thread")]
async fn events_reach_the_client_while_the_upstream_is_still_sending() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![
            (0, event(&notice())),
            (1000, answer_event(1, echo_result())),
        ],
        Tail::Close,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let chunks = drain(&mut response).await;
    let first = chunks.first().expect("the notice").0;
    let last = chunks.last().expect("the answer").0;
    assert!(
        last.saturating_duration_since(first) >= Duration::from_millis(500),
        "the notice must arrive about a second before the answer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_receives_exactly_the_upstream_bytes_split_events_included() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let pieces = vec![
        (
            0,
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/mess".to_owned(),
        ),
        (100, "age\",\"params\":{\"da".to_owned()),
        (100, "ta\":\"wo\"}}\n\ndata: {\"jsonrpc\"".to_owned()),
        (100, ":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n".to_owned()),
    ];
    let sent: String = pieces.iter().map(|(_, text)| text.as_str()).collect();
    demo.fake.set(script(pieces, Tail::Close, &closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let received = joined(&drain(&mut response).await);
    assert_eq!(received, sent.into_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_stops_mid_event_ends_the_client_stream_and_writes_unavailable() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![(0, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"resu".to_owned())],
        Tail::Close,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("the client stream must end when the upstream stops");
    let rows = demo.gw.tool_calls();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "unavailable");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_upstream_ends_the_stream_within_three_seconds_and_writes_unavailable() {
    let demo = demo_with(|c| c.limits.upstream_timeout_seconds = 1, (false, false)).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let mut response = open_call(&demo, &closed).await;
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("an idle stream must end within 3 seconds");
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "unavailable");
    assert!(
        wait_until(Duration::from_secs(2), || seen_closed(&closed)).await,
        "the upstream must see its connection closed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_event_larger_than_tools_list_bytes_ends_the_stream() {
    let demo = demo_with(|c| c.limits.tools_list_bytes = 2000, (false, false)).await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let big = format!("data: {}\n\n", "x".repeat(3000));
    demo.fake.set(script(
        vec![(0, event(&notice())), (0, big)],
        Tail::Hang,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("an oversize event must end the stream within 3 seconds");
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "unavailable");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_event_growing_past_tools_list_bytes_ends_the_stream() {
    let demo = demo_with(|c| c.limits.tools_list_bytes = 2000, (false, false)).await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![(0, format!("data: {}", "x".repeat(3000)))],
        Tail::Hang,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("an open event past the limit must end the stream within 3 seconds");
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "unavailable");
}

/// Bob's stream is cut off by `how` while it is open: it ends within 3 seconds, its upstream
/// connection closes, and its row is `refused`.
async fn a_cut_off_ends_an_open_stream(how: Cut) {
    let demo = demo().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let mut response = open_call(&demo, &closed).await;
    let bob = demo.bob;
    cut(&demo, bob, &demo.token, how);
    let rest = tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("the cut-off must end the stream within 3 seconds");
    assert!(rest.is_empty(), "the silent upstream sent nothing more");
    assert!(
        wait_until(Duration::from_secs(2), || seen_closed(&closed)).await,
        "the upstream must see its connection closed"
    );
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disabled_user_ends_an_open_stream() {
    a_cut_off_ends_an_open_stream(Cut::Disable).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_family_ends_an_open_stream() {
    a_cut_off_ends_an_open_stream(Cut::Revoke).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_reset_ends_an_open_stream() {
    a_cut_off_ends_an_open_stream(Cut::Reset).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_access_token_ends_an_open_stream() {
    a_cut_off_ends_an_open_stream(Cut::Expire).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unassigned_user_ends_an_open_stream() {
    a_cut_off_ends_an_open_stream(Cut::Unassign).await;
}

/// Bob's stream is cut off by `how`, and carol's stream on the same server stays open and
/// finishes with its answer.
async fn a_cut_off_spares_another_users_stream(how: Cut) {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let carol = demo.gw.add_user(CAROL);
    demo.gw.grant(carol, demo.server);
    let carol_token = demo.gw.token(carol, demo.server);
    demo.fake.set(Mode::Counted(Arc::new(AtomicUsize::new(0))));
    let bob_session = initialized(&demo).await;
    let carol_session = open(
        &demo.gw,
        &carol_token,
        reqwest::Method::POST,
        session_headers(None),
        Some(initialize_body()),
    )
    .await
    .headers()
    .get("mcp-session-id")
    .and_then(|value| value.to_str().ok())
    .expect("carol's initialize must relay a session id")
    .to_owned();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut steps: Vec<(u64, String)> = (0..30).map(|_| (100, event(&notice()))).collect();
    steps.push((0, answer_event(1, echo_result())));
    demo.fake.set(script(steps, Tail::Close, &closed));
    let mut bobs = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&bob_session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let mut carols = open(
        &demo.gw,
        &carol_token,
        reqwest::Method::POST,
        session_headers(Some(&carol_session)),
        Some(call_body(1, "echo")),
    )
    .await;
    bobs.chunk().await.expect("chunk");
    carols.chunk().await.expect("chunk");
    cut(&demo, demo.bob, &demo.token, how);
    tokio::time::timeout(Duration::from_secs(3), drain(&mut bobs))
        .await
        .expect("bob's stream must end within 3 seconds");
    let carol_rest = joined(&drain(&mut carols).await);
    assert!(
        String::from_utf8_lossy(&carol_rest).contains("called: echo"),
        "carol's stream must still deliver its answer"
    );
    let rows = rows_within(&demo.gw, 2, Duration::from_secs(2)).await;
    let outcome_of = |user: i64| {
        rows.iter()
            .find(|row| row.user_id == Some(user))
            .map(|row| row.outcome.clone())
    };
    assert_eq!(outcome_of(demo.bob).as_deref(), Some("refused"));
    assert_eq!(outcome_of(carol).as_deref(), Some("ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disabled_user_does_not_end_another_users_stream() {
    a_cut_off_spares_another_users_stream(Cut::Disable).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_family_does_not_end_another_users_stream() {
    a_cut_off_spares_another_users_stream(Cut::Revoke).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_reset_does_not_end_another_users_stream() {
    a_cut_off_spares_another_users_stream(Cut::Reset).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unassigned_user_does_not_end_another_users_stream() {
    a_cut_off_spares_another_users_stream(Cut::Unassign).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cut_off_fires_while_the_upstream_is_silent() {
    let demo = demo().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let mut response = open_call(&demo, &closed).await;
    let started = Instant::now();
    cut(&demo, demo.bob, &demo.token, Cut::Disable);
    let rest = tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("the cut-off must end the silent stream");
    assert!(rest.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the end must come from the gateway's own check, not from a chunk"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_drops_the_stream_closes_the_upstream_and_writes_error() {
    let demo = demo().await;
    let closed = Arc::new(AtomicUsize::new(0));
    let response = open_call(&demo, &closed).await;
    drop(response);
    assert!(
        wait_until(Duration::from_secs(2), || seen_closed(&closed)).await,
        "the upstream must see its connection closed within 2 seconds"
    );
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(2)).await;
    assert_eq!(rows.len(), 1, "one row when the client leaves");
    assert_eq!(rows[0].outcome, "error");
    assert_eq!(details(&demo.gw), vec!["the client closed the stream"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_seen_and_then_cut_off_records_the_answer_outcome() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![(0, answer_event(1, echo_result()))],
        Tail::Hang,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let first = response.chunk().await.expect("chunk").expect("the answer");
    assert!(String::from_utf8_lossy(&first).contains("called: echo"));
    cut(&demo, demo.bob, &demo.token, Cut::Disable);
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("the cut-off must end the stream within 3 seconds");
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "ok", "the answer's outcome is recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_for_another_method_writes_no_row() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![(0, event(&notice())), (0, answer_event(2, json!({})))],
        Tail::Close,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(session_body(2, "ping", json!({}))),
    )
    .await;
    let received = joined(&drain(&mut response).await);
    assert!(String::from_utf8_lossy(&received).contains("notifications/message"));
    assert!(demo.gw.tool_calls().is_empty(), "a ping writes no row");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_get_stream_is_relayed_ends_on_a_cut_off_and_writes_no_row() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(silent(&closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::GET,
        vec![
            ("mcp-session-id", session.clone()),
            ("accept", "text/event-stream".to_owned()),
        ],
        None,
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "the GET must open the stream"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let first = response.chunk().await.expect("chunk").expect("the notice");
    assert!(String::from_utf8_lossy(&first).contains("notifications/message"));
    cut(&demo, demo.bob, &demo.token, Cut::Disable);
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("the cut-off must end the GET stream within 3 seconds");
    assert!(
        wait_until(Duration::from_secs(2), || seen_closed(&closed)).await,
        "the upstream must see the GET's connection closed"
    );
    assert!(demo.gw.tool_calls().is_empty(), "a GET writes no row");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_get_answered_405_is_relayed_as_405_with_no_body() {
    let demo = demo().await;
    let session = initialized(&demo).await;
    demo.fake
        .set(Mode::Status(405, Some("application/json"), "{}"));
    let reply: Reply = demo
        .gw
        .send(
            reqwest::Method::GET,
            "/demo",
            Some(&demo.token),
            vec![("mcp-session-id", session)],
            None,
        )
        .await;
    assert_eq!(reply.status, 405, "a 405 is relayed");
    assert_eq!(reply.body, "", "the relayed 405 has no body");
    reply.assert_inert("the 405");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_get_answered_otherwise_is_the_502() {
    let cases: [(u16, Option<&'static str>, &'static str); 5] = [
        (200, Some("application/json"), "{}"),
        (200, None, ""),
        (404, Some("application/json"), "{}"),
        (404, Some("text/event-stream"), ""),
        (400, Some("text/event-stream"), ""),
    ];
    for (status, content_type, body) in cases {
        let demo = demo().await;
        let session = initialized(&demo).await;
        demo.fake.set(Mode::Status(status, content_type, body));
        let reply = demo
            .gw
            .send(
                reqwest::Method::GET,
                "/demo",
                Some(&demo.token),
                vec![("mcp-session-id", session)],
                None,
            )
            .await;
        assert_eq!(reply.status, 502, "a GET answered {status} must be the 502");
        assert_eq!(
            reply.error_message().as_deref(),
            Some("Upstream demo is unavailable")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_stream_arrives_in_pieces_and_writes_one_ok_row() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let mut steps: Vec<(u64, String)> = (0..20).map(|_| (50, event(&notice()))).collect();
    steps.push((0, answer_event(1, echo_result())));
    demo.fake.set(script(steps, Tail::Close, &closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let chunks = drain(&mut response).await;
    assert!(
        chunks.len() >= 2,
        "the stream must arrive in pieces, got {}",
        chunks.len()
    );
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "ok");
}

// The splitter's own tests, moved from the catalog's.

#[test]
fn sse_splitter_reads_lf_and_crlf_events() {
    let text = "data: {\"a\":1}\n\ndata: {\"b\":2}\r\n\r\n";
    let (events, used) = sse_events(text.as_bytes());
    assert_eq!(events, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
    assert_eq!(used, text.len());
}

#[test]
fn sse_splitter_skips_comments_and_other_fields() {
    let text = ": hello\nevent: message\nid: 7\nretry: 5\ndata: x\n\n";
    let (events, used) = sse_events(text.as_bytes());
    assert_eq!(events, vec![b"x".to_vec()]);
    assert_eq!(used, text.len());
}

#[test]
fn sse_splitter_joins_data_lines_and_drops_one_space() {
    let (events, _) = sse_events(b"data: a\ndata:b\n\n");
    assert_eq!(events, vec![b"a\nb".to_vec()]);
    let (events, _) = sse_events(b"data:  a\n\n");
    assert_eq!(events, vec![b" a".to_vec()], "only one space is dropped");
}

#[test]
fn sse_splitter_keeps_an_open_event_for_later() {
    let first = "data: {\"a\":1}\n\n";
    let text = format!("{first}data: {{\"b\"");
    let (events, used) = sse_events(text.as_bytes());
    assert_eq!(events, vec![b"{\"a\":1}".to_vec()]);
    assert_eq!(used, first.len());
    for unfinished in ["data: {\"a\":1}", "data: {\"a\":1}\n"] {
        let (events, used) = sse_events(unfinished.as_bytes());
        assert!(events.is_empty(), "{unfinished:?} has no blank line");
        assert_eq!(used, 0);
    }
}

#[test]
fn sse_splitter_emits_nothing_for_empty_input_or_events_without_data() {
    assert_eq!(sse_events(b""), (Vec::new(), 0));
    let (events, used) = sse_events(b"event: ping\n\n");
    assert!(events.is_empty());
    assert_eq!(used, "event: ping\n\n".len());
}

/// The framing and the splitter agree on whether the input ends its event, byte by byte.
#[test]
fn framing_ends_an_event_only_where_the_splitter_does() {
    for input in ["a\n\n", "a\r\n\r\n", "a\n\r\r\n", "a\n\r\r\r\n", "a\n \n"] {
        let mut framing = Framing::default();
        for byte in input.as_bytes() {
            framing.feed(std::slice::from_ref(byte), u64::MAX);
        }
        let (_, used) = sse_events(input.as_bytes());
        assert_eq!(
            framing.open == 0,
            used == input.len(),
            "framing and splitter disagree on {input:?}"
        );
    }
}

/// An answer fed one byte at a time through the relay's path is found, and the buffer is released.
#[test]
fn an_answer_fed_one_byte_at_a_time_is_found() {
    let text = format!(
        "{}{}data: tail",
        event(&notice()),
        answer_event(1, echo_result())
    );
    let mut observer = Observer::default();
    let id = json!(1);
    for byte in text.as_bytes() {
        let oversize = observer.feed(std::slice::from_ref(byte), Some(&id), u64::MAX);
        assert!(!oversize, "no oversize in a small answer");
    }
    assert_eq!(observer.answer.outcome, Some("ok"));
    assert!(
        observer.answer.pending.is_empty(),
        "the buffer is released once the outcome is known"
    );
    let mut whole = Observer::default();
    let joined_text = format!(
        "{}{}data: tail",
        event(&notice()),
        answer_event(1, echo_result())
    );
    whole.feed(joined_text.as_bytes(), Some(&id), u64::MAX);
    assert_eq!(whole.answer.outcome, Some("ok"));
    assert!(
        whole.answer.pending.is_empty(),
        "a tail in the same chunk as the answer is released too"
    );
}

/// An open event fed in chunks is not scanned; its closing blank line scans it once.
#[test]
fn the_buffer_is_scanned_only_when_an_event_ends() {
    let mut observer = Observer::default();
    let id = json!(1);
    let open = format!("data: {}", "x".repeat(994));
    assert_eq!(open.len(), 1000);
    for chunk in open.as_bytes().chunks(100) {
        observer.feed(chunk, Some(&id), u64::MAX);
    }
    assert_eq!(observer.answer.scans, 0, "an open event is not scanned");
    observer.feed(b"\n\n", Some(&id), u64::MAX);
    assert_eq!(
        observer.answer.scans, 1,
        "the closing blank line is scanned once"
    );
}

/// The buffer of an open event never holds more than the limit, whatever the framing says.
#[test]
fn an_open_buffer_past_the_limit_ends_the_observation() {
    let mut observed = Observed::default();
    let id = json!(1);
    let chunk = vec![b'x'; 3000];
    assert!(
        observed.feed(&chunk, false, &id, 2000),
        "3000 open bytes pass a 2000 limit"
    );
}

/// An event of exactly the limit's bytes, blank line included, is not oversize; one byte more is.
#[test]
fn an_event_of_exactly_the_limit_passes_and_one_byte_more_ends_the_stream() {
    let exact = "data: x\n\n";
    let limit = exact.len() as u64;
    assert_eq!(limit, 9);
    let mut framing = Framing::default();
    assert!(
        !framing.feed(exact.as_bytes(), limit),
        "an event of exactly the limit is not oversize"
    );
    assert_eq!(framing.ended, 1);
    let mut framing = Framing::default();
    assert!(
        framing.feed(b"data: xy\n\n", limit),
        "one byte past the limit is oversize"
    );
}

/// A buffer of exactly the limit is kept; one byte more ends the observation.
#[test]
fn a_buffer_of_exactly_the_limit_is_kept_and_one_byte_more_is_not() {
    let id = json!(1);
    let exact = [b'x'; 2000];
    let mut kept = Observed::default();
    assert!(
        !kept.feed(&exact, false, &id, 2000),
        "a buffer of exactly the limit is kept"
    );
    assert_eq!(kept.pending.len(), 2000);
    let over = [b'x'; 2001];
    let mut ended = Observed::default();
    assert!(
        ended.feed(&over, false, &id, 2000),
        "one byte past the limit ends the observation"
    );
}

/// Only a result without an error is `ok`; a result beside an error, or an error alone, is `error`.
#[test]
fn an_answer_with_both_result_and_error_is_an_error() {
    let both = json!({"jsonrpc": "2.0", "id": 1, "result": {},
        "error": {"code": -32000, "message": "x"}});
    assert_eq!(outcome_of(&both), "error");
    let result = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
    assert_eq!(outcome_of(&result), "ok");
    let error = json!({"jsonrpc": "2.0", "id": 1,
        "error": {"code": -32000, "message": "x"}});
    assert_eq!(outcome_of(&error), "error");
}

/// With nothing watched, the bytes are framed but never buffered or scanned.
#[test]
fn an_unwatched_stream_is_never_buffered() {
    let open = format!("data: {}", "x".repeat(9_994));
    assert_eq!(open.len(), 10_000);
    let text = format!(
        "{open}\n\n{}{}{}",
        event(&notice()),
        event(&notice()),
        event(&notice())
    );
    let mut observer = Observer::default();
    for chunk in text.as_bytes().chunks(512) {
        let oversize = observer.feed(chunk, None, 20_000);
        assert!(!oversize, "a 10,000 byte event passes a 20,000 limit");
        assert!(
            observer.answer.pending.is_empty(),
            "nothing watched, nothing buffered"
        );
        assert_eq!(observer.answer.scans, 0, "nothing watched, nothing scanned");
    }
    assert_eq!(
        observer.framing.ended, 4,
        "the framing still ends every event"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_never_ends_an_event_for_the_splitter_ends_the_stream() {
    let demo = demo_with(|c| c.limits.tools_list_bytes = 2000, (false, false)).await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let steps: Vec<(u64, String)> = (0..1000)
        .map(|_| (0, "data: x\n\r\r\n".to_owned()))
        .collect();
    demo.fake.set(script(steps, Tail::Hang, &closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), drain(&mut response))
        .await
        .expect("an event the splitter never ends must end the stream within 3 seconds");
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "unavailable");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_keeps_sending_outlives_the_idle_limit() {
    let demo = demo_with(|c| c.limits.upstream_timeout_seconds = 1, (false, false)).await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    let mut steps: Vec<(u64, String)> = (0..6).map(|_| (400, event(&notice()))).collect();
    steps.push((400, answer_event(1, echo_result())));
    demo.fake.set(script(steps, Tail::Close, &closed));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let received = joined(
        &tokio::time::timeout(Duration::from_secs(10), drain(&mut response))
            .await
            .expect("a stream that keeps sending must not end"),
    );
    assert!(String::from_utf8_lossy(&received).contains("called: echo"));
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cut_off_reaches_a_client_that_is_not_reading() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(Mode::Endless {
        closed: Arc::clone(&closed),
    });
    let response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    assert_eq!(response.status().as_u16(), 200, "the call must be answered");
    tokio::time::sleep(Duration::from_millis(300)).await;
    cut(&demo, demo.bob, &demo.token, Cut::Disable);
    assert!(
        wait_until(Duration::from_secs(3), || seen_closed(&closed)).await,
        "the upstream must see its connection closed within 3 seconds"
    );
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(1)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, "refused");
    drop(response);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_leaves_after_the_answer_keeps_the_answers_outcome() {
    let demo = demo().await;
    demo.gw.seed(demo.server, &["echo"]);
    let session = initialized(&demo).await;
    let closed = Arc::new(AtomicUsize::new(0));
    demo.fake.set(script(
        vec![(0, answer_event(1, echo_result()))],
        Tail::Hang,
        &closed,
    ));
    let mut response = open(
        &demo.gw,
        &demo.token,
        reqwest::Method::POST,
        session_headers(Some(&session)),
        Some(call_body(1, "echo")),
    )
    .await;
    let first = response.chunk().await.expect("chunk").expect("the answer");
    assert!(String::from_utf8_lossy(&first).contains("called: echo"));
    drop(response);
    let rows = rows_within(&demo.gw, 1, Duration::from_secs(2)).await;
    assert_eq!(rows.len(), 1, "one row when the client leaves");
    assert_eq!(rows[0].outcome, "ok", "the answer's outcome is kept");
    assert_eq!(details(&demo.gw), vec!["the client closed the stream"]);
}
