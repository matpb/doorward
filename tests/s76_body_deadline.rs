mod common;

use std::time::Duration;

use common::upstream::UpstreamOptions;
use common::world::World;
use rusqlite::Connection;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BOB: &str = "bob@example.com";
const FORM: &str = "application/x-www-form-urlencoded";
const JSON_TYPE: &str = "application/json";
/// The body length the stalled request promises.
const PROMISED: usize = 100;
/// The gateway's answer must end within this many seconds.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// The head of a POST that promises `PROMISED` body bytes and carries `headers`.
fn stalled_head(authority: &str, path: &str, headers: &[(&str, &str)]) -> String {
    let mut head = format!("POST {path} HTTP/1.1\r\nHost: {authority}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {PROMISED}\r\n\r\n"));
    head
}

/// Sends `head` and `sent`, then reads the gateway's answer until it closes, for at most 5 seconds.
async fn stalled(w: &World, head: String, sent: &[u8]) -> Vec<u8> {
    let authority = w.gw.base.trim_start_matches("http://");
    let mut stream = TcpStream::connect(authority)
        .await
        .expect("the gateway accepts a connection");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("the head is written");
    stream
        .write_all(sent)
        .await
        .expect("the body start is written");
    let mut answer = Vec::new();
    let read = tokio::time::timeout(ANSWER_WITHIN, stream.read_to_end(&mut answer)).await;
    match read {
        Err(_) => panic!(
            "the gateway must answer a stalled body within {ANSWER_WITHIN:?} and close; \
             it wrote {:?} before the wait ended",
            String::from_utf8_lossy(&answer)
        ),
        Ok(result) => {
            result.expect("the answer is read to its end");
        }
    }
    answer
}

/// Asserts the answer is `408` with `Connection: close` and no body, then the close.
fn assert_timed_out(answer: &[u8], route: &str) {
    let text = String::from_utf8_lossy(answer).into_owned();
    let head_end = text
        .find("\r\n\r\n")
        .unwrap_or_else(|| panic!("{route}: the answer has no head: {text:?}"));
    let head = &text[..head_end];
    let body = &text[head_end + 4..];
    assert!(
        head.starts_with("HTTP/1.1 408 "),
        "{route}: the status line must be 408, the answer was {head:?}"
    );
    assert!(
        head.to_ascii_lowercase().contains("\r\nconnection: close"),
        "{route}: the 408 must carry Connection: close, the head was {head:?}"
    );
    assert_eq!(body, "", "{route}: the 408 must have an empty body");
}

/// The number of rows in the activity table.
fn activity_rows(w: &World) -> i64 {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .query_row("SELECT COUNT(*) FROM activity", [], |row| row.get(0))
        .expect("the count query runs")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_token_request_is_answered_408_and_closed() {
    let w = World::start_with(|c| c.limits.body_read_seconds = 1).await;
    let authority = w.gw.base.trim_start_matches("http://").to_owned();
    let head = stalled_head(&authority, "/oauth/token", &[("Content-Type", FORM)]);
    let answer = stalled(&w, head, b"grant").await;
    assert_timed_out(&answer, "POST /oauth/token");

    let response =
        w.gw.http
            .post(w.gw.url("/oauth/token"))
            .header("content-type", FORM)
            .body("client_id=x")
            .send()
            .await
            .expect("the token request is sent");
    assert_eq!(
        response.status().as_u16(),
        400,
        "a complete token request without a grant must keep its 400"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_registration_is_answered_408_and_closed() {
    let w = World::start_with(|c| c.limits.body_read_seconds = 1).await;
    let authority = w.gw.base.trim_start_matches("http://").to_owned();
    let head = stalled_head(
        &authority,
        "/oauth/register",
        &[("Content-Type", JSON_TYPE)],
    );
    let answer = stalled(&w, head, b"{\"cli").await;
    assert_timed_out(&answer, "POST /oauth/register");

    let page = w
        .client()
        .post_json(
            "/oauth/register",
            &json!({
                "client_name": "X",
                "redirect_uris": ["http://127.0.0.1:8787/callback"],
            }),
        )
        .await;
    assert_eq!(
        page.status, 201,
        "a complete registration must keep its 201"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_logout_is_answered_408_and_closed() {
    let w = World::start_with(|c| c.limits.body_read_seconds = 1).await;
    let authority = w.gw.base.trim_start_matches("http://").to_owned();
    let origin = w.gw.base.clone();
    let head = stalled_head(
        &authority,
        "/logout",
        &[("Content-Type", FORM), ("Origin", &origin)],
    );
    let answer = stalled(&w, head, b"csrf=").await;
    assert_timed_out(&answer, "POST /logout");

    let response =
        w.gw.http
            .post(w.gw.url("/logout"))
            .header("content-type", FORM)
            .header("Origin", &origin)
            .body("csrf=not-the-token")
            .send()
            .await
            .expect("the logout request is sent");
    assert_eq!(
        response.status().as_u16(),
        403,
        "a complete logout with a wrong anti-forgery token must keep its 403"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_mcp_post_is_answered_408_forwards_nothing_and_writes_no_activity() {
    let w = World::start_with(|c| c.limits.body_read_seconds = 1).await;
    let bob = w.user(BOB).await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[&id]).await;
    let tokens = w.token(&bob, "demo").await;
    let authority = w.gw.base.trim_start_matches("http://").to_owned();
    let bearer = format!("Bearer {}", tokens.access_token);
    let rows_before = activity_rows(&w);

    let head = stalled_head(
        &authority,
        "/demo",
        &[
            ("Content-Type", JSON_TYPE),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &bearer),
        ],
    );
    let answer = stalled(&w, head, b"{\"jso").await;
    assert_timed_out(&answer, "POST /demo");
    assert_eq!(
        activity_rows(&w),
        rows_before,
        "a stalled MCP post must write no activity row"
    );
    assert_eq!(
        upstream.calls_to("echo"),
        0,
        "a stalled MCP post must not reach the upstream"
    );

    let reply = w
        .stateless_mcp("demo", &tokens)
        .call_tool("echo", json!({"text": "hi"}))
        .await;
    assert_eq!(reply.status, 200, "a complete tool call must keep its 200");
    assert_eq!(
        upstream.calls_to("echo"),
        1,
        "a complete tool call must reach the upstream once"
    );
    assert!(
        activity_rows(&w) > rows_before,
        "a complete tool call must write its activity row"
    );
}
