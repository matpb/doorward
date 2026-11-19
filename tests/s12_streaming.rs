mod common;

use std::time::Duration;

use common::client::{TestClient, Tokens};
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::world::World;
use serde_json::json;

const BOB: &str = "bob@example.com";

/// Bob, signed in and assigned to a new server at `slug` built from `options`.
async fn bob_on(
    w: &World,
    slug: &str,
    options: UpstreamOptions,
) -> (TestClient, FakeUpstream, String) {
    let bob = w.user(BOB).await;
    let (upstream, id) = w.upstream(slug, options).await;
    w.grant(BOB, &[&id]).await;
    (bob, upstream, id)
}

/// A session client on `slug`, initialized; the handshake must be answered 200.
async fn session_on(w: &World, slug: &str, tokens: &Tokens) -> McpClient {
    let client = w.session_mcp(slug, tokens);
    let reply = client.initialize().await;
    assert_eq!(reply.status, 200, "initialize on {slug} must be answered");
    client
}

fn progress_options() -> UpstreamOptions {
    UpstreamOptions {
        mode: Mode::Progress {
            steps: 3,
            interval_ms: 300,
        },
        ..Default::default()
    }
}

/// Asserts the named error: 502, JSON-RPC -32000, and the message naming `slug`.
fn assert_unavailable(reply: &McpReply, slug: &str) {
    assert_eq!(reply.status, 502, "an unavailable upstream must answer 502");
    assert_eq!(
        reply.error_code(),
        Some(-32000),
        "an unavailable upstream must carry JSON-RPC -32000"
    );
    assert_eq!(
        reply.error_message(),
        Some(format!("Upstream {slug} is unavailable")),
        "the message must name the server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_arrives_before_the_end_session() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", progress_options()).await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    let reply = client.call_tool("echo", json!({"text": "hi"})).await;
    assert!(
        reply.events.len() >= 4,
        "three progress events and the result must arrive, got {}",
        reply.events.len()
    );
    let first = reply.events.first().expect("events present").at;
    let last = reply.events.last().expect("events present").at;
    assert!(
        last.saturating_sub(first) >= Duration::from_millis(500),
        "the first event ({first:?}) must arrive at least 500 ms before the last ({last:?})"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the streamed answer must be the tool's result"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_arrives_before_the_end_stateless() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", progress_options()).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.stateless_mcp("demo", &tokens);
    let reply = client.call_tool("echo", json!({"text": "hi"})).await;
    assert!(
        reply.events.len() >= 4,
        "three progress events and the result must arrive, got {}",
        reply.events.len()
    );
    let first = reply.events.first().expect("events present").at;
    let last = reply.events.last().expect("events present").at;
    assert!(
        last.saturating_sub(first) >= Duration::from_millis(500),
        "the first event ({first:?}) must arrive at least 500 ms before the last ({last:?})"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the streamed answer must be the tool's result"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_arrives_before_the_end_on_the_combined_endpoint() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", progress_options()).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = session_on(&w, "mcp", &tokens).await;
    let reply = client.call_tool("demo__echo", json!({"text": "hi"})).await;
    assert!(
        reply.events.len() >= 4,
        "three progress events and the result must arrive, got {}",
        reply.events.len()
    );
    let first = reply.events.first().expect("events present").at;
    let last = reply.events.last().expect("events present").at;
    assert!(
        last.saturating_sub(first) >= Duration::from_millis(500),
        "the first event ({first:?}) must arrive at least 500 ms before the last ({last:?})"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the streamed answer must be the tool's result"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_headers_are_clean() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", progress_options()).await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    let reply = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(reply.status, 200, "the streamed call must be answered");
    assert_eq!(
        reply.header("content-type").as_deref(),
        Some("text/event-stream"),
        "the stream must be text/event-stream"
    );
    assert_eq!(
        reply.header("x-content-type-options").as_deref(),
        Some("nosniff"),
        "the stream must carry x-content-type-options nosniff"
    );
    assert!(
        reply.header("set-cookie").is_none(),
        "the stream must not carry a set-cookie header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hung_upstream_ends_with_a_named_error() {
    let w = World::start_with(|c| c.limits.upstream_timeout_seconds = 1).await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    upstream.set_mode(Mode::Hang);
    let reply = tokio::time::timeout(
        Duration::from_secs(4),
        client.call_tool("echo", json!({"text": "hi"})),
    )
    .await
    .expect("a hung upstream must end the call within 4 seconds");
    assert_unavailable(&reply, "demo");
}

#[tokio::test(flavor = "multi_thread")]
async fn server_request_is_relayed_on_a_session() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(
        &w,
        "demo",
        UpstreamOptions {
            mode: Mode::ServerRequest,
            ..Default::default()
        },
    )
    .await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    let reply = client.call_tool("echo", json!({"text": "hi"})).await;
    let first = reply
        .events
        .first()
        .expect("the stream must carry the server request first");
    assert_eq!(
        first.data["method"], "elicitation/create",
        "the first event must be the server's request"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the result must follow the server's request"
    );

    let session_id = client
        .session_id()
        .expect("initialize must record the session id");
    let answer = client
        .raw(
            br#"{"jsonrpc":"2.0","id":"srv-1","result":{"action":"accept"}}"#,
            &[
                ("Mcp-Session-Id", session_id.as_str()),
                ("MCP-Protocol-Version", "2025-11-25"),
            ],
        )
        .await;
    assert_eq!(
        answer.status, 202,
        "the client's answer to the server's request must be accepted"
    );
    assert!(
        upstream
            .requests()
            .iter()
            .any(|r| r.json().is_some_and(|j| j["id"] == "srv-1")),
        "the client's answer must reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_endpoint_does_not_relay_server_requests() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(
        &w,
        "demo",
        UpstreamOptions {
            mode: Mode::ServerRequest,
            ..Default::default()
        },
    )
    .await;
    let tokens = w.token(&bob, "mcp").await;
    let client = session_on(&w, "mcp", &tokens).await;
    let reply = client.call_tool("demo__echo", json!({"text": "hi"})).await;
    assert_eq!(reply.status, 200, "the call through /mcp must be answered");
    assert!(
        reply
            .events
            .iter()
            .all(|e| e.data["method"] != "elicitation/create"),
        "the combined endpoint must not relay a server request"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the result must still arrive through /mcp"
    );
}
