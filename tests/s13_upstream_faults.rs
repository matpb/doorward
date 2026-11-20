mod common;

use std::time::Duration;

use common::admin;
use common::client::{TestClient, Tokens};
use common::mcp::McpReply;
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::world::{SECRET_HEADER, World, secret_for};
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

/// The status of GET /healthz.
async fn healthz_status(w: &World) -> reqwest::StatusCode {
    w.gw.http
        .get(w.gw.url("/healthz"))
        .send()
        .await
        .expect("request")
        .status()
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
async fn a_stopped_upstream_gives_a_named_error() {
    let w = World::start().await;
    let (bob, mut upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.shutdown().await;
    let reply = client.list_tools().await;
    assert_unavailable(&reply, "demo");
    assert_eq!(
        healthz_status(&w).await,
        reqwest::StatusCode::OK,
        "the gateway must stay up when an upstream is stopped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_gives_a_named_error() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    upstream.set_mode(Mode::Garbage);
    let reply = w.stateless_mcp("demo", &tokens).list_tools().await;
    assert_unavailable(&reply, "demo");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unexpected_content_type_gives_a_named_error() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    upstream.set_mode(Mode::WrongContentType);
    let reply = w.stateless_mcp("demo", &tokens).list_tools().await;
    assert_unavailable(&reply, "demo");
    assert!(
        !reply.body.contains("<script>"),
        "the upstream's markup must not reach the client"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_not_followed() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let elsewhere = FakeUpstream::start(UpstreamOptions::default()).await;
    upstream.set_mode(Mode::Redirect(elsewhere.url()));
    let reply = w.stateless_mcp("demo", &tokens).list_tools().await;
    assert_unavailable(&reply, "demo");
    assert!(
        elsewhere.requests().is_empty(),
        "the gateway must not follow the redirect to the second upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_401_is_not_passed_on() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = w
        .open_upstream(
            "demo",
            UpstreamOptions {
                require_header: Some((SECRET_HEADER.into(), "other".into())),
                ..Default::default()
            },
        )
        .await;
    w.grant(BOB, &[&id]).await;
    let tokens = w.token(&bob, "demo").await;
    let reply = w.stateless_mcp("demo", &tokens).list_tools().await;
    assert_unavailable(&reply, "demo");
    assert!(
        reply.header("www-authenticate").is_none(),
        "the upstream's www-authenticate challenge must not reach the client"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_upstream_times_out() {
    let w = World::start_with(|c| c.limits.upstream_timeout_seconds = 1).await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    upstream.set_mode(Mode::Hang);
    let client = w.stateless_mcp("demo", &tokens);
    let reply = tokio::time::timeout(
        Duration::from_secs(4),
        client.call_tool("echo", json!({"text": "hi"})),
    )
    .await
    .expect("a slow upstream must end the call within 4 seconds");
    assert_unavailable(&reply, "demo");
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_endpoint_keeps_the_healthy_servers() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_a, id_a) = w.upstream("a", UpstreamOptions::default()).await;
    let (mut b, id_b) = w
        .upstream(
            "b",
            UpstreamOptions {
                tools: vec!["alpha".into()],
                ..Default::default()
            },
        )
        .await;
    w.grant(BOB, &[&id_a, &id_b]).await;
    let tokens = w.token(&bob, "mcp").await;
    b.shutdown().await;

    let client = w.stateless_mcp("mcp", &tokens);
    let names = client.list_tools().await.tool_names();
    assert_eq!(
        names,
        ["a__echo", "a__search", "a__delete_db"],
        "the combined list must keep the healthy server's tools and drop the stopped one's"
    );
    let echo = client.call_tool("a__echo", json!({"text": "hi"})).await;
    assert_eq!(
        echo.text().as_deref(),
        Some("called: echo"),
        "a__echo must still work"
    );
    let alpha = client.call_tool("b__alpha", json!({"text": "hi"})).await;
    assert_unavailable(&alpha, "b");

    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "tool_call"
            && row.server == "b"
            && row.tool == "alpha"
            && row.outcome == "unavailable"),
        "the activity must hold an unavailable row for b's alpha call, got {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_survives_repeated_failures() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (broken, id_broken) = w.upstream("broken", UpstreamOptions::default()).await;
    let (_healthy, id_healthy) = w.upstream("healthy", UpstreamOptions::default()).await;
    w.grant(BOB, &[&id_broken, &id_healthy]).await;
    broken.set_mode(Mode::Garbage);
    let broken_tokens = w.token(&bob, "broken").await;
    let healthy_tokens = w.token(&bob, "healthy").await;

    let failing = w.stateless_mcp("broken", &broken_tokens);
    for _ in 0..20 {
        let reply = failing.call_tool("echo", json!({"text": "hi"})).await;
        assert_unavailable(&reply, "broken");
    }

    assert_eq!(
        healthz_status(&w).await,
        reqwest::StatusCode::OK,
        "the gateway must still answer /healthz after twenty failures"
    );
    let answer = w
        .stateless_mcp("healthy", &healthy_tokens)
        .call_tool("echo", json!({"text": "hi"}))
        .await;
    assert_eq!(
        answer.text().as_deref(),
        Some("called: echo"),
        "a healthy server must still answer after twenty failures"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_do_not_leak_the_upstream() {
    let w = World::start().await;
    let (bob, mut upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let address = url::Url::parse(&upstream.url()).expect("upstream url");
    let port = address.port().expect("upstream port");
    upstream.shutdown().await;
    let reply = w.stateless_mcp("demo", &tokens).list_tools().await;
    assert_unavailable(&reply, "demo");
    assert!(
        !reply.body.contains(&port.to_string()),
        "the 502 body must not contain the upstream's port number"
    );
    assert!(
        !reply.body.contains(&secret_for("demo")),
        "the 502 body must not contain the upstream's secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_are_recorded() {
    let w = World::start().await;
    let (bob, upstream, id) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    upstream.set_mode(Mode::Garbage);
    let reply = w
        .stateless_mcp("demo", &tokens)
        .call_tool("echo", json!({"text": "hi"}))
        .await;
    assert_unavailable(&reply, "demo");
    let rows = admin::activity(&w.owner, None, Some(&id)).await;
    assert!(
        rows.iter().any(|row| row.kind == "tool_call"
            && row.tool == "echo"
            && row.decision == "allow"
            && row.outcome == "unavailable"),
        "the failed call must be recorded as allowed and unavailable, got {rows:?}"
    );
}

/// One failed `echo` call on `slug`: the client gets the named error, and the one tool_call row of
/// server `id` says why in its detail.
async fn assert_fault_says(w: &World, slug: &str, id: &str, tokens: &Tokens, phrase: &str) {
    let reply = w
        .stateless_mcp(slug, tokens)
        .call_tool("echo", json!({"text": "hi"}))
        .await;
    assert_unavailable(&reply, slug);
    let rows = admin::activity_with_details(&w.owner, None, Some(id)).await;
    let calls: Vec<&(admin::ActivityRow, String)> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call")
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "{slug}: one failed call must write one tool_call row, rows were {rows:?}"
    );
    assert_eq!(
        calls[0].1, phrase,
        "{slug}: the row must say why the call failed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fault_row_says_why() {
    let w = World::start_with(|c| {
        c.limits.upstream_timeout_seconds = 1;
        c.limits.tools_list_bytes = 1024;
    })
    .await;
    let bob = w.user(BOB).await;
    let (mut closed, closed_id) = w.upstream("closed-port", UpstreamOptions::default()).await;
    let (redirected, redirected_id) = w.upstream("wrong-status", UpstreamOptions::default()).await;
    let (wrong_type, wrong_type_id) = w.upstream("wrong-type", UpstreamOptions::default()).await;
    let (big, big_id) = w.upstream("too-big", UpstreamOptions::default()).await;
    let (junk, junk_id) = w.upstream("not-json", UpstreamOptions::default()).await;
    let (slow, slow_id) = w.upstream("too-slow", UpstreamOptions::default()).await;
    let ids = [
        closed_id.as_str(),
        redirected_id.as_str(),
        wrong_type_id.as_str(),
        big_id.as_str(),
        junk_id.as_str(),
        slow_id.as_str(),
    ];
    w.grant(BOB, &ids).await;
    let closed_tokens = w.token(&bob, "closed-port").await;
    let status_tokens = w.token(&bob, "wrong-status").await;
    let type_tokens = w.token(&bob, "wrong-type").await;
    let big_tokens = w.token(&bob, "too-big").await;
    let junk_tokens = w.token(&bob, "not-json").await;
    let slow_tokens = w.token(&bob, "too-slow").await;

    closed.shutdown().await;
    redirected.set_mode(Mode::Redirect("/elsewhere".into()));
    wrong_type.set_mode(Mode::WrongContentType);
    big.set_mode(Mode::Oversized { bytes: 4096 });
    junk.set_mode(Mode::Garbage);
    slow.set_mode(Mode::Hang);

    assert_fault_says(
        &w,
        "closed-port",
        &closed_id,
        &closed_tokens,
        "no connection",
    )
    .await;
    assert_fault_says(
        &w,
        "wrong-status",
        &redirected_id,
        &status_tokens,
        "the upstream answered 307",
    )
    .await;
    assert_fault_says(
        &w,
        "wrong-type",
        &wrong_type_id,
        &type_tokens,
        "an answer of the wrong content type",
    )
    .await;
    assert_fault_says(
        &w,
        "too-big",
        &big_id,
        &big_tokens,
        "an answer over the size limit",
    )
    .await;
    assert_fault_says(
        &w,
        "not-json",
        &junk_id,
        &junk_tokens,
        "an answer that is not valid JSON",
    )
    .await;
    assert_fault_says(&w, "too-slow", &slow_id, &slow_tokens, "no answer in time").await;
}
