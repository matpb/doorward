mod common;

use common::admin::{self, ServerSpec};
use common::client::{TestClient, Tokens};
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Mode, Recorded, UpstreamOptions};
use common::world::{SECRET_HEADER, World, secret_for};
use serde_json::json;

const STATELESS: &str = "2026-07-28";
const META: &str = r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test-client","version":"0"}}"#;
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test-client","version":"0"}}}"#;

/// Bob on demo: his browser, the demo upstream, its server id and his tokens.
async fn bob_on_demo(w: &World) -> (TestClient, FakeUpstream, String, Tokens) {
    let bob = w.user("bob@example.com").await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    (bob, upstream, id, tokens)
}

/// Carol, assigned to the server `id`, with her own token.
async fn carol_on(w: &World, id: &str) -> Tokens {
    let carol = w.user("carol@example.com").await;
    w.grant("carol@example.com", &[id]).await;
    w.token(&carol, "demo").await
}

/// A stateless tools/call body for `name`, written into the JSON as given.
fn call_body(name: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{{}},"_meta":{META}}}}}"#
    )
}

/// Sends a POST, a GET and a DELETE with the client's session id; each must be 404.
async fn expect_unknown_session(client: &McpClient, what: &str) {
    assert_eq!(
        client.list_tools().await.status,
        404,
        "a POST with {what} must be 404"
    );
    assert_eq!(
        client.get().await.status,
        404,
        "a GET with {what} must be 404"
    );
    assert_eq!(
        client.delete().await.status,
        404,
        "a DELETE with {what} must be 404"
    );
}

fn has_secret(request: &Recorded, secret: &str) -> bool {
    request.header_all(SECRET_HEADER).contains(&secret)
}

fn bytes_contain(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn request_mentions(request: &Recorded, needle: &str) -> bool {
    bytes_contain(&request.body, needle)
        || request
            .headers
            .iter()
            .any(|(_, value)| value.contains(needle))
}

fn reply_mentions(reply: &McpReply, needle: &str) -> bool {
    reply.body.contains(needle)
        || reply
            .headers
            .values()
            .any(|value| bytes_contain(value.as_bytes(), needle))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_token_never_reaches_the_upstream() {
    let w = World::start().await;
    let (_bob, upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    upstream.clear();
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    assert_eq!(
        client.list_tools().await.status,
        200,
        "tools/list must be relayed"
    );
    assert_eq!(
        client.call_tool("echo", json!({})).await.status,
        200,
        "tools/call must be relayed"
    );
    assert_eq!(
        client.get().await.status,
        200,
        "the GET stream must be relayed"
    );
    assert_eq!(
        client.delete().await.status,
        200,
        "the DELETE must be relayed"
    );
    let seen = upstream.requests();
    assert!(
        !seen.is_empty(),
        "the upstream must have received the session"
    );
    let secret = secret_for("demo");
    for request in &seen {
        assert!(
            request.header("authorization").is_none(),
            "{} {} must carry no authorization header",
            request.http_method,
            request.path
        );
        assert!(
            has_secret(request, &secret),
            "{} {} must carry the server's secret header",
            request.http_method,
            request.path
        );
        assert!(
            !String::from_utf8_lossy(&request.body).contains(&tokens.access_token),
            "{} {} must not carry the client's access token",
            request.http_method,
            request.path
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_cookies_are_stripped() {
    let w = World::start().await;
    let (_bob, upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let reply = client
        .raw(
            call_body("echo").as_bytes(),
            &[
                ("Cookie", "a=b"),
                ("MCP-Protocol-Version", STATELESS),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "echo"),
            ],
        )
        .await;
    assert_eq!(reply.status, 200, "the call with a cookie must be relayed");
    let seen = upstream.requests();
    let call = seen
        .iter()
        .find(|request| request.tool.as_deref() == Some("echo"))
        .expect("the call must reach the upstream");
    assert!(
        call.header("cookie").is_none(),
        "the upstream must not receive the client's cookie"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_upstream_cannot_set_cookies() {
    let w = World::start().await;
    let (_bob, upstream, _id, tokens) = bob_on_demo(&w).await;
    upstream.set_mode(Mode::SetCookie);
    let client = w.session_mcp("demo", &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize must be relayed");
    let listed = client.list_tools().await;
    assert_eq!(listed.status, 200, "tools/list must be relayed");
    let called = client.call_tool("echo", json!({})).await;
    assert_eq!(called.status, 200, "tools/call must be relayed");
    for reply in [&init, &listed, &called] {
        assert!(
            reply.header("set-cookie").is_none(),
            "a reply must carry no set-cookie from the upstream"
        );
        assert!(
            reply.header("www-authenticate").is_none(),
            "a reply must carry no www-authenticate from the upstream"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_are_marked_inert() {
    let w = World::start().await;
    let (_bob, _upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    let init = client.initialize().await;
    let listed = client.list_tools().await;
    let called = client.call_tool("echo", json!({})).await;
    let streamed = client.get().await;
    for reply in [&init, &listed, &called, &streamed] {
        assert_eq!(
            reply.header("x-content-type-options").as_deref(),
            Some("nosniff"),
            "a reply must say nosniff"
        );
        assert_eq!(
            reply.header("content-security-policy").as_deref(),
            Some("sandbox"),
            "a reply must carry the sandbox policy"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_upstream_is_flagged() {
    let w = World::start().await;
    let (open, open_id) = w.open_upstream("open", UpstreamOptions::default()).await;
    let (_gated, gated_id) = w.upstream("demo", UpstreamOptions::default()).await;
    let (mut stopped, stopped_id) = w.upstream("stopped", UpstreamOptions::default()).await;
    stopped.shutdown().await;
    for (id, want) in [
        (&open_id, "open"),
        (&gated_id, "ok"),
        (&stopped_id, "unknown"),
    ] {
        let page = admin::check_lockdown(&w.owner, id).await;
        assert_eq!(page.status, 303, "the lock-down check must be accepted");
        assert_eq!(
            admin::lockdown(&w.owner, id).await.as_deref(),
            Some(want),
            "the lock-down result of server {id} must be {want}"
        );
    }
    let probes = open.requests();
    assert!(
        !probes.is_empty(),
        "the open upstream must receive the probe"
    );
    assert!(
        probes
            .iter()
            .all(|request| request.header_all(SECRET_HEADER).is_empty()),
        "the probe must carry no secret header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_is_never_shown_or_stored_in_the_clear() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let secret = secret_for("demo");
    let page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert_eq!(page.status, 200, "the server page must render");
    assert!(
        !page.body.contains(&secret),
        "the server page must never show the secret"
    );
    assert!(
        !bytes_contain(&w.stored_bytes(), &secret),
        "the database must not hold the secret in the clear"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_address_clears_the_secret() {
    let w = World::start().await;
    let (_first, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let second = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = second.url();
    let page = admin::update_server(
        &w.owner,
        &id,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    assert_eq!(page.status, 303, "the address change must be saved");
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "the tool refresh must be accepted");
    let seen = second.requests();
    assert!(
        !seen.is_empty(),
        "the new address must receive the tool refresh"
    );
    let secret = secret_for("demo");
    for request in &seen {
        assert!(
            request.header_all(SECRET_HEADER).is_empty(),
            "the new address must receive no secret header"
        );
        assert!(
            !request_mentions(request, &secret),
            "the new address must never see the old secret"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_address_with_a_new_secret_sends_the_new_one() {
    let w = World::start().await;
    let (_first, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let rotated = FakeUpstream::start(UpstreamOptions {
        tools: vec!["rotated".into()],
        require_header: Some((SECRET_HEADER.into(), "secret-rotated".into())),
        ..UpstreamOptions::default()
    })
    .await;
    let url = rotated.url();
    let page = admin::update_server(
        &w.owner,
        &id,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: Some((SECRET_HEADER, "secret-rotated")),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    assert_eq!(
        page.status, 303,
        "the address and secret change must be saved"
    );
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "the tool refresh must be accepted");
    assert_eq!(
        admin::catalog_tools(&w.owner, &id).await,
        vec!["rotated"],
        "the new address must answer the refresh with the new secret"
    );
    assert!(
        rotated
            .requests()
            .iter()
            .any(|request| has_secret(request, "secret-rotated")),
        "the new address must receive the new secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_never_reaches_the_client() {
    let w = World::start().await;
    let (_bob, upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    let mut replies = vec![
        client.initialize().await,
        client.list_tools().await,
        client.call_tool("echo", json!({})).await,
        client.get().await,
    ];
    upstream.set_mode(Mode::Garbage);
    let garbage = client.call_tool("echo", json!({})).await;
    assert_eq!(
        garbage.status, 502,
        "an upstream answering garbage must be a named error"
    );
    replies.push(garbage);
    upstream.set_mode(Mode::WrongContentType);
    let wrong_type = client.call_tool("echo", json!({})).await;
    assert_eq!(
        wrong_type.status, 502,
        "an upstream answering the wrong content type must be a named error"
    );
    replies.push(wrong_type);
    replies.push(client.delete().await);
    let secret = secret_for("demo");
    for reply in &replies {
        assert!(
            !reply_mentions(reply, &secret),
            "no reply of the session may carry the secret, status {}",
            reply.status
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_planted_session_id_is_stripped_from_initialize() {
    let w = World::start().await;
    let (_bob, upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    upstream.clear();
    let reply = client
        .raw(INITIALIZE.as_bytes(), &[("Mcp-Session-Id", "planted")])
        .await;
    assert_eq!(reply.status, 200, "the initialize must be relayed");
    let init = upstream
        .requests()
        .into_iter()
        .find(|request| request.rpc_method.as_deref() == Some("initialize"))
        .expect("the initialize must reach the upstream");
    assert!(
        init.header("mcp-session-id").is_none(),
        "the upstream must not receive a session id the client planted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_and_invented_session_ids_are_refused() {
    let w = World::start().await;
    let (_bob, upstream, id, bob_tokens) = bob_on_demo(&w).await;
    let bob_client = w.session_mcp("demo", &bob_tokens);
    assert_eq!(
        bob_client.initialize().await.status,
        200,
        "bob must initialise"
    );
    let bob_session = bob_client.session_id().expect("bob's session id");
    let carol_tokens = carol_on(&w, &id).await;
    let carol_client = w.session_mcp("demo", &carol_tokens);
    upstream.clear();
    carol_client.set_session_id(Some(&bob_session));
    expect_unknown_session(&carol_client, "bob's session id").await;
    assert!(
        upstream.requests().is_empty(),
        "bob's session id must not reach the upstream"
    );
    carol_client.set_session_id(Some("invented-session"));
    expect_unknown_session(&carol_client, "an invented session id").await;
    assert!(
        upstream.requests().is_empty(),
        "an invented session id must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reused_upstream_session_id_is_not_rebound() {
    let w = World::start().await;
    let (_bob, upstream, id, bob_tokens) = bob_on_demo(&w).await;
    upstream.set_mode(Mode::ReuseSessionId);
    let bob_client = w.session_mcp("demo", &bob_tokens);
    assert_eq!(
        bob_client.initialize().await.status,
        200,
        "bob must initialise"
    );
    let carol_tokens = carol_on(&w, &id).await;
    let carol_client = w.session_mcp("demo", &carol_tokens);
    carol_client.initialize().await;
    assert_eq!(
        bob_client.list_tools().await.status,
        200,
        "bob's session must keep working after carol initialises"
    );
    assert_ne!(
        carol_client.list_tools().await.status,
        200,
        "carol must not ride on bob's upstream session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_dies_with_its_token_family() {
    let w = World::start().await;
    let (bob, _upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    let session = client.session_id().expect("the session id");
    let account = bob.get("/account").await;
    let family = account
        .attr("[data-family]", "data-family")
        .expect("the account page must list the connected client's family");
    let page = bob
        .submit(
            "/account",
            &format!("/account/clients/{family}/disconnect"),
            &[],
        )
        .await;
    assert_eq!(page.status, 303, "the disconnect must be accepted");
    let fresh = w.token(&bob, "demo").await;
    let again = w.session_mcp("demo", &fresh);
    again.set_session_id(Some(&session));
    assert_eq!(
        again.list_tools().await.status,
        404,
        "a new token family must not use the old session id"
    );
}
