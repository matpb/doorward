mod common;

use common::admin;
use common::client::{TestClient, Tokens, tokens as token_pair};
use common::mcp::{McpClient, McpReply};
use common::upstream::UpstreamOptions;
use common::world::World;
use serde_json::json;

const BOB: &str = "bob@example.com";

/// A server whose only tool is `tool`.
fn one_tool(tool: &str) -> UpstreamOptions {
    UpstreamOptions {
        tools: vec![tool.into()],
        ..Default::default()
    }
}

/// Signs `browser` in for `slug` and completes the session handshake.
async fn connect(w: &World, browser: &TestClient, slug: &str) -> (Tokens, McpClient) {
    let tokens = w.token(browser, slug).await;
    let client = w.session_mcp(slug, &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize on /{slug} must answer 200");
    (tokens, client)
}

/// The names of a tool list answer, which must be a 200.
fn names(reply: &McpReply) -> Vec<String> {
    assert_eq!(reply.status, 200, "the tool list must answer 200");
    reply.tool_names()
}

/// Asserts that the activity log holds a refused tool call by bob.
async fn assert_refused_row(w: &World) {
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| {
            row.kind == "tool_call"
                && row.user == BOB
                && row.decision == "deny"
                && row.outcome == "refused"
        }),
        "the refused call must be recorded as a deny / refused row of bob, rows were {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_assigned_later_is_listed_without_a_new_consent() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_a_up, a) = w.upstream("a", one_tool("alpha")).await;
    let (b_up, b) = w.upstream("b", one_tool("beta")).await;
    w.grant(BOB, &[a.as_str()]).await;
    let (_, client) = connect(&w, &bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__alpha"],
        "bob must list a__alpha while assigned to a only"
    );
    w.grant(BOB, &[a.as_str(), b.as_str()]).await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__alpha", "b__beta"],
        "a server assigned later must be listed on the same token"
    );
    let reply = client.call_tool("b__beta", json!({})).await;
    assert_eq!(
        reply.text(),
        Some("called: beta".to_string()),
        "b__beta must answer with the upstream's beta"
    );
    assert_eq!(
        b_up.calls_to("beta"),
        1,
        "b must receive the name beta once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unassigned_server_is_gone_at_once() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (a_up, a) = w.upstream("a", one_tool("alpha")).await;
    let (_b_up, b) = w.upstream("b", one_tool("beta")).await;
    w.grant(BOB, &[a.as_str(), b.as_str()]).await;
    let (_, client) = connect(&w, &bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__alpha", "b__beta"],
        "bob must list both servers before the unassignment"
    );
    w.grant(BOB, &[b.as_str()]).await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["b__beta"],
        "after the unassignment the list must hold no a__ tool"
    );
    a_up.clear();
    let reply = client.call_tool("a__alpha", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a call to a__alpha after the unassignment must be refused with -32602"
    );
    assert_eq!(
        reply.error_message(),
        Some("Unknown tool: a__alpha".to_string()),
        "a call to a__alpha after the unassignment must be refused as unknown"
    );
    assert!(
        a_up.requests().is_empty(),
        "upstream a must not be contacted after the unassignment"
    );
    assert_refused_row(&w).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_with_no_server_left_still_answers() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_a_up, a) = w.upstream("a", one_tool("alpha")).await;
    w.grant(BOB, &[a.as_str()]).await;
    let (first, client) = connect(&w, &bob, "mcp").await;
    w.grant(BOB, &[]).await;
    assert_eq!(
        names(&client.list_tools().await),
        Vec::<String>::new(),
        "a token with no server left must list an empty list with a 200"
    );
    let refresh = w
        .client()
        .token_refresh(&w.app(), &first.refresh_token, None)
        .await;
    assert_eq!(
        refresh.status, 200,
        "the refresh token must still rotate after the last server is unassigned"
    );
    let rotated = token_pair(&refresh).expect("the refresh must issue a token pair");
    assert_ne!(
        rotated.refresh_token, first.refresh_token,
        "the refresh must issue a new refresh token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_check_is_made_on_every_call() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (a_up, a) = w.upstream("a", one_tool("alpha")).await;
    w.grant(BOB, &[a.as_str()]).await;
    let (_, client) = connect(&w, &bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__alpha"],
        "bob must list a__alpha while assigned"
    );
    w.grant(BOB, &[]).await;
    a_up.clear();
    let reply = client.call_tool("a__alpha", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a call to a__alpha from the old list must be refused with -32602"
    );
    assert_eq!(
        reply.error_message(),
        Some("Unknown tool: a__alpha".to_string()),
        "a call to a__alpha from the old list must be refused as unknown"
    );
    assert!(
        a_up.requests().is_empty(),
        "upstream a must not be contacted after the unassignment"
    );
    assert_refused_row(&w).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn both_generations_follow_the_same_rule() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (a_up, a) = w.upstream("a", one_tool("alpha")).await;
    let (_b_up, b) = w.upstream("b", one_tool("beta")).await;
    w.grant(BOB, &[a.as_str()]).await;
    let tokens = w.token(&bob, "mcp").await;
    let stateless = w.stateless_mcp("mcp", &tokens);
    assert_eq!(
        names(&stateless.list_tools().await),
        vec!["a__alpha"],
        "a stateless bob must list a__alpha while assigned to a only"
    );
    w.grant(BOB, &[a.as_str(), b.as_str()]).await;
    assert_eq!(
        names(&stateless.list_tools().await),
        vec!["a__alpha", "b__beta"],
        "a stateless client must list a server assigned later"
    );
    let reply = stateless.call_tool("b__beta", json!({})).await;
    assert_eq!(
        reply.text(),
        Some("called: beta".to_string()),
        "a stateless b__beta must answer with the upstream's beta"
    );
    w.grant(BOB, &[b.as_str()]).await;
    assert_eq!(
        names(&stateless.list_tools().await),
        vec!["b__beta"],
        "a stateless list after the unassignment must hold no a__ tool"
    );
    a_up.clear();
    let reply = stateless.call_tool("a__alpha", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a stateless call to a__alpha after the unassignment must be refused with -32602"
    );
    assert_eq!(
        reply.error_message(),
        Some("Unknown tool: a__alpha".to_string()),
        "a stateless call to a__alpha after the unassignment must be refused as unknown"
    );
    assert!(
        a_up.requests().is_empty(),
        "upstream a must not be contacted after the unassignment"
    );
    assert_refused_row(&w).await;
}
