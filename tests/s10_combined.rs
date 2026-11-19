mod common;

use common::admin;
use common::client::{TestClient, Tokens};
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Generation, UpstreamOptions};
use common::world::{SECRET_HEADER, World, secret_for};
use serde_json::json;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const DAVE: &str = "dave@example.com";

/// Server `a` with the given options, server `b` (tool `alpha`), and bob assigned to both.
struct Scene {
    w: World,
    a: FakeUpstream,
    a_id: String,
    b: FakeUpstream,
    b_id: String,
    bob: TestClient,
}

async fn start(a_options: UpstreamOptions) -> Scene {
    let w = World::start().await;
    let (a, a_id) = w.upstream("a", a_options).await;
    let b_options = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let (b, b_id) = w.upstream("b", b_options).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[a_id.as_str(), b_id.as_str()]).await;
    Scene {
        w,
        a,
        a_id,
        b,
        b_id,
        bob,
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

#[tokio::test(flavor = "multi_thread")]
async fn lists_every_permitted_tool_with_its_prefix() {
    let sc = start(UpstreamOptions::default()).await;
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__echo", "a__search", "a__delete_db", "b__alpha"],
        "bob must see every tool of both servers, prefixed by its slug"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_each_call_to_its_upstream() {
    let sc = start(UpstreamOptions::default()).await;
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    sc.a.clear();
    sc.b.clear();
    let echo = client.call_tool("a__echo", json!({})).await;
    assert_eq!(
        echo.text(),
        Some("called: echo".to_string()),
        "a__echo must answer with the upstream's echo"
    );
    assert_eq!(
        sc.a.rpc_count("tools/call"),
        1,
        "a must record one tools/call"
    );
    assert_eq!(sc.a.calls_to("echo"), 1, "a must receive the name echo");
    assert_eq!(sc.b.rpc_count("tools/call"), 0, "b must not see a__echo");
    sc.a.clear();
    sc.b.clear();
    let alpha = client.call_tool("b__alpha", json!({})).await;
    assert_eq!(
        alpha.text(),
        Some("called: alpha".to_string()),
        "b__alpha must answer with the upstream's alpha"
    );
    assert_eq!(
        sc.b.rpc_count("tools/call"),
        1,
        "b must record one tools/call"
    );
    assert_eq!(sc.b.calls_to("alpha"), 1, "b must receive the name alpha");
    assert_eq!(sc.a.rpc_count("tools/call"), 0, "a must not see b__alpha");
}

#[tokio::test(flavor = "multi_thread")]
async fn descriptions_and_schemas_are_kept() {
    let sc = start(UpstreamOptions::default()).await;
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    let listed = client.list_tools().await;
    let entry = listed
        .result()
        .and_then(|result| result["tools"].as_array())
        .and_then(|tools| tools.iter().find(|tool| tool["name"] == "a__echo"))
        .expect("a__echo must be listed");
    assert_eq!(
        entry["description"], "fake tool",
        "the description of a__echo must be the upstream's"
    );
    assert_eq!(
        entry["inputSchema"],
        json!({"type": "object", "properties": {"text": {"type": "string"}}}),
        "the input schema of a__echo must be the upstream's"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_tools_are_absent_and_refused() {
    let sc = start(UpstreamOptions::default()).await;
    let page = admin::add_rule(
        &sc.w.owner,
        "everyone",
        "deny",
        "tool",
        Some(sc.a_id.as_str()),
        Some("delete_db"),
    )
    .await;
    assert_eq!(
        page.status, 303,
        "the deny rule for a/delete_db must be accepted"
    );
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__echo", "a__search", "b__alpha"],
        "a denied tool must be absent from the combined list"
    );
    sc.a.clear();
    let reply = client.call_tool("a__delete_db", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a denied tool must be refused with -32602"
    );
    assert_eq!(
        reply.error_message(),
        Some("Unknown tool: a__delete_db".to_string()),
        "a denied tool must be refused as unknown"
    );
    assert_eq!(
        sc.a.rpc_count("tools/call"),
        0,
        "a must not record the refused call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigned_servers_are_absent_and_refused() {
    let sc = start(UpstreamOptions::default()).await;
    let carol = sc.w.user(CAROL).await;
    sc.w.grant(CAROL, &[sc.a_id.as_str()]).await;
    let (_, client) = connect(&sc.w, &carol, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__echo", "a__search", "a__delete_db"],
        "carol must see only the tools of server a"
    );
    sc.b.clear();
    let reply = client.call_tool("b__alpha", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a tool of an unassigned server must be refused with -32602"
    );
    assert!(sc.b.requests().is_empty(), "b must not be contacted");
}

#[tokio::test(flavor = "multi_thread")]
async fn assignment_changes_show_on_the_next_request() {
    let sc = start(UpstreamOptions::default()).await;
    let carol = sc.w.user(CAROL).await;
    sc.w.grant(CAROL, &[sc.a_id.as_str()]).await;
    let (_, client) = connect(&sc.w, &carol, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__echo", "a__search", "a__delete_db"],
        "before the grant carol must see only server a"
    );
    sc.w.grant(CAROL, &[sc.a_id.as_str(), sc.b_id.as_str()])
        .await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["a__echo", "a__search", "a__delete_db", "b__alpha"],
        "the grant must show on the same token's next list"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstreams_get_the_secret_and_never_the_token() {
    let sc = start(UpstreamOptions::default()).await;
    let (tokens, client) = connect(&sc.w, &sc.bob, "mcp").await;
    names(&client.list_tools().await);
    assert_eq!(
        client.call_tool("a__echo", json!({})).await.text(),
        Some("called: echo".to_string()),
        "a__echo must answer"
    );
    assert_eq!(
        client.call_tool("b__alpha", json!({})).await.text(),
        Some("called: alpha".to_string()),
        "b__alpha must answer"
    );
    for (upstream, slug) in [(&sc.a, "a"), (&sc.b, "b")] {
        let seen = upstream.requests();
        assert!(!seen.is_empty(), "upstream {slug} must have been reached");
        let secret = secret_for(slug);
        for request in &seen {
            assert!(
                request.header_all(SECRET_HEADER).contains(&secret.as_str()),
                "every request to {slug} must carry its secret header"
            );
            assert!(
                request.header("authorization").is_none(),
                "no request to {slug} may carry an authorization header"
            );
            assert!(
                !String::from_utf8_lossy(&request.body).contains(tokens.access_token.as_str()),
                "no request body to {slug} may contain the access token"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_upstream_session_per_token_family() {
    let options = UpstreamOptions {
        generation: Generation::Session,
        ..Default::default()
    };
    let sc = start(options).await;
    sc.a.clear();
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    for _ in 0..3 {
        let reply = client.call_tool("a__echo", json!({})).await;
        assert_eq!(
            reply.text(),
            Some("called: echo".to_string()),
            "each call through /mcp must reach a session-only upstream"
        );
    }
    assert_eq!(
        sc.a.rpc_count("initialize"),
        1,
        "three calls from one token family must leave one upstream initialize"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_with_no_servers_gets_an_empty_list() {
    let sc = start(UpstreamOptions::default()).await;
    let dave = sc.w.user(DAVE).await;
    let (_, client) = connect(&sc.w, &dave, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        Vec::<String>::new(),
        "a user with no servers must see an empty list"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_token_does_not_open_server_paths() {
    let sc = start(UpstreamOptions::default()).await;
    let on_mcp = sc.w.token(&sc.bob, "mcp").await;
    let on_a = sc.w.token(&sc.bob, "a").await;
    let own_mcp = sc.w.session_mcp("mcp", &on_mcp).initialize().await;
    assert_eq!(own_mcp.status, 200, "the combined token must open /mcp");
    let own_a = sc.w.session_mcp("a", &on_a).initialize().await;
    assert_eq!(own_a.status, 200, "the token of /a must open /a");
    let on_path = sc.w.session_mcp("a", &on_mcp).initialize().await;
    assert_eq!(
        on_path.status, 401,
        "the combined token must be refused on /a"
    );
    let on_combined = sc.w.session_mcp("mcp", &on_a).initialize().await;
    assert_eq!(
        on_combined.status, 401,
        "the token of /a must be refused on /mcp"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_and_malformed_names_are_refused() {
    let options = UpstreamOptions {
        tools: vec![
            "echo".into(),
            "search".into(),
            "delete_db".into(),
            "b__c".into(),
        ],
        ..Default::default()
    };
    let sc = start(options).await;
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    sc.a.clear();
    let reply = client.call_tool("a__b__c", json!({})).await;
    assert_eq!(
        reply.text(),
        Some("called: b__c".to_string()),
        "a__b__c must reach a as b__c"
    );
    assert_eq!(sc.a.calls_to("b__c"), 1, "a must receive the name b__c");
    for name in ["a__nope", "echo", "__echo", "A__echo", "a__", "a___echo"] {
        sc.a.clear();
        sc.b.clear();
        let reply = client.call_tool(name, json!({})).await;
        assert_eq!(
            reply.error_code(),
            Some(-32602),
            "{name} must be refused with -32602"
        );
        assert_eq!(
            sc.a.rpc_count("tools/call"),
            0,
            "{name} must not reach a as a tools/call"
        );
        assert_eq!(
            sc.b.rpc_count("tools/call"),
            0,
            "{name} must not reach b as a tools/call"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn over_length_names_are_left_out() {
    let options = UpstreamOptions {
        tools: vec!["x".repeat(125), "y".repeat(126)],
        ..Default::default()
    };
    let sc = start(options).await;
    let short = format!("a__{}", "x".repeat(125));
    let long = format!("a__{}", "y".repeat(126));
    let (_, client) = connect(&sc.w, &sc.bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec![short, "b__alpha".to_string()],
        "the 128 character name must be listed and the 129 character name left out"
    );
    sc.a.clear();
    let reply = client.call_tool(&long, json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "the 129 character name must be refused with -32602"
    );
    assert_eq!(
        reply.error_message(),
        Some(format!("Unknown tool: {long}")),
        "the 129 character name must be refused as unknown"
    );
    assert_eq!(
        sc.a.rpc_count("tools/call"),
        0,
        "a must not see the refused call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_tool_methods_exist_here() {
    let sc = start(UpstreamOptions::default()).await;
    let tokens = sc.w.token(&sc.bob, "mcp").await;
    let stateless = sc.w.stateless_mcp("mcp", &tokens);
    for method in ["resources/list", "prompts/list", "ping"] {
        let reply = stateless.request(method, json!({})).await;
        assert_eq!(
            reply.error_code(),
            Some(-32601),
            "{method} under the stateless rules must answer -32601"
        );
    }
    let session = sc.w.session_mcp("mcp", &tokens);
    let init = session.initialize().await;
    assert_eq!(init.status, 200, "initialize on /mcp must answer 200");
    let pong = session.request("ping", json!({})).await;
    assert_eq!(
        pong.result(),
        Some(&json!({})),
        "ping under the session rules must answer an empty object"
    );
}
