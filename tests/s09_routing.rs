mod common;

use common::admin::{self, ServerSpec};
use common::client::{TestClient, Tokens};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{SECRET_HEADER, World, secret_for};
use serde_json::json;

const BOB: &str = "bob@example.com";
/// The upstream address of refused server forms; the gateway must refuse them before contacting it.
const NO_UPSTREAM: &str = "http://127.0.0.1:9/mcp";
const RESERVED: [&str; 16] = [
    "-",
    ".well-known",
    "oauth",
    "login",
    "logout",
    "setup",
    "invite",
    "forgot",
    "reset",
    "account",
    "admin",
    "assets",
    "healthz",
    "mcp",
    "favicon.ico",
    "robots.txt",
];

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

/// A server spec without a secret, named after its slug.
fn spec<'a>(slug: &'a str, upstream_url: &'a str) -> ServerSpec<'a> {
    ServerSpec {
        name: slug,
        slug,
        upstream_url,
        secret: None,
        pass_resources: false,
        pass_prompts: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_reaches_the_upstream_through_its_path() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    assert_eq!(
        client.list_tools().await.tool_names(),
        ["echo", "search", "delete_db"],
        "the path must list the upstream's tools"
    );
    let called = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        called.text().as_deref(),
        Some("called: echo"),
        "echo must be answered by the upstream"
    );
    assert_eq!(
        upstream.calls_to("echo"),
        1,
        "the upstream must receive the echo call once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_servers_route_independently() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let alpha = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let beta = UpstreamOptions {
        tools: vec!["beta".into()],
        ..Default::default()
    };
    let (a, id_a) = w.upstream("a", alpha).await;
    let (b, id_b) = w.upstream("b", beta).await;
    w.grant(BOB, &[&id_a, &id_b]).await;
    let tokens_a = w.token(&bob, "a").await;
    let tokens_b = w.token(&bob, "b").await;

    let on_a = session_on(&w, "a", &tokens_a).await;
    assert_eq!(
        on_a.list_tools().await.tool_names(),
        ["alpha"],
        "path a must list only its own tool"
    );
    let answer = on_a.call_tool("alpha", json!({})).await;
    assert_eq!(
        answer.text().as_deref(),
        Some("called: alpha"),
        "alpha must be answered by upstream a"
    );
    assert!(
        b.requests().is_empty(),
        "upstream b must not see anything sent to path a"
    );

    let on_b = session_on(&w, "b", &tokens_b).await;
    assert_eq!(
        on_b.list_tools().await.tool_names(),
        ["beta"],
        "path b must list only its own tool"
    );
    let answer = on_b.call_tool("beta", json!({})).await;
    assert_eq!(
        answer.text().as_deref(),
        Some("called: beta"),
        "beta must be answered by upstream b"
    );
    assert_eq!(a.calls_to("beta"), 0, "upstream a must not receive beta");
    assert_eq!(b.calls_to("alpha"), 0, "upstream b must not receive alpha");
    assert_eq!(
        a.rpc_count("tools/call"),
        1,
        "upstream a must see one tools/call"
    );
    assert_eq!(
        b.rpc_count("tools/call"),
        1,
        "upstream b must see one tools/call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reserved_paths_cannot_be_taken() {
    let w = World::start().await;
    for slug in RESERVED {
        let page = admin::add_server_page(&w.owner, &spec(slug, NO_UPSTREAM)).await;
        assert_eq!(
            page.status, 400,
            "the reserved path {slug:?} must not take a server"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn path_syntax_is_enforced() {
    let w = World::start().await;
    let long = "a".repeat(25);
    let longest = "a".repeat(24);
    for slug in ["Bad", "a_b", long.as_str(), "", "-a", "a/b", "a.b"] {
        let page = admin::add_server_page(&w.owner, &spec(slug, NO_UPSTREAM)).await;
        assert_eq!(page.status, 400, "the path {slug:?} is not a valid slug");
    }
    for slug in ["a", "a-b-1", longest.as_str()] {
        let page = admin::add_server_page(&w.owner, &spec(slug, NO_UPSTREAM)).await;
        assert_eq!(page.status, 303, "the path {slug:?} is a valid slug");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taken_path_is_refused() {
    let w = World::start().await;
    let (_demo, _) = w.upstream("demo", UpstreamOptions::default()).await;
    let page = admin::add_server_page(&w.owner, &spec("demo", NO_UPSTREAM)).await;
    assert_eq!(
        page.status, 400,
        "a second server on the path demo must be refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_address_must_be_http_or_https() {
    let w = World::start().await;
    let addresses = [
        "file:///etc/passwd",
        "ftp://example.com/",
        "javascript:alert(1)",
        "not a url",
    ];
    for (index, address) in addresses.into_iter().enumerate() {
        let slug = format!("u{index}");
        let page = admin::add_server_page(&w.owner, &spec(&slug, address)).await;
        assert_eq!(
            page.status, 400,
            "the upstream address {address:?} must be refused"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deeper_paths_are_not_forwarded() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    upstream.clear();
    let deeper = McpClient::session(
        &format!("{}/extra", w.resource("demo")),
        Some(&tokens.access_token),
    );
    let reply = deeper.initialize().await;
    assert_eq!(
        reply.status, 404,
        "a path deeper than the server must be answered 404"
    );
    assert!(
        upstream.requests().is_empty(),
        "the upstream must not see a request on a deeper path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn query_string_is_dropped() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let with_query = McpClient::session(
        &format!("{}?x=1", w.resource("demo")),
        Some(&tokens.access_token),
    );
    let reply = with_query.initialize().await;
    assert_eq!(
        reply.status, 200,
        "a query string must not stop the request"
    );
    let requests = upstream.requests();
    assert!(!requests.is_empty(), "the request must reach the upstream");
    for request in requests {
        assert_eq!(
            request.path, "/mcp",
            "the upstream must see the path without the query string"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_listed_headers_reach_the_upstream() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    upstream.clear();
    let client = w.session_mcp("demo", &tokens);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0"},
        },
    })
    .to_string();
    let reply = client
        .raw(
            body.as_bytes(),
            &[
                ("X-Custom", "1"),
                ("X-Forwarded-For", "203.0.113.9"),
                ("Forwarded", "for=203.0.113.9"),
                ("Last-Event-ID", "7"),
                ("Cookie", "a=b"),
            ],
        )
        .await;
    assert_eq!(reply.status, 200, "the initialize must be answered");
    let requests = upstream.requests();
    assert!(!requests.is_empty(), "the request must reach the upstream");
    let secret = secret_for("demo");
    for request in &requests {
        for name in [
            "x-custom",
            "x-forwarded-for",
            "forwarded",
            "last-event-id",
            "cookie",
            "authorization",
        ] {
            assert!(
                request.header(name).is_none(),
                "the client's {name} header must not reach the upstream"
            );
        }
        assert_eq!(
            request.header(SECRET_HEADER),
            Some(secret.as_str()),
            "the upstream must receive the gateway's secret"
        );
        assert!(
            request.header("content-type").is_some(),
            "content-type must reach the upstream"
        );
        assert!(
            request.header("accept").is_some(),
            "accept must reach the upstream"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_server_stops_routing() {
    let w = World::start().await;
    let (bob, upstream, id) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    let deleted = admin::delete_server(&w.owner, &id).await;
    assert_eq!(
        deleted.status, 303,
        "the owner must be able to delete the server"
    );
    upstream.clear();
    let reply = w.session_mcp("demo", &tokens).initialize().await;
    assert_eq!(
        reply.status, 401,
        "a token for a deleted server path must be refused"
    );
    assert!(
        upstream.requests().is_empty(),
        "the upstream of a deleted server must not be contacted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn server_survives_a_restart() {
    let mut w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", UpstreamOptions::default()).await;
    let tokens = w.token(&bob, "demo").await;
    w.gw.restart().await;
    let client = session_on(&w, "demo", &tokens).await;
    assert_eq!(
        client.list_tools().await.tool_names(),
        ["echo", "search", "delete_db"],
        "the same token must still list the server's tools after a restart"
    );
}
