mod common;

use common::client::{TestClient, Tokens};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, Generation, Mode, UpstreamOptions};
use common::world::World;
use serde_json::{Value, json};

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

/// The body of a session-style initialize that asks for `version`.
fn initialize_body(version: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0"},
        },
    })
    .to_string()
}

fn options(generation: Generation) -> UpstreamOptions {
    UpstreamOptions {
        generation,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn session_client_on_a_server_path() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.session_mcp("demo", &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize must be answered");
    assert_eq!(
        init.result().and_then(|r| r["protocolVersion"].as_str()),
        Some("2025-11-25"),
        "the session revision must be 2025-11-25"
    );
    assert!(
        init.header("mcp-session-id").is_some(),
        "a session-style initialize must carry an mcp-session-id header"
    );
    assert_eq!(
        client.list_tools().await.tool_names(),
        ["echo", "search", "delete_db"],
        "the session client must list the upstream's tools"
    );
    let called = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        called.text().as_deref(),
        Some("called: echo"),
        "the session client must call a tool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_client_on_a_server_path() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.stateless_mcp("demo", &tokens);
    let discovered = client.discover().await;
    assert_eq!(discovered.status, 200, "server/discover must be answered");
    let versions = discovered
        .result()
        .and_then(|r| r["supportedVersions"].as_array())
        .expect("server/discover must list supportedVersions");
    assert!(
        versions.iter().any(|v| v.as_str() == Some("2026-07-28")),
        "server/discover must list revision 2026-07-28, got {versions:?}"
    );
    let listed = client.list_tools().await;
    let result = listed.result().expect("tools/list must answer a result");
    assert_eq!(
        result["resultType"], "complete",
        "a stateless list answer must be complete"
    );
    assert_eq!(
        result["cacheScope"], "private",
        "a stateless list answer must be private"
    );
    let called = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        called.text().as_deref(),
        Some("called: echo"),
        "the stateless client must call a tool"
    );
    let call = upstream
        .requests()
        .into_iter()
        .find(|r| r.rpc_method.as_deref() == Some("tools/call"))
        .expect("the upstream must record the tools/call");
    assert_eq!(
        call.header("mcp-method"),
        Some("tools/call"),
        "the upstream must receive the Mcp-Method header"
    );
    assert_eq!(
        call.header("mcp-name"),
        Some("echo"),
        "the upstream must receive the Mcp-Name header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_client_on_the_combined_endpoint_with_a_stateless_upstream() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Stateless)).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = w.session_mcp("mcp", &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize on /mcp must be answered");
    assert_eq!(
        init.result().and_then(|r| r["serverInfo"]["name"].as_str()),
        Some("doorward"),
        "the combined endpoint must name itself doorward"
    );
    assert!(
        init.header("mcp-session-id").is_none(),
        "the combined endpoint must not issue a session id"
    );
    let names = client.list_tools().await.tool_names();
    assert!(
        names.iter().any(|n| n == "demo__echo"),
        "the combined list must name demo__echo, got {names:?}"
    );
    let called = client.call_tool("demo__echo", json!({"text": "hi"})).await;
    assert_eq!(
        called.text().as_deref(),
        Some("called: echo"),
        "demo__echo must be callable"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_client_on_the_combined_endpoint_with_a_session_upstream() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", options(Generation::Session)).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = w.stateless_mcp("mcp", &tokens);
    let names = client.list_tools().await.tool_names();
    assert!(
        names.iter().any(|n| n == "demo__echo"),
        "the combined list must name demo__echo, got {names:?}"
    );
    for _ in 0..2 {
        let called = client.call_tool("demo__echo", json!({"text": "hi"})).await;
        assert_eq!(
            called.text().as_deref(),
            Some("called: echo"),
            "demo__echo must be callable through the session upstream"
        );
    }
    assert_eq!(
        upstream.rpc_count("initialize"),
        1,
        "the upstream must be initialized once for the token family"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_endpoint_with_mixed_upstreams() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (a, id_a) = w.upstream("a", options(Generation::Session)).await;
    let (b, id_b) = w
        .upstream(
            "b",
            UpstreamOptions {
                generation: Generation::Stateless,
                tools: vec!["alpha".into()],
                ..Default::default()
            },
        )
        .await;
    w.grant(BOB, &[&id_a, &id_b]).await;
    let tokens = w.token(&bob, "mcp").await;
    let session = w.session_mcp("mcp", &tokens);
    assert_eq!(
        session.initialize().await.status,
        200,
        "initialize on /mcp must be answered"
    );
    let stateless = w.stateless_mcp("mcp", &tokens);
    for client in [&session, &stateless] {
        assert_eq!(
            client.list_tools().await.tool_names(),
            ["a__echo", "a__search", "a__delete_db", "b__alpha"],
            "both upstreams' tools must be listed"
        );
        let echo = client.call_tool("a__echo", json!({"text": "hi"})).await;
        assert_eq!(
            echo.text().as_deref(),
            Some("called: echo"),
            "a__echo must reach the session-only upstream"
        );
        let alpha = client.call_tool("b__alpha", json!({"text": "hi"})).await;
        assert_eq!(
            alpha.text().as_deref(),
            Some("called: alpha"),
            "b__alpha must reach the stateless-only upstream"
        );
    }
    assert_eq!(
        a.calls_to("echo"),
        2,
        "upstream a must receive both echo calls"
    );
    assert_eq!(
        b.calls_to("alpha"),
        2,
        "upstream b must receive both alpha calls"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_discover_shape() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "mcp").await;
    let reply = w.stateless_mcp("mcp", &tokens).discover().await;
    assert_eq!(
        reply.status, 200,
        "server/discover on /mcp must be answered"
    );
    let result = reply
        .result()
        .expect("server/discover must answer a result");
    assert_eq!(
        result["supportedVersions"],
        json!(["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]),
        "the combined endpoint must list its supported revisions"
    );
    assert_eq!(
        result["capabilities"],
        json!({"tools": {}}),
        "the combined endpoint must offer only tools"
    );
    assert_eq!(
        result["cacheScope"], "private",
        "the discover answer must be private"
    );
    assert_eq!(
        result["resultType"], "complete",
        "the discover answer must be complete"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_initialize_negotiates_the_revision() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = McpClient::session(&w.resource("mcp"), Some(&tokens.access_token));
    let known = client
        .raw(initialize_body("2025-06-18").as_bytes(), &[])
        .await;
    assert_eq!(
        known.result().and_then(|r| r["protocolVersion"].as_str()),
        Some("2025-06-18"),
        "a known revision must be answered with itself"
    );
    let unknown = client
        .raw(initialize_body("1999-01-01").as_bytes(), &[])
        .await;
    assert_eq!(
        unknown.result().and_then(|r| r["protocolVersion"].as_str()),
        Some("2025-11-25"),
        "an unknown revision must be answered with 2025-11-25"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_refuses_an_unknown_stateless_revision() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = McpClient::session(&w.resource("mcp"), Some(&tokens.access_token));
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2031-01-01", "io.modelcontextprotocol/clientCapabilities": {}}},
    })
    .to_string();
    let reply = client
        .raw(
            body.as_bytes(),
            &[
                ("MCP-Protocol-Version", "2031-01-01"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(
        reply.status, 400,
        "an unknown stateless revision must be refused"
    );
    assert_eq!(
        reply.error_code(),
        Some(-32022),
        "an unknown stateless revision must carry JSON-RPC -32022"
    );
    let supported = reply
        .json
        .as_ref()
        .and_then(|j| j["error"]["data"]["supported"].as_array());
    assert!(
        supported.is_some(),
        "the error must list error.data.supported as an array"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn older_session_revision_is_relayed() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.session_mcp("demo", &tokens);
    let reply = client
        .raw(initialize_body("2025-03-26").as_bytes(), &[])
        .await;
    assert_eq!(
        reply.result().and_then(|r| r["protocolVersion"].as_str()),
        Some("2025-03-26"),
        "an older session revision must be relayed as the upstream answers it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_stream_needs_a_session() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let demo_tokens = w.token(&bob, "demo").await;
    let mcp_tokens = w.token(&bob, "mcp").await;

    let client = session_on(&w, "demo", &demo_tokens).await;
    let stream = client.get().await;
    assert_eq!(
        stream.status, 200,
        "a GET with a recorded session must open the stream"
    );
    assert_eq!(
        stream.header("content-type").as_deref(),
        Some("text/event-stream"),
        "the stream must be text/event-stream"
    );

    let never_started = w.session_mcp("demo", &demo_tokens).get().await;
    assert_eq!(
        never_started.status, 405,
        "a session client that never initialised must get 405 on GET"
    );

    let combined = session_on(&w, "mcp", &mcp_tokens).await;
    assert_eq!(
        combined.get().await.status,
        405,
        "GET on /mcp must be answered 405"
    );

    let session_id = client
        .session_id()
        .expect("initialize must record the session id");
    let response =
        w.gw.http
            .get(w.resource("demo"))
            .bearer_auth(&demo_tokens.access_token)
            .header("Mcp-Session-Id", session_id)
            .header("MCP-Protocol-Version", "2026-07-28")
            .send()
            .await
            .expect("request");
    assert_eq!(
        response.status().as_u16(),
        405,
        "a GET carrying MCP-Protocol-Version 2026-07-28 must be answered 405"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_ends_the_session() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    let deleted = client.delete().await;
    assert_eq!(
        deleted.status, 200,
        "DELETE with a recorded session must be answered 200"
    );
    assert!(
        upstream
            .requests()
            .iter()
            .any(|r| r.http_method == "DELETE"),
        "the upstream must record the DELETE"
    );
    assert_eq!(
        client.list_tools().await.status,
        404,
        "the next request on the ended session must be answered 404"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn notifications_are_accepted() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let demo_tokens = w.token(&bob, "demo").await;
    let mcp_tokens = w.token(&bob, "mcp").await;

    let client = session_on(&w, "demo", &demo_tokens).await;
    let note = client
        .notify("notifications/initialized", Value::Null)
        .await;
    assert_eq!(
        note.status, 202,
        "a notification on a server path must be accepted"
    );

    let combined = session_on(&w, "mcp", &mcp_tokens).await;
    let note = combined
        .notify("notifications/initialized", Value::Null)
        .await;
    assert_eq!(note.status, 202, "a notification on /mcp must be accepted");
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_follows_the_generation() {
    let w = World::start().await;
    let (bob, upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let tokens = w.token(&bob, "demo").await;
    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let pong = session.request("ping", json!({})).await;
    assert_eq!(
        pong.result(),
        Some(&json!({})),
        "a session ping must be answered with an empty result"
    );
    assert_eq!(
        upstream.rpc_count("ping"),
        1,
        "a session ping must reach the upstream"
    );

    let stateless = w.stateless_mcp("demo", &tokens);
    let refused = stateless.request("ping", json!({})).await;
    assert_eq!(
        refused.status, 404,
        "a stateless ping the server does not implement is 404"
    );
    assert_eq!(
        refused.error_code(),
        Some(-32601),
        "a stateless ping must be refused with -32601"
    );
    assert_eq!(
        upstream.rpc_count("ping"),
        1,
        "a stateless ping must never reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_typescript_style_upstream_works_in_session_mode() {
    let w = World::start().await;
    let options = UpstreamOptions {
        generation: Generation::Session,
        mode: Mode::TypeScriptNotices,
        ..Default::default()
    };
    let (bob, _upstream, _) = bob_on(&w, "demo", options).await;
    let tokens = w.token(&bob, "demo").await;
    let client = session_on(&w, "demo", &tokens).await;
    let note = client
        .notify("notifications/initialized", Value::Null)
        .await;
    assert_eq!(
        note.status, 202,
        "a notification answered 202 by the upstream must be accepted"
    );
    assert_eq!(note.body, "", "the accepted notification has no body");
    assert!(
        note.header("content-type").is_none(),
        "the accepted notification has no content type"
    );
    assert_eq!(
        client.list_tools().await.tool_names(),
        ["echo", "search", "delete_db"],
        "the session client must list the upstream's tools"
    );
    let called = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        called.text().as_deref(),
        Some("called: echo"),
        "the session client must call a tool"
    );
}

/// The id of a JSON-RPC answer, or null when it has none.
fn id_of(reply: &common::mcp::McpReply) -> Value {
    reply
        .json
        .as_ref()
        .and_then(|answer| answer.get("id").cloned())
        .unwrap_or(Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_refusals_have_the_specified_shapes() {
    let w = World::start().await;
    let (bob, _upstream, _) = bob_on(&w, "demo", options(Generation::Both)).await;
    let demo_tokens = w.token(&bob, "demo").await;
    let mcp_tokens = w.token(&bob, "mcp").await;
    let demo = McpClient::stateless(&w.resource("demo"), Some(&demo_tokens.access_token));
    let mcp = McpClient::stateless(&w.resource("mcp"), Some(&mcp_tokens.access_token));
    let stateless_meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}});
    let with_meta = |params: Value| {
        let mut params = params;
        params["_meta"] = stateless_meta.clone();
        params
    };
    let request = |id: u64, method: &str, params: Value| {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
            .to_string()
            .into_bytes()
    };

    let refused = demo
        .raw(
            &request(4, "ping", with_meta(json!({}))),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "ping"),
            ],
        )
        .await;
    assert_eq!(
        refused.status, 404,
        "a stateless ping the server does not implement must be 404"
    );
    assert_eq!(refused.error_code(), Some(-32601));
    assert_eq!(
        id_of(&refused),
        json!(4),
        "the answer carries the request id"
    );

    let refused = mcp
        .raw(
            &request(5, "resources/list", with_meta(json!({}))),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "resources/list"),
            ],
        )
        .await;
    assert_eq!(
        refused.status, 404,
        "a stateless resources/list on /mcp must be 404"
    );
    assert_eq!(refused.error_code(), Some(-32601));
    assert_eq!(id_of(&refused), json!(5));

    let session_mcp = session_on(&w, "mcp", &mcp_tokens).await;
    let refused = session_mcp.request("resources/list", json!({})).await;
    assert_eq!(
        refused.status, 200,
        "a session resources/list on /mcp stays 200"
    );
    assert_eq!(refused.error_code(), Some(-32601));

    let session_demo = session_on(&w, "demo", &demo_tokens).await;
    let refused = session_demo.request("tasks/get", json!({})).await;
    assert_eq!(
        refused.status, 200,
        "a session tasks/get on a server path stays 200"
    );
    assert_eq!(refused.error_code(), Some(-32601));

    let missing_meta = demo
        .raw(
            &request(9, "tools/list", json!({})),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(
        missing_meta.status, 400,
        "a stateless body without _meta must be 400"
    );
    assert_eq!(missing_meta.error_code(), Some(-32602));
    assert_eq!(
        missing_meta.error_message().as_deref(),
        Some("Invalid params: missing _meta, protocol version or client capabilities")
    );
    assert_eq!(id_of(&missing_meta), json!(9));

    let missing_version = mcp
        .raw(
            &request(
                10,
                "tools/list",
                json!({"_meta": {"io.modelcontextprotocol/clientInfo": {}}}),
            ),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(
        missing_version.status, 400,
        "a _meta without a protocol version must be 400 on /mcp"
    );
    assert_eq!(missing_version.error_code(), Some(-32602));
    assert_eq!(
        missing_version.error_message().as_deref(),
        Some("Invalid params: missing _meta, protocol version or client capabilities")
    );
    assert_eq!(id_of(&missing_version), json!(10));

    let other_version = demo
        .raw(
            &request(
                11,
                "tools/list",
                json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25", "io.modelcontextprotocol/clientCapabilities": {}}}),
            ),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(
        other_version.status, 400,
        "a _meta version that differs from the header must be 400"
    );
    assert_eq!(other_version.error_code(), Some(-32020));
    assert_eq!(
        other_version.error_message().as_deref(),
        Some("Header mismatch: MCP-Protocol-Version")
    );
    assert_eq!(id_of(&other_version), json!(11));

    let no_capabilities = demo
        .raw(
            &request(
                12,
                "tools/list",
                json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}),
            ),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(
        no_capabilities.status, 400,
        "a stateless request without client capabilities is 400 on a server path"
    );
    assert_eq!(no_capabilities.error_code(), Some(-32602));
    assert_eq!(
        no_capabilities.error_message().as_deref(),
        Some("Invalid params: missing _meta, protocol version or client capabilities")
    );
    assert_eq!(id_of(&no_capabilities), json!(12));

    let no_capabilities = mcp
        .raw(
            &request(
                13,
                "server/discover",
                json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}),
            ),
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "server/discover"),
            ],
        )
        .await;
    assert_eq!(
        no_capabilities.status, 400,
        "a stateless request without client capabilities is 400 on /mcp"
    );
    assert_eq!(no_capabilities.error_code(), Some(-32602));
    assert_eq!(
        no_capabilities.error_message().as_deref(),
        Some("Invalid params: missing _meta, protocol version or client capabilities")
    );
    assert_eq!(id_of(&no_capabilities), json!(13));
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_subscriptions_are_refused_and_not_advertised() {
    let w = World::start().await;
    let options = UpstreamOptions {
        mode: Mode::DeclaresFlags,
        ..Default::default()
    };
    let (bob, upstream, _) = bob_on(&w, "demo", options).await;
    let demo_tokens = w.token(&bob, "demo").await;
    let mcp_tokens = w.token(&bob, "mcp").await;
    let demo = McpClient::stateless(&w.resource("demo"), Some(&demo_tokens.access_token));
    let mcp = McpClient::stateless(&w.resource("mcp"), Some(&mcp_tokens.access_token));
    let body = json!({"jsonrpc": "2.0", "id": 4, "method": "subscriptions/listen", "params": {
        "notifications": {},
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}},
    }})
    .to_string();
    let headers = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "subscriptions/listen"),
    ];
    for (label, client) in [("/demo", &demo), ("/mcp", &mcp)] {
        let refused = client.raw(body.as_bytes(), &headers).await;
        assert_eq!(
            refused.status, 404,
            "a stateless subscriptions/listen on {label} is 404"
        );
        assert_eq!(refused.error_code(), Some(-32601), "on {label}");
        assert_eq!(
            id_of(&refused),
            json!(4),
            "on {label} the id is the request's"
        );
    }
    assert_eq!(
        upstream.rpc_count("subscriptions/listen"),
        0,
        "no subscription reaches the upstream"
    );

    let discovered = demo.discover().await;
    assert_eq!(
        discovered
            .result()
            .map(|result| result["capabilities"].clone()),
        Some(json!({"tools": {"extra": 1}})),
        "a stateless discover drops listChanged and subscribe and keeps the other members"
    );

    let initialized = w.session_mcp("demo", &demo_tokens).initialize().await;
    assert_eq!(
        initialized
            .result()
            .map(|result| result["capabilities"]["tools"].clone()),
        Some(json!({"listChanged": true, "extra": 1})),
        "a session initialize keeps its listChanged flag"
    );
}
