#[path = "common/mcp.rs"]
mod mcp;
#[path = "common/upstream.rs"]
mod upstream;

use std::time::{Duration, Instant};

use mcp::McpClient;
use serde_json::{Value, json};
use upstream::{FakeUpstream, Generation, Mode, UpstreamOptions};

const TOOLS: [&str; 3] = ["echo", "search", "delete_db"];
const STATELESS_VERSION: &str = "2026-07-28";

/// A stateless POST body with the three protocol _meta keys.
fn stateless_body(version: &str, id: Value, method: &str, mut params: Value) -> Vec<u8> {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "0"},
    });
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        .to_string()
        .into_bytes()
}

async fn initialized(url: &str) -> McpClient {
    let client = McpClient::session(url, None);
    assert_eq!(client.initialize().await.status, 200);
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn session_list_and_call() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::session(&fake.url(), None);
    let init = client.initialize().await;
    assert_eq!(init.status, 200);
    assert_eq!(init.header("mcp-session-id").as_deref(), Some("sess-1"));
    assert_eq!(
        init.result().expect("result")["protocolVersion"],
        "2025-11-25"
    );
    let list = client.list_tools().await;
    assert_eq!(list.status, 200);
    assert_eq!(list.tool_names(), TOOLS);
    let call = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(call.status, 200);
    assert_eq!(call.text().as_deref(), Some("called: echo"));
    assert_eq!(fake.rpc_count("tools/call"), 1);
    assert_eq!(fake.calls_to("echo"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_requires_known_session() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = initialized(&fake.url()).await;
    client.set_session_id(Some("nope"));
    assert_eq!(client.list_tools().await.status, 404);
    let fresh = McpClient::session(&fake.url(), None);
    assert_eq!(fresh.list_tools().await.status, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_get_and_delete() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = initialized(&fake.url()).await;
    let open = client.get().await;
    assert_eq!(open.status, 200);
    assert_eq!(
        open.header("content-type").as_deref(),
        Some("text/event-stream")
    );
    assert_eq!(open.body, ": open\n\n");
    assert!(open.events.is_empty());
    let gone = client.delete().await;
    assert_eq!(gone.status, 200);
    assert_eq!(client.list_tools().await.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_discover_list_call() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::stateless(&fake.url(), None);
    let discover = client.discover().await;
    assert_eq!(discover.status, 200);
    let found = discover.result().expect("discover result");
    assert_eq!(
        found["supportedVersions"],
        json!(["2026-07-28", "2025-11-25"])
    );
    assert_eq!(found["resultType"], "complete");
    let list = client.list_tools().await;
    assert_eq!(list.status, 200);
    assert_eq!(list.tool_names(), TOOLS);
    let listed = list.result().expect("list result");
    assert_eq!(listed["resultType"], "complete");
    assert_eq!(listed["ttlMs"], 300000);
    assert_eq!(listed["cacheScope"], "public");
    let call = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(call.status, 200);
    assert_eq!(call.text().as_deref(), Some("called: echo"));
    assert_eq!(
        call.result().expect("call result")["resultType"],
        "complete"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_header_mismatch() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::stateless(&fake.url(), None);
    let call = stateless_body(
        STATELESS_VERSION,
        json!(1),
        "tools/call",
        json!({"name": "echo", "arguments": {}}),
    );
    let wrong_name = client
        .raw(
            &call,
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "other"),
            ],
        )
        .await;
    assert_eq!(wrong_name.status, 400);
    assert_eq!(wrong_name.error_code(), Some(-32020));
    assert_eq!(
        wrong_name.error_message().as_deref(),
        Some("Header mismatch: Mcp-Name does not match the body")
    );

    let list = stateless_body(STATELESS_VERSION, json!(2), "tools/list", json!({}));
    let duplicated = client
        .raw(
            &list,
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(duplicated.status, 400);
    assert_eq!(duplicated.error_code(), Some(-32020));
    assert_eq!(
        duplicated.error_message().as_deref(),
        Some("Header mismatch: Mcp-Method repeated")
    );

    let missing = client
        .raw(&list, &[("MCP-Protocol-Version", "2026-07-28")])
        .await;
    assert_eq!(missing.status, 400);
    assert_eq!(missing.error_code(), Some(-32020));
    assert_eq!(
        missing.error_message().as_deref(),
        Some("Header mismatch: Mcp-Method missing")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_base64_name() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    fake.set_tools(&["héllo"]);
    let client = McpClient::stateless(&fake.url(), None);
    let call = client.call_tool("héllo", json!({})).await;
    assert_eq!(call.status, 200);
    assert_eq!(call.text().as_deref(), Some("called: héllo"));
    let recorded = fake
        .requests()
        .into_iter()
        .rev()
        .find(|r| r.tool.is_some())
        .expect("tools/call recorded");
    let name = recorded.header("mcp-name").expect("mcp-name header");
    assert!(name.starts_with("=?base64?"));
    assert_eq!(name, "=?base64?aMOpbGxv?=");
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_unsupported_version() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::stateless(&fake.url(), None);
    let body = stateless_body("1900-01-01", json!(7), "tools/list", json!({}));
    let reply = client
        .raw(
            &body,
            &[
                ("MCP-Protocol-Version", "1900-01-01"),
                ("Mcp-Method", "tools/list"),
            ],
        )
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error_code(), Some(-32022));
    let error = &reply.json.as_ref().expect("json")["error"];
    assert!(error["data"]["supported"].is_array());
    assert_eq!(error["data"]["requested"], "1900-01-01");
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_only_rejects_handshake() {
    let fake = FakeUpstream::start(UpstreamOptions {
        generation: Generation::Stateless,
        ..UpstreamOptions::default()
    })
    .await;
    let client = McpClient::session(&fake.url(), None);
    let init = client.initialize().await;
    assert_eq!(init.status, 400);
    assert_eq!(init.error_code(), Some(-32022));
    assert_eq!(client.get().await.status, 405);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_only_rejects_discover() {
    let fake = FakeUpstream::start(UpstreamOptions {
        generation: Generation::Session,
        ..UpstreamOptions::default()
    })
    .await;
    let client = McpClient::stateless(&fake.url(), None);
    let reply = client.discover().await;
    assert_eq!(reply.error_code(), Some(-32601));
    assert_eq!(reply.error_message().as_deref(), Some("Method not found"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tool_and_method() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let session = initialized(&fake.url()).await;
    let stateless = McpClient::stateless(&fake.url(), None);
    for client in [&session, &stateless] {
        let unknown = client.call_tool("nope", json!({})).await;
        assert_eq!(unknown.error_code(), Some(-32602));
        assert_eq!(
            unknown.error_message().as_deref(),
            Some("Unknown tool: nope")
        );
        let missing = client.request("tasks/list", json!({})).await;
        assert_eq!(missing.error_code(), Some(-32601));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn progress_is_streamed() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let session = initialized(&fake.url()).await;
    let stateless = McpClient::stateless(&fake.url(), None);
    fake.set_mode(Mode::Progress {
        steps: 3,
        interval_ms: 200,
    });
    for client in [&session, &stateless] {
        let reply = client.call_tool("echo", json!({})).await;
        assert_eq!(reply.status, 200);
        assert!(reply.events.len() >= 4, "events: {}", reply.events.len());
        let first = reply.events.first().expect("first event");
        let last = reply.events.last().expect("last event");
        assert!(last.at >= first.at + Duration::from_millis(350));
        assert_eq!(first.data["method"], "notifications/progress");
        assert_eq!(first.data["params"]["progress"], 1);
        assert_eq!(first.data["params"]["total"], 3);
        assert_eq!(reply.text().as_deref(), Some("called: echo"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hang_times_out() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let session = initialized(&fake.url()).await;
    let stateless = McpClient::stateless(&fake.url(), None);
    fake.set_mode(Mode::Hang);
    for client in [&session, &stateless] {
        client.set_timeout(Duration::from_millis(300));
        let hung = client.call_tool("echo", json!({})).await;
        assert_eq!(hung.status, 0);
        assert_eq!(hung.body, "");
        let listed = client.list_tools().await;
        assert_eq!(listed.status, 200);
        assert_eq!(listed.tool_names(), TOOLS);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_redirect_cookie_html() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::stateless(&fake.url(), None);
    fake.set_mode(Mode::Garbage);
    let garbage = client.list_tools().await;
    assert_eq!(garbage.status, 200);
    assert_eq!(garbage.body, "not json at all");
    assert!(garbage.json.is_none());

    fake.set_mode(Mode::Redirect("http://127.0.0.1:9/x".into()));
    let redirect = client.list_tools().await;
    assert_eq!(redirect.status, 307);
    assert_eq!(
        redirect.header("location").as_deref(),
        Some("http://127.0.0.1:9/x")
    );

    fake.set_mode(Mode::SetCookie);
    let cookie = client.list_tools().await;
    assert_eq!(cookie.status, 200);
    assert_eq!(
        cookie.header("set-cookie").as_deref(),
        Some("upstream=1; Path=/")
    );
    assert_eq!(
        cookie.header("www-authenticate").as_deref(),
        Some("Basic realm=\"up\"")
    );

    fake.set_mode(Mode::WrongContentType);
    let html = client.list_tools().await;
    assert_eq!(html.status, 200);
    assert_eq!(html.header("content-type").as_deref(), Some("text/html"));
    assert_eq!(html.body, "<script>alert(1)</script>");
    assert!(html.json.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn lenient_names_and_methods() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let session = initialized(&fake.url()).await;
    let stateless = McpClient::stateless(&fake.url(), None);

    fake.set_mode(Mode::LenientNames);
    let spaced = session.call_tool(" Delete_DB ", json!({})).await;
    assert_eq!(spaced.text().as_deref(), Some("called: delete_db"));
    let zero_width = session.call_tool("delete\u{200B}_db", json!({})).await;
    assert_eq!(zero_width.text().as_deref(), Some("called: delete_db"));

    fake.set_mode(Mode::Normal);
    let strict = session.call_tool(" Delete_DB ", json!({})).await;
    assert_eq!(strict.error_code(), Some(-32602));
    assert_eq!(
        strict.error_message().as_deref(),
        Some("Unknown tool:  Delete_DB ")
    );
    let strict_zero_width = session.call_tool("delete\u{200B}_db", json!({})).await;
    assert_eq!(strict_zero_width.error_code(), Some(-32602));

    fake.set_mode(Mode::LenientMethods);
    let lenient = stateless.request("Tools/List", json!({})).await;
    assert_eq!(lenient.status, 200);
    assert_eq!(lenient.tool_names(), TOOLS);

    fake.set_mode(Mode::Normal);
    let strict_method = stateless.request("Tools/List", json!({})).await;
    assert_eq!(strict_method.error_code(), Some(-32601));
}

#[tokio::test(flavor = "multi_thread")]
async fn reuse_session_id() {
    let fake = FakeUpstream::start(UpstreamOptions {
        mode: Mode::ReuseSessionId,
        ..UpstreamOptions::default()
    })
    .await;
    let first = McpClient::session(&fake.url(), None);
    let second = McpClient::session(&fake.url(), None);
    assert_eq!(
        first.initialize().await.header("mcp-session-id").as_deref(),
        Some("fixed-session")
    );
    assert_eq!(
        second
            .initialize()
            .await
            .header("mcp-session-id")
            .as_deref(),
        Some("fixed-session")
    );
    assert_eq!(first.session_id().as_deref(), Some("fixed-session"));
    assert_eq!(second.session_id().as_deref(), Some("fixed-session"));
}

#[tokio::test(flavor = "multi_thread")]
async fn require_header_gate() {
    let fake = FakeUpstream::start(UpstreamOptions {
        require_header: Some(("x-gateway-secret".into(), "s3cret".into())),
        ..UpstreamOptions::default()
    })
    .await;
    let client = McpClient::stateless(&fake.url(), None);
    let refused = client.list_tools().await;
    assert_eq!(refused.status, 401);
    assert_eq!(refused.body, "{}");

    let body = stateless_body(STATELESS_VERSION, json!(1), "tools/list", json!({}));
    let allowed = client
        .raw(
            &body,
            &[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
                ("x-gateway-secret", "s3cret"),
            ],
        )
        .await;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.tool_names(), TOOLS);

    let requests = fake.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].header("x-gateway-secret"), None);
    assert_eq!(requests[1].header("x-gateway-secret"), Some("s3cret"));
}

#[tokio::test(flavor = "multi_thread")]
async fn records_everything() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::stateless(&fake.url(), None);

    let garbage = client.raw(b"not json", &[]).await;
    assert_eq!(garbage.status, 400);
    assert_eq!(
        garbage.body,
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#
    );
    let recorded = fake.requests().pop().expect("recorded");
    assert_eq!(recorded.http_method, "POST");
    assert_eq!(recorded.path, "/mcp");
    assert_eq!(recorded.body, b"not json");
    assert_eq!(recorded.rpc_method, None);
    assert_eq!(recorded.json(), None);

    let duplicated = client
        .raw(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            &[("X-Dup", "a"), ("X-Dup", "b")],
        )
        .await;
    assert_eq!(duplicated.status, 400);
    let recorded = fake.requests().pop().expect("recorded");
    assert_eq!(recorded.header_all("x-dup"), ["a", "b"]);
    assert_eq!(recorded.header("x-dup"), Some("a"));
    assert_eq!(recorded.rpc_method.as_deref(), Some("ping"));

    let query = reqwest::Client::new()
        .get(format!("{}?x=1", fake.url()))
        .send()
        .await
        .expect("query request");
    assert_eq!(query.status(), reqwest::StatusCode::BAD_REQUEST);
    let recorded = fake.requests().pop().expect("recorded");
    assert_eq!(recorded.http_method, "GET");
    assert_eq!(recorded.path, "/mcp?x=1");

    let session = initialized(&fake.url()).await;
    let plain = McpClient::session(&fake.url(), None);
    assert_eq!(plain.list_tools().await.status, 400);
    let session_resources = session.request("resources/list", json!({})).await;
    assert_eq!(
        session_resources.result(),
        Some(&json!({"resources": [{"uri": "file:///secret.txt", "name": "secret"}]}))
    );
    let session_read = session
        .request("resources/read", json!({"uri": "file:///secret.txt"}))
        .await;
    assert_eq!(
        session_read.result(),
        Some(&json!({"contents": [{"uri": "file:///secret.txt", "text": "TOP-SECRET"}]}))
    );
    let session_prompts = session.request("prompts/list", json!({})).await;
    assert_eq!(
        session_prompts.result(),
        Some(&json!({"prompts": [{"name": "greet"}]}))
    );
    let session_prompt = session
        .request("prompts/get", json!({"name": "greet"}))
        .await;
    assert_eq!(
        session_prompt.result(),
        Some(
            &json!({"messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}]})
        )
    );

    let stateless = McpClient::stateless(&fake.url(), None);
    let resources = stateless.request("resources/list", json!({})).await;
    assert_eq!(
        resources.result(),
        Some(&json!({
            "resultType": "complete",
            "resources": [{"uri": "file:///secret.txt", "name": "secret"}],
            "ttlMs": 300000,
            "cacheScope": "public",
        }))
    );
    let read = stateless
        .request("resources/read", json!({"uri": "file:///secret.txt"}))
        .await;
    assert_eq!(
        read.result(),
        Some(&json!({
            "resultType": "complete",
            "contents": [{"uri": "file:///secret.txt", "text": "TOP-SECRET"}],
        }))
    );
    let prompts = stateless.request("prompts/list", json!({})).await;
    assert_eq!(
        prompts.result(),
        Some(&json!({
            "resultType": "complete",
            "prompts": [{"name": "greet"}],
            "ttlMs": 300000,
            "cacheScope": "public",
        }))
    );
    let prompt = stateless
        .request("prompts/get", json!({"name": "greet"}))
        .await;
    assert_eq!(
        prompt.result(),
        Some(&json!({
            "resultType": "complete",
            "messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}],
        }))
    );

    fake.clear();
    assert!(fake.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_refuses() {
    let mut fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = McpClient::stateless(&fake.url(), None);
    assert_eq!(client.list_tools().await.status, 200);
    fake.shutdown().await;
    let started = Instant::now();
    let refused = client.list_tools().await;
    assert_eq!(refused.status, 0);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn server_request_then_result() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let session = initialized(&fake.url()).await;
    let stateless = McpClient::stateless(&fake.url(), None);
    fake.set_mode(Mode::ServerRequest);
    for client in [&session, &stateless] {
        let reply = client.call_tool("echo", json!({})).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.events.len(), 2, "events: {}", reply.events.len());
        let request = &reply.events[0];
        assert_eq!(request.data["method"], "elicitation/create");
        assert_eq!(request.data["id"], "srv-1");
        assert_eq!(reply.text().as_deref(), Some("called: echo"));
        let gap = reply.events[1].at.saturating_sub(request.at);
        assert!(gap >= Duration::from_millis(80), "gap: {gap:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_answer_is_accepted() {
    let fake = FakeUpstream::start(UpstreamOptions::default()).await;
    let client = initialized(&fake.url()).await;
    let session_id = client.session_id().expect("session id");
    let accept = br#"{"jsonrpc":"2.0","id":"srv-1","result":{"action":"accept"}}"#;
    let failed = br#"{"jsonrpc":"2.0","id":"srv-1","error":{"code":-1,"message":"no"}}"#;
    for mode in [Mode::Normal, Mode::ServerRequest, Mode::LenientMethods] {
        fake.set_mode(mode);
        for body in [&accept[..], &failed[..]] {
            let answered = client
                .raw(
                    body,
                    &[
                        ("Mcp-Session-Id", session_id.as_str()),
                        ("MCP-Protocol-Version", "2025-11-25"),
                    ],
                )
                .await;
            assert_eq!(answered.status, 202);
            assert_eq!(answered.body, "");
            let anonymous = client
                .raw(body, &[("MCP-Protocol-Version", "2025-11-25")])
                .await;
            assert_eq!(anonymous.status, 400);
        }
    }
}
