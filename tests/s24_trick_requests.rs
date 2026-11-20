mod common;

use base64::Engine as _;
use common::admin;
use common::client::Tokens;
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::world::World;
use serde_json::json;

const STATELESS: &str = "2026-07-28";
const SESSION: &str = "2025-11-25";
const META: &str = r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test-client","version":"0"}}"#;

/// A JSON-RPC request with id 1; `params` is the text inside the params object, never empty.
fn request_body(method: &str, params: &str, stateless: bool) -> String {
    let meta = if stateless {
        format!(r#","_meta":{META}"#)
    } else {
        String::new()
    };
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{{params}{meta}}}}}"#)
}

/// The params text of a tools/call for `name`; the name is written as given.
fn call_params(name: &str) -> String {
    format!(r#""name":"{name}","arguments":{{}}"#)
}

fn call_body(name: &str) -> String {
    request_body("tools/call", &call_params(name), true)
}

fn base64_form(text: &str) -> String {
    format!(
        "=?base64?{}?=",
        base64::engine::general_purpose::STANDARD.encode(text)
    )
}

/// The header value for `text`: itself when plain printable ASCII, else the base64 form.
fn plain_or_base64(text: &str) -> String {
    if text.bytes().all(|byte| byte.is_ascii_graphic()) {
        text.to_string()
    } else {
        base64_form(text)
    }
}

fn header(name: &'static str, value: &str) -> (&'static str, String) {
    (name, value.to_string())
}

/// The headers of a well-formed stateless tools/call whose Mcp-Name is `name_header`.
fn call_headers(name_header: &str) -> Vec<(&'static str, String)> {
    vec![
        header("MCP-Protocol-Version", STATELESS),
        header("Mcp-Method", "tools/call"),
        header("Mcp-Name", name_header),
    ]
}

/// The headers a session-style request carries after initialize.
fn session_headers(session_id: &str, version: &str) -> Vec<(&'static str, String)> {
    vec![
        header("Mcp-Session-Id", session_id),
        header("MCP-Protocol-Version", version),
    ]
}

/// POSTs `body` with `headers` exactly as given, using the client's token.
async fn send(
    client: &McpClient,
    body: impl AsRef<[u8]>,
    headers: &[(&'static str, String)],
) -> McpReply {
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    client.raw(body.as_ref(), &pairs).await
}

fn assert_refused(reply: &McpReply, status: u16, code: i64, case: &str) {
    assert_eq!(
        reply.status, status,
        "{case}: HTTP status, body {}",
        reply.body
    );
    assert_eq!(
        reply.error_code(),
        Some(code),
        "{case}: JSON-RPC error code, body {}",
        reply.body
    );
}

/// Bob on demo, with a deny rule on delete_db for everyone; returns the upstream and his tokens.
async fn bob_with_deny(w: &World) -> (FakeUpstream, Tokens) {
    let bob = w.user("bob@example.com").await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(id.as_str()),
        Some("delete_db"),
    )
    .await;
    assert_eq!(
        page.status, 303,
        "the deny rule for delete_db must be stored"
    );
    (upstream, tokens)
}

/// A session-style client for bob that has completed initialize.
async fn initialized(w: &World, tokens: &Tokens) -> McpClient {
    let client = w.session_mcp("demo", tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn header_and_body_name_different_tools() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let reply = send(&client, call_body("delete_db"), &call_headers("echo")).await;
    assert_refused(
        &reply,
        400,
        -32020,
        "a header naming echo with a body naming delete_db",
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        0,
        "the upstream must not see the call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn required_headers_must_be_present_once() {
    let w = World::start().await;
    let (_upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    let version = header("MCP-Protocol-Version", STATELESS);
    let method = header("Mcp-Method", "tools/call");
    let name = header("Mcp-Name", "echo");
    let cases = [
        ("Mcp-Method missing", vec![version.clone(), name.clone()]),
        (
            "Mcp-Method twice",
            vec![
                version.clone(),
                method.clone(),
                method.clone(),
                name.clone(),
            ],
        ),
        ("Mcp-Name missing", vec![version.clone(), method.clone()]),
        (
            "Mcp-Name twice",
            vec![version.clone(), method.clone(), name.clone(), name.clone()],
        ),
        (
            "MCP-Protocol-Version differs from _meta",
            vec![
                header("MCP-Protocol-Version", SESSION),
                method.clone(),
                name.clone(),
            ],
        ),
    ];
    for (case, headers) in cases {
        let reply = send(&client, call_body("echo"), &headers).await;
        assert_refused(&reply, 400, -32020, case);
        assert!(
            reply
                .error_message()
                .is_some_and(|message| message.starts_with("Header mismatch:")),
            "{case}: the message must start with Header mismatch:, got {:?}",
            reply.error_message()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_base64_header_form_is_decoded() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    let encoded_echo = base64_form("echo");
    let served = send(&client, call_body("echo"), &call_headers(&encoded_echo)).await;
    assert_eq!(
        served.status, 200,
        "the base64 name of echo must match the body"
    );
    assert_eq!(
        served.text().as_deref(),
        Some("called: echo"),
        "the call must reach echo"
    );
    upstream.clear();
    let refused = send(
        &client,
        call_body("delete_db"),
        &call_headers(&encoded_echo),
    )
    .await;
    assert_refused(
        &refused,
        400,
        -32020,
        "the base64 name of echo with a body naming delete_db",
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        0,
        "the refused call must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_decision_is_made_from_the_body() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let reply = send(&client, call_body("delete_db"), &call_headers("delete_db")).await;
    assert_eq!(
        reply.status, 200,
        "a denied tool answers as a JSON-RPC error"
    );
    assert_eq!(reply.error_code(), Some(-32602), "a denied tool is -32602");
    assert_eq!(
        reply.error_message().as_deref(),
        Some("Unknown tool: delete_db"),
        "the denied tool is reported as unknown"
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        0,
        "the upstream must not see the denied call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_keys_are_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = initialized(&w, &tokens).await;
    let session = session_headers(&client.session_id().expect("session id"), SESSION);
    let cases = [
        (
            "a duplicate name in params",
            r#""name":"echo","name":"delete_db","arguments":{}"#,
        ),
        (
            "a duplicate key in arguments",
            r#""name":"echo","arguments":{"text":"a","text":"b"}"#,
        ),
        (
            "a duplicate name written with an escape",
            r#""name":"echo","arguments":{},"\u006eame":"delete_db""#,
        ),
    ];
    for (case, params) in cases {
        upstream.clear();
        let stateless = send(
            &client,
            request_body("tools/call", params, true),
            &call_headers(&plain_or_base64("echo")),
        )
        .await;
        assert_refused(&stateless, 400, -32700, &format!("stateless: {case}"));
        let session_reply =
            send(&client, request_body("tools/call", params, false), &session).await;
        assert_refused(&session_reply, 400, -32700, &format!("session: {case}"));
        assert!(
            upstream.requests().is_empty(),
            "{case}: the upstream must not be contacted"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn batches_are_refused() {
    let w = World::start().await;
    let (_upstream, tokens) = bob_with_deny(&w).await;
    let stateless_batch = format!(
        "[{},{}]",
        request_body("tools/call", &call_params("echo"), true),
        request_body("tools/call", &call_params("search"), true)
    );
    let stateless = w.stateless_mcp("demo", &tokens);
    let reply = send(
        &stateless,
        stateless_batch,
        &call_headers(&plain_or_base64("echo")),
    )
    .await;
    assert_refused(&reply, 400, -32600, "a batch under the stateless rules");

    let session_batch = format!(
        "[{},{}]",
        request_body("tools/call", &call_params("echo"), false),
        request_body("tools/call", &call_params("search"), false)
    );
    let client = initialized(&w, &tokens).await;
    let session = session_headers(&client.session_id().expect("session id"), SESSION);
    let reply = send(&client, &session_batch, &session).await;
    assert_refused(&reply, 400, -32600, "a batch under the session rules");

    let old = w.session_mcp("demo", &tokens);
    let init_params = r#""protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test-client","version":"0"}"#;
    let init = send(&old, request_body("initialize", init_params, false), &[]).await;
    assert_eq!(init.status, 200, "a 2025-03-26 initialize must be relayed");
    assert_eq!(
        init.result()
            .and_then(|result| result["protocolVersion"].as_str()),
        Some("2025-03-26"),
        "the session must negotiate 2025-03-26"
    );
    let old_session = init.header("mcp-session-id").expect("the session id");
    let reply = send(
        &old,
        &session_batch,
        &session_headers(&old_session, "2025-03-26"),
    )
    .await;
    assert_refused(
        &reply,
        400,
        -32600,
        "a batch on a session that negotiated 2025-03-26",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_bodies_are_refused() {
    let w = World::start_with(|config| config.limits.body_bytes = 2000).await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    let padding = "x".repeat(3000);
    let body = request_body(
        "tools/call",
        &format!(r#""name":"echo","arguments":{{"text":"{padding}"}}"#),
        true,
    );
    upstream.clear();
    let reply = send(&client, body, &call_headers(&plain_or_base64("echo"))).await;
    assert_eq!(
        reply.status, 413,
        "a body over body_bytes must be refused with 413"
    );
    assert!(
        upstream.requests().is_empty(),
        "an oversized body must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn compressed_bodies_are_refused() {
    let w = World::start().await;
    let (_upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    let mut headers = call_headers(&plain_or_base64("echo"));
    headers.push(header("Content-Encoding", "gzip"));
    let reply = send(&client, call_body("echo"), &headers).await;
    assert_refused(
        &reply,
        400,
        -32600,
        "a body sent with Content-Encoding gzip",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_text_is_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    let headers = call_headers(&plain_or_base64("echo"));

    let bom = format!("\u{feff}{}", call_body("echo"));
    let reply = send(&client, bom, &headers).await;
    assert_refused(
        &reply,
        400,
        -32600,
        "a body starting with a byte order mark",
    );

    let mut not_utf8 =
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\""
            .to_vec();
    not_utf8.extend_from_slice(&[0xff, 0xfe]);
    not_utf8.extend_from_slice(b"\"}}}");
    let reply = send(&client, not_utf8, &headers).await;
    assert_eq!(
        reply.status, 400,
        "bytes that are not UTF-8 must be refused"
    );

    let surrogate = request_body(
        "tools/call",
        r#""name":"echo","arguments":{"text":"\ud800"}"#,
        true,
    );
    let reply = send(&client, surrogate, &headers).await;
    assert_refused(&reply, 400, -32700, "a lone surrogate escape");

    let trailing = format!("{}{}", call_body("echo"), call_body("echo"));
    let reply = send(&client, trailing, &headers).await;
    assert_refused(&reply, 400, -32700, "a second JSON value after the first");
    assert!(
        upstream.requests().is_empty(),
        "malformed text must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deep_nesting_is_refused() {
    let w = World::start().await;
    let (_upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    let depth = 10_000;
    let nested = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let params = format!(r#""name":"echo","arguments":{nested}"#);
    let reply = send(
        &client,
        request_body("tools/call", &params, true),
        &call_headers(&plain_or_base64("echo")),
    )
    .await;
    assert_refused(&reply, 400, -32700, "arguments nested 10000 deep");
    let health =
        w.gw.http
            .get(w.gw.url("/healthz"))
            .send()
            .await
            .expect("the healthz request");
    assert_eq!(
        health.status(),
        reqwest::StatusCode::OK,
        "the gateway must still answer /healthz"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn look_alike_tool_names_do_not_reach_a_lenient_upstream() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    upstream.set_mode(Mode::LenientNames);
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    for name in [" delete_db", "DELETE_DB", "delete_db\u{200b}", "delete_db "] {
        let reply = send(
            &client,
            call_body(name),
            &call_headers(&plain_or_base64(name)),
        )
        .await;
        assert_eq!(
            reply.status, 200,
            "{name:?}: a refused name answers as a JSON-RPC error"
        );
        assert_eq!(reply.error_code(), Some(-32602), "{name:?}: must be -32602");
        assert_eq!(
            reply.error_message(),
            Some(format!("Unknown tool: {name}")),
            "{name:?}: the message must name the tool as sent"
        );
    }
    assert_eq!(
        upstream.rpc_count("tools/call"),
        0,
        "no look-alike name may reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_case_methods_are_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    upstream.set_mode(Mode::LenientMethods);
    let client = w.stateless_mcp("demo", &tokens);
    for method in ["Tools/Call", "tools/call "] {
        upstream.clear();
        let headers = vec![
            header("MCP-Protocol-Version", STATELESS),
            header("Mcp-Method", &plain_or_base64(method)),
            header("Mcp-Name", &plain_or_base64("echo")),
        ];
        let reply = send(
            &client,
            request_body(method, &call_params("echo"), true),
            &headers,
        )
        .await;
        assert_eq!(
            reply.status, 404,
            "{method:?}: a refused stateless method is 404 with a JSON-RPC error"
        );
        assert_eq!(
            reply.error_code(),
            Some(-32601),
            "{method:?}: must be -32601"
        );
        assert!(
            upstream.requests().is_empty(),
            "{method:?}: the upstream must not be contacted"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn methods_outside_the_list_are_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let stateless = w.stateless_mcp("demo", &tokens);
    let session = initialized(&w, &tokens).await;
    let session_hdrs = session_headers(&session.session_id().expect("session id"), SESSION);
    let methods = [
        "admin/shutdown",
        "tasks/list",
        "tasks/get",
        "sampling/createMessage",
        "roots/list",
        "elicitation/create",
    ];
    for method in methods {
        upstream.clear();
        let reply = send(
            &stateless,
            request_body(method, r#""arguments":{}"#, true),
            &[
                header("MCP-Protocol-Version", STATELESS),
                header("Mcp-Method", method),
            ],
        )
        .await;
        assert_eq!(
            reply.error_code(),
            Some(-32601),
            "stateless {method} must be -32601"
        );
        assert!(
            upstream.requests().is_empty(),
            "stateless {method} must not be forwarded"
        );

        let reply = send(
            &session,
            request_body(method, r#""arguments":{}"#, false),
            &session_hdrs,
        )
        .await;
        assert_eq!(
            reply.error_code(),
            Some(-32601),
            "session {method} must be -32601"
        );
        assert!(
            upstream.requests().is_empty(),
            "session {method} must not be forwarded"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn task_requests_are_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let body = request_body(
        "tools/call",
        r#""name":"echo","arguments":{},"task":{}"#,
        true,
    );
    let reply = send(&client, body, &call_headers(&plain_or_base64("echo"))).await;
    assert_eq!(
        reply.status, 404,
        "a stateless task request is 404 with a JSON-RPC error"
    );
    assert_eq!(
        reply.error_code(),
        Some(-32601),
        "a task request must be -32601"
    );
    assert!(
        upstream.requests().is_empty(),
        "a task request must not be forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_without_an_id_is_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let body = call_body("echo").replace(r#""id":1,"#, "");
    let reply = send(&client, body, &call_headers(&plain_or_base64("echo"))).await;
    assert_refused(&reply, 400, -32600, "a tools/call without an id");
    assert!(
        upstream.requests().is_empty(),
        "a tools/call without an id must not be forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_response_is_refused() {
    let w = World::start().await;
    let (upstream, tokens) = bob_with_deny(&w).await;
    let forged = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let stateless = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let reply = send(
        &stateless,
        forged,
        &[header("MCP-Protocol-Version", STATELESS)],
    )
    .await;
    assert_refused(
        &reply,
        400,
        -32600,
        "a forged response under the stateless rules",
    );
    assert!(
        upstream.requests().is_empty(),
        "a forged response must not be forwarded"
    );

    let no_session = w.session_mcp("demo", &tokens);
    let reply = send(&no_session, forged, &[]).await;
    assert_refused(&reply, 400, -32600, "a forged response without a session");
    assert!(
        upstream.requests().is_empty(),
        "a forged response without a session must not be forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_and_missing_tools_look_alike() {
    let w = World::start().await;
    let (_upstream, tokens) = bob_with_deny(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    for name in ["delete_db", "nope"] {
        let reply = send(
            &client,
            call_body(name),
            &call_headers(&plain_or_base64(name)),
        )
        .await;
        assert_eq!(
            reply.status, 200,
            "{name}: a refused tool answers as a JSON-RPC error"
        );
        assert_eq!(reply.error_code(), Some(-32602), "{name}: must be -32602");
        assert_eq!(
            reply.error_message(),
            Some(format!("Unknown tool: {name}")),
            "{name}: the message must read Unknown tool followed by the name"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tool_names_do_not_make_the_gateway_refetch_the_list() {
    let w = World::start().await;
    let bob = w.user("bob@example.com").await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    for n in 0..10 {
        let name = format!("unknown-{n}");
        let reply = client.call_tool(&name, json!({})).await;
        assert_eq!(
            reply.error_code(),
            Some(-32602),
            "{name} must be refused as an unknown tool"
        );
    }
    let burst = upstream.rpc_count("tools/list");
    assert!(
        burst <= 1,
        "ten calls with unknown names must refresh the list at most once, the upstream saw {burst} tools/list requests"
    );

    w.gw.clock.advance(time::Duration::seconds(31));
    let reply = client.call_tool("unknown-later", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a name after 31 seconds must be refused as an unknown tool"
    );
    assert_eq!(
        upstream.rpc_count("tools/list"),
        burst + 1,
        "a miss 31 seconds after the last refresh must refresh the list once more"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_denied_for_all_tools_needs_no_upstream() {
    let w = World::start().await;
    let bob = w.user("bob@example.com").await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "server",
        Some(id.as_str()),
        None,
    )
    .await;
    assert_eq!(
        page.status, 303,
        "the deny rule for all of demo must be stored"
    );
    upstream.clear();
    let reply = w
        .stateless_mcp("demo", &tokens)
        .call_tool("nope", json!({}))
        .await;
    assert_eq!(
        reply.status, 200,
        "a refused call answers as a JSON-RPC error"
    );
    assert_eq!(
        reply.error_message(),
        Some("Unknown tool: nope".to_string()),
        "a call denied for every tool must be refused as an unknown tool"
    );
    assert!(
        upstream.requests().is_empty(),
        "a call denied for every tool must not reach the upstream, it recorded {:?}",
        upstream
            .requests()
            .iter()
            .map(|request| request.rpc_method.clone())
            .collect::<Vec<_>>()
    );
}
