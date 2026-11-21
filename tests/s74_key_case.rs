mod common;

use common::admin::{self, ActivityRow};
use common::client::TestClient;
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Recorded, UpstreamOptions};
use common::world::World;
use serde_json::{Value, json};

const BOB: &str = "bob@example.com";
const SESSION: &str = "2025-11-25";
const STATELESS: &str = "2026-07-28";
const META: &str = r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;
const ODD_ARGUMENTS: &str = r#"{"Name":"x","näme":"y","ProgressToken":1,"Arguments":{"ß":2}}"#;
const INVALID: &str = "Invalid request";

/// Where the bodies go: the client, the body style, the Mcp-Session-Id the client holds (if any),
/// the tool names that route uses, and whether the gateway forwards the client's bytes unchanged.
struct Route<'a> {
    name: &'static str,
    client: &'a McpClient,
    stateless: bool,
    session: Option<String>,
    echo: &'static str,
    search: &'static str,
    verbatim: bool,
}

/// Bob, assigned to server `demo`, whose tool `search` is denied for everyone.
async fn deny_search(w: &World) -> (TestClient, FakeUpstream) {
    let bob = w.user(BOB).await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(id.as_str()),
        Some("search"),
    )
    .await;
    assert_eq!(page.status, 303, "the deny rule for search must be stored");
    (bob, upstream)
}

/// Starts a session on `client` and returns the Mcp-Session-Id it was given, if any.
async fn initialized_session(client: &McpClient) -> Option<String> {
    let reply = client.initialize().await;
    assert_eq!(reply.status, 200, "initialize must be relayed");
    client.session_id()
}

/// The stateless `_meta` member of a body, or nothing on a session.
fn meta_member(route: &Route<'_>) -> String {
    if route.stateless {
        format!(r#","_meta":{META}"#)
    } else {
        String::new()
    }
}

/// The three trick bodies: A and B on both styles, and C (a response) on a session only.
/// The names are the route's own: `echo` is judged, `search` is the denied tool.
fn bodies(route: &Route<'_>) -> Vec<(&'static str, String)> {
    let meta = meta_member(route);
    let (echo, search) = (route.echo, route.search);
    let a = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"{echo}","Name":"{search}","arguments":{{}}{meta}}}}}"#
    );
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/list","Method":"tools/call","params":{{"Name":"{search}"{meta}}}}}"#
    );
    let mut all = vec![("A", a), ("B", b)];
    if !route.stateless {
        let c = format!(
            r#"{{"jsonrpc":"2.0","id":5,"Method":"tools/call","Params":{{"name":"{search}"}},"result":{{}}}}"#
        );
        all.push(("C", c));
    }
    all
}

/// The headers a body of `route` needs to be well formed; stateless body A names `echo`.
fn headers(route: &Route<'_>, label: &str) -> Vec<(&'static str, String)> {
    if !route.stateless {
        let mut all = vec![("MCP-Protocol-Version", SESSION.to_string())];
        if let Some(session) = &route.session {
            all.push(("Mcp-Session-Id", session.clone()));
        }
        return all;
    }
    let method = if label == "B" {
        "tools/list"
    } else {
        "tools/call"
    };
    let mut all = vec![
        ("MCP-Protocol-Version", STATELESS.to_string()),
        ("Mcp-Method", method.to_string()),
    ];
    if label == "A" {
        all.push(("Mcp-Name", route.echo.to_string()));
    }
    all
}

/// POSTs `body` with the headers of `label` and returns the reply.
async fn post(route: &Route<'_>, label: &str, body: &str) -> McpReply {
    let headers = headers(route, label);
    let pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    route.client.raw(body.as_bytes(), &pairs).await
}

fn assert_refused(reply: &McpReply, case: &str) {
    assert_eq!(
        reply.status, 400,
        "{case}: HTTP status, body {}",
        reply.body
    );
    assert_eq!(
        reply.error_code(),
        Some(-32600),
        "{case}: JSON-RPC error code, body {}",
        reply.body
    );
    assert_eq!(
        reply.error_message().as_deref(),
        Some(INVALID),
        "{case}: JSON-RPC error message, body {}",
        reply.body
    );
}

/// The activity rows that say `echo` or `search` was allowed.
fn allowed_trick_rows(rows: &[ActivityRow]) -> usize {
    rows.iter()
        .filter(|row| {
            row.decision == "allow" && (row.tool.ends_with("echo") || row.tool.ends_with("search"))
        })
        .count()
}

/// Each trick body is refused with 400 and -32600, reaches no upstream, and writes no allowed row.
async fn refuse_every_body(w: &World, upstream: &FakeUpstream, route: &Route<'_>) {
    for (label, body) in bodies(route) {
        let case = format!("{} body {label}", route.name);
        let before = admin::activity(&w.owner, None, None).await;
        upstream.clear();
        let reply = post(route, label, &body).await;
        assert_refused(&reply, &case);
        assert!(
            upstream.requests().is_empty(),
            "{case}: the upstream must not see the body"
        );
        let after = admin::activity(&w.owner, None, None).await;
        assert_eq!(
            allowed_trick_rows(&after),
            allowed_trick_rows(&before),
            "{case}: the activity log must gain no allowed row for echo or search"
        );
    }
}

/// The allowed tool still answers after the refused bodies.
async fn assert_ordinary_call(upstream: &FakeUpstream, route: &Route<'_>) {
    upstream.clear();
    let reply = route.client.call_tool(route.echo, json!({})).await;
    assert_eq!(
        reply.status, 200,
        "{}: the allowed call must succeed, body {}",
        route.name, reply.body
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "{}: the allowed call must reach echo",
        route.name
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        1,
        "{}: the allowed call must reach the upstream once",
        route.name
    );
}

/// A call whose arguments have mixed-case and non-ASCII names reaches the upstream unchanged.
async fn forwards_odd_arguments(upstream: &FakeUpstream, route: &Route<'_>) {
    let case = format!("{} odd arguments", route.name);
    let meta = meta_member(route);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{}","arguments":{ODD_ARGUMENTS}{meta}}}}}"#,
        route.echo
    );
    upstream.clear();
    let reply = post(route, "A", &body).await;
    assert_eq!(
        reply.status, 200,
        "{case}: the call must succeed, body {}",
        reply.body
    );
    let calls: Vec<Recorded> = upstream
        .requests()
        .into_iter()
        .filter(|request| request.rpc_method.as_deref() == Some("tools/call"))
        .collect();
    assert_eq!(calls.len(), 1, "{case}: the upstream gets one call");
    if route.verbatim {
        assert_eq!(
            calls[0].body,
            body.as_bytes(),
            "{case}: the bytes must be forwarded unchanged"
        );
    } else {
        let sent: Value = serde_json::from_slice(&calls[0].body).expect("the upstream got JSON");
        assert_eq!(
            sent["params"]["arguments"],
            serde_json::from_str::<Value>(ODD_ARGUMENTS).expect("the arguments are JSON"),
            "{case}: the arguments must reach the upstream unchanged"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn per_server_session_refuses_each_trick_body() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.session_mcp("demo", &tokens);
    let session = initialized_session(&client).await;
    let route = Route {
        name: "per-server session",
        client: &client,
        stateless: false,
        session,
        echo: "echo",
        search: "search",
        verbatim: true,
    };
    refuse_every_body(&w, &upstream, &route).await;
    assert_ordinary_call(&upstream, &route).await;
    forwards_odd_arguments(&upstream, &route).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn per_server_stateless_refuses_each_trick_body() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.stateless_mcp("demo", &tokens);
    let route = Route {
        name: "per-server stateless",
        client: &client,
        stateless: true,
        session: None,
        echo: "echo",
        search: "search",
        verbatim: true,
    };
    refuse_every_body(&w, &upstream, &route).await;
    assert_ordinary_call(&upstream, &route).await;
    forwards_odd_arguments(&upstream, &route).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_session_refuses_each_trick_body() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = w.session_mcp("mcp", &tokens);
    let session = initialized_session(&client).await;
    let route = Route {
        name: "combined session",
        client: &client,
        stateless: false,
        session,
        echo: "demo__echo",
        search: "demo__search",
        verbatim: false,
    };
    refuse_every_body(&w, &upstream, &route).await;
    assert_ordinary_call(&upstream, &route).await;
    forwards_odd_arguments(&upstream, &route).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_stateless_refuses_each_trick_body() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = w.stateless_mcp("mcp", &tokens);
    let route = Route {
        name: "combined stateless",
        client: &client,
        stateless: true,
        session: None,
        echo: "demo__echo",
        search: "demo__search",
        verbatim: false,
    };
    refuse_every_body(&w, &upstream, &route).await;
    assert_ordinary_call(&upstream, &route).await;
    forwards_odd_arguments(&upstream, &route).await;
}

/// Refuses `body` as the file's other bodies: 400 with `-32600`, no upstream call, no activity row.
async fn refuse_one_body(
    w: &World,
    upstream: &FakeUpstream,
    route: &Route<'_>,
    case: &str,
    body: &str,
) {
    let before = admin::activity(&w.owner, None, None).await;
    upstream.clear();
    let reply = post(route, "A", body).await;
    assert_refused(&reply, case);
    assert!(
        upstream.requests().is_empty(),
        "{case}: the upstream must not see the body"
    );
    let after = admin::activity(&w.owner, None, None).await;
    assert_eq!(
        after.len(),
        before.len(),
        "{case}: the activity log must gain no row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_control_character_in_a_name_is_refused_on_both_session_routes() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let demo_tokens = w.token(&bob, "demo").await;
    let demo = w.session_mcp("demo", &demo_tokens);
    let demo_session = initialized_session(&demo).await;
    let mcp_tokens = w.token(&bob, "mcp").await;
    let mcp = w.session_mcp("mcp", &mcp_tokens);
    let mcp_session = initialized_session(&mcp).await;
    let routes = [
        Route {
            name: "per-server session",
            client: &demo,
            stateless: false,
            session: demo_session,
            echo: "echo",
            search: "search",
            verbatim: true,
        },
        Route {
            name: "combined session",
            client: &mcp,
            stateless: false,
            session: mcp_session,
            echo: "demo__echo",
            search: "demo__search",
            verbatim: false,
        },
    ];
    for route in &routes {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"{}","name\u0000":"{}","arguments":{{}}}}}}"#,
            route.echo, route.search
        );
        refuse_one_body(&w, &upstream, route, route.name, &body).await;
        assert_ordinary_call(&upstream, route).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_ascii_name_under_meta_is_refused_on_the_per_server_route() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.session_mcp("demo", &tokens);
    let session = initialized_session(&client).await;
    let route = Route {
        name: "per-server session",
        client: &client,
        stateless: false,
        session,
        echo: "echo",
        search: "search",
        verbatim: true,
    };
    let body = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"progressToken":1,"ü":2}}}"#;
    refuse_one_body(&w, &upstream, &route, "non-ASCII name under _meta", body).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_case_variant_decision_key_under_ref_is_refused_on_the_per_server_route() {
    let w = World::start().await;
    let (bob, upstream) = deny_search(&w).await;
    let tokens = w.token(&bob, "demo").await;
    let client = w.session_mcp("demo", &tokens);
    let session = initialized_session(&client).await;
    let route = Route {
        name: "per-server session",
        client: &client,
        stateless: false,
        session,
        echo: "echo",
        search: "search",
        verbatim: true,
    };
    let body = r#"{"jsonrpc":"2.0","id":3,"method":"completion/complete","params":{"ref":{"Type":"ref/prompt","name":"x"},"argument":{"name":"a","value":"b"}}}"#;
    refuse_one_body(
        &w,
        &upstream,
        &route,
        "case variant of type under ref",
        body,
    )
    .await;
}
