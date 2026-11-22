mod common;

use common::admin;
use common::client::TestClient;
use common::headers::{
    add_server_named, declare_header, header_id, session_call, set_switches, stateless_call,
};
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Generation, Mode, UpstreamOptions};
use common::values::{CANARY, live_db, store_value};
use common::world::{SECRET_HEADER, World, secret_for};
use serde_json::json;

const BOB: &str = "bob@example.com";
const SLUG: &str = "demo";
const HEADER: &str = "X-Trace-Id";
const LOWER: &str = "x-trace-id";

async fn declare_ok(owner: &TestClient, id: &str, required: bool) {
    let page = declare_header(owner, id, HEADER, required).await;
    assert_eq!(page.status, 303, "declaring the header must be accepted");
}

async fn switches_ok(owner: &TestClient, id: &str, pass: bool, store: bool) {
    let page = set_switches(owner, id, pass, store).await;
    assert_eq!(page.status, 303, "saving the switches must be accepted");
}

/// Bob on the demo server with a required header, the store switch on and nothing stored.
async fn bob_without_a_value(w: &World) -> (FakeUpstream, String, String, TestClient) {
    let (upstream, id) = w.upstream(SLUG, UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    declare_ok(&w.owner, &id, true).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = header_id(&w.owner, &id, HEADER).await.expect("header id");
    upstream.clear();
    (upstream, id, hid, bob)
}

fn instructions(reply: &McpReply) -> String {
    reply
        .result()
        .and_then(|result| result.get("instructions"))
        .and_then(|text| text.as_str())
        .unwrap_or_default()
        .to_owned()
}

fn is_tool_error(reply: &McpReply) -> bool {
    reply.status == 200 && reply.result().and_then(|r| r.get("isError")) == Some(&json!(true))
}

/// The (decision, outcome, detail) of every tool_call row, oldest first.
fn tool_rows(w: &World) -> Vec<(String, String, String)> {
    let live = live_db(w);
    let mut statement = live
        .prepare(
            "SELECT decision, outcome, detail FROM activity WHERE kind = 'tool_call' ORDER BY id",
        )
        .expect("prepares");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("runs")
        .map(|row| row.expect("row"))
        .collect()
}

async fn open(w: &World, bob: &TestClient, slug: &str) -> McpClient {
    let tokens = w.token(bob, slug).await;
    let client = w.session_mcp(slug, &tokens);
    let reply = client.initialize().await;
    assert_eq!(reply.status, 200, "initialize on {slug} must be answered");
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_with_a_missing_required_value_opens_a_connection_on_the_server_path() {
    let w = World::start().await;
    let (upstream, _id, _hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    let client = w.session_mcp(SLUG, &tokens);
    let reply = client.initialize().await;
    assert_eq!(reply.status, 200);
    let session = reply.header("mcp-session-id").unwrap_or_default();
    assert!(session.starts_with("dw-wait-"), "got {session:?}");
    assert_eq!(session.len(), "dw-wait-".len() + 32);
    assert!(instructions(&reply).contains(&format!("{}/account", w.base())));
    assert_eq!(reply.header("cache-control").as_deref(), Some("no-store"));
    assert!(upstream.requests().is_empty(), "the upstream sees nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tool_list_of_a_withheld_caller_is_the_stored_catalog_under_that_callers_rules() {
    let w = World::start().await;
    let (upstream, id, _hid, bob) = bob_without_a_value(&w).await;
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(id.as_str()),
        Some("delete_db"),
    )
    .await;
    assert_eq!(page.status, 303);
    let client = open(&w, &bob, SLUG).await;
    let listed = client.list_tools().await;
    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.tool_names(),
        vec!["echo".to_string(), "search".to_string()]
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_of_a_withheld_caller_is_a_tool_error_with_one_deny_row() {
    let w = World::start().await;
    let (upstream, id, _hid, bob) = bob_without_a_value(&w).await;
    admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(id.as_str()),
        Some("delete_db"),
    )
    .await;
    let client = open(&w, &bob, SLUG).await;
    let reply = client.call_tool("echo", json!({})).await;
    assert!(is_tool_error(&reply), "got {:?}", reply.body);
    assert!(
        reply
            .text()
            .unwrap_or_default()
            .contains("needs your credentials")
    );
    let rows = tool_rows(&w);
    assert_eq!(
        rows,
        vec![(
            "deny".into(),
            "refused".into(),
            "credentials missing".into()
        )]
    );
    let denied = client.call_tool("delete_db", json!({})).await;
    assert_eq!(
        denied.error_code(),
        Some(-32602),
        "a rule-denied tool is an unknown tool"
    );
    let unknown = client.call_tool("nothing_here", json!({})).await;
    assert_eq!(unknown.error_code(), Some(-32602));
    let rows = tool_rows(&w);
    assert_eq!(rows.len(), 3);
    assert!(rows[1].2.starts_with("rule"), "got {:?}", rows[1]);
    assert_eq!(rows[2].2, "not in the tool list");
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locked_connection_gets_reconnect_this_app_the_same_way() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let stored = store_value(&bob, SLUG, &hid, CANARY).await;
    assert_eq!(stored.status, 303);
    let tokens = w.token(&bob, SLUG).await;
    live_db(&w)
        .execute(
            "UPDATE access_tokens SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
            [],
        )
        .expect("damage");
    let client = w.session_mcp(SLUG, &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200);
    assert!(instructions(&init).contains("Reconnect this app to use"));
    let reply = client.call_tool("echo", json!({})).await;
    assert!(is_tool_error(&reply));
    assert!(
        reply
            .text()
            .unwrap_or_default()
            .contains("Reconnect this app to use")
    );
    assert_eq!(
        tool_rows(&w).last().map(|row| row.2.clone()).as_deref(),
        Some("reconnect needed")
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_that_cannot_be_opened_gets_the_store_again_text_the_same_way() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = bob_without_a_value(&w).await;
    store_value(&bob, SLUG, &hid, CANARY).await;
    let moved = FakeUpstream::start(UpstreamOptions {
        require_header: Some((SECRET_HEADER.into(), secret_for(SLUG))),
        ..Default::default()
    })
    .await;
    live_db(&w)
        .execute(
            "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
            rusqlite::params![moved.url(), id.parse::<i64>().expect("id")],
        )
        .expect("move");
    let client = open(&w, &bob, SLUG).await;
    let reply = client.call_tool("echo", json!({})).await;
    assert!(is_tool_error(&reply));
    assert!(
        reply
            .text()
            .unwrap_or_default()
            .contains("cannot be opened. Store them again at")
    );
    assert_eq!(
        tool_rows(&w).last().map(|row| row.2.clone()).as_deref(),
        Some("credentials missing")
    );
    assert!(upstream.requests().is_empty());
    assert!(moved.requests().is_empty());
}

const WAIT_ID: &str = "dw-wait-0123456789abcdef0123456789abcdef";

/// The values the upstream received for `tool`, one entry per call.
fn carried(upstream: &FakeUpstream, tool: &str) -> Vec<Option<String>> {
    upstream
        .requests()
        .iter()
        .filter(|request| request.tool.as_deref() == Some(tool))
        .map(|request| request.header(LOWER).map(str::to_string))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn after_the_value_is_stored_the_same_placeholder_session_is_served_with_the_value() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = bob_without_a_value(&w).await;
    admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(id.as_str()),
        Some("delete_db"),
    )
    .await;
    let tokens = w.token(&bob, SLUG).await;
    let waiting = w.session_mcp(SLUG, &tokens);
    assert_eq!(waiting.initialize().await.status, 200);
    let stored = store_value(&bob, SLUG, &hid, CANARY).await;
    assert_eq!(stored.status, 303);
    upstream.clear();

    let reply = session_call(&waiting, "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(carried(&upstream, "echo"), vec![Some(CANARY.to_string())]);
    let listed = waiting.list_tools().await;
    assert_eq!(
        listed.tool_names(),
        vec!["echo".to_string(), "search".to_string()]
    );
    let denied = waiting.call_tool("delete_db", json!({})).await;
    assert_eq!(
        denied.error_code(),
        Some(-32602),
        "a rule-denied tool is unknown"
    );
    let rows = tool_rows(&w);
    assert!(
        rows.contains(&("allow".into(), "ok".into(), String::new())),
        "a normal allow/ok row, got {rows:?}"
    );
    assert_eq!(waiting.request("ping", json!({})).await.status, 200);
    let other = waiting.request("resources/list", json!({})).await;
    assert_eq!(other.error_code(), Some(-32601));
    assert_eq!(
        waiting.initialize().await.status,
        200,
        "a client may repeat initialize"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_initialize_after_the_value_is_stored_reaches_the_upstream_as_a_normal_session() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    store_value(&bob, SLUG, &hid, CANARY).await;
    let fresh = w.session_mcp(SLUG, &tokens);
    assert_eq!(fresh.initialize().await.status, 200);
    assert!(upstream.rpc_count("initialize") >= 1);
    assert!(
        !fresh
            .session_id()
            .unwrap_or_default()
            .starts_with("dw-wait-")
    );
    let reply = session_call(&fresh, "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(carried(&upstream, "echo"), vec![Some(CANARY.to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invented_placeholder_id_and_a_placeholder_id_of_an_unassigned_caller_are_not_served() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    store_value(&bob, SLUG, &hid, CANARY).await;
    upstream.clear();
    for invented in [
        "dw-wait-short",
        "dw-wait-0123456789abcdef0123456789abcdef0",
        "dw-wait-0123456789ABCDEF0123456789ABCDEF",
        "dw-wait-0123456789abcdef0123456789abcdeg",
    ] {
        let client = w.session_mcp(SLUG, &tokens);
        client.set_session_id(Some(invented));
        assert_eq!(
            session_call(&client, "echo", &[]).await.status,
            404,
            "{invented}"
        );
    }
    assert!(upstream.requests().is_empty());

    let user = w.user_id(BOB).await;
    let page = admin::assign(&w.owner, &user, &[]).await;
    assert_eq!(page.status, 303);
    let plain = {
        let client = w.session_mcp(SLUG, &tokens);
        session_call(&client, "echo", &[]).await.status
    };
    let client = w.session_mcp(SLUG, &tokens);
    client.set_session_id(Some(WAIT_ID));
    let waiting = session_call(&client, "echo", &[]).await;
    assert_eq!(waiting.status, plain, "the unassigned answer is unchanged");
    assert!(waiting.text().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_session_whose_value_is_removed_again_is_answered_by_the_withheld_handshake()
{
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    let waiting = w.session_mcp(SLUG, &tokens);
    assert_eq!(waiting.initialize().await.status, 200);
    store_value(&bob, SLUG, &hid, CANARY).await;
    assert_eq!(
        session_call(&waiting, "echo", &[]).await.text().as_deref(),
        Some("called: echo")
    );
    let removed = common::values::remove_value(&bob, SLUG, &hid).await;
    assert_eq!(removed.status, 303);
    upstream.clear();
    let reply = session_call(&waiting, "echo", &[]).await;
    assert!(is_tool_error(&reply));
    assert!(
        reply
            .text()
            .unwrap_or_default()
            .contains("needs your credentials")
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stateless_generation_ignores_a_placeholder_session_id() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    store_value(&bob, SLUG, &hid, CANARY).await;
    let stateless = w.stateless_mcp(SLUG, &tokens);
    let wait = stateless_call(&stateless, "echo", &[("Mcp-Session-Id", WAIT_ID)]).await;
    let other = stateless_call(&stateless, "echo", &[("Mcp-Session-Id", "other-id-123")]).await;
    assert_eq!(
        (wait.status, wait.text()),
        (other.status, other.text()),
        "the stateless generation treats a placeholder id like any other id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_is_405_and_delete_is_204_on_a_placeholder_session_of_a_caller_who_is_not_withheld() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    let waiting = w.session_mcp(SLUG, &tokens);
    assert_eq!(waiting.initialize().await.status, 200);
    store_value(&bob, SLUG, &hid, CANARY).await;
    upstream.clear();
    assert_eq!(waiting.get().await.status, 405);
    assert_eq!(waiting.delete().await.status, 204);
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn with_pass_through_only_the_text_names_the_header() {
    let w = World::start().await;
    let (upstream, id) = add_server_named(&w.owner, "Demo Server", SLUG, true).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    declare_ok(&w.owner, &id, true).await;
    switches_ok(&w.owner, &id, true, false).await;
    let client = open(&w, &bob, SLUG).await;
    let reply = client.call_tool("echo", json!({})).await;
    assert!(is_tool_error(&reply));
    let text = reply.text().unwrap_or_default();
    assert!(
        text.contains("Demo Server needs the header") && text.contains(HEADER),
        "got {text:?}"
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_stateless_caller_gets_method_not_found_for_discover_and_the_usual_list_and_call()
 {
    let w = World::start().await;
    let (upstream, _id, _hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    let stateless = w.stateless_mcp(SLUG, &tokens);
    let discovered = stateless.discover().await;
    assert_eq!(discovered.status, 200);
    assert_eq!(discovered.error_code(), Some(-32601));
    assert_eq!(
        discovered.header("cache-control").as_deref(),
        Some("no-store")
    );
    let listed = stateless.list_tools().await;
    assert_eq!(listed.status, 200);
    assert_eq!(listed.tool_names().len(), 3);
    let called = stateless_call(&stateless, "echo", &[]).await;
    assert!(is_tool_error(&called));
    assert_eq!(
        called.result().and_then(|r| r.get("resultType")),
        Some(&json!("complete"))
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_is_405_and_delete_is_204_for_a_withheld_caller() {
    let w = World::start().await;
    let (upstream, _id, _hid, bob) = bob_without_a_value(&w).await;
    let client = open(&w, &bob, SLUG).await;
    assert_eq!(client.get().await.status, 405);
    assert_eq!(client.delete().await.status, 204);
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn on_the_combined_endpoint_the_withheld_servers_tools_are_listed_and_a_call_returns_the_text()
 {
    let w = World::start().await;
    let (a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let b_options = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let (b, b_id) = w.upstream("b", b_options).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&a_id, &b_id]).await;
    declare_ok(&w.owner, &a_id, true).await;
    switches_ok(&w.owner, &a_id, false, true).await;
    a.clear();
    b.clear();
    let client = open(&w, &bob, "mcp").await;
    let listed = client.list_tools().await;
    assert_eq!(
        listed.tool_names(),
        vec!["a__echo", "a__search", "a__delete_db", "b__alpha"]
    );
    let refused = session_call(&client, "a__echo", &[]).await;
    assert!(is_tool_error(&refused));
    assert!(
        refused
            .text()
            .unwrap_or_default()
            .contains("needs your credentials")
    );
    let served = session_call(&client, "b__alpha", &[]).await;
    assert_eq!(served.text().as_deref(), Some("called: alpha"));
    assert!(
        a.requests().is_empty(),
        "the withheld server is never contacted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_answer_to_a_withheld_caller_is_a_401_or_a_403() {
    let w = World::start().await;
    let (_upstream, _id, _hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    let session = w.session_mcp(SLUG, &tokens);
    let stateless = w.stateless_mcp(SLUG, &tokens);
    let combined = w.session_mcp("mcp", &w.token(&bob, "mcp").await);
    let replies = vec![
        session.initialize().await,
        session.list_tools().await,
        session.call_tool("echo", json!({})).await,
        session.call_tool("nothing_here", json!({})).await,
        session.request("resources/list", json!({})).await,
        session.get().await,
        session.delete().await,
        stateless.discover().await,
        stateless.list_tools().await,
        stateless_call(&stateless, "echo", &[]).await,
        combined.initialize().await,
        combined.list_tools().await,
        session_call(&combined, "demo__echo", &[]).await,
    ];
    for reply in replies {
        assert!(
            reply.status != 401 && reply.status != 403,
            "no answer may be 401 or 403, got {}",
            reply.status
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_probes_discover_first_is_steered_to_a_session_that_survives_the_store() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let tokens = w.token(&bob, SLUG).await;
    let discovers_before = upstream.rpc_count("server/discover");
    let probe = w.stateless_mcp(SLUG, &tokens);
    assert_eq!(probe.discover().await.error_code(), Some(-32601));
    let client = w.session_mcp(SLUG, &tokens);
    let init = client.initialize().await;
    assert!(
        init.header("mcp-session-id")
            .unwrap_or_default()
            .starts_with("dw-wait-")
    );
    let refused = client.call_tool("echo", json!({})).await;
    assert!(is_tool_error(&refused));
    assert!(
        refused
            .text()
            .unwrap_or_default()
            .contains("needs your credentials")
    );
    assert_eq!(upstream.rpc_count("server/discover"), discovers_before);

    let stored = store_value(&bob, SLUG, &hid, CANARY).await;
    assert_eq!(stored.status, 303);
    let reply = client.call_tool("echo", json!({})).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(carried(&upstream, "echo"), vec![Some(CANARY.to_string())]);
}

const CAROL: &str = "carol@example.com";

/// The (email, slug, tool, decision, outcome, detail) of every tool_call row, oldest first.
fn full_rows(w: &World) -> Vec<(String, String, String, String, String, String)> {
    let live = live_db(w);
    let mut statement = live
        .prepare(
            "SELECT user_email, server_slug, tool, decision, outcome, detail FROM activity \
             WHERE kind = 'tool_call' ORDER BY id",
        )
        .expect("prepares");
    statement
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .expect("runs")
        .map(|row| row.expect("row"))
        .collect()
}

async fn wait_for_rows(
    w: &World,
    count: usize,
) -> Vec<(String, String, String, String, String, String)> {
    for _ in 0..40 {
        let rows = full_rows(w);
        if rows.len() >= count {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    full_rows(w)
}

/// Bob on a server with the given options, the required header declared, store switch on, nothing stored.
async fn bob_on(w: &World, options: UpstreamOptions) -> (FakeUpstream, String, String, TestClient) {
    let (upstream, id) = w.upstream(SLUG, options).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    declare_ok(&w.owner, &id, true).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = header_id(&w.owner, &id, HEADER).await.expect("header id");
    upstream.clear();
    (upstream, id, hid, bob)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_only_upstream_is_steered_from_discover_to_a_session_that_survives_the_store() {
    let w = World::start().await;
    let options = UpstreamOptions {
        generation: Generation::Session,
        ..UpstreamOptions::default()
    };
    let (upstream, _id, hid, bob) = bob_on(&w, options).await;
    let tokens = w.token(&bob, SLUG).await;
    let probe = w.stateless_mcp(SLUG, &tokens);
    let discovered = probe.discover().await;
    assert_eq!(
        (discovered.status, discovered.error_code()),
        (200, Some(-32601))
    );
    let client = w.session_mcp(SLUG, &tokens);
    let init = client.initialize().await;
    assert!(
        init.header("mcp-session-id")
            .unwrap_or_default()
            .starts_with("dw-wait-")
    );
    assert!(is_tool_error(&client.call_tool("echo", json!({})).await));
    assert!(upstream.requests().is_empty());
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    let reply = client.call_tool("echo", json!({})).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(carried(&upstream, "echo"), vec![Some(CANARY.to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_call_on_a_placeholder_session_completes_and_loses_access_cleanly() {
    let w = World::start().await;
    let mode = Mode::Progress {
        steps: 2,
        interval_ms: 20,
    };
    let (_upstream, _id, hid, bob) = bob_on(
        &w,
        UpstreamOptions {
            mode,
            ..UpstreamOptions::default()
        },
    )
    .await;
    let client = open(&w, &bob, SLUG).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    let accept = [("Accept", "application/json, text/event-stream")];
    let reply = session_call(&client, "echo", &accept).await;
    assert_eq!(reply.status, 200);
    assert!(!reply.events.is_empty(), "the call is streamed");
    let rows = wait_for_rows(&w, 1).await;
    let last = rows.last().expect("a row");
    assert_eq!(
        (last.3.as_str(), last.4.as_str()),
        ("allow", "ok"),
        "{last:?}"
    );

    let mode = Mode::Progress {
        steps: 30,
        interval_ms: 100,
    };
    _upstream.set_mode(mode);
    let user = w.user_id(BOB).await;
    let call = session_call(&client, "echo", &accept);
    let unassign = async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        admin::assign(&w.owner, &user, &[]).await
    };
    let (_reply, page) = tokio::join!(call, unassign);
    assert_eq!(page.status, 303);
    let rows = wait_for_rows(&w, 2).await;
    let last = rows.last().expect("a row");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        (last.3.as_str(), last.4.as_str()),
        ("allow", "refused"),
        "{last:?}"
    );
    assert!(last.5.contains("access was lost"), "{last:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_users_sending_the_same_placeholder_id_each_get_their_own_value_and_row() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = bob_without_a_value(&w).await;
    let carol = w.user(CAROL).await;
    w.grant(CAROL, &[&id]).await;
    let waiting = open(&w, &bob, SLUG).await;
    let shared = waiting.session_id().expect("the placeholder id");
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    assert_eq!(
        store_value(&carol, SLUG, &hid, "carol-value").await.status,
        303
    );
    let carols = w.session_mcp(SLUG, &w.token(&carol, SLUG).await);
    carols.set_session_id(Some(&shared));
    upstream.clear();
    assert_eq!(
        waiting.call_tool("echo", json!({})).await.text().as_deref(),
        Some("called: echo")
    );
    assert_eq!(
        carols.call_tool("echo", json!({})).await.text().as_deref(),
        Some("called: echo")
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string()), Some("carol-value".to_string())]
    );
    let rows = wait_for_rows(&w, 2).await;
    let emails: Vec<_> = rows
        .iter()
        .map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_str()))
        .collect();
    assert_eq!(
        emails,
        vec![(BOB, SLUG, "echo"), (CAROL, SLUG, "echo")],
        "{rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_for_another_server_with_a_placeholder_id_is_a_401() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = bob_without_a_value(&w).await;
    let (_other, other_id) = w.upstream("other", UpstreamOptions::default()).await;
    w.grant(BOB, &[&id, &other_id]).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    let tokens = w.token(&bob, SLUG).await;
    let wrong = w.session_mcp("other", &tokens);
    wrong.set_session_id(Some(WAIT_ID));
    assert_eq!(session_call(&wrong, "echo", &[]).await.status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invented_placeholder_id_from_a_caller_who_resolves_is_served_and_records_no_session() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    let client = w.session_mcp(SLUG, &w.token(&bob, SLUG).await);
    client.set_session_id(Some(WAIT_ID));
    let reply = client.call_tool("echo", json!({})).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    let live = live_db(&w);
    let count: i64 = live
        .query_row("SELECT COUNT(*) FROM upstream_sessions", [], |r| r.get(0))
        .expect("counts");
    assert_eq!(count, 0);
    for request in upstream.requests() {
        assert!(
            !request
                .header_all("mcp-session-id")
                .iter()
                .any(|v| v.starts_with("dw-wait-")),
            "no upstream request carries a placeholder id"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_caller_with_an_unrecorded_plain_id_gets_the_gateway_made_answer() {
    let w = World::start().await;
    let (upstream, _id, _hid, bob) = bob_without_a_value(&w).await;
    let client = w.session_mcp(SLUG, &w.token(&bob, SLUG).await);
    client.set_session_id(Some("some-unrecorded-session"));
    let reply = client.call_tool("echo", json!({})).await;
    assert!(is_tool_error(&reply), "got {:?}", reply.body);
    assert!(
        reply
            .text()
            .unwrap_or_default()
            .contains("needs your credentials")
    );
    assert!(upstream.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_upstream_request_carries_a_placeholder_session_id() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let client = open(&w, &bob, SLUG).await;
    client.list_tools().await;
    client.call_tool("echo", json!({})).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    client.list_tools().await;
    client.call_tool("echo", json!({})).await;
    client.notify("notifications/initialized", json!({})).await;
    assert!(!upstream.requests().is_empty());
    for request in upstream.requests() {
        assert!(
            !request
                .header_all("mcp-session-id")
                .iter()
                .any(|v| v.starts_with("dw-wait-"))
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_tool_list_with_an_empty_stored_catalog_answers_no_tools() {
    let w = World::start().await;
    let (_upstream, _id, _hid, bob) = bob_without_a_value(&w).await;
    live_db(&w)
        .execute("DELETE FROM tool_catalog", [])
        .expect("empties");
    let client = open(&w, &bob, SLUG).await;
    let listed = client.list_tools().await;
    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.result().and_then(|r| r.get("tools")),
        Some(&json!([]))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_list_with_the_upstream_down_names_the_server() {
    let w = World::start().await;
    let (mut upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let client = open(&w, &bob, SLUG).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    upstream.shutdown().await;
    let listed = client.list_tools().await;
    assert_eq!(listed.status, 502);
    assert!(
        listed.error_message().unwrap_or_default().contains(SLUG),
        "got {:?}",
        listed.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_list_is_rechecked_after_the_fetch() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let client = open(&w, &bob, SLUG).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    upstream.set_mode(Mode::SlowListing { millis: 600 });
    let user = w.user_id(BOB).await;
    let list = client.list_tools();
    let unassign = async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        admin::assign(&w.owner, &user, &[]).await
    };
    let (listed, page) = tokio::join!(list, unassign);
    assert_eq!(page.status, 303);
    assert!(listed.tool_names().is_empty(), "got {:?}", listed.body);
    assert_ne!(listed.status, 200, "got {:?}", listed.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_call_on_a_placeholder_session_is_answered_as_on_a_recorded_session() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = bob_without_a_value(&w).await;
    let waiting = open(&w, &bob, SLUG).await;
    assert_eq!(store_value(&bob, SLUG, &hid, CANARY).await.status, 303);
    let recorded = open(&w, &bob, SLUG).await;
    let body = json!({"name": "echo", "arguments": {}, "task": {"ttl": 1000}});
    let on_recorded = recorded.request("tools/call", body.clone()).await;
    let on_placeholder = waiting.request("tools/call", body).await;
    assert_eq!(
        on_recorded.error_code(),
        Some(-32601),
        "got {:?}",
        on_recorded.body
    );
    assert_eq!(on_placeholder.status, on_recorded.status);
    assert_eq!(on_placeholder.error_code(), on_recorded.error_code());
    assert_eq!(upstream.calls_to("echo"), 0);
}
