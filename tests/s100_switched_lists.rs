mod common;

use common::admin;
use common::client::TestClient;
use common::mcp::{McpClient, McpReply};
use common::switches::{deny_tool, post_switches, stored_definitions, switched_off};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::World;
use serde_json::{Value, json};

const BOB: &str = "bob@example.com";
const SWITCHED: &str = "switched off";

/// Server `s` (echo, search, delete_db) with bob assigned to it.
struct Scene {
    w: World,
    up: FakeUpstream,
    id: String,
    bob: TestClient,
    bob_id: String,
}

async fn start() -> Scene {
    let w = World::start().await;
    let (up, id) = w.upstream("s", UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[id.as_str()]).await;
    let bob_id = w.user_id(BOB).await;
    Scene {
        w,
        up,
        id,
        bob,
        bob_id,
    }
}

/// Switches delete_db off for bob on server `s`, and asserts the save was accepted.
async fn switch_delete_db_off(sc: &Scene) {
    let page = post_switches(&sc.bob, "s", "chosen", &["echo", "search"]).await;
    assert_eq!(
        page.status, 303,
        "the save that switches delete_db off must be accepted"
    );
}

/// The refusal text of a call to a switched-off tool, under the name the client sent.
fn switched_off_text(name: &str) -> String {
    format!(
        "Tool {name} is switched off in your Doorward account. Switch it on under Your tools, then reconnect."
    )
}

/// The tool names of a tool list answer, which must be a 200.
fn names(reply: &McpReply) -> Vec<String> {
    assert_eq!(reply.status, 200, "the tool list must answer 200");
    reply.tool_names()
}

/// A session client on `slug` for `browser`, initialized.
async fn session(w: &World, browser: &TestClient, slug: &str) -> McpClient {
    let tokens = w.token(browser, slug).await;
    let client = w.session_mcp(slug, &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize on /{slug} must answer 200");
    client
}

/// The tool names `browser` sees on `slug` through a fresh session, or a stateless client.
async fn listed(w: &World, browser: &TestClient, slug: &str, stateless: bool) -> Vec<String> {
    let tokens = w.token(browser, slug).await;
    if stateless {
        return names(&w.stateless_mcp(slug, &tokens).list_tools().await);
    }
    let client = w.session_mcp(slug, &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize on /{slug} must answer 200");
    names(&client.list_tools().await)
}

/// The bytes the combined list counts for a server: each stored tool with its merged name, as JSON.
fn merged_bytes(slug: &str, definitions: &[(String, String)]) -> usize {
    definitions
        .iter()
        .map(|(name, definition)| {
            let mut tool: Value =
                serde_json::from_str(definition).expect("a stored definition is JSON");
            tool["name"] = json!(format!("{slug}__{name}"));
            tool.to_string().len()
        })
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_is_absent_from_the_server_path_list_in_the_session_generation() {
    let sc = start().await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "s", false).await,
        vec!["echo", "search", "delete_db"],
        "before the switch every tool is listed"
    );
    switch_delete_db_off(&sc).await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "s", false).await,
        vec!["echo", "search"],
        "a switched-off tool must be absent from the session list on /s"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_is_absent_from_the_server_path_list_in_the_stateless_generation() {
    let sc = start().await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "s", true).await,
        vec!["echo", "search", "delete_db"],
        "before the switch every tool is listed"
    );
    switch_delete_db_off(&sc).await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "s", true).await,
        vec!["echo", "search"],
        "a switched-off tool must be absent from the stateless list on /s"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_is_absent_from_the_combined_list_in_the_session_generation() {
    let sc = start().await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "mcp", false).await,
        vec!["s__echo", "s__search", "s__delete_db"],
        "before the switch every tool is listed under its merged name"
    );
    switch_delete_db_off(&sc).await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "mcp", false).await,
        vec!["s__echo", "s__search"],
        "a switched-off tool must be absent from the session list on /mcp"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_is_absent_from_the_combined_list_in_the_stateless_generation() {
    let sc = start().await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "mcp", true).await,
        vec!["s__echo", "s__search", "s__delete_db"],
        "before the switch every tool is listed under its merged name"
    );
    switch_delete_db_off(&sc).await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "mcp", true).await,
        vec!["s__echo", "s__search"],
        "a switched-off tool must be absent from the stateless list on /mcp"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_to_a_switched_off_tool_is_refused_on_the_server_path_without_reaching_the_upstream()
{
    let sc = start().await;
    switch_delete_db_off(&sc).await;
    let client = session(&sc.w, &sc.bob, "s").await;
    sc.up.clear();
    let refused = client.call_tool("delete_db", json!({})).await;
    assert_eq!(
        refused.status, 200,
        "a refused call is a JSON-RPC answer on HTTP 200"
    );
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "the refusal must be -32602"
    );
    assert_eq!(
        refused.error_message(),
        Some(switched_off_text("delete_db")),
        "the refusal must say the tool is switched off"
    );
    assert_eq!(
        sc.up.calls_to("delete_db"),
        0,
        "the upstream must never see a call to a switched-off tool"
    );
    let allowed = client.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        allowed.text().as_deref(),
        Some("called: echo"),
        "an on tool must still be called"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_to_a_switched_off_tool_is_refused_on_the_combined_endpoint_with_the_merged_name() {
    let sc = start().await;
    switch_delete_db_off(&sc).await;
    let client = session(&sc.w, &sc.bob, "mcp").await;
    sc.up.clear();
    let refused = client.call_tool("s__delete_db", json!({})).await;
    assert_eq!(
        refused.status, 200,
        "a refused call is a JSON-RPC answer on HTTP 200"
    );
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "the refusal must be -32602"
    );
    assert_eq!(
        refused.error_message(),
        Some(switched_off_text("s__delete_db")),
        "the refusal must name the merged tool as the client sent it"
    );
    assert_eq!(
        sc.up.calls_to("delete_db"),
        0,
        "the upstream must never see a call to a switched-off tool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_switched_off_call_writes_a_deny_row_with_the_switched_off_detail() {
    let sc = start().await;
    switch_delete_db_off(&sc).await;
    let path = session(&sc.w, &sc.bob, "s").await;
    let combined = session(&sc.w, &sc.bob, "mcp").await;
    path.call_tool("delete_db", json!({})).await;
    combined.call_tool("s__delete_db", json!({})).await;
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.id)).await;
    let refused: Vec<(String, String, String, String, String)> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call" && row.decision == "deny")
        .map(|(row, detail)| {
            (
                row.kind.clone(),
                row.decision.clone(),
                row.outcome.clone(),
                row.server.clone(),
                detail.clone(),
            )
        })
        .collect();
    let want = (
        "tool_call".to_string(),
        "deny".to_string(),
        "refused".to_string(),
        "s".to_string(),
        SWITCHED.to_string(),
    );
    assert_eq!(
        refused,
        vec![want.clone(), want],
        "each refused switched-off call must write a tool_call deny refused row with the detail switched off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_denied_tool_that_is_also_switched_off_answers_unknown_with_its_rule_detail() {
    let sc = start().await;
    switch_delete_db_off(&sc).await;
    let rule = deny_tool(&sc.w, "everyone", &sc.id, "delete_db").await;
    let path = session(&sc.w, &sc.bob, "s").await;
    let combined = session(&sc.w, &sc.bob, "mcp").await;
    sc.up.clear();
    let on_path = path.call_tool("delete_db", json!({})).await;
    assert_eq!(
        on_path.error_code(),
        Some(-32602),
        "the path refusal must be -32602"
    );
    assert_eq!(
        on_path.error_message(),
        Some("Unknown tool: delete_db".to_string()),
        "a rule-denied tool must answer as unknown even when it is switched off"
    );
    let on_combined = combined.call_tool("s__delete_db", json!({})).await;
    assert_eq!(
        on_combined.error_message(),
        Some("Unknown tool: s__delete_db".to_string()),
        "a rule-denied tool must answer as unknown on the combined endpoint"
    );
    assert_eq!(
        sc.up.calls_to("delete_db"),
        0,
        "the upstream must never see the call"
    );
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.id)).await;
    let details: Vec<String> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call" && row.decision == "deny")
        .map(|(_, detail)| detail.clone())
        .collect();
    assert_eq!(
        details,
        vec![format!("rule {rule}"), format!("rule {rule}")],
        "the rule must stay the detail of a call that is both denied and switched off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn switching_a_tool_back_on_restores_its_list_entry_and_its_call() {
    let sc = start().await;
    switch_delete_db_off(&sc).await;
    assert_eq!(
        listed(&sc.w, &sc.bob, "s", false).await,
        vec!["echo", "search"],
        "delete_db must be absent while it is switched off"
    );
    let page = post_switches(&sc.bob, "s", "all-on", &[]).await;
    assert_eq!(page.status, 303, "All on must be accepted");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        Vec::<String>::new(),
        "All on must clear the switch"
    );
    assert_eq!(
        listed(&sc.w, &sc.bob, "mcp", false).await,
        vec!["s__echo", "s__search", "s__delete_db"],
        "a tool switched back on must be listed again on /mcp"
    );
    let client = session(&sc.w, &sc.bob, "s").await;
    sc.up.clear();
    let reply = client.call_tool("delete_db", json!({})).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: delete_db"),
        "a tool switched back on must be called through"
    );
    assert_eq!(
        sc.up.calls_to("delete_db"),
        1,
        "the upstream must see the call"
    );
}

/// Two servers, `a` (aa, ab) and `b` (bb), where `a` is the larger list; the budget fits `b` only.
/// Switching `ab` off in `a` lets `a` in with `aa`.
async fn over_budget(stateless: bool) {
    let mut w = World::start().await;
    let (_a_up, a_id) = w
        .upstream(
            "a",
            UpstreamOptions {
                tools: vec!["aa".into(), "ab".into()],
                ..Default::default()
            },
        )
        .await;
    let (_b_up, b_id) = w
        .upstream(
            "b",
            UpstreamOptions {
                tools: vec!["bb".into()],
                ..Default::default()
            },
        )
        .await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[a_id.as_str(), b_id.as_str()]).await;
    let bob_id = w.user_id(BOB).await;
    let a_bytes = merged_bytes("a", &stored_definitions(&w, &a_id));
    let b_bytes = merged_bytes("b", &stored_definitions(&w, &b_id));
    assert!(
        a_bytes > b_bytes,
        "server a must be the larger list, got {a_bytes} against {b_bytes}"
    );
    let limit = a_bytes + b_bytes - 1;
    w.tighten(|c| c.limits.tools_list_bytes = limit as u64)
        .await;
    assert_eq!(
        listed(&w, &bob, "mcp", stateless).await,
        vec!["b__bb"],
        "a list that does not fit the budget must leave its server out"
    );
    let page = post_switches(&bob, "a", "chosen", &["aa"]).await;
    assert_eq!(
        page.status, 303,
        "the save that switches ab off must be accepted"
    );
    assert_eq!(
        switched_off(&w, &bob_id, &a_id),
        vec!["ab"],
        "ab must be the one switched-off tool"
    );
    assert_eq!(
        listed(&w, &bob, "mcp", stateless).await,
        vec!["a__aa", "b__bb"],
        "a switched-off tool must take no room, so the next server fits"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_takes_no_room_in_the_combined_size_budget_in_the_session_generation() {
    over_budget(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_takes_no_room_in_the_combined_size_budget_in_the_stateless_generation()
{
    over_budget(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_with_no_switches_gets_the_upstream_bytes_on_the_server_path() {
    let w = World::start().await;
    let (up, id) = w.open_upstream("open", UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "open").await;
    let direct = McpClient::session(&up.url(), None);
    assert_eq!(
        direct.initialize().await.status,
        200,
        "the upstream must answer initialize"
    );
    let direct_list = direct.list_tools().await;
    let via = w.session_mcp("open", &tokens);
    assert_eq!(
        via.initialize().await.status,
        200,
        "the gateway must answer initialize"
    );
    let via_list = via.list_tools().await;
    assert_eq!(
        via_list.body, direct_list.body,
        "with no switch the session list on /open must be the upstream's bytes"
    );
    let direct_list = McpClient::stateless(&up.url(), None).list_tools().await;
    let via_list = w.stateless_mcp("open", &tokens).list_tools().await;
    assert_eq!(
        direct_list.status, 200,
        "the upstream must answer tools/list"
    );
    // A stateless answer is marked private by the gateway (tests/s11_generations.rs); nothing else changes.
    let mut expected: Value =
        serde_json::from_str(&direct_list.body).expect("the upstream answers JSON");
    expected["result"]["cacheScope"] = json!("private");
    assert_eq!(
        via_list.body,
        expected.to_string(),
        "with no switch the stateless list on /open must be the upstream's bytes, marked private"
    );
}
