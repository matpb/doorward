mod common;

use std::time::Duration;

use common::admin;
use common::mail::link_with_prefix;
use common::upstream::UpstreamOptions;
use common::world::{PASSWORD, World};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const NEW_PASSWORD: &str = "a new long password";
const CANARY: &str = "CANARY-7f3a91";
const TOOL_CALL: &str = r#"[data-kind="tool_call"]"#;
const HOSTILE_ADDRESS: &str = "\"<b>x</b>\"@example.com";

fn kinds(rows: &[admin::ActivityRow]) -> Vec<String> {
    rows.iter().map(|row| row.kind.clone()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_is_recorded() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let reply = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(reply.status, 200, "the allowed call must answer 200");

    let rows = admin::activity(&w.owner, None, None).await;
    let row = rows
        .iter()
        .find(|row| row.kind == "tool_call")
        .unwrap_or_else(|| {
            panic!(
                "the activity log must hold a tool_call row, kinds were {:?}",
                kinds(&rows)
            )
        });
    assert_eq!(row.user, BOB, "the call must be recorded under bob");
    assert_eq!(
        row.server, "demo",
        "the call must be recorded under server demo"
    );
    assert_eq!(
        row.tool, "echo",
        "the call must be recorded under tool echo"
    );
    assert_eq!(
        row.decision, "allow",
        "an allowed call must have decision allow"
    );
    assert_eq!(row.outcome, "ok", "a successful call must have outcome ok");

    let page = w.owner.get("/admin/activity").await;
    let stamp = page
        .attr(TOOL_CALL, "data-time")
        .expect("the tool_call row must carry data-time");
    assert!(
        OffsetDateTime::parse(&stamp, &Rfc3339).is_ok(),
        "data-time must be an RFC 3339 time, got {stamp:?}"
    );
    let duration = page
        .attr(TOOL_CALL, "data-duration-ms")
        .expect("the tool_call row must carry data-duration-ms");
    assert!(
        duration.parse::<f64>().is_ok_and(|ms| ms >= 0.0),
        "data-duration-ms must be a number, got {duration:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_call_is_recorded() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(&id),
        Some("delete_db"),
    )
    .await;
    assert_eq!(page.status, 303, "the deny rule must be saved");
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let reply = mcp.call_tool("delete_db", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a denied tool must be refused with -32602"
    );

    let rows = admin::activity(&w.owner, None, None).await;
    let row = rows
        .iter()
        .find(|row| row.kind == "tool_call" && row.tool == "delete_db")
        .unwrap_or_else(|| {
            panic!(
                "the denied call must be recorded, kinds were {:?}",
                kinds(&rows)
            )
        });
    assert_eq!(
        row.decision, "deny",
        "a denied call must have decision deny"
    );
    assert_eq!(
        row.outcome, "refused",
        "a denied call must have outcome refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn arguments_and_results_are_not_stored() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let reply = mcp.call_tool("echo", json!({"text": CANARY})).await;
    assert_eq!(reply.status, 200, "the call must answer 200");

    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "tool_call"),
        "the call must be recorded before its storage is checked"
    );
    let stored = String::from_utf8_lossy(&w.stored_bytes()).into_owned();
    assert!(
        !stored.contains(CANARY),
        "the arguments of a call must not be stored"
    );
    assert!(
        !stored.contains("called: echo"),
        "the result of a call must not be stored"
    );
    let page = w.owner.get("/admin/activity").await;
    assert!(
        !page.body.contains(CANARY),
        "the activity page must not show the arguments of a call"
    );
    assert!(
        !page.body.contains("called: echo"),
        "the activity page must not show the result of a call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn account_events_are_recorded() {
    let w = World::start().await;
    w.user(BOB).await;
    let signed_in = w.client().login(BOB, PASSWORD).await;
    assert_eq!(signed_in.status, 303, "the right password must sign bob in");
    let refused = w.client().login(BOB, "not the password at all").await;
    assert_eq!(refused.status, 401, "a wrong password must be refused");

    w.mail.clear();
    let anonymous = w.client();
    let page = anonymous
        .submit("/forgot", "/forgot", &[("email", BOB)])
        .await;
    assert_eq!(page.status, 200, "a reset request must answer 200");
    let mail = w
        .mail
        .wait_to(BOB, Duration::from_secs(5))
        .await
        .expect("the reset mail must arrive within 5 seconds");
    let prefix = format!("{}/reset/", w.base());
    let link = link_with_prefix(&mail.text, &prefix)
        .unwrap_or_else(|| panic!("the reset mail must hold a link starting with {prefix}"));
    let page = anonymous.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "the reset must set the new password");

    let (_up, _id) = w.upstream("demo", UpstreamOptions::default()).await;

    let rows = admin::activity(&w.owner, None, None).await;
    let found = kinds(&rows);
    for wanted in [
        "login",
        "login_failed",
        "invitation",
        "reset",
        "admin_change",
    ] {
        assert!(
            found.iter().any(|kind| kind == wanted),
            "the activity log must record {wanted}, kinds were {found:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_by_user_and_by_server() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let carol = w.user(CAROL).await;
    let (_a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let (_b, b_id) = w
        .upstream(
            "b",
            UpstreamOptions {
                tools: vec!["alpha".into()],
                ..Default::default()
            },
        )
        .await;
    w.grant(BOB, &[a_id.as_str(), b_id.as_str()]).await;
    w.grant(CAROL, &[a_id.as_str()]).await;

    let bob_a = w.session_mcp("a", &w.token(&bob, "a").await);
    bob_a.initialize().await;
    bob_a.call_tool("echo", json!({})).await;
    let bob_b = w.session_mcp("b", &w.token(&bob, "b").await);
    bob_b.initialize().await;
    bob_b.call_tool("alpha", json!({})).await;
    let carol_a = w.session_mcp("a", &w.token(&carol, "a").await);
    carol_a.initialize().await;
    carol_a.call_tool("echo", json!({})).await;

    let bob_id = w.user_id(BOB).await;
    let by_user = admin::activity(&w.owner, Some(&bob_id), None).await;
    assert!(!by_user.is_empty(), "bob's activity must not be empty");
    for row in &by_user {
        assert_eq!(row.user, BOB, "filtering by bob must show only bob's rows");
    }
    let by_server = admin::activity(&w.owner, None, Some(&a_id)).await;
    assert!(
        !by_server.is_empty(),
        "server a's activity must not be empty"
    );
    for row in &by_server {
        assert_eq!(
            row.server, "a",
            "filtering by server a must show only server a rows"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_admins_read_the_activity() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob.get("/admin/activity").await;
    assert_eq!(
        page.status, 403,
        "a plain user must be refused the activity page"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "a plain user must see the forbidden page"
    );
    let anonymous = w.client();
    let page = anonymous.get("/admin/activity").await;
    assert_eq!(page.status, 303, "an anonymous visitor must be redirected");
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "an anonymous visitor must be sent to sign-in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_combined_call_is_recorded_under_the_real_server_and_tool() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "mcp").await;
    let mcp = w.session_mcp("mcp", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let reply = mcp.call_tool("demo__echo", json!({})).await;
    assert_eq!(reply.status, 200, "the combined call must answer 200");

    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter()
            .any(|row| row.kind == "tool_call" && row.server == "demo" && row.tool == "echo"),
        "the combined call must be recorded under server demo and tool echo, rows were {:?}",
        rows.iter()
            .map(|row| (row.kind.clone(), row.server.clone(), row.tool.clone()))
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn activity_outlives_the_user() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let reply = mcp.call_tool("echo", json!({})).await;
    assert_eq!(reply.status, 200, "the call must answer 200");

    let bob_id = w.user_id(BOB).await;
    let page = admin::user_action(&w.owner, &bob_id, "delete").await;
    assert_eq!(page.status, 303, "deleting bob must answer 303");
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter()
            .any(|row| row.kind == "tool_call" && row.user == BOB),
        "bob's rows must still show his email after he is deleted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn user_text_is_escaped() {
    let w = World::start().await;
    let page = w.client().login(HOSTILE_ADDRESS, "a wrong password").await;
    assert_eq!(page.status, 401, "an unknown address must be refused");
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "login_failed"),
        "the failed sign-in must be recorded, kinds were {:?}",
        kinds(&rows)
    );
    let page = w.owner.get("/admin/activity").await;
    assert!(
        !page.body.contains("<b>x</b>"),
        "the activity page must escape the address typed by the user"
    );
}
