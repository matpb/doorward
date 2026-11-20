mod common;

use std::sync::Arc;
use std::time::Duration;

use common::admin;
use common::client::{Page, TestClient, Tokens};
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::world::{OWNER_EMAIL, PASSWORD, World};
use doorward::clock::Clock;
use doorward::oauth::families;
use rusqlite::Connection;
use serde_json::{Value, json};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";

/// Bob, granted demo, with a token for demo. The upstream is returned so that it stays alive.
async fn bob_on_demo(w: &World) -> (TestClient, FakeUpstream, String, Tokens) {
    let bob = w.user(BOB).await;
    let (upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    (bob, upstream, demo, tokens)
}

/// Asserts that a token request was refused with 400 and `invalid_grant`.
fn assert_invalid_grant(page: &Page, what: &str) {
    assert_eq!(page.status, 400, "{what} must answer 400");
    let error = page
        .json()
        .and_then(|json| json["error"].as_str().map(str::to_owned));
    assert_eq!(
        error.as_deref(),
        Some("invalid_grant"),
        "{what} must answer invalid_grant"
    );
}

/// Asserts that a browser is sent to the sign-in page.
fn assert_sent_to_login(page: &Page, what: &str) {
    assert_eq!(page.status, 303, "{what} must redirect");
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "{what} must go to /login"
    );
}

/// Reads the csrf token of a signed-in browser from its account page.
async fn csrf_of(browser: &TestClient) -> String {
    browser
        .get("/account")
        .await
        .csrf()
        .expect("the account page carries a csrf token")
}

/// Bob on demo, then `action` on bob: his token, his browser and his sign-in are all refused.
async fn action_refuses_bob(w: &World, action: &str) {
    let (bob, _upstream, _demo, tokens) = bob_on_demo(w).await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start before {action}"
    );
    assert_eq!(
        mcp.list_tools().await.status,
        200,
        "bob must list tools before {action}"
    );
    let bob_id = w.user_id(BOB).await;
    let page = admin::user_action(&w.owner, &bob_id, action).await;
    assert_eq!(page.status, 303, "{action} on bob must answer 303");
    assert_eq!(
        mcp.list_tools().await.status,
        401,
        "after {action}, bob's token must be refused on the next request"
    );
    let anon = w.client();
    assert_invalid_grant(
        &anon
            .token_refresh(&w.app(), &tokens.refresh_token, None)
            .await,
        "refreshing bob's token after the action",
    );
    assert_sent_to_login(
        &bob.get("/account").await,
        "bob's browser on /account after the action",
    );
    let login = anon.login(BOB, PASSWORD).await;
    assert_eq!(
        login.status, 401,
        "signing in as bob after the action must answer 401"
    );
    assert_eq!(
        login.error().as_deref(),
        Some("Wrong email or password."),
        "signing in as bob after the action must show the wrong-password text"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_user_is_refused_on_the_next_request() {
    let w = World::start().await;
    action_refuses_bob(&w, "disable").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deleted_user_is_refused_on_the_next_request() {
    let w = World::start().await;
    action_refuses_bob(&w, "delete").await;
    assert_eq!(
        admin::user_id(&w.owner, BOB).await,
        None,
        "the users page must no longer list bob"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn re_enabled_user_must_connect_again() {
    let w = World::start().await;
    let (_bob, _upstream, _demo, tokens) = bob_on_demo(&w).await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    assert_eq!(mcp.list_tools().await.status, 200, "bob must list tools");
    let bob_id = w.user_id(BOB).await;
    let disabled = admin::user_action(&w.owner, &bob_id, "disable").await;
    assert_eq!(disabled.status, 303, "disabling bob must answer 303");
    let enabled = admin::user_action(&w.owner, &bob_id, "enable").await;
    assert_eq!(enabled.status, 303, "enabling bob must answer 303");
    assert_eq!(
        mcp.list_tools().await.status,
        401,
        "the old access token must stay refused after bob is enabled again"
    );
    let anon = w.client();
    assert_invalid_grant(
        &anon
            .token_refresh(&w.app(), &tokens.refresh_token, None)
            .await,
        "the old refresh token after bob is enabled again",
    );
    let login = anon.login(BOB, PASSWORD).await;
    assert_eq!(login.status, 303, "bob must be able to sign in again");
    let fresh = w.token(&anon, "demo").await;
    let fresh_mcp = w.session_mcp("demo", &fresh);
    assert_eq!(
        fresh_mcp.initialize().await.status,
        200,
        "a new token for bob must start a session"
    );
    assert_eq!(
        fresh_mcp.list_tools().await.status,
        200,
        "a new token for bob must list tools"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_cannot_be_disabled_or_deleted() {
    let w = World::start().await;
    let carol = w.admin(CAROL).await;
    let owner_id = w.user_id(OWNER_EMAIL).await;
    let disable = admin::user_action(&carol, &owner_id, "disable").await;
    assert_eq!(
        disable.status, 400,
        "an admin disabling the owner must answer 400"
    );
    let delete = admin::user_action(&carol, &owner_id, "delete").await;
    assert_eq!(
        delete.status, 400,
        "an admin deleting the owner must answer 400"
    );
    assert!(
        admin::user_id(&w.owner, OWNER_EMAIL).await.is_some(),
        "the owner must still be listed on the users page"
    );
    let panel = w.owner.get("/admin").await;
    assert_eq!(panel.status, 200, "the owner must still reach /admin");
    assert_eq!(
        panel.kind().as_deref(),
        Some("admin"),
        "the owner must still see the admin page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn open_stream_ends_when_the_user_is_disabled() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Progress {
            steps: 50,
            interval_ms: 100,
        },
        ..UpstreamOptions::default()
    };
    let (_upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = Arc::new(w.session_mcp("demo", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let bob_id = w.user_id(BOB).await;
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let page = admin::user_action(&w.owner, &bob_id, "disable").await;
    assert_eq!(page.status, 303, "disabling bob must answer 303");
    let reply = tokio::time::timeout(Duration::from_secs(3), call)
        .await
        .expect("the open call must return within 3 seconds of the disable")
        .expect("the call task must not panic");
    let progress = reply
        .events
        .iter()
        .filter(|event| {
            event.data.get("method").and_then(Value::as_str) == Some("notifications/progress")
        })
        .count();
    assert!(
        progress >= 1,
        "the stream must have started before the disable, got {progress} progress events"
    );
    assert!(
        progress < 50,
        "the disable must end the stream early, got {progress} progress events"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cannot_disable_an_admin_of_higher_rank() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let carol = w.admin(CAROL).await;
    let carol_id = w.user_id(CAROL).await;
    let csrf = csrf_of(&bob).await;
    let page = bob
        .post(
            &format!("/admin/users/{carol_id}/disable"),
            &[("csrf", csrf.as_str())],
        )
        .await;
    assert_eq!(
        page.status, 403,
        "a plain user disabling an admin must answer 403"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "a plain user disabling an admin must see the forbidden page"
    );
    let panel = carol.get("/admin").await;
    assert_eq!(
        panel.status, 200,
        "the admin must stay signed in and reach /admin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_cannot_disable_or_delete_another_admin() {
    let w = World::start().await;
    let alice = w.admin(ALICE).await;
    let carol = w.admin(CAROL).await;
    let _bob = w.user(BOB).await;
    let carol_id = w.user_id(CAROL).await;
    let disable = admin::user_action(&alice, &carol_id, "disable").await;
    assert_eq!(
        disable.status, 403,
        "an admin disabling another admin must answer 403"
    );
    assert_eq!(
        disable.kind().as_deref(),
        Some("forbidden"),
        "an admin disabling another admin must show the forbidden page"
    );
    let delete = admin::user_action(&alice, &carol_id, "delete").await;
    assert_eq!(
        delete.status, 403,
        "an admin deleting another admin must answer 403"
    );
    assert_eq!(
        delete.kind().as_deref(),
        Some("forbidden"),
        "an admin deleting another admin must show the forbidden page"
    );
    let panel = carol.get("/admin").await;
    assert_eq!(
        panel.status, 200,
        "the targeted admin must still reach /admin"
    );
    let bob_id = w.user_id(BOB).await;
    let page = admin::user_action(&alice, &bob_id, "disable").await;
    assert_eq!(
        page.status, 303,
        "an admin disabling a plain user must answer 303"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_path_answer_is_not_returned_after_access_was_lost() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Delayed { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (_upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = Arc::new(w.session_mcp("demo", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let bob_id = w.user_id(BOB).await;
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let page = admin::user_action(&w.owner, &bob_id, "disable").await;
    assert_eq!(page.status, 303, "disabling bob must answer 303");
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the delayed call must return within 5 seconds")
        .expect("the call task must not panic");
    assert_eq!(
        reply.status, 200,
        "a tools/call whose access was lost must be answered 200 as an unknown tool, as /mcp answers"
    );
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a tools/call whose access was lost must answer -32602"
    );
    assert_eq!(
        reply.error_message().as_deref(),
        Some("Unknown tool: echo"),
        "a tools/call whose access was lost must say the tool is unknown"
    );
    assert!(
        !reply.body.contains("called: echo"),
        "the upstream's answer must not be returned after bob was disabled"
    );
    let rows = admin::activity_with_details(&w.owner, None, None).await;
    let calls: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call" && row.tool == "echo")
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "the lost call must write exactly one activity row, rows were {rows:?}"
    );
    assert_eq!(
        calls[0].0.outcome, "refused",
        "the lost call's row must be refused"
    );
    assert_eq!(
        calls[0].1, "access was lost",
        "the lost call's row must say access was lost"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_access_on_another_method_gets_the_challenge() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::SlowListing { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (_upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = Arc::new(w.session_mcp("demo", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let bob_id = w.user_id(BOB).await;
    let listing = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.list_tools().await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let page = admin::user_action(&w.owner, &bob_id, "disable").await;
    assert_eq!(page.status, 303, "disabling bob must answer 303");
    let reply = tokio::time::timeout(Duration::from_secs(5), listing)
        .await
        .expect("the delayed listing must return within 5 seconds")
        .expect("the listing task must not panic");
    assert_eq!(
        reply.status, 401,
        "a tools/list whose access was lost must get the 401 challenge"
    );
    assert!(
        reply.headers.contains_key("www-authenticate"),
        "the 401 must carry the bearer challenge"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_that_expires_during_a_call_still_gets_its_answer() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Delayed { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = Arc::new(w.session_mcp("demo", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.gw.clock.advance(time::Duration::hours(2));
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the delayed call must return within 5 seconds")
        .expect("the call task must not panic");
    assert_eq!(
        reply.status, 200,
        "a call whose token expired while it ran must still get the upstream's answer"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the upstream's answer must be returned"
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        1,
        "the upstream must see the call once"
    );
    assert_one_ok_call(&w, "echo", "demo").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_that_expires_during_a_combined_call_still_gets_its_answer() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Delayed { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "mcp").await;
    let mcp = Arc::new(w.session_mcp("mcp", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("demo__echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.gw.clock.advance(time::Duration::hours(2));
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the delayed call must return within 5 seconds")
        .expect("the call task must not panic");
    assert_eq!(
        reply.status, 200,
        "a combined call whose token expired while it ran must still get the upstream's answer"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the upstream's answer must be returned"
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        1,
        "the upstream must see the call once"
    );
    assert_one_ok_call(&w, "echo", "demo").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_that_expires_during_a_streamed_call_still_gets_its_answer() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Progress {
            steps: 5,
            interval_ms: 300,
        },
        ..UpstreamOptions::default()
    };
    let (upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = Arc::new(w.session_mcp("demo", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.gw.clock.advance(time::Duration::hours(2));
    let reply = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("the streamed call must end within 10 seconds")
        .expect("the call task must not panic");
    let progress = reply
        .events
        .iter()
        .filter(|event| {
            event.data.get("method").and_then(Value::as_str) == Some("notifications/progress")
        })
        .count();
    assert_eq!(
        progress, 5,
        "every progress event must reach the client, got {progress}"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the streamed answer must reach the client"
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        1,
        "the upstream must see the call once"
    );
    assert_one_ok_call(&w, "echo", "demo").await;
}

/// Asserts one activity row for `tool` on `server` with outcome ok.
async fn assert_one_ok_call(w: &World, tool: &str, server: &str) {
    let rows = admin::activity(&w.owner, None, None).await;
    let calls: Vec<_> = rows
        .iter()
        .filter(|row| row.kind == "tool_call" && row.tool == tool && row.server == server)
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "the call must write exactly one activity row, rows were {rows:?}"
    );
    assert_eq!(
        calls[0].outcome, "ok",
        "the call that expired during its run must be recorded as ok"
    );
}

/// The token part of a housekeeping run, at the gateway's clock, while a call is still in flight.
fn sweep_tokens_now(w: &World) {
    let conn = Connection::open(w.gw.db_path()).expect("the gateway database opens");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("the busy timeout is set");
    let now = w.gw.clock.now().unix_timestamp();
    let replay = families::replay_window(&w.gw.config().lifetimes);
    families::sweep(&conn, now, replay).expect("the housekeeping token sweep runs");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_that_outlives_its_token_survives_the_housekeeping_run() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Delayed { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = Arc::new(w.session_mcp("demo", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.gw.clock
        .advance(time::Duration::hours(1) + time::Duration::minutes(20));
    sweep_tokens_now(&w);
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the delayed call must return within 5 seconds")
        .expect("the call task must not panic");
    assert_eq!(
        reply.status, 200,
        "a call that outlives its token must still get the upstream's answer"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the upstream's answer must be returned after the housekeeping run"
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        1,
        "the upstream must see the call once"
    );
    assert_one_ok_call(&w, "echo", "demo").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_combined_call_that_outlives_its_token_survives_the_housekeeping_run() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Delayed { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "mcp").await;
    let mcp = Arc::new(w.session_mcp("mcp", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("demo__echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.gw.clock
        .advance(time::Duration::hours(1) + time::Duration::minutes(20));
    sweep_tokens_now(&w);
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the delayed call must return within 5 seconds")
        .expect("the call task must not panic");
    assert_eq!(
        reply.status, 200,
        "a combined call that outlives its token must still get the upstream's answer"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the upstream's answer must be returned after the housekeeping run"
    );
    assert_eq!(
        upstream.rpc_count("tools/call"),
        1,
        "the upstream must see the call once"
    );
    assert_one_ok_call(&w, "echo", "demo").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_combined_answer_is_not_returned_after_access_was_lost() {
    let w = World::start().await;
    let slow = UpstreamOptions {
        mode: Mode::Delayed { millis: 1500 },
        ..UpstreamOptions::default()
    };
    let (_upstream, demo) = w.upstream("demo", slow).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "mcp").await;
    let mcp = Arc::new(w.session_mcp("mcp", &tokens));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start"
    );
    let bob_id = w.user_id(BOB).await;
    let call = {
        let mcp = mcp.clone();
        tokio::spawn(async move { mcp.call_tool("demo__echo", json!({"text": "hi"})).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let page = admin::user_action(&w.owner, &bob_id, "disable").await;
    assert_eq!(page.status, 303, "disabling bob must answer 303");
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the delayed call must return within 5 seconds")
        .expect("the call task must not panic");
    assert_eq!(
        reply.result(),
        None,
        "the upstream's answer must not be returned after bob was disabled"
    );
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "the combined endpoint must answer -32602 when access was lost"
    );
    assert_eq!(
        reply.error_message(),
        Some("Unknown tool: demo__echo".to_string()),
        "the combined endpoint must answer the unknown-tool message when access was lost"
    );
}
