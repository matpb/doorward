mod common;

use common::admin;
use common::client::{Page, TestClient};
use common::mcp::{McpClient, McpReply};
use common::switches::{
    deny_tool, post_switches, post_switches_with_shown, stored_rows, switched_off, tool_rows,
};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::values::account_csrf;
use common::world::World;
use serde_json::json;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const ADMIN: &str = "admin@example.com";
const EVIL: &str = "https://evil.example.com";
const MADE_UP: usize = 3500;

/// Server `s` (echo, search, delete_db) assigned to bob and carol, and server `other` (echo) to carol.
struct Scene {
    w: World,
    s_up: FakeUpstream,
    s_id: String,
    other_up: FakeUpstream,
    other_id: String,
    bob: TestClient,
    bob_id: String,
    carol: TestClient,
    carol_id: String,
}

async fn start() -> Scene {
    let w = World::start().await;
    let (s_up, s_id) = w.upstream("s", UpstreamOptions::default()).await;
    let other = UpstreamOptions {
        tools: vec!["echo".into()],
        ..Default::default()
    };
    let (other_up, other_id) = w.upstream("other", other).await;
    let bob = w.user(BOB).await;
    let carol = w.user(CAROL).await;
    w.grant(BOB, &[s_id.as_str()]).await;
    w.grant(CAROL, &[s_id.as_str(), other_id.as_str()]).await;
    let bob_id = w.user_id(BOB).await;
    let carol_id = w.user_id(CAROL).await;
    Scene {
        w,
        s_up,
        s_id,
        other_up,
        other_id,
        bob,
        bob_id,
        carol,
        carol_id,
    }
}

/// Bob switches echo off on server `s`; the save is accepted and only echo is stored.
async fn bob_switches_echo_off(sc: &Scene) {
    let page = post_switches(&sc.bob, "s", "chosen", &["search", "delete_db"]).await;
    assert_eq!(page.status, 303, "bob's own save must be accepted");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["echo"],
        "bob's save must store echo as switched off"
    );
}

/// Asserts that a post was refused: 403, or sent to the sign-in page; never to the tools section.
fn assert_refused(page: &Page, what: &str) {
    let to_sign_in = page.status == 303 && page.location().as_deref() == Some("/login");
    assert!(
        page.status == 403 || to_sign_in,
        "{what} must be refused, got status {} and location {:?}",
        page.status,
        page.location()
    );
    assert!(
        !page
            .location()
            .is_some_and(|location| location.starts_with("/account?saved=")),
        "{what} must not be accepted"
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn a_post_without_the_csrf_token_is_refused_and_stores_nothing() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let refused = sc.bob.post("/account/tools/s", &[("set", "all-on")]).await;
    assert_eq!(
        refused.status, 403,
        "a post without the csrf token must answer 403"
    );
    assert_eq!(
        refused.kind().as_deref(),
        Some("forbidden"),
        "a post without the csrf token must show the forbidden page"
    );
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a refused post must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_with_another_sessions_csrf_token_is_refused_and_stores_nothing() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let carol_csrf = account_csrf(&sc.carol).await;
    let refused = sc
        .bob
        .post(
            "/account/tools/s",
            &[("csrf", carol_csrf.as_str()), ("set", "all-on")],
        )
        .await;
    assert_eq!(
        refused.status, 403,
        "another session's csrf token must answer 403"
    );
    assert_eq!(
        refused.kind().as_deref(),
        Some("forbidden"),
        "another session's csrf token must show the forbidden page"
    );
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a refused post must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_from_a_foreign_origin_is_refused_and_stores_nothing() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let csrf = account_csrf(&sc.bob).await;
    let refused = sc
        .bob
        .post_with(
            "/account/tools/s",
            &[("csrf", csrf.as_str()), ("set", "all-on")],
            &[("Origin", EVIL)],
        )
        .await;
    assert_eq!(refused.status, 403, "a foreign origin must answer 403");
    assert_eq!(
        refused.kind().as_deref(),
        Some("forbidden"),
        "a foreign origin must show the forbidden page"
    );
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a refused post must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_for_an_unassigned_or_unknown_server_gets_the_same_not_found_answer_and_stores_nothing()
 {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let csrf = account_csrf(&sc.bob).await;
    let fields = [("csrf", csrf.as_str()), ("set", "all-off")];
    let unassigned = sc.bob.post("/account/tools/other", &fields).await;
    let unknown = sc.bob.post("/account/tools/nowhere", &fields).await;
    assert_eq!(
        unassigned.status, 404,
        "a server bob is not assigned to must answer 404"
    );
    assert_eq!(
        unknown.status, unassigned.status,
        "an unknown slug must answer the same status as an unassigned server"
    );
    assert_eq!(
        unknown.kind(),
        unassigned.kind(),
        "an unknown slug must show the same page as an unassigned server"
    );
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "neither post may store anything"
    );
    assert!(
        switched_off(&sc.w, &sc.bob_id, &sc.other_id).is_empty(),
        "no switch may be stored for the unassigned server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_out_post_is_refused_and_stores_nothing() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let anon = sc.w.client();
    let csrf = anon
        .get("/login")
        .await
        .csrf()
        .expect("the sign-in form carries a csrf token");
    let refused = anon
        .post(
            "/account/tools/s",
            &[("csrf", csrf.as_str()), ("set", "all-on")],
        )
        .await;
    assert_refused(&refused, "a signed-out post");
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a signed-out post must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn thousands_of_made_up_names_store_no_row_while_the_real_ones_do() {
    let sc = start().await;
    let made_up: Vec<String> = (0..MADE_UP).map(|n| format!("made-up-{n:04}")).collect();
    let names: Vec<&str> = made_up.iter().map(String::as_str).collect();
    let mut honest = names.clone();
    honest.push("echo");
    let page = post_switches(&sc.bob, "s", "chosen", &honest).await;
    assert_eq!(
        page.status, 303,
        "the form with one real name must be accepted"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["delete_db", "search"],
        "the real names must be stored, the made-up ones ignored"
    );
    let page = post_switches(&sc.bob, "s", "chosen", &names).await;
    assert_eq!(
        page.status, 303,
        "the form of made-up names only must be accepted"
    );
    assert!(
        stored_rows(&sc.w)
            .iter()
            .all(|(_, _, tool)| !tool.starts_with("made-up-")),
        "no made-up name may be stored"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["delete_db", "echo", "search"],
        "with no real name in on every allowed tool goes off"
    );
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.s_id)).await;
    assert!(
        rows.iter()
            .any(|(row, detail)| row.kind == "tool_switches" && detail == "3 of 3 off"),
        "the count must hold the three allowed tools only, rows were {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_form_over_the_size_limit_is_refused_and_stores_nothing() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let made_up: Vec<String> = (0..5000).map(|n| format!("made-up-{n:04}")).collect();
    let names: Vec<&str> = made_up.iter().map(String::as_str).collect();
    let page = post_switches(&sc.bob, "s", "chosen", &names).await;
    assert_eq!(
        page.status, 403,
        "a form over the size limit must be refused with the status the product gives an over-limit form"
    );
    assert!(
        !page
            .location()
            .is_some_and(|location| location.starts_with("/account?saved=")),
        "a refused over-limit form must not be accepted"
    );
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a refused over-limit form must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_users_switches_change_nothing_for_another_user_on_the_same_server() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let bob_list = session(&sc.w, &sc.bob, "s").await.list_tools().await;
    assert_eq!(
        names(&bob_list),
        vec!["search", "delete_db"],
        "bob's own list must lack the tool he switched off"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.carol_id, &sc.s_id),
        Vec::<String>::new(),
        "carol must have no switches"
    );
    let carol = session(&sc.w, &sc.carol, "s").await;
    assert_eq!(
        names(&carol.list_tools().await),
        vec!["echo", "search", "delete_db"],
        "carol's list must not change"
    );
    let called = carol.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        called.text().as_deref(),
        Some("called: echo"),
        "carol must still call echo"
    );
    assert!(
        tool_rows(&sc.carol, "s")
            .await
            .iter()
            .all(|row| row.state == "on"),
        "carol's page must show every tool on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn switching_a_denied_tool_on_leaves_it_denied_in_the_list_and_the_call() {
    let sc = start().await;
    let page = post_switches(&sc.bob, "s", "chosen", &["echo", "delete_db"]).await;
    assert_eq!(
        page.status, 303,
        "bob's save must be accepted before the rule"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["search"],
        "search must be stored as switched off"
    );
    deny_tool(&sc.w, "everyone", &sc.s_id, "delete_db").await;
    let page = post_switches(&sc.bob, "s", "chosen", &["echo", "search", "delete_db"]).await;
    assert_eq!(
        page.status, 303,
        "posting a denied name in on must still be accepted"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        Vec::<String>::new(),
        "the denied name in on must change nothing, and search goes on"
    );
    assert!(
        !stored_rows(&sc.w)
            .iter()
            .any(|(_, _, tool)| tool == "delete_db"),
        "a denied tool must never get a switch row"
    );
    let client = session(&sc.w, &sc.bob, "s").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["echo", "search"],
        "the denied tool must stay absent from the list"
    );
    sc.s_up.clear();
    let refused = client.call_tool("delete_db", json!({})).await;
    assert_eq!(
        refused.error_message(),
        Some("Unknown tool: delete_db".to_string()),
        "the denied tool must stay refused"
    );
    assert_eq!(
        sc.s_up.calls_to("delete_db"),
        0,
        "the upstream must never see the call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn all_off_stores_no_row_for_a_denied_tool_and_does_not_count_it() {
    let sc = start().await;
    deny_tool(&sc.w, "everyone", &sc.s_id, "delete_db").await;
    let page = post_switches(&sc.bob, "s", "all-off", &[]).await;
    assert_eq!(page.status, 303, "All off must be accepted");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["echo", "search"],
        "All off must store the allowed tools and never the denied one"
    );
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.s_id)).await;
    assert!(
        rows.iter()
            .any(|(row, detail)| row.kind == "tool_switches" && detail == "2 of 2 off"),
        "the count must leave the denied tool out, rows were {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_name_with_markup_and_quotes_is_escaped_and_round_trips() {
    let sc = start().await;
    let name = r#"<script>alert("x")</script>"#;
    let (_markup_up, markup_id) =
        sc.w.upstream(
            "markup",
            UpstreamOptions {
                tools: vec![name.to_string(), "plain".to_string()],
                ..Default::default()
            },
        )
        .await;
    sc.w.grant(BOB, &[sc.s_id.as_str(), markup_id.as_str()])
        .await;
    let page = sc.bob.get("/account").await;
    assert!(
        !page.body.contains("<script>alert"),
        "the page must escape the tool name, but it holds the raw tag"
    );
    assert_eq!(
        page.attrs(
            r#"section#tools [data-server="markup"] [data-tool]"#,
            "data-tool"
        ),
        vec![name.to_string(), "plain".to_string()],
        "the name must read back unchanged from data-tool"
    );
    let page = post_switches(&sc.bob, "markup", "chosen", &["plain"]).await;
    assert_eq!(
        page.status, 303,
        "switching the markup name off must be accepted"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &markup_id),
        vec![name.to_string()],
        "the markup name must be stored as switched off"
    );
    let rows = tool_rows(&sc.bob, "markup").await;
    let states: Vec<(String, String, bool)> = rows
        .iter()
        .map(|row| (row.name.clone(), row.state.clone(), row.checked))
        .collect();
    assert_eq!(
        states,
        vec![
            (name.to_string(), "off".to_string(), false),
            ("plain".to_string(), "on".to_string(), true),
        ],
        "the markup name must show as off and unchecked"
    );
    let page = post_switches(&sc.bob, "markup", "chosen", &[name, "plain"]).await;
    assert_eq!(
        page.status, 303,
        "switching the markup name back on must be accepted"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &markup_id),
        Vec::<String>::new(),
        "the markup name must be switched back on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_token_is_not_accepted_on_the_switch_post() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let stored = stored_rows(&sc.w);
    let tokens = sc.w.token(&sc.bob, "s").await;
    let csrf = account_csrf(&sc.bob).await;
    let bearer = format!("Bearer {}", tokens.access_token);
    let stranger = sc.w.client();
    let refused = stranger
        .post_with(
            "/account/tools/s",
            &[("csrf", csrf.as_str()), ("set", "all-on")],
            &[("Authorization", bearer.as_str())],
        )
        .await;
    assert_refused(&refused, "a bearer token");
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a bearer post must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_admin_form_names_the_switches() {
    let sc = start().await;
    let _admin = sc.w.admin(ADMIN).await;
    sc.w.grant(ADMIN, &[sc.s_id.as_str()]).await;
    bob_switches_echo_off(&sc).await;
    let pages = [
        format!("/admin/users/{}", sc.bob_id),
        format!("/admin/servers/{}", sc.s_id),
        "/admin/users".to_string(),
    ];
    for path in pages {
        let page = sc.w.owner.get(&path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 for the owner");
        assert_eq!(
            page.count(r#"form[action*="/account/tools"]"#),
            0,
            "{path} must hold no form that posts the switches"
        );
        assert_eq!(
            page.count(r#"input[name="on"]"#),
            0,
            "{path} must hold no switch field"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_post_to_the_user_form_changes_only_the_admins_own_switches() {
    let sc = start().await;
    let admin = sc.w.admin(ADMIN).await;
    sc.w.grant(ADMIN, &[sc.s_id.as_str()]).await;
    let admin_id = sc.w.user_id(ADMIN).await;
    bob_switches_echo_off(&sc).await;
    let page = post_switches(&admin, "s", "all-off", &[]).await;
    assert_eq!(page.status, 303, "the admin's own save must be accepted");
    assert_eq!(
        switched_off(&sc.w, &admin_id, &sc.s_id),
        vec!["delete_db", "echo", "search"],
        "the admin's own switches must change"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["echo"],
        "bob's switches must not change"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn after_unassign_and_assign_again_every_tool_is_on() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let page = admin::assign(&sc.w.owner, &sc.bob_id, &[]).await;
    assert_eq!(page.status, 303, "unassigning bob must answer 303");
    sc.w.grant(BOB, &[sc.s_id.as_str()]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        Vec::<String>::new(),
        "assigning again must start with no switch"
    );
    assert_eq!(
        names(&session(&sc.w, &sc.bob, "s").await.list_tools().await),
        vec!["echo", "search", "delete_db"],
        "every tool must be listed after the assignment is made again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn after_the_user_and_the_server_are_deleted_no_rows_remain_for_them() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let page = post_switches(&sc.carol, "s", "chosen", &["echo", "delete_db"]).await;
    assert_eq!(page.status, 303, "carol's save must be accepted");
    let carol_rows = switched_off(&sc.w, &sc.carol_id, &sc.s_id);
    assert_eq!(carol_rows, vec!["search"], "carol's switch must be stored");
    let page = admin::user_action(&sc.w.owner, &sc.bob_id, "delete").await;
    assert_eq!(page.status, 303, "deleting bob must answer 303");
    let bob: i64 = sc.bob_id.parse().expect("numeric id");
    assert!(
        stored_rows(&sc.w).iter().all(|(user, _, _)| *user != bob),
        "deleting bob must remove his switches"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.carol_id, &sc.s_id),
        carol_rows,
        "deleting bob must leave carol's switches alone"
    );
    let page = admin::delete_server(&sc.w.owner, &sc.s_id).await;
    assert_eq!(page.status, 303, "deleting server s must answer 303");
    assert!(
        stored_rows(&sc.w).is_empty(),
        "deleting the server must remove every switch of it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_for_an_unassigned_server_never_makes_it_reachable() {
    let sc = start().await;
    bob_switches_echo_off(&sc).await;
    let tokens = sc.w.token(&sc.bob, "mcp").await;
    let combined = sc.w.session_mcp("mcp", &tokens);
    let init = combined.initialize().await;
    assert_eq!(init.status, 200, "initialize on /mcp must answer 200");
    assert_eq!(
        names(&combined.list_tools().await),
        vec!["s__search", "s__delete_db"],
        "bob's combined list must hold his own server's tools that are on"
    );
    let refused = combined
        .call_tool("other__echo", json!({"text": "hi"}))
        .await;
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "a call to an unassigned server must be refused"
    );
    assert_eq!(
        refused.error_message(),
        Some("Unknown tool: other__echo".to_string()),
        "a call to an unassigned server must answer as an unknown tool"
    );
    assert_eq!(
        sc.other_up.calls_to("echo"),
        0,
        "the unassigned server's upstream must never see the call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shown_name_that_is_not_an_allowed_catalog_tool_stores_nothing() {
    let sc = start().await;
    deny_tool(&sc.w, "everyone", &sc.s_id, "delete_db").await;
    let page = post_switches_with_shown(
        &sc.bob,
        "s",
        "chosen",
        &["made-up", "delete_db"],
        &["made-up", "delete_db", "not-listed", "echo"],
    )
    .await;
    assert_eq!(page.status, 303, "the form must be accepted");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.s_id),
        vec!["echo"],
        "only the allowed tool that the form showed is stored"
    );
    assert!(
        stored_rows(&sc.w)
            .iter()
            .all(|(_, _, tool)| tool == "echo" || !tool.starts_with("made-up")),
        "a shown name outside the catalog must never be stored"
    );
}
