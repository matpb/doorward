mod common;

use common::admin::{self, ServerSpec};
use common::client::TestClient;
use common::switches::{
    deny_tool, percent, post_switches, size_text, stored_definitions, stored_rows, switched_off,
    tool_rows,
};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::values::{account_csrf, live_db};
use common::world::World;
use rusqlite::params;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const RECONNECT: &str = "A client picks up a change when it reconnects or refreshes its tools.";
const NO_LIST: &str = "No tools listed yet. Connect a client to this server once.";
const SENDING: &str = r#"section#tools [data-server="s"] [data-sending]"#;

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

/// Saves `set` with `on` for bob on server `s`, and asserts the 303 back to the tools section.
async fn save(sc: &Scene, set: &str, on: &[&str]) {
    let page = post_switches(&sc.bob, "s", set, on).await;
    assert_eq!(page.status, 303, "the {set} post must be accepted");
    assert_eq!(
        page.location().as_deref(),
        Some("/account#tools"),
        "the {set} post must answer 303 to /account#tools"
    );
}

/// Replaces the stored definition of `name` on server `id` with JSON of exactly `bytes` bytes.
fn set_definition_size(sc: &Scene, name: &str, bytes: usize) {
    let empty = format!(r#"{{"name":"{name}","pad":""}}"#);
    let text = format!(
        r#"{{"name":"{name}","pad":"{}"}}"#,
        "x".repeat(bytes - empty.len())
    );
    let conn = live_db(&sc.w);
    let changed = conn
        .execute(
            "UPDATE tool_catalog SET definition = ?1 WHERE server_id = ?2 AND name = ?3",
            params![text, sc.id.parse::<i64>().expect("numeric id"), name],
        )
        .expect("the stored definition can be set");
    assert_eq!(changed, 1, "{name} must be a stored tool of server s");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_account_page_has_a_your_tools_section_with_a_heading() {
    let sc = start().await;
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.count(r#"section#tools[data-section="tools"]"#),
        1,
        "the account page must hold one Your tools section"
    );
    assert_eq!(
        page.text("section#tools h2").as_deref(),
        Some("Your tools"),
        "the section must be headed Your tools"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_assigned_server_gets_one_block_in_slug_order() {
    let sc = start().await;
    let (_a_up, a_id) = sc.w.upstream("a", UpstreamOptions::default()).await;
    sc.w.grant(BOB, &[sc.id.as_str(), a_id.as_str()]).await;
    let page = sc.bob.get("/account").await;
    let mut blocks = page.attrs("section#tools [data-server]", "data-server");
    blocks.dedup();
    assert_eq!(
        blocks,
        vec!["a", "s"],
        "bob must see one block per assigned server, in slug order"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_block_holds_one_form_that_posts_to_its_server() {
    let sc = start().await;
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.count(
            r#"section#tools [data-server="s"] form[method="post"][action="/account/tools/s"]"#
        ),
        1,
        "the block of server s must hold one form posting to /account/tools/s"
    );
    assert_eq!(
        page.count(r#"section#tools [data-server="s"] form input[name="csrf"]"#),
        1,
        "the form must carry the csrf field"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_allowed_tool_row_holds_its_state_checkbox_and_size_in_catalog_order() {
    let sc = start().await;
    let definitions = stored_definitions(&sc.w, &sc.id);
    let rows = tool_rows(&sc.bob, "s").await;
    let names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["echo", "search", "delete_db"],
        "the rows must follow the catalog order"
    );
    for (row, (name, definition)) in rows.iter().zip(&definitions) {
        assert_eq!(
            row.state, "on",
            "{name} must be on when nothing is switched off"
        );
        assert!(row.checked, "{name} must have its checkbox checked");
        assert_eq!(
            row.size,
            size_text(definition.len()),
            "{name} must show the size of its stored definition"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_row_is_off_and_unchecked() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let rows = tool_rows(&sc.bob, "s").await;
    let states: Vec<(&str, &str, bool)> = rows
        .iter()
        .map(|row| (row.name.as_str(), row.state.as_str(), row.checked))
        .collect();
    assert_eq!(
        states,
        vec![
            ("echo", "on", true),
            ("search", "off", false),
            ("delete_db", "on", true),
        ],
        "only search must be off and unchecked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sizes_are_bytes_below_a_kilobyte_and_one_decimal_kilobytes_from_1024_bytes_up() {
    let sc = start().await;
    set_definition_size(&sc, "echo", 1023);
    set_definition_size(&sc, "search", 1024);
    set_definition_size(&sc, "delete_db", 1843);
    let sizes: Vec<String> = tool_rows(&sc.bob, "s")
        .await
        .into_iter()
        .map(|row| row.size)
        .collect();
    assert_eq!(
        sizes,
        vec!["1023 B", "1.0 KB", "1.8 KB"],
        "1023 bytes is bytes, 1024 is 1.0 KB, 1843 is 1.8 KB"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_summary_gives_the_sent_size_against_all_and_a_share() {
    let sc = start().await;
    let sizes: Vec<usize> = stored_definitions(&sc.w, &sc.id)
        .iter()
        .map(|(_, definition)| definition.len())
        .collect();
    let all: usize = sizes.iter().sum();
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.text(SENDING),
        Some(format!("{} of {} (100%)", size_text(all), size_text(all))),
        "with every tool on the summary says all of it, at 100%"
    );
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let on = sizes[0] + sizes[2];
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.text(SENDING),
        Some(format!(
            "{} of {} ({}%)",
            size_text(on),
            size_text(all),
            percent(on, all)
        )),
        "with search off the summary counts only the tools left on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_summary_with_no_allowed_tool_reads_zero_of_zero_at_100_percent() {
    let sc = start().await;
    let all: usize = stored_definitions(&sc.w, &sc.id)
        .iter()
        .map(|(_, definition)| definition.len())
        .sum();
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.text(SENDING),
        Some(format!("{} of {} (100%)", size_text(all), size_text(all))),
        "while tools are allowed the summary must show their total"
    );
    let page = admin::add_rule(
        &sc.w.owner,
        "everyone",
        "deny",
        "server",
        Some(&sc.id),
        None,
    )
    .await;
    assert_eq!(
        page.status, 303,
        "the deny rule for server s must be accepted"
    );
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.text(SENDING),
        Some("0 B of 0 B (100%)".to_string()),
        "with no tool allowed the summary reads 0 B of 0 B at 100%"
    );
    assert_eq!(
        tool_rows(&sc.bob, "s").await.len(),
        0,
        "with no tool allowed the block lists no row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn save_stores_exactly_the_checked_tools_and_answers_303_to_the_tools_anchor() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["delete_db", "search"],
        "Save must switch off every allowed tool that is not checked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn all_off_switches_every_allowed_tool_off() {
    let sc = start().await;
    save(&sc, "all-off", &[]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["delete_db", "echo", "search"],
        "All off must switch every allowed tool off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn all_on_clears_the_switches_of_the_allowed_tools() {
    let sc = start().await;
    save(&sc, "all-off", &[]).await;
    save(&sc, "all-on", &[]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        Vec::<String>::new(),
        "All on must leave every tool on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_section_has_save_all_on_and_all_off_buttons_named_set() {
    let sc = start().await;
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.count(r#"section#tools [data-server="s"] button[name="set"]"#),
        3,
        "the block must hold three submit buttons named set"
    );
    for (value, label) in [
        ("chosen", "Save"),
        ("all-on", "All on"),
        ("all-off", "All off"),
    ] {
        assert_eq!(
            page.text(&format!(
                r#"section#tools [data-server="s"] button[name="set"][value="{value}"]"#
            ))
            .as_deref(),
            Some(label),
            "the button with value {value} must read {label}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn each_save_writes_one_tool_switches_row_with_the_off_count() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    let server: i64 = sc.id.parse().expect("numeric id");
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.id)).await;
    let switches: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_switches")
        .collect();
    assert_eq!(
        switches.len(),
        1,
        "one save must write one tool_switches row"
    );
    assert_eq!(switches[0].0.user, BOB, "the row must name bob");
    assert_eq!(switches[0].0.server, "s", "the row must name server s");
    assert_eq!(
        switches[0].1, "2 of 3 off",
        "the detail must count the tools off"
    );
    assert_eq!(
        stored_rows(&sc.w)
            .iter()
            .filter(|(_, s, _)| *s == server)
            .count(),
        2,
        "two tools off are stored for server s"
    );
    save(&sc, "all-on", &[]).await;
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.id)).await;
    let details: Vec<&str> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_switches")
        .map(|(_, detail)| detail.as_str())
        .collect();
    assert_eq!(
        details,
        vec!["0 of 3 off", "2 of 3 off"],
        "each save writes its own row with the count it left off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_tool_on_the_upstream_starts_on() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    sc.up.set_tools(&["echo", "search", "delete_db", "fresh"]);
    let page = admin::refresh_tools(&sc.w.owner, &sc.id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    let rows = tool_rows(&sc.bob, "s").await;
    let states: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.name.as_str(), row.state.as_str()))
        .collect();
    assert_eq!(
        states,
        vec![
            ("echo", "on"),
            ("search", "off"),
            ("delete_db", "on"),
            ("fresh", "on"),
        ],
        "a tool that appears later must start on, and the switch of search must stay"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "the new tool must not be stored as switched off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_tool_that_leaves_the_list_and_returns_is_still_off() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    sc.up.set_tools(&["echo", "delete_db"]);
    assert_eq!(
        admin::refresh_tools(&sc.w.owner, &sc.id).await.status,
        303,
        "refreshing the tools must answer 303"
    );
    let names: Vec<String> = tool_rows(&sc.bob, "s")
        .await
        .into_iter()
        .map(|row| row.name)
        .collect();
    assert_eq!(
        names,
        vec!["echo", "delete_db"],
        "a tool that left the list must leave the page"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "the switch of a tool that left the list must stay stored"
    );
    sc.up.set_tools(&["echo", "search", "delete_db"]);
    assert_eq!(
        admin::refresh_tools(&sc.w.owner, &sc.id).await.status,
        303,
        "refreshing the tools must answer 303"
    );
    let rows = tool_rows(&sc.bob, "s").await;
    let search = rows
        .iter()
        .find(|row| row.name == "search")
        .expect("search must be listed again");
    assert_eq!(search.state, "off", "search must be off when it returns");
    assert!(!search.checked, "search must be unchecked when it returns");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_user_page_marks_each_switched_off_tool_as_switched_off_by_the_user() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let view = admin::effective_tools(&sc.w.owner, &sc.bob_id).await;
    assert!(
        view.contains(&(
            "s".to_string(),
            "search".to_string(),
            "switched-off".to_string()
        )),
        "the admin page must give search the verdict switched-off, got {view:?}"
    );
    let page = sc.w.owner.get(&format!("/admin/users/{}", sc.bob_id)).await;
    let text = page
        .text(r#"[data-tool="search"][data-verdict="switched-off"]"#)
        .expect("the search row must carry data-verdict switched-off");
    assert!(
        text.contains("switched off by the user"),
        "the row must say switched off by the user, got {text:?}"
    );
    assert!(
        view.iter()
            .filter(|(_, tool, _)| tool == "echo")
            .all(|(_, _, verdict)| verdict != "switched-off"),
        "an on tool must not read switched-off, got {view:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigning_removes_the_switches_and_assigning_again_turns_every_tool_on() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "search must be switched off before the unassign"
    );
    let page = admin::assign(&sc.w.owner, &sc.bob_id, &[]).await;
    assert_eq!(page.status, 303, "unassigning must answer 303");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        Vec::<String>::new(),
        "unassigning must remove the switches of the server"
    );
    sc.w.grant(BOB, &[sc.id.as_str()]).await;
    let rows = tool_rows(&sc.bob, "s").await;
    assert!(
        rows.iter().all(|row| row.state == "on" && row.checked),
        "a server assigned again must start with every tool on, got {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_server_removes_its_switches() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    let server: i64 = sc.id.parse().expect("numeric id");
    assert_eq!(
        stored_rows(&sc.w)
            .iter()
            .filter(|(_, s, _)| *s == server)
            .count(),
        2,
        "two switches must be stored before the server is deleted"
    );
    let page = admin::delete_server(&sc.w.owner, &sc.id).await;
    assert_eq!(page.status, 303, "deleting the server must answer 303");
    assert_eq!(
        stored_rows(&sc.w)
            .iter()
            .filter(|(_, s, _)| *s == server)
            .count(),
        0,
        "deleting the server must remove its switches"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_user_removes_its_switches() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    let user: i64 = sc.bob_id.parse().expect("numeric id");
    assert_eq!(
        stored_rows(&sc.w)
            .iter()
            .filter(|(u, _, _)| *u == user)
            .count(),
        2,
        "two switches must be stored before the user is deleted"
    );
    let page = admin::user_action(&sc.w.owner, &sc.bob_id, "delete").await;
    assert_eq!(page.status, 303, "deleting the user must answer 303");
    assert_eq!(
        stored_rows(&sc.w)
            .iter()
            .filter(|(u, _, _)| *u == user)
            .count(),
        0,
        "deleting the user must remove its switches"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_whose_list_was_never_read_says_so_and_has_no_form() {
    let sc = start().await;
    let up = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = up.url();
    let never_id = admin::add_server(
        &sc.w.owner,
        &ServerSpec {
            name: "never",
            slug: "never",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    sc.w.grant(BOB, &[sc.id.as_str(), never_id.as_str()]).await;
    let page = sc.bob.get("/account").await;
    let block = page
        .text(r#"section#tools [data-server="never"]"#)
        .unwrap_or_default();
    assert!(
        block.contains(NO_LIST),
        "the block of a server never read must say {NO_LIST:?}, got {block:?}"
    );
    assert_eq!(
        page.count(r#"section#tools [data-server="never"] form"#),
        0,
        "a server never read must show no form"
    );
    assert_eq!(
        page.count(r#"section#tools [data-server="s"] form"#),
        1,
        "a server read before must still show its form"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_with_no_assigned_server_sees_no_your_tools_section() {
    let sc = start().await;
    let carol = sc.w.user(CAROL).await;
    assert_eq!(
        carol.get("/account").await.count("section#tools"),
        0,
        "a user with no assigned server must see no Your tools section"
    );
    assert_eq!(
        sc.bob.get("/account").await.count("section#tools"),
        1,
        "bob, who has server s, must see the section"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_the_rules_deny_is_not_shown_and_not_counted() {
    let sc = start().await;
    let names: Vec<String> = tool_rows(&sc.bob, "s")
        .await
        .into_iter()
        .map(|row| row.name)
        .collect();
    assert_eq!(
        names,
        vec!["echo", "search", "delete_db"],
        "before the rule every tool is shown"
    );
    deny_tool(&sc.w, "everyone", &sc.id, "delete_db").await;
    let names: Vec<String> = tool_rows(&sc.bob, "s")
        .await
        .into_iter()
        .map(|row| row.name)
        .collect();
    assert_eq!(
        names,
        vec!["echo", "search"],
        "a denied tool must not be shown"
    );
    let sizes: Vec<usize> = stored_definitions(&sc.w, &sc.id)
        .iter()
        .take(2)
        .map(|(_, definition)| definition.len())
        .collect();
    let allowed = sizes[0] + sizes[1];
    let page = sc.bob.get("/account").await;
    assert_eq!(
        page.text(SENDING),
        Some(format!(
            "{} of {} (100%)",
            size_text(allowed),
            size_text(allowed)
        )),
        "the summary must not count the denied tool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_with_an_unknown_set_value_answers_400_and_stores_nothing() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    let stored = stored_rows(&sc.w);
    let page = post_switches(&sc.bob, "s", "invert", &["echo"]).await;
    assert_eq!(
        page.status, 400,
        "a set value other than the three must answer 400"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("error"),
        "a set value other than the three must show the error page"
    );
    assert_eq!(
        stored_rows(&sc.w),
        stored,
        "a refused set value must store nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_leaves_the_rows_of_tools_no_longer_listed_as_they_are() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    sc.up.set_tools(&["echo", "delete_db"]);
    assert_eq!(
        admin::refresh_tools(&sc.w.owner, &sc.id).await.status,
        303,
        "refreshing the tools must answer 303"
    );
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "a save must leave the row of a tool no longer listed as it is"
    );
    save(&sc, "all-on", &[]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "All on must leave the row of a tool no longer listed as it is"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_section_says_a_client_picks_up_a_change_on_reconnect() {
    let sc = start().await;
    let page = sc.bob.get("/account").await;
    assert!(
        page.text("section#tools")
            .is_some_and(|text| text.contains(RECONNECT)),
        "the section must say {RECONNECT:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_password_change_still_shows_your_tools_with_bobs_rows() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let csrf = account_csrf(&sc.bob).await;
    let page = sc
        .bob
        .post(
            "/account/password",
            &[
                ("csrf", csrf.as_str()),
                ("current_password", "not-the-current-password"),
                ("new_password", "a-new-password-123"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a wrong current password must be refused with 400"
    );
    assert_eq!(
        page.count(r#"section#tools[data-section="tools"]"#),
        1,
        "the refused account page must hold the Your tools section"
    );
    assert_eq!(
        page.attrs(r#"section#tools [data-tool]"#, "data-tool"),
        vec!["echo", "search", "delete_db"],
        "the refused account page must list bob's tools in catalog order"
    );
    assert_eq!(
        page.attrs(
            r#"section#tools [data-tool][data-state="off"]"#,
            "data-tool"
        ),
        vec!["search"],
        "the refused account page must show bob's switches"
    );
}
