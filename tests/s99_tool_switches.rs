mod common;

use common::admin::{self, ServerSpec};
use common::client::TestClient;
use common::switches::{
    deny_tool, percent, post_switches, post_switches_with_shown, size_text, stored_definitions,
    stored_rows, switched_off, tool_rows,
};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::values::{account_csrf, live_db};
use common::world::World;
use rusqlite::params;
use scraper::{ElementRef, Html, Selector};

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

/// Saves `set` with `on` for bob on server `s`, and asserts the 303 back to the saved server's section.
async fn save(sc: &Scene, set: &str, on: &[&str]) {
    let page = post_switches(&sc.bob, "s", set, on).await;
    assert_eq!(page.status, 303, "the {set} post must be accepted");
    assert_eq!(
        page.location().as_deref(),
        Some("/account?saved=s#tools"),
        "the {set} post must answer 303 to /account?saved=s#tools"
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
async fn sizes_are_bytes_below_1000_and_one_decimal_kilobytes_from_1000_bytes_up() {
    let sc = start().await;
    set_definition_size(&sc, "echo", 999);
    set_definition_size(&sc, "search", 1000);
    set_definition_size(&sc, "delete_db", 1843);
    let sizes: Vec<String> = tool_rows(&sc.bob, "s")
        .await
        .into_iter()
        .map(|row| row.size)
        .collect();
    assert_eq!(
        sizes,
        vec!["999 B", "1.0 KB", "1.8 KB"],
        "999 bytes is bytes, 1000 is 1.0 KB, 1843 is 1.8 KB"
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
async fn saving_the_same_assignments_again_keeps_the_switches_of_the_kept_server() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "search must be switched off before the assignments are saved"
    );
    let page = admin::assign(&sc.w.owner, &sc.bob_id, &[sc.id.as_str()]).await;
    assert_eq!(
        page.status, 303,
        "saving the same assignments must answer 303"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "saving the same set of servers must keep the switch of search"
    );
    let (_a_up, a_id) = sc.w.upstream("a", UpstreamOptions::default()).await;
    let page = admin::assign(&sc.w.owner, &sc.bob_id, &[sc.id.as_str(), a_id.as_str()]).await;
    assert_eq!(page.status, 303, "adding a server must answer 303");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "adding another server must keep the switch of search"
    );
    let rows = tool_rows(&sc.bob, "s").await;
    let search = rows
        .iter()
        .find(|row| row.name == "search")
        .expect("search must be listed");
    assert_eq!(search.state, "off", "search must still be off for bob");
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
        "a chosen save must leave the row of a tool no longer listed as it is"
    );
    save(&sc, "all-off", &[]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["delete_db", "echo", "search"],
        "All off must leave the row of a tool no longer listed as it is"
    );
    save(&sc, "all-on", &[]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        Vec::<String>::new(),
        "All on must remove the rows of tools no longer listed too"
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

/// The first element `css` names in `doc`; panics when no element matches.
fn first<'a>(doc: &'a Html, css: &str) -> ElementRef<'a> {
    doc.select(&Selector::parse(css).expect("selector"))
        .next()
        .unwrap_or_else(|| panic!("{css} must be on the page"))
}

/// Every element `css` names in `doc`, in document order.
fn every<'a>(doc: &'a Html, css: &str) -> Vec<ElementRef<'a>> {
    doc.select(&Selector::parse(css).expect("selector"))
        .collect()
}

/// An element as its name and its classes, such as `span.tool-size`.
fn shape(element: ElementRef) -> String {
    let mut text = element.value().name().to_owned();
    for class in element.value().classes() {
        text.push('.');
        text.push_str(class);
    }
    text
}

/// The shapes of the element children of `element`, in document order.
fn child_shapes(element: ElementRef) -> Vec<String> {
    element
        .children()
        .filter_map(ElementRef::wrap)
        .map(shape)
        .collect()
}

/// The text of `element`, markup removed.
fn text_of(element: ElementRef) -> String {
    element.text().collect()
}

/// The rect widths inside each bar of server `s`'s rows, in row order; a bar with no rect has none.
fn bar_rects(body: &str) -> Vec<Vec<String>> {
    let doc = Html::parse_document(body);
    every(&doc, r#"section[data-server="s"] svg.tool-bar"#)
        .into_iter()
        .map(|bar| {
            bar.children()
                .filter_map(ElementRef::wrap)
                .filter_map(|rect| rect.value().attr("width").map(str::to_owned))
                .collect()
        })
        .collect()
}

/// The width of the rule under the summary of server `s`.
fn server_rule(body: &str) -> String {
    let doc = Html::parse_document(body);
    first(&doc, r#"section[data-server="s"] > svg.sending-bar > rect"#)
        .value()
        .attr("width")
        .expect("the rule of server s must have a width")
        .to_owned()
}

/// Sets the stored sizes of echo, search and delete_db to 1000, 3000 and `delete_db` bytes.
fn set_sizes(sc: &Scene, delete_db: usize) {
    set_definition_size(sc, "echo", 1000);
    set_definition_size(sc, "search", 3000);
    set_definition_size(sc, "delete_db", delete_db);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_section_markup_follows_the_design() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let page = sc.bob.get("/account").await;
    let doc = Html::parse_document(&page.body);
    assert_eq!(
        child_shapes(first(&doc, "section#tools")),
        vec!["div.part-head", "div.part-body"],
        "the section is a head and a body"
    );
    assert_eq!(
        child_shapes(first(&doc, "section#tools > div.part-head")),
        vec!["h2", "p", "p.muted"],
        "the head holds the title, the sentence and the reconnect sentence"
    );
    let block = first(
        &doc,
        r#"section#tools > div.part-body > section[data-server="s"]"#,
    );
    assert_eq!(shape(block), "section.flow.narrow");
    assert_eq!(
        child_shapes(block),
        vec!["h3", "p.sending", "svg.sending-bar", "details.toolbox"],
        "a block is the heading, the sentence, the rule, then the disclosure"
    );
    assert_eq!(
        child_shapes(first(&doc, r#"section[data-server="s"] > h3"#)),
        vec!["span.block-name", "span.count"],
        "the heading holds the name and the count"
    );
    assert_eq!(
        text_of(first(&doc, "section#tools h3 > span.block-name")),
        "s"
    );
    assert_eq!(
        text_of(first(&doc, "section#tools h3 > span.count")),
        "2 of 3 on",
        "the count reads the tools on, of the tools listed"
    );
    let sending = first(&doc, r#"section[data-server="s"] > p.sending"#);
    assert_eq!(child_shapes(sending), vec!["strong"]);
    assert_eq!(
        text_of(sending),
        format!("Sending {}", page.text(SENDING).unwrap_or_default()),
        "the sentence reads Sending and the summary figures"
    );
    assert_eq!(
        every(
            &doc,
            r#"section[data-server="s"] > p.sending + svg.sending-bar > rect"#
        )
        .len(),
        1,
        "the rule of the block follows its sentence"
    );
    let details = first(&doc, r#"section[data-server="s"] > details.toolbox"#);
    assert!(
        details.value().attr("open").is_none(),
        "a list is closed on a page no save has led to"
    );
    assert_eq!(child_shapes(details), vec!["summary", "form.tools-form"]);
    assert_eq!(
        child_shapes(first(&doc, "details.toolbox > summary"))
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["span.toolbox-open"]
    );
    assert_eq!(
        text_of(first(&doc, "details.toolbox > summary > span.toolbox-open")),
        "Choose tools"
    );
    let form = first(&doc, "form.tools-form");
    assert_eq!(form.value().attr("method"), Some("post"));
    assert_eq!(form.value().attr("action"), Some("/account/tools/s"));
    assert_eq!(
        child_shapes(form),
        vec![
            "input",
            "input",
            "input",
            "input",
            "div.tool-cols",
            "ul.tool-list",
            "div.tools-foot"
        ],
        "the form is the csrf field, one shown field per row, the head row, the list and the foot"
    );
    let heads: Vec<String> = every(&doc, "div.tool-cols > span")
        .into_iter()
        .map(text_of)
        .collect();
    assert_eq!(heads, vec!["On", "Tool", "Size"]);
    let list = first(&doc, "ul.tool-list");
    assert_eq!(list.value().attr("aria-labelledby"), Some("tools-s-title"));
    assert_eq!(
        first(&doc, "section[data-server=\"s\"] > h3")
            .value()
            .attr("id"),
        Some("tools-s-title")
    );
    let rows = every(&doc, "ul.tool-list > li.tool");
    let expected = [
        ("echo", "on", true),
        ("search", "off", false),
        ("delete_db", "on", true),
    ];
    assert_eq!(rows.len(), expected.len(), "one row per listed tool");
    for (index, (row, (name, state, checked))) in rows.iter().zip(expected).enumerate() {
        let (number, id, size_id) = (
            index + 1,
            format!("tool-s-{}", index + 1),
            format!("tool-s-{}-size", index + 1),
        );
        assert_eq!(shape(*row), "li.tool");
        assert_eq!(row.value().attr("data-tool"), Some(name));
        assert_eq!(row.value().attr("data-state"), Some(state));
        assert_eq!(
            child_shapes(*row),
            vec!["input", "label", "span.tool-size", "svg.tool-bar"],
            "row {number} holds its box, name, size and bar as siblings in that order"
        );
        let parts: Vec<ElementRef> = row.children().filter_map(ElementRef::wrap).collect();
        let (input, label, size, bar) = (parts[0], parts[1], parts[2], parts[3]);
        assert_eq!(input.value().attr("type"), Some("checkbox"));
        assert_eq!(input.value().attr("name"), Some("on"));
        assert_eq!(input.value().attr("value"), Some(name));
        assert_eq!(input.value().attr("id"), Some(id.as_str()));
        assert_eq!(input.value().attr("checked").is_some(), checked);
        assert_eq!(
            input.value().attr("aria-describedby"),
            Some(size_id.as_str())
        );
        assert_eq!(label.value().attr("for"), Some(id.as_str()));
        assert_eq!(size.value().attr("id"), Some(size_id.as_str()));
        assert!(size.value().attr("data-size").is_some());
        assert_eq!(bar.value().attr("width"), Some("100%"));
        assert_eq!(bar.value().attr("height"), Some("2"));
    }
    let foot = first(&doc, "div.tools-foot");
    assert_eq!(
        child_shapes(foot),
        vec!["button", "span.tools-unsaved", "div.row-actions"],
        "the foot is Save, the unsaved line, then the two quiet actions"
    );
    assert!(
        first(&doc, "div.tools-foot > span.tools-unsaved")
            .value()
            .attr("hidden")
            .is_some(),
        "the unsaved line stays hidden until a box differs"
    );
    let submits = every(&doc, r#"form.tools-form button[name="set"]"#);
    assert_eq!(
        submits
            .iter()
            .map(|b| b.value().attr("value"))
            .collect::<Vec<_>>(),
        vec![Some("chosen"), Some("all-on"), Some("all-off")],
        "Save is the first submit button in the form"
    );
    assert_eq!(
        submits.iter().map(|b| text_of(*b)).collect::<Vec<_>>(),
        vec!["Save", "All on", "All off"]
    );
    assert_eq!(
        every(&doc, "div.row-actions > details.row-confirm").len(),
        2,
        "on a mixed list All on and All off are the two questions of the foot"
    );
    assert_eq!(
        every(&doc, r#"section#tools div.notice"#).len(),
        0,
        "a page no save has led to shows no notice"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_bar_is_its_bytes_over_the_largest_tool_to_three_decimals() {
    let sc = start().await;
    set_sizes(&sc, 60);
    let page = sc.bob.get("/account").await;
    assert_eq!(
        bar_rects(&page.body),
        vec![
            vec!["33.333%".to_owned()],
            vec!["100.000%".to_owned()],
            vec!["2.000%".to_owned()],
        ],
        "a bar is the tool's bytes over the largest tool's, to three decimals; 60 of 3000 is exactly 2%"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_under_two_percent_of_the_largest_keeps_its_bar_empty() {
    let sc = start().await;
    set_sizes(&sc, 59);
    let page = sc.bob.get("/account").await;
    assert_eq!(
        bar_rects(&page.body),
        vec![
            vec!["33.333%".to_owned()],
            vec!["100.000%".to_owned()],
            Vec::<String>::new(),
        ],
        "59 of 3000 is under 2%: its svg stays and no rect is written"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_rule_is_the_bytes_on_over_all_bytes_and_zero_when_none_is_on() {
    let sc = start().await;
    set_sizes(&sc, 60);
    let page = sc.bob.get("/account").await;
    assert_eq!(
        server_rule(&page.body),
        "100.000%",
        "all on is the whole rule"
    );
    save(&sc, "chosen", &["echo"]).await;
    let page = sc.bob.get("/account").await;
    assert_eq!(
        server_rule(&page.body),
        "24.631%",
        "1000 of 4060 bytes is 24.631%"
    );
    assert_eq!(
        page.text(SENDING).as_deref(),
        Some("1.0 KB of 4.0 KB (25%)"),
        "the sentence beside the rule gives the same bytes"
    );
    save(&sc, "all-off", &[]).await;
    let page = sc.bob.get("/account").await;
    assert_eq!(server_rule(&page.body), "0%", "zero stays zero");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_name_breaks_where_the_design_says_and_keeps_its_raw_text() {
    let sc = start().await;
    let names = [
        "getHTTPResponse",
        "bitbucket_get_pipeline_step_log",
        "getRepositoryPullRequestCommentThreads",
    ];
    let breaks = [
        "get<wbr>HTTPResponse",
        "bitbucket_<wbr>get_<wbr>pipeline_<wbr>step_<wbr>log",
        "get<wbr>Repository<wbr>Pull<wbr>Request<wbr>Comment<wbr>Threads",
    ];
    sc.up.set_tools(&names);
    assert_eq!(
        admin::refresh_tools(&sc.w.owner, &sc.id).await.status,
        303,
        "refreshing the tools must answer 303"
    );
    let page = sc.bob.get("/account").await;
    let doc = Html::parse_document(&page.body);
    let codes = every(&doc, r#"section[data-server="s"] label > code"#);
    let boxes = every(&doc, r#"section[data-server="s"] input[name="on"]"#);
    let rows = every(&doc, r#"section[data-server="s"] li.tool"#);
    assert_eq!(codes.len(), names.len());
    for index in 0..names.len() {
        assert_eq!(
            codes[index].inner_html(),
            breaks[index],
            "the name {} must break at the design's points",
            names[index]
        );
        assert_eq!(
            text_of(codes[index]),
            names[index],
            "the label's text is the raw name"
        );
        assert_eq!(rows[index].value().attr("data-tool"), Some(names[index]));
        assert_eq!(boxes[index].value().attr("value"), Some(names[index]));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_leads_to_a_notice_and_opens_only_the_list_of_its_server() {
    let sc = start().await;
    let (_a_up, a_id) = sc.w.upstream("a", UpstreamOptions::default()).await;
    sc.w.grant(BOB, &[sc.id.as_str(), a_id.as_str()]).await;
    let page = post_switches(&sc.bob, "s", "chosen", &["echo"]).await;
    assert_eq!(page.status, 303, "the save must be accepted");
    let location = page.location().expect("the save must name where it leads");
    assert_eq!(location, "/account?saved=s#tools");
    let page = sc.bob.get(&location).await;
    let doc = Html::parse_document(&page.body);
    assert_eq!(
        text_of(first(
            &doc,
            r#"section#tools [data-server="s"] > div.notice[data-notice="ok"] > p"#
        )),
        "Tools saved for s.",
        "the notice names the saved server"
    );
    assert_eq!(
        every(&doc, "section#tools div.notice").len(),
        1,
        "one notice in the section"
    );
    assert_eq!(
        every(&doc, r#"section#tools [data-server="s"] details[open]"#).len(),
        1,
        "the saved server's list is open"
    );
    assert_eq!(
        every(&doc, r#"section#tools [data-server="a"] details[open]"#).len(),
        0,
        "the other server's list stays closed"
    );
    assert_eq!(
        every(&doc, r#"section#tools [data-server="a"] div.notice"#).len(),
        0,
        "the other server gets no notice"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_query_that_names_no_assigned_server_shows_nothing() {
    let sc = start().await;
    let (_z_up, _z_id) = sc.w.upstream("z", UpstreamOptions::default()).await;
    for query in ["z", "nosuch", "", "z&saved=s"] {
        let page = sc.bob.get(&format!("/account?saved={query}")).await;
        assert_eq!(
            page.status, 200,
            "{query:?} must not change the page's answer"
        );
        let doc = Html::parse_document(&page.body);
        assert_eq!(
            every(&doc, "section#tools div.notice").len(),
            0,
            "the query {query:?} must show no notice"
        );
        assert_eq!(
            every(&doc, "section#tools details[open]").len(),
            0,
            "the query {query:?} must open no list"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_saved_notice_escapes_the_server_name() {
    let sc = start().await;
    let up = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = up.url();
    let id = admin::add_server(
        &sc.w.owner,
        &ServerSpec {
            name: "<i>Tools</i> & more",
            slug: "markup-name",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    sc.w.grant(BOB, &[id.as_str()]).await;
    let page = sc.bob.get("/account?saved=markup-name").await;
    assert!(
        !page.body.contains("<i>Tools</i>"),
        "the server name must not reach the page as markup"
    );
    assert!(
        page.body
            .contains("Tools saved for &lt;i&gt;Tools&lt;/i&gt; &amp; more."),
        "the notice must hold the name escaped"
    );
    let doc = Html::parse_document(&page.body);
    assert_eq!(
        text_of(first(
            &doc,
            r#"section#tools [data-server="markup-name"] div.notice > p"#
        )),
        "Tools saved for <i>Tools</i> & more."
    );
}

/// The names the account page lists for server `s`, in row order, as the form carries them.
fn shown_names(body: &str) -> Vec<String> {
    let doc = Html::parse_document(body);
    every(
        &doc,
        r#"section#tools [data-server="s"] input[name="shown"]"#,
    )
    .into_iter()
    .filter_map(|input| input.value().attr("value").map(str::to_owned))
    .collect()
}

/// The number of activity rows of kind tool_switches that bob's saves on server `s` wrote.
async fn switch_rows(sc: &Scene) -> usize {
    admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.id))
        .await
        .iter()
        .filter(|(row, _)| row.kind == "tool_switches")
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_save_changes_only_the_tools_the_page_showed() {
    let sc = start().await;
    let old = sc.bob.get("/account").await;
    let shown = shown_names(&old.body);
    assert_eq!(shown, vec!["echo", "search", "delete_db"]);
    sc.up.set_tools(&["echo", "search", "delete_db", "fresh"]);
    let tokens = sc.w.token(&sc.bob, "s").await;
    let client = sc.w.session_mcp("s", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    assert!(
        client
            .list_tools()
            .await
            .tool_names()
            .contains(&"fresh".to_string()),
        "a client that lists sees the tool that entered the catalog"
    );
    let shown: Vec<&str> = shown.iter().map(String::as_str).collect();
    let page =
        post_switches_with_shown(&sc.bob, "s", "chosen", &["echo", "delete_db"], &shown).await;
    assert_eq!(page.status, 303, "the stale save must be accepted");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["search"],
        "fresh was not on the page, so the save must leave it as it is"
    );
    assert!(
        client
            .list_tools()
            .await
            .tool_names()
            .contains(&"fresh".to_string()),
        "the tool that the stale save did not show stays listed to the client"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_off_count_of_a_save_covers_the_tools_the_page_did_not_show() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "search"]).await;
    let page = post_switches_with_shown(&sc.bob, "s", "chosen", &[], &["echo"]).await;
    assert_eq!(page.status, 303, "the partial save must be accepted");
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["delete_db", "echo"],
        "echo goes off, and the tools that were not shown stay as they were"
    );
    let rows = admin::activity_with_details(&sc.w.owner, Some(&sc.bob_id), Some(&sc.id)).await;
    let details: Vec<&str> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_switches")
        .map(|(_, detail)| detail.as_str())
        .collect();
    assert_eq!(
        details,
        vec!["2 of 3 off", "1 of 3 off"],
        "the newest row counts every allowed tool, shown or not"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unlisted_switches_are_kept_to_the_1000_most_recently_set() {
    let sc = start().await;
    let bob: i64 = sc.bob_id.parse().expect("numeric id");
    let server: i64 = sc.id.parse().expect("numeric id");
    let conn = live_db(&sc.w);
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .expect("foreign keys on");
    for n in 0..1005i64 {
        conn.execute(
            "INSERT INTO tool_switches (user_id, server_id, tool, set_at) VALUES (?1, ?2, ?3, ?4)",
            params![bob, server, format!("gone-{n:04}"), n + 1],
        )
        .expect("an unlisted row can be seeded");
    }
    save(&sc, "chosen", &["echo"]).await;
    let mut statement = conn
        .prepare(
            "SELECT tool FROM tool_switches WHERE user_id = ?1 AND server_id = ?2 \
             AND tool LIKE 'gone-%' ORDER BY set_at",
        )
        .expect("the query prepares");
    let kept: Vec<String> = statement
        .query_map(params![bob, server], |row| row.get(0))
        .expect("the query runs")
        .collect::<rusqlite::Result<_>>()
        .expect("the rows read");
    let newest: Vec<String> = (5..1005).map(|n| format!("gone-{n:04}")).collect();
    assert_eq!(
        kept, newest,
        "exactly the 1000 most recently set unlisted rows remain"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_for_a_pair_with_no_assignment_is_refused_by_the_database() {
    let sc = start().await;
    let (_a_up, a_id) = sc.w.upstream("a", UpstreamOptions::default()).await;
    let bob: i64 = sc.bob_id.parse().expect("numeric id");
    let other: i64 = a_id.parse().expect("numeric id");
    let conn = live_db(&sc.w);
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .expect("foreign keys on");
    let err = conn
        .execute(
            "INSERT INTO tool_switches (user_id, server_id, tool, set_at) VALUES (?1, ?2, 'echo', 1)",
            params![bob, other],
        )
        .expect_err("a switch for a server bob is not assigned to must be refused");
    assert!(
        err.to_string().contains("FOREIGN KEY constraint failed"),
        "the refusal must be the foreign key, got {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_that_changes_nothing_writes_no_row() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    assert_eq!(switch_rows(&sc).await, 1, "the first save changes rows");
    save(&sc, "chosen", &["echo"]).await;
    assert_eq!(
        switch_rows(&sc).await,
        1,
        "a save that leaves every row as it is writes no activity row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_61st_changing_save_in_an_hour_stores_its_switches_and_writes_no_row() {
    let sc = start().await;
    for n in 0..61 {
        let on: &[&str] = if n % 2 == 0 {
            &["echo"]
        } else {
            &["echo", "search", "delete_db"]
        };
        let page = post_switches(&sc.bob, "s", "chosen", on).await;
        assert_eq!(page.status, 303, "save {n} must be accepted");
    }
    assert_eq!(
        switch_rows(&sc).await,
        60,
        "the 61st changing save in the hour writes no row"
    );
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["delete_db", "search"],
        "the 61st save still stores its switches"
    );
}

/// The elements under `element` that `css` names, in document order.
fn within<'a>(element: ElementRef<'a>, css: &str) -> Vec<ElementRef<'a>> {
    element
        .select(&Selector::parse(css).expect("selector"))
        .collect()
}

/// The sentence of each question in the foot of server `s`, in the order the foot holds them.
fn question_sentences(body: &str) -> Vec<String> {
    let doc = Html::parse_document(body);
    every(
        &doc,
        r#"section#tools [data-server="s"] div.tools-foot > div.row-actions > details p"#,
    )
    .into_iter()
    .map(text_of)
    .collect()
}

/// The text of the notice that a save of server `s` leads to.
async fn notice_of_s(sc: &Scene) -> Option<String> {
    sc.bob
        .get("/account?saved=s")
        .await
        .text(r#"section#tools [data-server="s"] > div.notice[data-notice="ok"] > p"#)
}

/// Asserts that the foot of server `s` in `body` is the plain one: no `data-bulk`, two submits and no question.
fn assert_plain_foot(body: &str, state: &str) {
    let doc = Html::parse_document(body);
    let foot = first(&doc, r#"section#tools [data-server="s"] div.tools-foot"#);
    assert_eq!(
        foot.value().attr("data-bulk"),
        None,
        "{state}: the foot must not carry data-bulk"
    );
    let actions = within(foot, "div.row-actions > button.row-action");
    assert_eq!(
        actions
            .iter()
            .map(|button| button.value().attr("value"))
            .collect::<Vec<_>>(),
        vec![Some("all-on"), Some("all-off")],
        "{state}: the foot holds All on and All off as two plain submits"
    );
    assert_eq!(
        actions
            .iter()
            .map(|button| text_of(*button))
            .collect::<Vec<_>>(),
        vec!["All on", "All off"],
        "{state}: the two plain submits read All on and All off"
    );
    assert!(
        within(foot, "details").is_empty(),
        "{state}: the foot holds no question"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_list_foot_asks_before_all_on_or_all_off() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let page = sc.bob.get("/account").await;
    let doc = Html::parse_document(&page.body);
    let foot = first(&doc, r#"section#tools [data-server="s"] div.tools-foot"#);
    assert_eq!(
        foot.value().attr("data-bulk"),
        Some("ask"),
        "a list with some tools on and some off must mark its foot data-bulk ask"
    );
    let questions = within(foot, "div.row-actions > details");
    assert_eq!(
        questions.len(),
        2,
        "All on and All off must each be a disclosure in the row actions"
    );
    let expected = [
        (
            "all-on",
            "All on",
            "Saves all 3 tools as on right away. 1 is saved as off. Unsaved changes are dropped.",
            "1 is saved as off.",
        ),
        (
            "all-off",
            "All off",
            "Saves all 3 tools as off right away. 2 are saved as on. Unsaved changes are dropped.",
            "2 are saved as on.",
        ),
    ];
    for (question, (value, label, sentence, second)) in questions.into_iter().zip(expected) {
        assert_eq!(
            question.value().attr("name"),
            Some("tools-s-all"),
            "{label} must share the group name of its server"
        );
        assert!(
            question.value().attr("open").is_none(),
            "{label} must be closed on arrival"
        );
        let summaries = within(question, "summary");
        assert_eq!(summaries.len(), 1, "{label} must have one summary");
        assert_eq!(
            text_of(summaries[0]),
            label,
            "the summary must read {label}"
        );
        let sentences = within(question, "p");
        assert_eq!(sentences.len(), 1, "{label} must say one sentence");
        assert_eq!(
            text_of(sentences[0]),
            sentence,
            "the sentence of {label} must give the tool count and the choices replaced"
        );
        let choices = within(sentences[0], "span.whole");
        assert_eq!(
            choices.len(),
            1,
            "{label} must set its choices in span.whole"
        );
        let unsaved = within(sentences[0], "span.when-unsaved");
        assert_eq!(unsaved.len(), 1, "{label} must hold one span.when-unsaved");
        assert_eq!(
            text_of(unsaved[0]),
            "Unsaved changes are dropped.",
            "the span.when-unsaved of {label} must say that unsaved changes are dropped"
        );
        assert_eq!(
            text_of(choices[0]),
            second,
            "the span.whole of {label} must hold its second sentence"
        );
        let submits = within(question, r#"button[name="set"]"#);
        assert_eq!(submits.len(), 1, "{label} must hold one submit named set");
        assert_eq!(
            submits[0].value().attr("value"),
            Some(value),
            "the submit of {label} must carry its value"
        );
        assert_eq!(
            text_of(submits[0]),
            label,
            "the submit of {label} must read {label}"
        );
    }
    assert_eq!(
        page.count(r#"section#tools [data-server="s"] div.row-actions > details.row-confirm button[name="set"]"#),
        2,
        "both bulk submits must sit inside a question"
    );
    assert_eq!(
        page.count(r#"section#tools [data-server="s"] button[name="set"][value^="all-"]"#),
        2,
        "no bulk submit may sit outside a question"
    );
    assert_eq!(page.count("form form"), 0, "no form may sit inside a form");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_all_on_or_all_off_list_keeps_the_plain_foot() {
    let sc = start().await;
    assert_plain_foot(&sc.bob.get("/account").await.body, "all on");
    save(&sc, "all-off", &[]).await;
    assert_plain_foot(&sc.bob.get("/account").await.body, "all off");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_list_puts_save_first_so_that_enter_saves() {
    let sc = start().await;
    save(&sc, "chosen", &["echo", "delete_db"]).await;
    let page = sc.bob.get("/account").await;
    let doc = Html::parse_document(&page.body);
    let buttons = every(&doc, "form.tools-form button");
    assert_eq!(
        buttons
            .iter()
            .map(|b| b.value().attr("value"))
            .collect::<Vec<_>>(),
        vec![Some("chosen"), Some("all-on"), Some("all-off")],
        "on a mixed list Save must be the first button of the form, ahead of both bulk buttons"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_tool_is_left_out_of_the_questions_and_the_notice() {
    let sc = start().await;
    deny_tool(&sc.w, "everyone", &sc.id, "delete_db").await;
    save(&sc, "chosen", &["echo"]).await;
    assert_eq!(
        question_sentences(&sc.bob.get("/account").await.body),
        vec![
            "Saves all 2 tools as on right away. 1 is saved as off. Unsaved changes are dropped.",
            "Saves all 2 tools as off right away. 1 is saved as on. Unsaved changes are dropped.",
        ],
        "the questions must count the two tools the user may use, not the denied one"
    );
    save(&sc, "all-on", &[]).await;
    assert_eq!(
        notice_of_s(&sc).await.as_deref(),
        Some("All 2 s tools are on."),
        "the notice must count the two tools shown, not the denied one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_list_of_62_tools_with_39_on_says_the_brief_sentences() {
    let sc = start().await;
    let names: Vec<String> = (0..62).map(|n| format!("tool_{n:02}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    sc.up.set_tools(&names);
    let page = admin::refresh_tools(&sc.w.owner, &sc.id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    save(&sc, "chosen", &names[..39]).await;
    assert_eq!(
        question_sentences(&sc.bob.get("/account").await.body),
        vec![
            "Saves all 62 tools as on right away. 23 are saved as off. Unsaved changes are dropped.",
            "Saves all 62 tools as off right away. 39 are saved as on. Unsaved changes are dropped.",
        ],
        "62 rows with 39 on must read as the design's example"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_list_of_62_tools_with_one_off_says_one_switched_off_comes_back() {
    let sc = start().await;
    let names: Vec<String> = (0..62).map(|n| format!("tool_{n:02}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    sc.up.set_tools(&names);
    let page = admin::refresh_tools(&sc.w.owner, &sc.id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    save(&sc, "chosen", &names[..61]).await;
    assert_eq!(
        question_sentences(&sc.bob.get("/account").await.body),
        vec![
            "Saves all 62 tools as on right away. 1 is saved as off. Unsaved changes are dropped.",
            "Saves all 62 tools as off right away. 61 are saved as on. Unsaved changes are dropped.",
        ],
        "one tool off must read as one switched off that comes back"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_list_with_one_choice_says_one_choice() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    assert_eq!(
        question_sentences(&sc.bob.get("/account").await.body),
        vec![
            "Saves all 3 tools as on right away. 2 are saved as off. Unsaved changes are dropped.",
            "Saves all 3 tools as off right away. 1 is saved as on. Unsaved changes are dropped.",
        ],
        "one tool on must read as one that goes off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn all_off_on_a_mixed_list_still_switches_every_tool_off() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    save(&sc, "all-off", &[]).await;
    assert_eq!(
        switched_off(&sc.w, &sc.bob_id, &sc.id),
        vec!["delete_db", "echo", "search"],
        "All off from a mixed list must still switch every allowed tool off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_says_the_state_it_left_a_mix_all_off_or_all_on() {
    let sc = start().await;
    save(&sc, "chosen", &["echo"]).await;
    assert_eq!(
        notice_of_s(&sc).await.as_deref(),
        Some("Tools saved for s."),
        "a save that leaves a mix says Tools saved for s"
    );
    save(&sc, "all-off", &[]).await;
    assert_eq!(
        notice_of_s(&sc).await.as_deref(),
        Some("All 3 s tools are off."),
        "All off says all tools are off"
    );
    save(&sc, "all-on", &[]).await;
    assert_eq!(
        notice_of_s(&sc).await.as_deref(),
        Some("All 3 s tools are on."),
        "All on says all tools are on"
    );
    save(&sc, "chosen", &["echo", "search", "delete_db"]).await;
    assert_eq!(
        notice_of_s(&sc).await.as_deref(),
        Some("All 3 s tools are on."),
        "a chosen save that leaves every tool on says all tools are on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_of_one_tool_keeps_the_plural_in_its_notice() {
    let sc = start().await;
    let (demo_up, demo) = sc.w.upstream("demo", UpstreamOptions::default()).await;
    demo_up.set_tools(&["only"]);
    let page = admin::refresh_tools(&sc.w.owner, &demo).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    sc.w.grant(BOB, &[sc.id.as_str(), demo.as_str()]).await;
    let page = post_switches(&sc.bob, "demo", "all-off", &[]).await;
    assert_eq!(page.status, 303, "All off on demo must be accepted");
    let page = sc.bob.get("/account?saved=demo").await;
    assert_eq!(
        page.text(r#"section#tools [data-server="demo"] > div.notice[data-notice="ok"] > p"#)
            .as_deref(),
        Some("All 1 demo tools are off."),
        "a server of one tool reads All 1 demo tools are off, with no grammar case"
    );
}

#[test]
fn size_text_prints_bytes_below_1000_and_one_decimal_kilobytes_from_1000_up() {
    use doorward::accounts::tools::size_text;
    assert_eq!(size_text(0), "0 B");
    assert_eq!(size_text(999), "999 B");
    assert_eq!(size_text(1000), "1.0 KB");
    assert_eq!(size_text(1014), "1.0 KB");
    assert_eq!(size_text(1023), "1.0 KB");
    assert_eq!(size_text(1024), "1.0 KB");
    assert_eq!(size_text(1843), "1.8 KB");
    assert_eq!(size_text(1_843_000), "1799.8 KB");
}

/// The declarations of the first rule in `css` whose selector opens its line, indented or not.
fn rule_of<'a>(css: &'a str, selector: &str) -> &'a str {
    let start = css
        .match_indices(&format!("{selector} {{"))
        .map(|(at, _)| at)
        .find(|&at| {
            css[..at]
                .rsplit('\n')
                .next()
                .is_some_and(|line| line.trim().is_empty())
        })
        .unwrap_or_else(|| panic!("the stylesheet must hold the rule {selector}"));
    let rule = &css[start..];
    let open = rule.find('{').expect("a rule opens its block");
    let close = rule.find('}').expect("a rule closes its block");
    &rule[open + 1..close]
}

#[test]
fn the_question_sentence_has_a_whole_line_and_the_question_buttons_one_width() {
    let css = include_str!("../assets/doorward.css");
    assert!(
        rule_of(css, ".tools-foot .confirm-body > p").contains("line-height: 20px;"),
        "the sentence of a question must take a 20 px line"
    );
    assert!(
        rule_of(css, ".tools-foot .confirm-body > button").contains("min-inline-size: 73px;"),
        "both question buttons must take at least 73 px so that their left edge does not shift"
    );
    assert!(
        rule_of(css, ".tools-foot .when-unsaved").contains("display: none;"),
        "the unsaved sentence must be hidden unless the form has unsaved boxes"
    );
    assert!(
        rule_of(
            css,
            ".tools-form:has(.tool > input:checked:not([checked]), .tool > input[checked]:not(:checked)) .tools-foot .when-unsaved"
        )
        .contains("display: block;"),
        "the unsaved sentence must show while the form has unsaved boxes"
    );
    let desktop = css
        .find("@media (min-width: 640px) {\n  .tools-foot .confirm-body > p {")
        .expect("the desktop width of the sentence must sit in a 640 px media block");
    assert!(
        rule_of(&css[desktop..], ".tools-foot .confirm-body > p").contains("inline-size: 22.5rem;"),
        "from 640 px the sentence of a question must take 22.5rem"
    );
}
