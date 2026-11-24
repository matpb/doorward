mod common;

use std::path::Path;

use common::admin;
use common::client::Page;
use common::upstream::UpstreamOptions;
use common::world::{OWNER_EMAIL, PASSWORD, World};
use rusqlite::{Connection, params};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const DAVE: &str = "dave@example.com";
const EVE: &str = "eve@example.com";
const ANN: &str = "ann@example.com";

/// The count link of `key` in the overview, from its opening tag to its closing tag.
fn cell_html(body: &str, key: &str) -> String {
    let start_tag = format!(r#"<a data-count="{key}""#);
    let Some(start) = body.find(&start_tag) else {
        return String::new();
    };
    let rest = &body[start..];
    match rest.find("</a>") {
        Some(end) => rest[..end + "</a>".len()].to_string(),
        None => rest.to_string(),
    }
}

/// A count link as the overview writes it. `state` is what sits inside its `span.count-state`.
fn expected_cell(key: &str, href: &str, value: usize, label: &str, state: Option<&str>) -> String {
    let line = state
        .map(|inside| format!(r#"<span class="count-state">{inside}</span>"#))
        .unwrap_or_default();
    format!(
        r#"<a data-count="{key}" href="{href}"><span class="count-value" data-count-value>{value}</span><span class="count-label">{label}</span>{line}</a>"#
    )
}

/// A status pill as `ui::pill` writes it.
fn pill(tone: &str, text: &str) -> String {
    format!(r#"<span class="state" data-pill data-tone="{tone}">{text}</span>"#)
}

/// The inside of an expiry line: the words, then the date in a time element.
fn expiry_line(words: &str, instant: &str, date: &str) -> String {
    format!(r#"{words} <time datetime="{instant}">{date}</time>"#)
}

/// Asserts the overview's count link for `key` is exactly `want`, markup and text.
fn assert_cell(page: &Page, key: &str, want: &str) {
    assert_eq!(
        cell_html(&page.body, key),
        want,
        "the {key} count link on the overview"
    );
}

/// The overview as the owner, or as whoever `c` is.
async fn overview(c: &common::client::TestClient) -> Page {
    let page = c.get("/admin").await;
    assert_eq!(page.status, 200, "the overview must answer 200");
    page
}

/// Runs the lock-down check of a server and asserts it was saved.
async fn check(w: &World, server_id: &str) {
    let page = admin::check_lockdown(&w.owner, server_id).await;
    assert_eq!(
        page.status, 303,
        "the lock-down check of {server_id} must answer 303"
    );
}

/// Disables a user from the users page.
async fn disable(w: &World, email: &str) {
    let id = w.user_id(email).await;
    let page = admin::user_action(&w.owner, &id, "disable").await;
    assert_eq!(page.status, 303, "{email} must be disabled");
}

/// Signs the owner in again, for after the clock has moved past the owner's session.
async fn sign_in_owner_again(w: &mut World) {
    let fresh = w.gw.client();
    let login = fresh.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(login.status, 303, "the owner must sign in again");
    w.owner = fresh;
}

/// The expiry of an invitation as RFC 3339, read from the gateway's database.
fn expires_at(db: &Path, email: &str) -> String {
    let conn = Connection::open(db).expect("the gateway database opens");
    let at: i64 = conn
        .query_row(
            "SELECT expires_at FROM invitations WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )
        .expect("the invitation is stored");
    OffsetDateTime::from_unix_timestamp(at)
        .expect("the stored expiry is a valid unix time")
        .format(&Rfc3339)
        .expect("the expiry formats as RFC 3339")
}

#[tokio::test(flavor = "multi_thread")]
async fn one_open_server_reads_answers_without_the_gateway_in_the_singular() {
    let w = World::start().await;
    let (_up, open) = w.open_upstream("open", UpstreamOptions::default()).await;
    check(&w, &open).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            1,
            "Server",
            Some(&pill("bad", "1 answers without the gateway")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_open_servers_read_answer_without_the_gateway_in_the_plural() {
    let w = World::start().await;
    let (_first, first) = w.open_upstream("first", UpstreamOptions::default()).await;
    let (_second, second) = w.open_upstream("second", UpstreamOptions::default()).await;
    check(&w, &first).await;
    check(&w, &second).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            2,
            "Servers",
            Some(&pill("bad", "2 answer without the gateway")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unchecked_servers_with_none_open_read_not_checked() {
    let w = World::start().await;
    let (_first, _first_id) = w.open_upstream("first", UpstreamOptions::default()).await;
    let (_second, _second_id) = w.open_upstream("second", UpstreamOptions::default()).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            2,
            "Servers",
            Some(&pill("warn", "2 not checked")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unchecked_server_beside_a_locked_down_one_reads_not_checked() {
    let w = World::start().await;
    let (_gated, gated) = w.upstream("gated", UpstreamOptions::default()).await;
    let (_idle, _idle_id) = w.open_upstream("idle", UpstreamOptions::default()).await;
    check(&w, &gated).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            2,
            "Servers",
            Some(&pill("warn", "1 not checked")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_server_hides_the_unchecked_count() {
    let w = World::start().await;
    let (_open, open) = w.open_upstream("open", UpstreamOptions::default()).await;
    let (_idle, _idle_id) = w.open_upstream("idle", UpstreamOptions::default()).await;
    check(&w, &open).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            2,
            "Servers",
            Some(&pill("bad", "1 answers without the gateway")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_locked_down_server_reads_locked_down() {
    let w = World::start().await;
    let (_gated, gated) = w.upstream("gated", UpstreamOptions::default()).await;
    check(&w, &gated).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            1,
            "Server",
            Some(&pill("ok", "Locked down")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_server_locked_down_reads_all_locked_down() {
    let w = World::start().await;
    let (_first, first) = w.upstream("first", UpstreamOptions::default()).await;
    let (_second, second) = w.upstream("second", UpstreamOptions::default()).await;
    check(&w, &first).await;
    check(&w, &second).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            2,
            "Servers",
            Some(&pill("ok", "All locked down")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_disabled_user_reads_disabled_in_muted() {
    let w = World::start().await;
    w.user(BOB).await;
    w.user(CAROL).await;
    disable(&w, CAROL).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "users",
        &expected_cell(
            "users",
            "/admin/users",
            3,
            "Users",
            Some(&pill("muted", "1 disabled")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_disabled_users_read_two_disabled() {
    let w = World::start().await;
    w.user(BOB).await;
    w.user(CAROL).await;
    w.user(DAVE).await;
    disable(&w, CAROL).await;
    disable(&w, DAVE).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "users",
        &expected_cell(
            "users",
            "/admin/users",
            4,
            "Users",
            Some(&pill("muted", "2 disabled")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_open_invitation_reads_expires_with_its_date() {
    let w = World::start().await;
    let _link = w.invite_link(DAVE, "user").await;
    let db = w.gw.db_path();
    assert_eq!(
        expires_at(&db, DAVE),
        "2030-01-08T00:00:00Z",
        "seven days after the start of the harness clock"
    );
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "invitations",
        &expected_cell(
            "invitations",
            "/admin/invitations",
            1,
            "Open invitation",
            Some(&expiry_line(
                "Expires",
                "2030-01-08T00:00:00Z",
                "8 Jan 2030",
            )),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_open_invitations_read_the_next_expiry_of_the_earliest() {
    let mut w = World::start().await;
    let _first = w.invite_link(EVE, "user").await;
    w.gw.clock.advance(Duration::days(1));
    sign_in_owner_again(&mut w).await;
    let _second = w.invite_link(DAVE, "user").await;
    let db = w.gw.db_path();
    assert_eq!(expires_at(&db, EVE), "2030-01-08T00:00:00Z");
    assert_eq!(expires_at(&db, DAVE), "2030-01-09T00:00:00Z");
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "invitations",
        &expected_cell(
            "invitations",
            "/admin/invitations",
            2,
            "Open invitations",
            Some(&expiry_line(
                "Next expires",
                "2030-01-08T00:00:00Z",
                "8 Jan 2030",
            )),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_or_expired_invitation_is_not_open() {
    let mut w = World::start().await;
    let _revoked = w.invite_link(DAVE, "user").await;
    let dave = admin::invitation_id(&w.owner, DAVE)
        .await
        .expect("dave's invitation must be listed");
    let revoke = admin::revoke_invitation(&w.owner, &dave).await;
    assert_eq!(revoke.status, 303, "dave's invitation must be revoked");
    let _expiring = w.invite_link(ANN, "user").await;
    w.gw.clock.advance(Duration::days(8));
    sign_in_owner_again(&mut w).await;
    let _open = w.invite_link(EVE, "user").await;
    let db = w.gw.db_path();
    assert_eq!(expires_at(&db, EVE), "2030-01-16T00:00:00Z");
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "invitations",
        &expected_cell(
            "invitations",
            "/admin/invitations",
            1,
            "Open invitation",
            Some(&expiry_line(
                "Expires",
                "2030-01-16T00:00:00Z",
                "16 Jan 2030",
            )),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_and_allow_rules_read_deny_then_allow() {
    let w = World::start().await;
    let (_demo_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let allow = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&demo), None).await;
    assert_eq!(allow.status, 303, "the allow rule must be saved");
    let deny_one = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(&demo),
        Some("delete_db"),
    )
    .await;
    assert_eq!(deny_one.status, 303, "the first deny rule must be saved");
    let deny_two = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(&demo),
        Some("search"),
    )
    .await;
    assert_eq!(deny_two.status, 303, "the second deny rule must be saved");
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            3,
            "Rules",
            Some(&format!(
                "{} {}",
                pill("bad", "2 deny"),
                pill("ok", "1 allow")
            )),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_deny_rules_read_deny_alone() {
    let w = World::start().await;
    let (_demo_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let deny = admin::add_rule(&w.owner, "everyone", "deny", "server", Some(&demo), None).await;
    assert_eq!(deny.status, 303, "the deny rule must be saved");
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            1,
            "Rule",
            Some(&pill("bad", "1 deny")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_allow_rules_read_allow_alone() {
    let w = World::start().await;
    let (_first_up, first) = w.upstream("first", UpstreamOptions::default()).await;
    let (_second_up, second) = w.upstream("second", UpstreamOptions::default()).await;
    let one = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&first), None).await;
    assert_eq!(one.status, 303, "the first allow rule must be saved");
    let two = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&second), None).await;
    assert_eq!(two.status, 303, "the second allow rule must be saved");
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            2,
            "Rules",
            Some(&pill("ok", "2 allow")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quiet_overview_gives_every_count_a_sub_line_at_zero() {
    let w = World::start().await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell("servers", "/admin/servers", 0, "Servers", Some("None yet")),
    );
    assert_cell(
        &page,
        "users",
        &expected_cell("users", "/admin/users", 1, "User", Some("None disabled")),
    );
    assert_cell(
        &page,
        "invitations",
        &expected_cell(
            "invitations",
            "/admin/invitations",
            0,
            "Open invitations",
            Some("None open"),
        ),
    );
    assert_cell(
        &page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            0,
            "Rules",
            Some("Every assigned tool is allowed"),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_nouns_take_the_singular_at_one_and_the_plural_otherwise() {
    let w = World::start().await;
    let (_first_up, first) = w.upstream("first", UpstreamOptions::default()).await;
    let allow = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&first), None).await;
    assert_eq!(allow.status, 303, "the allow rule must be saved");
    let _dave = w.invite_link(DAVE, "user").await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            1,
            "Server",
            Some(&pill("warn", "1 not checked")),
        ),
    );
    assert_cell(
        &page,
        "users",
        &expected_cell("users", "/admin/users", 1, "User", Some("None disabled")),
    );
    assert_cell(
        &page,
        "invitations",
        &expected_cell(
            "invitations",
            "/admin/invitations",
            1,
            "Open invitation",
            Some(&expiry_line(
                "Expires",
                "2030-01-08T00:00:00Z",
                "8 Jan 2030",
            )),
        ),
    );
    assert_cell(
        &page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            1,
            "Rule",
            Some(&pill("ok", "1 allow")),
        ),
    );

    let (_second_up, second) = w.upstream("second", UpstreamOptions::default()).await;
    let allow = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&second), None).await;
    assert_eq!(allow.status, 303, "the second allow rule must be saved");
    let _eve = w.invite_link(EVE, "user").await;
    w.user(BOB).await;
    let page = overview(&w.owner).await;
    assert_cell(
        &page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            2,
            "Servers",
            Some(&pill("warn", "2 not checked")),
        ),
    );
    assert_cell(
        &page,
        "users",
        &expected_cell("users", "/admin/users", 2, "Users", Some("None disabled")),
    );
    assert_cell(
        &page,
        "invitations",
        &expected_cell(
            "invitations",
            "/admin/invitations",
            2,
            "Open invitations",
            Some(&expiry_line(
                "Next expires",
                "2030-01-08T00:00:00Z",
                "8 Jan 2030",
            )),
        ),
    );
    assert_cell(
        &page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            2,
            "Rules",
            Some(&pill("ok", "2 allow")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_who_is_not_the_owner_sees_the_same_lines() {
    let w = World::start().await;
    let carol = w.admin(CAROL).await;
    let (_open_up, open) = w.open_upstream("open", UpstreamOptions::default()).await;
    check(&w, &open).await;
    w.user(BOB).await;
    disable(&w, BOB).await;
    let _dave = w.invite_link(DAVE, "user").await;
    let deny = admin::add_rule(&w.owner, "everyone", "deny", "server", Some(&open), None).await;
    assert_eq!(deny.status, 303, "the deny rule must be saved");
    let owner_page = overview(&w.owner).await;
    let admin_page = overview(&carol).await;
    for key in ["servers", "users", "invitations", "rules"] {
        assert!(
            !cell_html(&owner_page.body, key).is_empty(),
            "the owner's overview must hold the {key} count"
        );
        assert_eq!(
            cell_html(&admin_page.body, key),
            cell_html(&owner_page.body, key),
            "the {key} count must read the same for an admin and for the owner"
        );
    }
    assert_cell(
        &admin_page,
        "servers",
        &expected_cell(
            "servers",
            "/admin/servers",
            1,
            "Server",
            Some(&pill("bad", "1 answers without the gateway")),
        ),
    );
    assert_cell(
        &admin_page,
        "users",
        &expected_cell(
            "users",
            "/admin/users",
            3,
            "Users",
            Some(&pill("muted", "1 disabled")),
        ),
    );
    assert_cell(
        &admin_page,
        "rules",
        &expected_cell(
            "rules",
            "/admin/rules",
            1,
            "Rule",
            Some(&pill("bad", "1 deny")),
        ),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_user_cannot_open_the_overview_and_sees_no_count() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob.get("/admin").await;
    assert_eq!(
        page.status, 403,
        "a plain user must be refused the overview"
    );
    assert!(
        !page.body.contains("data-count"),
        "a refused overview must show no count"
    );
}
