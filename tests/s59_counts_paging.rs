mod common;

use std::path::Path;

use common::admin;
use common::client::Page;
use common::upstream::UpstreamOptions;
use common::world::{OWNER_EMAIL, World};
use rusqlite::{Connection, params, params_from_iter};
use scraper::{ElementRef, Html, Selector};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const DAVE: &str = "dave@example.com";
const EVE: &str = "eve@example.com";
const PER_PAGE: usize = 50;
/// The count links of the overview: key, page the link goes to, and the number expected.
const COUNTS: [(&str, &str, usize); 4] = [
    ("servers", "/admin/servers", 2),
    ("users", "/admin/users", 3),
    ("invitations", "/admin/invitations", 1),
    ("rules", "/admin/rules", 4),
];

/// Collapses runs of whitespace into single spaces.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn text_of(element: ElementRef<'_>) -> String {
    collapse(&element.text().collect::<String>())
}

/// Every element under `root` matching `css`, in document order.
fn all<'a>(root: ElementRef<'a>, css: &str) -> Vec<ElementRef<'a>> {
    let selector =
        Selector::parse(css).unwrap_or_else(|err| panic!("bad selector {css:?}: {err:?}"));
    root.select(&selector).collect()
}

/// The pills under `row` as (text, tone).
fn pills_in(row: ElementRef<'_>) -> Vec<(String, String)> {
    all(row, "[data-pill]")
        .into_iter()
        .map(|pill| {
            (
                text_of(pill),
                pill.value().attr("data-tone").unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// The data-time of each activity row on the page, in the order shown.
fn row_times(page: &Page) -> Vec<String> {
    let doc = Html::parse_document(&page.body);
    all(doc.root_element(), "li[data-kind]")
        .into_iter()
        .map(|row| row.value().attr("data-time").unwrap_or("").to_string())
        .collect()
}

/// The unix time the harness clock starts at.
fn clock_start() -> i64 {
    OffsetDateTime::parse("2030-01-01T00:00:00Z", &Rfc3339)
        .expect("the start time parses")
        .unix_timestamp()
}

fn rfc3339(at: i64) -> String {
    OffsetDateTime::from_unix_timestamp(at)
        .expect("the stored time is a valid unix time")
        .format(&Rfc3339)
        .expect("the stored time formats as RFC 3339")
}

/// Counts the activity rows, all of them or those of one user and server.
fn count_rows(db: &Path, filter: Option<(i64, i64)>) -> usize {
    let conn = Connection::open(db).expect("the gateway database opens");
    let (clause, args) = clause_of(filter);
    let count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM activity {clause}"),
            params_from_iter(args),
            |row| row.get(0),
        )
        .expect("the count query runs");
    usize::try_from(count).expect("a row count is not negative")
}

/// The RFC 3339 times of the rows in the order the page shows them, from `offset`, at most `limit`.
fn oracle_times(db: &Path, filter: Option<(i64, i64)>, offset: usize, limit: usize) -> Vec<String> {
    let conn = Connection::open(db).expect("the gateway database opens");
    let (clause, args) = clause_of(filter);
    let sql = format!(
        "SELECT at FROM activity {clause} ORDER BY at DESC, id DESC LIMIT {limit} OFFSET {offset}"
    );
    let mut statement = conn.prepare(&sql).expect("the time query prepares");
    let times: Vec<i64> = statement
        .query_map(params_from_iter(args), |row| row.get(0))
        .expect("the time query runs")
        .map(|time| time.expect("a stored time reads"))
        .collect();
    times.into_iter().map(rfc3339).collect()
}

fn clause_of(filter: Option<(i64, i64)>) -> (&'static str, Vec<i64>) {
    match filter {
        Some((user, server)) => ("WHERE user_id = ?1 AND server_id = ?2", vec![user, server]),
        None => ("", Vec::new()),
    }
}

/// Inserts `count` activity rows from `first`, each one second after the last.
fn insert_rows(
    db: &Path,
    first: i64,
    count: i64,
    actor: Option<(i64, &str)>,
    server: Option<(i64, &str)>,
) {
    let mut conn = Connection::open(db).expect("the gateway database opens");
    let tx = conn.transaction().expect("a transaction opens");
    for index in first..first + count {
        tx.execute(
            "INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, \
             decision, outcome) VALUES (?1, 'tool_call', ?2, ?3, ?4, ?5, 'echo', 'allow', 'ok')",
            params![
                clock_start() + 1000 + index,
                actor.map(|(id, _)| id),
                actor.map_or("", |(_, email)| email),
                server.map(|(id, _)| id),
                server.map_or("", |(_, slug)| slug),
            ],
        )
        .expect("an activity row is inserted");
    }
    tx.commit().expect("the activity rows are committed");
}

/// A world whose activity holds 135 more rows than the harness wrote: 120 of bob on demo, 15 of
/// no user or server. Returns the world, bob's id and demo's id.
async fn paged_world() -> (World, i64, i64) {
    let w = World::start().await;
    w.user(BOB).await;
    let (_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob_id: i64 = w.user_id(BOB).await.parse().expect("bob's id is a number");
    let demo_id: i64 = demo.parse().expect("the server id is a number");
    let db = w.gw.db_path();
    insert_rows(&db, 0, 120, Some((bob_id, BOB)), Some((demo_id, "demo")));
    insert_rows(&db, 120, 15, None, None);
    (w, bob_id, demo_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_counts_and_shows_the_latest_activity() {
    let w = World::start().await;
    w.user(BOB).await;
    let carol = w.admin(CAROL).await;
    let bob_id = w.user_id(BOB).await;
    let carol_id = w.user_id(CAROL).await;
    let (_demo_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let other_options = UpstreamOptions {
        tools: vec!["echo".into()],
        ..UpstreamOptions::default()
    };
    let (_other_up, other) = w.open_upstream("other", other_options).await;
    w.grant(BOB, &[demo.as_str()]).await;
    w.gw.clock.advance(Duration::minutes(1));

    let rules = [
        admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&demo), None).await,
        admin::add_rule(
            &w.owner,
            "everyone",
            "deny",
            "tool",
            Some(&demo),
            Some("delete_db"),
        )
        .await,
        admin::add_rule(
            &w.owner,
            &bob_id,
            "allow",
            "tool",
            Some(&demo),
            Some("echo"),
        )
        .await,
        admin::add_rule(&w.owner, &carol_id, "deny", "server", Some(&other), None).await,
    ];
    for (index, page) in rules.iter().enumerate() {
        assert_eq!(page.status, 303, "rule {} must be saved", index + 1);
    }
    w.gw.clock.advance(Duration::minutes(1));

    let _open = w.invite_link(DAVE, "user").await;
    w.gw.clock.advance(Duration::minutes(1));
    let _revoked = w.invite_link(EVE, "user").await;
    let eve_invitation = admin::invitation_id(&w.owner, EVE)
        .await
        .expect("eve's invitation must be listed");
    let revoked = admin::revoke_invitation(&w.owner, &eve_invitation).await;
    assert_eq!(revoked.status, 303, "eve's invitation must be revoked");
    w.gw.clock.advance(Duration::minutes(1));

    let overview = w.owner.get("/admin").await;
    assert_eq!(
        overview.status, 200,
        "the overview must answer 200 to the owner"
    );
    assert_counts(&overview, "the owner");
    let activity = w.owner.get("/admin/activity").await;
    assert_latest(&overview, &row_times(&activity));

    let admin_overview = carol.get("/admin").await;
    assert_eq!(
        admin_overview.status, 200,
        "the overview must answer 200 to an admin"
    );
    assert_counts(&admin_overview, "an admin");
}

/// Asserts the four count links of the overview with their numbers.
fn assert_counts(page: &Page, who: &str) {
    for (key, href, value) in COUNTS {
        let link = format!(r#"a[data-count="{key}"]"#);
        assert_eq!(
            page.count(&link),
            1,
            "the overview must show one {key} count for {who}"
        );
        assert_eq!(
            page.attr(&link, "href").as_deref(),
            Some(href),
            "the {key} count must link to {href} for {who}"
        );
        let shown = format!("{link} [data-count-value]");
        assert_eq!(
            page.count(&shown),
            1,
            "the {key} count must hold one [data-count-value] for {who}"
        );
        let expected = value.to_string();
        assert_eq!(
            page.text(&shown).as_deref(),
            Some(expected.as_str()),
            "the {key} count must read {expected} for {who}"
        );
    }
}

/// Asserts the overview's latest-activity section holds the newest five rows of the activity page.
fn assert_latest(overview: &Page, newest_first: &[String]) {
    let doc = Html::parse_document(&overview.body);
    let sections = all(doc.root_element(), "[data-latest-activity]");
    assert_eq!(
        sections.len(),
        1,
        "the overview must hold one [data-latest-activity] section"
    );
    let section = sections[0];
    let want = newest_first.len().min(5);
    assert_eq!(want, 5, "the seeded activity must hold more than five rows");
    let shown: Vec<String> = all(section, "tr[data-kind]")
        .into_iter()
        .map(|row| row.value().attr("data-time").unwrap_or("").to_string())
        .collect();
    assert_eq!(
        shown,
        newest_first[..want].to_vec(),
        "the latest-activity section must hold the five newest rows, newest first"
    );
    assert!(
        !all(section, r#"a[href="/admin/activity"]"#).is_empty(),
        "the latest-activity section must link to the whole activity page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lists_show_counts_and_states() {
    let w = World::start().await;
    w.user(BOB).await;
    w.user(CAROL).await;
    let (_demo_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let other_options = UpstreamOptions {
        tools: vec!["echo".into()],
        ..UpstreamOptions::default()
    };
    let (_other_up, _other) = w.open_upstream("other", other_options).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let carol_id = w.user_id(CAROL).await;
    let disabled = admin::user_action(&w.owner, &carol_id, "disable").await;
    assert_eq!(disabled.status, 303, "carol must be disabled");

    let servers = w.owner.get("/admin/servers").await;
    assert_eq!(
        servers.status, 200,
        "the servers page must answer 200 to the owner"
    );
    let doc = Html::parse_document(&servers.body);
    let rows = all(doc.root_element(), "tr[data-server-id]");
    assert_eq!(rows.len(), 2, "the servers page must list both servers");
    for row in rows {
        let slug = row.value().attr("data-slug").unwrap_or("");
        let id = row.value().attr("data-server-id").unwrap_or("");
        let (tools, users) = match slug {
            "demo" => (3, 1),
            "other" => (1, 0),
            other => panic!("the servers page lists an unexpected server {other:?}"),
        };
        let tool_count = all(row, "[data-tool-count]");
        assert_eq!(
            tool_count.len(),
            1,
            "server {slug} must hold one [data-tool-count]"
        );
        assert!(
            text_of(tool_count[0]).starts_with(&format!("{tools} ")),
            "the tool count of {slug} must start with {tools}, got {:?}",
            text_of(tool_count[0])
        );
        let user_count = all(row, "[data-user-count]");
        assert_eq!(
            user_count.len(),
            1,
            "server {slug} must hold one [data-user-count]"
        );
        assert!(
            text_of(user_count[0]).starts_with(&format!("{users} ")),
            "the user count of {slug} must start with {users}, got {:?}",
            text_of(user_count[0])
        );
        assert!(
            text_of(row).contains(slug),
            "the server row of {slug} must show its path"
        );
        let state = admin::lockdown(&w.owner, id)
            .await
            .unwrap_or_else(|| panic!("server {slug} must show its lock-down state"));
        let tone = match state.as_str() {
            "ok" => "ok",
            "open" => "bad",
            _ => "warn",
        };
        let pills = pills_in(row);
        assert_eq!(
            pills.len(),
            1,
            "the server row of {slug} must hold one lock-down pill"
        );
        assert_eq!(
            pills[0].1, tone,
            "the lock-down pill of {slug} in state {state} must carry tone {tone}"
        );
        assert!(
            !pills[0].0.is_empty(),
            "the lock-down pill of {slug} must hold text"
        );
    }

    let users = w.owner.get("/admin/users").await;
    assert_eq!(
        users.status, 200,
        "the users page must answer 200 to the owner"
    );
    let doc = Html::parse_document(&users.body);
    let rows = all(doc.root_element(), "tr[data-user-id]");
    assert_eq!(
        rows.len(),
        3,
        "the users page must list owner, bob and carol"
    );
    for row in rows {
        let email = row.value().attr("data-email").unwrap_or("");
        let (servers, role) = match email {
            OWNER_EMAIL => (0, "owner"),
            BOB => (1, "user"),
            CAROL => (0, "user"),
            other => panic!("the users page lists an unexpected user {other:?}"),
        };
        let server_count = all(row, "[data-server-count]");
        assert_eq!(
            server_count.len(),
            1,
            "the user row of {email} must hold one [data-server-count]"
        );
        assert!(
            text_of(server_count[0]).starts_with(&format!("{servers} ")),
            "the server count of {email} must start with {servers}, got {:?}",
            text_of(server_count[0])
        );
        assert!(
            text_of(row).to_lowercase().contains(role),
            "the user row of {email} must show its role {role}"
        );
        let (status, tone) = if email == CAROL {
            ("Disabled", "muted")
        } else {
            ("Active", "ok")
        };
        assert_eq!(
            pills_in(row),
            vec![(status.to_string(), tone.to_string())],
            "the user row of {email} must hold one pill reading {status} with tone {tone}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn activity_is_paged() {
    let (w, bob_id, demo_id) = paged_world().await;
    let db = w.gw.db_path();
    let total = count_rows(&db, None);
    let last = total.div_ceil(PER_PAGE);
    assert!(
        total > 100,
        "the seeded activity must hold more than 100 rows"
    );

    for number in 1..=last {
        let page = w.owner.get(&format!("/admin/activity?page={number}")).await;
        assert_eq!(page.status, 200, "page {number} must answer 200");
        let first = (number - 1) * PER_PAGE;
        let count = PER_PAGE.min(total - first);
        assert_eq!(
            row_times(&page),
            oracle_times(&db, None, first, PER_PAGE),
            "page {number} must show rows {} to {}, newest first",
            first + 1,
            first + count
        );
        assert_eq!(
            page.text("[data-range]").as_deref(),
            Some(format!("Rows {} to {} of {total}", first + 1, first + count).as_str()),
            "page {number} must say which rows of how many it shows"
        );
        assert_page_links(&page, number, last, None);
    }

    let past = w
        .owner
        .get(&format!("/admin/activity?page={}", last + 1))
        .await;
    assert_eq!(past.status, 200, "a page past the end must answer 200");
    assert_eq!(
        past.count("li[data-kind]"),
        0,
        "a page past the end must show no rows"
    );
    assert!(
        past.body.contains("No activity matches."),
        "a page past the end must say No activity matches."
    );
    assert_eq!(
        past.count(r#"a[data-page-link="newer"]"#),
        1,
        "a page past the end must link back to newer rows"
    );

    for value in ["0", "abc", "-1"] {
        let page = w.owner.get(&format!("/admin/activity?page={value}")).await;
        assert_eq!(page.status, 200, "page={value} must answer 200");
        assert_eq!(
            row_times(&page),
            oracle_times(&db, None, 0, PER_PAGE),
            "page={value} must show the first page"
        );
    }

    let filter = format!("user={bob_id}&server={demo_id}");
    let filter_pair = Some((bob_id, demo_id));
    let filtered_total = count_rows(&db, filter_pair);
    let filtered_last = filtered_total.div_ceil(PER_PAGE);
    assert!(
        filtered_total > PER_PAGE,
        "the filtered activity must span more than one page"
    );
    for number in 1..=filtered_last {
        let page = w
            .owner
            .get(&format!("/admin/activity?{filter}&page={number}"))
            .await;
        assert_eq!(page.status, 200, "filtered page {number} must answer 200");
        let first = (number - 1) * PER_PAGE;
        let count = PER_PAGE.min(filtered_total - first);
        assert_eq!(
            row_times(&page),
            oracle_times(&db, filter_pair, first, PER_PAGE),
            "filtered page {number} must show the filtered rows, newest first"
        );
        assert_eq!(
            page.text("[data-range]").as_deref(),
            Some(
                format!(
                    "Rows {} to {} of {filtered_total}",
                    first + 1,
                    first + count
                )
                .as_str()
            ),
            "filtered page {number} must count the filtered rows"
        );
        assert_page_links(&page, number, filtered_last, Some(filter.as_str()));
    }
}

/// Asserts the older and newer links of a page: each exists exactly when a page lies that way,
/// and points at it, keeping the filter when one is given.
fn assert_page_links(page: &Page, number: usize, last: usize, filter: Option<&str>) {
    let older = page.attr(r#"a[data-page-link="older"]"#, "href");
    let newer = page.attr(r#"a[data-page-link="newer"]"#, "href");
    assert_eq!(
        page.count(r#"a[data-page-link="older"]"#),
        usize::from(number < last),
        "page {number} of {last} must have an older link exactly when an older page exists"
    );
    assert_eq!(
        page.count(r#"a[data-page-link="newer"]"#),
        usize::from(number > 1),
        "page {number} must have a newer link exactly when a newer page exists"
    );
    if let Some(href) = older {
        assert!(
            href.contains(&format!("page={}", number + 1)),
            "the older link of page {number} must carry page={}, got {href}",
            number + 1
        );
        assert_keeps(&href, filter);
    }
    if let Some(href) = newer {
        assert!(
            href.contains(&format!("page={}", number - 1)),
            "the newer link of page {number} must carry page={}, got {href}",
            number - 1
        );
        assert_keeps(&href, filter);
    }
}

/// Asserts a page link keeps the user and server of the filter when there is one.
fn assert_keeps(href: &str, filter: Option<&str>) {
    let Some(filter) = filter else {
        return;
    };
    for pair in filter.split('&') {
        assert!(
            href.contains(pair),
            "a page link must keep {pair}, got {href}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn filters_reset_to_the_first_page() {
    let (w, bob_id, demo_id) = paged_world().await;
    let page = w
        .owner
        .get(&format!(
            "/admin/activity?user={bob_id}&server={demo_id}&page=2"
        ))
        .await;
    assert_eq!(page.status, 200, "the filtered second page must answer 200");
    assert_eq!(
        page.count(r#"form[data-form="activity-filter"]"#),
        1,
        "the activity page must hold the filter form"
    );
    assert_eq!(
        page.count(r#"form[data-form="activity-filter"] [name="page"]"#),
        0,
        "the filter form must hold no page field, so submitting it lands on page 1"
    );
    let user = page
        .attr(r#"select[name="user"] option[selected]"#, "value")
        .expect("the user filter must show the chosen user");
    let server = page
        .attr(r#"select[name="server"] option[selected]"#, "value")
        .expect("the server filter must show the chosen server");
    assert_eq!(user, bob_id.to_string(), "the user filter must hold bob");
    assert_eq!(
        server,
        demo_id.to_string(),
        "the server filter must hold demo"
    );

    let submitted = w
        .owner
        .get(&format!("/admin/activity?user={user}&server={server}"))
        .await;
    assert_eq!(
        submitted.status, 200,
        "the submitted filter must answer 200"
    );
    let db = w.gw.db_path();
    assert_eq!(
        row_times(&submitted),
        oracle_times(&db, Some((bob_id, demo_id)), 0, PER_PAGE),
        "submitting the filter must show the first page of the filtered rows"
    );
    assert_eq!(
        submitted.text("[data-range]").as_deref(),
        Some(
            format!(
                "Rows 1 to 50 of {}",
                count_rows(&db, Some((bob_id, demo_id)))
            )
            .as_str()
        ),
        "submitting the filter must say it shows rows 1 to 50"
    );
}
