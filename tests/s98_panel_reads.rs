mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::admin;
use common::client::{Page, TestClient};
use common::upstream::UpstreamOptions;
use common::world::World;
use rusqlite::{Connection, params};
use scraper::{ElementRef, Html, Selector};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const NOW: &str = "2030-01-01T00:00:00Z";
const DAY: i64 = 86_400;
const SESSION: &str = "__Host-doorward_session";
const COULD_NOT_DRAW: &str = "This chart could not be drawn.";
const EXPORT: &str = "/admin/activity.csv";
const BOB: &str = "bob@example.com";
const LIST: &str = "/admin/dashboards";

fn now() -> i64 {
    OffsetDateTime::parse(NOW, &Rfc3339)
        .expect("the time is RFC 3339")
        .unix_timestamp()
}

fn open(w: &World) -> Connection {
    Connection::open(w.gw.db_path()).expect("the gateway database opens")
}

/// The details of the admin_change rows, oldest first.
fn admin_changes(w: &World) -> Vec<String> {
    let conn = open(w);
    let mut statement = conn
        .prepare("SELECT detail FROM activity WHERE kind = 'admin_change' ORDER BY id")
        .expect("the query");
    statement
        .query_map([], |row| row.get(0))
        .expect("the rows")
        .collect::<rusqlite::Result<_>>()
        .expect("the details")
}

/// Inserts `count` let-through calls, one per 25 seconds back from now, in one transaction.
fn seed_calls(db: &Path, count: i64) {
    let mut conn = Connection::open(db).expect("the gateway database opens");
    let tx = conn.transaction().expect("a transaction");
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, \
                 client, decision, outcome, detail, duration_ms) \
                 VALUES (?1, 'tool_call', ?2, ?3, 1, 'demo', ?4, 'claude', 'allow', 'ok', '', ?5)",
            )
            .expect("the insert");
        for index in 0..count {
            let user = index % 7 + 1;
            insert
                .execute(params![
                    now() - (index * 25) % (90 * DAY),
                    user,
                    format!("user{user}@example.com"),
                    format!("tool{}", index % 5),
                    index % 900 + 1,
                ])
                .expect("a row");
        }
    }
    tx.commit().expect("the rows are committed");
}

/// One let-through call written straight into the table, with its client and age in seconds.
fn insert_call(db: &Path, at: i64, client: &str, kind: &str) {
    let conn = Connection::open(db).expect("the gateway database opens");
    conn.execute(
        "INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, client, \
         decision, outcome, detail, duration_ms) VALUES (?1, ?2, 1, 'bob@example.com', 1, 'demo', \
         'alpha', ?3, 'allow', 'ok', '', 5)",
        params![at, kind, client],
    )
    .expect("an activity row");
}

/// Seeds `count` calls and a server and a user, and returns the world with bob's id and the demo server's.
async fn world_with_calls(count: i64) -> (World, i64) {
    let w = World::start().await;
    w.user(BOB).await;
    w.upstream("demo", UpstreamOptions::default()).await;
    seed_calls(w.gw.db_path().as_path(), count);
    let server: i64 = open(&w)
        .query_row("SELECT id FROM servers WHERE slug = 'demo'", [], |row| {
            row.get(0)
        })
        .expect("the demo server");
    (w, server)
}

/// The csrf token of the Activity page, which holds one once it has rows.
async fn csrf_of_activity(w: &World) -> String {
    let page = w.owner.get("/admin/activity").await;
    page.csrf()
        .expect("the Activity page with rows holds a csrf token")
}

fn section<'a>(doc: &'a Html, title: &str) -> ElementRef<'a> {
    let figures = Selector::parse("figure.chart").expect("a selector");
    let heading = Selector::parse("h3").expect("a selector");
    doc.select(&figures)
        .find(|figure| {
            figure
                .select(&heading)
                .next()
                .is_some_and(|h| h.text().collect::<String>().trim().starts_with(title))
        })
        .unwrap_or_else(|| panic!("a chart titled {title}"))
}

fn text_of(element: ElementRef<'_>) -> String {
    element.text().collect::<String>().trim().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_get_of_the_export_answers_405_and_writes_no_row() {
    let (w, _) = world_with_calls(3).await;
    let before = admin_changes(&w).len();
    let page = w.owner.get(EXPORT).await;
    assert_eq!(page.status, 405, "the export is a POST only");
    assert_eq!(
        admin_changes(&w).len(),
        before,
        "a GET writes no admin_change row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_without_the_csrf_token_is_refused_and_writes_no_row() {
    let (w, _) = world_with_calls(3).await;
    let before = admin_changes(&w).len();
    let page = w.owner.post(EXPORT, &[("period", "all")]).await;
    assert_eq!(page.status, 403, "a form post needs the csrf token");
    assert_eq!(admin_changes(&w).len(), before, "nothing is written");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_from_another_origin_is_refused_and_a_post_from_the_gateway_is_not() {
    let (w, _) = world_with_calls(3).await;
    let token = csrf_of_activity(&w).await;
    let before = admin_changes(&w).len();
    let foreign = w
        .owner
        .post_with(
            EXPORT,
            &[("csrf", token.as_str())],
            &[("origin", "https://example.com")],
        )
        .await;
    assert_eq!(foreign.status, 403, "a foreign Origin is refused");
    assert_eq!(admin_changes(&w).len(), before, "nothing is written");
    let own = w.owner.post(EXPORT, &[("csrf", token.as_str())]).await;
    assert_eq!(
        own.status, 200,
        "the same post from the gateway's own origin is served"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_post_writes_its_started_row_with_the_count_and_the_filters() {
    let (w, server) = world_with_calls(3).await;
    let token = csrf_of_activity(&w).await;
    let server = server.to_string();
    let page = w
        .owner
        .post(
            EXPORT,
            &[
                ("csrf", token.as_str()),
                ("period", "7d"),
                ("event", "tool_call"),
                ("server", server.as_str()),
            ],
        )
        .await;
    assert_eq!(page.status, 200, "the export is served");
    assert_eq!(
        page.header("content-type").as_deref(),
        Some("text/csv; charset=utf-8")
    );
    assert_eq!(
        admin_changes(&w).last().map(String::as_str),
        Some("export started (3 rows; period 7d, event tool_call, server demo)"),
        "the started row counts the rows and names the filters in force"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_is_redirected_and_a_plain_user_is_forbidden_on_the_export_post() {
    let w = World::start().await;
    seed_calls(w.gw.db_path().as_path(), 1);
    let anonymous = w.client().post(EXPORT, &[("csrf", "x")]).await;
    assert_eq!(anonymous.status, 303, "an anonymous post goes to sign-in");
    assert_eq!(anonymous.location().as_deref(), Some("/login"));
    let bob = w.user(BOB).await;
    let token = csrf_of_activity(&w).await;
    let plain = bob.post(EXPORT, &[("csrf", token.as_str())]).await;
    assert_eq!(plain.status, 403, "a plain user is forbidden");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_button_is_a_post_form_that_carries_the_active_filters() {
    let (w, _) = world_with_calls(3).await;
    let page = w.owner.get("/admin/activity?event=tool_call&q=tool").await;
    assert_eq!(
        page.count("form.export-form[method=post][action='/admin/activity.csv']"),
        1
    );
    assert_eq!(page.count("button#export-csv[type=submit]"), 1);
    assert_eq!(page.count("a#export-csv"), 0, "the export is no link");
    assert_eq!(
        page.attr("form.export-form input[name=event]", "value")
            .as_deref(),
        Some("tool_call")
    );
    assert_eq!(
        page.attr("form.export-form input[name=q]", "value")
            .as_deref(),
        Some("tool")
    );
    assert_eq!(page.count("form.export-form input[name=csrf]"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_search_text_is_cut_to_200_characters_and_the_form_shows_the_cut() {
    let (w, _) = world_with_calls(1).await;
    let long = "a".repeat(250);
    let page = w.owner.get(&format!("/admin/activity?q={long}")).await;
    let shown = page
        .attr("input#filter-q", "value")
        .expect("the search field");
    assert_eq!(
        shown.chars().count(),
        200,
        "the search is cut to 200 characters"
    );
    assert_eq!(shown, "a".repeat(200));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_panel_and_account_pages_open_in_their_own_browsing_context_and_the_sign_in_pages_do_not()
 {
    let (w, _) = world_with_calls(1).await;
    for path in ["/admin", "/admin/activity", "/admin/dashboards", "/account"] {
        let page = w.owner.get(path).await;
        assert_eq!(page.status, 200, "{path} answers");
        assert_eq!(
            page.header("cross-origin-opener-policy").as_deref(),
            Some("same-origin"),
            "{path} sends the opener policy"
        );
    }
    let anonymous = w.client();
    for path in [
        "/login",
        "/oauth/authorize?response_type=code",
        "/oauth/consent?req=missing",
    ] {
        let page = anonymous.get(path).await;
        assert!(
            page.header("content-type")
                .is_some_and(|kind| kind.starts_with("text/html")),
            "{path} is an HTML page"
        );
        assert_eq!(
            page.header("cross-origin-opener-policy"),
            None,
            "{path} must not send the opener policy"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_list_holds_only_the_tool_calls_of_the_last_30_days() {
    let w = World::start().await;
    w.user(BOB).await;
    let db = w.gw.db_path();
    insert_call(&db, now() - 40 * DAY, "stale", "tool_call");
    insert_call(&db, now() - DAY, "recent", "tool_call");
    insert_call(&db, now() - DAY, "connected", "client_connected");
    let page = w.owner.get("/admin/activity").await;
    let options = Selector::parse("select[name=client] option").expect("a selector");
    let doc = Html::parse_document(&page.body);
    let names: Vec<String> = doc
        .select(&options)
        .map(|option| option.value().attr("value").unwrap_or("").to_owned())
        .collect();
    assert!(names.contains(&"recent".to_owned()), "{names:?}");
    assert!(!names.contains(&"stale".to_owned()), "{names:?}");
    assert!(!names.contains(&"connected".to_owned()), "{names:?}");
}

/// The values of the client options of the activity page, in page order, without the "Any client" choice.
async fn client_options(w: &World, path: &str) -> Vec<(String, String, bool)> {
    let page = w.owner.get(path).await;
    let options = Selector::parse("select[name=client] option").expect("a selector");
    let doc = Html::parse_document(&page.body);
    doc.select(&options)
        .filter(|option| option.value().attr("value") != Some(""))
        .map(|option| {
            (
                option.value().attr("value").unwrap_or("").to_owned(),
                option.text().collect::<String>().trim().to_owned(),
                option.value().attr("selected").is_some(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_list_is_the_first_fifty_client_names_of_the_last_30_days_in_name_order() {
    let w = World::start().await;
    w.user(BOB).await;
    let db = w.gw.db_path();
    for number in (0..60).rev() {
        let name = format!("client-{number:02}");
        insert_call(&db, now() - DAY, &name, "tool_call");
        insert_call(&db, now() - 2 * DAY, &name, "tool_call");
    }
    let names: Vec<String> = client_options(&w, "/admin/activity")
        .await
        .into_iter()
        .map(|(value, _, _)| value)
        .collect();
    let want: Vec<String> = (0..50)
        .map(|number| format!("client-{number:02}"))
        .collect();
    assert_eq!(names, want);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_filtered_client_outside_the_list_is_one_selected_option_with_its_own_name() {
    let w = World::start().await;
    w.user(BOB).await;
    let db = w.gw.db_path();
    insert_call(&db, now() - 40 * DAY, "stale", "tool_call");
    let options = client_options(&w, "/admin/activity?client=stale").await;
    assert_eq!(
        options,
        vec![("stale".to_owned(), "stale".to_owned(), true)],
        "the filter shows its own name, selected, and no note that it matches nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chart_that_fails_shows_an_error_and_the_counts_and_latest_activity_still_render() {
    let (w, _) = world_with_calls(5).await;
    open(&w)
        .execute_batch("DROP TABLE tool_catalog;")
        .expect("the catalog is dropped to make the unused-tools chart fail");
    let page = w.owner.get("/admin").await;
    assert_eq!(page.status, 200, "the Overview still answers");
    let doc = Html::parse_document(&page.body);
    let failed = text_of(
        section(&doc, "Unused tools")
            .select(&Selector::parse("p.chart-empty").expect("a selector"))
            .next()
            .expect("the error sentence"),
    );
    assert_eq!(failed, COULD_NOT_DRAW);
    assert!(
        text_of(section(&doc, "Tool calls over time")).contains("Tool calls over time"),
        "the other charts are drawn"
    );
    assert_eq!(
        page.count("[data-count=servers]"),
        1,
        "the counts are drawn"
    );
    assert_eq!(
        page.count("[data-latest-activity]"),
        1,
        "the latest activity is drawn"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chart_is_drawn_again_only_after_its_minute_turns_or_its_definition_changes() {
    let (w, _) = world_with_calls(5).await;
    let first = w.owner.get("/admin").await;
    assert_eq!(first.status, 200);
    open(&w)
        .execute_batch("DROP TABLE tool_catalog;")
        .expect("the catalog is dropped");
    let same_minute = w.owner.get("/admin").await;
    let doc = Html::parse_document(&same_minute.body);
    assert_eq!(
        same_minute.count("figure[data-error]"),
        0,
        "a reload within the minute draws from the memo, not the database"
    );
    assert!(text_of(section(&doc, "Unused tools")).contains("Unused tools"));
    w.gw.clock.advance(time::Duration::seconds(60));
    let next_minute = w.owner.get("/admin").await;
    assert_eq!(
        next_minute.count("figure[data-error]"),
        1,
        "a new minute draws the chart again, and the dropped table fails it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_chart_is_drawn_at_once_within_the_minute() {
    let w = World::start().await;
    w.user(BOB).await;
    insert_call(&w.gw.db_path(), now() - 60, "claude", "tool_call");
    let page = w.owner.submit(LIST, LIST, &[("name", "Changes")]).await;
    assert_eq!(page.status, 303);
    let board: i64 = open(&w)
        .query_row(
            "SELECT id FROM dashboards WHERE name = 'Changes'",
            [],
            |row| row.get(0),
        )
        .expect("the dashboard");
    let path = format!("/admin/dashboards/{board}/charts");
    let fields = |title: &str| -> Vec<(&'static str, String)> {
        vec![
            ("title", title.to_owned()),
            ("metric", "calls".to_owned()),
            ("group_by", "none".to_owned()),
            ("shape", "number".to_owned()),
            ("period", "24h".to_owned()),
            ("server_id", String::new()),
            ("user_id", String::new()),
            ("tool", String::new()),
            ("top_n", "10".to_owned()),
            ("width", "half".to_owned()),
        ]
    };
    let owned = fields("Calls");
    let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(w.owner.submit(LIST, &path, &pairs).await.status, 303);
    let first = w.owner.get(&format!("/admin?dashboard={board}")).await;
    assert!(first.body.contains("Calls"), "the chart is listed");
    insert_call(&w.gw.db_path(), now() - 30, "claude", "tool_call");
    let stale = w.owner.get(&format!("/admin?dashboard={board}")).await;
    assert_eq!(
        stale.count("figure[data-error]"),
        0,
        "the same minute holds the first number"
    );
    let chart: i64 = open(&w)
        .query_row(
            "SELECT id FROM charts WHERE dashboard_id = ?1",
            params![board],
            |row| row.get(0),
        )
        .expect("the chart");
    let renamed = fields("Calls renamed");
    let renamed_pairs: Vec<(&str, &str)> = renamed.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let update = w
        .owner
        .submit(
            &format!("/admin/dashboards/{board}"),
            &format!("/admin/dashboards/{board}/charts/{chart}"),
            &renamed_pairs,
        )
        .await;
    assert_eq!(update.status, 303, "the chart is updated");
    let after = w.owner.get(&format!("/admin?dashboard={board}")).await;
    let doc = Html::parse_document(&after.body);
    assert!(
        text_of(section(&doc, "Calls renamed")).contains("Calls renamed"),
        "the new definition is drawn at once"
    );
    let value = Selector::parse("span.figure-value").expect("a selector");
    assert_eq!(
        text_of(
            section(&doc, "Calls renamed")
                .select(&value)
                .next()
                .expect("the value")
        ),
        "2",
        "the new definition counts both calls"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_server_or_a_user_logs_one_row_per_chart_it_removes() {
    let w = World::start().await;
    w.user(BOB).await;
    w.upstream("demo", UpstreamOptions::default()).await;
    let bob = w.user_id(BOB).await;
    let server = admin::server_id(&w.owner, "demo")
        .await
        .expect("the demo server");
    let page = w.owner.submit(LIST, LIST, &[("name", "Scoped")]).await;
    assert_eq!(page.status, 303);
    let board: i64 = open(&w)
        .query_row(
            "SELECT id FROM dashboards WHERE name = 'Scoped'",
            [],
            |row| row.get(0),
        )
        .expect("the dashboard");
    let path = format!("/admin/dashboards/{board}/charts");
    let scoped = [("title", "On demo", "server"), ("title", "For bob", "user")];
    for (_, title, kind) in scoped {
        let server_id = if kind == "server" {
            server.as_str()
        } else {
            ""
        };
        let user_id = if kind == "user" { bob.as_str() } else { "" };
        let fields = [
            ("title", title),
            ("metric", "calls"),
            ("group_by", "none"),
            ("shape", "number"),
            ("period", "30d"),
            ("server_id", server_id),
            ("user_id", user_id),
            ("tool", ""),
            ("top_n", "10"),
            ("width", "half"),
        ];
        assert_eq!(w.owner.submit(LIST, &path, &fields).await.status, 303);
    }
    let before = admin_changes(&w).len();
    let deleted = admin::delete_server(&w.owner, &server).await;
    assert_eq!(deleted.status, 303, "the server is deleted");
    let user_gone = admin::user_action(&w.owner, &bob, "delete").await;
    assert_eq!(user_gone.status, 303, "the user is deleted");
    let rows = admin_changes(&w);
    let new_rows: Vec<&String> = rows[before..].iter().collect();
    assert!(
        new_rows.contains(
            &&"deleted chart On demo from dashboard Scoped: its server was deleted".to_owned()
        ),
        "{new_rows:?}"
    );
    assert!(
        new_rows.contains(
            &&"deleted chart For bob from dashboard Scoped: its user was deleted".to_owned()
        ),
        "{new_rows:?}"
    );
    let removed = new_rows
        .iter()
        .filter(|detail| detail.starts_with("deleted chart"))
        .count();
    assert_eq!(removed, 2, "one row per removed chart: {new_rows:?}");
    let conn = open(&w);
    let mut statement = conn
        .prepare(
            "SELECT user_email, at FROM activity WHERE kind = 'admin_change' \
             AND detail LIKE 'deleted chart %' ORDER BY id",
        )
        .expect("the query");
    let by: Vec<(String, i64)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("the rows")
        .collect::<rusqlite::Result<_>>()
        .expect("each row");
    assert_eq!(by.len(), 2, "{by:?}");
    for (email, at) in by {
        assert_eq!(
            email,
            common::world::OWNER_EMAIL,
            "the admin who deleted is the actor"
        );
        assert_eq!(at, now(), "the row carries the application clock");
    }
}

/// Seeds calls, then asks the Overview for its period while a bearer-free panel request takes the writer.
#[tokio::test(flavor = "multi_thread")]
async fn a_panel_request_answers_under_150_ms_while_the_90_day_overview_is_computing() {
    let (w, _) = world_with_calls(0).await;
    seed_calls(w.gw.db_path().as_path(), 300_000);
    let base = w.base().to_owned();
    let overview_client = TestClient::new(&base);
    overview_client.set_cookie(
        SESSION,
        &w.owner.cookie(SESSION).expect("the owner's session"),
    );
    let overview = tokio::spawn(async move { overview_client.get("/admin?period=90d").await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    let started = Instant::now();
    let fast: Page = w.owner.get("/account").await;
    let took = started.elapsed();
    assert_eq!(fast.status, 200, "the account page answers");
    assert!(
        !overview.is_finished(),
        "the Overview was still computing when the fast request answered"
    );
    assert!(
        took < Duration::from_millis(150),
        "the fast request took {took:?} while the Overview computed"
    );
    let page = overview.await.expect("the overview task");
    assert_eq!(page.status, 200, "the Overview answers");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_recorded_email_and_slug_filters_show_as_chips_that_remove_them() {
    let (w, _) = world_with_calls(3).await;
    let page = w
        .owner
        .get("/admin/activity?email=user1%40example.com&slug=demo")
        .await;
    assert_eq!(
        page.text("li[data-filter=email] .chip-key").as_deref(),
        Some("User (recorded)")
    );
    assert_eq!(
        page.text("li[data-filter=slug] .chip-key").as_deref(),
        Some("Server (recorded)")
    );
    let removed = page
        .attr("li[data-filter=slug] a.chip", "href")
        .expect("the server chip removes itself");
    assert!(removed.contains("email=user1"), "{removed}");
    assert!(!removed.contains("slug="), "{removed}");
}

/// The Activity page and the Overview answer, within two seconds each, while another connection
/// holds an open write transaction: WAL readers do not wait for a writer.
#[tokio::test(flavor = "multi_thread")]
async fn the_panel_reads_answer_while_another_connection_holds_a_write_transaction() {
    let (w, _) = world_with_calls(5).await;
    let blocker = open(&w);
    blocker
        .busy_timeout(Duration::from_millis(50))
        .expect("the timeout");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the write lock is taken");
    let activity = tokio::time::timeout(Duration::from_secs(2), w.owner.get("/admin/activity"))
        .await
        .expect("the Activity page answers while the writer is held");
    assert_eq!(activity.status, 200, "the Activity page answers");
    assert!(
        activity.count("table.activity tbody tr") > 0,
        "the Activity page lists the seeded calls"
    );
    let overview = tokio::time::timeout(Duration::from_secs(2), w.owner.get("/admin"))
        .await
        .expect("the Overview answers while the writer is held");
    assert_eq!(overview.status, 200, "the Overview answers");
    assert!(
        overview.count("figure.chart") > 0 && overview.count("figure[data-error='1']") == 0,
        "the Overview draws its charts while the writer is held"
    );
    blocker
        .execute_batch("ROLLBACK")
        .expect("the lock is released");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_name_in_the_activity_table_is_one_piece_with_no_break_inside_it() {
    let (w, _) = world_with_calls(0).await;
    let server = admin::server_id(&w.owner, "demo")
        .await
        .expect("the demo server");
    open(&w)
        .execute(
            "INSERT INTO activity (at, kind, server_id, server_slug, tool, decision, outcome) \
             VALUES (?1, 'tool_call', ?2, 'demo', 'alpha_long_tool_name', 'allow', 'ok')",
            params![now(), server],
        )
        .expect("a call");
    let page = w.owner.get("/admin/activity").await;
    let doc = Html::parse_document(&page.body);
    let cell = Selector::parse("td.where").expect("a selector");
    let cells: Vec<String> = doc.select(&cell).map(|cell| cell.inner_html()).collect();
    assert!(
        cells
            .iter()
            .any(|html| html.contains("<code>alpha_long_tool_name</code>")),
        "the tool is one piece of text: {cells:?}"
    );
}
