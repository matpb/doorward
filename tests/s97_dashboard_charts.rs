mod common;

use std::path::Path;
use std::time::Instant;

use common::admin;
use common::client::{Page, TestClient};
use common::upstream::UpstreamOptions;
use common::world::World;
use rusqlite::{Connection, params};
use scraper::{ElementRef, Html, Selector};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const NOW: &str = "2030-01-01T00:00:00Z";
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
const TOOL_ERROR: &str = "the tool reported an error";
const LIST: &str = "/admin/dashboards";
const NO_ACTIVITY: &str = "No activity in this period.";

fn now() -> i64 {
    OffsetDateTime::parse(NOW, &Rfc3339)
        .expect("the time is RFC 3339")
        .unix_timestamp()
}

/// One activity row written straight into the table, as the proxy and the panel write them.
#[derive(Clone, Default)]
struct Row {
    at: i64,
    kind: &'static str,
    user_id: Option<i64>,
    user: &'static str,
    server_id: Option<i64>,
    server: &'static str,
    tool: &'static str,
    client: &'static str,
    decision: &'static str,
    outcome: &'static str,
    detail: &'static str,
    duration_ms: Option<i64>,
}

/// A let-through call that completed.
fn call(
    at: i64,
    who: (i64, &'static str),
    server: (i64, &'static str),
    tool: &'static str,
    client: &'static str,
    ms: Option<i64>,
) -> Row {
    Row {
        at,
        kind: "tool_call",
        user_id: Some(who.0),
        user: who.1,
        server_id: Some(server.0),
        server: server.1,
        tool,
        client,
        decision: "allow",
        outcome: "ok",
        duration_ms: ms,
        ..Row::default()
    }
}

/// A call the policy refused.
fn refused(
    at: i64,
    who: (i64, &'static str),
    server: (i64, &'static str),
    tool: &'static str,
    client: &'static str,
) -> Row {
    Row {
        decision: "deny",
        outcome: "refused",
        ..call(at, who, server, tool, client, None)
    }
}

/// A let-through call that failed.
fn failed(
    at: i64,
    who: (i64, &'static str),
    server: (i64, &'static str),
    tool: &'static str,
    client: &'static str,
    ms: Option<i64>,
) -> Row {
    Row {
        outcome: "error",
        detail: "boom",
        ..call(at, who, server, tool, client, ms)
    }
}

/// A let-through call whose result reported a tool error.
fn tool_error(
    at: i64,
    who: (i64, &'static str),
    server: (i64, &'static str),
    tool: &'static str,
    client: &'static str,
    ms: Option<i64>,
) -> Row {
    Row {
        detail: TOOL_ERROR,
        ..call(at, who, server, tool, client, ms)
    }
}

fn login(at: i64, who: (i64, &'static str)) -> Row {
    Row {
        at,
        kind: "login",
        user_id: Some(who.0),
        user: who.1,
        outcome: "ok",
        ..Row::default()
    }
}

/// A refused sign-in; `who` is the account it named, when there is one.
fn login_failed(at: i64, email: &'static str, who: Option<i64>) -> Row {
    Row {
        at,
        kind: "login_failed",
        user_id: who,
        user: email,
        outcome: "refused",
        ..Row::default()
    }
}

fn insert(db: &Path, rows: &[Row]) {
    let mut conn = Connection::open(db).expect("the gateway database opens");
    let tx = conn.transaction().expect("a transaction opens");
    for row in rows {
        insert_row(&tx, row);
    }
    tx.commit().expect("the activity rows are committed");
}

fn insert_row(conn: &Connection, row: &Row) {
    conn.execute(
        "INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, \
         client, decision, outcome, detail, duration_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            row.at,
            row.kind,
            row.user_id,
            row.user,
            row.server_id,
            row.server,
            row.tool,
            row.client,
            row.decision,
            row.outcome,
            row.detail,
            row.duration_ms,
        ],
    )
    .expect("an activity row is inserted");
}

fn open(w: &World) -> Connection {
    Connection::open(w.gw.db_path()).expect("the gateway database opens")
}

/// A world with bob and carol, and two servers: demo and other. Each id is paired with its name.
struct Seeded {
    w: World,
    bob: (i64, &'static str),
    carol: (i64, &'static str),
    demo: (i64, &'static str),
    other: (i64, &'static str),
}

async fn seeded() -> Seeded {
    let w = World::start().await;
    w.user(BOB).await;
    w.user(CAROL).await;
    let bob: i64 = w.user_id(BOB).await.parse().expect("an id");
    let carol: i64 = w.user_id(CAROL).await.parse().expect("an id");
    w.upstream("demo", UpstreamOptions::default()).await;
    w.upstream("other", UpstreamOptions::default()).await;
    let server_id = |slug: &str| -> i64 {
        open(&w)
            .query_row(
                "SELECT id FROM servers WHERE slug = ?1",
                params![slug],
                |row| row.get(0),
            )
            .unwrap_or_else(|err| panic!("a server {slug}: {err}"))
    };
    let demo = server_id("demo");
    let other = server_id("other");
    Seeded {
        w,
        bob: (bob, BOB),
        carol: (carol, CAROL),
        demo: (demo, "demo"),
        other: (other, "other"),
    }
}

/// A chart as the builder form posts it. An empty server, user or tool is no filter.
#[derive(Clone)]
struct Chart {
    title: &'static str,
    metric: &'static str,
    group_by: &'static str,
    shape: &'static str,
    period: &'static str,
    server_id: String,
    user_id: String,
    tool: &'static str,
    top_n: &'static str,
    width: &'static str,
}

fn chart(
    title: &'static str,
    metric: &'static str,
    group_by: &'static str,
    shape: &'static str,
    period: &'static str,
) -> Chart {
    Chart {
        title,
        metric,
        group_by,
        shape,
        period,
        server_id: String::new(),
        user_id: String::new(),
        tool: "",
        top_n: "10",
        width: "half",
    }
}

fn pairs(chart: &Chart) -> Vec<(&str, &str)> {
    vec![
        ("title", chart.title),
        ("metric", chart.metric),
        ("group_by", chart.group_by),
        ("shape", chart.shape),
        ("period", chart.period),
        ("server_id", chart.server_id.as_str()),
        ("user_id", chart.user_id.as_str()),
        ("tool", chart.tool),
        ("top_n", chart.top_n),
        ("width", chart.width),
    ]
}

/// Creates a dashboard named `name` with `charts` and returns its id.
async fn make_dashboard(w: &World, name: &str, charts: &[Chart]) -> i64 {
    let page = w.owner.submit(LIST, LIST, &[("name", name)]).await;
    assert_eq!(page.status, 303, "the dashboard {name} is created");
    let id: i64 = open(w)
        .query_row(
            "SELECT id FROM dashboards WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
        .unwrap_or_else(|err| panic!("a dashboard named {name}: {err}"));
    for chart in charts {
        let path = format!("/admin/dashboards/{id}/charts");
        let added = w.owner.submit(LIST, &path, &pairs(chart)).await;
        assert_eq!(added.status, 303, "the chart {} is added", chart.title);
    }
    id
}

/// The Overview with its query string.
async fn overview(w: &World, query: &str) -> Page {
    w.owner.get(&format!("/admin{query}")).await
}

fn text_of(element: ElementRef<'_>) -> String {
    element.text().collect::<String>().trim().to_owned()
}

/// The chart section whose heading is `title`.
fn section<'a>(doc: &'a Html, title: &str) -> ElementRef<'a> {
    let sections = Selector::parse("figure.chart").expect("a selector");
    let heading = Selector::parse("h3").expect("a selector");
    doc.select(&sections)
        .find(|section| {
            section
                .select(&heading)
                .next()
                .is_some_and(|h3| h3.text().next().map(str::trim) == Some(title))
        })
        .unwrap_or_else(|| panic!("the overview shows no chart titled {title}"))
}

/// The one figure text of a number chart, such as `3 calls`.
fn number(page: &Page, title: &str) -> String {
    let doc = Html::parse_document(&page.body);
    let figure = Selector::parse("p.figure-number").expect("a selector");
    let found: Vec<String> = section(&doc, title).select(&figure).map(text_of).collect();
    assert_eq!(found.len(), 1, "{title} shows one number");
    found[0].clone()
}

/// The rows of a chart's table, the Data table under a figure or the table of its shape, in table order.
fn data_rows(page: &Page, title: &str) -> Vec<(String, String)> {
    let doc = Html::parse_document(&page.body);
    let rows = Selector::parse("table tbody tr").expect("a selector");
    let cell = Selector::parse("th, td").expect("a selector");
    section(&doc, title)
        .select(&rows)
        .map(|row| {
            let cells: Vec<String> = row.select(&cell).map(text_of).collect();
            assert_eq!(cells.len(), 2, "a data row holds a label and a value");
            (cells[0].clone(), cells[1].clone())
        })
        .collect()
}

/// The rows of a ranked chart: the label (a tool's two parts joined by " / "), the value, and the
/// link of the label when it is a link. A row with no key is plain text, so its link is None.
fn ranked(page: &Page, title: &str) -> Vec<(String, String, Option<String>)> {
    let doc = Html::parse_document(&page.body);
    let items = Selector::parse("ol.ranked li").expect("a selector");
    let name = Selector::parse(".ranked-name").expect("a selector");
    let code = Selector::parse("code").expect("a selector");
    let value = Selector::parse("span.ranked-value").expect("a selector");
    section(&doc, title)
        .select(&items)
        .map(|item| {
            let label = item.select(&name).next().expect("a label");
            let parts: Vec<String> = label.select(&code).map(text_of).collect();
            let text = if parts.is_empty() {
                text_of(label)
            } else {
                parts.join(" / ")
            };
            (
                text,
                item.select(&value).next().map(text_of).unwrap_or_default(),
                label
                    .value()
                    .attr("href")
                    .filter(|_| label.value().name() == "a")
                    .map(str::to_owned),
            )
        })
        .collect()
}

/// The `title` of each bar of a chart: "DATE: VALUE", as the figure writes it.
fn bar_titles(page: &Page, title: &str) -> Vec<String> {
    let doc = Html::parse_document(&page.body);
    let bars = Selector::parse("g.marks > g > title").expect("a selector");
    section(&doc, title).select(&bars).map(text_of).collect()
}

/// The ranked rows as (label, value) pairs.
fn ranked_pairs(page: &Page, title: &str) -> Vec<(String, String)> {
    ranked(page, title)
        .into_iter()
        .map(|(label, value, _)| (label, value))
        .collect()
}

/// The number of rows an Activity page reports for the filters of `href`.
async fn activity_total(c: &TestClient, href: &str) -> i64 {
    let page = c.get(href).await;
    assert_eq!(page.status, 200, "the link {href} answers 200");
    if page.count("p[data-range]") == 1 {
        let text = page.text("p[data-range]").expect("the range");
        text.rsplit(' ')
            .next()
            .and_then(|last| last.parse().ok())
            .unwrap_or_else(|| panic!("the range {text:?} names a total"))
    } else {
        assert!(
            page.body.contains("No activity matches these filters."),
            "the activity page of {href} says it has no rows"
        );
        0
    }
}

/// The rows of statement 97's counts, all in the last 24 hours. Let-through calls are the bob and
/// carol rows with outcome ok or error; the refused rows are denied.
fn day_dataset(s: &Seeded) -> Vec<Row> {
    let at = now();
    vec![
        call(at - 100, s.bob, s.demo, "alpha", "claude", Some(10)),
        call(at - 200, s.bob, s.demo, "alpha", "claude", Some(20)),
        call(at - 300, s.carol, s.demo, "beta", "", Some(30)),
        failed(at - 400, s.carol, s.other, "gamma", "vscode", Some(40)),
        tool_error(at - 500, s.bob, s.other, "gamma", "claude", Some(50)),
        refused(at - 600, s.carol, s.demo, "beta", "claude"),
        refused(at - 700, s.bob, s.demo, "alpha", "claude"),
        login(at - 150, s.bob),
        login_failed(at - 250, "eve@example.com", None),
        login_failed(at - 350, BOB, Some(s.bob.0)),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn the_number_metrics_count_exactly_the_rows_their_class_names() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let board = make_dashboard(
        &s.w,
        "Numbers",
        &[
            chart("Calls", "calls", "none", "number", "24h"),
            chart("Refused", "refused", "none", "number", "24h"),
            chart("Failed", "failed", "none", "number", "24h"),
            chart("All", "all_calls", "none", "number", "24h"),
            chart("Users", "active_users", "none", "number", "24h"),
            chart("Sign-ins", "sign_ins", "none", "number", "24h"),
            chart(
                "Refused sign-ins",
                "sign_ins_refused",
                "none",
                "number",
                "24h",
            ),
            chart("Median", "duration_median", "none", "number", "24h"),
            chart("P95", "duration_p95", "none", "number", "24h"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    assert_eq!(
        number(&page, "Calls"),
        "3 tool calls",
        "let-through calls that completed"
    );
    assert_eq!(number(&page, "Refused"), "2 tool calls refused");
    assert_eq!(
        number(&page, "Failed"),
        "2 tool calls failed",
        "failures and tool errors"
    );
    assert_eq!(number(&page, "All"), "7 tool calls");
    assert_eq!(
        number(&page, "Users"),
        "2 people",
        "bob and carol made let-through calls"
    );
    assert_eq!(number(&page, "Sign-ins"), "1 sign-in");
    assert_eq!(number(&page, "Refused sign-ins"), "2 sign-ins refused");
    assert_eq!(
        number(&page, "Median"),
        "30 ms",
        "the median of 10, 20, 30, 40 and 50"
    );
    assert_eq!(
        number(&page, "P95"),
        "50 ms",
        "nearest rank: the fifth of five"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ranked_categories_are_counted_ordered_and_labelled_exactly() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let board = make_dashboard(
        &s.w,
        "Ranked",
        &[
            chart("By user", "calls", "user", "ranked", "24h"),
            chart("By server", "all_calls", "server", "ranked", "24h"),
            chart("Failed by server", "failed", "server", "ranked", "24h"),
            chart("Refused by user", "refused", "user", "ranked", "24h"),
            chart("By tool", "calls", "tool", "ranked", "24h"),
            chart("By client", "calls", "client", "ranked", "24h"),
            chart("Slowest", "duration_p95", "tool", "ranked", "24h"),
            chart(
                "Sign-in refusals",
                "sign_ins_refused",
                "user",
                "ranked",
                "24h",
            ),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let pair = |label: &str, value: &str| (label.to_owned(), value.to_owned());
    assert_eq!(
        ranked_pairs(&page, "By user"),
        vec![pair("bob@example.com", "2"), pair("carol@example.com", "1")]
    );
    assert_eq!(
        ranked_pairs(&page, "By server"),
        vec![pair("demo", "5"), pair("other", "2")]
    );
    assert_eq!(
        ranked_pairs(&page, "Failed by server"),
        vec![pair("other", "2")]
    );
    assert_eq!(
        ranked_pairs(&page, "Refused by user"),
        vec![pair("bob@example.com", "1"), pair("carol@example.com", "1")],
        "a tie is ordered by label"
    );
    assert_eq!(
        ranked_pairs(&page, "By tool"),
        vec![pair("demo / alpha", "2"), pair("demo / beta", "1")]
    );
    assert_eq!(
        ranked_pairs(&page, "By client"),
        vec![pair("claude", "2"), pair("unknown", "1")],
        "an empty client is shown as unknown"
    );
    assert_eq!(
        ranked_pairs(&page, "Slowest"),
        vec![
            pair("other / gamma", "50 ms"),
            pair("demo / beta", "30 ms"),
            pair("demo / alpha", "20 ms"),
        ],
        "the p95 of each tool over its let-through calls that have a duration"
    );
    assert_eq!(
        ranked_pairs(&page, "Sign-in refusals"),
        vec![pair("bob@example.com", "1"), pair("eve@example.com", "1")]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ranked_links_lead_to_an_activity_page_with_the_same_count() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let titles = [
        "Calls by user",
        "Calls by tool",
        "Failed by server",
        "Refused by user",
        "Sign-in refusals",
        "Every call by tool",
        "Calls by client",
    ];
    let board = make_dashboard(
        &s.w,
        "Links",
        &[
            chart(titles[0], "calls", "user", "ranked", "24h"),
            chart(titles[1], "calls", "tool", "ranked", "24h"),
            chart(titles[2], "failed", "server", "ranked", "24h"),
            chart(titles[3], "refused", "user", "ranked", "24h"),
            chart(titles[4], "sign_ins_refused", "user", "ranked", "24h"),
            chart(titles[5], "all_calls", "tool", "ranked", "24h"),
            chart(titles[6], "calls", "client", "ranked", "24h"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    for title in titles {
        let rows = ranked(&page, title);
        assert!(!rows.is_empty(), "{title} has rows");
        for (label, value, href) in rows {
            let shown: i64 = value.replace(',', "").parse().expect("a value");
            let Some(href) = href else {
                assert_eq!(
                    (title, label.as_str()),
                    ("Calls by client", "unknown"),
                    "only the empty client is written as plain text"
                );
                continue;
            };
            assert!(href.starts_with("/admin/activity?"), "{title}: {href}");
            assert_eq!(
                activity_total(&s.w.owner, &href).await,
                shown,
                "{title}: the Activity page for {label} counts the bar's value"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ranked_links_of_every_call_metric_name_their_own_event() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let cases = [
        ("calls", "event=tool_call"),
        ("refused", "event=tool_refused"),
        ("failed", "event=tool_failed"),
        ("all_calls", "event=tool_any"),
        ("active_users", "event=tool_let_through"),
        ("duration_median", "event=tool_let_through"),
        ("duration_p95", "event=tool_let_through"),
    ];
    for (metric, event) in cases {
        let board = make_dashboard(
            &s.w,
            &format!("Event {metric}"),
            &[chart("Rows", metric, "tool", "ranked", "24h")],
        )
        .await;
        let page = overview(&s.w, &format!("?dashboard={board}")).await;
        let rows = ranked(&page, "Rows");
        assert!(!rows.is_empty(), "{metric} has rows");
        for (label, _, href) in rows {
            let href = href.unwrap_or_else(|| panic!("{metric}: {label} is a link"));
            assert!(
                href.contains(event),
                "{metric}: {label} links with {event}, got {href}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hourly_buckets_are_24_with_exact_boundaries_and_zero_fill() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[
            call(at, s.bob, s.demo, "alpha", "claude", Some(1)),
            call(at, s.bob, s.demo, "alpha", "claude", Some(2)),
            call(at - 2 * HOUR + 1, s.carol, s.demo, "beta", "", Some(100)),
            refused(at - 2 * HOUR + 2, s.carol, s.demo, "beta", "claude"),
            call(
                at - 23 * HOUR + 1,
                s.bob,
                s.other,
                "gamma",
                "vscode",
                Some(7),
            ),
            call(at - 25 * HOUR, s.bob, s.demo, "alpha", "claude", Some(9)),
        ],
    );
    let board = make_dashboard(
        &s.w,
        "Hours",
        &[
            chart("Calls by hour", "calls", "time", "bars", "24h"),
            chart("Refused by hour", "refused", "time", "line", "24h"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let rows = data_rows(&page, "Calls by hour");
    assert_eq!(rows.len(), 24, "24 hourly buckets");
    assert_eq!(
        rows[0].0, "31 Dec 2029 01:00",
        "the first bucket starts 23 hours before the current hour"
    );
    assert_eq!(
        rows[23].0, "1 Jan 2030 00:00",
        "the last bucket is the current hour"
    );
    let values: Vec<String> = rows.into_iter().map(|(_, value)| value).collect();
    let mut expected = vec!["0".to_owned(); 24];
    expected[0] = "1".to_owned();
    expected[21] = "1".to_owned();
    expected[23] = "2".to_owned();
    assert_eq!(
        values, expected,
        "empty hours are zero; the call 25 hours back is outside"
    );
    let refused_values: Vec<String> = data_rows(&page, "Refused by hour")
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    assert_eq!(refused_values.len(), 24);
    assert_eq!(refused_values[21], "1");
    assert_eq!(
        refused_values.iter().filter(|value| *value != "0").count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn daily_buckets_are_n_utc_days_ending_today_with_exact_boundaries() {
    let s = seeded().await;
    let at = now();
    let mut rows = vec![
        // The first second of the first day of the window, and the two seconds after it.
        call(at - 6 * DAY, s.bob, s.demo, "alpha", "claude", Some(5)),
        call(at - 6 * DAY + 1, s.bob, s.demo, "alpha", "claude", Some(6)),
        call(at - 6 * DAY + 2, s.bob, s.demo, "alpha", "claude", Some(7)),
        // One second before the window: not counted.
        call(
            at - 6 * DAY - 1,
            s.carol,
            s.demo,
            "beta",
            "claude",
            Some(999),
        ),
        // Today, the last bucket.
        call(at, s.bob, s.demo, "alpha", "claude", Some(1000)),
        // Long before the window.
        call(at - 60 * DAY, s.carol, s.demo, "beta", "claude", Some(999)),
    ];
    for index in 0..10i64 {
        let who = if index % 2 == 0 { s.bob } else { s.carol };
        rows.push(call(
            at - 2 * DAY + 43_200 + index,
            who,
            s.demo,
            "beta",
            "claude",
            Some(10 * (index + 1)),
        ));
    }
    insert(s.w.gw.db_path().as_path(), &rows);
    let board = make_dashboard(
        &s.w,
        "Days",
        &[chart("Calls by day", "calls", "time", "bars", "7d")],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let shown = data_rows(&page, "Calls by day");
    let labels: Vec<&str> = shown.iter().map(|(label, _)| label.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "26 Dec 2029",
            "27 Dec 2029",
            "28 Dec 2029",
            "29 Dec 2029",
            "30 Dec 2029",
            "31 Dec 2029",
            "1 Jan 2030",
        ]
    );
    let values: Vec<&str> = shown.iter().map(|(_, value)| value.as_str()).collect();
    assert_eq!(values, vec!["3", "0", "0", "0", "10", "0", "1"]);
    assert_eq!(
        bar_titles(&page, "Calls by day"),
        vec![
            "26 Dec 2029: 3 tool calls",
            "27 Dec 2029: 0 tool calls",
            "28 Dec 2029: 0 tool calls",
            "29 Dec 2029: 0 tool calls",
            "30 Dec 2029: 10 tool calls",
            "31 Dec 2029: 0 tool calls",
            "1 Jan 2030: 1 tool calls",
        ],
        "every bar's title is its date and exact value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn median_and_p95_are_nearest_rank_per_bucket_and_empty_buckets_are_gaps() {
    let s = seeded().await;
    let at = now();
    let mut rows = vec![
        call(at - 6 * DAY, s.bob, s.demo, "alpha", "claude", Some(5)),
        call(at - 6 * DAY + 1, s.bob, s.demo, "alpha", "claude", Some(6)),
        call(at - 6 * DAY + 2, s.bob, s.demo, "alpha", "claude", Some(7)),
        // Without a duration, and refused calls, are left out of the percentiles.
        call(at - 6 * DAY + 3, s.bob, s.demo, "alpha", "claude", None),
        refused(at - 6 * DAY + 4, s.bob, s.demo, "alpha", "claude"),
    ];
    for index in 0..10i64 {
        let who = if index % 2 == 0 { s.bob } else { s.carol };
        rows.push(call(
            at - 2 * DAY + 43_200 + index,
            who,
            s.demo,
            "beta",
            "claude",
            Some(10 * (index + 1)),
        ));
    }
    insert(s.w.gw.db_path().as_path(), &rows);
    let board = make_dashboard(
        &s.w,
        "Percentiles",
        &[
            chart("Median", "duration_median", "time", "line", "7d"),
            chart("P95", "duration_p95", "time", "bars", "7d"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let column = |title: &str| -> Vec<String> {
        data_rows(&page, title)
            .into_iter()
            .map(|(_, value)| value)
            .collect()
    };
    assert_eq!(
        column("Median"),
        vec![
            "6 ms", "No value", "No value", "No value", "50 ms", "No value", "No value"
        ],
        "the second of three and the fifth of ten; an empty bucket has no value"
    );
    assert_eq!(
        column("P95"),
        vec![
            "7 ms", "No value", "No value", "No value", "100 ms", "No value", "No value"
        ]
    );
    assert_eq!(
        bar_titles(&page, "P95"),
        vec![
            "26 Dec 2029: 7 ms",
            "27 Dec 2029: no value",
            "28 Dec 2029: no value",
            "29 Dec 2029: no value",
            "30 Dec 2029: 100 ms",
            "31 Dec 2029: no value",
            "1 Jan 2030: no value",
        ],
        "an empty bucket draws no mark"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn active_users_counts_distinct_users_in_each_bucket() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[
            call(at - 6 * DAY, s.bob, s.demo, "alpha", "claude", Some(5)),
            call(at - 6 * DAY + 1, s.bob, s.demo, "alpha", "claude", Some(5)),
            refused(at - 2 * DAY, s.carol, s.demo, "alpha", "claude"),
            failed(
                at - 2 * DAY + 1,
                s.carol,
                s.demo,
                "alpha",
                "claude",
                Some(5),
            ),
            call(at - 2 * DAY + 2, s.bob, s.demo, "alpha", "claude", Some(5)),
            call(
                at - 2 * DAY + 3,
                s.carol,
                s.demo,
                "alpha",
                "claude",
                Some(5),
            ),
            login(at - 2 * DAY + 4, s.carol),
        ],
    );
    let board = make_dashboard(
        &s.w,
        "Users",
        &[chart("Users by day", "active_users", "time", "bars", "7d")],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let values: Vec<String> = data_rows(&page, "Users by day")
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    assert_eq!(
        values,
        vec!["1", "0", "0", "0", "2", "0", "0"],
        "distinct users with a let-through call; a refusal and a sign-in do not count"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ranked_lists_are_cut_to_top_n_with_ties_by_label() {
    let s = seeded().await;
    let at = now();
    let counts: [(&'static str, i64); 6] = [
        ("ann@example.com", 5),
        ("bea@example.com", 3),
        ("cy@example.com", 3),
        ("dee@example.com", 2),
        ("eve2@example.com", 1),
        ("fay@example.com", 1),
    ];
    let mut rows = Vec::new();
    for (email, count) in counts {
        for index in 0..count {
            rows.push(call(
                at - 100 - index,
                (0, email),
                s.demo,
                "alpha",
                "claude",
                Some(1),
            ));
        }
    }
    insert(s.w.gw.db_path().as_path(), &rows);
    let mut top_five = chart("Top five", "calls", "user", "ranked", "30d");
    top_five.top_n = "5";
    let board = make_dashboard(&s.w, "Cut", &[top_five]).await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let expected: Vec<(String, String)> = [
        ("ann@example.com", "5"),
        ("bea@example.com", "3"),
        ("cy@example.com", "3"),
        ("dee@example.com", "2"),
        ("eve2@example.com", "1"),
    ]
    .iter()
    .map(|(label, value)| ((*label).to_owned(), (*value).to_owned()))
    .collect();
    assert_eq!(
        ranked_pairs(&page, "Top five"),
        expected,
        "five rows; the tie at one is ordered by label and fay is cut"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unused_tools_lists_catalog_tools_without_a_let_through_call_in_order() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[
            call(at - 100, s.bob, s.demo, "alpha", "claude", Some(1)),
            failed(at - 200, s.carol, s.demo, "gamma", "claude", Some(1)),
            refused(at - 300, s.bob, s.demo, "beta", "claude"),
        ],
    );
    {
        let conn = open(&s.w);
        conn.execute("DELETE FROM tool_catalog", [])
            .expect("the harness's default catalog is cleared");
        for (server, position, name) in [
            (s.demo.0, 0, "alpha"),
            (s.demo.0, 1, "beta"),
            (s.demo.0, 2, "gamma"),
            (s.other.0, 0, "delta"),
        ] {
            conn.execute(
                "INSERT INTO tool_catalog (server_id, position, name, definition) VALUES (?1, ?2, ?3, '{}')",
                params![server, position, name],
            )
            .expect("a catalog row");
        }
    }
    let board = make_dashboard(
        &s.w,
        "Unused",
        &[chart("Unused", "unused_tools", "none", "table", "30d")],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    assert_eq!(
        data_rows(&page, "Unused"),
        vec![
            ("demo".to_owned(), "beta".to_owned()),
            ("other".to_owned(), "delta".to_owned()),
        ],
        "a refused call does not use a tool; a failed call does"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn chart_filters_by_server_user_and_tool_restrict_the_rows() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let mut by_user = chart("Calls by bob", "calls", "none", "number", "24h");
    by_user.user_id = s.bob.0.to_string();
    let mut by_tool = chart("Calls to beta", "calls", "none", "number", "24h");
    by_tool.tool = "beta";
    let mut failed_other = chart("Failed on other", "failed", "none", "number", "24h");
    failed_other.server_id = s.other.0.to_string();
    let mut calls_demo = chart("Calls on demo", "calls", "tool", "ranked", "24h");
    calls_demo.server_id = s.demo.0.to_string();
    let board = make_dashboard(
        &s.w,
        "Filters",
        &[by_user, by_tool, failed_other, calls_demo],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    assert_eq!(number(&page, "Calls by bob"), "2 tool calls");
    assert_eq!(number(&page, "Calls to beta"), "1 tool call");
    assert_eq!(number(&page, "Failed on other"), "2 tool calls failed");
    assert_eq!(
        ranked_pairs(&page, "Calls on demo"),
        vec![
            ("demo / alpha".to_owned(), "2".to_owned()),
            ("demo / beta".to_owned(), "1".to_owned()),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_dashboard_period_overrides_every_chart_while_set() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[
            call(at - 10 * DAY, s.bob, s.demo, "alpha", "claude", Some(1)),
            call(at - 100, s.bob, s.demo, "alpha", "claude", Some(1)),
        ],
    );
    let board = make_dashboard(
        &s.w,
        "Override",
        &[chart("Thirty days", "calls", "none", "number", "30d")],
    )
    .await;
    let own = overview(&s.w, &format!("?dashboard={board}")).await;
    assert_eq!(
        number(&own, "Thirty days"),
        "2 tool calls",
        "the chart's own period is 30 days"
    );
    let day = overview(&s.w, &format!("?dashboard={board}&period=24h")).await;
    assert_eq!(
        number(&day, "Thirty days"),
        "1 tool call",
        "the switch shows the last 24 hours"
    );
    let week = overview(&s.w, &format!("?dashboard={board}&period=7d")).await;
    assert_eq!(number(&week, "Thirty days"), "1 tool call");
    let unknown = overview(&s.w, &format!("?dashboard={board}&period=1y")).await;
    assert_eq!(
        number(&unknown, "Thirty days"),
        "2 tool calls",
        "an unknown period is no override"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_data_table_numbers_equal_the_figure_titles() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[
            call(at - 2 * HOUR + 1, s.bob, s.demo, "alpha", "claude", Some(1)),
            call(at - 2 * HOUR + 2, s.bob, s.demo, "alpha", "claude", Some(1)),
        ],
    );
    let board = make_dashboard(
        &s.w,
        "Table",
        &[chart("Hours", "calls", "time", "bars", "24h")],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let titles = bar_titles(&page, "Hours");
    let table: Vec<String> = data_rows(&page, "Hours")
        .into_iter()
        .filter(|(_, value)| value != "0")
        .map(|(label, value)| format!("{label}: {value}"))
        .collect();
    assert_eq!(
        titles.len(),
        24,
        "every bucket has a mark, zero marks included"
    );
    assert_eq!(table, vec!["31 Dec 2029 22:00: 2".to_owned()]);
    assert!(titles.contains(&"31 Dec 2029 22:00 to 23:00 UTC: 2 tool calls".to_owned()));
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_labels_are_escaped_and_no_page_holds_a_script_or_a_style() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[call(
            at - 100,
            s.bob,
            s.demo,
            "\"><img src=x onerror=1>",
            "<script>alert(\"x\")</script>",
            Some(1),
        )],
    );
    let board = make_dashboard(
        &s.w,
        "Hostile",
        &[
            chart("Clients", "calls", "client", "ranked", "24h"),
            chart("Tools", "calls", "tool", "ranked", "24h"),
            chart("Per hour", "calls", "time", "bars", "24h"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let lower = page.body.to_ascii_lowercase();
    for banned in ["<script", " style=", "<style", "<img"] {
        assert!(
            !lower.contains(banned),
            "the overview must not contain {banned}"
        );
    }
    assert_eq!(
        ranked(&page, "Clients")[0].0,
        "<script>alert(\"x\")</script>",
        "the label is the stored text"
    );
    assert_eq!(
        ranked(&page, "Tools")[0].0,
        "demo / \"><img src=x onerror=1>"
    );
    for path in [LIST.to_owned(), format!("/admin/dashboards/{board}")] {
        let body = s.w.owner.get(&path).await.body.to_ascii_lowercase();
        for banned in ["<script", " style=", "<style"] {
            assert!(!body.contains(banned), "{path} must not contain {banned}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn overview_with_no_dashboards_has_a_note_and_a_link_and_keeps_its_counts() {
    let w = World::start().await;
    let deleted = w
        .owner
        .submit(LIST, "/admin/dashboards/1/delete", &[])
        .await;
    assert_eq!(deleted.status, 303);
    let page = overview(&w, "").await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.count("section.chart"),
        0,
        "no chart without a dashboard"
    );
    assert!(
        page.count(r#"a[href^="/admin/dashboards"]"#) >= 1,
        "the note links to the dashboards"
    );
    assert_eq!(
        page.count("div.counts a[data-count]"),
        4,
        "the four counters stay"
    );
    assert_eq!(
        page.count("section[data-latest-activity]"),
        1,
        "the latest activity stays"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_query_key_answers_200_and_takes_its_first_value() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[call(at - 100, s.bob, s.demo, "alpha", "claude", Some(1))],
    );
    let board = make_dashboard(
        &s.w,
        "Repeat",
        &[chart("Calls", "calls", "none", "number", "24h")],
    )
    .await;
    let page = overview(
        &s.w,
        &format!("?dashboard={board}&dashboard=999&period=7d&period=24h"),
    )
    .await;
    assert_eq!(page.status, 200, "a repeated key is not refused");
    assert_eq!(
        number(&page, "Calls"),
        "1 tool call",
        "the first period, 7 days, applies"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_data_says_no_activity_in_this_period() {
    let w = World::start().await;
    let page = overview(&w, "").await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.body.matches(NO_ACTIVITY).count(),
        9,
        "nine of the ten Usage charts have no data and say so"
    );
    assert_eq!(
        page.body
            .matches("Every listed tool was called in this period.")
            .count(),
        1,
        "the unused tools chart with no tool to list says every listed tool was called"
    );
    let board = make_dashboard(
        &w,
        "Empty",
        &[chart("Zero", "calls", "none", "number", "24h")],
    )
    .await;
    let page = overview(&w, &format!("?dashboard={board}")).await;
    assert_eq!(
        number(&page, "Zero"),
        "0 tool calls",
        "a number is always a figure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_at_90_days_over_200000_rows_answers_in_under_three_seconds() {
    let s = seeded().await;
    let at = now();
    let mut rows = Vec::with_capacity(200_000);
    for index in 0..200_000i64 {
        let offset = (index * 37) % (90 * DAY);
        let user = if index % 2 == 0 { s.bob } else { s.carol };
        let server = if index % 3 == 0 { s.demo } else { s.other };
        let tool = ["alpha", "beta", "gamma", "delta"][(index % 4) as usize];
        rows.push(if index % 97 == 0 {
            refused(at - offset, user, server, tool, "claude")
        } else {
            call(
                at - offset,
                user,
                server,
                tool,
                "claude",
                Some(1 + index % 500),
            )
        });
    }
    let started = Instant::now();
    insert(s.w.gw.db_path().as_path(), &rows);
    let seeding = started.elapsed();
    let started = Instant::now();
    let page = overview(&s.w, "?period=90d").await;
    let elapsed = started.elapsed();
    assert_eq!(page.status, 200);
    assert!(
        elapsed.as_secs_f64() < 3.0,
        "the overview took {elapsed:?} (seeding took {seeding:?})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_edit_page_of_a_chart_with_a_server_filter_keeps_it_selected() {
    let s = seeded().await;
    let mut filtered = chart("Filtered", "calls", "tool", "ranked", "30d");
    filtered.server_id = s.demo.0.to_string();
    let board = make_dashboard(&s.w, "Edit", &[filtered]).await;
    let chart_id: i64 = open(&s.w)
        .query_row(
            "SELECT id FROM charts WHERE title = 'Filtered'",
            [],
            |row| row.get(0),
        )
        .expect("the chart is stored");
    let page =
        s.w.owner
            .get(&format!("/admin/dashboards/{board}?chart={chart_id}"))
            .await;
    assert_eq!(page.status, 200);
    let doc = Html::parse_document(&page.body);
    let server = Selector::parse("select#chart-server option[selected]").expect("a selector");
    let chosen: Vec<String> = doc
        .select(&server)
        .filter_map(|option| option.value().attr("value").map(str::to_owned))
        .collect();
    assert_eq!(chosen, vec![s.demo.0.to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_time_scale_is_drawn_inside_its_own_svg() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let board = make_dashboard(
        &s.w,
        "Scale",
        &[
            chart("Bars", "calls", "time", "bars", "7d"),
            chart("Line", "calls", "time", "line", "7d"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let doc = Html::parse_document(&page.body);
    let svgs = Selector::parse("svg.time").expect("a selector");
    let labels = Selector::parse(":scope > g.y > text").expect("a selector");
    let plot = Selector::parse(":scope > svg.plot-area").expect("a selector");
    let bars = Selector::parse("svg.plot-area g.marks rect.bar").expect("a selector");
    let mut charts = 0;
    for time in doc.select(&svgs) {
        charts += 1;
        let texts: Vec<_> = time.select(&labels).collect();
        assert!(texts.len() >= 2, "the scale has its zero and its steps");
        for text in texts {
            assert_eq!(
                text.value().attr("x"),
                Some("100%"),
                "a scale figure ends at the svg's right edge"
            );
            assert!(
                text.value().attr("dx").is_none(),
                "no figure is pushed outside the svg"
            );
        }
        let inner = time.select(&plot).next().expect("the plot has its own svg");
        assert_eq!(
            inner.value().attr("width"),
            Some("calc(100% - 48px)"),
            "the plot leaves the scale column inside the svg"
        );
        for bar in time.select(&bars) {
            let x: f64 = bar
                .value()
                .attr("x")
                .expect("x")
                .trim_end_matches('%')
                .parse()
                .expect("a percentage");
            let w: f64 = bar
                .value()
                .attr("width")
                .expect("width")
                .trim_end_matches('%')
                .parse()
                .expect("a percentage");
            assert!(
                x >= 0.0 && x + w <= 100.0,
                "a bar stays inside the plot: {x} + {w}"
            );
        }
    }
    assert_eq!(charts, 2, "both time charts are drawn");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_caption_names_each_scope_filter_in_force_in_design_order() {
    let s = seeded().await;
    insert(
        &s.w.gw.db_path(),
        &[call(now() - 60, s.bob, s.demo, "alpha", "claude", Some(5))],
    );
    let mut scoped = chart("Scoped", "calls", "time", "bars", "30d");
    scoped.server_id = s.demo.0.to_string();
    scoped.user_id = s.bob.0.to_string();
    scoped.tool = "alpha";
    let board = make_dashboard(&s.w, "Scope", &[scoped]).await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let doc = Html::parse_document(&page.body);
    let caption = Selector::parse(r#"p[id$="-caption"]"#).expect("a selector");
    let found: Vec<String> = section(&doc, "Scoped")
        .select(&caption)
        .map(text_of)
        .collect();
    assert_eq!(
        found,
        vec![format!(
            "Tool calls let through per day on demo by {BOB} of alpha, last 30 days."
        )],
        "the caption names the server, user and tool in force"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duration_number_carries_its_unit() {
    let s = seeded().await;
    insert(
        &s.w.gw.db_path(),
        &[call(
            now() - 60,
            s.bob,
            s.demo,
            "alpha",
            "claude",
            Some(5813),
        )],
    );
    let median = chart("Median now", "duration_median", "none", "number", "30d");
    let board = make_dashboard(&s.w, "Units", &[median]).await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    assert_eq!(number(&page, "Median now"), "5,813 ms");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_to_a_deleted_user_or_server_opens_the_rows_it_counts() {
    let s = seeded().await;
    insert(s.w.gw.db_path().as_path(), &day_dataset(&s));
    let bob = s.bob.0.to_string();
    let other = s.other.0.to_string();
    assert_eq!(
        admin::user_action(&s.w.owner, &bob, "delete").await.status,
        303
    );
    assert_eq!(admin::delete_server(&s.w.owner, &other).await.status, 303);
    let board = make_dashboard(
        &s.w,
        "Gone",
        &[
            chart("Calls by user", "calls", "user", "ranked", "24h"),
            chart("Failed by server", "failed", "server", "ranked", "24h"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let users = ranked(&page, "Calls by user");
    assert!(
        users.iter().any(|(label, _, href)| label == BOB
            && href
                .as_deref()
                .is_some_and(|href| href.contains("email=bob%40example.com"))),
        "bob's link names his recorded email"
    );
    let servers = ranked(&page, "Failed by server");
    assert!(
        servers.iter().any(|(label, _, href)| label == "other"
            && href
                .as_deref()
                .is_some_and(|href| href.contains("slug=other"))),
        "the deleted server's link names its recorded slug"
    );
    for title in ["Calls by user", "Failed by server"] {
        for (label, value, href) in ranked(&page, title) {
            let href = href.unwrap_or_else(|| panic!("{title}: {label} is a link"));
            assert!(
                !href.contains("q="),
                "{title}: {label} is not a substring search: {href}"
            );
            let shown: i64 = value.replace(',', "").parse().expect("a value");
            assert_eq!(
                activity_total(&s.w.owner, &href).await,
                shown,
                "{title}: the page for {label} counts the bar"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_to_an_email_held_by_two_accounts_opens_the_rows_of_both() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[call(at - 100, s.bob, s.demo, "alpha", "claude", Some(10))],
    );
    let old = s.bob.0.to_string();
    assert_eq!(
        admin::user_action(&s.w.owner, &old, "delete").await.status,
        303
    );
    s.w.user(BOB).await;
    let new: i64 = s.w.user_id(BOB).await.parse().expect("an id");
    assert_ne!(new, s.bob.0, "the account is a new one");
    insert(
        s.w.gw.db_path().as_path(),
        &[call(
            at - 200,
            (new, BOB),
            s.demo,
            "alpha",
            "claude",
            Some(20),
        )],
    );
    let board = make_dashboard(
        &s.w,
        "Twice",
        &[chart("Calls by user", "calls", "user", "ranked", "24h")],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    let rows = ranked(&page, "Calls by user");
    let (_, value, href) = rows
        .iter()
        .find(|(label, _, _)| label == BOB)
        .expect("bob's row");
    assert_eq!(
        value, "2",
        "both accounts' calls are counted under the email"
    );
    let href = href.clone().expect("bob's row is a link");
    assert_eq!(
        activity_total(&s.w.owner, &href).await,
        2,
        "the link opens the calls of both accounts"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duration_link_opens_every_let_through_call_including_the_failed_ones() {
    let s = seeded().await;
    let at = now();
    insert(
        s.w.gw.db_path().as_path(),
        &[
            call(at - 100, s.bob, s.demo, "alpha", "claude", Some(10)),
            failed(at - 200, s.bob, s.demo, "alpha", "claude", Some(20)),
            refused(at - 300, s.bob, s.demo, "alpha", "claude"),
        ],
    );
    let board = make_dashboard(
        &s.w,
        "Durations",
        &[
            chart("Median by tool", "duration_median", "tool", "ranked", "24h"),
            chart("People by tool", "active_users", "tool", "ranked", "24h"),
        ],
    )
    .await;
    let page = overview(&s.w, &format!("?dashboard={board}")).await;
    for title in ["Median by tool", "People by tool"] {
        let (_, _, href) = ranked(&page, title)
            .into_iter()
            .find(|(label, _, _)| label == "demo / alpha")
            .unwrap_or_else(|| panic!("{title} has demo / alpha"));
        let href = href.expect("a link");
        assert!(href.contains("event=tool_let_through"), "{href}");
        assert_eq!(
            activity_total(&s.w.owner, &href).await,
            2,
            "{title} opens the two let-through calls, the failed one included, not the refused one"
        );
    }
}
