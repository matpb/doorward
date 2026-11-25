mod common;

use std::path::Path;

use common::admin;
use common::client::Page;
use common::upstream::{Mode, UpstreamOptions};
use common::world::World;
use form_urlencoded::Serializer;
use rusqlite::{Connection, params};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const NOW: &str = "2030-01-01T00:00:00Z";
const DAY: i64 = 86_400;
const FORM: &str = r#"form[data-form="activity-filter"]"#;

/// An event key, the tags of its seeded rows, and the (server, tool) of its real calls.
type Expectation<'a> = (&'a str, Vec<&'a str>, Vec<(&'a str, &'a str)>);

/// One activity row written straight into the table. Empty text is an empty column.
#[derive(Default)]
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
}

fn stamp(text: &str) -> i64 {
    OffsetDateTime::parse(text, &Rfc3339)
        .expect("the time is RFC 3339")
        .unix_timestamp()
}

/// The unix time `seconds` before the test clock.
fn ago(seconds: i64) -> i64 {
    stamp(NOW) - seconds
}

/// A world whose clock reads NOW, the instant the harness clock starts at. The clock stays there:
/// moving it would expire the owner's session.
async fn world() -> World {
    World::start().await
}

fn id(text: String) -> i64 {
    text.parse().expect("an id is a number")
}

/// Creates the user and returns its id.
async fn add_user(w: &World, email: &str) -> i64 {
    w.user(email).await;
    id(w.user_id(email).await)
}

fn insert(db: &Path, rows: &[Row]) {
    let mut conn = Connection::open(db).expect("the gateway database opens");
    let tx = conn.transaction().expect("a transaction opens");
    for row in rows {
        tx.execute(
            "INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, \
             client, decision, outcome, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
            ],
        )
        .expect("an activity row is inserted");
    }
    tx.commit().expect("the activity rows are committed");
}

/// An allowed call that succeeded, as the proxy records it.
fn call(
    at: i64,
    who: (i64, &'static str),
    server: (i64, &'static str),
    tool: &'static str,
    client: &'static str,
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
        ..Row::default()
    }
}

fn login(at: i64, who: (i64, &'static str), tool: &'static str) -> Row {
    Row {
        at,
        kind: "login",
        user_id: Some(who.0),
        user: who.1,
        tool,
        outcome: "ok",
        ..Row::default()
    }
}

/// A query string from pairs, each value percent-encoded.
fn query(pairs: &[(&str, &str)]) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

/// The activity page for a query string, read as the owner.
async fn list(w: &World, filter: &str) -> Page {
    w.owner.get(&format!("/admin/activity?{filter}")).await
}

/// The tools of the rows whose tool starts with `prefix`, sorted.
fn tagged(page: &Page, prefix: &str) -> Vec<String> {
    let mut tools: Vec<String> = page
        .attrs("tr[data-kind]", "data-tool")
        .into_iter()
        .filter(|tool| tool.starts_with(prefix))
        .collect();
    tools.sort();
    tools
}

/// The tools of the seeded rows of this file, which all start with `s-`.
fn seeded(page: &Page) -> Vec<String> {
    tagged(page, "s-")
}

/// The number of rows the count line reports, when there is a count line.
fn total(page: &Page) -> Option<usize> {
    let text = page.text("[data-range]")?;
    text.rsplit(' ').next()?.parse().ok()
}

/// The (name, value) pairs of a link's query string.
fn pairs_of(href: &str) -> Vec<(String, String)> {
    let url = Url::parse(&format!("http://127.0.0.1{href}")).expect("a link is a path");
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn values_of(pairs: &[(String, String)], key: &str) -> Vec<String> {
    pairs
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
        .collect()
}

/// (kind, server, tool) of every tool_call row whose tool is not a seeded `e-` tool, sorted.
fn real_calls(page: &Page) -> Vec<(String, String)> {
    let kinds = page.attrs("tr[data-kind]", "data-kind");
    let servers = page.attrs("tr[data-kind]", "data-server");
    let tools = page.attrs("tr[data-kind]", "data-tool");
    let mut found: Vec<(String, String)> = kinds
        .iter()
        .zip(servers.iter().zip(tools.iter()))
        .filter(|(kind, (_, tool))| kind.as_str() == "tool_call" && !tool.starts_with("e-"))
        .map(|(_, (server, tool))| (server.clone(), tool.clone()))
        .collect();
    found.sort();
    found
}

#[tokio::test(flavor = "multi_thread")]
async fn each_filter_alone_narrows_the_page() {
    let w = world().await;
    w.user(BOB).await;
    w.user(CAROL).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let (_beta_up, beta) = w.upstream("beta", UpstreamOptions::default()).await;
    let bob = id(w.user_id(BOB).await);
    let carol = id(w.user_id(CAROL).await);
    let alpha_id = id(alpha);
    let beta_id = id(beta);
    insert(
        &w.gw.db_path(),
        &[
            call(
                ago(60),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-echo",
                "claude-desktop",
            ),
            call(
                ago(120),
                (carol, CAROL),
                (alpha_id, "alpha"),
                "s-search",
                "cursor",
            ),
            call(ago(180), (bob, BOB), (beta_id, "beta"), "s-list", "cursor"),
            login(ago(240), (bob, BOB), "s-login"),
            call(
                ago(3 * DAY),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-old",
                "cursor",
            ),
        ],
    );
    let cases: Vec<(String, Vec<&str>)> = vec![
        (
            "period=24h".to_string(),
            vec!["s-echo", "s-list", "s-login", "s-search"],
        ),
        (
            "event=tool_call".to_string(),
            vec!["s-echo", "s-list", "s-old", "s-search"],
        ),
        (
            format!("user={bob}"),
            vec!["s-echo", "s-list", "s-login", "s-old"],
        ),
        (
            format!("server={alpha_id}"),
            vec!["s-echo", "s-old", "s-search"],
        ),
        ("tool=s-search".to_string(), vec!["s-search"]),
        (
            "client=cursor".to_string(),
            vec!["s-list", "s-old", "s-search"],
        ),
        ("q=CLAUDE".to_string(), vec!["s-echo"]),
    ];
    for (filter, expected) in cases {
        let page = list(&w, &filter).await;
        assert_eq!(page.status, 200, "{filter} must answer 200");
        assert_eq!(
            seeded(&page),
            expected,
            "{filter} must show exactly the seeded rows it names"
        );
    }
    let by_tool = list(&w, "tool=s-search").await;
    assert_eq!(
        total(&by_tool),
        Some(1),
        "the count line must count the one row the tool filter matches"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn three_filters_combine_with_and() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let (_beta_up, beta) = w.upstream("beta", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let beta_id = id(beta);
    insert(
        &w.gw.db_path(),
        &[
            call(ago(60), (bob, BOB), (alpha_id, "alpha"), "s-echo", "cursor"),
            call(
                ago(3 * DAY),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-old",
                "cursor",
            ),
            call(ago(180), (bob, BOB), (beta_id, "beta"), "s-list", "cursor"),
            login(ago(240), (bob, BOB), "s-login"),
        ],
    );
    let page = list(
        &w,
        &format!("user={bob}&server={alpha_id}&event=tool_call&period=24h"),
    )
    .await;
    assert_eq!(
        seeded(&page),
        vec!["s-echo"],
        "user, server, event and period together show only the row that meets all four"
    );
    let page = list(&w, &format!("user={bob}&client=cursor&server={beta_id}")).await;
    assert_eq!(
        seeded(&page),
        vec!["s-list"],
        "user, client and server together show only the row that meets all three"
    );
    let page = list(&w, "client=cursor&event=tool_call&period=7d&q=s-").await;
    assert_eq!(
        seeded(&page),
        vec!["s-echo", "s-list", "s-old"],
        "client, event, period and q together show every call of the last 7 days from cursor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custom_day_range_includes_its_first_and_last_second_only() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[
            call(
                stamp("2030-01-04T23:59:59Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-before",
                "c",
            ),
            call(
                stamp("2030-01-05T00:00:00Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-first",
                "c",
            ),
            call(
                stamp("2030-01-05T12:00:00Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-inside",
                "c",
            ),
            call(
                stamp("2030-01-06T23:59:59Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-last",
                "c",
            ),
            call(
                stamp("2030-01-07T00:00:00Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-after",
                "c",
            ),
        ],
    );
    let page = list(&w, "period=custom&from=2030-01-05&to=2030-01-06").await;
    assert_eq!(
        seeded(&page),
        vec!["s-first", "s-inside", "s-last"],
        "a range from the 5th to the 6th holds the first second of the 5th and the last of the 6th"
    );
    let page = list(&w, "period=custom&from=2030-01-05&to=2030-01-05").await;
    assert_eq!(
        seeded(&page),
        vec!["s-first", "s-inside"],
        "a range of one day ends at its last second"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rolling_period_counts_back_from_the_clock() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[
            call(ago(60), (bob, BOB), (alpha_id, "alpha"), "s-recent", "c"),
            call(ago(DAY), (bob, BOB), (alpha_id, "alpha"), "s-edge24", "c"),
            call(
                ago(DAY + 1),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-past24",
                "c",
            ),
            call(
                ago(7 * DAY),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-edge7",
                "c",
            ),
            call(
                ago(7 * DAY + 1),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-past7",
                "c",
            ),
        ],
    );
    let page = list(&w, "period=24h").await;
    assert_eq!(
        seeded(&page),
        vec!["s-edge24", "s-recent"],
        "24 hours back from the clock includes the row exactly a day old and not the one a second older"
    );
    let page = list(&w, "period=7d").await;
    assert_eq!(
        seeded(&page),
        vec!["s-edge24", "s-edge7", "s-past24", "s-recent"],
        "7 days back from the clock includes the row exactly 7 days old and not the one a second older"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn q_treats_percent_and_underscore_as_literal_text() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let plain = |tool: &'static str| call(ago(60), (bob, BOB), (alpha_id, "alpha"), tool, "c");
    insert(
        &w.gw.db_path(),
        &[
            plain("s-a_b"),
            plain("s-axb"),
            Row {
                detail: "50% off",
                ..plain("s-pct")
            },
            Row {
                detail: r"C:\dir",
                ..plain("s-bs")
            },
            plain("s-UPPER"),
        ],
    );
    let cases = [
        ("_", vec!["s-a_b"]),
        ("%", vec!["s-pct"]),
        (r"\", vec!["s-bs"]),
        ("upper", vec!["s-UPPER"]),
        ("UpPeR", vec!["s-UPPER"]),
        ("a_b", vec!["s-a_b"]),
    ];
    for (text, expected) in cases {
        let page = list(&w, &query(&[("q", text)])).await;
        assert_eq!(page.status, 200, "q={text} must answer 200");
        assert_eq!(
            seeded(&page),
            expected,
            "q={text} must match the rows that hold it, with % and _ literal and any case"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_event_key_selects_its_kinds() {
    let w = world().await;
    let bob_client = w.user(BOB).await;
    let bob = id(w.user_id(BOB).await);
    let (_demo_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let errors_options = UpstreamOptions {
        mode: Mode::ToolErrors,
        ..UpstreamOptions::default()
    };
    let (_errors_up, errors) = w.upstream("errors", errors_options).await;
    w.grant(BOB, &[demo.as_str(), errors.as_str()]).await;

    let demo_tokens = w.token(&bob_client, "demo").await;
    let demo_mcp = w.session_mcp("demo", &demo_tokens);
    assert_eq!(
        demo_mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let answered = demo_mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(answered.status, 200, "the allowed call must answer 200");
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(demo.as_str()),
        Some("delete_db"),
    )
    .await;
    assert_eq!(page.status, 303, "the deny rule must be saved");
    let refused = demo_mcp.call_tool("delete_db", json!({})).await;
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "the denied call must be refused"
    );

    let errors_tokens = w.token(&bob_client, "errors").await;
    let errors_mcp = w.session_mcp("errors", &errors_tokens);
    assert_eq!(
        errors_mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let failed = errors_mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(failed.status, 200, "the tool error must be answered 200");

    let ago60 = ago(60);
    let seeded_row = |kind: &'static str, tool: &'static str| Row {
        at: ago60,
        kind,
        user_id: Some(bob),
        user: BOB,
        tool,
        outcome: "ok",
        ..Row::default()
    };
    let call_row = |decision: &'static str,
                    outcome: &'static str,
                    detail: &'static str,
                    tool: &'static str| {
        Row {
            decision,
            outcome,
            detail,
            ..seeded_row("tool_call", tool)
        }
    };
    insert(
        &w.gw.db_path(),
        &[
            call_row("allow", "ok", "", "e-tool_call"),
            call_row("deny", "refused", "", "e-tool_refused"),
            call_row("allow", "error", "", "e-tool_failed"),
            call_row(
                "allow",
                "ok",
                "the tool reported an error",
                "e-tool_error_marker",
            ),
            seeded_row("login", "e-sign_in"),
            seeded_row("login_failed", "e-sign_in_refused"),
            seeded_row("client_connected", "e-client"),
            seeded_row("client_disconnected", "e-client-off"),
            seeded_row("admin_change", "e-admin_change"),
            seeded_row("invitation", "e-invitation"),
            seeded_row("owner_created", "e-owner"),
            seeded_row("reset", "e-reset"),
            seeded_row("password_change", "e-password"),
            seeded_row("mail_failed", "e-mail"),
            seeded_row("unlock", "e-unlock"),
            seeded_row("mystery_kind", "e-unknown"),
        ],
    );

    let expectations: [Expectation<'static>; 11] = [
        (
            "tool_any",
            vec![
                "e-tool_call",
                "e-tool_error_marker",
                "e-tool_failed",
                "e-tool_refused",
            ],
            vec![("demo", "delete_db"), ("demo", "echo"), ("errors", "echo")],
        ),
        ("tool_call", vec!["e-tool_call"], vec![("demo", "echo")]),
        (
            "tool_refused",
            vec!["e-tool_refused"],
            vec![("demo", "delete_db")],
        ),
        (
            "tool_failed",
            vec!["e-tool_error_marker", "e-tool_failed"],
            vec![("errors", "echo")],
        ),
        ("sign_in", vec!["e-sign_in"], vec![]),
        ("sign_in_refused", vec!["e-sign_in_refused"], vec![]),
        ("client", vec!["e-client", "e-client-off"], vec![]),
        ("admin_change", vec!["e-admin_change"], vec![]),
        ("invitation", vec!["e-invitation"], vec![]),
        ("account", vec!["e-owner", "e-password", "e-reset"], vec![]),
        ("other", vec!["e-mail", "e-unknown", "e-unlock"], vec![]),
    ];
    for (key, tags, calls) in expectations {
        let page = list(&w, &format!("event={key}")).await;
        assert_eq!(page.status, 200, "event={key} must answer 200");
        assert_eq!(
            tagged(&page, "e-"),
            tags,
            "event={key} must show exactly the seeded rows of that event"
        );
        let mut want: Vec<(String, String)> = calls
            .into_iter()
            .map(|(server, tool)| (server.to_string(), tool.to_string()))
            .collect();
        want.sort();
        assert_eq!(
            real_calls(&page),
            want,
            "event={key} must show exactly the real calls of that event"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_that_names_nothing_shows_nothing() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[call(
            ago(60),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-echo",
            "c",
        )],
    );
    let shown = list(&w, "period=all").await;
    assert_eq!(
        seeded(&shown),
        vec!["s-echo"],
        "period=all must show the seeded row"
    );

    for filter in [
        "period=weekly".to_string(),
        "event=bogus".to_string(),
        "user=abc".to_string(),
        "server=12x".to_string(),
        "period=custom&from=2030-01-05&to=2030-01-05&user=abc".to_string(),
        "period=custom&from=2030-01-10&to=2030-01-05".to_string(),
    ] {
        let page = list(&w, &filter).await;
        assert_eq!(page.status, 200, "{filter} must answer 200");
        assert_eq!(page.count("tr[data-kind]"), 0, "{filter} must show no row");
        assert!(
            page.body.contains("No activity matches these filters."),
            "{filter} must say No activity matches these filters."
        );
    }

    let page = list(&w, "period=custom").await;
    assert_eq!(
        page.count("tr[data-kind]"),
        0,
        "a custom period with no day must show no row"
    );
    assert_eq!(
        page.text("p#filter-from-error").as_deref(),
        Some("Enter the first day as YYYY-MM-DD."),
        "a missing first day must have its field error"
    );
    assert_eq!(
        page.text("p#filter-to-error").as_deref(),
        Some("Enter the last day as YYYY-MM-DD."),
        "a missing last day must have its field error"
    );
    assert_eq!(
        page.attr("input#filter-from", "aria-invalid").as_deref(),
        Some("true"),
        "the first day field must be marked invalid"
    );
    assert_eq!(
        page.attr("input#filter-from", "aria-describedby")
            .as_deref(),
        Some("filter-from-error"),
        "the first day field must be described by its error"
    );

    let page = list(&w, "period=custom&from=2030-02-30&to=2030-01-10").await;
    assert_eq!(
        page.count("tr[data-kind]"),
        0,
        "a day that does not exist must show no row"
    );
    assert_eq!(
        page.text("p#filter-from-error").as_deref(),
        Some("Enter the first day as YYYY-MM-DD."),
        "a day that is not a date must have its field error"
    );
    assert_eq!(
        page.count("p#filter-to-error"),
        0,
        "a valid last day must have no field error"
    );

    let page = list(&w, "period=custom&from=2030-01-10&to=2030-01-05").await;
    assert_eq!(
        page.count("p.field-error"),
        0,
        "a first day after the last day is not a field error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_key_answers_200_and_takes_its_first_value() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let carol = add_user(&w, CAROL).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[
            call(ago(60), (bob, BOB), (alpha_id, "alpha"), "s-echo", "cursor"),
            call(
                ago(3 * DAY),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-old",
                "cursor",
            ),
            call(
                ago(120),
                (carol, CAROL),
                (alpha_id, "alpha"),
                "s-search",
                "cursor",
            ),
            login(ago(240), (bob, BOB), "s-login"),
        ],
    );
    let cases: Vec<(String, Vec<&str>)> = vec![
        (
            format!("user={bob}&user={carol}"),
            vec!["s-echo", "s-login", "s-old"],
        ),
        (
            format!("server={alpha_id}&server=abc"),
            vec!["s-echo", "s-old", "s-search"],
        ),
        (
            "period=24h&period=all".to_string(),
            vec!["s-echo", "s-login", "s-search"],
        ),
        (
            "event=tool_call&event=login".to_string(),
            vec!["s-echo", "s-old", "s-search"],
        ),
    ];
    for (filter, expected) in cases {
        let page = list(&w, &filter).await;
        assert_eq!(page.status, 200, "{filter} must answer 200");
        assert_eq!(
            seeded(&page),
            expected,
            "{filter} must take the first value of each key"
        );
    }
    let page = list(&w, "page=2&page=1").await;
    assert_eq!(page.status, 200, "a repeated page key must answer 200");
    assert_eq!(
        page.count("tr[data-kind]"),
        0,
        "the first page value 2 must be the page shown, past the end"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn paging_and_remove_links_keep_the_other_filters() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let carol = add_user(&w, CAROL).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let mut rows = Vec::new();
    for index in 0..60 {
        rows.push(call(
            ago(60 + index * 10),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-page",
            "cursor",
        ));
    }
    for index in 0..5 {
        rows.push(call(
            ago(900 + index * 10),
            (carol, CAROL),
            (alpha_id, "alpha"),
            "s-page",
            "cursor",
        ));
        rows.push(call(
            ago(1000 + index * 10),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-page",
            "other",
        ));
    }
    insert(&w.gw.db_path(), &rows);
    let filter = format!("user={bob}&server={alpha_id}&client=cursor&q=page");

    let first = list(&w, &filter).await;
    assert_eq!(total(&first), Some(60), "the filtered count must be 60");
    let older = first
        .attr(r#"a[data-page-link="older"]"#, "href")
        .expect("page 1 must link to the older rows");
    let pairs = pairs_of(&older);
    assert_eq!(
        values_of(&pairs, "page"),
        vec!["2"],
        "the older link must set page 2"
    );
    assert_eq!(
        values_of(&pairs, "user"),
        vec![bob.to_string()],
        "the older link keeps the user"
    );
    assert_eq!(
        values_of(&pairs, "server"),
        vec![alpha_id.to_string()],
        "the older link keeps the server"
    );
    assert_eq!(
        values_of(&pairs, "client"),
        vec!["cursor"],
        "the older link keeps the client"
    );
    assert_eq!(
        values_of(&pairs, "q"),
        vec!["page"],
        "the older link keeps q"
    );

    for key in ["user", "server", "client", "q"] {
        let href = first
            .attr(
                &format!(r#"ul#active-filters li[data-filter="{key}"] a"#),
                "href",
            )
            .unwrap_or_else(|| panic!("the chip of {key} must hold a Remove link"));
        let pairs = pairs_of(&href);
        assert!(
            values_of(&pairs, key).is_empty(),
            "the Remove link of {key} must drop {key}"
        );
        assert!(
            values_of(&pairs, "page").is_empty(),
            "a Remove link must drop page"
        );
        for other in ["user", "server", "client", "q"] {
            if other != key {
                assert!(
                    !values_of(&pairs, other).is_empty(),
                    "the Remove link of {key} must keep {other}, got {href}"
                );
            }
        }
    }

    let second = list(&w, &format!("{filter}&page=2")).await;
    assert_eq!(
        total(&second),
        Some(60),
        "page 2 must count the same 60 rows"
    );
    let newer = second
        .attr(r#"a[data-page-link="newer"]"#, "href")
        .expect("page 2 must link to the newer rows");
    let pairs = pairs_of(&newer);
    assert_eq!(
        values_of(&pairs, "page"),
        vec!["1"],
        "the newer link must set page 1"
    );
    assert_eq!(
        values_of(&pairs, "client"),
        vec!["cursor"],
        "the newer link keeps the client"
    );
    assert_eq!(
        values_of(&pairs, "q"),
        vec!["page"],
        "the newer link keeps q"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_filters_shows_only_while_a_filter_is_active() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[call(
            ago(60),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-echo",
            "c",
        )],
    );
    let page = list(&w, "").await;
    assert_eq!(
        page.count("a#clear-filters"),
        0,
        "no filter means no Clear filters link"
    );
    assert_eq!(
        page.count("ul#active-filters"),
        0,
        "no filter means no list of active filters"
    );

    let page = list(&w, "period=all&q=").await;
    assert_eq!(
        page.count("a#clear-filters"),
        0,
        "period all and an empty q are no filter"
    );
    assert_eq!(
        page.count("ul#active-filters"),
        0,
        "period all and an empty q list no chip"
    );

    let page = list(&w, "tool=s-echo").await;
    assert_eq!(
        page.attr("a#clear-filters", "href").as_deref(),
        Some("/admin/activity"),
        "an active filter shows Clear filters, linking to the plain page"
    );
    assert_eq!(
        page.text("a#clear-filters").as_deref(),
        Some("Clear filters"),
        "the link reads Clear filters"
    );
    assert_eq!(
        page.count("ul#active-filters li[data-filter]"),
        1,
        "one chip per active filter"
    );
    let chip = r#"ul#active-filters li[data-filter="tool"] a.chip"#;
    assert_eq!(
        page.text(&format!("{chip} .chip-key")).as_deref(),
        Some("Tool"),
        "the chip names its filter"
    );
    assert_eq!(
        page.text(&format!("{chip} .chip-value")).as_deref(),
        Some("s-echo"),
        "the chip shows its value"
    );
    assert_eq!(
        page.text(&format!("{chip} .sr-only")).as_deref(),
        Some("Remove this filter"),
        "the chip is a link that removes the filter"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_count_line_counts_the_filtered_rows() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let carol = add_user(&w, CAROL).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[
            call(ago(60), (bob, BOB), (alpha_id, "alpha"), "s-echo", "c"),
            call(
                ago(120),
                (carol, CAROL),
                (alpha_id, "alpha"),
                "s-search",
                "c",
            ),
        ],
    );
    let page = list(&w, "q=s-search").await;
    assert_eq!(
        page.text("[data-range]").as_deref(),
        Some("Rows 1 to 1 of 1"),
        "the count line must count the filtered rows"
    );
    let page = list(&w, "q=nothing-matches-this").await;
    assert_eq!(
        page.count("[data-range]"),
        0,
        "no match means no count line"
    );
    assert!(
        page.body.contains("No activity matches these filters."),
        "no match must say No activity matches these filters."
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_filter_form_reflects_the_query_and_labels_every_control() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[call(
            ago(60),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-echo",
            "cursor",
        )],
    );
    let filter = format!(
        "period=custom&from=2030-01-05&to=2030-01-06&event=tool_failed&user={bob}&server={alpha_id}&tool=s-echo&client=cursor&q=ab"
    );
    let page = list(&w, &filter).await;
    assert_eq!(page.status, 200, "the filtered page must answer 200");
    assert_eq!(page.count(FORM), 1, "the page must hold one filter form");
    assert_eq!(
        page.attr(FORM, "method").as_deref(),
        Some("get"),
        "the form must submit with GET"
    );
    assert_eq!(
        page.attr(FORM, "action").as_deref(),
        Some("/admin/activity"),
        "the form must submit to the activity page"
    );
    let controls = [
        ("filter-period", "Period"),
        ("filter-from", "From"),
        ("filter-to", "To"),
        ("filter-event", "Event"),
        ("filter-user", "User"),
        ("filter-server", "Server"),
        ("filter-tool", "Tool"),
        ("filter-client", "Client"),
        ("filter-q", "Search"),
    ];
    for (control, label) in controls {
        assert_eq!(
            page.count(&format!("#{control}")),
            1,
            "{control} must be one element"
        );
        assert_eq!(
            page.text(&format!(r#"label[for="{control}"]"#)).as_deref(),
            Some(label),
            "{control} must be labelled {label}"
        );
    }
    assert_eq!(
        page.attr("select#filter-period option[selected]", "value")
            .as_deref(),
        Some("custom"),
        "the period select must show custom"
    );
    assert_eq!(
        page.attr("input#filter-from", "type").as_deref(),
        Some("date")
    );
    assert_eq!(
        page.attr("input#filter-from", "value").as_deref(),
        Some("2030-01-05")
    );
    assert_eq!(
        page.attr("input#filter-to", "type").as_deref(),
        Some("date")
    );
    assert_eq!(
        page.attr("input#filter-to", "value").as_deref(),
        Some("2030-01-06")
    );
    assert_eq!(
        page.attr("select#filter-event option[selected]", "value")
            .as_deref(),
        Some("tool_failed"),
        "the event select must show tool_failed"
    );
    assert_eq!(
        page.attr("select#filter-user option[selected]", "value"),
        Some(bob.to_string()),
        "the user select must show bob"
    );
    assert_eq!(
        page.attr("select#filter-server option[selected]", "value"),
        Some(alpha_id.to_string()),
        "the server select must show alpha"
    );
    assert_eq!(
        page.attr("input#filter-tool", "type").as_deref(),
        Some("text")
    );
    assert_eq!(
        page.attr("input#filter-tool", "value").as_deref(),
        Some("s-echo")
    );
    assert_eq!(
        page.attr("select#filter-client option[selected]", "value")
            .as_deref(),
        Some("cursor"),
        "the client select must show cursor"
    );
    assert_eq!(
        page.attr("input#filter-q", "type").as_deref(),
        Some("search")
    );
    assert_eq!(page.attr("input#filter-q", "value").as_deref(), Some("ab"));
    assert_eq!(
        page.texts(&format!("{FORM} button")),
        vec!["Filter".to_string()],
        "the form must hold one button reading Filter"
    );
    assert_eq!(
        page.text(r#"select#filter-event option[value="tool_any"]"#)
            .as_deref(),
        Some("Any tool call"),
        "the event select lists tool_any as Any tool call"
    );

    assert_eq!(
        page.count("a#export-csv"),
        0,
        "a filter that matches no row has no export link"
    );
    assert_eq!(
        page.text("div.empty p").as_deref(),
        Some(
            "Remove one of them above, or clear the filters. Activity older than 90 days is not kept."
        ),
        "the empty state says what is not kept"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_link_keeps_the_filters_and_shows_only_with_rows() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[call(
            ago(60),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-echo",
            "cursor",
        )],
    );
    let page = list(&w, "client=cursor&q=s-echo&period=7d").await;
    assert_eq!(
        page.count("a#export-csv"),
        0,
        "the export is a button, not a link"
    );
    assert_eq!(
        page.text("button#export-csv").as_deref(),
        Some("Export 1 row as CSV"),
        "the export button names the one row the filters hold"
    );
    assert_eq!(
        page.attr("form.export-form", "action").as_deref(),
        Some("/admin/activity.csv"),
        "the export form posts to the export route"
    );
    assert_eq!(
        page.attr("form.export-form", "method").as_deref(),
        Some("post")
    );
    for (key, value) in [("client", "cursor"), ("q", "s-echo"), ("period", "7d")] {
        assert_eq!(
            page.attr(&format!("form.export-form input[name={key}]"), "value")
                .as_deref(),
            Some(value),
            "the export keeps {key}"
        );
    }
    assert_eq!(
        page.count("form.export-form input[name=page]"),
        0,
        "the export holds no page"
    );
}

/// The position of each id in the page, so the order of the controls can be checked.
fn positions(page: &Page, ids: &[&str]) -> Vec<usize> {
    ids.iter()
        .map(|id| {
            page.body
                .find(&format!("id=\"{id}\""))
                .unwrap_or_else(|| panic!("the page holds {id}"))
        })
        .collect()
}

/// The stored name of the server with this slug.
fn server_name(db: &Path, slug: &str) -> String {
    let conn = Connection::open(db).expect("the gateway database opens");
    conn.query_row(
        "SELECT name FROM servers WHERE slug = ?1",
        params![slug],
        |row| row.get(0),
    )
    .expect("the server exists")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_filter_form_is_a_closed_details_and_the_server_never_opens_it() {
    let w = world().await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    for filter in ["", "q=ab&period=7d&event=tool_call"] {
        let page = list(&w, filter).await;
        assert_eq!(page.status, 200, "{filter:?} must answer 200");
        assert_eq!(
            page.count("details.filter-panel"),
            1,
            "the filter form is one details"
        );
        assert_eq!(
            page.count("details.filter-panel[open]"),
            0,
            "the server must not write open on the filter details ({filter:?})"
        );
        assert_eq!(
            page.count("details.filter-panel > summary > .filter-open"),
            1,
            "the details has its summary control"
        );
        assert_eq!(
            page.count(&format!("details.filter-panel {FORM}")),
            1,
            "the form sits inside the details"
        );
    }
    let set = list(&w, &format!("server={alpha_id}")).await;
    assert_eq!(
        set.attr("details.filter-panel .f-server select", "name")
            .as_deref(),
        Some("server"),
        "the server field sits in the form"
    );
    assert_eq!(
        set.count("details.filter-panel > summary .count"),
        1,
        "the summary holds the count of set filters"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn from_and_to_follow_period_in_the_markup_order() {
    let w = world().await;
    let page = list(&w, "period=custom&from=2030-01-05&to=2030-01-06").await;
    let found = positions(
        &page,
        &[
            "filter-q",
            "filter-tool",
            "filter-client",
            "filter-period",
            "filter-from",
            "filter-to",
            "filter-event",
            "filter-user",
            "filter-server",
        ],
    );
    assert!(
        found.windows(2).all(|pair| pair[0] < pair[1]),
        "the controls are in the order Search, Tool, Client, Period, From, To, Event, User, Server: {found:?}"
    );
    assert_eq!(
        page.attr("input#filter-from", "aria-describedby")
            .as_deref(),
        Some("filter-from-hint"),
        "the From hint is tied to its input"
    );
    assert_eq!(
        page.text("p#filter-from-hint").as_deref(),
        Some("UTC, both days included."),
        "the From hint names the time zone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn server_options_read_slug_first() {
    let w = world().await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let name = server_name(&w.gw.db_path(), "alpha");
    let page = list(&w, "").await;
    assert_eq!(
        page.text(&format!(
            r#"select#filter-server option[value="{alpha_id}"]"#
        ))
        .as_deref(),
        Some(format!("alpha, {name}").as_str()),
        "a server option reads its slug, a comma, then its name"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duration_is_written_with_a_thousands_comma() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    insert(
        &w.gw.db_path(),
        &[call(
            ago(60),
            (bob, BOB),
            (id(alpha), "alpha"),
            "s-echo",
            "claude",
        )],
    );
    {
        let conn = Connection::open(w.gw.db_path()).expect("the gateway database opens");
        conn.execute(
            "UPDATE activity SET duration_ms = 1869 WHERE id = (SELECT MAX(id) FROM activity)",
            [],
        )
        .expect("a duration is set");
    }
    let page = list(&w, "tool=s-echo").await;
    assert_eq!(
        page.text("tr[data-kind] td.duration").as_deref(),
        Some("1,869 ms"),
        "a duration of 1869 ms reads 1,869 ms"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_activity_page_carries_no_script_and_no_style_attribute() {
    let w = world().await;
    let page = list(&w, "q=ab&period=7d").await;
    let lower = page.body.to_ascii_lowercase();
    for banned in ["<script", " style=", "<style"] {
        assert!(
            !lower.contains(banned),
            "the page must not contain {banned}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_select_lists_distinct_clients_by_name_at_most_fifty() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let mut rows = Vec::new();
    for n in (0..55).rev() {
        let client: &'static str = Box::leak(format!("client-{n:02}").into_boxed_str());
        rows.push(call(
            ago(60 + n),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-echo",
            client,
        ));
        rows.push(call(
            ago(60 + n),
            (bob, BOB),
            (alpha_id, "alpha"),
            "s-echo",
            client,
        ));
    }
    insert(&w.gw.db_path(), &rows);
    let page = list(&w, "").await;
    let options = page.texts("select#filter-client option");
    assert_eq!(options[0], "Any client", "the first choice is Any client");
    let names: Vec<String> = (0..50).map(|n| format!("client-{n:02}")).collect();
    assert_eq!(
        options[1..].to_vec(),
        names,
        "the distinct clients by name, at most 50"
    );
    assert_eq!(
        page.attr("select#filter-client option[selected]", "value")
            .as_deref(),
        Some(""),
        "with no client set, Any client is selected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_is_not_listed_still_filters_and_shows_as_selected() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[
            call(ago(60), (bob, BOB), (alpha_id, "alpha"), "s-echo", "cursor"),
            call(
                ago(120),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-echo",
                "claude",
            ),
        ],
    );
    let page = list(&w, "client=vscode").await;
    assert_eq!(
        page.attr("select#filter-client option[selected]", "value")
            .as_deref(),
        Some("vscode"),
        "an unlisted client shows as the selected extra option"
    );
    assert_eq!(
        page.count("table.activity tbody tr"),
        0,
        "no row names vscode, so none of the rows is shown"
    );
    assert_eq!(
        page.text("div.empty h2").as_deref(),
        Some("No activity matches these filters."),
        "a client that matches nothing shows the empty state"
    );
    let page = list(&w, "client=cursor").await;
    assert_eq!(
        page.attr("select#filter-client option[selected]", "value")
            .as_deref(),
        Some("cursor"),
        "a listed client is selected"
    );
    assert_eq!(
        page.count("table.activity tbody tr"),
        1,
        "the one cursor row is shown, so the row selector above is real"
    );
}
