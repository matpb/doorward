mod common;

use std::path::Path;

use common::admin;
use common::client::Page;
use common::upstream::UpstreamOptions;
use common::world::{OWNER_EMAIL, World};
use form_urlencoded::Serializer;
use rusqlite::{Connection, params};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const NOW: &str = "2030-01-01T00:00:00Z";
const HEADER: &str = "time_utc,event,user,server,tool,client,decision,outcome,detail,duration_ms";
/// The export's filter for the seeded rows of 5 and 6 January 2030, which the setup rows miss.
const SEEDED_DAYS: &str = "period=custom&from=2030-01-05&to=2030-01-06";

/// One activity row written straight into the table. Empty text is an empty column.
#[derive(Default, Clone)]
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

fn stamp(text: &str) -> i64 {
    OffsetDateTime::parse(text, &Rfc3339)
        .expect("the time is RFC 3339")
        .unix_timestamp()
}

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
    tx.commit().expect("the activity rows are committed");
}

/// An allowed call that succeeded, as the proxy records it.
fn call(at: i64, who: (i64, &'static str), server: (i64, &'static str), tool: &'static str) -> Row {
    Row {
        at,
        kind: "tool_call",
        user_id: Some(who.0),
        user: who.1,
        server_id: Some(server.0),
        server: server.1,
        tool,
        client: "c",
        decision: "allow",
        outcome: "ok",
        ..Row::default()
    }
}

/// The export of a query string, read as the owner.
async fn export(w: &World, filter: &str) -> Page {
    w.owner.get(&format!("/admin/activity.csv?{filter}")).await
}

fn query(pairs: &[(&str, &str)]) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

/// The body of the export without its header line.
fn data_lines(body: &str) -> String {
    let header = format!("{HEADER}\r\n");
    body.strip_prefix(&header)
        .unwrap_or_else(|| panic!("the export must start with the header line, got {body:?}"))
        .to_string()
}

/// The detail of the admin_change row the export wrote, if one exists.
async fn export_rows(w: &World) -> Vec<String> {
    admin::activity_with_details(&w.owner, None, None)
        .await
        .into_iter()
        .filter(|(row, _)| row.kind == "admin_change")
        .map(|(_, detail)| detail)
        .filter(|detail| detail.starts_with("exported activity"))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_answers_with_csv_headers_and_the_documented_file_name() {
    let w = world().await;
    let page = export(&w, "").await;
    assert_eq!(page.status, 200, "the export must answer 200");
    assert_eq!(
        page.header("content-type").as_deref(),
        Some("text/csv; charset=utf-8"),
        "the export must be CSV in UTF-8"
    );
    assert_eq!(
        page.header("content-disposition").as_deref(),
        Some("attachment; filename=\"doorward-activity.csv\""),
        "the export must download as doorward-activity.csv"
    );
    assert_eq!(
        page.header("cache-control").as_deref(),
        Some("no-store"),
        "the export must not be cached"
    );
    assert_eq!(
        page.header("x-content-type-options").as_deref(),
        Some("nosniff"),
        "the export must say nosniff"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_lists_the_filtered_rows_oldest_first_with_the_documented_columns() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let carol = add_user(&w, CAROL).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let mut late = call(
        stamp("2030-01-06T08:30:00Z"),
        (bob, BOB),
        (alpha_id, "alpha"),
        "s-b",
    );
    late.client = "cursor";
    late.duration_ms = Some(12);
    let mut early = call(
        stamp("2030-01-05T10:00:00Z"),
        (carol, CAROL),
        (alpha_id, "alpha"),
        "s-a",
    );
    early.client = "claude-desktop";
    early.duration_ms = Some(7);
    let sign_in = Row {
        at: stamp("2030-01-05T10:00:01Z"),
        kind: "login",
        user_id: Some(bob),
        user: BOB,
        outcome: "ok",
        ..Row::default()
    };
    insert(&w.gw.db_path(), &[late, sign_in, early]);

    let page = export(&w, SEEDED_DAYS).await;
    assert_eq!(page.status, 200, "the export must answer 200");
    let expected = format!(
        "{HEADER}\r\n\
         2030-01-05T10:00:00Z,Tool call,{CAROL},alpha,s-a,claude-desktop,allow,ok,,7\r\n\
         2030-01-05T10:00:01Z,Sign-in,{BOB},,,,,ok,,\r\n\
         2030-01-06T08:30:00Z,Tool call,{BOB},alpha,s-b,cursor,allow,ok,,12\r\n"
    );
    assert_eq!(
        page.body, expected,
        "the export must hold the seeded rows oldest first, with the documented columns"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_holds_every_row_across_more_than_one_chunk() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let db = w.gw.db_path();
    let first = stamp("2030-01-05T00:00:00Z");
    let rows: Vec<Row> = (0..5200)
        .map(|index| Row {
            duration_ms: Some(index),
            ..call(first + index, (bob, BOB), (alpha_id, "alpha"), "s-bulk")
        })
        .collect();
    insert(&db, &rows);

    let filter = query(&[
        ("period", "custom"),
        ("from", "2030-01-05"),
        ("to", "2030-01-06"),
        ("server", &alpha_id.to_string()),
    ]);
    let page = export(&w, &filter).await;
    assert_eq!(page.status, 200, "the export must answer 200");

    // Brute force: every row of the table, read in order, filtered here rather than in SQL.
    let conn = Connection::open(&db).expect("the gateway database opens");
    let mut statement = conn
        .prepare(
            "SELECT at, user_email, server_slug, tool, client, decision, outcome, detail, duration_ms \
             FROM activity ORDER BY at, id",
        )
        .expect("the table query prepares");
    let mut expected = String::new();
    let mut count = 0;
    let all = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })
        .expect("the table query runs");
    for item in all {
        let (at, user, server, tool, client, decision, outcome, detail, duration) =
            item.expect("a row reads");
        if server != "alpha"
            || at < stamp("2030-01-05T00:00:00Z")
            || at >= stamp("2030-01-07T00:00:00Z")
        {
            continue;
        }
        count += 1;
        let time = OffsetDateTime::from_unix_timestamp(at)
            .expect("a valid time")
            .format(&Rfc3339)
            .expect("the time formats");
        let duration = duration.map_or(String::new(), |ms| ms.to_string());
        expected.push_str(&format!(
            "{time},Tool call,{user},{server},{tool},{client},{decision},{outcome},{detail},{duration}\r\n"
        ));
    }
    assert_eq!(
        count, 5200,
        "the brute-force read must find all 5200 seeded rows"
    );
    assert_eq!(
        data_lines(&page.body),
        expected,
        "the export must hold every row, oldest first, across the chunk boundary"
    );
    let shown = w.owner.get(&format!("/admin/activity?{filter}")).await;
    assert_eq!(
        shown.text("[data-range]").as_deref(),
        Some("Rows 1 to 50 of 5200"),
        "the page must count the same 5200 rows"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cells_are_quoted_as_rfc_4180_and_lines_end_in_crlf() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[Row {
            detail: "x,\"y\"\nz\rw",
            ..call(
                stamp("2030-01-05T10:00:00Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-q",
            )
        }],
    );
    let page = export(&w, SEEDED_DAYS).await;
    assert_eq!(
        page.body,
        format!(
            "{HEADER}\r\n2030-01-05T10:00:00Z,Tool call,{BOB},alpha,s-q,c,allow,ok,\"x,\"\"y\"\"\nz\rw\",\r\n"
        ),
        "a cell with a comma, quotes, a line feed or a carriage return is quoted with doubled quotes, and the record ends in CRLF"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cell_starting_with_a_formula_character_is_prefixed_with_a_quote() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let cases = [
        ("s-eq", "=1+1", "'=1+1"),
        ("s-plus", "+x", "'+x"),
        ("s-minus", "-x", "'-x"),
        ("s-at", "@x", "'@x"),
        ("s-tab", "\tx", "'\tx"),
        ("s-cr", "\rx", "\"'\rx\""),
        ("s-plain", "a=1", "a=1"),
    ];
    let rows: Vec<Row> = cases
        .iter()
        .enumerate()
        .map(|(index, &(tool, detail, _))| Row {
            detail,
            ..call(
                stamp("2030-01-05T10:00:00Z") + index as i64,
                (bob, BOB),
                (alpha_id, "alpha"),
                tool,
            )
        })
        .collect();
    insert(&w.gw.db_path(), &rows);
    let page = export(&w, SEEDED_DAYS).await;
    assert_eq!(page.status, 200, "the export must answer 200");
    for (index, (tool, _, cell)) in cases.iter().enumerate() {
        let time =
            OffsetDateTime::from_unix_timestamp(stamp("2030-01-05T10:00:00Z") + index as i64)
                .expect("a valid time")
                .format(&Rfc3339)
                .expect("the time formats");
        let line = format!("{time},Tool call,{BOB},alpha,{tool},c,allow,ok,{cell},\r\n");
        assert!(
            page.body.contains(&line),
            "the row of {tool} must read {line:?} in the export, body was {:?}",
            page.body
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_is_redirected_and_a_plain_user_is_forbidden() {
    let w = world().await;
    let bob = w.user(BOB).await;
    let anonymous = w.client().get("/admin/activity.csv").await;
    assert_eq!(
        anonymous.status, 303,
        "an anonymous visitor must be redirected"
    );
    assert_eq!(
        anonymous.location().as_deref(),
        Some("/login"),
        "an anonymous visitor must be sent to sign-in"
    );
    let plain = bob.get("/admin/activity.csv").await;
    assert_eq!(plain.status, 403, "a plain user must be refused the export");
    assert_eq!(
        plain.kind().as_deref(),
        Some("forbidden"),
        "a plain user must see the forbidden page, not CSV"
    );
    assert!(
        export_rows(&w).await.is_empty(),
        "a refused export must write no export row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_writes_one_admin_change_row_with_the_row_count() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    insert(
        &w.gw.db_path(),
        &[
            call(
                stamp("2030-01-05T10:00:00Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-1",
            ),
            call(
                stamp("2030-01-05T10:00:01Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-2",
            ),
            call(
                stamp("2030-01-05T10:00:02Z"),
                (bob, BOB),
                (alpha_id, "alpha"),
                "s-3",
            ),
        ],
    );
    let page = export(&w, SEEDED_DAYS).await;
    assert_eq!(page.status, 200, "the export must answer 200");
    assert_eq!(
        data_lines(&page.body).lines().count(),
        3,
        "the export must hold the three seeded rows"
    );
    assert!(
        !page.body.contains("exported activity"),
        "the export row must not be part of the export"
    );
    assert_eq!(
        export_rows(&w).await,
        vec!["exported activity (3 rows)".to_string()],
        "the export must write one admin_change row with the count of its rows"
    );
    let rows = admin::activity_with_details(&w.owner, None, None).await;
    let (row, _) = rows
        .iter()
        .find(|(row, detail)| row.kind == "admin_change" && detail.starts_with("exported"))
        .expect("the export row must be listed");
    assert_eq!(
        row.user, OWNER_EMAIL,
        "the export row must name the owner who exported"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_export_holds_no_ids_and_no_tokens() {
    let w = world().await;
    let bob_client = w.user(BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    w.grant(BOB, &[alpha.as_str()]).await;
    let tokens = w.token(&bob_client, "alpha").await;
    let mcp = w.session_mcp("alpha", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let reply = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(reply.status, 200, "the call must answer 200");

    let page = export(&w, "period=24h").await;
    assert_eq!(page.status, 200, "the export must answer 200");
    let body = data_lines(&page.body);
    let lines: Vec<&str> = body.split("\r\n").filter(|line| !line.is_empty()).collect();
    assert!(!lines.is_empty(), "the export must hold the call");
    for line in &lines {
        assert_eq!(
            line.split(',').count(),
            10,
            "every row must hold exactly the ten documented cells, got {line:?}"
        );
    }
    assert!(
        !page.body.contains(&tokens.access_token),
        "the export must not hold the access token"
    );
    assert!(
        !page.body.contains(&tokens.refresh_token),
        "the export must not hold the refresh token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_export_with_no_matching_rows_has_only_the_header() {
    let w = world().await;
    let page = export(&w, "period=custom&from=2031-01-01&to=2031-01-02").await;
    assert_eq!(page.status, 200, "an empty export must answer 200");
    assert_eq!(
        page.body,
        format!("{HEADER}\r\n"),
        "an export that matches nothing must hold the header line alone"
    );
    assert_eq!(
        export_rows(&w).await,
        vec!["exported activity (0 rows)".to_string()],
        "an empty export must still write its admin_change row with 0 rows"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_key_on_the_export_takes_its_first_value() {
    let w = world().await;
    let bob = add_user(&w, BOB).await;
    let (_alpha_up, alpha) = w.upstream("alpha", UpstreamOptions::default()).await;
    let (_beta_up, beta) = w.upstream("beta", UpstreamOptions::default()).await;
    let alpha_id = id(alpha);
    let beta_id = id(beta);
    insert(
        &w.gw.db_path(),
        &[
            call(ago(60), (bob, BOB), (alpha_id, "alpha"), "s-now"),
            call(
                stamp("2030-01-05T10:00:00Z"),
                (bob, BOB),
                (beta_id, "beta"),
                "s-old",
            ),
        ],
    );
    let page = export(
        &w,
        &format!("period=24h&period=all&server={alpha_id}&server=abc"),
    )
    .await;
    assert_eq!(
        page.status, 200,
        "a repeated key on the export must answer 200"
    );
    assert!(
        page.body.contains("s-now"),
        "the first period and server must be used"
    );
    assert!(
        !page.body.contains("s-old"),
        "the second period must not be used"
    );
}
