mod common;

use common::admin;
use common::client::TestClient;
use common::mcp::McpClient;
use common::upstream::UpstreamOptions;
use common::world::World;
use rusqlite::Connection;
use serde_json::json;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const NOT_LISTED: &str = "not in the tool list";
const NOTICE: &str = " Further refused calls by this user are not recorded for up to an hour.";

/// Opens the gateway's database file for a direct read.
fn open(w: &World) -> Connection {
    Connection::open(w.gw.db_path()).expect("the gateway database opens")
}

/// The refused tool call rows of the user with this email.
fn refused_rows(w: &World, email: &str) -> i64 {
    open(w)
        .query_row(
            "SELECT COUNT(*) FROM activity a JOIN users u ON u.id = a.user_id \
             WHERE u.email = ?1 AND a.kind = 'tool_call' AND a.decision = 'deny'",
            [email],
            |row| row.get(0),
        )
        .expect("the count")
}

/// The tool and detail of the newest refused tool call row.
fn newest_refused(w: &World) -> (String, String) {
    open(w)
        .query_row(
            "SELECT tool, detail FROM activity WHERE kind = 'tool_call' AND decision = 'deny' \
             ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("a refused row")
}

/// Signs `browser` in for `slug` and completes the session handshake.
async fn connect(w: &World, browser: &TestClient, slug: &str) -> McpClient {
    let tokens = w.token(browser, slug).await;
    let mcp = w.session_mcp(slug, &tokens);
    let init = mcp.initialize().await;
    assert_eq!(init.status, 200, "initialize on /{slug} must answer 200");
    mcp
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_tool_name_is_stored_cut_and_clean() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let mcp = connect(&w, &bob, "demo").await;
    let name = format!("\u{202E}\u{7}{}", "a".repeat(5000));
    let reply = mcp.call_tool(&name, json!({})).await;
    assert_eq!(reply.status, 200, "the refused call answers 200");
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "the refused call answers Unknown tool"
    );

    let stored: String = open(&w)
        .query_row(
            "SELECT tool FROM activity WHERE kind = 'tool_call' AND decision = 'deny'",
            [],
            |row| row.get(0),
        )
        .expect("the refused call's row");
    assert!(
        stored.chars().count() <= 128,
        "the stored tool holds {} characters, the limit is 128",
        stored.chars().count()
    );
    assert!(
        !stored.contains('\u{202E}'),
        "the stored tool must not hold a direction character"
    );
    assert!(
        !stored.contains('\u{7}'),
        "the stored tool must not hold a control character"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_rows_stop_at_one_hundred_an_hour() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let carol = w.user(CAROL).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    w.grant(CAROL, &[id.as_str()]).await;
    let mcp = connect(&w, &bob, "demo").await;
    for n in 1..=105 {
        let reply = mcp.call_tool(&format!("missing_{n}"), json!({})).await;
        assert_eq!(
            reply.error_code(),
            Some(-32602),
            "refused call {n} answers Unknown tool"
        );
    }
    assert_eq!(
        refused_rows(&w, BOB),
        100,
        "one user writes exactly 100 refused rows in an hour"
    );
    assert_eq!(
        newest_refused(&w),
        ("missing_100".to_owned(), format!("{NOT_LISTED}{NOTICE}")),
        "the 100th row carries the notice"
    );

    let other = connect(&w, &carol, "demo").await;
    let reply = other.call_tool("missing_carol", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "carol's refused call answers Unknown tool"
    );
    assert_eq!(
        refused_rows(&w, CAROL),
        1,
        "a second user's refused call still writes a row"
    );

    let allowed = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(allowed.status, 200, "an allowed call answers 200");
    let allowed_rows: i64 = open(&w)
        .query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'tool_call' AND decision = 'allow'",
            [],
            |row| row.get(0),
        )
        .expect("the count");
    assert_eq!(allowed_rows, 1, "an allowed call writes its row");

    w.gw.clock.advance(time::Duration::seconds(3601));
    let mcp = connect(&w, &bob, "demo").await;
    let reply = mcp.call_tool("missing_later", json!({})).await;
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "the call after an hour answers Unknown tool"
    );
    assert_eq!(
        refused_rows(&w, BOB),
        101,
        "after an hour the next refused call writes a row"
    );
    assert_eq!(
        newest_refused(&w),
        ("missing_later".to_owned(), NOT_LISTED.to_owned()),
        "a row after the notice carries no notice"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_rows_stop_at_one_hundred_an_hour_on_the_combined_route() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let mcp = connect(&w, &bob, "mcp").await;
    for n in 1..=105 {
        let reply = mcp.call_tool(&format!("missing_{n}"), json!({})).await;
        assert_eq!(
            reply.error_code(),
            Some(-32602),
            "refused call {n} on /mcp answers Unknown tool"
        );
    }
    assert_eq!(
        refused_rows(&w, BOB),
        100,
        "the combined route writes exactly 100 refused rows in an hour"
    );
    assert_eq!(
        newest_refused(&w),
        ("missing_100".to_owned(), format!("{NOT_LISTED}{NOTICE}")),
        "the 100th row on /mcp carries the notice"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_catalog_keeps_at_most_one_thousand_tools() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let tools: Vec<String> = (0..1200).map(|n| format!("tool_{n}")).collect();
    let (_up, id) = w
        .upstream(
            "demo",
            UpstreamOptions {
                tools,
                ..Default::default()
            },
        )
        .await;
    let listed = admin::catalog_tools(&w.owner, &id).await;
    assert_eq!(listed.len(), 1000, "the server page shows 1000 tools");
    assert_eq!(listed.first().map(String::as_str), Some("tool_0"));
    assert_eq!(listed.last().map(String::as_str), Some("tool_999"));

    w.grant(BOB, &[id.as_str()]).await;
    let mcp = connect(&w, &bob, "demo").await;
    let kept = mcp.call_tool("tool_999", json!({})).await;
    assert_eq!(
        kept.text().as_deref(),
        Some("called: tool_999"),
        "the 1000th tool can be called"
    );
    let left_out = mcp.call_tool("tool_1000", json!({})).await;
    assert_eq!(
        left_out.error_message().as_deref(),
        Some("Unknown tool: tool_1000"),
        "the 1001st tool cannot be called"
    );
}
