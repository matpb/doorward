mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::admin;
use common::binary::{Outcome, Run, required_vars};
use common::upstream::UpstreamOptions;
use common::world::World;
use doorward::clock::Clock;
use doorward::config::Limits;
use doorward::crypto::token_hash;
use rusqlite::{Connection, params};

const DAY: i64 = 86_400;
const BOB: &str = "bob@example.com";

/// The gateway's current time, in unix seconds.
fn now(w: &World) -> i64 {
    w.gw.clock.now().unix_timestamp()
}

/// Writes one activity row at `at`, straight into the gateway's database.
fn write_row(w: &World, at: i64, kind: &str, tool: &str) {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .execute(
            "INSERT INTO activity (at, kind, tool) VALUES (?1, ?2, ?3)",
            params![at, kind, tool],
        )
        .expect("the activity row is written");
}

/// The number of activity rows whose tool is `tool`.
fn rows_tagged(w: &World, tool: &str) -> i64 {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .query_row(
            "SELECT COUNT(*) FROM activity WHERE tool = ?1",
            [tool],
            |row| row.get(0),
        )
        .expect("the count query runs")
}

/// Waits up to 5 seconds for the housekeeping run to delete the rows tagged `tool`.
async fn wait_for_deletion(w: &World, tool: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while rows_tagged(w, tool) > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The number of access token rows that hold the hash of `token`.
fn access_rows(w: &World, token: &str) -> i64 {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .query_row(
            "SELECT COUNT(*) FROM access_tokens WHERE token_hash = ?1",
            [token_hash(token)],
            |row| row.get(0),
        )
        .expect("the count query runs")
}

/// The number of token family rows.
fn family_rows(w: &World) -> i64 {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .query_row("SELECT COUNT(*) FROM token_families", [], |row| row.get(0))
        .expect("the count query runs")
}

/// Restarts the gateway, which runs the housekeeping at once, and waits until the run has deleted
/// a marker row. The token sweep runs in the same transaction, before the activity sweep.
async fn housekeeping_run(w: &mut World, marker: &str) {
    write_row(w, now(w) - 91 * DAY, "tool_call", marker);
    w.gw.restart().await;
    wait_for_deletion(w, marker).await;
}

/// The row count of every table but `activity`, by name.
fn other_table_counts(w: &World) -> Vec<(String, i64)> {
    let conn = Connection::open(w.gw.db_path()).expect("the gateway database opens");
    let names: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name <> 'activity' AND name NOT LIKE 'sqlite%' ORDER BY name",
        )
        .expect("the table query prepares")
        .query_map([], |row| row.get(0))
        .expect("the table query runs")
        .collect::<rusqlite::Result<Vec<String>>>()
        .expect("the table names are read");
    names
        .into_iter()
        .map(|name| {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |row| {
                    row.get(0)
                })
                .expect("the table is counted");
            (name, count)
        })
        .collect()
}

/// Runs the binary with `name` set to `value` on top of the required variables.
fn start_with_variable(name: &str, value: &str) -> Outcome {
    let mut vars = required_vars();
    vars.push((name.to_owned(), value.to_owned()));
    let pairs: Vec<(&str, &str)> = vars
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut run = Run::spawn(&[], &pairs);
    run.wait_for_exit()
}

#[tokio::test(flavor = "multi_thread")]
async fn rows_older_than_the_period_are_deleted() {
    let mut w = World::start().await;
    let at = now(&w);
    write_row(&w, at - 91 * DAY, "tool_call", "aged-91");
    write_row(&w, at - 89 * DAY, "tool_call", "aged-89");
    w.gw.restart().await;
    wait_for_deletion(&w, "aged-91").await;
    assert_eq!(
        rows_tagged(&w, "aged-91"),
        0,
        "the housekeeping run must delete the row aged 91 days"
    );
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.tool == "aged-89"),
        "the row aged 89 days must stay on /admin/activity, rows were {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_boundary_is_exact() {
    let mut w = World::start().await;
    let at = now(&w);
    write_row(&w, at - 90 * DAY + 1, "tool_call", "kept-edge");
    write_row(&w, at - 90 * DAY - 1, "tool_call", "gone-edge");
    w.gw.restart().await;
    wait_for_deletion(&w, "gone-edge").await;
    assert_eq!(
        rows_tagged(&w, "gone-edge"),
        0,
        "the housekeeping run must delete a row aged 90 days plus 1 second"
    );
    assert_eq!(
        rows_tagged(&w, "kept-edge"),
        1,
        "a row aged 90 days minus 1 second must stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_period_is_a_setting() {
    assert_eq!(
        Limits::default().activity_days,
        90,
        "activity_days must default to 90"
    );
    let outcome = start_with_variable("DOORWARD_LIMITS_ACTIVITY_DAYS", "0");
    assert_eq!(
        outcome.code,
        Some(2),
        "an activity period of 0 must refuse the start"
    );
    assert_eq!(
        outcome.stderr, "doorward: invalid config: limits.activity_days must be at least 1\n",
        "the refusal must name the setting"
    );

    let mut w = World::start_with(|c| c.limits.activity_days = 7).await;
    let at = now(&w);
    write_row(&w, at - 8 * DAY, "tool_call", "aged-8");
    write_row(&w, at - 6 * DAY, "tool_call", "aged-6");
    w.gw.restart().await;
    wait_for_deletion(&w, "aged-8").await;
    assert_eq!(
        rows_tagged(&w, "aged-8"),
        0,
        "with activity_days 7 the housekeeping run must delete a row aged 8 days"
    );
    assert_eq!(
        rows_tagged(&w, "aged-6"),
        1,
        "with activity_days 7 a row aged 6 days must stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_kind_of_row_is_pruned_alike() {
    let mut w = World::start().await;
    let at = now(&w);
    write_row(&w, at - 91 * DAY, "tool_call", "old-tool-call");
    write_row(&w, at - 91 * DAY, "login_failed", "old-login-failed");
    write_row(&w, at - 91 * DAY, "admin_change", "old-admin-change");
    let before = other_table_counts(&w);
    w.gw.restart().await;
    wait_for_deletion(&w, "old-tool-call").await;
    for tool in ["old-tool-call", "old-login-failed", "old-admin-change"] {
        assert_eq!(
            rows_tagged(&w, tool),
            0,
            "the housekeeping run must delete the old row {tool}"
        );
    }
    let after = other_table_counts(&w);
    assert!(!before.is_empty(), "the database must hold other tables");
    for ((table, count), (_, counted_after)) in before.iter().zip(after.iter()) {
        assert!(
            counted_after >= count,
            "the housekeeping run must not delete rows of table {table}: {count} before, {counted_after} after"
        );
    }
}

/// An access token lives an hour; the housekeeping keeps it for an hour more, so a call that
/// started while it was valid can still be answered.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_access_token_is_removed_after_its_grace() {
    let mut w = World::start().await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    assert_eq!(
        access_rows(&w, &tokens.access_token),
        1,
        "the access token must be stored after sign-in"
    );
    w.gw.clock.advance(time::Duration::minutes(90));
    housekeeping_run(&mut w, "marker-token-30").await;
    assert_eq!(
        access_rows(&w, &tokens.access_token),
        1,
        "an access token expired 30 minutes ago must survive the housekeeping run"
    );
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        401,
        "an access token expired 30 minutes ago must be refused while its row is kept"
    );
    w.gw.clock.advance(time::Duration::minutes(40));
    housekeeping_run(&mut w, "marker-token-70").await;
    assert_eq!(
        access_rows(&w, &tokens.access_token),
        0,
        "an access token expired more than an hour ago must be deleted by the housekeeping run"
    );
}

/// A token family lasts 90 days; the housekeeping keeps an expired one for an hour more.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_family_is_removed_after_its_grace() {
    let mut w = World::start().await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let _tokens = w.token(&bob, "demo").await;
    assert_eq!(
        family_rows(&w),
        1,
        "the token family must be stored after sign-in"
    );
    w.gw.clock
        .advance(time::Duration::days(90) + time::Duration::minutes(30));
    housekeeping_run(&mut w, "marker-family-30").await;
    assert_eq!(
        family_rows(&w),
        1,
        "a family expired 30 minutes ago must survive the housekeeping run"
    );
    w.gw.clock.advance(time::Duration::minutes(40));
    housekeeping_run(&mut w, "marker-family-70").await;
    assert_eq!(
        family_rows(&w),
        0,
        "a family expired more than an hour ago must be deleted by the housekeeping run"
    );
}

/// The gap between two reset mails is one public constant: housekeeping must read it, not copy it.
#[test]
fn the_reset_gap_is_one_public_constant() {
    let accounts = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/accounts");
    let reset = std::fs::read_to_string(accounts.join("reset.rs")).expect("read reset.rs");
    let housekeeping =
        std::fs::read_to_string(accounts.join("housekeeping.rs")).expect("read housekeeping.rs");
    assert!(
        reset.contains("pub const REQUEST_GAP_SECONDS"),
        "reset.rs must export the gap between reset mails as REQUEST_GAP_SECONDS"
    );
    assert!(
        !housekeeping.contains("const RESET_GAP_SECONDS")
            && !housekeeping.contains("const REQUEST_GAP_SECONDS"),
        "housekeeping.rs must not keep its own copy of the reset gap"
    );
    assert!(
        housekeeping.contains("REQUEST_GAP_SECONDS"),
        "housekeeping.rs must use the reset gap constant of reset.rs"
    );
}
