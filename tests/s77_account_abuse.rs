mod common;

use std::time::{Duration, Instant};

use common::admin;
use common::client::{Page, TestClient};
use common::mail::link_with_prefix;
use common::upstream::UpstreamOptions;
use common::world::{OWNER_EMAIL, World};
use doorward::Config;
use doorward::clock::Clock;
use rusqlite::Connection;
use serde_json::json;

const GUESS: &str = "a wrong password entirely";
const UNKNOWN: &str = "nobody-here@example.com";
const BOB: &str = "bob@example.com";
const RESET_SUBJECT: &str = "Reset your Doorward password";
const MADE_UP: usize = 25;

/// Raises the sign-in burst, which would answer 429 before the 21st attempt from one address.
fn raise_sign_in_burst(config: &mut Config) {
    config.limits.credentials_burst = 100;
}

/// The users named by the login_failed rows of the activity log, one entry per row.
async fn failed_sign_ins(w: &World) -> Vec<String> {
    admin::activity(&w.owner, None, None)
        .await
        .into_iter()
        .filter(|row| row.kind == "login_failed")
        .map(|row| row.user)
        .collect()
}

/// The body of a refused sign-in with its anti-forgery value and its echoed address blanked.
fn blanked(page: &Page, address: &str) -> String {
    let csrf = page.csrf().expect("a refused sign-in carries a csrf field");
    page.body.replace(&csrf, "CSRF").replace(address, "ADDRESS")
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_address_rows_stop_at_twenty_an_hour() {
    let w = World::start_with(raise_sign_in_burst).await;
    for n in 0..MADE_UP {
        let address = format!("made-up-{n}@example.com");
        let refused = w.client().login(&address, GUESS).await;
        assert_eq!(refused.status, 401, "an unknown address must be refused");
    }
    let rows = failed_sign_ins(&w).await;
    assert_eq!(
        rows.len(),
        20,
        "at most 20 unknown-address rows in an hour, rows were {rows:?}"
    );
    assert!(
        rows.iter().all(|user| user.is_empty()),
        "the unknown-address rows name no account, rows were {rows:?}"
    );

    let refused = w.client().login(OWNER_EMAIL, GUESS).await;
    assert_eq!(refused.status, 401, "a wrong password must be refused");
    let rows = failed_sign_ins(&w).await;
    assert_eq!(
        rows.len(),
        21,
        "the account's row is never counted or skipped"
    );
    assert_eq!(
        rows.iter().filter(|user| *user == OWNER_EMAIL).count(),
        1,
        "exactly one row must name the account, rows were {rows:?}"
    );

    w.gw.clock.advance(time::Duration::seconds(3601));
    let refused = w
        .client()
        .login("made-up-after-an-hour@example.com", GUESS)
        .await;
    assert_eq!(refused.status, 401, "an unknown address must be refused");
    assert_eq!(
        failed_sign_ins(&w).await.len(),
        22,
        "an hour later the count starts again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_sign_in_for_an_existing_account_writes_one_row_naming_it() {
    let w = World::start().await;
    let refused = w.client().login(OWNER_EMAIL, GUESS).await;
    assert_eq!(refused.status, 401, "a wrong password must be refused");
    assert_eq!(
        failed_sign_ins(&w).await,
        vec![OWNER_EMAIL.to_owned()],
        "exactly one login_failed row must name the account"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_address_and_a_wrong_password_get_the_same_answer() {
    let w = World::start().await;
    let unknown = w.client().login(UNKNOWN, GUESS).await;
    let known = w.client().login(OWNER_EMAIL, GUESS).await;
    assert_eq!(unknown.status, 401, "an unknown address must be refused");
    assert_eq!(
        known.status, unknown.status,
        "a wrong password must get the same status"
    );
    assert_eq!(
        blanked(&unknown, UNKNOWN),
        blanked(&known, OWNER_EMAIL),
        "the two refusals must differ only in the anti-forgery value and the echoed address"
    );
}

/// The reset mails that have reached BOB.
fn reset_mails(w: &World) -> usize {
    w.mail
        .to(BOB)
        .iter()
        .filter(|message| message.subject == RESET_SUBJECT)
        .count()
}

/// Waits up to 5 seconds until `count` reset mails have reached BOB.
async fn wait_for_reset_mails(w: &World, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while reset_mails(w) < count {
        assert!(
            Instant::now() < deadline,
            "{count} reset mails were expected to reach BOB within 5 seconds, {} arrived",
            reset_mails(w)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One anonymous request for a reset of BOB's password.
async fn request_reset(browser: &TestClient) -> Page {
    let csrf = browser
        .get("/forgot")
        .await
        .csrf()
        .expect("the forgot page carries a csrf field");
    browser
        .post("/forgot", &[("csrf", csrf.as_str()), ("email", BOB)])
        .await
}

/// The token hash of BOB's stored reset link.
fn stored_token_hash(w: &World) -> String {
    let conn = Connection::open(w.gw.db_path()).expect("the gateway database opens");
    conn.query_row(
        "SELECT r.token_hash FROM password_resets r JOIN users u ON u.id = r.user_id \
         WHERE u.email = ?1",
        [BOB],
        |row| row.get(0),
    )
    .expect("BOB has a stored reset link")
}

#[tokio::test(flavor = "multi_thread")]
async fn six_reset_requests_in_a_day_send_five_mails_and_a_day_later_one_more() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let first_mail_at = w.gw.clock.now();
    let mut answers = Vec::new();
    for round in 1..=5 {
        if round > 1 {
            w.gw.clock.advance(time::Duration::seconds(301));
        }
        answers.push(request_reset(&anonymous).await);
        wait_for_reset_mails(&w, round).await;
    }
    let link_before = stored_token_hash(&w);

    w.gw.clock.advance(time::Duration::seconds(301));
    let sixth = request_reset(&anonymous).await;
    // A refused request sends nothing; one second is long enough for a mail task to finish.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        reset_mails(&w),
        5,
        "the sixth request within a day must send no mail"
    );
    assert_eq!(
        stored_token_hash(&w),
        link_before,
        "a refused request must leave the stored link as it was"
    );
    assert_eq!(
        sixth.status, answers[4].status,
        "the sixth status must match the fifth"
    );
    assert_eq!(
        sixth.body, answers[4].body,
        "the sixth body must match the fifth"
    );

    w.gw.clock.set(first_mail_at + time::Duration::days(1));
    let seventh = request_reset(&anonymous).await;
    assert_eq!(
        seventh.status, 200,
        "a request after a day must be answered 200"
    );
    wait_for_reset_mails(&w, 6).await;
    assert_eq!(
        reset_mails(&w),
        6,
        "a request 24 hours after the first mail must send one more"
    );
}

/// The link of the newest reset mail to BOB.
fn last_reset_link(w: &World) -> String {
    let prefix = format!("{}/reset/", w.base());
    let mail = w
        .mail
        .to(BOB)
        .into_iter()
        .rfind(|message| message.subject == RESET_SUBJECT)
        .expect("a reset mail reached BOB");
    link_with_prefix(&mail.text, &prefix).expect("the reset mail has a link")
}

/// The number of rows in a table of the gateway database.
fn rows_in(w: &World, table: &str) -> i64 {
    let conn = Connection::open(w.gw.db_path()).expect("the gateway database opens");
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("the table counts")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_daily_cap_survives_a_sweep_while_its_day_is_current() {
    let mut w = World::start().await;
    w.user(BOB).await;
    // This failed sign-in leaves a login_failures row, which the sweep removes once it is old.
    let refused = w.client().login(OWNER_EMAIL, GUESS).await;
    assert_eq!(refused.status, 401, "a wrong password must be refused");
    let anonymous = w.client();
    for round in 1..=5 {
        if round > 1 {
            w.gw.clock.advance(time::Duration::seconds(301));
        }
        request_reset(&anonymous).await;
        wait_for_reset_mails(&w, round).await;
    }

    // Two hours on: the link has expired and the day's count is still current.
    w.gw.clock.advance(time::Duration::hours(2));
    w.gw.restart().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while rows_in(&w, "login_failures") > 0 {
        assert!(
            Instant::now() < deadline,
            "the sweep must run after a restart"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        rows_in(&w, "password_resets"),
        1,
        "the sweep must keep the reset row while its day is current"
    );
    let expired = anonymous.get(&last_reset_link(&w)).await;
    assert_eq!(
        expired.kind().as_deref(),
        Some("link-invalid"),
        "the kept row's link has expired and must stay unusable"
    );

    let sixth = request_reset(&anonymous).await;
    assert_eq!(
        sixth.status, 200,
        "the refused request must be answered 200"
    );
    // A refused request sends nothing; one second is long enough for a mail task to finish.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        reset_mails(&w),
        5,
        "after the sweep the sixth request within a day must send no mail"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_discovery_health_token_and_register_answer_carries_nosniff_once() {
    let w = World::start().await;
    let (_upstream, _id) = w.upstream("demo", UpstreamOptions::default()).await;
    let anonymous = w.client();
    let answers = [
        (
            "GET /.well-known/oauth-authorization-server",
            anonymous
                .get("/.well-known/oauth-authorization-server")
                .await,
        ),
        (
            "GET /.well-known/oauth-protected-resource/demo",
            anonymous
                .get("/.well-known/oauth-protected-resource/demo")
                .await,
        ),
        (
            "POST /oauth/token with an empty form",
            anonymous.post("/oauth/token", &[]).await,
        ),
        (
            "POST /oauth/register with {}",
            anonymous.post_json("/oauth/register", &json!({})).await,
        ),
        ("GET /healthz", anonymous.get("/healthz").await),
        (
            "POST /mcp without a token",
            anonymous.post("/mcp", &[]).await,
        ),
    ];
    for (name, page) in answers {
        assert_eq!(
            page.headers_all("x-content-type-options"),
            vec!["nosniff".to_owned()],
            "{name} (status {}) must carry exactly one x-content-type-options: nosniff",
            page.status
        );
    }
}
