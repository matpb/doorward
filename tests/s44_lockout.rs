mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::binary::{Outcome, Run, required_vars};
use common::client::{Page, TestClient};
use common::mail::link_with_prefix;
use common::world::{OWNER_EMAIL, PASSWORD, World};
use doorward::Config;
use doorward::config::{Limits, Range, SETTINGS};
use futures_util::future::join_all;
use rusqlite::Connection;

const BOB: &str = "bob@example.com";
const NOBODY: &str = "nobody@example.com";
const WRONG: &str = "definitely wrong";
const NEW_PASSWORD: &str = "a brand new passphrase";
const A: &str = "192.0.2.10";
const B: &str = "192.0.2.20";
const C: &str = "192.0.2.30";
const D: &str = "192.0.2.40";

/// Trusts the loopback peer, so that X-Forwarded-For names the browser's address.
fn trust_loopback(c: &mut Config) {
    c.trusted_proxies = vec![Range::from(IpAddr::V4(Ipv4Addr::LOCALHOST))];
}

/// A gateway that trusts X-Forwarded-For, with `edit` applied to its configuration.
async fn world(edit: impl FnOnce(&mut Config)) -> World {
    World::start_with(move |c| {
        trust_loopback(c);
        edit(c);
    })
    .await
}

/// A browser that sends from `address`.
fn browser_at(w: &World, address: &str) -> TestClient {
    TestClient::at(w.base(), address)
}

/// The number of rows in `login_failures`.
fn failure_rows(w: &World) -> i64 {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .query_row("SELECT COUNT(*) FROM login_failures", [], |row| row.get(0))
        .expect("the count query runs")
}

/// The page with its csrf value masked, so that two answers of one kind compare equal.
fn masked(page: &Page) -> String {
    let csrf = page.csrf().expect("a sign-in answer carries a csrf value");
    page.body.replace(&csrf, "CSRF")
}

/// Asks for a reset of `email` from an anonymous browser; returns the link from the mail.
async fn reset_link(w: &World, email: &str) -> String {
    let page = w
        .client()
        .submit("/forgot", "/forgot", &[("email", email)])
        .await;
    assert_eq!(page.status, 200, "the reset request must answer 200");
    let message = w
        .mail
        .wait_to(email, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| panic!("no reset mail to {email} arrived within 5 seconds"));
    let prefix = format!("{}/reset/", w.base());
    link_with_prefix(&message.text, &prefix)
        .unwrap_or_else(|| panic!("the reset mail has no link, text: {:?}", message.text))
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

/// Five wrong guesses for the owner at A, which block the owner's pair at A.
async fn block_owner_at_a(w: &World) {
    let a = browser_at(w, A);
    for n in 1..=5 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at A must answer 401");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_strangers_failures_do_not_lock_the_owner_out() {
    let w = world(|_| {}).await;
    let a = browser_at(&w, A);
    for n in 1..=5 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at A must answer 401");
    }
    let blocked = a.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the owner's right password at A must be refused after five wrong guesses at A"
    );
    let page = browser_at(&w, B).login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the owner's right password at B must sign in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_block_of_a_pair_ends_with_the_window() {
    let w = world(|_| {}).await;
    let a = browser_at(&w, A);
    for n in 1..=4 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at A must answer 401");
    }
    w.gw.clock.advance(time::Duration::minutes(10));
    let page = a.login(OWNER_EMAIL, WRONG).await;
    assert_eq!(
        page.status, 401,
        "the fifth wrong password at A, ten minutes after the first, must answer 401"
    );
    w.gw.clock.advance(time::Duration::minutes(4));
    let blocked = a.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the pair at A must stay blocked fourteen minutes after its first wrong guess"
    );
    w.gw.clock
        .advance(time::Duration::minutes(1) + time::Duration::seconds(1));
    let page = a.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the right password at A must sign in 15 minutes and 1 second after the first failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_success_clears_only_its_own_pair() {
    let w = world(|_| {}).await;
    let a = browser_at(&w, A);
    let b = browser_at(&w, B);
    for n in 1..=4 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at A must answer 401");
    }
    for n in 1..=4 {
        let page = b.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at B must answer 401");
    }
    let page = a.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the right password at A must sign in after four wrong guesses at A"
    );
    let page = b.login(OWNER_EMAIL, WRONG).await;
    assert_eq!(
        page.status, 401,
        "one more wrong password at B must answer 401, because the pair at B is not blocked"
    );
    let blocked = b.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the right password at B must be refused after five wrong guesses at B"
    );
    for n in 1..=4 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(
            page.status, 401,
            "wrong password {n} at A after the success must answer 401, not 429"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_attempt_is_neither_checked_nor_counted() {
    let w = world(|_| {}).await;
    block_owner_at_a(&w).await;
    assert_eq!(
        failure_rows(&w),
        5,
        "five wrong guesses must leave five rows"
    );
    let a = browser_at(&w, A);
    for n in 1..=10 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(
            page.status, 429,
            "attempt {n} at A while blocked must answer 429"
        );
    }
    assert_eq!(
        failure_rows(&w),
        5,
        "a blocked attempt must not add a row to login_failures"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_account_ceiling_blocks_every_address() {
    let w = world(|c| c.limits.account_ceiling = 8).await;
    for address in ["192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"] {
        let browser = browser_at(&w, address);
        for n in 1..=2 {
            let page = browser.login(OWNER_EMAIL, WRONG).await;
            assert_eq!(
                page.status, 401,
                "wrong password {n} from {address} must answer 401"
            );
        }
    }
    let fifth = browser_at(&w, "192.0.2.15");
    let blocked = fifth.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the right password from a fifth address must be refused once the account holds 8 failures"
    );
    w.gw.clock
        .advance(time::Duration::minutes(15) + time::Duration::seconds(1));
    let page = fifth.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the right password must sign in 15 minutes and 1 second later"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ceiling_defaults_to_fifty_and_both_numbers_are_settings() {
    let defaults = Limits::default();
    assert_eq!(
        defaults.account_failures, 5,
        "account_failures must default to 5"
    );
    assert_eq!(
        defaults.account_ceiling, 50,
        "account_ceiling must default to 50"
    );
    for (variable, path) in [
        (
            "DOORWARD_LIMITS_ACCOUNT_FAILURES",
            "limits.account_failures",
        ),
        ("DOORWARD_LIMITS_ACCOUNT_CEILING", "limits.account_ceiling"),
    ] {
        assert!(
            SETTINGS
                .iter()
                .any(|setting| setting.variable == variable && setting.path == path),
            "{variable} must be a setting for {path}"
        );
    }
    let outcome = start_with_variable("DOORWARD_LIMITS_ACCOUNT_CEILING", "4");
    assert_eq!(
        outcome.code,
        Some(2),
        "a ceiling below the failures must refuse the start"
    );
    assert_eq!(
        outcome.stderr,
        "doorward: invalid config: limits.account_ceiling must be at least limits.account_failures\n",
        "the refusal must name the two settings"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_guesses_from_many_addresses_stop_at_the_ceiling() {
    let w = world(|c| {
        c.limits.account_ceiling = 10;
        c.limits.address_failures = 1000;
    })
    .await;
    let guesses = (1..=30).map(|n| {
        let browser = browser_at(&w, &format!("192.0.2.{n}"));
        async move { browser.login(OWNER_EMAIL, WRONG).await.status }
    });
    let statuses = join_all(guesses).await;
    assert_eq!(
        statuses.len(),
        30,
        "all thirty parallel guesses must finish"
    );
    for (n, status) in statuses.iter().enumerate() {
        assert!(
            *status == 401 || *status == 429,
            "parallel guess {n} must answer 401 or 429, got {status}"
        );
    }
    let unauthorized = statuses.iter().filter(|status| **status == 401).count();
    assert_eq!(
        unauthorized, 10,
        "exactly ten parallel guesses must answer 401 before the ceiling, statuses were {statuses:?}"
    );
    let right = browser_at(&w, "192.0.2.50")
        .login(OWNER_EMAIL, PASSWORD)
        .await;
    assert_eq!(
        right.status, 429,
        "the owner's right password must be refused once the ceiling is reached"
    );
}

/// The statuses and masked bodies of six guesses for `email` from `first`, and one from `second`.
async fn guess_sequence(w: &World, email: &str, first: &str, second: &str) -> Vec<(u16, String)> {
    let mut answers = Vec::new();
    let near = browser_at(w, first);
    for _ in 0..6 {
        let page = near.login(email, WRONG).await;
        answers.push((page.status, masked(&page)));
    }
    let far = browser_at(w, second).login(email, WRONG).await;
    answers.push((far.status, masked(&far)));
    answers
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_account_is_throttled_like_a_real_one() {
    let w = world(|_| {}).await;
    let owner = guess_sequence(&w, OWNER_EMAIL, A, B).await;
    let unknown = guess_sequence(&w, NOBODY, C, D).await;
    let expected = vec![401, 401, 401, 401, 401, 429, 401];
    let owner_statuses: Vec<u16> = owner.iter().map(|(status, _)| *status).collect();
    let unknown_statuses: Vec<u16> = unknown.iter().map(|(status, _)| *status).collect();
    assert_eq!(
        owner_statuses, expected,
        "the owner's guesses: five at A, a sixth at A blocked, one at B not blocked"
    );
    assert_eq!(
        unknown_statuses, expected,
        "an unknown account's guesses must get the same statuses as the owner's"
    );
    // Statement 71: a refused sign-in sends the typed address back, so each side's own is masked.
    let without = |answers: &[(u16, String)], email: &str| -> Vec<(u16, String)> {
        answers
            .iter()
            .map(|(status, body)| (*status, body.replace(email, "ADDRESS")))
            .collect()
    };
    assert_eq!(
        without(&unknown, NOBODY),
        without(&owner, OWNER_EMAIL),
        "an unknown account's answers must match the owner's, apart from the csrf value and the typed address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_lifts_every_block_of_the_account() {
    let w = world(|c| c.limits.account_ceiling = 8).await;
    let a = browser_at(&w, A);
    for n in 1..=5 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at A must answer 401");
    }
    let b = browser_at(&w, B);
    for n in 1..=3 {
        let page = b.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(
            page.status, 401,
            "wrong password {n} at B must answer 401 while the account holds 5 failures"
        );
    }
    let blocked = browser_at(&w, C).login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the ceiling of 8 must refuse the right password from a fresh address"
    );
    let link = reset_link(&w, OWNER_EMAIL).await;
    let page = browser_at(&w, D).reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "the reset must answer 303");
    let page = a.login(OWNER_EMAIL, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the new password must sign in at A without waiting"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_lifts_every_block_of_the_account() {
    let w = world(|c| c.limits.account_ceiling = 8).await;
    let a = browser_at(&w, A);
    for n in 1..=5 {
        let page = a.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} at A must answer 401");
    }
    let b = browser_at(&w, B);
    for n in 1..=3 {
        let page = b.login(OWNER_EMAIL, WRONG).await;
        assert_eq!(
            page.status, 401,
            "wrong password {n} at B must answer 401 while the account holds 5 failures"
        );
    }
    let blocked = browser_at(&w, C).login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the ceiling of 8 must refuse the right password from a fresh address"
    );
    let database = w.gw.db_path().display().to_string();
    let vars = [
        ("DOORWARD_PUBLIC_URL", w.base()),
        ("DOORWARD_DATABASE", database.as_str()),
    ];
    let mut run = Run::spawn(&["unlock", OWNER_EMAIL], &vars);
    let outcome = run.wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(0),
        "doorward unlock must exit 0, stderr: {}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stdout,
        format!("unlocked {OWNER_EMAIL}\n"),
        "doorward unlock must print the unlocked line"
    );
    let page = a.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the right password at A must sign in after doorward unlock"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_current_passwords_count_for_the_pair() {
    let w = world(|_| {}).await;
    w.user(BOB).await;
    let a = browser_at(&w, A);
    let page = a.login(BOB, PASSWORD).await;
    assert_eq!(page.status, 303, "bob must sign in at A");
    for n in 1..=5 {
        let page = a.change_password(WRONG, NEW_PASSWORD).await;
        assert_eq!(
            page.status, 400,
            "wrong current password {n} at A must answer 400"
        );
    }
    let blocked = a.change_password(PASSWORD, NEW_PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the right current password at A must be refused after five wrong ones"
    );
    let page = browser_at(&w, B).login(BOB, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "bob must sign in at B, where the pair is not blocked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_right_current_password_clears_its_own_pair() {
    let w = world(|_| {}).await;
    w.user(BOB).await;
    let a = browser_at(&w, A);
    let page = a.login(BOB, PASSWORD).await;
    assert_eq!(page.status, 303, "bob must sign in at A");
    for n in 1..=2 {
        let page = a.change_password(WRONG, NEW_PASSWORD).await;
        assert_eq!(
            page.status, 400,
            "wrong current password {n} at A must answer 400"
        );
    }
    assert_eq!(
        failure_rows(&w),
        2,
        "the two wrong current passwords must be counted"
    );
    let page = a.change_password(PASSWORD, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the right current password at A must change the password"
    );
    assert_eq!(
        failure_rows(&w),
        0,
        "a right current password must leave no counted failure for its pair"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_address_rule_still_spans_accounts() {
    let w = world(|c| c.limits.address_failures = 6).await;
    let a = browser_at(&w, A);
    for n in 1..=7 {
        let page = a.login(&format!("user{n}@example.com"), WRONG).await;
        assert_eq!(
            page.status, 401,
            "wrong guess {n} for another account must answer 401"
        );
    }
    let blocked = a.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the owner's right password from a blocked address must be refused"
    );
    let unknown = a.login(NOBODY, WRONG).await;
    assert_eq!(
        unknown.status, 429,
        "any account from a blocked address must be refused"
    );
    let page = browser_at(&w, B).login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the owner's right password from another address must sign in"
    );
}
