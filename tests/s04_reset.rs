mod common;

use std::time::Duration;

use common::admin;
use common::client::{Page, TestClient};
use common::mail::{Captured, link_with_prefix};
use common::upstream::UpstreamOptions;
use common::world::{PASSWORD, World};

const BOB: &str = "bob@example.com";
const NOBODY: &str = "nobody@example.com";
const WRONG: &str = "definitely wrong";
const NEW_PASSWORD: &str = "a brand new passphrase";
const SESSION: &str = "__Host-doorward_session";
const SUBJECT: &str = "Reset your Doorward password";

/// Reads the csrf value of the login page, which exists on every instance.
async fn login_csrf(browser: &TestClient) -> String {
    browser
        .get("/login")
        .await
        .csrf()
        .expect("GET /login must carry a csrf field")
}

/// Posts the forgot-password form for `address`, with extra request headers.
async fn forgot(browser: &TestClient, address: &str, headers: &[(&str, &str)]) -> Page {
    let csrf = browser
        .get("/forgot")
        .await
        .csrf()
        .expect("the forgot page must carry a csrf field");
    browser
        .post_with(
            "/forgot",
            &[("csrf", csrf.as_str()), ("email", address)],
            headers,
        )
        .await
}

/// The reset mail that reached `address`, waiting up to 5 seconds for it.
async fn reset_mail(w: &World, address: &str) -> Captured {
    let message = w
        .mail
        .wait_to(address, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| panic!("no mail to {address} arrived within 5 seconds"));
    assert_eq!(
        message.subject, SUBJECT,
        "the reset mail must have the reset subject"
    );
    message
}

/// The reset link in the mail, which must start with the gateway's own address.
fn reset_link(w: &World, message: &Captured) -> String {
    let prefix = format!("{}/reset/", w.base());
    link_with_prefix(&message.text, &prefix).unwrap_or_else(|| {
        panic!(
            "the reset mail has no link starting with {prefix}, text: {:?}",
            message.text
        )
    })
}

/// Asks for a reset of `address` from `browser` and returns the link from the mail that follows.
async fn request_reset(w: &World, browser: &TestClient, address: &str) -> String {
    w.mail.clear();
    let page = forgot(browser, address, &[]).await;
    assert_eq!(page.status, 200, "a reset request must be answered 200");
    assert_eq!(
        page.kind().as_deref(),
        Some("forgot-sent"),
        "a reset request must show data-page forgot-sent"
    );
    let message = reset_mail(w, address).await;
    reset_link(w, &message)
}

/// The text after the last `/` of a link.
fn token_of(link: &str) -> &str {
    link.rsplit('/').next().unwrap_or(link)
}

/// True when the stored bytes contain `text`; the text must not be empty.
fn stored_contains(w: &World, text: &str) -> bool {
    assert!(!text.is_empty(), "the token under test must not be empty");
    let bytes = w.stored_bytes();
    bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes())
}

/// The `error` member of a JSON answer, or a panic naming the status.
fn error_code(page: &Page) -> String {
    page.json()
        .and_then(|json| json["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("the answer with status {} has no error member", page.status))
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_by_email_sets_a_new_password() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let link = request_reset(&w, &anonymous, BOB).await;
    let page = anonymous.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "a valid reset must answer 303");
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "a completed reset must redirect to /login"
    );
    let page = w.client().login(BOB, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "the new password must sign in");
    let page = w.client().login(BOB, PASSWORD).await;
    assert_eq!(page.status, 401, "the old password must no longer sign in");
}

#[tokio::test(flavor = "multi_thread")]
async fn answer_is_identical_for_an_unknown_address() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let known = forgot(&anonymous, BOB, &[]).await;
    let unknown = forgot(&anonymous, NOBODY, &[]).await;
    assert_eq!(
        known.status, 200,
        "a reset request for a known address must be answered 200"
    );
    assert_eq!(
        unknown.status, known.status,
        "a reset request for an unknown address must get the same status"
    );
    assert_eq!(
        unknown.body, known.body,
        "a reset request for an unknown address must get the same body"
    );
    reset_mail(&w, BOB).await;
    assert!(
        w.mail.to(NOBODY).is_empty(),
        "no reset mail may go to an unknown address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_link_works_once() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let link = request_reset(&w, &anonymous, BOB).await;
    let page = anonymous.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the first use of the reset link must work"
    );
    let page = anonymous.get(&link).await;
    assert_eq!(page.status, 404, "a used reset link must be refused on GET");
    assert_eq!(
        page.kind().as_deref(),
        Some("link-invalid"),
        "a used reset link must show data-page link-invalid"
    );
    let csrf = login_csrf(&anonymous).await;
    let page = anonymous
        .post(
            &link,
            &[("csrf", csrf.as_str()), ("password", NEW_PASSWORD)],
        )
        .await;
    assert_eq!(
        page.status, 404,
        "a used reset link must be refused on POST"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_link_expires_after_an_hour() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let old = request_reset(&w, &anonymous, BOB).await;
    w.gw.clock.advance(time::Duration::minutes(59));
    let fresh = request_reset(&w, &anonymous, BOB).await;
    w.gw.clock.advance(time::Duration::minutes(2));
    let page = anonymous.get(&old).await;
    assert_eq!(
        page.status, 404,
        "a reset link older than an hour must be refused on GET"
    );
    let csrf = login_csrf(&anonymous).await;
    let page = anonymous
        .post(&old, &[("csrf", csrf.as_str()), ("password", NEW_PASSWORD)])
        .await;
    assert_eq!(
        page.status, 404,
        "a reset link older than an hour must be refused on POST"
    );
    let page = anonymous.get(&fresh).await;
    assert_eq!(
        page.status, 200,
        "a reset link requested at 59 minutes must still open"
    );
    let page = anonymous.reset_password(&fresh, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "a reset link requested at 59 minutes must still work"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_kills_sessions_and_tokens() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let anonymous = w.client();
    let link = request_reset(&w, &anonymous, BOB).await;
    let page = anonymous.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "the reset must be accepted");
    let page = bob.get("/account").await;
    assert_eq!(
        page.status, 303,
        "the browser signed in before the reset must lose its session"
    );
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "a browser whose session was ended must be sent to /login"
    );
    let page = w.session_mcp("demo", &tokens).list_tools().await;
    assert_eq!(
        page.status, 401,
        "the access token from before the reset must be refused"
    );
    let page = w
        .client()
        .token_refresh(&w.app(), &tokens.refresh_token, None)
        .await;
    assert_eq!(
        page.status, 400,
        "the refresh token from before the reset must be refused"
    );
    assert_eq!(
        error_code(&page),
        "invalid_grant",
        "the refresh token from before the reset must answer invalid_grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_keeps_this_session_and_kills_the_rest() {
    let w = World::start().await;
    let a = w.user(BOB).await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&a, "demo").await;
    let b = w.client();
    let page = b.login(BOB, PASSWORD).await;
    assert_eq!(page.status, 303, "the second browser must sign in");
    let before = a
        .cookie(SESSION)
        .expect("browser A must hold a session cookie before the change");
    let page = a.change_password(PASSWORD, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "a valid password change must answer 303");
    assert_eq!(
        page.location().as_deref(),
        Some("/account"),
        "a password change must redirect to /account"
    );
    let page = a.get("/account").await;
    assert_eq!(
        page.status, 200,
        "the browser that changed the password must stay signed in"
    );
    let after = a
        .cookie(SESSION)
        .expect("browser A must hold a session cookie after the change");
    assert_ne!(
        before, after,
        "the session cookie of the changing browser must be replaced"
    );
    let page = b.get("/account").await;
    assert_eq!(
        page.status, 303,
        "another browser's session must end with the password change"
    );
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "another browser's ended session must be sent to /login"
    );
    let page = w.session_mcp("demo", &tokens).list_tools().await;
    assert_eq!(
        page.status, 401,
        "the access token must be refused after the password change"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_needs_the_current_password() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob
        .change_password("not-the-current-password", NEW_PASSWORD)
        .await;
    assert_eq!(
        page.status, 400,
        "a password change with a wrong current password must be refused"
    );
    let page = w.client().login(BOB, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the old password must still sign in after a refused change"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_link_ignores_the_host_header() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    w.mail.clear();
    let page = forgot(
        &anonymous,
        BOB,
        &[
            ("Host", "evil.example.com"),
            ("X-Forwarded-Host", "evil.example.com"),
        ],
    )
    .await;
    assert_eq!(
        page.status, 200,
        "a reset request with a forged Host must be answered 200"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forgot-sent"),
        "a reset request with a forged Host must show data-page forgot-sent"
    );
    let message = reset_mail(&w, BOB).await;
    reset_link(&w, &message);
    assert!(
        !message.text.contains("evil.example.com"),
        "the reset text must not use the forged host"
    );
    assert!(
        !message.html.contains("evil.example.com"),
        "the reset html must not use the forged host"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_user_gets_no_reset_mail() {
    let w = World::start().await;
    w.user(BOB).await;
    let bob_id = w.user_id(BOB).await;
    let page = admin::user_action(&w.owner, &bob_id, "disable").await;
    assert_eq!(page.status, 303, "disabling bob must answer 303");
    w.mail.clear();
    let anonymous = w.client();
    let page = forgot(&anonymous, BOB, &[]).await;
    assert_eq!(
        page.status, 200,
        "a reset request for a disabled user must be answered 200"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forgot-sent"),
        "a reset request for a disabled user must show data-page forgot-sent"
    );
    assert!(
        w.mail.wait_to(BOB, Duration::from_secs(1)).await.is_none(),
        "a disabled user must get no reset mail"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_token_is_not_stored() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let link = request_reset(&w, &anonymous, BOB).await;
    let token = token_of(&link);
    assert!(
        !stored_contains(&w, token),
        "the reset token must not appear in the database"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scanner_get_does_not_use_up_the_reset_link() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let link = request_reset(&w, &anonymous, BOB).await;
    let scanner = w.client();
    for attempt in 1..=3 {
        let page = scanner.get(&link).await;
        assert_eq!(
            page.status, 200,
            "GET number {attempt} of the reset link must open the page"
        );
        assert_eq!(
            page.kind().as_deref(),
            Some("reset"),
            "the reset link must show data-page reset"
        );
    }
    let browser = w.client();
    let page = browser.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "a reset link fetched by scanners must still set the password"
    );
    let page = w.client().login(BOB, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the password set through the link must sign in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_request_within_five_minutes_sends_nothing() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let first = request_reset(&w, &anonymous, BOB).await;
    w.mail.clear();
    let page = forgot(&anonymous, BOB, &[]).await;
    assert_eq!(
        page.status, 200,
        "a second reset request must be answered 200"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forgot-sent"),
        "a second reset request must show data-page forgot-sent"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        w.mail.to(BOB).is_empty(),
        "a reset request within five minutes of the last mail must send no mail"
    );
    let page = anonymous.get(&first).await;
    assert_eq!(
        page.status, 200,
        "the first reset link must still open after a second request"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("reset"),
        "the first reset link must show data-page reset"
    );
    w.gw.clock
        .advance(time::Duration::minutes(5) + time::Duration::seconds(1));
    let third = request_reset(&w, &anonymous, BOB).await;
    assert_ne!(
        third, first,
        "a reset request after five minutes must send a link that differs from the first"
    );
    let page = anonymous.get(&first).await;
    assert_eq!(
        page.status, 404,
        "the first reset link must be refused once a newer link exists"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("link-invalid"),
        "the first reset link must show data-page link-invalid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_lifts_the_login_block() {
    let w = World::start().await;
    w.user(BOB).await;
    for attempt in 1..=5 {
        let page = w.client().login(BOB, WRONG).await;
        assert_eq!(page.status, 401, "wrong guess {attempt} must answer 401");
    }
    let blocked = w.client().login(BOB, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the right password must be refused while the account is blocked"
    );
    let anonymous = w.client();
    let link = request_reset(&w, &anonymous, BOB).await;
    let page = anonymous.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(page.status, 303, "a valid reset must answer 303");
    let page = w.client().login(BOB, NEW_PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the new password must sign in at once, without waiting out the block"
    );
}
