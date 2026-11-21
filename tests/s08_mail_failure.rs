mod common;

use std::net::TcpListener;
use std::time::Duration;

use common::admin;
use common::client::Page;
use common::mail::Fail;
use common::world::{FROM, PASSWORD, World};

const BOB: &str = "bob@example.com";
const UNKNOWN: &str = "nobody@example.com";

/// Invites bob while the next mail fails; returns the failure page and the link it shows.
async fn failed_invitation(w: &World) -> (Page, String) {
    w.mail.fail_next(Fail::SmtpReject);
    let page = admin::invite(&w.owner, BOB, "user").await;
    assert_eq!(page.status, 200, "a failed invitation mail must answer 200");
    assert_eq!(
        page.kind().as_deref(),
        Some("invitation-created"),
        "a failed invitation mail must show the invitation-created page"
    );
    let error = page.text(r#"[data-notice="warning"]"#).unwrap_or_default();
    assert!(
        !error.is_empty(),
        "the failure page must show the error as a warning notice"
    );
    let prefix = format!("{}/invite/", w.base());
    let link = page
        .attr("[data-invite-link]", "data-invite-link")
        .unwrap_or_default();
    assert!(
        link.starts_with(prefix.as_str()),
        "the failure page must hold the invitation link starting with {prefix}, got {link:?}"
    );
    (page, link)
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_invitation_shows_the_error_and_the_link() {
    let w = World::start().await;
    let (_, link) = failed_invitation(&w).await;
    let browser = w.client();
    let page = browser.accept_invite(&link, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the link shown after a failed mail must accept a password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mail_failure_is_in_the_activity_log() {
    let w = World::start().await;
    failed_invitation(&w).await;
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "mail_failed"),
        "the activity log must hold a mail_failed row, kinds were {:?}",
        rows.iter().map(|row| row.kind.clone()).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_mail_server_does_not_hang_the_panel() {
    let w = World::start().await;
    let closed = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let port = closed.local_addr().expect("local address").port();
    drop(closed);
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "127.0.0.1",
        port,
        "mailer",
        "mail-password",
        "off",
    )
    .await;
    assert_eq!(page.status, 303, "saving the SMTP settings must answer 303");
    let page = tokio::time::timeout(
        Duration::from_secs(10),
        admin::invite(&w.owner, BOB, "user"),
    )
    .await
    .expect("the invitation must be answered within 10 seconds");
    assert_eq!(
        page.status, 200,
        "an unreachable mail server must answer 200 with the failure page"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("invitation-created"),
        "an unreachable mail server must show the invitation-created page"
    );
    assert!(
        !page
            .text(r#"[data-notice="warning"]"#)
            .unwrap_or_default()
            .is_empty(),
        "the failure page must show the error as a warning notice"
    );
    let health =
        w.gw.http
            .get(w.gw.url("/healthz"))
            .send()
            .await
            .expect("healthz request");
    assert_eq!(
        health.status(),
        reqwest::StatusCode::OK,
        "the gateway must stay up after an unreachable mail server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_reset_mail_reveals_nothing() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let unknown = anonymous
        .submit("/forgot", "/forgot", &[("email", UNKNOWN)])
        .await;
    assert_eq!(unknown.status, 200, "a reset request must answer 200");
    assert_eq!(
        unknown.kind().as_deref(),
        Some("forgot-sent"),
        "a reset request must show the forgot-sent page"
    );
    w.mail.fail_next(Fail::SmtpReject);
    let known = anonymous
        .submit("/forgot", "/forgot", &[("email", BOB)])
        .await;
    assert_eq!(
        known.status, 200,
        "a reset request with a failing mail must answer 200"
    );
    assert_eq!(
        known.body, unknown.body,
        "a failed reset mail must answer the same body as an unknown address"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let rows = admin::activity(&w.owner, None, None).await;
        if rows.iter().any(|row| row.kind == "mail_failed") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the failed reset mail must be in the activity log within 5 seconds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_link_is_shown_only_once() {
    let w = World::start().await;
    let (_, link) = failed_invitation(&w).await;
    let token = link.rsplit('/').next().unwrap_or_default();
    assert!(!token.is_empty(), "the invitation link must carry a token");
    assert!(
        admin::invitation_id(&w.owner, BOB).await.is_some(),
        "the failed invitation must be stored and listed"
    );
    let page = w.owner.get("/admin/invitations").await;
    assert!(
        !page.body.contains(token),
        "the invitations page must not show the token of a link that was already shown"
    );
}
