mod common;

use std::time::Duration;

use common::admin;
use common::mail::{Captured, Fail, MailCatcher, Via, link_with_prefix};
use common::world::{FROM, World};

const PROBE: &str = "probe@example.com";
const BOB: &str = "bob@example.com";
const WAIT: Duration = Duration::from_secs(5);
const CANARIES: [&str; 3] = [
    "CANARY-SMTP-4f1e9a",
    "CANARY-RESEND-8c2d7b",
    "CANARY-MAILGUN-1b6e3f",
];
const PLAIN_USER_SETTINGS: &[(&str, &str)] = &[
    ("provider", "resend"),
    ("from", FROM),
    ("resend_api_key", "re_plain_user"),
];

/// The newest mail to `address` that the catcher holds, waiting up to 5 seconds for it.
async fn mail_to(mail: &MailCatcher, address: &str) -> Captured {
    mail.wait_to(address, WAIT)
        .await
        .unwrap_or_else(|| panic!("no mail to {address} arrived within 5 seconds"))
}

/// Sends the test mail to PROBE and checks that the gateway reports it sent.
async fn send_test_mail(w: &World) {
    let page = admin::mail_test(&w.owner, PROBE).await;
    assert_eq!(page.status, 200, "the test mail must be answered with 200");
    assert_eq!(
        page.notice().as_deref(),
        Some("Test email sent."),
        "the test mail must report that it was sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_test_email_arrives() {
    let w = World::start().await;
    send_test_mail(&w).await;
    let message = mail_to(&w.mail, PROBE).await;
    assert_eq!(
        message.via,
        Via::Smtp,
        "the test mail must travel over SMTP"
    );
    assert!(!message.tls, "the plain SMTP test mail must not be TLS");
    assert_eq!(
        message.subject, "Doorward test email",
        "the test mail must have the test subject"
    );
    assert!(
        message.from.contains(FROM),
        "the test mail must come from {FROM}, got {:?}",
        message.from
    );
    assert_eq!(
        message.auth_user.as_deref(),
        Some("mailer"),
        "the SMTP login must be the configured user"
    );
    assert_eq!(
        message.auth_secret.as_deref(),
        Some("mail-password"),
        "the SMTP login must use the configured password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_starttls_with_the_configured_roots() {
    let m = MailCatcher::start().await;
    let w = World::start_with(|c| c.mail.smtp_ca_file = Some(m.ca_pem_path())).await;
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "localhost",
        m.smtp_starttls_port(),
        "mailer",
        "mail-password",
        "starttls",
    )
    .await;
    assert_eq!(page.status, 303, "saving STARTTLS settings must answer 303");
    send_test_mail(&w).await;
    let message = mail_to(&m, PROBE).await;
    assert_eq!(
        message.via,
        Via::Smtp,
        "the test mail must travel over SMTP"
    );
    assert!(message.tls, "the STARTTLS test mail must arrive over TLS");
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_implicit_tls() {
    let m = MailCatcher::start().await;
    let w = World::start_with(|c| c.mail.smtp_ca_file = Some(m.ca_pem_path())).await;
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "localhost",
        m.smtp_tls_port(),
        "mailer",
        "mail-password",
        "implicit",
    )
    .await;
    assert_eq!(
        page.status, 303,
        "saving implicit TLS settings must answer 303"
    );
    send_test_mail(&w).await;
    let message = mail_to(&m, PROBE).await;
    assert_eq!(
        message.via,
        Via::Smtp,
        "the test mail must travel over SMTP"
    );
    assert!(
        message.tls,
        "the implicit TLS test mail must arrive over TLS"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_certificate_shows_an_error() {
    let m = MailCatcher::start().await;
    let w = World::start().await;
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "localhost",
        m.smtp_starttls_port(),
        "mailer",
        "mail-password",
        "starttls",
    )
    .await;
    assert_eq!(page.status, 303, "saving STARTTLS settings must answer 303");
    let page = admin::mail_test(&w.owner, PROBE).await;
    assert_eq!(
        page.status, 200,
        "a failed test mail must be answered with 200"
    );
    let error = page
        .error()
        .expect("an untrusted certificate must show an error");
    assert!(!error.is_empty(), "the shown error must not be empty");
    assert!(
        m.messages().is_empty(),
        "no mail may be sent over an untrusted certificate"
    );
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "mail_failed"),
        "the activity log must hold a mail_failed row, kinds were {:?}",
        rows.iter().map(|row| row.kind.clone()).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_rejection_shows_the_provider_error() {
    let w = World::start().await;
    w.mail.fail_next(Fail::SmtpReject);
    let page = admin::mail_test(&w.owner, PROBE).await;
    assert_eq!(
        page.status, 200,
        "a rejected test mail must be answered with 200"
    );
    let error = page.error().unwrap_or_default();
    assert!(
        error.contains("Relaying denied"),
        "the SMTP server's rejection must be shown, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn starttls_is_never_downgraded() {
    let m = MailCatcher::start().await;
    let w = World::start_with(|c| c.mail.smtp_ca_file = Some(m.ca_pem_path())).await;
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "localhost",
        m.smtp_plain_port(),
        "mailer",
        "mail-password",
        "starttls",
    )
    .await;
    assert_eq!(page.status, 303, "saving STARTTLS settings must answer 303");
    let page = admin::mail_test(&w.owner, PROBE).await;
    assert_eq!(
        page.status, 200,
        "a refused STARTTLS must be answered with 200"
    );
    let error = page.error().unwrap_or_default();
    assert!(
        !error.is_empty(),
        "a server without STARTTLS must make the test fail with an error"
    );
    assert!(
        m.messages().is_empty(),
        "no mail may be sent without STARTTLS when it is required"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resend_test_email() {
    let w = World::start().await;
    let page = admin::mail_resend(&w.owner, FROM, "re_test_key", &w.mail.resend_base()).await;
    assert_eq!(page.status, 303, "saving Resend settings must answer 303");
    send_test_mail(&w).await;
    let message = mail_to(&w.mail, PROBE).await;
    assert_eq!(
        message.via,
        Via::Resend,
        "the test mail must go through Resend"
    );
    assert_eq!(
        message.auth_secret.as_deref(),
        Some("re_test_key"),
        "Resend must be called with the configured key"
    );
    assert_eq!(
        message.path, "/emails",
        "Resend mail must use the emails path"
    );
    assert_eq!(
        message.to,
        vec![PROBE],
        "the test mail must be addressed to the probe"
    );
    assert!(
        message
            .user_agent
            .as_deref()
            .unwrap_or_default()
            .starts_with("doorward/"),
        "Resend requests must carry a doorward/ user agent, got {:?}",
        message.user_agent
    );
    assert!(
        !message.text.is_empty(),
        "the Resend mail must have a text part"
    );
    assert!(
        !message.html.is_empty(),
        "the Resend mail must have an HTML part"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resend_error_is_shown() {
    let w = World::start().await;
    let page = admin::mail_resend(&w.owner, FROM, "re_test_key", &w.mail.resend_base()).await;
    assert_eq!(page.status, 303, "saving Resend settings must answer 303");
    w.mail.fail_next(Fail::ResendForbidden);
    let page = admin::mail_test(&w.owner, PROBE).await;
    assert_eq!(
        page.status, 200,
        "a refused Resend mail must be answered with 200"
    );
    let error = page.error().unwrap_or_default();
    assert!(
        error.contains("domain is not verified"),
        "Resend's error must be shown, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mailgun_test_email() {
    let w = World::start().await;
    let page = admin::mail_mailgun(
        &w.owner,
        FROM,
        "key-test",
        "mg.example.com",
        &w.mail.mailgun_base(),
    )
    .await;
    assert_eq!(page.status, 303, "saving Mailgun settings must answer 303");
    send_test_mail(&w).await;
    let message = mail_to(&w.mail, PROBE).await;
    assert_eq!(
        message.via,
        Via::Mailgun,
        "the test mail must go through Mailgun"
    );
    assert_eq!(
        message.auth_user.as_deref(),
        Some("api"),
        "Mailgun basic auth must use the api user"
    );
    assert_eq!(
        message.auth_secret.as_deref(),
        Some("key-test"),
        "Mailgun must be called with the configured key"
    );
    assert_eq!(
        message.path, "/v3/mg.example.com/messages",
        "Mailgun mail must use the domain's messages path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mailgun_error_is_shown() {
    let w = World::start().await;
    let page = admin::mail_mailgun(
        &w.owner,
        FROM,
        "key-test",
        "mg.example.com",
        &w.mail.mailgun_base(),
    )
    .await;
    assert_eq!(page.status, 303, "saving Mailgun settings must answer 303");
    w.mail.fail_next(Fail::MailgunUnauthorized);
    let page = admin::mail_test(&w.owner, PROBE).await;
    assert_eq!(
        page.status, 200,
        "a refused Mailgun mail must be answered with 200"
    );
    let error = page.error().unwrap_or_default();
    assert!(
        error.contains("Invalid private key"),
        "Mailgun's error must be shown, got {error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_are_encrypted_and_never_shown_again() {
    let w = World::start().await;
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "127.0.0.1",
        w.mail.smtp_plain_port(),
        "mailer",
        CANARIES[0],
        "off",
    )
    .await;
    assert_eq!(page.status, 303, "saving the SMTP password must answer 303");
    let page = admin::mail_resend(&w.owner, FROM, CANARIES[1], &w.mail.resend_base()).await;
    assert_eq!(page.status, 303, "saving the Resend key must answer 303");
    let page = admin::mail_mailgun(
        &w.owner,
        FROM,
        CANARIES[2],
        "mg.example.com",
        &w.mail.mailgun_base(),
    )
    .await;
    assert_eq!(page.status, 303, "saving the Mailgun key must answer 303");

    let shown = w.owner.get("/admin/mail").await;
    assert_eq!(
        shown.status, 200,
        "the mail page must answer 200 to the owner"
    );
    assert_eq!(
        shown.kind().as_deref(),
        Some("mail"),
        "the mail page must carry data-page mail"
    );
    let stored = String::from_utf8_lossy(&w.stored_bytes()).into_owned();
    for canary in CANARIES {
        assert!(
            !shown.body.contains(canary),
            "the mail page must never show a stored secret, but it shows {canary}"
        );
        assert!(
            !stored.contains(canary),
            "a stored secret must be encrypted, but {canary} is in the database"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_secret_keeps_the_stored_one() {
    let w = World::start().await;
    let page = admin::mail_smtp(
        &w.owner,
        FROM,
        "127.0.0.1",
        w.mail.smtp_plain_port(),
        "mailer",
        "",
        "off",
    )
    .await;
    assert_eq!(
        page.status, 303,
        "saving with an empty password must answer 303"
    );
    send_test_mail(&w).await;
    let message = mail_to(&w.mail, PROBE).await;
    assert_eq!(
        message.auth_secret.as_deref(),
        Some("mail-password"),
        "an empty password field must keep the stored password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_goes_through_the_selected_provider() {
    let w = World::start().await;
    let page = admin::mail_resend(&w.owner, FROM, "re_test_key", &w.mail.resend_base()).await;
    assert_eq!(page.status, 303, "saving Resend settings must answer 303");
    let page = admin::invite(&w.owner, BOB, "user").await;
    assert_eq!(page.status, 303, "the invitation must answer 303");
    let message = mail_to(&w.mail, BOB).await;
    assert_eq!(
        message.via,
        Via::Resend,
        "the invitation must go through the selected provider"
    );
    let prefix = format!("{}/invite/", w.base());
    assert!(
        link_with_prefix(&message.text, &prefix).is_some(),
        "the invitation must hold a link starting with {prefix}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_admins_change_mail_settings() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob
        .submit("/account", "/admin/mail", PLAIN_USER_SETTINGS)
        .await;
    assert_eq!(
        page.status, 403,
        "a plain user's settings post must be refused"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "a plain user's settings post must show the forbidden page"
    );
    let anonymous = w.client();
    let page = anonymous
        .submit("/login", "/admin/mail", PLAIN_USER_SETTINGS)
        .await;
    assert_eq!(
        page.status, 303,
        "an anonymous settings post must be redirected"
    );
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "an anonymous settings post must go to sign-in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mail_settings_survive_a_restart() {
    let mut w = World::start().await;
    w.gw.restart().await;
    w.mail.clear();
    send_test_mail(&w).await;
    let message = mail_to(&w.mail, PROBE).await;
    assert_eq!(
        message.via,
        Via::Smtp,
        "the saved SMTP settings must still send after a restart"
    );
}
