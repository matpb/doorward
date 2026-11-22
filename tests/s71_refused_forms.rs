mod common;

use std::time::Duration;

use common::TestGateway;
use common::admin;
use common::client::Page;
use common::headers::{declare_header, set_switches};
use common::mail::link_with_prefix;
use common::upstream::UpstreamOptions;
use common::world::{FROM, OWNER_EMAIL, PASSWORD, World};
use scraper::{Html, Selector};

const BOB: &str = "bob@example.com";
const DAVE: &str = "dave@example.com";
const UNKNOWN_EMAIL: &str = "nobody.here@example.com";
/// Stored addresses as a person might type them: spaced, in other capitals.
const OWNER_TYPED: &str = " Owner@example.com ";
const UNKNOWN_TYPED: &str = " Nobody.Here@example.com ";
const DAVE_TYPED: &str = " Dave@example.com ";
const TYPED_EMAIL: &str = "typed.person@example.org";
const TYPED_HOST: &str = "typed.example.org";

/// The elements of a parsed page that match `css`.
fn elements<'a>(doc: &'a Html, css: &str) -> Vec<scraper::ElementRef<'a>> {
    let selector =
        Selector::parse(css).unwrap_or_else(|err| panic!("bad selector {css:?}: {err:?}"));
    doc.select(&selector).collect()
}

/// The value attribute of the one element matching `css`; None when it has no value attribute.
fn value(page: &Page, css: &str) -> Option<String> {
    let doc = Html::parse_document(&page.body);
    let found = elements(&doc, css);
    assert_eq!(
        found.len(),
        1,
        "{css} must match one element, found {}",
        found.len()
    );
    found[0].value().attr("value").map(str::to_owned)
}

/// The values of the options of `select_css` that carry the selected attribute.
fn selected(page: &Page, select_css: &str) -> Vec<String> {
    let doc = Html::parse_document(&page.body);
    elements(&doc, &format!("{select_css} option[selected]"))
        .iter()
        .map(|option| option.value().attr("value").unwrap_or("").to_owned())
        .collect()
}

/// The control matching `css` holds no value attribute, so nothing posted is sent back in it.
fn assert_no_value(page: &Page, css: &str) {
    assert_eq!(
        value(page, css),
        None,
        "{css} must render with no value attribute"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_setup_sends_back_the_email() {
    let gw = TestGateway::start().await;
    let code = gw.setup_code().expect("the instance prints a setup code");
    let page = gw
        .client()
        .submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", code.as_str()),
                ("email", TYPED_EMAIL),
                ("password", "too short"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a short password must be refused with 400"
    );
    assert_eq!(
        value(&page, "input#email").as_deref(),
        Some(TYPED_EMAIL),
        "the owner email must come back as typed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_sign_in_sends_back_the_email() {
    let w = World::start().await;
    let page = w.client().login(TYPED_EMAIL, "wrong password typed").await;
    assert_eq!(
        page.status, 401,
        "a wrong password must be refused with 401"
    );
    assert_eq!(
        value(&page, "input#email").as_deref(),
        Some(TYPED_EMAIL),
        "the email must come back as typed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_invitation_sends_back_the_email_and_the_role() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let page = admin::invite(&w.owner, BOB, "admin").await;
    assert_eq!(
        page.status, 400,
        "an address that has an account must be refused with 400"
    );
    assert_eq!(
        value(&page, "input#invite-email").as_deref(),
        Some(BOB),
        "the email must come back as typed"
    );
    assert_eq!(
        selected(&page, "select#invite-role"),
        vec!["admin".to_string()],
        "the role chosen must stay selected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_rule_sends_back_every_choice() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob_id = w.user_id(BOB).await;
    let page = admin::add_rule(
        &w.owner,
        &bob_id,
        "deny",
        "tool",
        Some(&demo),
        Some("no_such_tool"),
    )
    .await;
    assert_eq!(
        page.status, 400,
        "a tool the server does not list must be refused with 400"
    );
    assert_eq!(
        selected(&page, "select#rule-subject"),
        vec![bob_id.clone()],
        "the subject chosen must stay selected"
    );
    assert_eq!(
        selected(&page, "select#rule-effect"),
        vec!["deny".to_string()],
        "the effect chosen must stay selected"
    );
    assert_eq!(
        selected(&page, "select#rule-scope"),
        vec!["tool".to_string()],
        "the scope chosen must stay selected"
    );
    assert_eq!(
        selected(&page, "select#rule-server"),
        vec![demo.clone()],
        "the server chosen must stay selected"
    );
    assert_eq!(
        value(&page, "input#rule-tool").as_deref(),
        Some("no_such_tool"),
        "the tool name must come back as typed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_redirect_sends_back_every_part() {
    let w = World::start().await;
    let page = admin::add_redirect(&w.owner, "http", TYPED_HOST, "/typed").await;
    assert_eq!(page.status, 400, "plain http must be refused with 400");
    assert_eq!(
        value(&page, "input#redirect-scheme").as_deref(),
        Some("http"),
        "the scheme must come back as typed"
    );
    assert_eq!(
        value(&page, "input#redirect-host").as_deref(),
        Some(TYPED_HOST),
        "the host must come back as typed"
    );
    assert_eq!(
        value(&page, "input#redirect-path").as_deref(),
        Some("/typed"),
        "the path prefix must come back as typed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_mail_provider_sends_back_its_posted_settings() {
    let w = World::start().await;
    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "smtp"),
                ("from", "typed-sender@example.org"),
                ("smtp_host", TYPED_HOST),
                ("smtp_port", "not-a-port"),
                ("smtp_username", "typed-user"),
                ("smtp_password", ""),
                ("smtp_tls", "starttls"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a port that is not a number must be refused with 400"
    );
    assert_eq!(
        value(&page, "input#smtp-from").as_deref(),
        Some("typed-sender@example.org"),
        "the refused form must show the posted address, not the stored one"
    );
    assert_eq!(
        value(&page, "input#smtp-host").as_deref(),
        Some(TYPED_HOST),
        "the refused form must show the posted server"
    );
    assert_eq!(
        value(&page, "input#smtp-port").as_deref(),
        Some("not-a-port"),
        "the refused form must show the posted port"
    );
    assert_eq!(
        value(&page, "input#smtp-username").as_deref(),
        Some("typed-user"),
        "the refused form must show the posted username"
    );
    assert_eq!(
        selected(&page, "select#smtp-tls"),
        vec!["starttls".to_string()],
        "the refused form must select the posted TLS setting"
    );
    assert_eq!(
        value(&page, "input#resend-from").as_deref(),
        Some(FROM),
        "the resend form must keep showing the stored address"
    );
    assert_eq!(
        value(&page, "input#mailgun-from").as_deref(),
        Some(FROM),
        "the mailgun form must keep showing the stored address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_test_email_sends_back_the_address() {
    let w = World::start().await;
    let page = admin::mail_test(&w.owner, "typed-address").await;
    assert_eq!(
        page.status, 400,
        "an address without an @ must be refused with 400"
    );
    assert_eq!(
        value(&page, "input#test-to").as_deref(),
        Some("typed-address"),
        "the test address must come back as typed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_refusal_sends_back_a_secret() {
    let gw = TestGateway::start().await;
    let code = gw.setup_code().expect("the instance prints a setup code");
    let page = gw
        .client()
        .submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", code.as_str()),
                ("email", TYPED_EMAIL),
                ("password", "zq-setup-7"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the setup refusal must answer 400");
    assert_no_value(&page, "input#password");
    assert_no_value(&page, "input#setup_code");
    assert!(
        !page.body.contains("zq-setup-7") && !page.body.contains(code.as_str()),
        "setup must not send back the password or the setup code"
    );

    let w = World::start().await;
    let page = w.client().login(OWNER_EMAIL, "zq-login-7").await;
    assert_eq!(page.status, 401, "the sign-in refusal must answer 401");
    assert_no_value(&page, "input#password");
    assert!(
        !page.body.contains("zq-login-7"),
        "sign-in must not send back the password"
    );

    let page = w
        .owner
        .submit(
            "/admin/servers",
            "/admin/servers",
            &[
                ("name", "Typed"),
                ("slug", "Bad Slug!"),
                ("upstream_url", "http://127.0.0.1:9/"),
                ("secret_header_name", "x-typed-header"),
                ("secret_header_value", "zq-server-7"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "a bad path must be refused with 400");
    assert_no_value(&page, "input#secret-value");
    assert!(
        !page.body.contains("zq-server-7"),
        "a server refusal must not send back the secret header value"
    );

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "smtp"),
                ("from", "typed-sender@example.org"),
                ("smtp_host", TYPED_HOST),
                ("smtp_port", "not-a-port"),
                ("smtp_username", "typed-user"),
                ("smtp_password", "zq-smtp-7"),
                ("smtp_tls", "off"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the smtp refusal must answer 400");
    assert_no_value(&page, "input#smtp-password");
    assert!(
        !page.body.contains("zq-smtp-7"),
        "a refused smtp save must not send back the password"
    );

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway\u{7}@example.com"),
                ("resend_api_key", "zq-resend-7"),
                ("resend_base_url", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the resend refusal must answer 400");
    assert_no_value(&page, "input#resend-key");
    assert!(
        !page.body.contains("zq-resend-7"),
        "a refused resend save must not send back the API key"
    );

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "mailgun"),
                ("from", "gateway\u{7}@example.com"),
                ("mailgun_api_key", "zq-mailgun-7"),
                ("mailgun_domain", "example.com"),
                ("mailgun_base_url", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the mailgun refusal must answer 400");
    assert_no_value(&page, "input#mailgun-key");
    assert!(
        !page.body.contains("zq-mailgun-7"),
        "a refused mailgun save must not send back the API key"
    );

    let page = w
        .owner
        .submit(
            "/account",
            "/account/password",
            &[
                ("current_password", PASSWORD),
                ("new_password", "zq-acct-7"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a short new password must be refused with 400"
    );
    assert_no_value(&page, "input#new_password");
    assert!(
        !page.body.contains("zq-acct-7"),
        "a refused password change must not send back the new password"
    );

    let anonymous = w.client();
    let asked = anonymous
        .submit("/forgot", "/forgot", &[("email", OWNER_EMAIL)])
        .await;
    assert_eq!(asked.status, 200, "the reset request must answer 200");
    let message = w
        .mail
        .wait_to(OWNER_EMAIL, Duration::from_secs(5))
        .await
        .expect("the reset mail arrives");
    let link = link_with_prefix(&message.text, &format!("{}/reset/", w.base()))
        .expect("the reset mail has a link");
    let page = anonymous
        .submit(&link, &link, &[("password", "zq-reset-7")])
        .await;
    assert_eq!(
        page.status, 400,
        "a short new password must be refused with 400"
    );
    assert_no_value(&page, "input#password");
    assert!(
        !page.body.contains("zq-reset-7"),
        "a refused reset must not send back the new password"
    );

    let invite = w.invite_link(DAVE, "user").await;
    let page = w
        .client()
        .submit(&invite, &invite, &[("password", "zq-invite-7")])
        .await;
    assert_eq!(
        page.status, 400,
        "a short password must be refused with 400"
    );
    assert_no_value(&page, "input#password");
    assert!(
        !page.body.contains("zq-invite-7"),
        "a refused invitation must not send back the password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_sign_in_reads_the_same_for_a_known_and_an_unknown_address() {
    let w = World::start().await;
    let _dave = w.user(DAVE).await;
    let dave_id = w.user_id(DAVE).await;
    let disabled = admin::user_action(&w.owner, &dave_id, "disable").await;
    assert_eq!(disabled.status, 303, "disabling dave must answer 303");
    for (typed, stored) in [
        (OWNER_TYPED, OWNER_EMAIL),
        (UNKNOWN_TYPED, UNKNOWN_EMAIL),
        (DAVE_TYPED, DAVE),
    ] {
        assert_eq!(
            typed.trim().to_lowercase(),
            stored,
            "the typed spelling must be another spelling of the stored one"
        );
    }
    // The known, the unknown and the disabled account, each with a wrong password; the disabled one also with the right one.
    let answers = [
        (OWNER_TYPED, "zq-same-7"),
        (UNKNOWN_TYPED, "zq-same-7"),
        (DAVE_TYPED, "zq-same-7"),
        (DAVE_TYPED, PASSWORD),
    ];
    let mut masked = Vec::new();
    for (typed, password) in answers {
        let page = w.client().login(typed, password).await;
        assert_eq!(
            page.status, 401,
            "a refused sign-in must answer 401 for {typed:?}"
        );
        assert_eq!(
            value(&page, "input#email").as_deref(),
            Some(typed),
            "the address must come back as typed"
        );
        let csrf = page.csrf().expect("the sign-in page carries a csrf value");
        masked.push(page.body.replace(&csrf, "CSRF").replace(typed, "ADDRESS"));
    }
    for (index, answer) in masked.iter().enumerate().skip(1) {
        assert_eq!(
            answer, &masked[0],
            "answer {index} must read the same as the first, apart from the typed address"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_typed_value_with_markup_comes_back_escaped() {
    let w = World::start().await;
    let page = admin::add_redirect(&w.owner, "http", "\"><b>x", "/typed").await;
    assert_eq!(page.status, 400, "plain http must be refused with 400");
    assert_eq!(
        value(&page, "input#redirect-host").as_deref(),
        Some("\"><b>x"),
        "the typed markup must come back as its characters"
    );
    let doc = Html::parse_document(&page.body);
    assert_eq!(
        elements(&doc, "b").len(),
        0,
        "no b element may come from a typed value"
    );
    assert!(
        page.body.contains(r#"value="&quot;&gt;&lt;b&gt;x""#),
        "the typed value must be escaped inside its attribute"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_control_character_is_removed_from_the_value_sent_back() {
    let w = World::start().await;
    let page = admin::add_redirect(&w.owner, "http", "typed\u{7}.\texample.org", "/typed").await;
    assert_eq!(
        page.status, 400,
        "a host with a control character must be refused with 400"
    );
    assert_eq!(
        value(&page, "input#redirect-host").as_deref(),
        Some("typed.example.org"),
        "the value must come back without its control characters"
    );
    assert!(
        !page.body.contains('\u{7}'),
        "the control character must not appear anywhere in the page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overlong_value_is_not_sent_back() {
    let w = World::start().await;
    let long_host = "h".repeat(501);
    let page = admin::add_redirect(&w.owner, "http", &long_host, "/typed").await;
    assert_eq!(page.status, 400, "plain http must be refused with 400");
    assert_eq!(
        value(&page, "input#redirect-scheme").as_deref(),
        Some("http"),
        "a short value must still come back"
    );
    assert_eq!(
        value(&page, "input#redirect-host").unwrap_or_default(),
        "",
        "a host over 500 characters must render empty"
    );
    assert!(
        !page.body.contains(&long_host),
        "the overlong host must not appear in the page"
    );

    let long_email = format!("{}@example.com", "a".repeat(250));
    let page = admin::invite(&w.owner, &long_email, "user").await;
    assert_eq!(
        page.status, 400,
        "an address over 254 characters must be refused with 400"
    );
    assert_eq!(
        value(&page, "input#invite-email").unwrap_or_default(),
        "",
        "an address over 254 characters must render empty"
    );
    assert!(
        !page.body.contains(&long_email),
        "the overlong address must not appear in the page"
    );
}

/// The text of the first element matching `css`, after parsing the page.
fn text_of(page: &Page, css: &str) -> String {
    let doc = Html::parse_document(&page.body);
    let found = elements(&doc, css);
    assert_eq!(found.len(), 1, "{css} must match one element");
    found[0].text().collect::<String>()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_server_form_sends_back_cleaned_values() {
    let w = World::start().await;
    let long_url = format!("https://example.com/{}", "a".repeat(481));
    assert_eq!(long_url.chars().count(), 501);
    let page = w
        .owner
        .submit(
            "/admin/servers",
            "/admin/servers",
            &[
                ("name", "Ty\u{7}ped"),
                ("slug", "Bad Slug!"),
                ("upstream_url", long_url.as_str()),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "a bad path must be refused with 400");
    assert!(
        !page.body.contains('\u{7}'),
        "the control character must not appear in the page"
    );
    assert_eq!(
        value(&page, "input#server-name").as_deref(),
        Some("Typed"),
        "the name must come back without its control character"
    );
    assert_eq!(
        value(&page, "input#server-url").unwrap_or_default(),
        "",
        "an address over 500 characters must render empty"
    );

    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let path = format!("/admin/servers/{demo}");
    let page = w
        .owner
        .submit(
            &path,
            &path,
            &[
                ("name", "Ty\u{7}ped"),
                ("slug", "Bad Slug!"),
                ("upstream_url", long_url.as_str()),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a bad path on the edit form must be refused with 400"
    );
    assert!(
        !page.body.contains('\u{7}'),
        "the control character must not appear on the edit page"
    );
    assert_eq!(
        value(&page, "input#server-url").unwrap_or_default(),
        "",
        "an address over 500 characters must render empty on the edit page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_mail_secret_is_asked_for_again() {
    const ASK_AGAIN: &str = "Enter it again: a secret is never sent back.";
    const SMTP_HINT: &str = "Leave empty to keep the stored one. If you change the server, the port, the username or the TLS setting, enter it again.";
    let w = World::start().await;

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "smtp"),
                ("from", FROM),
                ("smtp_host", TYPED_HOST),
                ("smtp_port", "not-a-port"),
                ("smtp_username", "typed-user"),
                ("smtp_password", "zq-smtp-7"),
                ("smtp_tls", "off"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the smtp refusal must answer 400");
    assert_eq!(text_of(&page, "p#smtp-password-hint"), ASK_AGAIN);
    assert!(
        value(&page, "input#smtp-password").is_none(),
        "the secret must not come back"
    );
    assert!(
        !page.body.contains("zq-smtp-7"),
        "the secret must appear nowhere"
    );

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "smtp"),
                ("from", FROM),
                ("smtp_host", TYPED_HOST),
                ("smtp_port", "not-a-port"),
                ("smtp_username", "typed-user"),
                ("smtp_password", ""),
                ("smtp_tls", "off"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the smtp refusal must answer 400");
    assert_eq!(text_of(&page, "p#smtp-password-hint"), SMTP_HINT);

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway\u{7}@example.com"),
                ("resend_api_key", "zq-resend-7"),
                ("resend_base_url", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the resend refusal must answer 400");
    assert_eq!(text_of(&page, "p#resend-key-hint"), ASK_AGAIN);
    assert!(
        !page.body.contains("zq-resend-7"),
        "the API key must appear nowhere"
    );

    let page = w
        .owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "mailgun"),
                ("from", "gateway\u{7}@example.com"),
                ("mailgun_api_key", "zq-mailgun-7"),
                ("mailgun_domain", "example.com"),
                ("mailgun_base_url", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "the mailgun refusal must answer 400");
    assert_eq!(text_of(&page, "p#mailgun-key-hint"), ASK_AGAIN);
    assert!(
        !page.body.contains("zq-mailgun-7"),
        "the API key must appear nowhere"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_server_form_asks_for_the_secret_again() {
    const ASK_AGAIN: &str = "Enter it again: a secret is never sent back.";
    let w = World::start().await;

    let page = w
        .owner
        .submit(
            "/admin/servers",
            "/admin/servers",
            &[
                ("name", "Typed"),
                ("slug", "Bad Slug!"),
                ("upstream_url", "http://127.0.0.1:9/"),
                ("secret_header_name", "x-typed-header"),
                ("secret_header_value", "zq-server-7"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "a bad path must be refused with 400");
    assert_eq!(text_of(&page, "#secret-value-hint"), ASK_AGAIN);
    assert!(
        !page.body.contains("zq-server-7"),
        "the secret must appear nowhere"
    );

    let page = w
        .owner
        .submit(
            "/admin/servers",
            "/admin/servers",
            &[
                ("name", "Typed"),
                ("slug", "Bad Slug!"),
                ("upstream_url", "http://127.0.0.1:9/"),
                ("secret_header_name", "x-typed-header"),
                ("secret_header_value", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "a bad path must be refused with 400");
    assert_eq!(
        text_of(&page, "#secret-value-hint"),
        "Kept encrypted and never shown again."
    );

    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let path = format!("/admin/servers/{demo}");
    let page = w
        .owner
        .submit(
            &path,
            &path,
            &[
                ("name", "Demo"),
                ("slug", "Bad Slug!"),
                ("upstream_url", "http://127.0.0.1:9/"),
                ("secret_header_name", "x-typed-header"),
                ("secret_header_value", "zq-server-8"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a bad path on the edit form must be refused with 400"
    );
    assert_eq!(text_of(&page, "#secret-value-hint"), ASK_AGAIN);
    assert!(
        !page.body.contains("zq-server-8"),
        "the secret must appear nowhere on the edit page"
    );

    let page = w
        .owner
        .submit(
            &path,
            &path,
            &[
                ("name", "Demo"),
                ("slug", "Bad Slug!"),
                ("upstream_url", "http://127.0.0.1:9/"),
                ("secret_header_name", "x-typed-header"),
                ("secret_header_value", ""),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a bad path on the edit form must be refused with 400"
    );
    assert_eq!(
        text_of(&page, "#secret-value-hint"),
        "Stored, never shown again. Leave empty to keep it. If you change the upstream address, enter it again."
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limited_sign_in_sends_no_address_back() {
    let w = World::start().await;
    let browser = w.client();
    for attempt in 1..=5 {
        let page = browser.login(OWNER_EMAIL, "zq-limit-7").await;
        assert_eq!(page.status, 401, "wrong password {attempt} must answer 401");
    }
    let limited = browser.login(OWNER_EMAIL, "zq-limit-7").await;
    assert_eq!(limited.status, 429, "the sixth guess must be limited");
    assert_no_value(&limited, "input#email");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_header_form_sends_back_its_name_and_its_required_box() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let path = format!("/admin/servers/{id}");
    let page = w
        .owner
        .submit(
            &path,
            &format!("{path}/headers"),
            &[("name", "Cookie"), ("required", "1")],
        )
        .await;
    assert_eq!(page.status, 400, "a refused header name must answer 400");
    assert_eq!(
        page.text(r#"div.notice[data-notice="error"] > p"#)
            .as_deref(),
        Some(
            "The header was not added. Cookie cannot be used as a custom header. Choose another name. Go to the header name field"
        ),
        "the notice names the outcome, then the reason, then links to the field"
    );
    assert_eq!(
        page.count(r#"div.notice[data-notice="error"] > p > code"#),
        1,
        "the header name in the notice is set in code"
    );
    assert_eq!(
        value(&page, "input#header-name").as_deref(),
        Some("Cookie"),
        "the refused name comes back in its field"
    );
    assert_eq!(
        page.attr("input#header-name", "aria-invalid").as_deref(),
        Some("true")
    );
    assert_eq!(
        page.text("p.field-error#header-name-error").as_deref(),
        Some("Cookie cannot be used as a custom header. Choose another name."),
        "the reason sits under the field"
    );
    assert_eq!(
        page.count("input#header-required[checked]"),
        1,
        "the Required box comes back as it was sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_field_error_of_a_refused_header_is_one_text_element_beside_its_mark() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let path = format!("/admin/servers/{id}");
    let page = w
        .owner
        .submit(
            &path,
            &format!("{path}/headers"),
            &[("name", "Cookie"), ("required", "1")],
        )
        .await;
    assert_eq!(page.status, 400, "a refused header name must answer 400");
    let doc = scraper::Html::parse_document(&page.body);
    let selector = Selector::parse("p.field-error#header-name-error").expect("selector");
    let error = doc
        .select(&selector)
        .next()
        .expect("the field error must be on the page");
    let elements: Vec<String> = error
        .children()
        .filter_map(|node| node.value().as_element().map(|el| el.name().to_owned()))
        .collect();
    assert_eq!(
        elements,
        vec!["span".to_owned()],
        "the field error must hold exactly one element, the text block beside its mark"
    );
    let loose_text = error.children().any(|node| {
        node.value()
            .as_text()
            .is_some_and(|text| !text.trim().is_empty())
    });
    assert!(
        !loose_text,
        "the field error must hold no bare text node beside its element"
    );
    assert_eq!(
        page.text("p.field-error#header-name-error > span > code")
            .as_deref(),
        Some("Cookie"),
        "the name is set in code inside the text block"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_password_change_still_holds_the_credentials_part() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    let declared = declare_header(&w.owner, &id, "X-Trace-Id", false).await;
    assert_eq!(
        declared.status, 303,
        "declaring the header must be accepted"
    );
    let switched = set_switches(&w.owner, &id, false, true).await;
    assert_eq!(switched.status, 303, "the store switch must be saved");
    let page = bob
        .submit(
            "/account",
            "/account/password",
            &[
                ("current_password", PASSWORD),
                ("new_password", "zq-acct-7"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a short new password must be refused with 400"
    );
    assert_eq!(
        page.count(r#"section[data-values-server="demo"]"#),
        1,
        "the refused account page must still hold the credentials part"
    );
    assert_eq!(
        page.count("[data-values-locked]"),
        0,
        "a session whose key opens must not show the locked part"
    );
}
