mod common;

use std::time::Duration;

use common::admin::{self, ServerSpec};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{APP_ID, APP_REDIRECT, World};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const SNEAKY: &str = "Sneaky Name 4711";
const SERVER_NAME: &str = "Internal documentation search";
const EVERY_SERVER: &str = "every server assigned to you";
const CLOSING: &str = "Doorward decides who reaches which MCP server and which tool, and keeps a record of every call.";
const RESET_NOTE: &str = "If this was not you, ignore this mail. Your password stays the same.";
const CONNECTED_SUBJECT: &str = "A new app was connected to your Doorward account";
const WAIT: Duration = Duration::from_secs(5);

/// The gateway's own host as the mails write it: its address without the scheme.
fn gateway_host(w: &World) -> &str {
    w.base()
        .split_once("://")
        .map_or(w.base(), |(_, rest)| rest)
}

/// Adds an upstream whose name is not its slug, and returns it with its id.
async fn named_server(w: &World, name: &str, slug: &str) -> (FakeUpstream, String) {
    let upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let id = admin::add_server(
        &w.owner,
        &ServerSpec {
            name,
            slug,
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    (upstream, id)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_connection_to_one_server_is_announced_with_its_facts() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = named_server(&w, SERVER_NAME, "docs").await;
    w.grant(BOB, &[id.as_str()]).await;
    w.gw.cimd().put(APP_ID, SNEAKY, &[APP_REDIRECT]);
    w.mail.clear();
    w.token(&bob, "docs").await;
    let message = w
        .mail
        .wait_to(BOB, WAIT)
        .await
        .expect("bob must be mailed about the new connection");
    assert_eq!(message.subject, CONNECTED_SUBJECT);
    let host = gateway_host(&w);
    assert!(
        message
            .text
            .contains(&format!("It can use {SERVER_NAME}.\n")),
        "the text names the server: {}",
        message.text
    );
    assert!(
        message
            .text
            .contains("The sign-in was sent to 127.0.0.1:53535.\n"),
        "the text names the destination: {}",
        message.text
    );
    assert!(
        message
            .text
            .lines()
            .any(|line| line.starts_with("Connected on ") && line.ends_with(" UTC.")),
        "the text holds a Connected on line: {}",
        message.text
    );
    assert!(
        message.text.contains(&format!(
            "Sent by the Doorward gateway at {host}. {CLOSING}"
        )),
        "the text closes with the gateway's host: {}",
        message.text
    );
    let port = host
        .strip_prefix("127.0.0.1:")
        .expect("the gateway listens on 127.0.0.1");
    assert!(
        message.html.contains(&format!(
            r#"<span style="display:inline-block;max-width:100%;">127<span>.0</span><span>.0</span><span>.1:{port}</span>.</span> Doorward decides"#
        )),
        "the HTML closes with the gateway's host in its last span"
    );
    assert!(message.html.contains(SERVER_NAME));
    for part in [&message.text, &message.html] {
        assert!(
            !part.contains(SNEAKY),
            "the client's own name must not be in the mail"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_connection_through_the_combined_endpoint_says_so() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = named_server(&w, SERVER_NAME, "docs").await;
    w.grant(BOB, &[id.as_str()]).await;
    w.mail.clear();
    w.token(&bob, "mcp").await;
    let message = w
        .mail
        .wait_to(BOB, WAIT)
        .await
        .expect("bob must be mailed about the new connection");
    assert!(
        message
            .text
            .contains(&format!("It can use {EVERY_SERVER}.\n")),
        "the combined endpoint names every server: {}",
        message.text
    );
    assert!(message.html.contains(EVERY_SERVER));
    assert!(!message.text.contains(SERVER_NAME));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reset_mail_says_what_to_do_when_it_was_not_asked_for() {
    let w = World::start().await;
    w.user(BOB).await;
    w.mail.clear();
    let browser = w.client();
    let csrf = browser
        .get("/forgot")
        .await
        .csrf()
        .expect("the forgot page must carry a csrf field");
    let page = browser
        .post("/forgot", &[("csrf", csrf.as_str()), ("email", BOB)])
        .await;
    assert_eq!(page.status, 200, "a reset request must be answered 200");
    let message = w
        .mail
        .wait_to(BOB, WAIT)
        .await
        .expect("bob must be mailed the reset link");
    assert_eq!(message.subject, "Reset your Doorward password");
    assert!(
        message.text.contains(RESET_NOTE),
        "the reset text holds the note: {}",
        message.text
    );
    assert!(
        message
            .html
            .contains("If this was not you, ignore this mail. Your password stays the&nbsp;same."),
        "the reset HTML holds the note"
    );
    assert!(
        message.text.contains(&format!(
            "Sent by the Doorward gateway at {}. {CLOSING}",
            gateway_host(&w)
        )),
        "the reset text closes with the gateway's host"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invitation_mail_closes_with_the_gateway_sentence() {
    let w = World::start().await;
    w.invite_link(CAROL, "user").await;
    let message = w
        .mail
        .last_to(CAROL)
        .expect("carol's invitation mail is caught");
    assert_eq!(message.subject, "You are invited to Doorward");
    assert!(
        message.text.contains(&format!(
            "Sent by the Doorward gateway at {}. {CLOSING}",
            gateway_host(&w)
        )),
        "the invitation text closes with the gateway's host: {}",
        message.text
    );
    assert!(
        message.html.contains(
            "Doorward decides who reaches which MCP server and which tool, and keeps a record of every&nbsp;call."
        ),
        "the invitation HTML closes with the gateway sentence"
    );
}
