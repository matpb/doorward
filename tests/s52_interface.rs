mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use common::TestGateway;
use common::admin;
use common::client::{self, OAuthApp, Page, TestClient};
use common::mail::{Fail, link_with_prefix};
use common::upstream::{Mode, UpstreamOptions};
use common::world::{APP_ID, APP_NAME, OWNER_EMAIL, PASSWORD, World};
use scraper::{ElementRef, Html, Selector};
use serde_json::json;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const DAVE: &str = "dave@example.com";
const EVE: &str = "eve@example.com";
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
const CARD: &str = "card";
const PANEL: &str = "panel";
const WIDE: &str = "page";
const HEADER: &str = "body > header[data-brand]";
const NAV: &str = r#"nav[data-nav="panel"]"#;
const TONES: [&str; 4] = ["ok", "bad", "warn", "muted"];
const DANGER_WORDS: [&str; 4] = ["Delete", "Revoke", "Remove", "Disconnect"];
const SECONDARY_WORDS: [&str; 8] = [
    "Disable",
    "Enable",
    "Deny",
    "Filter",
    "Refresh tools",
    "Check lock-down",
    "Send test email",
    "Sign out",
];
const PROVIDERS: [&str; 3] = ["smtp", "resend", "mailgun"];
const DARK_MEDIA: &str = "@media (prefers-color-scheme: dark)";
const VARIABLES: [&str; 13] = [
    "--bg",
    "--surface",
    "--ink",
    "--muted",
    "--line",
    "--accent",
    "--on-accent",
    "--ok",
    "--ok-bg",
    "--bad",
    "--bad-bg",
    "--warn",
    "--warn-bg",
];
/// (text colour, background colour) pairs that must reach 4.5 to 1 in both themes.
const PAIRS: [(&str, &str); 13] = [
    ("--ink", "--bg"),
    ("--ink", "--surface"),
    ("--muted", "--bg"),
    ("--muted", "--surface"),
    ("--accent", "--bg"),
    ("--accent", "--surface"),
    ("--on-accent", "--accent"),
    ("--ok", "--ok-bg"),
    ("--bad", "--bad-bg"),
    ("--warn", "--warn-bg"),
    ("--ok", "--surface"),
    ("--bad", "--surface"),
    ("--warn", "--surface"),
];

/// A page the interface tests read, with the layout it must carry.
struct Shot {
    name: String,
    page: Page,
    layout: &'static str,
}

/// The world the covered pages are read from.
struct Seeded {
    w: World,
    bob: TestClient,
    demo: String,
    bob_id: String,
    carol_id: String,
    dave_link: String,
}

/// Collapses runs of whitespace into single spaces.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn text_of(element: ElementRef<'_>) -> String {
    collapse(&element.text().collect::<String>())
}

/// Every element under `root` matching `css`, in document order.
fn all<'a>(root: ElementRef<'a>, css: &str) -> Vec<ElementRef<'a>> {
    let selector =
        Selector::parse(css).unwrap_or_else(|err| panic!("bad selector {css:?}: {err:?}"));
    root.select(&selector).collect()
}

/// The pills under `row` as (text, tone).
fn pills_in(row: ElementRef<'_>) -> Vec<(String, String)> {
    all(row, "[data-pill]")
        .into_iter()
        .map(|pill| {
            (
                text_of(pill),
                pill.value().attr("data-tone").unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn starts_with_any(text: &str, words: &[&str]) -> bool {
    words.iter().any(|word| text.starts_with(word))
}

/// Panics unless the status is `status`; the name says which page is meant.
fn shot(name: &str, page: Page, status: u16, layout: &'static str) -> Shot {
    assert_eq!(
        page.status, status,
        "{name} must answer {status}, got {}",
        page.status
    );
    Shot {
        name: name.to_string(),
        page,
        layout,
    }
}

/// True when the header of the page comes before its main element in document order.
fn header_precedes_main(body: &str) -> bool {
    let doc = Html::parse_document(body);
    let mut header_at = None;
    let mut main_at = None;
    for (index, node) in doc.root_element().descendants().enumerate() {
        if let Some(element) = node.value().as_element() {
            if element.name() == "main" && main_at.is_none() {
                main_at = Some(index);
            }
            if element.name() == "header" && element.attr("data-brand").is_some() {
                header_at.get_or_insert(index);
            }
        }
    }
    matches!((header_at, main_at), (Some(header), Some(main)) if header < main)
}

/// The seeded world: one server with three tools and bob granted, an allow and a deny rule,
/// an open invitation, a disabled user, a redirect entry, and activity of several kinds.
async fn seeded() -> Seeded {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_demo_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let refuser_options = UpstreamOptions {
        mode: Mode::RefusesCalls,
        ..UpstreamOptions::default()
    };
    let (_refuser_up, refuser) = w.upstream("refuser", refuser_options).await;
    w.grant(BOB, &[demo.as_str(), refuser.as_str()]).await;
    let bob_id = w.user_id(BOB).await;

    let page = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&demo), None).await;
    assert_eq!(page.status, 303, "the allow rule must be saved");
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(&demo),
        Some("delete_db"),
    )
    .await;
    assert_eq!(page.status, 303, "the deny rule must be saved");

    let dave_link = w.invite_link(DAVE, "user").await;
    w.user(CAROL).await;
    let carol_id = w.user_id(CAROL).await;
    let page = admin::user_action(&w.owner, &carol_id, "disable").await;
    assert_eq!(page.status, 303, "carol must be disabled");
    let page = admin::add_redirect(&w.owner, "https", "example.com", "/callback").await;
    assert_eq!(page.status, 303, "the redirect address must be saved");
    let redirect = admin::redirect_id(&w.owner, "example.com")
        .await
        .expect("the redirect address must be listed");
    let page = admin::redirect_action(&w.owner, &redirect, "disable").await;
    assert_eq!(page.status, 303, "the redirect address must be disabled");

    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let answered = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(answered.status, 200, "the allowed call must answer 200");
    let refused = mcp.call_tool("delete_db", json!({})).await;
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "the denied call must be refused"
    );
    let refuser_tokens = w.token(&bob, "refuser").await;
    let refuser_mcp = w.session_mcp("refuser", &refuser_tokens);
    assert_eq!(
        refuser_mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    // The upstream refuses every call, so this row is an error outcome.
    let _failed = refuser_mcp.call_tool("echo", json!({"text": "hi"})).await;

    Seeded {
        w,
        bob,
        demo,
        bob_id,
        carol_id,
        dave_link,
    }
}

/// The reset link mailed to `address`, waiting up to five seconds for the mail.
async fn reset_link(w: &World, address: &str) -> String {
    let prefix = format!("{}/reset/", w.base());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = w
            .mail
            .to(address)
            .iter()
            .rev()
            .find_map(|message| link_with_prefix(&message.text, &prefix));
        if let Some(link) = found {
            return link;
        }
        assert!(
            Instant::now() < deadline,
            "no mail with a reset link under {prefix} reached {address} within 5 seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The consent page for `app`, reached the way a signed-in browser reaches it.
async fn consent_page(browser: &TestClient, app: &OAuthApp, resource: &str) -> Page {
    let authorized = browser
        .authorize(app, resource, &client::pkce(), "state-52")
        .await;
    assert_eq!(
        authorized.status, 303,
        "authorize must answer 303 for a signed-in user"
    );
    let req = authorized
        .query("req")
        .expect("the consent redirect must carry req");
    browser.get(&format!("/oauth/consent?req={req}")).await
}

/// Every page the interface tests cover, each with the layout it must carry.
async fn covered(s: &Seeded) -> Vec<Shot> {
    let w = &s.w;
    let anonymous = w.client();
    let mut shots = vec![
        shot("/login", anonymous.get("/login").await, 200, CARD),
        shot("/forgot", anonymous.get("/forgot").await, 200, CARD),
        shot("/account (owner)", w.owner.get("/account").await, 200, WIDE),
        shot("/account (bob)", s.bob.get("/account").await, 200, WIDE),
    ];
    let panel_paths = [
        "/admin".to_string(),
        "/admin/servers".to_string(),
        format!("/admin/servers/{}", s.demo),
        "/admin/users".to_string(),
        format!("/admin/users/{}", s.bob_id),
        format!("/admin/users/{}", s.carol_id),
        "/admin/invitations".to_string(),
        "/admin/rules".to_string(),
        "/admin/redirects".to_string(),
        "/admin/mail".to_string(),
        "/admin/activity".to_string(),
    ];
    for path in panel_paths {
        let page = w.owner.get(&path).await;
        shots.push(shot(&path, page, 200, PANEL));
    }

    let local = consent_page(&s.bob, &w.app(), &w.resource("demo")).await;
    shots.push(shot("consent (local client)", local, 200, CARD));
    w.gw.cimd().put(APP_ID, APP_NAME, &[CLAUDE_CALLBACK]);
    let web = OAuthApp {
        client_id: APP_ID.into(),
        redirect_uri: CLAUDE_CALLBACK.into(),
    };
    let web_page = consent_page(&s.bob, &web, &w.resource("demo")).await;
    shots.push(shot("consent (web client)", web_page, 200, CARD));

    let invite = anonymous.get(&s.dave_link).await;
    shots.push(shot("invitation acceptance", invite, 200, CARD));

    let forgot = anonymous
        .submit("/forgot", "/forgot", &[("email", BOB)])
        .await;
    assert_eq!(forgot.status, 200, "a reset request must answer 200");
    let reset = reset_link(w, BOB).await;
    let reset_page = anonymous.get(&reset).await;
    shots.push(shot("choose a new password", reset_page, 200, CARD));

    let refused = s.bob.get("/admin").await;
    shots.push(shot("/admin for a plain user", refused, 403, CARD));
    let missing = anonymous.get("/invite/not-a-real-token").await;
    shots.push(shot("the link is not valid", missing, 404, CARD));
    shots
}

#[tokio::test(flavor = "multi_thread")]
async fn every_page_has_the_header_and_its_layout() {
    let s = seeded().await;
    for shot in covered(&s).await {
        let page = &shot.page;
        assert_eq!(
            page.count(HEADER),
            1,
            "{} must hold one header with data-brand directly in body",
            shot.name
        );
        let brand = page.text(HEADER).unwrap_or_default();
        assert!(
            brand.contains("Doorward"),
            "the header of {} must name Doorward, got {brand:?}",
            shot.name
        );
        assert!(
            page.count(&format!(r#"{HEADER} svg[aria-hidden="true"]"#)) >= 1,
            "the header of {} must hold an svg with aria-hidden true",
            shot.name
        );
        assert!(
            header_precedes_main(&page.body),
            "the header of {} must come before main",
            shot.name
        );
        assert_eq!(
            page.attr("body", "data-layout").as_deref(),
            Some(shot.layout),
            "{} must carry body data-layout {}",
            shot.name,
            shot.layout
        );
        if page.count(&format!("main {NAV}")) > 0 {
            assert_eq!(
                shot.layout, PANEL,
                "{} holds the panel navigation and must use the panel layout",
                shot.name
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limited_page_has_the_header_and_the_card_layout() {
    let mut w = World::start().await;
    w.tighten(|config| config.limits.general_burst = 2).await;
    let anonymous = w.client();
    let browser = [("accept", "text/html")];
    for _ in 0..2 {
        let answered = anonymous.get_with("/login", &browser).await;
        assert_ne!(
            answered.status, 429,
            "the first two page requests must be answered, not limited"
        );
    }
    let limited = anonymous.get_with("/login", &browser).await;
    assert_eq!(
        limited.status, 429,
        "a third browser request over the limit must answer 429"
    );
    assert!(
        limited
            .header("content-type")
            .unwrap_or_default()
            .starts_with("text/html"),
        "a limited browser request must answer HTML"
    );
    assert_eq!(
        limited.text("h1").as_deref(),
        Some("Too many requests"),
        "the limited page must say Too many requests in its h1"
    );
    assert_eq!(
        limited.count(HEADER),
        1,
        "the limited page must carry the header with data-brand"
    );
    assert!(
        limited
            .text(HEADER)
            .unwrap_or_default()
            .contains("Doorward"),
        "the header of the limited page must name Doorward"
    );
    assert_eq!(
        limited.attr("body", "data-layout").as_deref(),
        Some(CARD),
        "the limited page must carry body data-layout card"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_button_says_its_kind() {
    let s = seeded().await;
    for shot in covered(&s).await {
        let doc = Html::parse_document(&shot.page.body);
        for form in all(doc.root_element(), "form") {
            let primary = all(form, r#"button[data-kind="primary"]"#).len();
            assert!(
                primary <= 1,
                "a form on {} holds {primary} primary buttons, at most one is allowed",
                shot.name
            );
        }
        for button in all(doc.root_element(), "button") {
            let text = text_of(button);
            let kind = button.value().attr("data-kind").unwrap_or("");
            assert!(
                matches!(kind, "primary" | "secondary" | "danger"),
                "the button {text:?} on {} must carry data-kind primary, secondary or danger, got {kind:?}",
                shot.name
            );
            if starts_with_any(&text, &DANGER_WORDS) {
                assert_eq!(
                    kind, "danger",
                    "the button {text:?} on {} deletes, revokes, removes or disconnects and must be danger",
                    shot.name
                );
            }
            if starts_with_any(&text, &SECONDARY_WORDS) {
                assert_eq!(
                    kind, "secondary",
                    "the button {text:?} on {} must be secondary",
                    shot.name
                );
            }
        }
    }
}

/// Asserts the two-step delete of a page and returns the action of its delete form.
fn assert_two_step_delete(page: &Page, what: &str) -> String {
    assert_eq!(
        page.count("details[data-confirm]"),
        1,
        "{what} must hold exactly one details[data-confirm]"
    );
    assert_eq!(
        page.count("details[data-confirm][open]"),
        0,
        "{what} must keep its delete disclosure closed"
    );
    let summary = page
        .text("details[data-confirm] > summary")
        .unwrap_or_default();
    assert!(
        summary.contains("cannot be undone"),
        "the summary of the delete disclosure on {what} must say it cannot be undone, got {summary:?}"
    );
    assert_eq!(
        page.count(r#"details[data-confirm] form[action$="/delete"] input[name="csrf"]"#),
        1,
        "the delete form on {what} must carry the csrf field inside the disclosure"
    );
    assert_eq!(
        page.count(r#"form[action$="/delete"]"#),
        1,
        "{what} must hold no delete form outside the disclosure"
    );
    page.attr(r#"details[data-confirm] form[action$="/delete"]"#, "action")
        .unwrap_or_else(|| panic!("the delete form on {what} must carry an action"))
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_server_or_an_account_takes_two_steps() {
    let w = World::start().await;
    let (_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.user(BOB).await;
    let bob_id = w.user_id(BOB).await;
    let server_path = format!("/admin/servers/{demo}");
    let user_path = format!("/admin/users/{bob_id}");

    let mut actions = Vec::new();
    for path in [&server_path, &user_path] {
        let page = w.owner.get(path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 to the owner");
        let action = assert_two_step_delete(&page, path);
        let refused = w.owner.post(&action, &[]).await;
        assert_eq!(
            refused.status, 403,
            "posting {action} without the csrf value must be refused"
        );
        assert_eq!(
            refused.kind().as_deref(),
            Some("forbidden"),
            "posting {action} without the csrf value must show the forbidden page"
        );
        actions.push(action);
    }
    assert!(
        admin::server_id(&w.owner, "demo").await.is_some(),
        "a refused delete must keep the server"
    );
    assert!(
        admin::user_id(&w.owner, BOB).await.is_some(),
        "a refused delete must keep the account"
    );

    let deleted = w.owner.submit(&server_path, &actions[0], &[]).await;
    assert_eq!(
        deleted.status, 303,
        "posting the server delete with csrf must answer 303"
    );
    assert!(
        admin::server_id(&w.owner, "demo").await.is_none(),
        "the server delete with csrf must remove the server"
    );
    let deleted = w.owner.submit(&user_path, &actions[1], &[]).await;
    assert_eq!(
        deleted.status, 303,
        "posting the account delete with csrf must answer 303"
    );
    assert!(
        admin::user_id(&w.owner, BOB).await.is_none(),
        "the account delete with csrf must remove the account"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_status_is_a_word_with_a_marker() {
    let s = seeded().await;
    for shot in covered(&s).await {
        let doc = Html::parse_document(&shot.page.body);
        for pill in all(doc.root_element(), "[data-pill]") {
            let tone = pill.value().attr("data-tone").unwrap_or("");
            assert!(
                TONES.contains(&tone),
                "a pill on {} must carry data-tone ok, bad, warn or muted, got {tone:?}",
                shot.name
            );
            assert!(
                !text_of(pill).is_empty(),
                "a pill on {} must hold text",
                shot.name
            );
        }
    }

    let rules = s.w.owner.get("/admin/rules").await;
    let doc = Html::parse_document(&rules.body);
    let rows = all(doc.root_element(), "li[data-rule-id]");
    assert_eq!(
        rows.len(),
        2,
        "the rules page must list the two seeded rules"
    );
    for row in rows {
        let want = match row.value().attr("data-effect") {
            Some("allow") => ("Allow", "ok"),
            Some("deny") => ("Deny", "bad"),
            other => panic!("a rule must carry data-effect allow or deny, got {other:?}"),
        };
        assert_eq!(
            pills_in(row),
            vec![(want.0.to_string(), want.1.to_string())],
            "a rule row must hold one pill reading {} with tone {}",
            want.0,
            want.1
        );
    }

    let users = s.w.owner.get("/admin/users").await;
    let doc = Html::parse_document(&users.body);
    let rows = all(doc.root_element(), "li[data-user-id]");
    assert_eq!(
        rows.len(),
        3,
        "the users page must list owner, bob and carol"
    );
    for row in rows {
        let email = row.value().attr("data-email").unwrap_or("");
        let want = if email == CAROL {
            ("Disabled", "muted")
        } else {
            ("Active", "ok")
        };
        assert_eq!(
            pills_in(row),
            vec![(want.0.to_string(), want.1.to_string())],
            "the user row of {email} must hold one pill reading {} with tone {}",
            want.0,
            want.1
        );
    }

    let detail = s.w.owner.get(&format!("/admin/users/{}", s.bob_id)).await;
    let doc = Html::parse_document(&detail.body);
    let rows = all(doc.root_element(), "li[data-tool]");
    assert_eq!(
        rows.len(),
        6,
        "bob's page must list the three tools of each of his two servers"
    );
    for row in rows {
        let tool = row.value().attr("data-tool").unwrap_or("");
        let want = match row.value().attr("data-verdict") {
            Some("allow") => ("Allow", "ok"),
            Some("deny") => ("Deny", "bad"),
            other => panic!("a tool must carry data-verdict allow or deny, got {other:?}"),
        };
        assert_eq!(
            pills_in(row),
            vec![(want.0.to_string(), want.1.to_string())],
            "the tool {tool} must hold one pill reading {} with tone {}",
            want.0,
            want.1
        );
    }

    let redirects = s.w.owner.get("/admin/redirects").await;
    let doc = Html::parse_document(&redirects.body);
    let rows = all(doc.root_element(), "li[data-redirect-id]");
    assert!(
        !rows.is_empty(),
        "the redirects page must list allowed addresses"
    );
    for row in rows {
        let want = match row.value().attr("data-enabled") {
            Some("yes") => ("Enabled", "ok"),
            Some("no") => ("Disabled", "muted"),
            other => panic!("an address must carry data-enabled yes or no, got {other:?}"),
        };
        assert_eq!(
            pills_in(row),
            vec![(want.0.to_string(), want.1.to_string())],
            "an allowed address must hold one pill reading {} with tone {}",
            want.0,
            want.1
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lock_down_state_is_a_word_with_a_marker() {
    let w = World::start().await;
    let (_gated_up, gated) = w.upstream("gated", UpstreamOptions::default()).await;
    let (_open_up, open) = w.open_upstream("open", UpstreamOptions::default()).await;
    let (_idle_up, idle) = w.open_upstream("idle", UpstreamOptions::default()).await;
    let cases = [
        (gated, "ok", "ok"),
        (open, "open", "bad"),
        (idle, "unknown", "warn"),
    ];
    for (id, state, tone) in cases {
        if state != "unknown" {
            let page = admin::check_lockdown(&w.owner, &id).await;
            assert_eq!(
                page.status, 303,
                "the lock-down check of server {id} must answer 303"
            );
        }
        assert_eq!(
            admin::lockdown(&w.owner, &id).await.as_deref(),
            Some(state),
            "server {id} must hold the lock-down state {state} before its pill is read"
        );
        let page = w.owner.get(&format!("/admin/servers/{id}")).await;
        let doc = Html::parse_document(&page.body);
        let pills = pills_in(doc.root_element());
        assert_eq!(
            pills.len(),
            1,
            "the server page for lock-down state {state} must hold exactly one pill"
        );
        assert_eq!(
            pills[0].1, tone,
            "the lock-down pill for state {state} must carry tone {tone}"
        );
        assert!(
            !pills[0].0.is_empty(),
            "the lock-down pill for state {state} must hold text"
        );
    }
}

/// True when `text` reads like `20 Nov 2026 19:25:09 UTC`.
fn plain_time(text: &str) -> bool {
    let parts: Vec<&str> = text.split(' ').collect();
    if parts.len() != 5 {
        return false;
    }
    let (day, month, year, clock, zone) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    let month_ok = month.len() == 3
        && month.as_bytes()[0].is_ascii_uppercase()
        && month[1..].bytes().all(|byte| byte.is_ascii_lowercase());
    let clock_ok = clock.len() == 8
        && clock.bytes().enumerate().all(|(index, byte)| {
            if index == 2 || index == 5 {
                byte == b':'
            } else {
                byte.is_ascii_digit()
            }
        });
    (day.len() == 1 || day.len() == 2)
        && digits(day)
        && month_ok
        && year.len() == 4
        && digits(year)
        && clock_ok
        && zone == "UTC"
}

/// The label a row must read, for the kinds the brief names; None for the others.
fn expected_label(kind: &str, decision: &str, outcome: &str) -> Option<&'static str> {
    match kind {
        "tool_call" if decision == "deny" => Some("Tool call refused"),
        "tool_call" if outcome == "ok" => Some("Tool call"),
        "tool_call" => Some("Tool call failed"),
        "login" => Some("Sign-in"),
        "client_connected" => Some("Client connected"),
        "admin_change" => Some("Admin change"),
        "invitation" => Some("Invitation"),
        "mail_failed" => Some("Mail not sent"),
        "owner_created" => Some("Owner created"),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_activity_row_reads_in_plain_words() {
    let s = seeded().await;
    let w = &s.w;
    let refused = w.client().login(BOB, "not the password").await;
    assert_ne!(refused.status, 303, "a wrong password must not sign in");
    let signed_in = w.client().login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(signed_in.status, 303, "the owner must sign in");
    w.mail.fail_next(Fail::SmtpReject);
    let invited = admin::invite(&w.owner, EVE, "user").await;
    assert_eq!(
        invited.kind().as_deref(),
        Some("invitation-created"),
        "an invitation with a failing mail must still be created"
    );

    let page = w.owner.get("/admin/activity").await;
    assert_eq!(page.status, 200, "the activity page must answer 200");
    let doc = Html::parse_document(&page.body);
    let rows = all(doc.root_element(), "[data-kind]");
    assert!(!rows.is_empty(), "the activity page must list rows");
    let mut seen = BTreeSet::new();
    for row in rows {
        let kind = row.value().attr("data-kind").unwrap_or("").to_string();
        let time = row.value().attr("data-time").unwrap_or("").to_string();
        assert!(!time.is_empty(), "a {kind} row must carry data-time");
        let decision = row.value().attr("data-decision").unwrap_or("");
        let outcome = row.value().attr("data-outcome").unwrap_or("");
        seen.insert(kind.clone());

        let labels = all(row, "[data-label]");
        assert_eq!(labels.len(), 1, "a {kind} row must hold one [data-label]");
        let label = text_of(labels[0]);
        assert!(
            !label.is_empty(),
            "the label of a {kind} row must not be empty"
        );
        assert_ne!(
            label, kind,
            "the label of a {kind} row must not be the raw kind"
        );
        if let Some(want) = expected_label(&kind, decision, outcome) {
            assert_eq!(
                label, want,
                "a {kind} row with decision {decision:?} and outcome {outcome:?} must read {want}"
            );
        }

        let times = all(row, "time");
        assert_eq!(times.len(), 1, "a {kind} row must hold one time element");
        assert_eq!(
            times[0].value().attr("datetime"),
            Some(time.as_str()),
            "the time element of a {kind} row must carry datetime equal to data-time"
        );
        let shown = text_of(times[0]);
        assert!(
            plain_time(&shown),
            "the time of a {kind} row must read like 20 Nov 2026 19:25:09 UTC, got {shown:?}"
        );
    }
    for kind in [
        "tool_call",
        "login",
        "client_connected",
        "admin_change",
        "invitation",
        "mail_failed",
        "owner_created",
    ] {
        assert!(
            seen.contains(kind),
            "the activity page must hold a {kind} row to read, kinds were {seen:?}"
        );
    }
}

/// The provider disclosures of the mail page: exactly the three, each holding its own form.
fn assert_three_providers(page: &Page) {
    let mut shown = page.attrs("details[data-provider]", "data-provider");
    shown.sort();
    let mut want: Vec<String> = PROVIDERS.iter().map(|name| name.to_string()).collect();
    want.sort();
    assert_eq!(
        shown, want,
        "the mail page must hold one details[data-provider] per provider"
    );
    for provider in PROVIDERS {
        assert_eq!(
            page.count(&format!(
                r#"details[data-provider="{provider}"] input[name="provider"][value="{provider}"]"#
            )),
            1,
            "the {provider} disclosure must hold the {provider} form"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mail_page_shows_one_provider_at_a_time() {
    let w = World::start().await;
    let page = w.owner.get("/admin/mail").await;
    assert_eq!(
        page.status, 200,
        "the mail page must answer 200 to the owner"
    );
    assert_three_providers(&page);
    assert_eq!(
        page.attrs("details[open]", "data-provider"),
        vec!["smtp".to_string()],
        "only the provider in use may be open"
    );
    assert_eq!(
        page.count(r#"details[data-provider="smtp"] [data-in-use]"#),
        1,
        "the open smtp disclosure must be marked as in use"
    );
    assert_eq!(
        page.count("[data-in-use]"),
        1,
        "only the provider in use may be marked as in use"
    );
    assert!(
        !page.body.contains("No provider is in use."),
        "the mail page must not say no provider is in use while smtp is"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mail_page_with_no_provider_shows_all_three_closed() {
    let gw = TestGateway::start().await;
    let code = gw
        .setup_code()
        .expect("the gateway must print a setup code");
    let owner = gw.client();
    let page = owner.setup_owner(&code, OWNER_EMAIL, PASSWORD).await;
    assert_eq!(page.status, 303, "setup must make the owner");
    let mail = owner.get("/admin/mail").await;
    assert_eq!(
        mail.status, 200,
        "the mail page must answer 200 to the owner"
    );
    assert_three_providers(&mail);
    assert!(
        mail.attrs("details[open]", "data-provider").is_empty(),
        "with no provider in use every provider disclosure must be closed"
    );
    assert!(
        mail.body.contains("No provider is in use."),
        "the mail page must say No provider is in use."
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_provider_form_is_open_with_its_reason() {
    let w = World::start().await;
    let refused = admin::mail_resend(&w.owner, "gateway\u{7}@example.com", "key-example", "").await;
    assert_eq!(
        refused.status, 400,
        "a mail form with a control character must be refused with 400"
    );
    assert_eq!(
        refused.attrs(r#"details[data-provider="resend"][open]"#, "data-provider"),
        vec!["resend".to_string()],
        "the refused resend form must be open"
    );
    assert_eq!(
        refused
            .text(r#"details[data-provider="resend"] p.error"#)
            .as_deref(),
        Some("A field contains a control character."),
        "the refused resend form must hold its reason in p.error"
    );
}

/// The consent page must hold one primary Approve and a secondary Deny; a local client's
/// sentence sits in a warning.
fn assert_consent(page: &Page, what: &str, local: bool) {
    let doc = Html::parse_document(&page.body);
    let primary = all(doc.root_element(), r#"button[data-kind="primary"]"#);
    assert_eq!(
        primary.len(),
        1,
        "{what} must hold exactly one primary button"
    );
    assert_eq!(
        text_of(primary[0]),
        "Approve",
        "the primary button of {what} must read Approve"
    );
    let deny: Vec<ElementRef<'_>> = all(doc.root_element(), "button")
        .into_iter()
        .filter(|button| text_of(*button) == "Deny")
        .collect();
    assert_eq!(deny.len(), 1, "{what} must hold one Deny button");
    assert_eq!(
        deny[0].value().attr("data-kind"),
        Some("secondary"),
        "the Deny button of {what} must be secondary"
    );
    assert!(
        page.body
            .contains("Approve only if you started this sign-in yourself."),
        "{what} must keep the sentence about starting the sign-in yourself"
    );
    if local {
        assert_eq!(
            page.count(r#"[data-notice="warning"] p.local-app"#),
            1,
            "the local-client sentence on {what} must sit inside a warning notice"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_has_one_primary_button() {
    let w = World::start().await;
    let (_up, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let local = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_eq!(
        local.status, 200,
        "the consent page must load for a local client"
    );
    assert_consent(&local, "the consent page of a local client", true);

    w.gw.cimd().put(APP_ID, APP_NAME, &[CLAUDE_CALLBACK]);
    let web = OAuthApp {
        client_id: APP_ID.into(),
        redirect_uri: CLAUDE_CALLBACK.into(),
    };
    let page = consent_page(&bob, &web, &w.resource("demo")).await;
    assert_eq!(
        page.status, 200,
        "the consent page must load for a web client"
    );
    assert_consent(&page, "the consent page of a web client", false);
}

/// Removes the /* ... */ comments of a stylesheet.
fn strip_comments(css: &str) -> String {
    let mut out = String::new();
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start..].find("*/") {
            Some(end) => rest = &rest[start + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// One declaration, with the at-rules and the selector that enclose it.
struct Declaration {
    ancestors: Vec<String>,
    selector: String,
    name: String,
    value: String,
}

/// The declaration of `text` inside the innermost open block, when it has a name and a colon.
fn declaration_of(text: &str, stack: &[String]) -> Option<Declaration> {
    let (selector, ancestors) = stack.split_last()?;
    let (name, value) = text.split_once(':')?;
    let name: String = name.split_whitespace().collect();
    let value: String = value.split_whitespace().collect();
    if name.is_empty() {
        return None;
    }
    Some(Declaration {
        ancestors: ancestors.to_vec(),
        selector: selector.clone(),
        name,
        value,
    })
}

/// Every declaration of a stylesheet, nested blocks included.
fn declarations(css: &str) -> Vec<Declaration> {
    let css = strip_comments(css);
    let mut found = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut buffer = String::new();
    for ch in css.chars() {
        match ch {
            '{' => {
                stack.push(collapse(&buffer));
                buffer.clear();
            }
            ';' | '}' => {
                if let Some(declaration) = declaration_of(&buffer, &stack) {
                    found.push(declaration);
                }
                buffer.clear();
                if ch == '}' {
                    stack.pop();
                }
            }
            _ => buffer.push(ch),
        }
    }
    found
}

/// The custom properties the root block defines in the light or the dark theme.
fn theme_variables(decls: &[Declaration], dark: bool) -> BTreeMap<String, String> {
    decls
        .iter()
        .filter(|decl| {
            decl.selector == ":root"
                && decl.name.starts_with("--")
                && decl.ancestors.iter().any(|a| a == DARK_MEDIA) == dark
        })
        .map(|decl| (decl.name.clone(), decl.value.clone()))
        .collect()
}

/// The selectors of the rules that declare `min-height: 2.75rem`.
fn sized_selectors(decls: &[Declaration]) -> Vec<String> {
    decls
        .iter()
        .filter(|decl| decl.name == "min-height" && decl.value == "2.75rem")
        .flat_map(|decl| decl.selector.split(',').map(collapse).collect::<Vec<_>>())
        .collect()
}

/// The relative luminance of a six-digit hex colour, by the WCAG formula.
fn luminance(hex: &str) -> f64 {
    let channel = |index: usize| {
        let byte = u8::from_str_radix(&hex[1 + 2 * index..3 + 2 * index], 16).unwrap_or(0);
        let value = f64::from(byte) / 255.0;
        if value <= 0.03928 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2)
}

/// The WCAG contrast ratio of two hex colours.
fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (light, dark) = if la > lb { (la, lb) } else { (lb, la) };
    (light + 0.05) / (dark + 0.05)
}

fn is_hex6(value: &str) -> bool {
    value.len() == 7 && value.starts_with('#') && value[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// The stylesheet the gateway serves to the owner's panel.
async fn stylesheet(w: &World) -> String {
    let page = w.owner.get("/admin").await;
    let href = page
        .attr(r#"link[rel=stylesheet]"#, "href")
        .expect("the admin page must link a stylesheet");
    let path = href.strip_prefix(w.base()).unwrap_or(href.as_str());
    let asset = w.owner.get(path).await;
    assert_eq!(asset.status, 200, "the stylesheet must answer 200");
    asset.body
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stylesheet_meets_contrast_and_size() {
    let w = World::start().await;
    let decls = declarations(&stylesheet(&w).await);
    let themes = [
        ("light", theme_variables(&decls, false)),
        ("dark", theme_variables(&decls, true)),
    ];
    for (theme, vars) in &themes {
        for name in VARIABLES {
            let value = vars.get(name).unwrap_or_else(|| {
                panic!("the {theme} theme must define the custom property {name}")
            });
            assert!(
                is_hex6(value),
                "the {theme} value of {name} must be a six-digit hex colour, got {value:?}"
            );
        }
        for (text, background) in PAIRS {
            let ratio = contrast(&vars[text], &vars[background]);
            assert!(
                ratio >= 4.5,
                "{text} on {background} in the {theme} theme must reach 4.5 to 1, got {ratio:.2}"
            );
        }
    }

    let sized = sized_selectors(&decls);
    for selector in ["button", "summary", r#"nav[data-nav="panel"] a"#] {
        assert!(
            sized.iter().any(|shown| shown == selector),
            "the stylesheet must declare min-height 2.75rem for {selector}"
        );
    }
    assert!(
        sized.iter().any(|shown| {
            shown.starts_with("input") && (!shown.contains("checkbox") || shown.contains(":not("))
        }),
        "the stylesheet must declare min-height 2.75rem for input fields"
    );
    assert!(
        sized.iter().any(|shown| shown.starts_with("select")),
        "the stylesheet must declare min-height 2.75rem for select"
    );
    assert!(
        sized
            .iter()
            .all(|shown| !(shown.starts_with("input[") && shown.contains("checkbox"))),
        "the min-height of input fields must not reach checkboxes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_carry_no_inline_style() {
    let s = seeded().await;
    for shot in covered(&s).await {
        assert!(
            !shot.page.body.contains(" style=") && !shot.page.body.contains("<style"),
            "{} must carry no inline style",
            shot.name
        );
    }
}
