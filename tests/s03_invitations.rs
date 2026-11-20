mod common;

use std::time::Duration;

use common::admin;
use common::client::{Page, TestClient};
use common::mail::{Captured, link_with_prefix};
use common::world::{OWNER_EMAIL, PASSWORD, World};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const DAVE: &str = "dave@example.com";
const ERIN: &str = "erin@example.com";
const ELEVEN: &str = "abcdefghijk";
const TWELVE: &str = "abcdefghijkl";
const SUBJECT: &str = "You are invited to Doorward";

/// Reads the csrf value of the login page, which exists on every instance.
async fn login_csrf(browser: &TestClient) -> String {
    browser
        .get("/login")
        .await
        .csrf()
        .expect("GET /login must carry a csrf field")
}

fn assert_forbidden(page: &Page, what: &str) {
    assert_eq!(page.status, 403, "{what}: the answer must be 403");
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "{what}: the page must be the forbidden page"
    );
}

/// The invitation mail that reached `address`, waiting up to 5 seconds for it.
async fn invitation_mail(w: &World, address: &str) -> Captured {
    w.mail
        .wait_to(address, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| panic!("no mail to {address} arrived within 5 seconds"))
}

/// The invitation link in the mail, which must start with the gateway's own address.
fn invitation_link(w: &World, message: &Captured) -> String {
    let prefix = format!("{}/invite/", w.base());
    link_with_prefix(&message.text, &prefix).unwrap_or_else(|| {
        panic!(
            "the invitation mail has no link starting with {prefix}, text: {:?}",
            message.text
        )
    })
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

#[tokio::test(flavor = "multi_thread")]
async fn invited_user_sets_a_password_and_signs_in() {
    let w = World::start().await;
    let page = admin::invite(&w.owner, BOB, "user").await;
    assert_eq!(page.status, 303, "the owner's invitation must be accepted");
    let message = invitation_mail(&w, BOB).await;
    assert_eq!(
        message.subject, SUBJECT,
        "the invitation mail must have the invitation subject"
    );
    let link = invitation_link(&w, &message);
    let browser = w.client();
    let page = browser.get(&link).await;
    assert_eq!(
        page.status, 200,
        "the invitation link must open the set-password page"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("invite"),
        "the invitation link must show data-page invite"
    );
    let page = browser.accept_invite(&link, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "a valid password must accept the invitation"
    );
    assert_eq!(
        page.location().as_deref(),
        Some("/account"),
        "an accepted invitation must redirect to /account"
    );
    let page = browser.get("/account").await;
    assert_eq!(
        page.status, 200,
        "the invited user must be signed in after accepting"
    );
    let page = browser.logout().await;
    assert_eq!(page.status, 303, "logout must answer 303");
    let page = browser.login(BOB, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the password chosen at acceptance must sign in after logout"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_works_once() {
    let w = World::start().await;
    let link = w.invite_link(BOB, "user").await;
    let browser = w.client();
    let page = browser.accept_invite(&link, PASSWORD).await;
    assert_eq!(page.status, 303, "the first use must accept the invitation");
    let page = w.client().get(&link).await;
    assert_eq!(
        page.status, 404,
        "a used invitation link must be refused on GET"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("link-invalid"),
        "a used invitation link must show data-page link-invalid"
    );
    let second = w.client();
    let csrf = login_csrf(&second).await;
    let page = second
        .post(&link, &[("csrf", csrf.as_str()), ("password", PASSWORD)])
        .await;
    assert_eq!(
        page.status, 404,
        "a used invitation link must be refused on POST from another browser"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_expires_after_seven_days() {
    let w = World::start().await;
    let old = w.invite_link(BOB, "user").await;
    w.gw.clock
        .advance(time::Duration::minutes(1) + time::Duration::seconds(1));
    let newer = w.invite_link(CAROL, "user").await;
    w.gw.clock
        .advance(time::Duration::days(7) - time::Duration::minutes(1));
    let browser = w.client();
    let page = browser.get(&old).await;
    assert_eq!(
        page.status, 404,
        "an invitation older than seven days must be refused on GET"
    );
    let csrf = login_csrf(&browser).await;
    let page = browser
        .post(&old, &[("csrf", csrf.as_str()), ("password", PASSWORD)])
        .await;
    assert_eq!(
        page.status, 404,
        "an invitation older than seven days must be refused on POST"
    );
    let page = browser.get(&newer).await;
    assert_eq!(
        page.status, 200,
        "an invitation seven days minus one minute old must still open"
    );
    let page = browser.accept_invite(&newer, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "an invitation seven days minus one minute old must still be accepted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_invitation_is_refused() {
    let w = World::start().await;
    let link = w.invite_link(BOB, "user").await;
    let id = admin::invitation_id(&w.owner, BOB)
        .await
        .expect("the open invitation must be listed before it is revoked");
    let page = admin::revoke_invitation(&w.owner, &id).await;
    assert_eq!(page.status, 303, "revoking an invitation must answer 303");
    let page = w.client().get(&link).await;
    assert_eq!(
        page.status, 404,
        "a revoked invitation link must be refused"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("link-invalid"),
        "a revoked invitation link must show data-page link-invalid"
    );
    assert!(
        admin::invitation_id(&w.owner, BOB).await.is_none(),
        "the invitations page must no longer list the revoked address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scanner_get_does_not_use_up_the_link() {
    let w = World::start().await;
    let link = w.invite_link(BOB, "user").await;
    let scanner = w.client();
    for attempt in 1..=3 {
        let page = scanner.get(&link).await;
        assert_eq!(
            page.status, 200,
            "GET number {attempt} of the invitation link must open the page"
        );
    }
    let browser = w.client();
    let page = browser.accept_invite(&link, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "a link that was only fetched by scanners must still accept a password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_link_ignores_the_host_header() {
    let w = World::start().await;
    let csrf = w
        .owner
        .get("/admin/invitations")
        .await
        .csrf()
        .expect("the invitations page must carry a csrf field");
    let page = w
        .owner
        .post_with(
            "/admin/invitations",
            &[("csrf", csrf.as_str()), ("email", BOB), ("role", "user")],
            &[
                ("Host", "evil.example.com"),
                ("X-Forwarded-Host", "evil.example.com"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 303,
        "an invitation with a forged Host must still be stored and mailed"
    );
    let message = invitation_mail(&w, BOB).await;
    invitation_link(&w, &message);
    assert!(
        !message.text.contains("evil.example.com"),
        "the invitation text must not use the forged host"
    );
    assert!(
        !message.html.contains("evil.example.com"),
        "the invitation html must not use the forged host"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_token_is_not_stored() {
    let w = World::start().await;
    let link = w.invite_link(BOB, "user").await;
    let token = token_of(&link);
    assert!(
        !stored_contains(&w, token),
        "the invitation token must not appear in the database"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_admins_invite() {
    let w = World::start().await;
    let plain = w.user(BOB).await;
    let csrf = plain
        .get("/account")
        .await
        .csrf()
        .expect("the account page must carry a csrf field");
    w.mail.clear();
    let page = plain
        .post(
            "/admin/invitations",
            &[("csrf", csrf.as_str()), ("email", CAROL), ("role", "user")],
        )
        .await;
    assert_forbidden(&page, "a plain user must not invite");
    let anonymous = w.client();
    let csrf = login_csrf(&anonymous).await;
    let page = anonymous
        .post(
            "/admin/invitations",
            &[("csrf", csrf.as_str()), ("email", CAROL), ("role", "user")],
        )
        .await;
    assert_eq!(page.status, 303, "an anonymous invitation must answer 303");
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "an anonymous invitation must redirect to /login"
    );
    assert!(
        w.mail.messages().is_empty(),
        "no invitation mail may be sent by a refused invitation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invited_admin_reaches_the_panel_and_user_does_not() {
    let w = World::start().await;
    let admin = w.admin(CAROL).await;
    let page = admin.get("/admin").await;
    assert_eq!(page.status, 200, "an invited admin must reach the panel");
    assert_eq!(
        page.kind().as_deref(),
        Some("admin"),
        "the panel must be data-page admin"
    );
    let user = w.user(BOB).await;
    let page = user.get("/admin").await;
    assert_forbidden(&page, "an invited user must not reach the panel");
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_address_cannot_be_invited() {
    let w = World::start().await;
    w.mail.clear();
    let page = admin::invite(&w.owner, OWNER_EMAIL, "user").await;
    assert_eq!(
        page.status, 400,
        "inviting an address that already has an account must be refused"
    );
    assert!(
        page.error().is_some_and(|text| !text.is_empty()),
        "the refusal must show an error"
    );
    assert!(
        w.mail.messages().is_empty(),
        "no invitation mail may be sent to an existing address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn short_password_keeps_the_link_usable() {
    let w = World::start().await;
    let link = w.invite_link(BOB, "user").await;
    let browser = w.client();
    let page = browser.accept_invite(&link, ELEVEN).await;
    assert_eq!(page.status, 400, "an 11 character password must be refused");
    assert_eq!(
        page.kind().as_deref(),
        Some("invite"),
        "a refused password must re-render the invite page"
    );
    let page = browser.accept_invite(&link, TWELVE).await;
    assert_eq!(
        page.status, 303,
        "the same link must accept a 12 character password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mail_has_text_and_html_parts() {
    let w = World::start().await;
    let page = admin::invite(&w.owner, BOB, "user").await;
    assert_eq!(page.status, 303, "the owner's invitation must be accepted");
    let message = invitation_mail(&w, BOB).await;
    let link = invitation_link(&w, &message);
    assert!(
        message.text.contains(&link),
        "the text part must contain the invitation link"
    );
    assert!(
        message.html.contains(&link),
        "the html part must contain the invitation link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_cannot_invite_an_admin() {
    let w = World::start().await;
    let alice = w.admin(ALICE).await;
    w.mail.clear();
    let page = admin::invite(&alice, CAROL, "admin").await;
    assert_forbidden(&page, "an admin must not invite with the role admin");
    assert!(
        w.mail.messages().is_empty(),
        "a refused admin invitation must send no mail"
    );
    let page = admin::invite(&alice, CAROL, "user").await;
    assert_eq!(
        page.status, 303,
        "an admin must be able to invite with the role user"
    );
    invitation_mail(&w, CAROL).await;
    let page = admin::invite(&w.owner, DAVE, "admin").await;
    assert_eq!(
        page.status, 303,
        "the owner must be able to invite with the role admin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_admin_takes_their_pending_invitations_along() {
    for change in ["disable", "role changed to user", "deleted"] {
        removed_admin_takes_invitations_along(change).await;
    }
}

/// Carol, an admin, invites alice and dave; alice accepts and dave's link stays unused. The owner
/// then makes the change named by `change`: dave's link must stop working, alice must still sign in.
async fn removed_admin_takes_invitations_along(change: &str) {
    let w = World::start().await;
    let carol = w.admin(CAROL).await;
    let page = admin::invite(&carol, ALICE, "user").await;
    assert_eq!(page.status, 303, "{change}: carol must invite alice");
    let alice_link = invitation_link(&w, &invitation_mail(&w, ALICE).await);
    let page = admin::invite(&carol, DAVE, "user").await;
    assert_eq!(page.status, 303, "{change}: carol must invite dave");
    let dave_link = invitation_link(&w, &invitation_mail(&w, DAVE).await);
    let page = admin::invite(&w.owner, ERIN, "user").await;
    assert_eq!(page.status, 303, "{change}: the owner must invite erin");
    let erin_link = invitation_link(&w, &invitation_mail(&w, ERIN).await);
    let page = w.client().accept_invite(&alice_link, PASSWORD).await;
    assert_eq!(page.status, 303, "{change}: alice's link must accept her");

    let carol_id = w.user_id(CAROL).await;
    let page = match change {
        "disable" => admin::user_action(&w.owner, &carol_id, "disable").await,
        "role changed to user" => admin::set_role(&w.owner, &carol_id, "user").await,
        "deleted" => admin::user_action(&w.owner, &carol_id, "delete").await,
        other => panic!("no such change in this test: {other}"),
    };
    assert_eq!(
        page.status, 303,
        "{change}: the owner's change must answer 303"
    );

    let stranger = w.client();
    let page = stranger.get(&dave_link).await;
    assert_eq!(
        page.status, 404,
        "{change}: dave's unused link must be refused on GET"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("link-invalid"),
        "{change}: dave's unused link must show link-invalid"
    );
    let second = w.client();
    let csrf = login_csrf(&second).await;
    let page = second
        .post(
            &dave_link,
            &[("csrf", csrf.as_str()), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(
        page.status, 404,
        "{change}: dave's unused link must not accept a password"
    );
    assert_eq!(
        admin::invitation_id(&w.owner, DAVE).await,
        None,
        "{change}: dave's invitation must be gone from the invitations page"
    );
    let page = w.client().login(ALICE, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "{change}: alice, who accepted, must still sign in"
    );
    let page = w.client().get(&erin_link).await;
    assert_eq!(
        page.status, 200,
        "{change}: the owner's invitation to erin must still open, the change must not take it along"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invitations_page_says_who_invited() {
    let w = World::start().await;
    let page = admin::invite(&w.owner, BOB, "user").await;
    assert_eq!(page.status, 303, "the owner must invite bob");
    let carol = w.admin(CAROL).await;
    let page = admin::invite(&carol, DAVE, "user").await;
    assert_eq!(page.status, 303, "carol, an admin, must invite dave");

    let page = w.owner.get("/admin/invitations").await;
    assert_eq!(
        page.text(&format!(r#"[data-email="{BOB}"] [data-invited-by]"#))
            .as_deref(),
        Some(format!("invited by {OWNER_EMAIL}").as_str()),
        "bob's invitation must say the owner made it"
    );
    assert_eq!(
        page.text(&format!(r#"[data-email="{DAVE}"] [data-invited-by]"#))
            .as_deref(),
        Some(format!("invited by {CAROL}").as_str()),
        "dave's invitation must say carol made it"
    );

    let conn = rusqlite::Connection::open(w.gw.db_path()).expect("open the database");
    conn.execute(
        "UPDATE invitations SET invited_by = NULL WHERE email = ?1",
        [BOB],
    )
    .expect("clear the inviter of bob's invitation");
    let page = w.owner.get("/admin/invitations").await;
    assert_eq!(
        page.text(&format!(r#"[data-email="{BOB}"] [data-invited-by]"#))
            .as_deref(),
        Some("invited by a removed account"),
        "an invitation with no inviter must say so"
    );
}
