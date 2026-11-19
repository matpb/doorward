mod common;

use common::TestGateway;
use common::client::{Page, TestClient};
use common::world::{OWNER_EMAIL, PASSWORD, World};

const ELEVEN: &str = "abcdefghijk";
const TWELVE: &str = "abcdefghijkl";
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";

/// The setup code printed by the latest start of an instance without an owner.
fn expect_setup_code(gw: &TestGateway) -> String {
    gw.setup_code()
        .expect("a gateway with no owner must print a setup code")
}

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

#[tokio::test(flavor = "multi_thread")]
async fn setup_page_shows_while_no_owner() {
    let gw = TestGateway::start().await;
    let code = expect_setup_code(&gw);
    assert!(
        code.chars().count() >= 20,
        "the setup code must have at least 20 characters, got {code:?}"
    );
    let page = gw.client().get("/setup").await;
    assert_eq!(
        page.status, 200,
        "the setup page must be shown while there is no owner"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("setup"),
        "the setup page must be data-page setup"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_code_creates_nothing() {
    let gw = TestGateway::start().await;
    let code = expect_setup_code(&gw);
    let browser = gw.client();
    let page = browser
        .setup_owner("wrong-code", OWNER_EMAIL, PASSWORD)
        .await;
    assert_eq!(page.status, 403, "a wrong setup code must be refused");
    let page = browser.get("/setup").await;
    assert_eq!(
        page.status, 200,
        "a refused setup code must leave the setup page open"
    );
    let page = browser.setup_owner(&code, OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the right setup code must still create the owner"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_is_signed_in_and_reaches_the_panel() {
    let gw = TestGateway::start().await;
    let code = expect_setup_code(&gw);
    let owner = gw.client();
    let page = owner.setup_owner(&code, OWNER_EMAIL, PASSWORD).await;
    assert_eq!(page.status, 303, "the setup must create the owner");
    assert_eq!(
        page.location().as_deref(),
        Some("/admin"),
        "the setup must redirect to /admin"
    );
    let panel = owner.get("/admin").await;
    assert_eq!(
        panel.status, 200,
        "the new owner must be signed in and reach the panel"
    );
    assert_eq!(
        panel.kind().as_deref(),
        Some("admin"),
        "the panel must be data-page admin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_closes_after_the_owner_exists() {
    let mut w = World::start().await;
    let code = expect_setup_code(&w.gw);
    let browser = w.client();
    let page = browser.get("/setup").await;
    assert_eq!(
        page.status, 404,
        "the setup page must be gone once an owner exists"
    );
    let csrf = login_csrf(&browser).await;
    let page = browser
        .post(
            "/setup",
            &[
                ("csrf", csrf.as_str()),
                ("setup_code", code.as_str()),
                ("email", BOB),
                ("password", TWELVE),
            ],
        )
        .await;
    assert_eq!(
        page.status, 404,
        "a setup post with a valid csrf value must be gone once an owner exists"
    );
    w.gw.restart().await;
    assert!(
        w.gw.setup_code().is_none(),
        "no setup code may be printed once an owner exists"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn there_is_no_open_sign_up() {
    let w = World::start().await;
    let browser = w.client();
    for path in ["/signup", "/register"] {
        let page = browser.get(path).await;
        assert_eq!(
            page.status, 404,
            "{path} must not exist: sign-up is by invitation only"
        );
    }
    let page = browser.get("/invite/not-a-real-token").await;
    assert_eq!(
        page.status, 404,
        "an unknown invitation link must be refused"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("link-invalid"),
        "an unknown invitation link must show the link-invalid page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_setups_make_one_owner() {
    let gw = TestGateway::start().await;
    let code = expect_setup_code(&gw);
    let first = gw.client();
    let second = gw.client();
    let first_csrf = first
        .get("/setup")
        .await
        .csrf()
        .expect("the setup form must carry a csrf field");
    let second_csrf = second
        .get("/setup")
        .await
        .csrf()
        .expect("the setup form must carry a csrf field");
    let first_fields = [
        ("csrf", first_csrf.as_str()),
        ("setup_code", code.as_str()),
        ("email", BOB),
        ("password", PASSWORD),
    ];
    let second_fields = [
        ("csrf", second_csrf.as_str()),
        ("setup_code", code.as_str()),
        ("email", CAROL),
        ("password", PASSWORD),
    ];
    let (a, b) = tokio::join!(
        first.post("/setup", &first_fields),
        second.post("/setup", &second_fields),
    );
    let bob_won = a.status == 303;
    let carol_won = b.status == 303;
    assert!(
        bob_won ^ carol_won,
        "exactly one concurrent setup must create the owner, got {} and {}",
        a.status,
        b.status
    );
    let (winner, loser_email, loser) = if bob_won {
        (BOB, CAROL, &b)
    } else {
        (CAROL, BOB, &a)
    };
    assert_eq!(
        loser.status, 404,
        "the setup that lost must find that an owner already exists"
    );
    let signed_in = gw.client().login(winner, PASSWORD).await;
    assert_eq!(
        signed_in.status, 303,
        "the address of the setup that won must sign in"
    );
    let refused = gw.client().login(loser_email, PASSWORD).await;
    assert_eq!(
        refused.status, 401,
        "the address of the setup that lost must not sign in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_code_changes_at_restart() {
    let mut gw = TestGateway::start().await;
    let first = expect_setup_code(&gw);
    gw.restart().await;
    let second = expect_setup_code(&gw);
    assert_ne!(
        first, second,
        "a new setup code must be made at every start"
    );
    let browser = gw.client();
    let page = browser.setup_owner(&first, OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 403,
        "the setup code of the previous start must be refused"
    );
    let page = browser.setup_owner(&second, OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        page.status, 303,
        "the setup code of the latest start must create the owner"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn short_password_is_refused_at_setup() {
    let gw = TestGateway::start().await;
    let code = expect_setup_code(&gw);
    let browser = gw.client();
    let page = browser.setup_owner(&code, OWNER_EMAIL, ELEVEN).await;
    assert_eq!(
        page.status, 400,
        "an 11 character password must be refused at setup"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("setup"),
        "a refused password must re-render the setup page"
    );
    let page = browser.get("/setup").await;
    assert_eq!(
        page.status, 200,
        "a refused password must leave the setup page open"
    );
    let page = browser.setup_owner(&code, OWNER_EMAIL, TWELVE).await;
    assert_eq!(
        page.status, 303,
        "a 12 character password must create the owner"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_needs_csrf_and_origin() {
    let gw = TestGateway::start().await;
    let code = expect_setup_code(&gw);
    let browser = gw.client();
    let page = browser
        .post(
            "/setup",
            &[
                ("setup_code", code.as_str()),
                ("email", OWNER_EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_forbidden(&page, "a setup post without csrf must be refused");
    let csrf = browser
        .get("/setup")
        .await
        .csrf()
        .expect("the setup form must carry a csrf field");
    let fields = [
        ("csrf", csrf.as_str()),
        ("setup_code", code.as_str()),
        ("email", OWNER_EMAIL),
        ("password", PASSWORD),
    ];
    let page = browser
        .post_with("/setup", &fields, &[("Origin", "https://evil.example.com")])
        .await;
    assert_forbidden(&page, "a setup post from a foreign origin must be refused");
    let page = browser
        .post_with("/setup", &fields, &[("Origin", "null")])
        .await;
    assert_forbidden(&page, "a setup post with Origin null must be refused");
    let page = browser
        .post_with("/setup", &fields, &[("Origin", "")])
        .await;
    assert_forbidden(&page, "a setup post with no origin must be refused");
    let page = browser.get("/setup").await;
    assert_eq!(
        page.status, 200,
        "refused setup posts must leave the setup page open"
    );
}
