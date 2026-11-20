mod common;

use common::admin;
use common::client::{self, OAuthApp, Page, TestClient};
use common::upstream::UpstreamOptions;
use common::world::World;

const BOB: &str = "bob@example.com";
const STATE: &str = "state-1";
const NOTICE: &str = "Approve only if you started this sign-in yourself.";
const LOCAL_SENTENCE: &str =
    "The sign-in will be handed to whatever program is listening on this computer.";
const WEB_ID: &str = "https://web.example.com/app.json";
const WEB_URI: &str = "https://app.example.com/oauth/cb";

/// A signed-in user bob with the server `demo` assigned to him.
async fn bob_on_demo() -> (World, TestClient) {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    (w, bob)
}

/// Registers the web client's metadata and allows its redirect address.
async fn allow_web_client(w: &World) -> OAuthApp {
    w.gw.cimd().put(WEB_ID, "Example Web", &[WEB_URI]);
    let page = admin::add_redirect(&w.owner, "https", "app.example.com", "/oauth/").await;
    assert_eq!(
        page.status, 303,
        "adding the allowed address must answer 303"
    );
    OAuthApp {
        client_id: WEB_ID.to_owned(),
        redirect_uri: WEB_URI.to_owned(),
    }
}

/// The consent page that a signed-in browser reaches for `app` at `resource`.
async fn consent_page(browser: &TestClient, app: &OAuthApp, resource: &str) -> Page {
    let answer = browser
        .authorize(app, resource, &client::pkce(), STATE)
        .await;
    assert_eq!(
        answer.status, 303,
        "the authorize request for {resource} must answer 303"
    );
    let page = browser.follow(&answer).await;
    assert_eq!(
        page.kind().as_deref(),
        Some("consent"),
        "the answer for {resource} must be the consent page"
    );
    page
}

/// Asserts that the page has exactly one consent notice, and that it says the notice sentence.
fn assert_notice(page: &Page, step: &str) {
    assert_eq!(
        page.count("[data-consent-notice]"),
        1,
        "{step} must carry exactly one element with data-consent-notice"
    );
    assert_eq!(
        page.text("[data-consent-notice]").as_deref(),
        Some(NOTICE),
        "{step} must say the consent notice sentence"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_app_sees_the_notice() {
    let (w, bob) = bob_on_demo().await;
    let page = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_notice(&page, "the consent page of a local app");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_web_client_sees_the_notice() {
    let (w, bob) = bob_on_demo().await;
    let app = allow_web_client(&w).await;
    let page = consent_page(&bob, &app, &w.resource("demo")).await;
    assert_notice(&page, "the consent page of a web client");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_combined_endpoint_sees_the_notice() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let app = allow_web_client(&w).await;
    let page = consent_page(&bob, &app, &w.resource("mcp")).await;
    assert_notice(&page, "the consent page of the combined endpoint");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_local_app_is_told_it_runs_on_this_computer() {
    let (w, bob) = bob_on_demo().await;
    let app = allow_web_client(&w).await;
    let local = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    let web = consent_page(&bob, &app, &w.resource("demo")).await;
    let combined = consent_page(&bob, &app, &w.resource("mcp")).await;
    let local_text = local.text("body").unwrap_or_default();
    assert!(
        local_text.contains(LOCAL_SENTENCE),
        "the consent page of a local app must say: {LOCAL_SENTENCE}"
    );
    for (step, page) in [("a web client", &web), ("the combined endpoint", &combined)] {
        let text = page.text("body").unwrap_or_default();
        assert!(
            !text.contains(LOCAL_SENTENCE),
            "the consent page of {step} must not say: {LOCAL_SENTENCE}"
        );
    }
}
