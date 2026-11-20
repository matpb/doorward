mod common;

use std::time::Duration;

use common::client::{self, OAuthApp, Page, Pkce, TestClient};
use common::mail::link_with_prefix;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{APP_ID, APP_NAME, APP_REDIRECT, PASSWORD, World};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const DAVE: &str = "dave@example.com";
const STATE: &str = "state-1";
const REDIRECT_ORIGIN: &str = "http://127.0.0.1:53535";
const CONNECTED_SUBJECT: &str = "A new app was connected to your Doorward account";
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

type Query = Vec<(String, String)>;

/// A world where bob is assigned to demo and signed in.
async fn bob_on_demo() -> (World, TestClient, FakeUpstream) {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    (w, bob, upstream)
}

/// The parameters of a valid S256 authorize request for `resource`.
fn request_query(app: &OAuthApp, resource: &str, pkce: &Pkce) -> Query {
    [
        ("response_type", "code"),
        ("client_id", app.client_id.as_str()),
        ("redirect_uri", app.redirect_uri.as_str()),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("resource", resource),
        ("state", STATE),
        ("scope", "mcp"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

fn set_param(query: &mut Query, name: &str, value: &str) {
    drop_param(query, name);
    query.push((name.to_string(), value.to_string()));
}

fn drop_param(query: &mut Query, name: &str) {
    query.retain(|(key, _)| key.as_str() != name);
}

async fn send(browser: &TestClient, query: &Query) -> Page {
    let pairs: Vec<(&str, &str)> = query
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    browser.authorize_raw(&pairs).await
}

/// The request id carried by the 303 that an authorize request answers for a signed-in user.
fn consent_request(page: &Page) -> String {
    assert_eq!(
        page.status, 303,
        "authorize must answer 303 for a signed-in user"
    );
    let location = page.location().expect("the 303 must carry a Location");
    assert!(
        location.contains("/oauth/consent?req="),
        "authorize must send the browser to the consent page, got {location}"
    );
    page.query("req")
        .expect("the consent address must carry req")
}

fn consent_path(req: &str) -> String {
    format!("/oauth/consent?req={req}")
}

fn data(page: &Page, name: &str) -> Option<String> {
    page.attr(&format!("[{name}]"), name)
}

async fn csrf_of(browser: &TestClient) -> String {
    browser
        .get("/account")
        .await
        .csrf()
        .expect("the account page must carry a csrf token")
}

/// Posts a decision with a valid csrf value, without reading the consent page first.
async fn decide(browser: &TestClient, req: &str, decision: &str) -> Page {
    let csrf = csrf_of(browser).await;
    browser
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req),
                ("decision", decision),
            ],
        )
        .await
}

/// Asserts a 303 to the client's redirect address that carries state and iss.
fn assert_back_at_client(page: &Page, base: &str, step: &str) {
    assert_eq!(page.status, 303, "{step} must answer 303");
    let location = page.location().expect("the answer must carry a Location");
    assert!(
        location.starts_with(APP_REDIRECT),
        "{step} must go to the client's redirect address, got {location}"
    );
    assert_eq!(
        page.query("state").as_deref(),
        Some(STATE),
        "{step} must send the state back"
    );
    assert_eq!(
        page.query("iss").as_deref(),
        Some(base),
        "{step} must carry iss equal to the gateway address"
    );
}

/// Asserts an approval and returns its code.
fn approved_code(page: &Page, base: &str) -> String {
    assert_back_at_client(page, base, "an approval");
    let code = page.query("code").expect("an approval must carry a code");
    assert!(
        code.starts_with("dw_ac_"),
        "an authorization code must start with dw_ac_, got {code}"
    );
    code
}

fn assert_error_page(page: &Page, step: &str) {
    assert_eq!(page.status, 400, "{step} must answer 400");
    assert_eq!(
        page.kind().as_deref(),
        Some("error"),
        "{step} must render the error page"
    );
    assert!(page.location().is_none(), "{step} must not redirect");
}

fn assert_forbidden(page: &Page, step: &str) {
    assert_eq!(page.status, 403, "{step} must answer 403");
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "{step} must render the forbidden page"
    );
}

fn assert_no_code(page: &Page, step: &str) {
    assert!(page.query("code").is_none(), "{step} must not issue a code");
}

/// The source list of one directive of a Content-Security-Policy, when the policy has it.
fn csp_sources(policy: &str, name: &str) -> Option<Vec<String>> {
    policy.split(';').map(str::trim).find_map(|directive| {
        let mut parts = directive.split_whitespace();
        parts
            .next()?
            .eq_ignore_ascii_case(name)
            .then(|| parts.map(str::to_string).collect())
    })
}

/// The disconnect link of the mail that announces a new connection to bob.
async fn disconnect_link(w: &World) -> String {
    let mail = w
        .mail
        .wait_to(BOB, Duration::from_secs(5))
        .await
        .expect("bob must be mailed about the new connection");
    assert_eq!(
        mail.subject, CONNECTED_SUBJECT,
        "the new connection mail must have the announced subject"
    );
    link_with_prefix(&mail.text, &format!("{}/account/disconnect/", w.base()))
        .expect("the new connection mail must carry a disconnect link")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_consent_page_names_everything() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    consent_request(&page);
    let consent = bob
        .get(&page.location().expect("the 303 must carry a Location"))
        .await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load for an assigned user"
    );
    assert_eq!(
        consent.kind().as_deref(),
        Some("consent"),
        "the consent page must render the consent page"
    );
    assert_eq!(
        data(&consent, "data-redirect-host").as_deref(),
        Some("127.0.0.1:53535"),
        "the consent page must name the redirect host"
    );
    assert_eq!(
        data(&consent, "data-client-name").as_deref(),
        Some("Example Client"),
        "the consent page must name the client"
    );
    assert_eq!(
        data(&consent, "data-client-verified").as_deref(),
        Some("yes"),
        "a metadata document client must be shown as verified"
    );
    assert_eq!(
        data(&consent, "data-server").as_deref(),
        Some("demo"),
        "the consent page must name the server"
    );
    assert_eq!(
        data(&consent, "data-user").as_deref(),
        Some(BOB),
        "the consent page must name the signed-in user"
    );
    assert!(
        consent.location().is_none(),
        "the consent page must not redirect"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_is_asked_every_time() {
    let (w, bob, _upstream) = bob_on_demo().await;
    w.token(&bob, "demo").await;
    let again = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    assert_eq!(
        again.status, 303,
        "a second authorize must answer 303 even after an approval"
    );
    let location = again.location().expect("the 303 must carry a Location");
    assert!(
        location.contains("/oauth/consent?req="),
        "a second authorize must go to the consent page again, got {location}"
    );
    assert!(
        !location.starts_with(APP_REDIRECT),
        "a second authorize must not go to the client, got {location}"
    );
    assert_no_code(&again, "a second authorize");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_approval_issues_one_code() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let granted = bob.consent(&req, "approve").await;
    approved_code(&granted, w.base());
    let again = decide(&bob, &req, "approve").await;
    assert_error_page(&again, "a second approval of one request");
}

#[tokio::test(flavor = "multi_thread")]
async fn denying_returns_access_denied() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let denied = bob.consent(&req, "deny").await;
    assert_back_at_client(&denied, w.base(), "a denial");
    assert_eq!(
        denied.query("error").as_deref(),
        Some("access_denied"),
        "a denial must answer error=access_denied"
    );
    assert_no_code(&denied, "a denial");
    let retry = decide(&bob, &req, "approve").await;
    assert_error_page(&retry, "approving a request that was denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_needs_the_csrf_token() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let bare = bob
        .post(
            "/oauth/consent",
            &[("req", req.as_str()), ("decision", "approve")],
        )
        .await;
    assert_forbidden(&bare, "a consent post without csrf");
    assert_no_code(&bare, "a consent post without csrf");
    let granted = bob.consent(&req, "approve").await;
    approved_code(&granted, w.base());
}

#[tokio::test(flavor = "multi_thread")]
async fn another_sessions_token_is_refused() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let carol = w.user(CAROL).await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let carols_csrf = csrf_of(&carol).await;
    let reply = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", carols_csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_forbidden(&reply, "a consent post with another session's csrf token");
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_needs_the_gateway_origin() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let csrf = bob
        .get(&consent_path(&req))
        .await
        .csrf()
        .expect("the consent page must carry a csrf token");
    let fields = [
        ("csrf", csrf.as_str()),
        ("req", req.as_str()),
        ("decision", "approve"),
    ];
    let foreign = bob
        .post_with(
            "/oauth/consent",
            &fields,
            &[("Origin", "https://evil.example.com")],
        )
        .await;
    assert_forbidden(&foreign, "a consent post from a foreign origin");
    assert_no_code(&foreign, "a consent post from a foreign origin");
    let null = bob
        .post_with("/oauth/consent", &fields, &[("Origin", "null")])
        .await;
    assert_forbidden(&null, "a consent post with Origin null");
    assert_no_code(&null, "a consent post with Origin null");
    let none = bob
        .post_with("/oauth/consent", &fields, &[("Origin", "")])
        .await;
    assert_forbidden(&none, "a consent post with no origin");
    assert_no_code(&none, "a consent post with no origin");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_belongs_to_one_browser() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let carol = w.user(CAROL).await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let peek = carol.get(&consent_path(&req)).await;
    assert_error_page(&peek, "another browser's GET of the request");
    let poke = decide(&carol, &req, "approve").await;
    assert_error_page(&poke, "another browser's post of the decision");
    let anonymous = w.client().get(&consent_path(&req)).await;
    assert_eq!(
        anonymous.status, 303,
        "an anonymous GET of the consent page must be sent to sign in"
    );
    let location = anonymous
        .location()
        .expect("the sign-in redirect must carry a Location");
    assert!(
        location.contains(&format!("/login?req={req}")),
        "the sign-in redirect must keep the request id, got {location}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_expires_after_ten_minutes() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let live = bob.get(&consent_path(&req)).await;
    assert_eq!(
        live.status, 200,
        "the request must be live right after authorize"
    );
    w.gw.clock
        .advance(time::Duration::minutes(10) + time::Duration::seconds(1));
    let peek = bob.get(&consent_path(&req)).await;
    assert_error_page(&peek, "a consent GET ten minutes and one second later");
    let post = decide(&bob, &req, "approve").await;
    assert_error_page(&post, "an approval ten minutes and one second later");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unassigned_user_gets_no_code() {
    let (w, _bob, _upstream) = bob_on_demo().await;
    let dave = w.user(DAVE).await;
    let page = dave
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let consent = dave.get(&consent_path(&req)).await;
    assert_eq!(
        consent.status, 403,
        "an unassigned user must be refused the consent page"
    );
    assert_eq!(
        consent.kind().as_deref(),
        Some("no-access"),
        "an unassigned user must see the no-access page"
    );
    let post = decide(&dave, &req, "approve").await;
    assert_no_code(&post, "an approval by an unassigned user");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_server_looks_like_no_access() {
    let w = World::start().await;
    w.user(BOB).await;
    let anonymous = w.client();
    let page = anonymous
        .authorize(&w.app(), &w.resource("ghost"), &client::pkce(), STATE)
        .await;
    assert_eq!(
        page.status, 303,
        "an anonymous authorize must answer 303 to sign in"
    );
    let location = page.location().expect("the 303 must carry a Location");
    assert!(
        location.contains("/login?req="),
        "an anonymous authorize must go to the sign-in page, got {location}"
    );
    let req = page
        .query("req")
        .expect("the sign-in address must carry req");
    let signed_in = anonymous.login_for(&req, BOB, PASSWORD).await;
    assert_eq!(
        signed_in.status, 303,
        "signing in to a request must answer 303"
    );
    let next = signed_in.location().expect("the 303 must carry a Location");
    assert!(
        next.contains("/oauth/consent?req="),
        "signing in must go to the consent page, got {next}"
    );
    let consent = anonymous.get(&consent_path(&req)).await;
    assert_eq!(
        consent.status, 403,
        "a server that does not exist must be refused like an unassigned one"
    );
    assert_eq!(
        consent.kind().as_deref(),
        Some("no-access"),
        "a server that does not exist must show the no-access page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_consent_page_cannot_be_framed() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let consent = bob.get(&consent_path(&req)).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load for an assigned user"
    );
    assert_eq!(
        consent.header("x-frame-options").as_deref(),
        Some("DENY"),
        "the consent page must refuse to be framed"
    );
    let policy = consent
        .header("content-security-policy")
        .expect("the consent page must send a Content-Security-Policy");
    assert_eq!(
        csp_sources(&policy, "frame-ancestors"),
        Some(vec!["'none'".to_string()]),
        "the policy must forbid every frame ancestor"
    );
    let form_action =
        csp_sources(&policy, "form-action").expect("the policy must restrict form-action");
    assert!(
        form_action.iter().any(|source| source == "'self'"),
        "form-action must list 'self', got {form_action:?}"
    );
    assert!(
        form_action.iter().any(|source| source == REDIRECT_ORIGIN),
        "form-action must list the redirect origin, got {form_action:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_text_is_escaped() {
    let (w, bob, _upstream) = bob_on_demo().await;
    w.gw.cimd()
        .put(APP_ID, "<script>alert(1)</script>", &[APP_REDIRECT]);
    let page = bob
        .authorize(&w.app(), &w.resource("demo"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let consent = bob.get(&consent_path(&req)).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load for an assigned user"
    );
    assert!(
        !consent.body.contains("<script>alert"),
        "the client name must be escaped in the consent page"
    );
    assert_eq!(
        data(&consent, "data-client-name").as_deref(),
        Some("<script>alert(1)</script>"),
        "the client name attribute must read back as the raw name"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_connection_is_announced_by_mail() {
    let (w, bob, _upstream) = bob_on_demo().await;
    w.mail.clear();
    w.token(&bob, "demo").await;
    let link = disconnect_link(&w).await;
    assert!(
        link.starts_with(&format!("{}/account/disconnect/", w.base())),
        "the mail must link to the disconnect page, got {link}"
    );
    w.mail.clear();
    w.token(&bob, "demo").await;
    let second = w.mail.wait_to(BOB, Duration::from_millis(500)).await;
    assert!(
        second.is_none(),
        "a second connection of the same client must send no second mail"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mailed_link_disconnects_the_client() {
    let (w, bob, _upstream) = bob_on_demo().await;
    w.mail.clear();
    let tokens = w.token(&bob, "demo").await;
    let link = disconnect_link(&w).await;
    let anonymous = w.client();
    let view = anonymous.get(&link).await;
    assert_eq!(
        view.status, 200,
        "the mailed link must open the disconnect page"
    );
    assert_eq!(
        view.kind().as_deref(),
        Some("disconnect"),
        "the mailed link must render the disconnect page"
    );
    let still = w.session_mcp("demo", &tokens).initialize().await;
    assert_eq!(
        still.status, 200,
        "opening the mailed link must change nothing"
    );
    let done = anonymous.submit(&link, &link, &[]).await;
    assert_eq!(
        done.status, 200,
        "confirming the disconnect must answer 200"
    );
    assert_eq!(
        done.kind().as_deref(),
        Some("disconnected"),
        "confirming the disconnect must render the disconnected page"
    );
    let refused = w.session_mcp("demo", &tokens).initialize().await;
    assert_eq!(
        refused.status, 401,
        "the token of a disconnected client must be refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_combined_endpoint_is_named_on_the_page() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob
        .authorize(&w.app(), &w.resource("mcp"), &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    let consent = bob.get(&consent_path(&req)).await;
    assert_eq!(
        consent.status, 200,
        "the combined endpoint must show the consent page without an assignment"
    );
    assert_eq!(
        data(&consent, "data-server").as_deref(),
        Some("all servers"),
        "the combined endpoint must be named as all servers"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn prompt_none_never_yields_a_code() {
    let (w, bob, _upstream) = bob_on_demo().await;
    w.token(&bob, "demo").await;
    let pkce = client::pkce();
    let mut query = request_query(&w.app(), &w.resource("demo"), &pkce);
    set_param(&mut query, "prompt", "none");
    let page = send(&bob, &query).await;
    assert_back_at_client(&page, w.base(), "prompt=none");
    assert_eq!(
        page.query("error").as_deref(),
        Some("interaction_required"),
        "prompt=none must be refused with interaction_required"
    );
    assert_no_code(&page, "prompt=none");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_then_consent_round_trip() {
    let (w, _bob, _upstream) = bob_on_demo().await;
    let app = w.app();
    let resource = w.resource("demo");
    let pkce = client::pkce();
    let anonymous = w.client();
    let to_login = anonymous.authorize(&app, &resource, &pkce, STATE).await;
    assert_eq!(
        to_login.status, 303,
        "an anonymous authorize must answer 303"
    );
    let location = to_login.location().expect("the 303 must carry a Location");
    assert!(
        location.contains("/login?req="),
        "an anonymous authorize must go to the sign-in page, got {location}"
    );
    let req = to_login
        .query("req")
        .expect("the sign-in address must carry req");
    let to_consent = anonymous.login_for(&req, BOB, PASSWORD).await;
    assert_eq!(
        to_consent.status, 303,
        "signing in to a request must answer 303"
    );
    let next = to_consent
        .location()
        .expect("the 303 must carry a Location");
    assert!(
        next.contains("/oauth/consent?req="),
        "signing in must go to the consent page, got {next}"
    );
    let granted = anonymous.consent(&req, "approve").await;
    let code = approved_code(&granted, w.base());
    let issued = anonymous
        .token_code(&app, &code, &pkce.verifier, Some(resource.as_str()))
        .await;
    assert!(
        client::tokens(&issued).is_some(),
        "the code from the round trip must exchange for tokens, got status {}",
        issued.status
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_that_must_not_redirect() {
    let w = World::start().await;
    let browser = w.client();
    let app = w.app();
    let resource = w.resource("demo");
    let pkce = client::pkce();

    let mut unknown = request_query(&app, &resource, &pkce);
    set_param(&mut unknown, "client_id", "dcr_nobody");
    assert_error_page(&send(&browser, &unknown).await, "an unknown client_id");

    let mut repeated = request_query(&app, &resource, &pkce);
    repeated.push(("state".into(), "state-2".into()));
    assert_error_page(
        &send(&browser, &repeated).await,
        "a repeated state parameter",
    );

    let mut request_uri = request_query(&app, &resource, &pkce);
    request_uri.push(("request_uri".into(), "urn:example:request".into()));
    assert_error_page(
        &send(&browser, &request_uri).await,
        "a request_uri parameter",
    );

    let mut request = request_query(&app, &resource, &pkce);
    request.push(("request".into(), "not-a-request-object".into()));
    assert_error_page(&send(&browser, &request).await, "a request parameter");
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_that_go_back_to_the_client() {
    let w = World::start().await;
    let browser = w.client();
    let pkce = client::pkce();
    let base_query = request_query(&w.app(), &w.resource("demo"), &pkce);

    let mut response_type = base_query.clone();
    set_param(&mut response_type, "response_type", "token");
    let mut no_challenge = base_query.clone();
    drop_param(&mut no_challenge, "code_challenge");
    let mut plain = base_query.clone();
    set_param(&mut plain, "code_challenge_method", "plain");
    let mut no_resource = base_query.clone();
    drop_param(&mut no_resource, "resource");
    let mut foreign = base_query.clone();
    set_param(&mut foreign, "resource", "https://evil.example.com/demo");
    let mut bad_slug = base_query;
    set_param(&mut bad_slug, "resource", &w.resource("Bad_Slug"));

    let cases = [
        ("response_type=token", response_type, "invalid_request"),
        ("no code_challenge", no_challenge, "invalid_request"),
        ("code_challenge_method=plain", plain, "invalid_request"),
        ("no resource", no_resource, "invalid_target"),
        ("a resource on another origin", foreign, "invalid_target"),
        ("a resource at /Bad_Slug", bad_slug, "invalid_target"),
    ];
    for (step, query, error) in cases {
        let page = send(&browser, &query).await;
        assert_back_at_client(&page, w.base(), step);
        assert_eq!(
            page.query("error").as_deref(),
            Some(error),
            "{step} must be refused with error={error}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_challenge_never_reaches_consent() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let mut plain = request_query(&w.app(), &w.resource("demo"), &client::pkce());
    set_param(&mut plain, "code_challenge_method", "plain");
    let signed_in = send(&bob, &plain).await;
    let anonymous = send(&w.client(), &plain).await;
    assert_eq!(
        signed_in.query("error").as_deref(),
        Some("invalid_request"),
        "a plain challenge must be refused with invalid_request"
    );
    for (step, page) in [
        ("a signed-in browser", &signed_in),
        ("an anonymous browser", &anonymous),
    ] {
        let location = page.location().unwrap_or_default();
        assert!(
            !location.contains("/oauth/consent"),
            "{step} must not be sent to consent for a plain challenge, got {location}"
        );
        assert!(
            !page.body.contains("/oauth/consent"),
            "{step} must not be shown the consent address for a plain challenge"
        );
    }
}

/// The consent page that `browser` reaches by authorizing `app` at `resource`.
async fn consent_of(browser: &TestClient, app: &OAuthApp, resource: &str) -> Page {
    let page = browser
        .authorize(app, resource, &client::pkce(), STATE)
        .await;
    let req = consent_request(&page);
    browser.get(&consent_path(&req)).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registered_client_is_shown_as_a_claim() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let name = "Claude Code published by claude.ai";
    let registered = w.client().register(name, &[APP_REDIRECT]).await;
    assert_eq!(
        registered.status, 201,
        "registering the client must answer 201"
    );
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_string))
        .expect("the registration answer must carry a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: APP_REDIRECT.into(),
    };
    let consent = consent_of(&bob, &app, &w.resource("demo")).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load for a registered client"
    );
    assert_eq!(
        consent.count(r#"p[data-client="registered"]"#),
        1,
        "a registered client must have exactly one registered line"
    );
    assert_eq!(
        consent.text(r#"p[data-client="registered"]"#).as_deref(),
        Some(
            "An app that calls itself Claude Code published by claude.ai. Doorward cannot check this name."
        ),
        "the registered line must say the name is a claim the gateway cannot check"
    );
    assert_eq!(
        consent
            .text(r#"p[data-client="registered"] q.client-name"#)
            .as_deref(),
        Some(name),
        "the registered name must sit in its own q element"
    );
    assert!(
        !consent.body.contains("(unverified)"),
        "the consent page must not say (unverified)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_client_with_a_web_redirect_names_its_publisher() {
    let (w, bob, _upstream) = bob_on_demo().await;
    w.gw.cimd().put(APP_ID, APP_NAME, &[CLAUDE_CALLBACK]);
    let app = OAuthApp {
        client_id: APP_ID.into(),
        redirect_uri: CLAUDE_CALLBACK.into(),
    };
    let consent = consent_of(&bob, &app, &w.resource("demo")).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load for a document client"
    );
    assert_eq!(
        consent.count(r#"p[data-client="document"]"#),
        1,
        "a document client with a web redirect must have exactly one document line"
    );
    assert_eq!(
        consent.text(r#"p[data-client="document"]"#).as_deref(),
        Some("Example Client, published by client.example.com."),
        "the document line must name the client and the host that published it"
    );
    assert_eq!(
        consent
            .text(r#"p[data-client="document"] q.client-name"#)
            .as_deref(),
        Some(APP_NAME),
        "the document name must sit in its own q element"
    );
    assert_eq!(
        consent
            .text(r#"p[data-client="document"] span.client-host"#)
            .as_deref(),
        Some("client.example.com"),
        "the publisher host must sit in its own span element"
    );
    assert_eq!(
        consent.count(r#"p[data-client="document-loopback"]"#),
        0,
        "a web redirect must not be shown as a loopback line"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_client_with_a_loopback_redirect_is_shown_as_a_claim() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let consent = consent_of(&bob, &w.app(), &w.resource("demo")).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load for a document client"
    );
    assert_eq!(
        consent.count(r#"p[data-client="document-loopback"]"#),
        1,
        "a loopback document client must have exactly one loopback line"
    );
    assert_eq!(
        consent
            .text(r#"p[data-client="document-loopback"]"#)
            .as_deref(),
        Some(
            "Says it is Example Client from client.example.com. Any program on this computer can use that description."
        ),
        "the loopback line must present the name as a claim from the host"
    );
    assert_eq!(
        consent
            .text(r#"p[data-client="document-loopback"] q.client-name"#)
            .as_deref(),
        Some(APP_NAME),
        "the loopback name must sit in its own q element"
    );
    assert_eq!(
        consent
            .text(r#"p[data-client="document-loopback"] span.client-host"#)
            .as_deref(),
        Some("client.example.com"),
        "the host must sit in its own span element"
    );
    assert_eq!(
        consent.text("p.local-app").as_deref(),
        Some("The sign-in will be handed to whatever program is listening on this computer."),
        "a loopback redirect must carry the local-app sentence"
    );
    assert!(
        !consent.body.contains("This app runs on your computer."),
        "the consent page must not use the old local-app sentence"
    );
}
