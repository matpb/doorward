mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::admin;
use common::client::{OAuthApp, Page, TestClient, pkce};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{APP_ID, APP_NAME, APP_REDIRECT, PASSWORD, World};
use doorward::config::Range;
use doorward::{CimdError, ClientMetadata};
use serde_json::{Value, json};

const C3: [&str; 3] = [
    "cursor://anysphere.cursor-mcp/oauth/callback",
    "https://www.cursor.com/agents/mcp/oauth/callback",
    "http://localhost:8787/callback",
];
const LOCAL_8787: &str = "http://localhost:8787/callback";
/// Eleven addresses at 55 attempts each make 605, more than the 600 of the global total.
const PER_ADDRESS: u64 = 55;
const ADDRESSES: u8 = 11;

fn oauth_app(client_id: &str, redirect_uri: &str) -> OAuthApp {
    OAuthApp {
        client_id: client_id.into(),
        redirect_uri: redirect_uri.into(),
    }
}

/// The path of the Location header, whether it is relative or absolute.
fn location_path(page: &Page) -> Option<String> {
    let base = url::Url::parse("http://localhost/").expect("static url");
    let location = page.location()?;
    base.join(&location).ok().map(|url| url.path().to_string())
}

fn assert_error_page(page: &Page, case: &str) {
    assert!(
        page.status == 400 && page.kind().as_deref() == Some("error") && page.location().is_none(),
        "{case} must give an error page (400, no Location), got {} (kind {:?}) at {:?}",
        page.status,
        page.kind(),
        page.location()
    );
}

fn assert_refused(page: &Page, status: u16, error: &str, case: &str) {
    assert_eq!(page.status, status, "{case} must be answered {status}");
    let error_code = page.json().map(|json| json["error"].clone());
    assert_eq!(
        error_code,
        Some(json!(error)),
        "{case} must carry the error {error}"
    );
}

fn request_id(page: &Page) -> String {
    page.query("req").unwrap_or_else(|| {
        panic!(
            "authorize answered {} without a request id (kind {:?})",
            page.status,
            page.kind()
        )
    })
}

/// Registers a client with `redirect_uris` and returns its client id.
async fn register_client(w: &World, name: &str, redirect_uris: &[&str]) -> String {
    let page = w.client().register(name, redirect_uris).await;
    assert_eq!(page.status, 201, "registering {name} must answer 201");
    page.json()
        .and_then(|json| json["client_id"].as_str().map(str::to_string))
        .expect("registration answer must carry a client_id")
}

/// Bob, signed in and assigned the server `demo`, with the upstream that serves it.
async fn bob_on_demo(w: &World) -> (TestClient, FakeUpstream) {
    let bob = w.user("bob@example.com").await;
    let (upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[demo.as_str()]).await;
    (bob, upstream)
}

/// Runs authorize as `browser` and returns the request id with the consent page it opens.
async fn consent_page(browser: &TestClient, app: &OAuthApp, resource: &str) -> (String, Page) {
    let authorized = browser.authorize(app, resource, &pkce(), "state-1").await;
    let req = request_id(&authorized);
    let page = browser.get(&format!("/oauth/consent?req={req}")).await;
    (req, page)
}

#[tokio::test(flavor = "multi_thread")]
async fn dynamic_registration_issues_a_public_client() {
    let w = World::start().await;
    let page = w.client().register("Cursor", &C3).await;
    assert_eq!(
        page.status, 201,
        "a registration with three valid addresses must answer 201"
    );
    let json = page.json().expect("the registration answer must be JSON");
    assert!(
        json["client_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("dcr_")),
        "client_id must start with dcr_, got {}",
        json["client_id"]
    );
    assert_eq!(
        json["token_endpoint_auth_method"], "none",
        "a dynamically registered client must be public"
    );
    assert_eq!(
        json["redirect_uris"],
        json!(C3),
        "the registered redirect addresses must be echoed"
    );
    assert!(
        json.get("client_secret").is_none(),
        "a public client must get no client_secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registered_client_completes_the_flow() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &C3).await;
    let app = oauth_app(&client_id, LOCAL_8787);
    let (_req, consent) = consent_page(&bob, &app, &w.resource("demo")).await;
    assert_eq!(consent.status, 200, "the consent page must load");
    assert_eq!(
        consent.attr("main", "data-client-verified").as_deref(),
        Some("no"),
        "a dynamically registered client must be shown as unverified"
    );
    let tokens = bob.connect(&app, &w.resource("demo")).await;
    assert!(
        tokens.access_token.starts_with("dw_at_"),
        "the registered client must receive an access token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_registrations_are_refused() {
    let w = World::start().await;
    let client = w.client();
    for uri in [
        "https://www.cursor.com/callback#fragment",
        "http://client.example.com/callback",
        "https://*.example.com/callback",
    ] {
        let page = client.register("X", &[uri]).await;
        assert_refused(&page, 400, "invalid_redirect_uri", uri);
    }
    let page = client.register("X", &[]).await;
    assert_refused(&page, 400, "invalid_client_metadata", "an empty list");

    let eleven: Vec<String> = (0..11)
        .map(|n| format!("https://app{n}.example.com/callback"))
        .collect();
    let eleven: Vec<&str> = eleven.iter().map(String::as_str).collect();
    let page = client.register("X", &eleven).await;
    assert_refused(&page, 400, "invalid_client_metadata", "eleven addresses");

    let response =
        w.gw.http
            .post(w.gw.url("/oauth/register"))
            .header("content-type", "application/json")
            .body("this is not json")
            .send()
            .await
            .expect("registration request");
    assert_eq!(
        response.status().as_u16(),
        400,
        "a body that is not JSON must be refused"
    );
    let body: Value = response.json().await.expect("the refusal must be JSON");
    assert_eq!(
        body["error"], "invalid_client_metadata",
        "a body that is not JSON must carry invalid_client_metadata"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_is_rate_limited_per_address() {
    let w = World::start_with(|c| c.limits.dcr_per_hour = 3).await;
    let client = w.client();
    for n in 1..=3 {
        let page = client.register("X", &[LOCAL_8787]).await;
        assert_eq!(
            page.status, 201,
            "registration {n} of three must be allowed"
        );
    }
    let page = client.register("X", &[LOCAL_8787]).await;
    assert_eq!(
        page.status, 429,
        "a fourth registration within the hour must be limited"
    );
    w.gw.clock.advance(time::Duration::seconds(3601));
    let page = client.register("X", &[LOCAL_8787]).await;
    assert_eq!(
        page.status, 201,
        "a registration after one hour and 1 second must be allowed again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_confidential_registration_becomes_public() {
    let w = World::start().await;
    let page = w
        .client()
        .post_json(
            "/oauth/register",
            &json!({
                "client_name": "X",
                "redirect_uris": [LOCAL_8787],
                "token_endpoint_auth_method": "client_secret_basic",
            }),
        )
        .await;
    assert_eq!(
        page.status, 201,
        "a registration asking for a secret must still be accepted"
    );
    let json = page.json().expect("the registration answer must be JSON");
    assert_eq!(
        json["token_endpoint_auth_method"], "none",
        "a requested client_secret_basic must become none"
    );
    assert!(
        json.get("client_secret").is_none(),
        "no client_secret may be issued"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_named_like_a_known_one_is_marked_unverified() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Claude", &[LOCAL_8787]).await;
    let app = oauth_app(&client_id, LOCAL_8787);
    let (_req, consent) = consent_page(&bob, &app, &w.resource("demo")).await;
    assert_eq!(consent.status, 200, "the consent page must load");
    assert_eq!(
        consent.attr("main", "data-client-verified").as_deref(),
        Some("no"),
        "a client named like a known one must be shown as unverified"
    );
    assert_eq!(
        consent.attr("main", "data-redirect-host").as_deref(),
        Some("localhost:8787"),
        "the consent page must name the redirect host and port"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlisted_redirect_is_blocked_at_authorize() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let attacker = "https://attacker.example.com/cb";
    let client_id = register_client(&w, "X", &[attacker]).await;
    let page = bob
        .authorize(
            &oauth_app(&client_id, attacker),
            &w.resource("demo"),
            &pkce(),
            "state-1",
        )
        .await;
    assert_error_page(&page, "an unlisted redirect address");
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "redirect_blocked"),
        "the blocked redirect must show in the activity log"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_document_client_completes_the_flow() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let (_req, consent) = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_eq!(consent.status, 200, "the consent page must load");
    assert_eq!(
        consent.attr("main", "data-client-name").as_deref(),
        Some(APP_NAME),
        "the consent page must name the client from its document"
    );
    assert_eq!(
        consent.attr("main", "data-client-verified").as_deref(),
        Some("no"),
        "a metadata document on a loopback redirect must be shown as unverified"
    );
    let tokens = bob.connect(&w.app(), &w.resource("demo")).await;
    assert!(
        tokens.access_token.starts_with("dw_at_"),
        "the metadata document client must receive an access token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_document_is_fetched_only_after_sign_in() {
    let w = World::start().await;
    let (_bob, _upstream) = bob_on_demo(&w).await;
    let anonymous = w.client();
    let page = anonymous
        .authorize(&w.app(), &w.resource("demo"), &pkce(), "state-1")
        .await;
    assert_eq!(
        page.status, 303,
        "an anonymous authorize must be sent to sign-in"
    );
    assert_eq!(
        location_path(&page).as_deref(),
        Some("/login"),
        "an anonymous authorize must lead to /login"
    );
    let req = request_id(&page);
    assert_eq!(
        w.gw.cimd().fetches(APP_ID),
        0,
        "the metadata document must not be fetched before sign-in"
    );
    let logged_in = anonymous.login_for(&req, "bob@example.com", PASSWORD).await;
    assert_eq!(
        location_path(&logged_in).as_deref(),
        Some("/oauth/consent"),
        "signing in for the request must lead to consent"
    );
    let consent = anonymous.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load after sign-in"
    );
    assert!(
        w.gw.cimd().fetches(APP_ID) >= 1,
        "the metadata document must be fetched once the consent page is rendered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_fetch_shows_an_error() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    w.gw.cimd().fail(
        APP_ID,
        CimdError::Fetch("the document could not be fetched".into()),
    );
    let (req, consent) = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_error_page(&consent, "a consent page whose document cannot be fetched");
    let csrf = bob
        .get("/account")
        .await
        .csrf()
        .expect("the account page must carry a csrf value");
    let approved = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_eq!(
        approved.query("code"),
        None,
        "approving after a failed fetch must not issue a code"
    );
    assert!(
        !(approved.status == 303
            && approved
                .location()
                .is_some_and(|location| location.starts_with(APP_REDIRECT))),
        "approving after a failed fetch must not redirect to the client's address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_redirect_must_be_in_the_document() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let other = OAuthApp {
        redirect_uri: "http://127.0.0.1:53535/other".into(),
        ..w.app()
    };
    let (_req, consent) = consent_page(&bob, &other, &w.resource("demo")).await;
    assert_error_page(&consent, "a redirect address missing from the document");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_port_may_differ() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let other_port = OAuthApp {
        redirect_uri: "http://127.0.0.1:40123/callback".into(),
        ..w.app()
    };
    let tokens = bob.connect(&other_port, &w.resource("demo")).await;
    assert!(
        tokens.access_token.starts_with("dw_at_"),
        "a loopback redirect on another port must complete the flow"
    );
    let other_host = OAuthApp {
        redirect_uri: "http://localhost:53535/callback".into(),
        ..w.app()
    };
    let (_req, consent) = consent_page(&bob, &other_host, &w.resource("demo")).await;
    assert_error_page(&consent, "a loopback redirect with another host name");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_id_must_be_https_with_a_path() {
    let w = World::start().await;
    let anonymous = w.client();
    let control = anonymous
        .authorize(&w.app(), &w.resource("demo"), &pkce(), "state-1")
        .await;
    assert_eq!(
        control.status, 303,
        "the valid metadata client must reach sign-in"
    );
    assert_eq!(
        location_path(&control).as_deref(),
        Some("/login"),
        "the valid metadata client must be sent to /login"
    );
    assert!(
        control.query("req").is_some(),
        "the valid metadata client must be sent to /login with a request id"
    );
    for client_id in [
        "http://client.example.com/app.json",
        "https://client.example.com",
        "https://client.example.com/",
    ] {
        let page = anonymous
            .authorize(
                &oauth_app(client_id, APP_REDIRECT),
                &w.resource("demo"),
                &pkce(),
                "state-1",
            )
            .await;
        assert_error_page(&page, &format!("the client id {client_id}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_document_must_name_itself_and_be_public() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let (_req, consent) = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_eq!(
        consent.status, 200,
        "the consent page must load with a valid document"
    );
    w.gw.cimd().put_metadata(
        APP_ID,
        ClientMetadata {
            client_id: "https://client.example.com/other.json".into(),
            client_name: Some(APP_NAME.into()),
            redirect_uris: vec![APP_REDIRECT.into()],
            token_endpoint_auth_method: Some("none".into()),
        },
    );
    let (_req, consent) = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_error_page(&consent, "a document that names another client_id");
    w.gw.cimd().put_metadata(
        APP_ID,
        ClientMetadata {
            client_id: APP_ID.into(),
            client_name: Some(APP_NAME.into()),
            redirect_uris: vec![APP_REDIRECT.into()],
            token_endpoint_auth_method: Some("client_secret_basic".into()),
        },
    );
    let (_req, consent) = consent_page(&bob, &w.app(), &w.resource("demo")).await;
    assert_error_page(&consent, "a document that asks for a client secret");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_unknown_client_id_is_refused() {
    let w = World::start().await;
    let anonymous = w.client();
    let client_id = register_client(&w, "X", &[LOCAL_8787]).await;
    let control = anonymous
        .authorize(
            &oauth_app(&client_id, LOCAL_8787),
            &w.resource("demo"),
            &pkce(),
            "state-1",
        )
        .await;
    assert_eq!(
        control.status, 303,
        "a registered client must reach sign-in"
    );
    assert_eq!(
        location_path(&control).as_deref(),
        Some("/login"),
        "a registered client must be sent to /login"
    );
    assert!(
        control.query("req").is_some(),
        "a registered client must be sent to /login with a request id"
    );
    let page = anonymous
        .authorize(
            &oauth_app("dcr_doesnotexist", LOCAL_8787),
            &w.resource("demo"),
            &pkce(),
            "state-1",
        )
        .await;
    assert_error_page(&page, "an unknown client id");
}

/// A caller address in the documentation range 203.0.113.0/24.
fn address_of(n: u8) -> String {
    Ipv4Addr::new(203, 0, 113, n).to_string()
}

/// Whether `/oauth/authorize` knows the client id: a known one is sent on to sign-in,
/// an unknown one gets the error page.
async fn is_known(w: &World, client_id: &str) -> bool {
    let page = w
        .client()
        .authorize(
            &oauth_app(client_id, LOCAL_8787),
            &w.resource("demo"),
            &pkce(),
            "state-1",
        )
        .await;
    if location_path(&page).as_deref() == Some("/login") {
        return true;
    }
    assert_error_page(&page, &format!("the client id {client_id}"));
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn addresses_at_their_limit_do_not_stop_a_fresh_address() {
    let w = World::start_with(|c| {
        c.trusted_proxies = vec![Range::from(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        c.limits.dcr_per_hour = PER_ADDRESS;
    })
    .await;
    for n in 1..=ADDRESSES {
        let caller = TestClient::at(w.base(), &address_of(n));
        for attempt in 1..=PER_ADDRESS {
            let page = caller.register("X", &[LOCAL_8787]).await;
            assert_eq!(
                page.status, 201,
                "registration {attempt} from address {n} is within its own limit and must be allowed"
            );
        }
        let page = caller.register("X", &[LOCAL_8787]).await;
        assert_eq!(
            page.status, 429,
            "address {n} past its own limit must be limited"
        );
    }
    let fresh = TestClient::at(w.base(), &address_of(ADDRESSES + 1));
    let page = fresh.register("X", &[LOCAL_8787]).await;
    assert_eq!(
        page.status, 201,
        "a fresh address must register while the others are at their limit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_oldest_unused_registration_gives_way_at_the_bound() {
    let w = World::start_with(|c| {
        let mut value = serde_json::to_value(&*c).expect("the config as JSON");
        value["limits"]["unused_registrations"] = json!(3);
        *c = serde_json::from_value(value)
            .expect("the config must accept limits.unused_registrations");
    })
    .await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let resource = w.resource("demo");
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(register_client(&w, "X", &[LOCAL_8787]).await);
        w.gw.clock.advance(time::Duration::seconds(1));
    }
    assert!(
        !is_known(&w, &ids[0]).await,
        "the oldest unused registration must give way when the bound of 3 is reached"
    );
    for id in &ids[1..] {
        assert!(
            is_known(&w, id).await,
            "the unused registration {id} must stay known"
        );
    }
    bob.connect(&oauth_app(&ids[1], LOCAL_8787), &resource)
        .await;
    for _ in 0..4 {
        register_client(&w, "X", &[LOCAL_8787]).await;
        w.gw.clock.advance(time::Duration::seconds(1));
    }
    assert!(
        is_known(&w, &ids[1]).await,
        "a registration that completed an authorization must stay known after four more"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_attempts_table_has_an_index_on_time() {
    let w = World::start().await;
    let conn = rusqlite::Connection::open(w.gw.db_path()).expect("open the database");
    let mut statement = conn
        .prepare("EXPLAIN QUERY PLAN DELETE FROM dcr_attempts WHERE at < 1")
        .expect("prepare the plan");
    let details: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(3))
        .expect("run the plan")
        .collect::<Result<_, _>>()
        .expect("read the plan rows");
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("dcr_attempts_at")),
        "the clean-up of registration attempts by time must use the index dcr_attempts_at, plan was {details:?}"
    );
}
