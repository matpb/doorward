mod common;

use common::admin;
use common::client::{OAuthApp, Page, Pkce, TestClient, pkce, tokens};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{SECRET_HEADER, World, secret_for};
use futures_util::future::join_all;
use serde_json::Value;

const R: &str = "https://www.cursor.com/agents/mcp/oauth/callback";
const L: &str = "http://127.0.0.1:53535/callback";
const LOCAL_8787: &str = "http://localhost:8787/callback";
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

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

fn assert_accepted(page: &Page, case: &str) {
    let path = location_path(page);
    assert!(
        page.status == 303 && matches!(path.as_deref(), Some("/login" | "/oauth/consent")),
        "{case} must be accepted with a 303 to sign-in or consent, got {} at {:?}",
        page.status,
        page.location()
    );
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

fn token_error(page: &Page) -> Option<String> {
    page.json()?["error"].as_str().map(str::to_string)
}

fn assert_token_error(page: &Page, error: &str, case: &str) {
    assert_eq!(
        page.status, 400,
        "{case} must be answered 400, body {}",
        page.body
    );
    assert_eq!(
        token_error(page).as_deref(),
        Some(error),
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

fn issued_code(granted: &Page) -> String {
    granted.query("code").unwrap_or_else(|| {
        panic!(
            "consent answered {} without a code, location {:?}",
            granted.status,
            granted.location()
        )
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
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

async fn authorize_as(
    browser: &TestClient,
    client_id: &str,
    redirect: &str,
    resource: &str,
) -> Page {
    browser
        .authorize(
            &oauth_app(client_id, redirect),
            resource,
            &pkce(),
            "state-1",
        )
        .await
}

/// Authorizes and approves as `browser`; returns the verifier pair and the issued code.
async fn code_for(browser: &TestClient, app: &OAuthApp, resource: &str) -> (Pkce, String) {
    let pair = pkce();
    let authorized = browser.authorize(app, resource, &pair, "state-1").await;
    let req = request_id(&authorized);
    let granted = browser.consent(&req, "approve").await;
    (pair, issued_code(&granted))
}

/// The status a session-style client gets from `url` with `token`.
async fn initialize_status(url: &str, token: &str) -> u16 {
    McpClient::session(url, Some(token))
        .initialize()
        .await
        .status
}

#[tokio::test(flavor = "multi_thread")]
async fn the_redirect_must_match_exactly() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let page = authorize_as(&bob, &client_id, R, &w.resource("demo")).await;
    assert_accepted(&page, "the registered address R itself");
    let variants = [
        format!("{R}x"),
        format!("{R}/extra"),
        format!("{R}?a=1"),
        R.replacen("https", "http", 1),
        R.replacen("https://", "https://user@", 1),
        R.replacen("www.cursor.com", "www.cursor.com.", 1),
        R.replacen("www.cursor.com", "www.cursor.com:444", 1),
        R.replacen("www.cursor.com", "WWW.CURSOR.COM", 1),
        "https://www.cursor.com\\@evil.example.com/agents/mcp/oauth/callback".to_string(),
        "https://www.xn--curor-j2e.example.com/agents/mcp/oauth/callback".to_string(),
    ];
    for uri in variants {
        let page = authorize_as(&bob, &client_id, &uri, &w.resource("demo")).await;
        assert_error_page(
            &page,
            &format!("the redirect {uri} against the registered one"),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn loopback_look_alikes_are_refused() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let page = authorize_as(&bob, &client_id, L, &w.resource("demo")).await;
    assert_accepted(&page, "the registered loopback address L itself");
    let all_zero = format!("{0}.{0}.{0}.{0}", 0);
    let variants = [
        format!("http://{}.{}:53535/callback", 127, 1),
        "http://localhost.evil.example.com:53535/callback".to_string(),
        "http://127.0.0.1.evil.example.com:53535/callback".to_string(),
        format!("http://{all_zero}:53535/callback"),
        "http://[::ffff:127.0.0.1]:53535/callback".to_string(),
        "http://2130706433:53535/callback".to_string(),
        "https://127.0.0.1:53535/callback".to_string(),
        "http://127.0.0.1:53535/callback2".to_string(),
    ];
    for uri in variants {
        let page = authorize_as(&bob, &client_id, &uri, &w.resource("demo")).await;
        assert_error_page(&page, &format!("the loopback look-alike {uri}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn any_loopback_port_is_allowed() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[L]).await;
    let page = authorize_as(
        &bob,
        &client_id,
        "http://127.0.0.1:40001/callback",
        &w.resource("demo"),
    )
    .await;
    assert_accepted(&page, "the registered loopback address on port 40001");

    let local_id = register_client(&w, "Local", &[LOCAL_8787]).await;
    let page = authorize_as(
        &bob,
        &local_id,
        "http://localhost:9999/callback",
        &w.resource("demo"),
    )
    .await;
    assert_accepted(
        &page,
        "a localhost address on port 9999 for a client registered on 8787",
    );

    let v6_id = register_client(&w, "Six", &["http://[::1]:9/callback"]).await;
    let page = authorize_as(
        &bob,
        &v6_id,
        "http://[::1]:1234/callback",
        &w.resource("demo"),
    )
    .await;
    assert_accepted(
        &page,
        "an IPv6 loopback address on port 1234 for a client registered on port 9",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn known_clients_ship_on_the_list() {
    let w = World::start().await;
    let rows = w.owner.get("/admin/redirects").await;
    assert_eq!(
        rows.status, 200,
        "the redirects page must load for the owner"
    );
    for host in ["claude.ai", "chatgpt.com", "www.cursor.com"] {
        assert!(
            rows.count(&format!(
                r#"[data-host="{host}"][data-source="shipped"][data-enabled="yes"]"#
            )) > 0,
            "{host} must be an enabled shipped entry"
        );
    }
    assert!(
        rows.count(r#"[data-scheme="cursor"][data-source="shipped"][data-enabled="yes"]"#) > 0,
        "the cursor scheme must be an enabled shipped entry"
    );
    let (bob, _upstream) = bob_on_demo(&w).await;
    let known = [
        "https://claude.ai/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/abc123",
        R,
        "cursor://anysphere.cursor-mcp/oauth/callback",
    ];
    for uri in known {
        let client_id = register_client(&w, "Known", &[uri]).await;
        let page = authorize_as(&bob, &client_id, uri, &w.resource("demo")).await;
        assert_accepted(&page, &format!("the shipped address {uri}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listed_host_with_another_path_is_blocked() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Claude", &["https://claude.ai/evil"]).await;
    let page = authorize_as(
        &bob,
        &client_id,
        "https://claude.ai/evil",
        &w.resource("demo"),
    )
    .await;
    assert_error_page(&page, "a listed host with a path that is not listed");
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter().any(|row| row.kind == "redirect_blocked"),
        "the blocked redirect must show in the activity log"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_can_allow_and_disable_an_address() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let uri = "https://app.example.com/oauth/cb";
    let client_id = register_client(&w, "App", &[uri]).await;
    let page = authorize_as(&bob, &client_id, uri, &w.resource("demo")).await;
    assert_error_page(&page, "an address nobody has allowed yet");

    let added = admin::add_redirect(&w.owner, "https", "app.example.com", "/oauth/").await;
    assert_eq!(
        added.status, 303,
        "adding an allowed address must answer 303"
    );
    let page = authorize_as(&bob, &client_id, uri, &w.resource("demo")).await;
    assert_accepted(&page, "the address after the admin allowed it");

    let id = admin::redirect_id(&w.owner, "app.example.com")
        .await
        .expect("the added address must be listed");
    let disabled = admin::redirect_action(&w.owner, &id, "disable").await;
    assert_eq!(disabled.status, 303, "disabling an address must answer 303");
    let page = authorize_as(&bob, &client_id, uri, &w.resource("demo")).await;
    assert_error_page(&page, "the address after the admin disabled it");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shipped_entry_can_be_disabled() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Claude", &[CLAUDE_CALLBACK]).await;
    let page = authorize_as(&bob, &client_id, CLAUDE_CALLBACK, &w.resource("demo")).await;
    assert_accepted(&page, "the shipped claude.ai address before it is disabled");

    let id = admin::redirect_id(&w.owner, "claude.ai")
        .await
        .expect("the shipped claude.ai entry must be listed");
    let disabled = admin::redirect_action(&w.owner, &id, "disable").await;
    assert_eq!(
        disabled.status, 303,
        "disabling a shipped entry must answer 303"
    );
    let page = authorize_as(&bob, &client_id, CLAUDE_CALLBACK, &w.resource("demo")).await;
    assert_error_page(&page, "the shipped claude.ai address after it is disabled");
}

#[tokio::test(flavor = "multi_thread")]
async fn private_schemes_must_be_listed() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "App", &["evilapp://callback"]).await;
    let page = authorize_as(&bob, &client_id, "evilapp://callback", &w.resource("demo")).await;
    assert_error_page(&page, "a private scheme that is not on the list");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_works_once() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");
    let (pair, code) = code_for(&bob, &app, &resource).await;
    let first = bob
        .token_code(&app, &code, &pair.verifier, Some(&resource))
        .await;
    assert_eq!(first.status, 200, "the first use of a code must succeed");
    let issued = tokens(&first).expect("the first exchange must issue a pair");
    assert_eq!(
        initialize_status(&resource, &issued.access_token).await,
        200,
        "the access token of the first exchange must work before the code is reused"
    );
    let second = bob
        .token_code(&app, &code, &pair.verifier, Some(&resource))
        .await;
    assert_token_error(&second, "invalid_grant", "a second use of a code");
    assert_eq!(
        initialize_status(&resource, &issued.access_token).await,
        401,
        "the access token of the first exchange must be refused after the code is reused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_expires_after_sixty_seconds() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");
    let (first_pair, first_code) = code_for(&bob, &app, &resource).await;
    w.gw.clock.advance(time::Duration::seconds(59));
    let at_59 = bob
        .token_code(&app, &first_code, &first_pair.verifier, Some(&resource))
        .await;
    assert_eq!(
        at_59.status, 200,
        "a code redeemed 59 seconds after issue must work"
    );

    let (late_pair, late_code) = code_for(&bob, &app, &resource).await;
    w.gw.clock.advance(time::Duration::seconds(61));
    let at_61 = bob
        .token_code(&app, &late_code, &late_pair.verifier, Some(&resource))
        .await;
    assert_token_error(
        &at_61,
        "invalid_grant",
        "a code redeemed 61 seconds after issue",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_redemption_yields_one_success() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");
    let (pair, code) = code_for(&bob, &app, &resource).await;
    let pages =
        join_all((0..8).map(|_| bob.token_code(&app, &code, &pair.verifier, Some(&resource))))
            .await;
    let successes = pages.iter().filter(|page| page.status == 200).count();
    assert_eq!(
        successes, 1,
        "exactly one of eight simultaneous redemptions must succeed"
    );
    for page in pages.iter().filter(|page| page.status != 200) {
        assert_token_error(page, "invalid_grant", "a redemption that lost the race");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_verifier_must_match() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");

    let (_pair, code) = code_for(&bob, &app, &resource).await;
    let wrong = pkce().verifier;
    let page = bob.token_code(&app, &code, &wrong, Some(&resource)).await;
    assert_token_error(&page, "invalid_grant", "a wrong code_verifier");

    let (_pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_raw(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", L),
            ("client_id", client_id.as_str()),
            ("resource", resource.as_str()),
        ])
        .await;
    assert_token_error(&page, "invalid_request", "a missing code_verifier");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_code(&app, &code, &pair.verifier, Some(&resource))
        .await;
    assert_eq!(
        page.status, 200,
        "the right code_verifier must still redeem a fresh code"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_and_redirect_must_match() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let other_id = register_client(&w, "Other", &[LOCAL_8787]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_code(
            &oauth_app(&other_id, L),
            &code,
            &pair.verifier,
            Some(&resource),
        )
        .await;
    assert_token_error(&page, "invalid_grant", "another registered client's id");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_code(
            &oauth_app(&client_id, R),
            &code,
            &pair.verifier,
            Some(&resource),
        )
        .await;
    assert_token_error(&page, "invalid_grant", "another redirect address");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_code(
            &oauth_app("dcr_doesnotexist", L),
            &code,
            &pair.verifier,
            Some(&resource),
        )
        .await;
    assert_token_error(&page, "invalid_client", "an unknown client_id");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_resource_must_match_when_given() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let other_resource = w.resource("other");
    let page = bob
        .token_code(&app, &code, &pair.verifier, Some(&other_resource))
        .await;
    assert_token_error(&page, "invalid_target", "another resource");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob.token_code(&app, &code, &pair.verifier, None).await;
    assert_eq!(
        page.status, 200,
        "a code exchanged without a resource must work"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_works_only_on_its_server() {
    let w = World::start().await;
    let bob = w.user("bob@example.com").await;
    let (up_a, a) = w.upstream("a", UpstreamOptions::default()).await;
    let (up_b, b) = w.upstream("b", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[a.as_str(), b.as_str()]).await;
    let token = w.token(&bob, "a").await.access_token;
    assert_eq!(
        initialize_status(&w.resource("a"), &token).await,
        200,
        "the token must work on the server it was issued for"
    );

    up_a.clear();
    up_b.clear();
    assert_eq!(
        initialize_status(&w.resource("b"), &token).await,
        401,
        "the token of server a must be refused on server b"
    );
    assert_eq!(
        initialize_status(&format!("{}/mcp", w.base()), &token).await,
        401,
        "the token of server a must be refused on the combined endpoint"
    );
    assert!(
        up_a.requests().is_empty(),
        "server a must not see refused requests"
    );
    assert!(
        up_b.requests().is_empty(),
        "server b must not see refused requests"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_server_does_not_revive_tokens() {
    let w = World::start().await;
    let (bob, upstream) = bob_on_demo(&w).await;
    let pair = w.token(&bob, "demo").await;
    let demo_id = admin::server_id(&w.owner, "demo")
        .await
        .expect("demo must be listed");
    let deleted = admin::delete_server(&w.owner, &demo_id).await;
    assert_eq!(deleted.status, 303, "deleting the server must answer 303");

    let url = upstream.url();
    let secret = secret_for("demo");
    let recreated = admin::add_server(
        &w.owner,
        &admin::ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: Some((SECRET_HEADER, secret.as_str())),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    w.grant("bob@example.com", &[recreated.as_str()]).await;
    let fresh = w.token(&bob, "demo").await;
    assert_eq!(
        initialize_status(&w.resource("demo"), &fresh.access_token).await,
        200,
        "a new token for the re-created server must work"
    );
    assert_eq!(
        initialize_status(&w.resource("demo"), &pair.access_token).await,
        401,
        "the access token of the deleted server must stay refused"
    );
    let refresh = bob.token_refresh(&w.app(), &pair.refresh_token, None).await;
    assert_token_error(
        &refresh,
        "invalid_grant",
        "the refresh token of a deleted server",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn renaming_a_path_revokes_its_tokens() {
    let w = World::start().await;
    let (bob, upstream) = bob_on_demo(&w).await;
    let pair = w.token(&bob, "demo").await;
    let demo_id = admin::server_id(&w.owner, "demo")
        .await
        .expect("demo must be listed");
    let url = upstream.url();
    let secret = secret_for("demo");
    let renamed = admin::update_server(
        &w.owner,
        &demo_id,
        &admin::ServerSpec {
            name: "demo",
            slug: "demo2",
            upstream_url: &url,
            secret: Some((SECRET_HEADER, secret.as_str())),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    assert_eq!(renamed.status, 303, "renaming the server must answer 303");
    assert_eq!(
        initialize_status(&w.resource("demo"), &pair.access_token).await,
        401,
        "the old path must refuse the token after the rename"
    );
    assert_eq!(
        initialize_status(&w.resource("demo2"), &pair.access_token).await,
        401,
        "the new path must refuse the token issued for the old path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn token_response_shape() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");
    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_code(&app, &code, &pair.verifier, Some(&resource))
        .await;
    assert_eq!(page.status, 200, "the exchange must succeed");
    let cache = page.header("cache-control").unwrap_or_default();
    assert!(
        cache.contains("no-store"),
        "the token answer must say no-store, got {cache:?}"
    );
    let json: Value = page.json().expect("the token answer must be JSON");
    assert_eq!(json["token_type"], "Bearer", "token_type must be Bearer");
    assert_eq!(
        json["expires_in"], 3600,
        "an access token must last 3600 seconds"
    );
    assert_eq!(json["scope"], "mcp", "scope must be mcp");
    assert!(
        json["access_token"]
            .as_str()
            .is_some_and(|token| token.starts_with("dw_at_")),
        "the access token must start with dw_at_"
    );
    assert!(
        json["refresh_token"]
            .as_str()
            .is_some_and(|token| token.starts_with("dw_rt_")),
        "the refresh token must start with dw_rt_"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn token_endpoint_refuses_odd_requests() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let resource = w.resource("demo");

    let page = bob
        .token_raw(&[
            ("grant_type", "password"),
            ("client_id", client_id.as_str()),
        ])
        .await;
    assert_token_error(&page, "unsupported_grant_type", "an unknown grant type");

    let (pair, code) = code_for(&bob, &app, &resource).await;
    let page = bob
        .token_raw(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", L),
            ("client_id", client_id.as_str()),
            ("code_verifier", pair.verifier.as_str()),
            ("resource", resource.as_str()),
        ])
        .await;
    assert_token_error(&page, "invalid_request", "a repeated code field");

    let page = bob.get("/oauth/token").await;
    assert_eq!(
        page.status, 405,
        "a GET on the token endpoint must be answered 405"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_code_is_not_stored() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let app = oauth_app(&client_id, L);
    let (_pair, code) = code_for(&bob, &app, &w.resource("demo")).await;
    assert!(!code.is_empty(), "the issued code must not be empty");
    assert!(
        !contains(&w.stored_bytes(), code.as_bytes()),
        "the authorization code must not be stored in the database"
    );
}

/// An authorization request as a client sends it; `response_type` is left out when None.
async fn raw_authorize(
    browser: &TestClient,
    client_id: &str,
    redirect: &str,
    response_type: Option<&str>,
    resource: &str,
) -> Page {
    let pair = pkce();
    let mut params: Vec<(&str, &str)> = Vec::new();
    if let Some(kind) = response_type {
        params.push(("response_type", kind));
    }
    params.extend([
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("code_challenge", pair.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("resource", resource),
        ("state", "state-1"),
    ]);
    browser.authorize_raw(&params).await
}

/// Fails when any link of the page points at `host`.
fn assert_no_link_to(page: &Page, host: &str, case: &str) {
    let links = page.attrs("[href]", "href");
    assert!(
        links.iter().all(|href| !href.contains(host)),
        "{case} must not link to {host}, links {links:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_error_is_never_redirected_to_an_unlisted_address() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let resource = w.resource("demo");
    let document = "https://client.example.com/app.json";
    let evil = "https://evil.example.com/x";

    let page = raw_authorize(&bob, document, evil, None, &resource).await;
    assert_error_page(
        &page,
        "a document client with no response_type and an unlisted redirect",
    );
    assert_no_link_to(&page, "evil.example.com", "that error page");

    let registered = register_client(&w, "Local", &[L]).await;
    let page = raw_authorize(&bob, &registered, evil, None, &resource).await;
    assert_error_page(
        &page,
        "a registered client with no response_type and an unlisted redirect",
    );
    assert_no_link_to(&page, "evil.example.com", "that error page");

    let page = raw_authorize(&bob, document, evil, Some("token"), &resource).await;
    assert_error_page(
        &page,
        "a document client with response_type=token and an unlisted redirect",
    );
    assert_no_link_to(&page, "evil.example.com", "that error page");

    let page = raw_authorize(&bob, &registered, L, Some("token"), &resource).await;
    assert_eq!(
        page.status, 303,
        "a registered loopback redirect with response_type=token must be sent back"
    );
    let location = page.location().unwrap_or_default();
    assert!(
        location.starts_with(L),
        "the error must go to the registered loopback address, got {location}"
    );
    assert_eq!(
        page.query("error").as_deref(),
        Some("invalid_request"),
        "the error must be carried in the redirect"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_client_gets_no_error_redirect_to_a_loopback_address() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let resource = w.resource("demo");
    let document = "https://client.example.com/app.json";
    let control = raw_authorize(&bob, document, L, Some("code"), &resource).await;
    assert_accepted(
        &control,
        "a document client with a valid request to its loopback address",
    );
    let page = raw_authorize(&bob, document, L, None, &resource).await;
    assert_error_page(
        &page,
        "a document client with no response_type and a loopback redirect",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_client_gets_no_error_redirect_to_a_listed_callback() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let resource = w.resource("demo");
    let document = "https://client.example.com/app.json";
    w.gw.cimd()
        .put(document, "Example Client", &[CLAUDE_CALLBACK]);
    let control = raw_authorize(&bob, document, CLAUDE_CALLBACK, Some("code"), &resource).await;
    assert_accepted(
        &control,
        "a document client with a valid request to a listed callback",
    );
    let page = raw_authorize(&bob, document, CLAUDE_CALLBACK, None, &resource).await;
    assert_error_page(
        &page,
        "a document client with no response_type and a listed callback",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_address_cells_hold_their_addresses_whole_and_unchanged() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let added = admin::add_redirect(&w.owner, "https", "app.example.com", "/oauth/").await;
    assert_eq!(
        added.status, 303,
        "adding an allowed address must answer 303"
    );
    let client_id = register_client(&w, "Claude", &["https://claude.ai/evil"]).await;
    let _refused = authorize_as(
        &bob,
        &client_id,
        "https://claude.ai/evil",
        &w.resource("demo"),
    )
    .await;
    let page = w.owner.get("/admin/redirects").await;
    assert_eq!(
        page.status, 200,
        "the redirects page must load for the owner"
    );
    let allowed = r#"tr[data-redirect-id][data-host="app.example.com"] td.lead code"#;
    assert_eq!(
        page.text(allowed).as_deref(),
        Some("https://app.example.com/oauth/"),
        "the allowed address must read as its address"
    );
    assert_eq!(
        page.count(&format!("{allowed} span.whole")),
        1,
        "the allowed address must hold its path piece in a span.whole"
    );
    let blocked = r#"tr[data-blocked="yes"] td.lead code"#;
    assert_eq!(
        page.text(blocked).as_deref(),
        Some("https://claude.ai/evil"),
        "the blocked attempt must read as the address it asked for"
    );
    assert_eq!(
        page.count(&format!("{blocked} span.whole")),
        1,
        "the blocked address must hold its path piece in a span.whole"
    );
}
