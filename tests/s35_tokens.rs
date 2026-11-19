mod common;

use common::admin;
use common::client::{OAuthApp, Page, TestClient, tokens};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::World;
use futures_util::future::join_all;

const R: &str = "https://www.cursor.com/agents/mcp/oauth/callback";
const L: &str = "http://127.0.0.1:53535/callback";
const LOCAL_8787: &str = "http://localhost:8787/callback";

fn oauth_app(client_id: &str, redirect_uri: &str) -> OAuthApp {
    OAuthApp {
        client_id: client_id.into(),
        redirect_uri: redirect_uri.into(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// True when `value` is `prefix` followed by exactly 43 characters from A-Z a-z 0-9 _ -.
fn is_token(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 43
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    })
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

/// The status a session-style client gets from `url` with `token`.
async fn initialize_status(url: &str, token: &str) -> u16 {
    McpClient::session(url, Some(token))
        .initialize()
        .await
        .status
}

/// Bob, signed in and assigned the server `demo`, with the upstream that serves it.
async fn bob_on_demo(w: &World) -> (TestClient, FakeUpstream) {
    let bob = w.user("bob@example.com").await;
    let (upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[demo.as_str()]).await;
    (bob, upstream)
}

/// Registers a client with `redirect_uris` and returns its client id.
async fn register_client(w: &World, name: &str, redirect_uris: &[&str]) -> String {
    let page = w.client().register(name, redirect_uris).await;
    assert_eq!(page.status, 201, "registering {name} must answer 201");
    page.json()
        .and_then(|json| json["client_id"].as_str().map(str::to_string))
        .expect("registration answer must carry a client_id")
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_are_opaque_and_not_stored() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let pair = w.token(&bob, "demo").await;
    assert!(
        is_token(&pair.access_token, "dw_at_"),
        "the access token must be dw_at_ and 43 characters of A-Z a-z 0-9 _ -"
    );
    assert!(
        is_token(&pair.refresh_token, "dw_rt_"),
        "the refresh token must be dw_rt_ and 43 characters of A-Z a-z 0-9 _ -"
    );
    let stored = w.stored_bytes();
    assert!(
        !contains(&stored, pair.access_token.as_bytes()),
        "the access token must not be stored in the database"
    );
    assert!(
        !contains(&stored, pair.refresh_token.as_bytes()),
        "the refresh token must not be stored in the database"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_replaces_both_tokens() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let first = w.token(&bob, "demo").await;
    let page = bob
        .token_refresh(&w.app(), &first.refresh_token, None)
        .await;
    assert_eq!(
        page.status, 200,
        "a refresh with a valid refresh token must succeed"
    );
    let second = tokens(&page).expect("the refresh answer must hold a token pair");
    assert_ne!(
        second.access_token, first.access_token,
        "a refresh must issue a new access token"
    );
    assert_ne!(
        second.refresh_token, first.refresh_token,
        "a refresh must issue a new refresh token"
    );
    assert_eq!(
        initialize_status(&w.resource("demo"), &second.access_token).await,
        200,
        "the new access token must work"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replay_inside_the_window_gets_the_same_pair() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let first_pair = w.token(&bob, "demo").await;
    let first = bob
        .token_refresh(&w.app(), &first_pair.refresh_token, None)
        .await;
    assert_eq!(first.status, 200, "the first refresh must succeed");
    w.gw.clock.advance(time::Duration::seconds(10));
    let replay = bob
        .token_refresh(&w.app(), &first_pair.refresh_token, None)
        .await;
    assert_eq!(
        replay.status, 200,
        "a replay inside the window must be answered"
    );
    assert_eq!(
        replay.body, first.body,
        "a replay inside the window must return the identical pair"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_refreshes_get_identical_answers() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let first_pair = w.token(&bob, "demo").await;
    let app = w.app();
    let pages =
        join_all((0..8).map(|_| bob.token_refresh(&app, &first_pair.refresh_token, None))).await;
    for (n, page) in pages.iter().enumerate() {
        assert_eq!(
            page.status, 200,
            "parallel refresh {n} must be answered 200"
        );
        assert_eq!(
            page.body, pages[0].body,
            "parallel refresh {n} must get the identical pair"
        );
    }
    let shared = tokens(&pages[0]).expect("the shared answer must hold a token pair");
    let next = bob.token_refresh(&app, &shared.refresh_token, None).await;
    assert_eq!(
        next.status, 200,
        "the refresh token of the shared pair must work"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replay_after_the_window_revokes_the_chain() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let app = w.app();
    let first_pair = w.token(&bob, "demo").await;
    let used = bob
        .token_refresh(&app, &first_pair.refresh_token, None)
        .await;
    let successor = tokens(&used).expect("the first refresh must issue a pair");
    w.gw.clock.advance(time::Duration::seconds(31));
    let replay = bob
        .token_refresh(&app, &first_pair.refresh_token, None)
        .await;
    assert_token_error(&replay, "invalid_grant", "a replay after the window");
    let successor_refresh = bob
        .token_refresh(&app, &successor.refresh_token, None)
        .await;
    assert_token_error(
        &successor_refresh,
        "invalid_grant",
        "the successor refresh token after the chain is revoked",
    );
    let resource = w.resource("demo");
    assert_eq!(
        initialize_status(&resource, &first_pair.access_token).await,
        401,
        "the first access token must be refused once the chain is revoked"
    );
    assert_eq!(
        initialize_status(&resource, &successor.access_token).await,
        401,
        "the successor access token must be refused once the chain is revoked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_zero_window_is_strict() {
    let w = World::start_with(|c| c.lifetimes.refresh_replay_seconds = 0).await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let app = w.app();
    let first_pair = w.token(&bob, "demo").await;
    let used = bob
        .token_refresh(&app, &first_pair.refresh_token, None)
        .await;
    assert_eq!(used.status, 200, "the first refresh must succeed");
    let successor = tokens(&used).expect("the first refresh must issue a pair");
    let second = bob
        .token_refresh(&app, &first_pair.refresh_token, None)
        .await;
    assert_token_error(&second, "invalid_grant", "a second use with a zero window");
    let successor_refresh = bob
        .token_refresh(&app, &successor.refresh_token, None)
        .await;
    assert_token_error(
        &successor_refresh,
        "invalid_grant",
        "the successor refresh token after a strict replay",
    );
    let resource = w.resource("demo");
    assert_eq!(
        initialize_status(&resource, &successor.access_token).await,
        401,
        "the successor access token must be refused after a strict replay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_replay_copy_cannot_be_read_from_the_database() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let first_pair = w.token(&bob, "demo").await;
    let page = bob
        .token_refresh(&w.app(), &first_pair.refresh_token, None)
        .await;
    let successor = tokens(&page).expect("the refresh must issue a pair");
    let stored = w.stored_bytes();
    assert!(
        !contains(&stored, successor.access_token.as_bytes()),
        "the successor access token must not be stored in the database"
    );
    assert!(
        !contains(&stored, successor.refresh_token.as_bytes()),
        "the successor refresh token must not be stored in the database"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_token_lasts_thirty_days() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let pair = w.token(&bob, "demo").await;
    w.gw.clock
        .advance(time::Duration::days(30) + time::Duration::seconds(1));
    let page = bob.token_refresh(&w.app(), &pair.refresh_token, None).await;
    assert_token_error(
        &page,
        "invalid_grant",
        "a refresh token unused for 30 days and 1 second",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chain_ends_after_ninety_days() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let app = w.app();
    let pair = w.token(&bob, "demo").await;
    let mut current = pair.refresh_token;
    for step in 1..=4 {
        w.gw.clock.advance(time::Duration::days(20));
        let page = bob.token_refresh(&app, &current, None).await;
        assert_eq!(
            page.status,
            200,
            "refresh {step}, at day {}, must work",
            step * 20
        );
        current = tokens(&page)
            .expect("a refresh must issue a pair")
            .refresh_token;
    }
    w.gw.clock.advance(time::Duration::days(20));
    let page = bob.token_refresh(&app, &current, None).await;
    assert_token_error(&page, "invalid_grant", "a refresh at day 100 of the chain");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_rechecks_the_user_and_the_assignment() {
    let w = World::start().await;
    let bob = w.user("bob@example.com").await;
    let carol = w.user("carol@example.com").await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[demo.as_str()]).await;
    w.grant("carol@example.com", &[demo.as_str()]).await;
    let bob_pair = w.token(&bob, "demo").await;
    let carol_pair = w.token(&carol, "demo").await;

    w.grant("bob@example.com", &[]).await;
    let page = bob
        .token_refresh(&w.app(), &bob_pair.refresh_token, None)
        .await;
    assert_token_error(
        &page,
        "invalid_grant",
        "a refresh after the server was unassigned",
    );

    let carol_id = w.user_id("carol@example.com").await;
    let disabled = admin::user_action(&w.owner, &carol_id, "disable").await;
    assert_eq!(disabled.status, 303, "disabling a user must answer 303");
    let page = carol
        .token_refresh(&w.app(), &carol_pair.refresh_token, None)
        .await;
    assert_token_error(
        &page,
        "invalid_grant",
        "a refresh after the user was disabled",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_needs_the_same_client() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let client_id = register_client(&w, "Cursor", &[R, L]).await;
    let other_id = register_client(&w, "Other", &[LOCAL_8787]).await;
    let pair = bob
        .connect(&oauth_app(&client_id, L), &w.resource("demo"))
        .await;
    let page = bob
        .token_refresh(&oauth_app(&other_id, LOCAL_8787), &pair.refresh_token, None)
        .await;
    assert_token_error(&page, "invalid_grant", "a refresh by another client");

    let control = bob
        .connect(&oauth_app(&client_id, L), &w.resource("demo"))
        .await;
    let page = bob
        .token_refresh(&oauth_app(&client_id, L), &control.refresh_token, None)
        .await;
    assert_eq!(
        page.status, 200,
        "a refresh by the registered client must succeed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_needs_the_same_resource_when_given() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let app = w.app();
    let pair = w.token(&bob, "demo").await;
    let other_resource = w.resource("other");
    let page = bob
        .token_refresh(&app, &pair.refresh_token, Some(&other_resource))
        .await;
    assert_token_error(&page, "invalid_target", "a refresh for another resource");

    let control = w.token(&bob, "demo").await;
    let page = bob
        .token_refresh(&app, &control.refresh_token, Some(&w.resource("demo")))
        .await;
    assert_eq!(
        page.status, 200,
        "a refresh for the same resource must succeed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_access_token_lasts_an_hour() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let pair = w.token(&bob, "demo").await;
    let resource = w.resource("demo");
    w.gw.clock.advance(time::Duration::minutes(59));
    assert_eq!(
        initialize_status(&resource, &pair.access_token).await,
        200,
        "the access token must work at 59 minutes"
    );
    w.gw.clock.advance(time::Duration::minutes(2));
    assert_eq!(
        initialize_status(&resource, &pair.access_token).await,
        401,
        "the access token must be refused at 61 minutes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_old_access_token_stays_valid_until_it_expires() {
    let w = World::start().await;
    let (bob, _upstream) = bob_on_demo(&w).await;
    let first = w.token(&bob, "demo").await;
    let page = bob
        .token_refresh(&w.app(), &first.refresh_token, None)
        .await;
    assert_eq!(page.status, 200, "the refresh must succeed");
    w.gw.clock.advance(time::Duration::minutes(59));
    assert_eq!(
        initialize_status(&w.resource("demo"), &first.access_token).await,
        200,
        "the access token of the first pair must work until its hour is over"
    );
}
