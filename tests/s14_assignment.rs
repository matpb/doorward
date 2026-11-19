mod common;

use common::admin;
use common::client::{Page, TestClient, pkce};
use common::upstream::UpstreamOptions;
use common::world::{OWNER_EMAIL, World};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";

/// Reads the csrf token of a signed-in browser from its account page.
async fn csrf_of(browser: &TestClient) -> String {
    browser
        .get("/account")
        .await
        .csrf()
        .expect("the account page carries a csrf token")
}

/// Starts an authorization for `slug` as `browser`; returns the request id and the consent page.
async fn consent_for(w: &World, browser: &TestClient, slug: &str, state: &str) -> (String, Page) {
    let started = browser
        .authorize(&w.app(), &w.resource(slug), &pkce(), state)
        .await;
    assert_eq!(started.status, 303, "authorize for {slug} must redirect");
    assert!(
        started
            .location()
            .is_some_and(|location| location.starts_with("/oauth/consent?req=")),
        "authorize for {slug} must lead to the consent page"
    );
    let req = started
        .query("req")
        .expect("the consent redirect carries a req");
    let page = browser.get(&format!("/oauth/consent?req={req}")).await;
    (req, page)
}

#[tokio::test(flavor = "multi_thread")]
async fn assigning_on_the_user_page_shows_on_the_server_page() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob_id = w.user_id(BOB).await;
    let page = admin::assign(&w.owner, &bob_id, &[demo.as_str()]).await;
    assert_eq!(page.status, 303, "assigning demo to bob must answer 303");
    assert!(
        admin::assigned_user_ids(&w.owner, &demo)
            .await
            .contains(&bob_id),
        "the server page must show bob as assigned"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn assigning_on_the_server_page_shows_on_the_user_page() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob_id = w.user_id(BOB).await;
    let page = admin::assign_users(&w.owner, &demo, &[bob_id.as_str()]).await;
    assert_eq!(
        page.status, 303,
        "assigning bob on the server page must answer 303"
    );
    assert!(
        admin::assigned_server_ids(&w.owner, &bob_id)
            .await
            .contains(&demo),
        "the user page must show demo as assigned"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unassigned_user_gets_no_consent() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, _demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let (req, consent) = consent_for(&w, &bob, "demo", "unassigned").await;
    assert_eq!(
        consent.status, 403,
        "the consent page for an unassigned user must answer 403"
    );
    assert_eq!(
        consent.kind().as_deref(),
        Some("no-access"),
        "the consent page for an unassigned user must show no-access"
    );
    let csrf = csrf_of(&bob).await;
    let approval = bob
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
        approval.query("code"),
        None,
        "approving for an unassigned user must yield no code"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigning_refuses_the_next_request() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start before the unassignment"
    );
    assert_eq!(
        mcp.list_tools().await.status,
        200,
        "bob must list tools before the unassignment"
    );
    let bob_id = w.user_id(BOB).await;
    let page = admin::assign(&w.owner, &bob_id, &[]).await;
    assert_eq!(
        page.status, 303,
        "removing bob's assignments must answer 303"
    );
    assert_eq!(
        mcp.list_tools().await.status,
        401,
        "after the unassignment, bob's token must be refused on the next request"
    );
    let refresh = w
        .client()
        .token_refresh(&w.app(), &tokens.refresh_token, None)
        .await;
    assert_eq!(
        refresh.status, 400,
        "refreshing after the unassignment must answer 400"
    );
    let error = refresh
        .json()
        .and_then(|json| json["error"].as_str().map(str::to_owned));
    assert_eq!(
        error.as_deref(),
        Some("invalid_grant"),
        "refreshing after the unassignment must answer invalid_grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigned_server_is_absent_from_the_combined_endpoint() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_a_upstream, a) = w.upstream("a", UpstreamOptions::default()).await;
    let alpha_only = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..UpstreamOptions::default()
    };
    let (b_upstream, b) = w.upstream("b", alpha_only).await;
    w.grant(BOB, &[a.as_str(), b.as_str()]).await;
    let tokens = w.token(&bob, "mcp").await;
    let mcp = w.session_mcp("mcp", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's combined session must start"
    );
    let before = mcp.list_tools().await;
    assert!(
        before.tool_names().contains(&"b__alpha".to_string()),
        "bob must see b__alpha before the unassignment"
    );
    let bob_id = w.user_id(BOB).await;
    let page = admin::assign(&w.owner, &bob_id, &[a.as_str()]).await;
    assert_eq!(
        page.status, 303,
        "removing server b from bob must answer 303"
    );
    let after = mcp.list_tools().await;
    assert_eq!(
        after.status, 200,
        "the live combined token must still list the remaining server's tools"
    );
    assert!(
        after.tool_names().contains(&"a__echo".to_string()),
        "the combined list must keep a__echo"
    );
    assert!(
        after
            .tool_names()
            .iter()
            .all(|name| !name.starts_with("b__")),
        "the combined list must hold no b__ name after the unassignment"
    );
    b_upstream.clear();
    let refused = mcp.call_tool("b__alpha", serde_json::json!({})).await;
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "calling b__alpha after the unassignment must answer -32602"
    );
    assert!(
        b_upstream.requests().is_empty(),
        "server b must not be contacted after the unassignment"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_needs_an_assignment_too() {
    let w = World::start().await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let (_req, before) = consent_for(&w, &w.owner, "demo", "owner-before").await;
    assert_eq!(
        before.status, 403,
        "the owner's consent for demo must answer 403 before an assignment"
    );
    assert_eq!(
        before.kind().as_deref(),
        Some("no-access"),
        "the owner's consent for demo must show no-access before an assignment"
    );
    w.grant(OWNER_EMAIL, &[demo.as_str()]).await;
    let (_req, after) = consent_for(&w, &w.owner, "demo", "owner-after").await;
    assert_eq!(
        after.status, 200,
        "the owner's consent for demo must answer 200 once assigned"
    );
    assert_eq!(
        after.kind().as_deref(),
        Some("consent"),
        "the owner's consent page must be shown once assigned"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_admins_assign() {
    let w = World::start().await;
    let carol = w.user(CAROL).await;
    let _bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob_id = w.user_id(BOB).await;
    let csrf = csrf_of(&carol).await;
    let page = carol
        .post(
            &format!("/admin/users/{bob_id}/servers"),
            &[("csrf", csrf.as_str()), ("server_id", demo.as_str())],
        )
        .await;
    assert_eq!(
        page.status, 403,
        "a plain user assigning a server must answer 403"
    );
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "a plain user assigning a server must see the forbidden page"
    );
}
