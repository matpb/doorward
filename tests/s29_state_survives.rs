mod common;

use common::admin;
use common::upstream::UpstreamOptions;
use common::world::{PASSWORD, World};

const BOB: &str = "bob@example.com";

#[tokio::test(flavor = "multi_thread")]
async fn users_rules_and_tokens_survive_a_restart() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let rule = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(demo.as_str()),
        Some("delete_db"),
    )
    .await;
    assert_eq!(rule.status, 303, "a deny rule on delete_db must answer 303");
    let rules_before = admin::rule_ids(&w.owner).await;
    assert_eq!(
        rules_before.len(),
        1,
        "one rule must be listed before the restart"
    );

    w.gw.restart().await;

    assert_eq!(
        bob.get("/account").await.status,
        200,
        "bob's browser session must still open /account after the restart"
    );
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's token must start a session after the restart"
    );
    let listed = mcp.list_tools().await;
    assert_eq!(
        listed.status, 200,
        "bob's token must still list tools after the restart"
    );
    assert_eq!(
        listed.tool_names(),
        vec!["echo", "search"],
        "the deny rule must still hide delete_db after the restart"
    );
    let refreshed = w
        .client()
        .token_refresh(&w.app(), &tokens.refresh_token, None)
        .await;
    assert!(
        common::client::tokens(&refreshed).is_some(),
        "token_refresh must still work after the restart, got status {}",
        refreshed.status
    );
    assert_eq!(
        w.client().login(BOB, PASSWORD).await.status,
        303,
        "bob must still be able to sign in after the restart"
    );
    assert_eq!(
        admin::server_id(&w.owner, "demo").await,
        Some(demo.clone()),
        "the demo server must still be listed after the restart"
    );
    assert_eq!(
        admin::rule_ids(&w.owner).await,
        rules_before,
        "the deny rule must still be listed after the restart"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_live_mcp_session_survives_a_restart() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "bob's session must start before the restart"
    );

    w.gw.restart().await;

    let listed = mcp.list_tools().await;
    assert_eq!(
        listed.status, 200,
        "bob's session opened before the restart must still list tools after it"
    );
    assert_eq!(
        listed.tool_names(),
        vec!["echo", "search", "delete_db"],
        "the session opened before the restart must list every tool"
    );
}
