mod common;

use common::admin;
use common::client::{TestClient, pkce};
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::World;
use serde_json::json;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const EVERYONE: &str = "everyone";

/// Server `s` (echo, search, delete_db) and server `t` (echo); bob and carol are assigned to `s`.
struct Scene {
    w: World,
    s_up: FakeUpstream,
    s_id: String,
    _t_up: FakeUpstream,
    t_id: String,
    bob: TestClient,
    bob_id: String,
    carol: TestClient,
    carol_id: String,
}

async fn start() -> Scene {
    let w = World::start().await;
    let (s_up, s_id) = w.upstream("s", UpstreamOptions::default()).await;
    let t_options = UpstreamOptions {
        tools: vec!["echo".into()],
        ..Default::default()
    };
    let (_t_up, t_id) = w.upstream("t", t_options).await;
    let bob = w.user(BOB).await;
    let carol = w.user(CAROL).await;
    w.grant(BOB, &[s_id.as_str()]).await;
    w.grant(CAROL, &[s_id.as_str()]).await;
    let bob_id = w.user_id(BOB).await;
    let carol_id = w.user_id(CAROL).await;
    Scene {
        w,
        s_up,
        s_id,
        _t_up,
        t_id,
        bob,
        bob_id,
        carol,
        carol_id,
    }
}

/// Adds a rule the owner's form must accept, and returns the new rule's id.
async fn rule(
    sc: &Scene,
    subject: &str,
    effect: &str,
    scope: &str,
    server: Option<&str>,
    tool: Option<&str>,
) -> String {
    let before = admin::rule_ids(&sc.w.owner).await;
    let page = admin::add_rule(&sc.w.owner, subject, effect, scope, server, tool).await;
    assert_eq!(
        page.status, 303,
        "the rule {subject} {effect} {scope} must be accepted"
    );
    let after = admin::rule_ids(&sc.w.owner).await;
    after
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the new rule must be listed")
}

/// Signs `browser` in for `slug` and completes the session handshake.
async fn session(w: &World, browser: &TestClient, slug: &str) -> McpClient {
    let tokens = w.token(browser, slug).await;
    let client = w.session_mcp(slug, &tokens);
    let init = client.initialize().await;
    assert_eq!(init.status, 200, "initialize on /{slug} must answer 200");
    client
}

/// The names of a tool list answer, which must be a 200.
fn names(reply: &McpReply) -> Vec<String> {
    assert_eq!(reply.status, 200, "the tool list must answer 200");
    reply.tool_names()
}

/// The tool names that `browser` sees on `/slug` with a fresh session.
async fn tools(w: &World, browser: &TestClient, slug: &str) -> Vec<String> {
    let client = session(w, browser, slug).await;
    names(&client.list_tools().await)
}

/// Asserts that a call was refused as an unknown tool.
fn assert_refused(reply: &McpReply, tool: &str) {
    assert_eq!(
        reply.error_code(),
        Some(-32602),
        "a call to {tool} must be refused with -32602"
    );
    assert_eq!(
        reply.error_message(),
        Some(format!("Unknown tool: {tool}")),
        "a call to {tool} must be refused as unknown"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_rules_allows_everything() {
    let sc = start().await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search", "delete_db"],
        "with no rules bob must see every tool of his server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_tool_is_absent_and_refused() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    let client = session(&sc.w, &sc.bob, "s").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["echo", "search"],
        "a denied tool must be absent from the list"
    );
    sc.s_up.clear();
    let refused = client.call_tool("delete_db", json!({})).await;
    assert_refused(&refused, "delete_db");
    assert_eq!(
        sc.s_up.calls_to("delete_db"),
        0,
        "the upstream must never see the denied call"
    );
    let echo = client.call_tool("echo", json!({})).await;
    assert_eq!(
        echo.text(),
        Some("called: echo".to_string()),
        "an allowed tool must still work"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_narrower_allow_beats_a_wider_deny() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "all", None, None).await;
    rule(&sc, EVERYONE, "allow", "tool", Some(s), Some("search")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["search"],
        "the tool allow must beat the all deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_tool_beats_deny_server() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "server", Some(s), None).await;
    rule(&sc, EVERYONE, "allow", "tool", Some(s), Some("search")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["search"],
        "the tool allow must beat the server deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_deny_is_not_pierced_by_an_everyone_allow() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, &sc.bob_id, "deny", "all", None, None).await;
    rule(&sc, EVERYONE, "allow", "tool", Some(s), Some("search")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        Vec::<String>::new(),
        "bob's deny must not be pierced by the everyone allow"
    );
    assert_eq!(
        tools(&sc.w, &sc.carol, "s").await,
        vec!["echo", "search", "delete_db"],
        "carol has no deny and must see every tool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_allow_beats_an_everyone_deny_of_the_same_scope() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    rule(&sc, &sc.bob_id, "allow", "tool", Some(s), Some("delete_db")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search", "delete_db"],
        "bob's allow must beat the everyone deny of the same scope"
    );
    assert_eq!(
        tools(&sc.w, &sc.carol, "s").await,
        vec!["echo", "search"],
        "carol must still be denied delete_db"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wider_allow_does_not_beat_a_narrower_deny() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    let server_allow = rule(&sc, &sc.bob_id, "allow", "server", Some(s), None).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search"],
        "a server allow must not beat a tool deny"
    );
    let page = admin::delete_rule(&sc.w.owner, &server_allow).await;
    assert_eq!(page.status, 303, "the server allow must be deleted");
    rule(&sc, &sc.bob_id, "allow", "all", None, None).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search"],
        "an all allow must not beat a tool deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn user_allow_all_beats_everyone_deny_all() {
    let sc = start().await;
    rule(&sc, EVERYONE, "deny", "all", None, None).await;
    rule(&sc, &sc.bob_id, "allow", "all", None, None).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search", "delete_db"],
        "bob's all allow must beat the everyone all deny"
    );
    assert_eq!(
        tools(&sc.w, &sc.carol, "s").await,
        Vec::<String>::new(),
        "carol must have no tools under the everyone all deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn user_allow_server_beats_everyone_deny_server() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "server", Some(s), None).await;
    rule(&sc, &sc.bob_id, "allow", "server", Some(s), None).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search", "delete_db"],
        "bob's server allow must beat the everyone server deny"
    );
    assert_eq!(
        tools(&sc.w, &sc.carol, "s").await,
        Vec::<String>::new(),
        "carol must have no tools under the everyone server deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn everyone_allow_does_not_beat_a_user_deny_of_the_same_scope() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, &sc.bob_id, "deny", "server", Some(s), None).await;
    rule(&sc, EVERYONE, "allow", "server", Some(s), None).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        Vec::<String>::new(),
        "bob's server deny must beat the everyone server allow"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn user_allow_tool_beats_user_deny_server() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, &sc.bob_id, "deny", "server", Some(s), None).await;
    rule(&sc, &sc.bob_id, "allow", "tool", Some(s), Some("echo")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo"],
        "bob's tool allow must beat his own server deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_deny_needs_its_own_override() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "all", None, None).await;
    rule(&sc, &sc.bob_id, "allow", "server", Some(s), None).await;
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["echo", "search"],
        "the tool deny needs its own override and the all deny is overridden by the server allow"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_rules_are_refused() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    let same = admin::add_rule(
        &sc.w.owner,
        EVERYONE,
        "deny",
        "tool",
        Some(s),
        Some("delete_db"),
    )
    .await;
    assert_eq!(
        same.status, 400,
        "a second rule for the same subject and tool must be refused"
    );
    let other = admin::add_rule(
        &sc.w.owner,
        EVERYONE,
        "allow",
        "tool",
        Some(s),
        Some("delete_db"),
    )
    .await;
    assert_eq!(
        other.status, 400,
        "a rule with the other effect for the same subject and tool must be refused"
    );
    rule(&sc, EVERYONE, "allow", "server", Some(s), None).await;
    let server_again =
        admin::add_rule(&sc.w.owner, EVERYONE, "deny", "server", Some(s), None).await;
    assert_eq!(
        server_again.status, 400,
        "a second rule for the same subject and server must be refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allow_on_an_unassigned_server_grants_nothing() {
    let sc = start().await;
    let t = sc.t_id.as_str();
    rule(&sc, EVERYONE, "allow", "server", Some(t), None).await;
    let page = sc
        .bob
        .authorize(&sc.w.app(), &sc.w.resource("t"), &pkce(), "state-1")
        .await;
    let consent = sc
        .bob
        .get(&page.location().expect("authorize must redirect to consent"))
        .await;
    assert_eq!(
        consent.status, 403,
        "bob's consent for an unassigned server must be refused"
    );
    assert_eq!(
        consent.kind(),
        Some("no-access".to_string()),
        "the refusal must be no-access"
    );
    let client = session(&sc.w, &sc.bob, "mcp").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["s__echo", "s__search", "s__delete_db"],
        "bob's combined list must hold only the server he is assigned to"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rules_do_not_cross_servers() {
    let sc = start().await;
    let (s, t) = (sc.s_id.as_str(), sc.t_id.as_str());
    sc.w.grant(BOB, &[s, t]).await;
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("echo")).await;
    assert_eq!(
        tools(&sc.w, &sc.bob, "s").await,
        vec!["search", "delete_db"],
        "the rule must hide echo on /s"
    );
    assert_eq!(
        tools(&sc.w, &sc.bob, "t").await,
        vec!["echo"],
        "the rule must not hide echo on /t"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rules_apply_to_live_tokens_at_once() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    let client = session(&sc.w, &sc.bob, "s").await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["echo", "search", "delete_db"],
        "before the rule bob must see every tool"
    );
    let id = rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    assert_eq!(
        names(&client.list_tools().await),
        vec!["echo", "search"],
        "a deny added after the sign-in must hide the tool on the live token"
    );
    let page = admin::delete_rule(&sc.w.owner, &id).await;
    assert_eq!(page.status, 303, "the rule must be deleted");
    assert_eq!(
        names(&client.list_tools().await),
        vec!["echo", "search", "delete_db"],
        "deleting the rule must bring the tool back on the live token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn both_generations_and_the_combined_endpoint_are_filtered() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    let on_s = sc.w.token(&sc.bob, "s").await;
    let stateless_s = sc.w.stateless_mcp("s", &on_s);
    let session_s = sc.w.session_mcp("s", &on_s);
    assert_eq!(
        session_s.initialize().await.status,
        200,
        "initialize on /s must answer 200"
    );
    let on_mcp = sc.w.token(&sc.bob, "mcp").await;
    let stateless_mcp = sc.w.stateless_mcp("mcp", &on_mcp);
    let session_mcp = sc.w.session_mcp("mcp", &on_mcp);
    assert_eq!(
        session_mcp.initialize().await.status,
        200,
        "initialize on /mcp must answer 200"
    );
    assert_eq!(
        names(&stateless_s.list_tools().await),
        vec!["echo", "search"],
        "the stateless list on /s must lack the denied tool"
    );
    assert_eq!(
        names(&session_s.list_tools().await),
        vec!["echo", "search"],
        "the session list on /s must lack the denied tool"
    );
    assert_eq!(
        names(&stateless_mcp.list_tools().await),
        vec!["s__echo", "s__search"],
        "the stateless list on /mcp must lack the denied tool"
    );
    assert_eq!(
        names(&session_mcp.list_tools().await),
        vec!["s__echo", "s__search"],
        "the session list on /mcp must lack the denied tool"
    );
    sc.s_up.clear();
    assert_refused(
        &stateless_s.call_tool("delete_db", json!({})).await,
        "delete_db",
    );
    assert_refused(
        &session_s.call_tool("delete_db", json!({})).await,
        "delete_db",
    );
    assert_refused(
        &stateless_mcp.call_tool("s__delete_db", json!({})).await,
        "s__delete_db",
    );
    assert_refused(
        &session_mcp.call_tool("s__delete_db", json!({})).await,
        "s__delete_db",
    );
    assert_eq!(
        sc.s_up.calls_to("delete_db"),
        0,
        "the upstream must never see a refused call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_user_page_shows_the_effective_tools() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    rule(&sc, &sc.bob_id, "allow", "tool", Some(s), Some("delete_db")).await;
    let bob_view = admin::effective_tools(&sc.w.owner, &sc.bob_id).await;
    assert!(
        bob_view.contains(&(
            "s".to_string(),
            "delete_db".to_string(),
            "allow".to_string()
        )),
        "bob's page must show delete_db as allow, got {bob_view:?}"
    );
    let carol_view = admin::effective_tools(&sc.w.owner, &sc.carol_id).await;
    assert!(
        carol_view.contains(&("s".to_string(), "delete_db".to_string(), "deny".to_string())),
        "carol's page must show delete_db as deny, got {carol_view:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_shapes_are_checked() {
    let sc = start().await;
    let s = sc.s_id.as_str();
    let refused = [
        (
            "a tool scope without a tool",
            admin::add_rule(&sc.w.owner, EVERYONE, "deny", "tool", Some(s), None).await,
        ),
        (
            "a server scope without a server",
            admin::add_rule(&sc.w.owner, EVERYONE, "deny", "server", None, None).await,
        ),
        (
            "an unknown effect",
            admin::add_rule(&sc.w.owner, EVERYONE, "maybe", "all", None, None).await,
        ),
        (
            "an unknown subject id",
            admin::add_rule(&sc.w.owner, "no-such-user", "deny", "all", None, None).await,
        ),
    ];
    for (shape, page) in refused {
        assert_eq!(
            page.status, 400,
            "a rule with {shape} must be refused with 400"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_server_removes_its_rules() {
    let sc = start().await;
    let (s, t) = (sc.s_id.as_str(), sc.t_id.as_str());
    let s_rule = rule(&sc, EVERYONE, "deny", "tool", Some(s), Some("delete_db")).await;
    let t_rule = rule(&sc, EVERYONE, "deny", "server", Some(t), None).await;
    let before = admin::rule_ids(&sc.w.owner).await;
    assert_eq!(
        before.len(),
        2,
        "both rules must be listed before the delete"
    );
    assert!(before.contains(&s_rule), "the rule on s must be listed");
    let page = admin::delete_server(&sc.w.owner, s).await;
    assert_eq!(page.status, 303, "deleting server s must answer 303");
    assert_eq!(
        admin::rule_ids(&sc.w.owner).await,
        vec![t_rule],
        "deleting s must remove its rule and keep the rule on t"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_admins_write_rules() {
    let sc = start().await;
    let form = sc.bob.get("/account").await;
    let csrf = form
        .csrf()
        .expect("bob's account page must carry a csrf token");
    let page = sc
        .bob
        .post(
            "/admin/rules",
            &[
                ("csrf", csrf.as_str()),
                ("subject", EVERYONE),
                ("effect", "deny"),
                ("scope", "all"),
            ],
        )
        .await;
    assert_eq!(page.status, 403, "a plain user's rule post must be refused");
    assert_eq!(
        page.kind(),
        Some("forbidden".to_string()),
        "a plain user's rule post must answer forbidden"
    );
    assert!(
        admin::rule_ids(&sc.w.owner).await.is_empty(),
        "a refused post must create no rule"
    );
}
