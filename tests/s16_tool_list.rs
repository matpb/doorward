mod common;

use common::admin;
use common::upstream::UpstreamOptions;
use common::world::{SECRET_HEADER, World, secret_for};
use serde_json::json;

const BOB: &str = "bob@example.com";

fn two_tools() -> UpstreamOptions {
    UpstreamOptions {
        tools: vec!["alpha".into(), "beta".into()],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn server_page_shows_the_real_tools() {
    let w = World::start().await;
    let (_up, id) = w.upstream("demo", two_tools()).await;
    assert_eq!(
        admin::catalog_tools(&w.owner, &id).await,
        vec!["alpha", "beta"],
        "the server page must list the tools the upstream offers"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_picks_up_changes() {
    let w = World::start().await;
    let (up, id) = w.upstream("demo", two_tools()).await;
    up.set_tools(&["alpha", "gamma"]);
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    assert_eq!(
        admin::catalog_tools(&w.owner, &id).await,
        vec!["alpha", "gamma"],
        "a refresh must replace the list with the upstream's current tools"
    );
    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter()
            .any(|row| row.kind == "tool_appeared" && row.tool == "gamma"),
        "the activity log must record that gamma appeared"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rules_can_only_name_real_tools() {
    let w = World::start().await;
    let (_up, id) = w.upstream("demo", two_tools()).await;
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "allow",
        "tool",
        Some(&id),
        Some("nope"),
    )
    .await;
    assert_eq!(
        page.status, 400,
        "a rule naming a tool the server does not list must be refused"
    );
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "allow",
        "tool",
        Some(&id),
        Some("alpha"),
    )
    .await;
    assert_eq!(
        page.status, 303,
        "a rule naming a listed tool must be saved"
    );
}

/// The (value, label) of each option in the rule form's tool list.
fn rule_tool_options(page: &common::client::Page) -> Vec<(String, String)> {
    let values = page.attrs("datalist#rule-tools option", "value");
    let labels = page.attrs("datalist#rule-tools option", "label");
    assert_eq!(
        values.len(),
        labels.len(),
        "every tool option of the rule form must carry a server label"
    );
    values.into_iter().zip(labels).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rule_form_offers_the_real_tools() {
    let w = World::start().await;
    let (up, id) = w.upstream("demo", two_tools()).await;
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    let page = w.owner.get("/admin/rules").await;
    assert_eq!(
        page.count(r#"input#rule-tool[list="rule-tools"]"#),
        1,
        "the tool name field of the rule form must read its options from rule-tools"
    );
    assert_eq!(
        rule_tool_options(&page),
        vec![
            ("alpha".into(), "demo".into()),
            ("beta".into(), "demo".into())
        ],
        "the rule form must offer the real tools, labelled with the server's path"
    );
    up.set_tools(&["alpha", "gamma"]);
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    let page = w.owner.get("/admin/rules").await;
    assert_eq!(
        rule_tool_options(&page),
        vec![
            ("alpha".into(), "demo".into()),
            ("gamma".into(), "demo".into())
        ],
        "after a refresh the rule form must offer the upstream's current tools"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rule_form_lists_every_servers_tools_by_slug_then_name() {
    let w = World::start().await;
    w.upstream("demo", two_tools()).await;
    w.upstream(
        "aaa",
        UpstreamOptions {
            tools: vec!["zeta".into()],
            ..Default::default()
        },
    )
    .await;
    let page = w.owner.get("/admin/rules").await;
    assert_eq!(
        rule_tool_options(&page),
        vec![
            ("zeta".into(), "aaa".into()),
            ("alpha".into(), "demo".into()),
            ("beta".into(), "demo".into()),
        ],
        "the rule form must list every server's tools ordered by server path, then tool name"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fetch_sends_the_secret_and_no_user_credential() {
    let w = World::start().await;
    let (up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    let lists: Vec<_> = up
        .requests()
        .into_iter()
        .filter(|request| request.rpc_method.as_deref() == Some("tools/list"))
        .collect();
    assert!(
        !lists.is_empty(),
        "the refresh must ask the upstream for its tool list"
    );
    let secret = secret_for("demo");
    for request in &lists {
        assert_eq!(
            request.header(SECRET_HEADER),
            Some(secret.as_str()),
            "the tool list fetch must carry the server's secret header"
        );
        assert!(
            request.header("authorization").is_none(),
            "the tool list fetch must not carry an authorization header"
        );
        assert!(
            request.header("cookie").is_none(),
            "the tool list fetch must not carry a cookie"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn markup_in_tool_names_is_escaped() {
    let name = "<img src=x onerror=alert(1)>";
    let w = World::start().await;
    let (_up, id) = w
        .upstream(
            "demo",
            UpstreamOptions {
                tools: vec![name.into()],
                ..Default::default()
            },
        )
        .await;
    let page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert!(
        !page.body.contains("<img src=x"),
        "the server page must escape tool names, but it contains the raw tag"
    );
    assert_eq!(
        admin::catalog_tools(&w.owner, &id).await,
        vec![name],
        "the tool name must read back unchanged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_tool_list_is_refused() {
    let w = World::start_with(|c| c.limits.tools_list_bytes = 2000).await;
    let tools: Vec<String> = (0..200).map(|i| format!("tool_{i:03}")).collect();
    let (_up, id) = w
        .upstream(
            "demo",
            UpstreamOptions {
                tools,
                ..Default::default()
            },
        )
        .await;
    let page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert!(
        page.error().is_some_and(|error| !error.is_empty()),
        "the server page must show an error for a tool list over the limit"
    );
    assert!(
        admin::catalog_tools(&w.owner, &id).await.is_empty(),
        "an oversized tool list must leave the catalog empty"
    );
    let health =
        w.gw.http
            .get(w.gw.url("/healthz"))
            .send()
            .await
            .expect("healthz request");
    assert_eq!(
        health.status(),
        reqwest::StatusCode::OK,
        "the gateway must stay up after an oversized tool list"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_refresh_keeps_the_old_list() {
    let w = World::start().await;
    let (mut up, id) = w.upstream("demo", two_tools()).await;
    up.shutdown().await;
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");
    let page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert!(
        page.error().is_some_and(|error| !error.is_empty()),
        "a failed refresh must show an error on the server page"
    );
    assert_eq!(
        admin::catalog_tools(&w.owner, &id).await,
        vec!["alpha", "beta"],
        "a failed refresh must keep the previous tools listed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_that_cannot_read_the_secret_is_recorded_as_failed() {
    let w = World::start().await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let server_id: i64 = id.parse().expect("a numeric server id");
    let tools_refreshed = |rows: &[(admin::ActivityRow, String)]| {
        rows.iter()
            .filter(|(row, detail)| row.kind == "admin_change" && detail == "tools refreshed")
            .count()
    };
    let before = tools_refreshed(&admin::activity_with_details(&w.owner, None, None).await);

    let conn = rusqlite::Connection::open(w.gw.db_path()).expect("open the database");
    conn.execute(
        "UPDATE servers SET secret_header_value = 'not a sealed value' WHERE id = ?1",
        [server_id],
    )
    .expect("replace the stored secret");
    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 303, "refreshing the tools must answer 303");

    let rows = admin::activity_with_details(&w.owner, None, None).await;
    let failed = rows
        .iter()
        .filter(|(row, detail)| {
            row.kind == "admin_change" && row.server == "demo" && detail == "tool refresh failed"
        })
        .count();
    assert_eq!(
        failed, 1,
        "a refresh whose secret cannot be read must be recorded as tool refresh failed"
    );
    assert_eq!(
        tools_refreshed(&rows),
        before,
        "a refresh whose secret cannot be read must not be recorded as tools refreshed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_tool_is_usable_without_a_manual_refresh() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (up, id) = w.upstream("demo", two_tools()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    let initialized = mcp.initialize().await;
    assert_eq!(initialized.status, 200, "initialize must answer 200");
    up.set_tools(&["alpha", "beta", "gamma"]);
    let before = up.rpc_count("tools/list");
    let reply = mcp.call_tool("gamma", json!({})).await;
    assert_eq!(
        reply.status, 200,
        "a tool added upstream must be callable at once"
    );
    assert_eq!(
        reply.text().as_deref(),
        Some("called: gamma"),
        "the call to the new tool must reach the upstream"
    );
    assert_eq!(
        up.rpc_count("tools/list") - before,
        1,
        "a miss on the catalog must refresh it exactly once"
    );
}
