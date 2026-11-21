mod common;

use common::admin::{self, ServerSpec};
use common::client::Page;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::World;

const ALERT: &str = r#"main div.notice[data-notice="error"][data-lockdown-alert]"#;

/// Adds a server whose upstream asks for no secret, and checks it: its lock-down state is open.
async fn open_server(w: &World, name: &str, slug: &str) -> (FakeUpstream, String) {
    let upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let spec = ServerSpec {
        name,
        slug,
        upstream_url: &url,
        secret: None,
        pass_resources: false,
        pass_prompts: false,
    };
    let id = admin::add_server(&w.owner, &spec).await;
    let refreshed = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(refreshed.status, 303, "refresh tools must answer 303");
    let checked = admin::check_lockdown(&w.owner, &id).await;
    assert_eq!(checked.status, 303, "the lock-down check must answer 303");
    assert_eq!(
        admin::lockdown(&w.owner, &id).await.as_deref(),
        Some("open"),
        "server {id} must hold the lock-down state open"
    );
    (upstream, id)
}

/// The link on the overview for the server `id`, to its lock-down part.
fn lockdown_link(id: &str) -> String {
    format!(r#"a[href="/admin/servers/{id}#lockdown-title"]"#)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_server_has_an_alert_on_its_own_page() {
    let w = World::start().await;
    let (_upstream, id) = open_server(&w, "Open Demo", "open-demo").await;
    let page: Page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert_eq!(page.status, 200, "the server page must answer 200");
    assert_eq!(
        page.attr("main", "data-lockdown").as_deref(),
        Some("open"),
        "the server page must carry data-lockdown open"
    );
    assert_eq!(
        page.count(ALERT),
        1,
        "the open server page must hold one alert with data-lockdown-alert"
    );
    let alert = page.text(ALERT).unwrap_or_default();
    assert!(
        alert.contains("This server answers without the gateway."),
        "the alert must say This server answers without the gateway., got {alert:?}"
    );
    assert_eq!(
        page.count(&format!("{ALERT} a[href=\"#lockdown-title\"]")),
        1,
        "the alert must link to #lockdown-title"
    );
    assert_eq!(
        page.count("#lockdown-title"),
        1,
        "the page must hold the element with id lockdown-title"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_names_one_exposed_server() {
    let w = World::start().await;
    let (_open, id) = open_server(&w, "Open Demo", "open-demo").await;
    let (_gated, _gated_id) = w.upstream("gated", UpstreamOptions::default()).await;
    let page = w.owner.get("/admin").await;
    assert_eq!(page.status, 200, "the overview must answer 200");
    let notice = r#"div.notice[data-notice="error"][data-open-servers="1"]"#;
    assert_eq!(
        page.count(notice),
        1,
        "the overview must hold one error notice with data-open-servers 1"
    );
    let text = page.text(notice).unwrap_or_default();
    assert!(
        text.contains("Open Demo answers without the gateway."),
        "the notice must name the server, got {text:?}"
    );
    assert_eq!(
        page.count(&format!("{notice} {}", lockdown_link(&id))),
        1,
        "the notice must link to the lock-down part of Open Demo"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_counts_two_exposed_servers() {
    let w = World::start().await;
    let (_first, first) = open_server(&w, "Open Demo", "open-demo").await;
    let (_second, second) = open_server(&w, "Staging Mirror", "staging-mirror").await;
    let page = w.owner.get("/admin").await;
    assert_eq!(page.status, 200, "the overview must answer 200");
    let notice = r#"div.notice[data-notice="error"][data-open-servers="2"]"#;
    assert_eq!(
        page.count(notice),
        1,
        "the overview must hold one error notice with data-open-servers 2"
    );
    let text = page.text(notice).unwrap_or_default();
    assert!(
        text.contains("2 servers answer without the gateway."),
        "the notice must count the servers, got {text:?}"
    );
    for (id, name) in [(&first, "Open Demo"), (&second, "Staging Mirror")] {
        assert_eq!(
            page.count(&format!("{notice} {}", lockdown_link(id))),
            1,
            "the notice must link {name} to its lock-down part"
        );
        assert_eq!(
            page.text(&format!("{notice} {}", lockdown_link(id)))
                .as_deref(),
            Some(name),
            "the link to the lock-down part of {id} must read the server's name"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_alert_without_an_exposed_server() {
    let w = World::start().await;
    let (_gated, id) = w.upstream("gated", UpstreamOptions::default()).await;
    let checked = admin::check_lockdown(&w.owner, &id).await;
    assert_eq!(checked.status, 303, "the lock-down check must answer 303");
    assert_eq!(
        admin::lockdown(&w.owner, &id).await.as_deref(),
        Some("ok"),
        "a server that refuses without the secret must hold the lock-down state ok"
    );
    let overview = w.owner.get("/admin").await;
    assert_eq!(
        overview.count("[data-open-servers]"),
        0,
        "the overview must hold no exposed-server notice with no open server"
    );
    let page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert_eq!(
        page.count("[data-lockdown-alert]"),
        0,
        "a locked-down server's page must hold no lock-down alert"
    );
}
