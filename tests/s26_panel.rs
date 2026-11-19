mod common;

use common::admin;
use common::client::{Page, TestClient};
use common::upstream::UpstreamOptions;
use common::world::{APP_NAME, World};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const PAGES: [(&str, &str); 8] = [
    ("/admin", "admin"),
    ("/admin/servers", "servers"),
    ("/admin/users", "users"),
    ("/admin/invitations", "invitations"),
    ("/admin/rules", "rules"),
    ("/admin/redirects", "redirects"),
    ("/admin/mail", "mail"),
    ("/admin/activity", "activity"),
];
const SERVER: &[(&str, &str)] = &[
    ("name", "probe"),
    ("slug", "probe"),
    ("upstream_url", "http://127.0.0.1:9/mcp"),
];

/// Every page the security tests cover, each fetched by a browser that may open it.
async fn covered_pages(w: &World) -> Vec<(&'static str, Page)> {
    let anonymous = w.client();
    let mut pages = Vec::new();
    for path in ["/login", "/forgot"] {
        let page = anonymous.get(path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 to a visitor");
        pages.push((path, page));
    }
    let account = w.owner.get("/account").await;
    assert_eq!(account.status, 200, "/account must answer 200 to the owner");
    pages.push(("/account", account));
    for (path, _) in PAGES {
        let page = w.owner.get(path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 to the owner");
        pages.push((path, page));
    }
    pages
}

/// The family id of the connected client named like the test app on the account page.
async fn app_family(browser: &TestClient) -> String {
    let page = browser.get("/account").await;
    page.attr(
        &format!(r#"[data-client-name="{APP_NAME}"][data-family]"#),
        "data-family",
    )
    .unwrap_or_else(|| panic!("/account must list the connected client {APP_NAME}"))
}

/// The server form fields, with the csrf value first when one is given.
fn server_form(csrf: Option<&str>) -> Vec<(&str, &str)> {
    let mut fields: Vec<(&str, &str)> = csrf.map(|token| ("csrf", token)).into_iter().collect();
    fields.extend_from_slice(SERVER);
    fields
}

#[tokio::test(flavor = "multi_thread")]
async fn every_page_renders_for_the_owner() {
    let w = World::start().await;
    for (path, kind) in PAGES {
        let page = w.owner.get(path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 to the owner");
        assert_eq!(
            page.kind().as_deref(),
            Some(kind),
            "{path} must carry data-page {kind}"
        );
        assert!(
            page.body.contains("<html lang=\"en\">"),
            "{path} must declare the page language as English"
        );
        assert!(
            page.count(r#"meta[name="viewport"]"#) > 0,
            "{path} must carry a viewport meta tag"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_visitors_are_sent_to_sign_in() {
    let w = World::start().await;
    let anonymous = w.client();
    for (path, _) in PAGES {
        let page = anonymous.get(path).await;
        assert_eq!(
            page.status, 303,
            "{path} must redirect an anonymous visitor"
        );
        assert_eq!(
            page.location().as_deref(),
            Some("/login"),
            "{path} must send an anonymous visitor to /login"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_users_are_refused() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    for (path, _) in PAGES {
        let page = bob.get(path).await;
        assert_eq!(page.status, 403, "{path} must refuse a plain user");
        assert_eq!(
            page.kind().as_deref(),
            Some("forbidden"),
            "{path} must show the forbidden page to a plain user"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_owner_changes_roles() {
    let w = World::start().await;
    let admin_browser = w.admin(CAROL).await;
    let bob = w.user(BOB).await;
    let bob_id = w.user_id(BOB).await;
    let page = admin::set_role(&admin_browser, &bob_id, "admin").await;
    assert_eq!(page.status, 403, "an admin must not change roles");
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "an admin's role change must show the forbidden page"
    );
    let page = admin::set_role(&w.owner, &bob_id, "admin").await;
    assert_eq!(page.status, 303, "the owner must change roles");
    let page = bob.get("/admin").await;
    assert_eq!(
        page.status, 200,
        "a user promoted by the owner must reach /admin"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn account_page_lists_and_disconnects_clients() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let family = app_family(&bob).await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "the token must work before the disconnect"
    );
    let page = bob
        .submit(
            "/account",
            &format!("/account/clients/{family}/disconnect"),
            &[],
        )
        .await;
    assert_eq!(page.status, 303, "disconnecting a client must answer 303");
    let after = w.session_mcp("demo", &tokens);
    assert_eq!(
        after.initialize().await.status,
        401,
        "a disconnected client's token must be refused"
    );
    let account = bob.get("/account").await;
    assert_eq!(
        account.status, 200,
        "/account must answer 200 after the disconnect"
    );
    assert_eq!(
        account.count(&format!(r#"[data-family="{family}"]"#)),
        0,
        "a disconnected client must leave the account page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_cannot_disconnect_someone_elses_client() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let carol = w.user(CAROL).await;
    let (_up, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let family = app_family(&bob).await;
    let page = carol
        .submit(
            "/account",
            &format!("/account/clients/{family}/disconnect"),
            &[],
        )
        .await;
    assert!(
        page.status == 404 || page.status == 403,
        "another user's client must not be disconnected, got status {}",
        page.status
    );
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    assert_eq!(
        mcp.list_tools().await.status,
        200,
        "bob's token must still work after carol's attempt"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_page_sends_the_security_headers() {
    let w = World::start().await;
    for (path, page) in covered_pages(&w).await {
        let policy = page.header("content-security-policy").unwrap_or_default();
        assert!(
            policy.contains("default-src 'none'"),
            "{path} must send default-src 'none', got {policy:?}"
        );
        assert!(
            policy.contains("frame-ancestors 'none'"),
            "{path} must send frame-ancestors 'none', got {policy:?}"
        );
        assert_eq!(
            page.header("x-frame-options").as_deref(),
            Some("DENY"),
            "{path} must send x-frame-options DENY"
        );
        assert_eq!(
            page.header("x-content-type-options").as_deref(),
            Some("nosniff"),
            "{path} must send x-content-type-options nosniff"
        );
        assert!(
            page.header("cache-control")
                .unwrap_or_default()
                .contains("no-store"),
            "{path} must send cache-control no-store"
        );
        assert_eq!(
            page.header("referrer-policy").as_deref(),
            Some("same-origin"),
            "{path} must send referrer-policy same-origin"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_carry_no_script() {
    let w = World::start().await;
    for (path, page) in covered_pages(&w).await {
        assert!(
            !page.body.contains("<script"),
            "{path} must carry no script element"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_post_form_carries_the_token() {
    let w = World::start().await;
    for (path, page) in covered_pages(&w).await {
        let forms = page.count("form[method=post]");
        let tokens = page.count("form[method=post] input[name=csrf]");
        if matches!(path, "/login" | "/forgot" | "/account") {
            assert!(forms > 0, "{path} must hold a POST form");
        }
        assert_eq!(
            forms, tokens,
            "every POST form on {path} must carry the anti-forgery token"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn panel_posts_need_csrf_and_origin() {
    let w = World::start().await;
    let other = w.admin(CAROL).await;
    let other_csrf = other
        .get("/admin/servers")
        .await
        .csrf()
        .expect("the servers page must carry a csrf token");
    let owner_csrf = w
        .owner
        .get("/admin/servers")
        .await
        .csrf()
        .expect("the servers page must carry a csrf token");
    let foreign = [("Origin", "https://evil.example.com")];
    let no_origin = [("Origin", "")];

    let attempts = [
        (
            "without csrf",
            w.owner.post("/admin/servers", &server_form(None)).await,
        ),
        (
            "with another session's csrf",
            w.owner
                .post("/admin/servers", &server_form(Some(&other_csrf)))
                .await,
        ),
        (
            "with a foreign origin",
            w.owner
                .post_with("/admin/servers", &server_form(Some(&owner_csrf)), &foreign)
                .await,
        ),
        (
            "with no origin",
            w.owner
                .post_with(
                    "/admin/servers",
                    &server_form(Some(&owner_csrf)),
                    &no_origin,
                )
                .await,
        ),
    ];
    for (case, page) in attempts {
        assert_eq!(page.status, 403, "a panel post {case} must be refused");
        assert_eq!(
            page.kind().as_deref(),
            Some("forbidden"),
            "a panel post {case} must show the forbidden page"
        );
    }
    assert!(
        admin::server_id(&w.owner, "probe").await.is_none(),
        "no refused post may create a server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stylesheet_is_served_from_the_gateway() {
    let w = World::start().await;
    let page = w.owner.get("/admin").await;
    let href = page
        .attr(r#"link[rel=stylesheet]"#, "href")
        .expect("the admin page must link a stylesheet");
    let path = href.strip_prefix(w.base()).unwrap_or(href.as_str());
    assert!(
        path.starts_with("/assets/"),
        "the stylesheet must be served under /assets/, got {href:?}"
    );
    let asset = w.owner.get(path).await;
    assert_eq!(asset.status, 200, "the stylesheet must answer 200");
    assert!(
        asset
            .header("content-type")
            .unwrap_or_default()
            .starts_with("text/css"),
        "the stylesheet must be served as text/css"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_have_no_outside_resources() {
    let w = World::start().await;
    let base = w.base().to_string();
    let own_prefix = format!("{base}/");
    for (path, page) in covered_pages(&w).await {
        let mut urls = page.attrs("[src]", "src");
        urls.extend(page.attrs("[href]", "href"));
        for url in urls {
            let outside = (url.starts_with("http://") || url.starts_with("https://"))
                && url != base
                && !url.starts_with(&own_prefix);
            assert!(
                !outside,
                "{path} must not load or link {url}, which is outside the gateway"
            );
        }
    }
}
