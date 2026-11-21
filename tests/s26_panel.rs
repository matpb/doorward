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

const NAV: &str = r#"nav[data-nav="panel"]"#;
/// The panel links an owner sees, as (text, href), in the order of the navigation.
const OWNER_LINKS: [(&str, &str); 9] = [
    ("Overview", "/admin"),
    ("Users", "/admin/users"),
    ("Invitations", "/admin/invitations"),
    ("Servers", "/admin/servers"),
    ("Rules", "/admin/rules"),
    ("Redirects", "/admin/redirects"),
    ("Activity", "/admin/activity"),
    ("Mail", "/admin/mail"),
    ("Your account", "/account"),
];
/// The panel links an admin who is not the owner sees: the owner's list without Mail.
const ADMIN_LINKS: [(&str, &str); 8] = [
    ("Overview", "/admin"),
    ("Users", "/admin/users"),
    ("Invitations", "/admin/invitations"),
    ("Servers", "/admin/servers"),
    ("Rules", "/admin/rules"),
    ("Redirects", "/admin/redirects"),
    ("Activity", "/admin/activity"),
    ("Your account", "/account"),
];

/// One page carries exactly one panel navigation, in its header, with these links in this
/// order, and exactly one link marked as the current page: the one for `current`.
fn assert_panel_nav(path: &str, page: &Page, links: &[(&str, &str)], current: &str) {
    assert_eq!(
        page.count(NAV),
        1,
        "{path} must carry exactly one panel navigation"
    );
    assert_eq!(
        page.count(&format!("header[data-brand] {NAV}")),
        1,
        "{path} must put the panel navigation in its header"
    );
    let link = format!("{NAV} a");
    let shown: Vec<(String, String)> = page
        .texts(&link)
        .into_iter()
        .zip(page.attrs(&link, "href"))
        .collect();
    let wanted: Vec<(String, String)> = links
        .iter()
        .map(|(text, href)| (text.to_string(), href.to_string()))
        .collect();
    assert_eq!(shown, wanted, "{path} must list the panel links in order");
    assert_eq!(
        page.attrs(&format!(r#"{NAV} a[aria-current="page"]"#), "href"),
        vec![current.to_string()],
        "{path} must mark exactly its own section as the current page"
    );
}

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

#[tokio::test(flavor = "multi_thread")]
async fn every_panel_page_carries_the_navigation() {
    let w = World::start().await;
    w.user(BOB).await;
    let bob_id = w.user_id(BOB).await;
    let (_up, server_id) = w.upstream("demo", UpstreamOptions::default()).await;
    let cases: Vec<(String, &str)> = vec![
        ("/admin".into(), "/admin"),
        ("/admin/users".into(), "/admin/users"),
        (format!("/admin/users/{bob_id}"), "/admin/users"),
        ("/admin/invitations".into(), "/admin/invitations"),
        ("/admin/servers".into(), "/admin/servers"),
        (format!("/admin/servers/{server_id}"), "/admin/servers"),
        ("/admin/rules".into(), "/admin/rules"),
        ("/admin/redirects".into(), "/admin/redirects"),
        ("/admin/activity".into(), "/admin/activity"),
        ("/admin/mail".into(), "/admin/mail"),
    ];
    for (path, current) in cases {
        let page = w.owner.get(&path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 to the owner");
        assert_panel_nav(&path, &page, &OWNER_LINKS, current);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_sees_no_mail_link() {
    let w = World::start().await;
    let carol = w.admin(CAROL).await;
    let page = carol.get("/admin/users").await;
    assert_eq!(page.status, 200, "/admin/users must answer 200 to an admin");
    assert_panel_nav("/admin/users", &page, &ADMIN_LINKS, "/admin/users");
    assert_eq!(
        page.count(&format!(r#"{NAV} a[href="/admin/mail"]"#)),
        0,
        "an admin who is not the owner must not see the Mail link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_users_account_page_holds_one_link_and_public_pages_hold_none() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob.get("/admin/users").await;
    assert_eq!(page.status, 403, "/admin/users must refuse a plain user");
    assert_eq!(
        page.kind().as_deref(),
        Some("forbidden"),
        "a plain user's refusal must show the forbidden page"
    );
    assert_eq!(
        page.count("[data-nav]"),
        0,
        "the forbidden page must carry no navigation"
    );
    let account = bob.get("/account").await;
    assert_eq!(
        account.status, 200,
        "/account must answer 200 to a plain user"
    );
    assert_eq!(
        account.count(r#"header nav[data-nav="account"]"#),
        1,
        "a plain user's account page must carry its one account navigation in the header"
    );
    assert_eq!(
        account.count(r#"[data-nav="panel"]"#),
        0,
        "a plain user's account page must carry no panel navigation"
    );
    let anonymous = w.client();
    let invite = w.invite_link("dan@example.com", "user").await;
    let invite_path = invite.strip_prefix(w.base()).unwrap_or(invite.as_str());
    for path in ["/login", "/forgot", invite_path] {
        let page = anonymous.get(path).await;
        assert_eq!(page.status, 200, "{path} must answer 200 to a visitor");
        assert_eq!(
            page.count("[data-nav]"),
            0,
            "{path} must carry no navigation"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_account_page_links_to_the_panel_for_admins_only() {
    let w = World::start().await;
    let carol = w.admin(CAROL).await;
    let bob = w.user(BOB).await;
    for (who, browser) in [("the owner", &w.owner), ("an admin", &carol)] {
        let page = browser.get("/account").await;
        assert_eq!(page.status, 200, "/account must answer 200 to {who}");
        assert_eq!(
            page.attrs(r#"a[data-nav="to-panel"]"#, "href"),
            vec!["/admin".to_string()],
            "/account must link to the panel for {who}"
        );
        assert_eq!(
            page.texts(r#"a[data-nav="to-panel"]"#),
            vec!["Admin panel".to_string()],
            "the panel link on /account must read Admin panel for {who}"
        );
    }
    let page = bob.get("/account").await;
    assert_eq!(
        page.count(r#"a[data-nav="to-panel"]"#),
        0,
        "/account must not link to the panel for a plain user"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_form_keeps_the_navigation() {
    let w = World::start().await;
    let page = w
        .owner
        .submit(
            "/admin/servers",
            "/admin/servers",
            &[
                ("name", "probe"),
                ("slug", "Not A Slug!"),
                ("upstream_url", "http://127.0.0.1:9/mcp"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a bad path must refuse the server form with 400"
    );
    assert!(
        page.text(r#"[data-notice="error"]"#)
            .is_some_and(|error| !error.is_empty()),
        "the refused server form must show its error"
    );
    assert_panel_nav(
        "/admin/servers (refused form)",
        &page,
        &OWNER_LINKS,
        "/admin/servers",
    );
}
