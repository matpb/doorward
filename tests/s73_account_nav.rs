mod common;

use common::admin;
use common::client::{Page, TestClient};
use common::mail::Fail;
use common::world::World;
use scraper::{Html, Selector};

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
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

/// The (text, href) of each link in the panel navigation of `page`, in order.
fn panel_links(page: &Page) -> Vec<(String, String)> {
    page.texts("nav#panel-nav a")
        .into_iter()
        .zip(page.attrs("nav#panel-nav a", "href"))
        .collect()
}

/// The links of a list as the (text, href) pairs `panel_links` returns.
fn wanted(links: &[(&str, &str)]) -> Vec<(String, String)> {
    links
        .iter()
        .map(|(text, href)| (text.to_string(), href.to_string()))
        .collect()
}

/// The account page of an owner or admin is a panel page marked on Your account.
async fn assert_panel_account(who: &str, browser: &TestClient, links: &[(&str, &str)]) {
    let page = browser.get("/account").await;
    assert_eq!(page.status, 200, "/account must answer 200 to {who}");
    assert_eq!(
        page.attr("body", "data-layout").as_deref(),
        Some("panel"),
        "the account page of {who} must carry body data-layout panel"
    );
    assert_eq!(
        page.count(r#"header[data-brand] > div.site-bar > a.brand[href="/admin"]"#),
        1,
        "the account page of {who} must link its brand to /admin"
    );
    assert_eq!(
        page.count("nav#panel-nav"),
        1,
        "the account page of {who} must hold nav#panel-nav"
    );
    assert_eq!(
        panel_links(&page),
        wanted(links),
        "the account page of {who} must list the panel links in order"
    );
    let panel = browser.get("/admin").await;
    assert_eq!(
        panel_links(&page),
        panel_links(&panel),
        "the account page of {who} must list the same links as the panel"
    );
    assert_eq!(
        page.count(r#"[aria-current="page"]"#),
        1,
        "the account page of {who} must mark exactly one link as current"
    );
    assert_eq!(
        page.attrs(r#"[aria-current="page"]"#, "href"),
        vec!["/account".to_string()],
        "the one marked link of the account page of {who} must be Your account"
    );
    assert_eq!(
        page.count(r#"nav#panel-nav li.nav-end > a[href="/account"][aria-current="page"]"#),
        1,
        "Your account must be the last item of the panel of {who} and the marked one"
    );
    assert_eq!(
        page.count("#account-nav"),
        0,
        "the account page of {who} must hold no #account-nav"
    );
    assert!(
        !page.texts("a").iter().any(|text| text == "Admin panel"),
        "the account page of {who} must hold no link reading Admin panel"
    );
}

/// The refused page links to the start page, once, after its lede.
fn assert_start_link(page: &Page, what: &str) {
    assert_eq!(
        page.count(r#"p.back a[href="/"]"#),
        1,
        "{what} must hold one p.back link to /"
    );
    assert_eq!(
        page.texts(r#"p.back a[href="/"]"#),
        vec!["Go to the start page".to_string()],
        "{what} must read Go to the start page in its link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owners_account_page_is_a_panel_page_marked_on_your_account() {
    let w = World::start().await;
    assert_panel_account("the owner", &w.owner, &OWNER_LINKS).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admins_account_page_is_a_panel_page_marked_on_your_account() {
    let w = World::start().await;
    let carol = w.admin(CAROL).await;
    assert_panel_account("an admin", &carol, &ADMIN_LINKS).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_users_account_page_holds_one_link_and_no_panel_link() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let page = bob.get("/account").await;
    assert_eq!(page.status, 200, "/account must answer 200 to a plain user");
    assert_eq!(
        page.attr("body", "data-layout").as_deref(),
        Some("page"),
        "a plain user's account page must carry body data-layout page"
    );
    assert_eq!(
        page.count("nav#panel-nav"),
        0,
        "a plain user's account page must hold no nav#panel-nav"
    );
    assert_eq!(
        page.count(r#"a[href^="/admin"]"#),
        0,
        "a plain user's account page must link to no /admin path"
    );
    assert_eq!(
        page.texts(r#"header[data-brand] nav[data-nav="account"] a"#),
        vec!["Your account".to_string()],
        "a plain user's account page must hold one link, Your account"
    );
    assert_eq!(
        page.count(".menu-button"),
        0,
        "a plain user's account page must hold no Menu button"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_user_refused_a_panel_page_links_to_the_start_page() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let refused = bob.get("/admin").await;
    assert_eq!(
        refused.status, 403,
        "a plain user's GET /admin must answer 403"
    );
    assert_eq!(
        refused.kind().as_deref(),
        Some("forbidden"),
        "a plain user's GET /admin must show the refusal page"
    );
    assert_eq!(
        refused.text("main h1").as_deref(),
        Some("Request refused"),
        "the refusal page must say Request refused"
    );
    assert_start_link(&refused, "the refusal page of a plain user's GET /admin");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_form_post_links_to_the_start_page() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let refused = bob
        .post(
            "/admin/invitations",
            &[("email", "dan@example.com"), ("role", "user")],
        )
        .await;
    assert_eq!(
        refused.status, 403,
        "a form post without the anti-forgery token must answer 403"
    );
    assert_eq!(
        refused.kind().as_deref(),
        Some("forbidden"),
        "a refused form post must show the refusal page"
    );
    assert_start_link(&refused, "the refusal page of a refused form post");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_too_many_requests_page_holds_no_link_in_its_main() {
    let mut w = World::start().await;
    w.tighten(|config| config.limits.general_burst = 2).await;
    let anonymous = w.client();
    let browser = [("accept", "text/html")];
    for _ in 0..2 {
        anonymous.get_with("/login", &browser).await;
    }
    let limited = anonymous.get_with("/login", &browser).await;
    assert_eq!(
        limited.status, 429,
        "a request over the limit must answer 429"
    );
    assert_eq!(
        limited.text("main h1").as_deref(),
        Some("Too many requests"),
        "the limited page must say Too many requests"
    );
    assert_eq!(
        limited.count("main a"),
        0,
        "the limited page must hold no link in main"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_not_sent_shows_its_link_in_a_labelled_field() {
    let w = World::start().await;
    w.mail.fail_next(Fail::SmtpReject);
    let page = admin::invite(&w.owner, BOB, "user").await;
    assert_eq!(
        page.kind().as_deref(),
        Some("invitation-created"),
        "a failed invitation mail must show the invitation-created page"
    );
    let link = page
        .attr("[data-invite-link]", "data-invite-link")
        .unwrap_or_default();
    assert!(
        link.starts_with(&format!("{}/invite/", w.base())),
        "the invitation link must start with the gateway's address, got {link:?}"
    );
    assert_eq!(
        page.text("span.label#invite-link-label").as_deref(),
        Some("Invitation link"),
        "the label of the link must read Invitation link"
    );
    assert_eq!(
        page.count(
            r#"div.fields.narrow > div.field[role="group"][aria-labelledby="invite-link-label"] > code.copy[data-invite-link]"#
        ),
        1,
        "the link must sit in a labelled group field inside div.fields.narrow"
    );
    assert_eq!(
        page.count("code.copy > span"),
        2,
        "the link must be cut into two spans, origin and path"
    );
    assert_eq!(
        page.count("code.copy > wbr"),
        1,
        "the two spans must be divided by one wbr"
    );
    assert_eq!(
        page.count(r#"div.form-actions > a.button[href="/admin/invitations"]"#),
        1,
        "the way back must sit in div.form-actions"
    );
    let doc = Html::parse_document(&page.body);
    let code = doc
        .select(&Selector::parse("code.copy[data-invite-link]").expect("selector"))
        .next()
        .expect("the link code");
    let text: String = code.text().collect();
    assert_eq!(text, link, "the code must hold the link byte for byte");
    assert!(
        code.children().all(|child| child.value().is_element()),
        "no text node may sit directly inside the link code"
    );
    assert_eq!(
        page.text("code.copy > span:first-child").as_deref(),
        Some(w.base()),
        "the first span must hold the origin of the link"
    );
    let path = page.text("code.copy > span:last-child").unwrap_or_default();
    assert!(
        path.starts_with("/invite/"),
        "the second span must hold the path from its slash on, got {path:?}"
    );
    assert_eq!(
        page.count("code.copy > span:last-child wbr"),
        0,
        "the path must hold no wbr"
    );
}
