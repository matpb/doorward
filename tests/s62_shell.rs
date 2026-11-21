mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use common::TestGateway;
use common::client::{self, OAuthApp, Page, TestClient};
use common::mail::link_with_prefix;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{APP_ID, APP_NAME, World};
use scraper::{ElementRef, Html, Selector};

const BOB: &str = "bob@example.com";
const ADA: &str = "ada@example.com";
const DAVE: &str = "dave@example.com";
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
const CARD: &str = "card";
const PANEL: &str = "panel";
const PAGE: &str = "page";
const HEADER: &str = "body > header.site[data-brand]";
const NOTE: &str = "body > header.site[data-brand] > p.site-note";
const DARK_MEDIA: &str = "@media (prefers-color-scheme: dark)";
const MOTION: &str = "@media (prefers-reduced-motion: no-preference)";
const REDUCED: &str = "@media (prefers-reduced-motion: reduce)";
const TOUCH: &str = "@media (pointer: coarse), (max-width: 639.98px)";
/// The panel links for the owner, in order: label, href, and the class its item carries.
const PANEL_ITEMS: [(&str, &str, &str); 9] = [
    ("Overview", "/admin", ""),
    ("Users", "/admin/users", "nav-break"),
    ("Invitations", "/admin/invitations", ""),
    ("Servers", "/admin/servers", "nav-break"),
    ("Rules", "/admin/rules", ""),
    ("Redirects", "/admin/redirects", ""),
    ("Activity", "/admin/activity", "nav-break"),
    ("Mail", "/admin/mail", ""),
    ("Your account", "/account", "nav-end"),
];
/// (text colour, background colour) pairs that must reach 4.5 to 1 in both themes.
const TEXT_PAIRS: [(&str, &str); 19] = [
    ("--ink", "--paper"),
    ("--ink", "--surface"),
    ("--ink", "--sunken"),
    ("--ink-2", "--paper"),
    ("--ink-2", "--surface"),
    ("--ink-2", "--sunken"),
    ("--ink-3", "--paper"),
    ("--ink-3", "--surface"),
    ("--ink-3", "--sunken"),
    ("--ink", "--deny-wash"),
    ("--ink", "--warn-wash"),
    ("--ink", "--allow-wash"),
    ("--ink-2", "--deny-wash"),
    ("--ink-2", "--warn-wash"),
    ("--ink-2", "--allow-wash"),
    ("--on-door", "--door"),
    ("--on-door-2", "--door"),
    ("--on-deny", "--deny"),
    ("--paper", "--ink"),
];
/// (colour, background) pairs that must reach 3 to 1 in both themes.
const NON_TEXT_PAIRS: [(&str, &str); 8] = [
    ("--allow", "--paper"),
    ("--allow", "--surface"),
    ("--deny", "--paper"),
    ("--deny", "--surface"),
    ("--warn", "--paper"),
    ("--warn", "--surface"),
    ("--line-strong", "--paper"),
    ("--line-strong", "--surface"),
];
const MOTION_NAMES: [&str; 4] = ["door", "brand", "nav-mark", "room"];
const SIZE_PROPERTIES: [&str; 4] = ["min-block-size", "block-size", "height", "min-height"];

/// A page the shell tests read: its layout, and the href of the link its current mark belongs to.
struct Shot {
    name: String,
    page: Page,
    layout: &'static str,
    current: &'static str,
}

/// The world the covered pages are read from.
struct Seeded {
    w: World,
    bob: TestClient,
    admin: TestClient,
    demo: String,
    bob_id: String,
    dave_link: String,
    _upstream: FakeUpstream,
}

/// One declaration with the at-rules and the selector around it.
struct Decl {
    ancestors: Vec<String>,
    selector: String,
    name: String,
    value: String,
}

/// Collapses runs of whitespace into single spaces.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn text_of(element: ElementRef<'_>) -> String {
    collapse(&element.text().collect::<String>())
}

/// Every element under `root` matching `css`, in document order.
fn all<'a>(root: ElementRef<'a>, css: &str) -> Vec<ElementRef<'a>> {
    let selector =
        Selector::parse(css).unwrap_or_else(|err| panic!("bad selector {css:?}: {err:?}"));
    root.select(&selector).collect()
}

/// Panics unless the status is `status`; the name says which page is meant.
fn shot(name: &str, page: Page, status: u16, layout: &'static str, current: &'static str) -> Shot {
    assert_eq!(
        page.status, status,
        "{name} must answer {status}, got {}",
        page.status
    );
    Shot {
        name: name.to_string(),
        page,
        layout,
        current,
    }
}

/// True when the header of the page comes before its main element in document order.
fn header_precedes_main(body: &str) -> bool {
    let doc = Html::parse_document(body);
    let mut header_at = None;
    let mut main_at = None;
    for (index, node) in doc.root_element().descendants().enumerate() {
        if let Some(element) = node.value().as_element() {
            if element.name() == "main" && main_at.is_none() {
                main_at = Some(index);
            }
            if element.name() == "header" && element.attr("data-brand").is_some() {
                header_at.get_or_insert(index);
            }
        }
    }
    matches!((header_at, main_at), (Some(header), Some(main)) if header < main)
}

/// The seeded world: one server `demo` with bob granted, an admin, an open invitation for dave.
async fn seeded() -> Seeded {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let admin = w.admin(ADA).await;
    let (upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let bob_id = w.user_id(BOB).await;
    let dave_link = w.invite_link(DAVE, "user").await;
    Seeded {
        w,
        bob,
        admin,
        demo,
        bob_id,
        dave_link,
        _upstream: upstream,
    }
}

/// The reset link mailed to `address`, waiting up to five seconds for the mail.
async fn reset_link(w: &World, address: &str) -> String {
    let prefix = format!("{}/reset/", w.base());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = w
            .mail
            .to(address)
            .iter()
            .rev()
            .find_map(|message| link_with_prefix(&message.text, &prefix));
        if let Some(link) = found {
            return link;
        }
        assert!(
            Instant::now() < deadline,
            "no mail with a reset link under {prefix} reached {address} within 5 seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The consent page for `app`, reached the way a signed-in browser reaches it.
async fn consent_page(browser: &TestClient, app: &OAuthApp, resource: &str) -> Page {
    let authorized = browser
        .authorize(app, resource, &client::pkce(), "state-62")
        .await;
    assert_eq!(
        authorized.status, 303,
        "authorize must answer 303 for a signed-in user"
    );
    let req = authorized
        .query("req")
        .expect("the consent redirect must carry req");
    browser.get(&format!("/oauth/consent?req={req}")).await
}

/// Every page the shell tests cover, each with the layout and current link it must carry.
async fn covered(s: &Seeded) -> Vec<Shot> {
    let w = &s.w;
    let anonymous = w.client();
    let mut shots = vec![
        shot("/login", anonymous.get("/login").await, 200, CARD, ""),
        shot("/forgot", anonymous.get("/forgot").await, 200, CARD, ""),
        shot(
            "/account (owner)",
            w.owner.get("/account").await,
            200,
            PAGE,
            "/account",
        ),
        shot(
            "/account (admin)",
            s.admin.get("/account").await,
            200,
            PAGE,
            "/account",
        ),
        shot(
            "/account (bob)",
            s.bob.get("/account").await,
            200,
            PAGE,
            "/account",
        ),
    ];
    let panel = [
        ("/admin".to_string(), "/admin"),
        ("/admin/servers".to_string(), "/admin/servers"),
        (format!("/admin/servers/{}", s.demo), "/admin/servers"),
        ("/admin/users".to_string(), "/admin/users"),
        (format!("/admin/users/{}", s.bob_id), "/admin/users"),
        ("/admin/invitations".to_string(), "/admin/invitations"),
        ("/admin/rules".to_string(), "/admin/rules"),
        ("/admin/redirects".to_string(), "/admin/redirects"),
        ("/admin/mail".to_string(), "/admin/mail"),
        ("/admin/activity".to_string(), "/admin/activity"),
    ];
    for (path, current) in panel {
        let page = w.owner.get(&path).await;
        shots.push(shot(&path, page, 200, PANEL, current));
    }

    let local = consent_page(&s.bob, &w.app(), &w.resource("demo")).await;
    shots.push(shot("consent (local client)", local, 200, CARD, ""));
    w.gw.cimd().put(APP_ID, APP_NAME, &[CLAUDE_CALLBACK]);
    let web = OAuthApp {
        client_id: APP_ID.into(),
        redirect_uri: CLAUDE_CALLBACK.into(),
    };
    let web_page = consent_page(&s.bob, &web, &w.resource("demo")).await;
    shots.push(shot("consent (web client)", web_page, 200, CARD, ""));

    let invite = anonymous.get(&s.dave_link).await;
    shots.push(shot("invitation acceptance", invite, 200, CARD, ""));

    let forgot = anonymous
        .submit("/forgot", "/forgot", &[("email", BOB)])
        .await;
    assert_eq!(forgot.status, 200, "a reset request must answer 200");
    let reset = reset_link(w, BOB).await;
    let reset_page = anonymous.get(&reset).await;
    shots.push(shot("choose a new password", reset_page, 200, CARD, ""));

    let refused = s.bob.get("/admin").await;
    shots.push(shot("/admin for a plain user", refused, 403, CARD, ""));
    let missing = anonymous.get("/invite/not-a-real-token").await;
    shots.push(shot("the link is not valid", missing, 404, CARD, ""));
    shots
}

/// The page an unknown address answers with.
async fn not_found(s: &Seeded) -> Shot {
    let page = s.w.client().get("/no/such/page").await;
    shot("/no/such/page", page, 404, CARD, "")
}

/// The panel items of the navigation, in order, as the owner or an admin sees them.
fn assert_panel_items(page: &Page, who: &str, owner: bool) {
    let doc = Html::parse_document(&page.body);
    let items = all(
        doc.root_element(),
        &format!("{HEADER} nav#panel-nav > ul > li"),
    );
    let want: Vec<(&str, &str, &str)> = PANEL_ITEMS
        .iter()
        .copied()
        .filter(|item| owner || item.0 != "Mail")
        .collect();
    assert_eq!(
        items.len(),
        want.len(),
        "the panel navigation seen by {who} must list {} links, got {}",
        want.len(),
        items.len()
    );
    for (item, (label, href, class)) in items.into_iter().zip(want) {
        let links = all(item, "a");
        assert_eq!(
            links.len(),
            1,
            "each panel item seen by {who} holds one link"
        );
        assert_eq!(
            text_of(links[0]),
            label,
            "a panel link seen by {who} must read {label}"
        );
        assert_eq!(
            links[0].value().attr("href"),
            Some(href),
            "the panel link {label} seen by {who} must go to {href}"
        );
        let got = item.value().attr("class").unwrap_or("");
        assert_eq!(
            collapse(got),
            class,
            "the panel item {label} seen by {who} must carry class {class:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_page_holds_the_site_header_and_its_layout() {
    let s = seeded().await;
    let mut shots = covered(&s).await;
    shots.push(not_found(&s).await);
    for shot in shots {
        let page = &shot.page;
        assert_eq!(
            page.count(HEADER),
            1,
            "{} must hold one body > header.site[data-brand]",
            shot.name
        );
        let brand = page.text(HEADER).unwrap_or_default();
        assert!(
            brand.contains("Doorward"),
            "the header of {} must name Doorward, got {brand:?}",
            shot.name
        );
        assert!(
            header_precedes_main(&page.body),
            "the header of {} must come before main",
            shot.name
        );
        assert_eq!(
            page.attr("body", "data-layout").as_deref(),
            Some(shot.layout),
            "{} must carry body data-layout {}",
            shot.name,
            shot.layout
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_not_found_page_is_a_full_card_page() {
    let s = seeded().await;
    let page = s.w.client().get("/no/such/page").await;
    assert_eq!(page.status, 404, "an unknown address must answer 404");
    assert_eq!(
        page.count(HEADER),
        1,
        "the not-found page must hold one body > header.site[data-brand]"
    );
    let brand = page.text(HEADER).unwrap_or_default();
    assert!(
        brand.contains("Doorward"),
        "the not-found header must name Doorward, got {brand:?}"
    );
    assert_eq!(
        page.attr("body", "data-layout").as_deref(),
        Some(CARD),
        "the not-found page must carry body data-layout card"
    );
    assert_eq!(
        page.attr("main", "data-page").as_deref(),
        Some("not-found"),
        "the not-found page must hold main data-page not-found"
    );
    assert_eq!(
        page.text("main h1").as_deref(),
        Some("Page not found"),
        "the not-found page must say Page not found in its h1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_panel_page_holds_the_navigation_in_its_header() {
    let s = seeded().await;
    for shot in covered(&s).await.iter().filter(|shot| shot.layout == PANEL) {
        let page = &shot.page;
        assert_eq!(
            page.count(&format!(
                r#"{HEADER} > div.site-bar > a.brand[href="/admin"]"#
            )),
            1,
            "{} must hold a.brand to /admin in the site bar of its header",
            shot.name
        );
        assert_eq!(
            page.count(&format!(
                r#"{HEADER} nav#panel-nav[data-nav="panel"][aria-label="Admin"][popover]"#
            )),
            1,
            "{} must hold nav#panel-nav with data-nav panel, aria-label Admin and popover in its header",
            shot.name
        );
        assert_eq!(
            page.count("nav"),
            1,
            "{} must hold one nav, in its header",
            shot.name
        );
        assert_eq!(
            page.count("main nav"),
            0,
            "{} must keep no navigation inside main",
            shot.name
        );
        assert_panel_items(page, &shot.name, true);
    }
    let admin_page = s.admin.get("/admin").await;
    assert_eq!(admin_page.status, 200, "the admin must reach /admin");
    assert_panel_items(&admin_page, "an admin", false);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_current_section_is_marked_once() {
    let s = seeded().await;
    for shot in covered(&s).await {
        let doc = Html::parse_document(&shot.page.body);
        let marks = all(doc.root_element(), "span.nav-mark");
        if shot.current.is_empty() {
            assert!(
                marks.is_empty(),
                "{} has no current section and must hold no span.nav-mark",
                shot.name
            );
            continue;
        }
        assert_eq!(
            marks.len(),
            1,
            "{} must hold exactly one span.nav-mark, got {}",
            shot.name,
            marks.len()
        );
        assert_eq!(
            marks[0].value().attr("aria-hidden"),
            Some("true"),
            "the span.nav-mark of {} must be aria-hidden",
            shot.name
        );
        let link = marks[0]
            .parent()
            .and_then(ElementRef::wrap)
            .unwrap_or_else(|| panic!("the span.nav-mark of {} must sit in a link", shot.name));
        assert_eq!(
            link.value().name(),
            "a",
            "the span.nav-mark of {} must sit in an a element",
            shot.name
        );
        assert_eq!(
            link.value().attr("href"),
            Some(shot.current),
            "the span.nav-mark of {} must sit in the link to {}",
            shot.name,
            shot.current
        );
        assert_eq!(
            link.value().attr("aria-current"),
            Some("page"),
            "the marked link of {} must carry aria-current page",
            shot.name
        );
        assert_eq!(
            all(doc.root_element(), "a[aria-current]").len(),
            1,
            "{} must hold exactly one link with aria-current",
            shot.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_account_page_holds_its_own_navigation() {
    let s = seeded().await;
    for (who, browser) in [("the owner", &s.w.owner), ("an admin", &s.admin)] {
        let page = browser.get("/account").await;
        assert_eq!(
            page.status, 200,
            "the account page must answer 200 for {who}"
        );
        assert_eq!(
            page.count(&format!(
                r#"{HEADER} nav#account-nav[data-nav="account"][aria-label="Account"]"#
            )),
            1,
            "the account page of {who} must hold nav#account-nav in its header"
        );
        assert_eq!(
            page.count(&format!(
                r#"{HEADER} > div.site-bar > a.brand[href="/account"]"#
            )),
            1,
            "the account page of {who} must hold a.brand to /account"
        );
        assert_eq!(
            page.text(r#"#account-nav a[href="/account"][aria-current="page"]"#)
                .as_deref(),
            Some("Your account"),
            "the account page of {who} must mark Your account as the current link"
        );
        assert_eq!(
            page.count(r#"#account-nav li.nav-end > a[href="/admin"][data-nav="to-panel"]"#),
            1,
            "the account page of {who} must link to the panel from the foot of its navigation"
        );
    }
    let page = s.bob.get("/account").await;
    assert_eq!(page.status, 200, "the account page must answer 200 for bob");
    assert_eq!(
        page.count("nav"),
        0,
        "a plain user's account page must hold no navigation"
    );
    assert_eq!(
        page.count("button.menu-button"),
        0,
        "a plain user's account page must hold no Menu button"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_page_holds_the_note_and_no_navigation() {
    let s = seeded().await;
    let mut shots: Vec<Shot> = covered(&s)
        .await
        .into_iter()
        .filter(|shot| shot.layout == CARD)
        .collect();
    shots.push(not_found(&s).await);
    for shot in shots {
        let page = &shot.page;
        assert_eq!(
            page.count(NOTE),
            1,
            "{} must hold one body > header.site[data-brand] > p.site-note",
            shot.name
        );
        assert!(
            !page.text(NOTE).unwrap_or_default().is_empty(),
            "the site note of {} must hold text",
            shot.name
        );
        assert_eq!(
            page.count("nav"),
            0,
            "{} must hold no navigation",
            shot.name
        );
        assert_eq!(
            page.count("button.menu-button"),
            0,
            "{} must hold no Menu button",
            shot.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limited_page_holds_the_site_note() {
    let mut w = World::start().await;
    w.tighten(|config| config.limits.general_burst = 2).await;
    let anonymous = w.client();
    let browser = [("accept", "text/html")];
    for _ in 0..2 {
        let answered = anonymous.get_with("/login", &browser).await;
        assert_ne!(
            answered.status, 429,
            "the first two page requests must be answered, not limited"
        );
    }
    let limited = anonymous.get_with("/login", &browser).await;
    assert_eq!(
        limited.status, 429,
        "a third browser request over the limit must answer 429"
    );
    assert_eq!(
        limited.count(NOTE),
        1,
        "the limited page must hold one body > header.site[data-brand] > p.site-note"
    );
    assert_eq!(
        limited.count("nav"),
        0,
        "the limited page must hold no navigation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_menu_button_opens_the_panel_without_script() {
    let s = seeded().await;
    let button = format!(
        r#"{HEADER} > div.site-bar > button.menu-button[type="button"][popovertarget="panel-nav"]"#
    );
    for shot in covered(&s).await.iter().filter(|shot| shot.layout == PANEL) {
        let page = &shot.page;
        assert_eq!(
            page.count(&button),
            1,
            "{} must hold one Menu button in the site bar, with type button and popovertarget panel-nav",
            shot.name
        );
        assert_eq!(
            page.text(&format!("{button} > span.when-closed"))
                .as_deref(),
            Some("Menu"),
            "the Menu button of {} must say Menu when closed",
            shot.name
        );
        assert_eq!(
            page.text(&format!("{button} > span.when-open")).as_deref(),
            Some("Close"),
            "the Menu button of {} must say Close when open",
            shot.name
        );
        assert_eq!(
            page.count(&format!("{HEADER} nav#panel-nav[popover]")),
            1,
            "the navigation of {} must be a popover named panel-nav",
            shot.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_page_links_the_gateways_stylesheet() {
    let s = seeded().await;
    let mut shots = covered(&s).await;
    shots.push(not_found(&s).await);
    for shot in shots {
        let hrefs = shot.page.attrs(r#"link[rel="stylesheet"]"#, "href");
        assert_eq!(
            hrefs.len(),
            1,
            "{} must link exactly one stylesheet",
            shot.name
        );
        assert!(
            hrefs[0].starts_with("/assets/doorward.css"),
            "the stylesheet of {} must be /assets/doorward.css, got {}",
            shot.name,
            hrefs[0]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_page_holds_a_script_or_an_inline_style() {
    let s = seeded().await;
    let mut shots = covered(&s).await;
    shots.push(not_found(&s).await);
    for shot in shots {
        let body = shot.page.body.to_ascii_lowercase();
        for banned in ["<script", " style=", "<style"] {
            assert!(
                !body.contains(banned),
                "{} must not contain {banned}",
                shot.name
            );
        }
    }
}

#[test]
fn the_oklch_conversion_matches_known_colours() {
    let cases: [(&str, [i64; 3], f64); 4] = [
        ("oklch(1 0 0)", [255, 255, 255], 0.0),
        ("oklch(0 0 0)", [0, 0, 0], 0.0),
        ("oklch(0.5 0 0)", [99, 99, 99], 1.0),
        ("oklch(0.628 0.2577 29.23)", [255, 0, 0], 2.0),
    ];
    for (value, want, tolerance) in cases {
        let rgb = oklch_to_srgb(value).unwrap_or_else(|err| panic!("{err}"));
        for (channel, expected) in want.iter().enumerate() {
            let got = (rgb[channel] * 255.0).round();
            assert!(
                (got - *expected as f64).abs() <= tolerance,
                "{value} channel {channel} must be {expected} within {tolerance}, got {got}"
            );
        }
    }
}

/// The stylesheet the gateway serves, fetched the way the sign-in page links it.
async fn stylesheet(c: &TestClient) -> String {
    let page = c.get("/login").await;
    let href = page
        .attr(r#"link[rel="stylesheet"]"#, "href")
        .expect("the sign-in page must link a stylesheet");
    assert!(
        href.starts_with("/assets/doorward.css"),
        "the stylesheet must be /assets/doorward.css, got {href}"
    );
    let asset = c.get(&href).await;
    assert_eq!(asset.status, 200, "the stylesheet must answer 200");
    asset.body
}

/// Removes every `/* ... */` comment.
fn strip_comments(css: &str) -> String {
    let mut out = String::new();
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start..].find("*/") {
            Some(end) => rest = &rest[start + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Every declaration of a stylesheet, nested blocks included, with its values as written.
fn declarations(css: &str) -> Vec<Decl> {
    let css = strip_comments(css);
    let mut found = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut buffer = String::new();
    for ch in css.chars() {
        match ch {
            '{' => {
                stack.push(collapse(&buffer));
                buffer.clear();
            }
            ';' | '}' => {
                if let Some(decl) = declaration_of(&buffer, &stack) {
                    found.push(decl);
                }
                buffer.clear();
                if ch == '}' {
                    stack.pop();
                }
            }
            _ => buffer.push(ch),
        }
    }
    found
}

/// The declaration in `text`, when it has a name and a colon, inside the innermost open block.
fn declaration_of(text: &str, stack: &[String]) -> Option<Decl> {
    let (selector, ancestors) = stack.split_last()?;
    let (name, value) = text.split_once(':')?;
    let name = collapse(name);
    if name.is_empty() {
        return None;
    }
    Some(Decl {
        ancestors: ancestors.to_vec(),
        selector: selector.clone(),
        name,
        value: collapse(value),
    })
}

/// The custom properties of one theme: the light values, with the dark ones over them when `dark`.
fn theme_vars(decls: &[Decl], dark: bool) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for decl in decls
        .iter()
        .filter(|decl| decl.selector == ":root" && decl.name.starts_with("--"))
    {
        let light = decl.ancestors.is_empty();
        let dark_block = dark && decl.ancestors.len() == 1 && decl.ancestors[0] == DARK_MEDIA;
        if light || dark_block {
            vars.insert(decl.name.clone(), decl.value.clone());
        }
    }
    vars
}

/// The gamma sRGB channels, 0 to 1, of an opaque oklch colour such as `oklch(0.5 0.1 30)`.
fn oklch_to_srgb(value: &str) -> Result<[f64; 3], String> {
    let inner = value
        .strip_prefix("oklch(")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| format!("{value:?} is not an oklch colour"))?;
    let (numbers, alpha) = match inner.split_once('/') {
        Some((numbers, alpha)) => (numbers, Some(alpha.trim())),
        None => (inner, None),
    };
    if alpha.is_some_and(|alpha| alpha.parse::<f64>() != Ok(1.0)) {
        return Err(format!("{value:?} is not opaque"));
    }
    let parts = numbers
        .split_whitespace()
        .map(str::parse::<f64>)
        .collect::<Result<Vec<f64>, _>>()
        .map_err(|err| format!("{value:?}: {err}"))?;
    if parts.len() != 3 {
        return Err(format!("{value:?} needs three numbers"));
    }
    let (l, c, h) = (parts[0], parts[1], parts[2]);
    let hue = h.to_radians();
    let a = c * hue.cos();
    let b = c * hue.sin();
    let l_ = l + 0.396_337_777_4 * a + 0.215_803_757_3 * b;
    let m_ = l - 0.105_561_345_8 * a - 0.063_854_172_8 * b;
    let s_ = l - 0.089_484_177_5 * a - 1.291_485_548_0 * b;
    let (l3, m3, s3) = (l_.powi(3), m_.powi(3), s_.powi(3));
    let r = 4.076_741_662_1 * l3 - 3.307_711_591_3 * m3 + 0.230_969_929_2 * s3;
    let g = -1.268_438_004_6 * l3 + 2.609_757_401_1 * m3 - 0.341_319_396_5 * s3;
    let blue = -0.004_196_086_3 * l3 - 0.703_418_614_7 * m3 + 1.707_614_701_0 * s3;
    Ok([gamma(r), gamma(g), gamma(blue)])
}

/// Clamps a linear channel to 0..1 and encodes it as sRGB.
fn gamma(linear: f64) -> f64 {
    let x = linear.clamp(0.0, 1.0);
    if x <= 0.003_130_8 {
        12.92 * x
    } else {
        1.055 * x.powf(1.0 / 2.4) - 0.055
    }
}

/// The WCAG relative luminance of gamma sRGB channels.
fn luminance(rgb: [f64; 3]) -> f64 {
    let linear = |c: f64| {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2])
}

/// The WCAG contrast ratio of two colours.
fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (light, dark) = if la > lb { (la, lb) } else { (lb, la) };
    (light + 0.05) / (dark + 0.05)
}

/// The colour a token holds in a theme, or an error that names the token.
fn colour(vars: &BTreeMap<String, String>, name: &str) -> Result<[f64; 3], String> {
    let value = vars
        .get(name)
        .ok_or_else(|| format!("the token {name} is not declared on :root"))?;
    oklch_to_srgb(value).map_err(|err| format!("the token {name}: {err}"))
}

/// The font file names the stylesheet asks for, each written as `url("fonts/NAME.woff2")`.
fn font_names(css: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut rest = strip_comments(css);
    while let Some(at) = rest.find("url(") {
        let after = &rest[at + 4..];
        let end = after.find(')').ok_or("an url( has no closing bracket")?;
        let argument = &after[..end];
        let name = argument
            .strip_prefix("\"fonts/")
            .and_then(|tail| tail.strip_suffix(".woff2\""))
            .filter(|name| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            .ok_or_else(|| format!("url({argument}) is not url(\"fonts/<name>.woff2\")"))?;
        names.push(name.to_string());
        let next = after[end..].to_string();
        rest = next;
    }
    Ok(names)
}

/// True when a value holds a colour function or a hex colour of 3, 4, 6 or 8 digits.
fn has_colour_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if ["oklch(", "rgb(", "rgba(", "hsl(", "hsla("]
        .iter()
        .any(|function| lower.contains(function))
    {
        return true;
    }
    lower.split('#').skip(1).any(|rest| {
        let digits = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
        matches!(digits, 3 | 4 | 6 | 8)
    })
}

#[test]
fn the_font_licences_are_in_the_repository() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("fonts");
    for file in [
        "OFL-Atkinson-Hyperlegible-Next.txt",
        "OFL-Atkinson-Hyperlegible-Mono.txt",
    ] {
        let path = dir.join(file);
        assert!(
            path.is_file(),
            "the font licence {file} must be in assets/fonts"
        );
        let text =
            std::fs::read_to_string(&path).expect("the font licence must be readable as text");
        assert!(
            text.to_lowercase().contains("sil open font license"),
            "the font licence {file} must be the SIL Open Font License"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn text_reaches_4_5_to_1_on_its_background_in_both_themes() {
    let w = TestGateway::start().await;
    let decls = declarations(&stylesheet(&w.client()).await);
    let mut failures = Vec::new();
    for (theme, dark) in [("light", false), ("dark", true)] {
        let vars = theme_vars(&decls, dark);
        for (text, background) in TEXT_PAIRS {
            let result = colour(&vars, text)
                .and_then(|fg| colour(&vars, background).map(|bg| contrast(fg, bg)));
            match result {
                Ok(ratio) if ratio >= 4.5 => {}
                Ok(ratio) => failures.push(format!(
                    "{theme}: {text} on {background} is {ratio:.2} to 1"
                )),
                Err(err) => failures.push(format!("{theme}: {err}")),
            }
        }
    }
    failures.sort();
    failures.dedup();
    assert!(
        failures.is_empty(),
        "text pairs under 4.5 to 1:\n{}",
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn colour_and_rules_reach_3_to_1_on_their_background_in_both_themes() {
    let w = TestGateway::start().await;
    let decls = declarations(&stylesheet(&w.client()).await);
    let mut failures = Vec::new();
    for (theme, dark) in [("light", false), ("dark", true)] {
        let vars = theme_vars(&decls, dark);
        for (fg, background) in NON_TEXT_PAIRS {
            let result =
                colour(&vars, fg).and_then(|c| colour(&vars, background).map(|bg| contrast(c, bg)));
            match result {
                Ok(ratio) if ratio >= 3.0 => {}
                Ok(ratio) => {
                    failures.push(format!("{theme}: {fg} on {background} is {ratio:.2} to 1"))
                }
                Err(err) => failures.push(format!("{theme}: {err}")),
            }
        }
    }
    failures.sort();
    failures.dedup();
    assert!(
        failures.is_empty(),
        "colours under 3 to 1:\n{}",
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_controls_are_36_px_and_44_px_on_a_touch_or_narrow_screen() {
    let w = TestGateway::start().await;
    let decls = declarations(&stylesheet(&w.client()).await);
    assert!(
        decls.iter().any(|decl| decl.selector == ":root"
            && decl.ancestors.is_empty()
            && decl.name == "--control"
            && decl.value == "36px"),
        "the stylesheet must declare --control: 36px on :root"
    );
    assert!(
        decls.iter().any(|decl| decl.selector == ":root"
            && decl.name == "--control"
            && decl.value == "44px"
            && decl.ancestors.len() == 1
            && decl.ancestors[0] == TOUCH),
        "a block {TOUCH} must redeclare --control: 44px on :root"
    );
    for word in ["button", "input", "select"] {
        assert!(
            decls
                .iter()
                .any(|decl| SIZE_PROPERTIES.contains(&decl.name.as_str())
                    && decl.value == "var(--control)"
                    && decl.selector.contains(word)),
            "a rule whose selector mentions {word} must size it with var(--control) in height, block-size, min-height or min-block-size"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stylesheet_names_only_the_gateways_font_files() {
    let w = TestGateway::start().await;
    let css = stylesheet(&w.client()).await;
    let stripped = strip_comments(&css);
    assert!(
        !stripped.contains("@import"),
        "the stylesheet must not import anything"
    );
    let decls = declarations(&css);
    assert!(
        decls
            .iter()
            .any(|decl| decl.selector == "@font-face" && decl.name == "src"),
        "the stylesheet must declare its fonts with @font-face"
    );
    let names = font_names(&css).unwrap_or_else(|err| panic!("the stylesheet fonts: {err}"));
    assert!(
        !names.is_empty(),
        "the stylesheet must name at least one font file"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_font_files_are_served_as_woff2() {
    let w = TestGateway::start().await;
    let c = w.client();
    let css = stylesheet(&c).await;
    let names = font_names(&css).unwrap_or_else(|err| panic!("the stylesheet fonts: {err}"));
    assert!(
        !names.is_empty(),
        "the stylesheet must name at least one font file"
    );
    for name in names {
        let font = c.get(&format!("/assets/fonts/{name}.woff2")).await;
        assert_eq!(
            font.status, 200,
            "the font {name} must answer 200 from /assets/fonts"
        );
        assert_eq!(
            font.header("content-type").as_deref(),
            Some("font/woff2"),
            "the font {name} must be served as font/woff2"
        );
        assert_eq!(
            font.header("x-content-type-options").as_deref(),
            Some("nosniff"),
            "the font {name} must answer with nosniff"
        );
        assert!(
            font.body.starts_with("wOF2"),
            "the font {name} must start with the bytes wOF2"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_font_answers_404() {
    let w = TestGateway::start().await;
    let missing = w.client().get("/assets/fonts/nope.woff2").await;
    assert_eq!(
        missing.status, 404,
        "a font the gateway does not hold must answer 404"
    );
}

/// Asserts the directives of a policy: `font-src 'self'` exactly, and `default-src 'none'`.
fn assert_font_policy(page: &Page, what: &str) {
    let policy = page.header("content-security-policy").unwrap_or_default();
    let directives: Vec<&str> = policy.split(';').map(str::trim).collect();
    assert!(
        directives.contains(&"font-src 'self'"),
        "{what} must send the directive font-src 'self', got {policy:?}"
    );
    assert!(
        directives.contains(&"default-src 'none'"),
        "{what} must keep the directive default-src 'none', got {policy:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_policy_allows_fonts_from_the_gateway_only() {
    let s = seeded().await;
    let sign_in = s.w.client().get("/login").await;
    assert_font_policy(&sign_in, "the sign-in page");
    let consent = consent_page(&s.bob, &s.w.app(), &s.w.resource("demo")).await;
    assert_font_policy(&consent, "the consent page");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stylesheet_moves_pages_only_when_motion_is_allowed() {
    let w = TestGateway::start().await;
    let decls = declarations(&stylesheet(&w.client()).await);
    assert!(
        decls.iter().any(|decl| decl.selector == "@view-transition"
            && decl.name == "navigation"
            && decl.value == "auto"
            && decl.ancestors.iter().any(|a| a == MOTION)),
        "the stylesheet must declare @view-transition with navigation auto inside {MOTION}"
    );
    for name in MOTION_NAMES {
        assert!(
            decls
                .iter()
                .any(|decl| decl.name == "view-transition-name" && decl.value == name),
            "the stylesheet must name the view transition {name}"
        );
    }
    let reduced: Vec<&Decl> = decls
        .iter()
        .filter(|decl| decl.ancestors.iter().any(|a| a == REDUCED))
        .collect();
    for name in ["transition-duration", "animation-duration"] {
        assert!(
            reduced
                .iter()
                .any(|decl| decl.selector.contains('*') && decl.name == name),
            "the block {REDUCED} must set {name} on every element with a universal rule"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn colour_is_only_named_values_outside_custom_properties() {
    let w = TestGateway::start().await;
    let decls = declarations(&stylesheet(&w.client()).await);
    let literal: Vec<String> = decls
        .iter()
        .filter(|decl| !decl.name.starts_with("--") && has_colour_literal(&decl.value))
        .map(|decl| format!("{} {}: {}", decl.selector, decl.name, decl.value))
        .collect();
    assert!(
        literal.is_empty(),
        "no declaration outside a custom property may hold a colour literal, got {literal:?}"
    );
}
