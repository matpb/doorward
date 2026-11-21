use axum::http::{HeaderValue, StatusCode, header::LOCATION};
use axum::response::{Html, IntoResponse, Response};
use maud::{DOCTYPE, Markup, html};

use super::cookies::{csrf_cookie, with_cookie};
use super::headers::stylesheet_href;
use super::viewer::Viewer;
use crate::report;

/// Which navigation the header carries.
#[derive(Clone, Copy, Default)]
pub enum Nav<'a> {
    #[default]
    None,
    /// The admin panel's list; `current` is the path of the section shown, `owner` adds Mail.
    Panel { current: &'a str, owner: bool },
    /// The account page's list; `admin` adds the link to the panel.
    Account { admin: bool },
}

/// Extra data attributes of the main element. A None leaves the attribute out.
#[derive(Default)]
pub struct MainData<'a> {
    pub nav: Nav<'a>,
    pub lockdown: Option<&'a str>,
    pub redirect_host: Option<&'a str>,
    pub client_name: Option<&'a str>,
    pub client_verified: Option<&'a str>,
    pub client_host: Option<&'a str>,
    pub server: Option<&'a str>,
    pub user: Option<&'a str>,
}

/// The layout of a page kind: `panel` for the admin panel, `page` for the account page, else `card`.
pub fn layout_of(kind: &str) -> &'static str {
    match kind {
        "admin" | "users" | "user" | "invitations" | "invitation-created" | "servers"
        | "server" | "rules" | "redirects" | "mail" | "activity" => "panel",
        "account" => "page",
        _ => "card",
    }
}

/// The panel links: label, path, the class of the item, and whether only the owner sees it.
const PANEL_LINKS: [(&str, &str, &str, bool); 9] = [
    ("Overview", "/admin", "", false),
    ("Users", "/admin/users", "nav-break", false),
    ("Invitations", "/admin/invitations", "", false),
    ("Servers", "/admin/servers", "nav-break", false),
    ("Rules", "/admin/rules", "", false),
    ("Redirects", "/admin/redirects", "", false),
    ("Activity", "/admin/activity", "nav-break", false),
    ("Mail", "/admin/mail", "", true),
    ("Your account", "/account", "nav-end", false),
];

/// The brand of the header: a link to the panel or the account page, a plain span on the card.
fn brand(layout: &str) -> Markup {
    let content = html! {
        svg class="brand-mark" viewBox="0 0 24 24" aria-hidden="true" {
            path fill-rule="evenodd" d="M6.5 2h11A1.5 1.5 0 0 1 19 3.5v17a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20.5v-17A1.5 1.5 0 0 1 6.5 2Zm8.25 9.25a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3Z";
        }
        span { "Doorward" }
    };
    match layout {
        "panel" => html! { a class="brand" href="/admin" { (content) } },
        "page" => html! { a class="brand" href="/account" { (content) } },
        _ => html! { span class="brand" { (content) } },
    }
}

/// The panel's list; the link to `current` is the one marked as the current page.
fn panel_nav(current: &str, owner: bool) -> Markup {
    html! {
        nav id="panel-nav" data-nav="panel" aria-label="Admin" popover {
            ul {
                @for (label, href, class, owner_only) in PANEL_LINKS {
                    @if !owner_only || owner {
                        li class=[(!class.is_empty()).then_some(class)] {
                            a href=(href) aria-current=[(href == current).then_some("page")] {
                                @if href == current {
                                    span class="nav-mark" aria-hidden="true" {}
                                }
                                (label)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The account page's list: the account page itself, and the link to the panel for admins.
fn account_nav() -> Markup {
    html! {
        nav id="account-nav" data-nav="account" aria-label="Account" popover {
            ul {
                li {
                    a href="/account" aria-current="page" {
                        span class="nav-mark" aria-hidden="true" {}
                        "Your account"
                    }
                }
                li class="nav-end" {
                    a href="/admin" data-nav="to-panel" { "Admin panel" }
                }
            }
        }
    }
}

/// The navigation of a plain user's account page: its one link, with no menu to open it.
fn plain_account_nav() -> Markup {
    html! {
        nav data-nav="account" aria-label="Account" {
            ul {
                li {
                    a href="/account" aria-current="page" {
                        span class="nav-mark" aria-hidden="true" {}
                        "Your account"
                    }
                }
            }
        }
    }
}

/// The button that opens the navigation named `target`; its label follows the open state.
fn menu_button(target: &str) -> Markup {
    html! {
        button class="menu-button" type="button" data-kind="secondary" popovertarget=(target) {
            span class="when-closed" { "Menu" }
            span class="when-open" { "Close" }
        }
    }
}

/// The site header: the brand and the menu button in the site bar, then the navigation or,
/// on the card, its note.
fn header(layout: &str, nav: Nav<'_>) -> Markup {
    let (menu, list) = match nav {
        Nav::None => (None, None),
        Nav::Account { admin: false } => (None, Some(plain_account_nav())),
        Nav::Panel { current, owner } => (Some("panel-nav"), Some(panel_nav(current, owner))),
        Nav::Account { admin: true } => (Some("account-nav"), Some(account_nav())),
    };
    html! {
        header.site data-brand {
            div.site-bar {
                (brand(layout))
                @if let Some(target) = menu {
                    (menu_button(target))
                }
            }
            @if let Some(list) = list {
                (list)
            }
            @if layout == "card" {
                p.site-note { "Doorward decides who reaches which MCP server and which tool, and keeps a record of every call." }
            }
        }
    }
}

/// The page shell: doctype, language, viewport, stylesheet and the main element.
pub fn page(status: StatusCode, kind: &str, title: &str, body: Markup) -> Response {
    page_with(status, kind, title, &MainData::default(), body)
}

/// The page shell with extra data attributes on the main element.
pub fn page_with(
    status: StatusCode,
    kind: &str,
    title: &str,
    data: &MainData<'_>,
    body: Markup,
) -> Response {
    let layout = layout_of(kind);
    let document = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                link rel="preload" as="font" type="font/woff2" href="/assets/fonts/atkinson-hyperlegible-next-latin-wght-normal.woff2" crossorigin;
                link rel="preload" as="font" type="font/woff2" href="/assets/fonts/atkinson-hyperlegible-mono-latin-wght-normal.woff2" crossorigin;
                link rel="stylesheet" href=(stylesheet_href());
            }
            body data-layout=(layout) {
                (header(layout, data.nav))
                main data-page=(kind)
                    data-lockdown=[data.lockdown]
                    data-redirect-host=[data.redirect_host]
                    data-client-name=[data.client_name]
                    data-client-verified=[data.client_verified]
                    data-client-host=[data.client_host]
                    data-server=[data.server]
                    data-user=[data.user]
                {
                    (body)
                }
            }
        }
    };
    (status, Html(document.into_string())).into_response()
}

/// A form page. Mints the pre-session CSRF cookie when the browser has no binding.
pub fn form_page(
    viewer: &Viewer,
    status: StatusCode,
    kind: &str,
    title: &str,
    form: impl FnOnce(&str) -> Markup,
) -> Response {
    form_page_with(viewer, status, kind, title, &MainData::default(), form)
}

/// A form page with extra data attributes on the main element.
pub fn form_page_with(
    viewer: &Viewer,
    status: StatusCode,
    kind: &str,
    title: &str,
    data: &MainData<'_>,
    form: impl FnOnce(&str) -> Markup,
) -> Response {
    let (token, minted) = viewer.form_token();
    let response = page_with(status, kind, title, data, form(&token));
    match minted {
        Some(value) => with_cookie(response, &csrf_cookie(&value)),
        None => response,
    }
}

/// A 303 to `to`.
pub fn redirect(to: &str) -> Response {
    match HeaderValue::from_str(to) {
        Ok(location) => {
            let mut response = StatusCode::SEE_OTHER.into_response();
            response.headers_mut().insert(LOCATION, location);
            response
        }
        Err(err) => internal_error("redirect", &err),
    }
}

/// The refusal: a viewer who lacks the role, or a form that was refused.
pub fn forbidden() -> Response {
    page(
        StatusCode::FORBIDDEN,
        "forbidden",
        "Request refused",
        html! {
            h1 data-tone="bad" { "Request refused" }
            p.lede { "Doorward did not carry out this request. If you were sending a form, go back, reload the page and send it again. If you followed a link, your account may not open it." }
        },
    )
}

pub fn not_found_link() -> Response {
    page(
        StatusCode::NOT_FOUND,
        "link-invalid",
        "Link not valid",
        html! {
            h1 { "This link is not valid" }
            p.lede { "It may have expired or been used already." }
        },
    )
}

/// The bare 404 that programs get: no page, no body.
pub fn not_found_bare() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// The page for an address that leads nowhere.
pub fn not_found() -> Response {
    page(
        StatusCode::NOT_FOUND,
        "not-found",
        "Page not found",
        html! {
            h1 { "Page not found" }
            p.lede { "This address does not lead anywhere in Doorward." }
            p.back { a href="/" { "Go to the start page" } }
        },
    )
}

/// The 500 page; the failure is written to standard error first.
pub fn internal_error(what: &str, err: &dyn std::fmt::Display) -> Response {
    report::failure(what, err);
    page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "error",
        "Something went wrong",
        html! {
            h1 { "Something went wrong" }
            p.lede { "Try again in a moment." }
        },
    )
}

pub fn busy() -> Response {
    page(
        StatusCode::SERVICE_UNAVAILABLE,
        "error",
        "Busy",
        html! {
            h1 { "The server is busy" }
            p.lede { "Try again in a moment." }
        },
    )
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::extract::Path;
    use maud::html;
    use scraper::{Html, Selector};

    use super::*;
    use crate::web::headers::font;

    /// The attributes of the first main element of a response.
    async fn main_attributes(response: Response) -> Vec<(String, String)> {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(bytes.to_vec()).expect("utf-8");
        let doc = Html::parse_document(&text);
        let selector = Selector::parse("main").expect("selector");
        let main = doc.select(&selector).next().expect("a main element");
        main.value()
            .attrs()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    }

    /// The text of a response body.
    async fn text_of(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf-8")
    }

    /// How many elements of `doc` match `css`.
    fn count(doc: &Html, css: &str) -> usize {
        doc.select(&Selector::parse(css).expect("selector")).count()
    }

    #[test]
    fn each_listed_kind_has_its_layout() {
        let panel = [
            "admin",
            "users",
            "user",
            "invitations",
            "invitation-created",
            "servers",
            "server",
            "rules",
            "redirects",
            "mail",
            "activity",
        ];
        for kind in panel {
            assert_eq!(layout_of(kind), "panel", "{kind} must use the panel layout");
        }
        assert_eq!(layout_of("account"), "page");
        for kind in [
            "login",
            "forgot-sent",
            "invite",
            "consent",
            "disconnect",
            "disconnected",
            "error",
            "forbidden",
            "link-invalid",
            "no-access",
        ] {
            assert_eq!(layout_of(kind), "card", "{kind} must use the card layout");
        }
    }

    #[tokio::test]
    async fn the_header_names_doorward_and_links_the_brand_by_layout() {
        let cases = [
            ("servers", "panel", Some("/admin")),
            ("account", "page", Some("/account")),
            ("login", "card", None),
        ];
        for (kind, layout, href) in cases {
            let doc =
                Html::parse_document(&text_of(page(StatusCode::OK, kind, "T", html! {})).await);
            assert_eq!(
                count(
                    &doc,
                    &format!(r#"body[data-layout="{layout}"] > header[data-brand]"#)
                ),
                1,
                "{kind} must hold one header directly in body with layout {layout}"
            );
            let link = match href {
                Some(href) => format!(r#"a.brand[href="{href}"]"#),
                None => "span.brand".to_string(),
            };
            assert_eq!(
                count(&doc, &format!("header[data-brand] .site-bar > {link}")),
                1,
                "{kind} must show the brand as {link}"
            );
            assert_eq!(
                count(&doc, r#"header[data-brand] .brand svg[aria-hidden="true"]"#),
                1,
                "the brand of {kind} must hold the aria-hidden mark"
            );
            let brand = doc
                .select(&Selector::parse("header[data-brand] .brand").expect("selector"))
                .next()
                .expect("a brand");
            assert_eq!(brand.text().collect::<String>(), "Doorward");
        }
    }

    #[tokio::test]
    async fn the_head_preloads_both_fonts_before_the_stylesheet() {
        let doc =
            Html::parse_document(&text_of(page(StatusCode::OK, "login", "T", html! {})).await);
        let links: Vec<(String, String, String, bool)> = doc
            .select(&Selector::parse("head > link").expect("selector"))
            .map(|link| {
                let attr = |name: &str| link.value().attr(name).unwrap_or_default().to_owned();
                (
                    attr("rel"),
                    attr("as"),
                    attr("href"),
                    link.value().attr("crossorigin").is_some(),
                )
            })
            .collect();
        let font = |file: &str| {
            (
                "preload".to_owned(),
                "font".to_owned(),
                format!("/assets/fonts/{file}"),
                true,
            )
        };
        assert_eq!(
            links,
            vec![
                font("atkinson-hyperlegible-next-latin-wght-normal.woff2"),
                font("atkinson-hyperlegible-mono-latin-wght-normal.woff2"),
                (
                    "stylesheet".to_owned(),
                    String::new(),
                    stylesheet_href().to_owned(),
                    false,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn every_preloaded_font_is_answered_by_the_font_handler() {
        let doc =
            Html::parse_document(&text_of(page(StatusCode::OK, "login", "T", html! {})).await);
        let hrefs: Vec<String> = doc
            .select(&Selector::parse(r#"link[rel="preload"]"#).expect("selector"))
            .map(|link| link.value().attr("href").unwrap_or_default().to_owned())
            .collect();
        assert_eq!(hrefs.len(), 2, "the page must preload both fonts");
        for href in hrefs {
            let name = href
                .strip_prefix("/assets/fonts/")
                .unwrap_or_else(|| panic!("{href} must be a font under /assets/fonts/"))
                .to_owned();
            let response = font(Path(name)).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "the font handler must answer 200 for {href}"
            );
        }
    }

    #[tokio::test]
    async fn lockdown_is_an_attribute_of_main_and_a_default_page_has_no_extra_one() {
        let data = MainData {
            lockdown: Some("unknown"),
            ..MainData::default()
        };
        let shown =
            main_attributes(page_with(StatusCode::OK, "server", "T", &data, html! {})).await;
        assert!(shown.contains(&("data-lockdown".to_owned(), "unknown".to_owned())));
        let plain = main_attributes(page(StatusCode::OK, "server", "T", html! {})).await;
        for name in [
            "data-lockdown",
            "data-redirect-host",
            "data-client-name",
            "data-client-verified",
            "data-client-host",
            "data-server",
            "data-user",
        ] {
            assert!(
                plain.iter().all(|(key, _)| key != name),
                "{name} must be absent from a default page"
            );
        }
    }

    #[tokio::test]
    async fn the_refusal_page_is_a_403_with_its_title_heading_and_lede() {
        let response = forbidden();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let doc = Html::parse_document(&text_of(response).await);
        let title = doc
            .select(&Selector::parse("title").expect("selector"))
            .next()
            .expect("a title")
            .text()
            .collect::<String>();
        assert_eq!(title, "Request refused");
        assert!(
            doc.root_element().html().contains(
                r#"<h1 data-tone="bad">Request refused</h1><p class="lede">Doorward did not carry out this request. If you were sending a form, go back, reload the page and send it again. If you followed a link, your account may not open it.</p>"#
            ),
            "the refusal page must hold its heading and its lede"
        );
        assert_eq!(count(&doc, r#"main[data-page="forbidden"]"#), 1);
    }

    #[tokio::test]
    async fn the_refusal_page_marks_its_heading_as_refused() {
        let doc = Html::parse_document(&text_of(forbidden()).await);
        assert_eq!(
            count(&doc, r#"main h1[data-tone="bad"]"#),
            1,
            "the refusal page must mark its heading bad"
        );
        let heading = doc
            .select(&Selector::parse("main h1").expect("selector"))
            .next()
            .expect("a heading");
        assert_eq!(heading.text().collect::<String>(), "Request refused");
    }

    #[tokio::test]
    async fn the_messages_that_are_not_verdicts_have_no_tone_on_their_heading() {
        for response in [not_found(), not_found_link(), busy()] {
            let doc = Html::parse_document(&text_of(response).await);
            assert_eq!(
                count(&doc, "main h1"),
                1,
                "a message page holds one heading"
            );
            assert_eq!(
                count(&doc, "main h1[data-tone]"),
                0,
                "a message page other than the refusal must not mark its heading"
            );
        }
    }

    #[test]
    fn a_plain_users_account_nav_is_one_link_with_no_popover_and_no_menu() {
        assert_eq!(
            header("page", Nav::Account { admin: false }).into_string(),
            r#"<header class="site" data-brand><div class="site-bar"><a class="brand" href="/account"><svg class="brand-mark" viewBox="0 0 24 24" aria-hidden="true"><path fill-rule="evenodd" d="M6.5 2h11A1.5 1.5 0 0 1 19 3.5v17a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20.5v-17A1.5 1.5 0 0 1 6.5 2Zm8.25 9.25a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3Z"></svg><span>Doorward</span></a></div><nav data-nav="account" aria-label="Account"><ul><li><a href="/account" aria-current="page"><span class="nav-mark" aria-hidden="true"></span>Your account</a></li></ul></nav></header>"#
        );
    }

    #[tokio::test]
    async fn the_not_found_page_links_to_the_start_page_after_its_lede() {
        let doc = Html::parse_document(&text_of(not_found()).await);
        let links: Vec<_> = doc
            .select(&Selector::parse("main p.back a").expect("selector"))
            .collect();
        assert_eq!(links.len(), 1, "the not-found page must hold one back link");
        assert_eq!(links[0].value().attr("href"), Some("/"));
        assert_eq!(links[0].text().collect::<String>(), "Go to the start page");
    }

    #[tokio::test]
    async fn the_bare_not_found_has_an_empty_body() {
        let bytes = axum::body::to_bytes(not_found_bare().into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(bytes.is_empty(), "the bare 404 must carry no body");
    }

    #[tokio::test]
    async fn each_message_page_is_a_heading_and_one_lede() {
        let cases = [
            (
                forbidden(),
                r#"<h1 data-tone="bad">Request refused</h1>"#,
                "Doorward did not carry out this request. If you were sending a form, go back, reload the page and send it again. If you followed a link, your account may not open it.",
            ),
            (
                not_found_link(),
                "<h1>This link is not valid</h1>",
                "It may have expired or been used already.",
            ),
            (
                not_found(),
                "<h1>Page not found</h1>",
                "This address does not lead anywhere in Doorward.",
            ),
            (
                busy(),
                "<h1>The server is busy</h1>",
                "Try again in a moment.",
            ),
        ];
        for (response, heading, lede) in cases {
            let text = text_of(response).await;
            assert!(
                text.contains("<main data-page="),
                "the message page must hold a main element"
            );
            assert!(
                text.contains(&format!("{heading}<p class=\"lede\">{lede}</p>")),
                "the message page {heading} must hold its heading and one lede: {text}"
            );
        }
    }
}
