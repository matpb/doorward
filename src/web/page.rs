use axum::http::{HeaderValue, StatusCode, header::LOCATION};
use axum::response::{Html, IntoResponse, Response};
use maud::{DOCTYPE, Markup, html};

use super::cookies::{csrf_cookie, with_cookie};
use super::viewer::Viewer;
use crate::report;

/// Extra data attributes of the main element. A None leaves the attribute out.
#[derive(Default)]
pub struct MainData<'a> {
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

/// The brand of the header: a link to the panel or the account page, a plain span on the card.
fn brand(layout: &str) -> Markup {
    let content = html! {
        svg class="brand-mark" width="22" height="22" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round" aria-hidden="true" {
            rect x="5" y="3" width="14" height="18" rx="2";
            circle cx="15" cy="12.5" r="1.2" fill="currentColor" stroke="none";
        }
        span { "Doorward" }
    };
    match layout {
        "panel" => html! { a class="brand" href="/admin" { (content) } },
        "page" => html! { a class="brand" href="/account" { (content) } },
        _ => html! { span class="brand" { (content) } },
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
                link rel="stylesheet" href="/assets/doorward.css";
            }
            body data-layout=(layout) {
                header.site data-brand {
                    div.site-bar {
                        (brand(layout))
                    }
                }
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

pub fn forbidden() -> Response {
    page(
        StatusCode::FORBIDDEN,
        "forbidden",
        "Forbidden",
        html! {
            h1 { "Forbidden" }
            p { "This request was refused." }
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
            p { "It may have expired or been used already." }
        },
    )
}

/// The plain 404 answer.
pub fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
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
            p { "Try again in a moment." }
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
            p { "Try again in a moment." }
        },
    )
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use maud::html;
    use scraper::{Html, Selector};

    use super::*;

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
}
