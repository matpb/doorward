use axum::http::{HeaderValue, StatusCode, header::LOCATION};
use axum::response::{Html, IntoResponse, Response};
use maud::{DOCTYPE, Markup, html};

use super::cookies::{csrf_cookie, with_cookie};
use super::viewer::Viewer;

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
    let document = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                link rel="stylesheet" href="/assets/doorward.css";
            }
            body {
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
        Err(_) => internal_error(),
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

pub fn internal_error() -> Response {
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
