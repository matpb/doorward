use axum::http::{HeaderValue, StatusCode, header::LOCATION};
use axum::response::{Html, IntoResponse, Response};
use maud::{DOCTYPE, Markup, html};

use super::cookies::{csrf_cookie, with_cookie};
use super::viewer::Viewer;

/// The page shell: doctype, language, viewport, stylesheet and the main element.
pub fn page(status: StatusCode, kind: &str, title: &str, body: Markup) -> Response {
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
                main data-page=(kind) { (body) }
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
    let (token, minted) = viewer.form_token();
    let response = page(status, kind, title, form(&token));
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
