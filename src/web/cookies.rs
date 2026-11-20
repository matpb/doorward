use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;

use super::page::internal_error;

pub const SESSION_COOKIE: &str = "__Host-doorward_session";
pub const CSRF_COOKIE: &str = "__Host-doorward_csrf";

const ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Lax";

/// The value of the cookie `name`, or None when it is absent or sent twice.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = Vec::new();
    for header in headers.get_all(COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=')
                && key == name
            {
                values.push(value.to_owned());
            }
        }
    }
    match values.len() {
        1 => values.pop(),
        _ => None,
    }
}

pub fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; {ATTRIBUTES}")
}

pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; {ATTRIBUTES}")
}

/// A line that removes the cookie `name` from the browser.
pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; {ATTRIBUTES}; Max-Age=0")
}

/// Adds a Set-Cookie header to `response`.
pub fn with_cookie(mut response: Response, line: &str) -> Response {
    match HeaderValue::from_str(line) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
            response
        }
        Err(err) => internal_error("cookie", &err),
    }
}
