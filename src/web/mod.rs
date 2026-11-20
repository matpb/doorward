//! Shared browser-page machinery: the viewer, verified forms, the page shell and headers.

mod address;
mod cookies;
pub mod drain;
mod form;
mod headers;
pub mod limit;
mod page;
mod viewer;

pub use address::{client_address, throttle_key};
pub use cookies::{
    CSRF_COOKIE, SESSION_COOKIE, clear_cookie, cookie_value, csrf_cookie, session_cookie,
    with_cookie,
};
pub use form::{FormFields, VerifiedForm};
pub use headers::{content_security_policy, security_headers, stylesheet};
pub use page::{
    MainData, busy, forbidden, form_page, form_page_with, internal_error, not_found,
    not_found_link, page, page_with, redirect,
};
pub use viewer::{Role, SessionUser, Viewer};

#[cfg(test)]
mod tests_drain;
