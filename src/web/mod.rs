//! Shared browser-page machinery: the viewer, verified forms, the page shell and headers.

mod address;
mod cookies;
mod form;
mod headers;
mod page;
mod viewer;

pub use address::{client_address, throttle_key};
pub use cookies::{
    CSRF_COOKIE, SESSION_COOKIE, clear_cookie, cookie_value, csrf_cookie, session_cookie,
    with_cookie,
};
pub use form::{FormFields, VerifiedForm};
pub use headers::{security_headers, stylesheet};
pub use page::{
    busy, forbidden, form_page, internal_error, not_found, not_found_link, page, redirect,
};
pub use viewer::{Role, SessionUser, Viewer};
