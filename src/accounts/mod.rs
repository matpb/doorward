//! Owner setup, sign-in and sign-out, sessions, login throttling and the account page.

pub mod account;
pub mod input;
pub mod login;
pub mod session;
pub mod setup;
pub mod throttle;

use axum::response::Response;

use crate::web::not_found_link;

/// Invitations come in a later slice, so every invitation link is unusable for now.
pub async fn invite_unavailable() -> Response {
    not_found_link()
}
