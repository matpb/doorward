use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use crate::web::{Viewer, form_page, redirect};

pub async fn get_account(viewer: Viewer) -> Response {
    if viewer.user.is_none() {
        return redirect("/login");
    }
    account_page(&viewer, StatusCode::OK, None)
}

/// The account page, with an error line when `error` is given. Anonymous viewers go to sign-in.
pub fn account_page(viewer: &Viewer, status: StatusCode, error: Option<&str>) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    form_page(viewer, status, "account", "Your account", |csrf| {
        account_body(csrf, &user.email, error)
    })
}

fn account_body(csrf: &str, email: &str, error: Option<&str>) -> Markup {
    html! {
        h1 { "Your account" }
        p { "Signed in as " (email) }
        h2 { "Change password" }
        @if let Some(message) = error {
            p.error { (message) }
        }
        form method="post" action="/account/password" {
            input type="hidden" name="csrf" value=(csrf);
            label for="current_password" { "Current password" }
            input id="current_password" name="current_password" type="password" autocomplete="current-password" required;
            label for="new_password" { "New password" }
            input id="new_password" name="new_password" type="password" autocomplete="new-password" required;
            button type="submit" { "Change password" }
        }
        form method="post" action="/logout" {
            input type="hidden" name="csrf" value=(csrf);
            button type="submit" { "Sign out" }
        }
    }
}
