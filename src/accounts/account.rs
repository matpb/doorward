use axum::http::StatusCode;
use axum::response::Response;
use maud::html;

use crate::web::{Viewer, form_page, redirect};

pub async fn get_account(viewer: Viewer) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    form_page(&viewer, StatusCode::OK, "account", "Your account", |csrf| {
        html! {
            h1 { "Your account" }
            p { "Signed in as " (user.email) }
            h2 { "Change password" }
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
    })
}
