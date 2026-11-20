use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use crate::app::AppState;
use crate::oauth::connected::{self, Connected};
use crate::web::{Viewer, form_page, internal_error, redirect};

pub async fn get_account(State(state): State<AppState>, viewer: Viewer) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    match connected::list(&state.db, user.id, now).await {
        Ok(clients) => account_page(&viewer, StatusCode::OK, None, &clients),
        Err(err) => {
            eprintln!("doorward: cannot list connected clients: {err}");
            internal_error()
        }
    }
}

/// The account page with the connected `clients`, and an error line when `error` is given.
/// Anonymous viewers go to sign-in.
pub fn account_page(
    viewer: &Viewer,
    status: StatusCode,
    error: Option<&str>,
    clients: &[Connected],
) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    form_page(viewer, status, "account", "Your account", |csrf| {
        account_body(csrf, &user.email, viewer.is_admin(), error, clients)
    })
}

fn account_body(
    csrf: &str,
    email: &str,
    admin: bool,
    error: Option<&str>,
    clients: &[Connected],
) -> Markup {
    html! {
        h1 { "Your account" }
        @if admin {
            p { a href="/admin" data-nav="to-panel" { "Admin panel" } }
        }
        p { "Signed in as " (email) }
        h2 { "Connected clients" }
        @if clients.is_empty() {
            p { "No client is connected to your account." }
        } @else {
            ul {
                @for row in clients {
                    li data-family=(row.public_id) data-client-name=(row.client_name) data-server=(row.server) {
                        span { (row.client_name) " on " (row.server) }
                        form method="post" action=(format!("/account/clients/{}/disconnect", row.public_id)) {
                            input type="hidden" name="csrf" value=(csrf);
                            button type="submit" { "Disconnect" }
                        }
                    }
                }
            }
        }
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
