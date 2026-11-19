//! The admin panel. One nested router behind the admin check; the mail routes add the owner check.

mod activity;
mod mail;
#[cfg(test)]
mod tests;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use maud::html;

use crate::app::AppState;
use crate::web::{Viewer, forbidden, page, redirect};

pub fn router(state: AppState) -> Router<AppState> {
    let owner_only = Router::new()
        .route("/", get(mail::get_mail).post(mail::post_mail))
        .route("/test", post(mail::post_test))
        // Routes are added above this line: route_layer covers only routes that already exist.
        .route_layer(middleware::from_fn_with_state(state.clone(), require_owner));
    Router::new()
        .route("/", get(panel))
        .nest("/mail", owner_only)
        .route("/activity", get(activity::get_activity))
        // Routes are added above this line: route_layer covers only routes that already exist.
        .route_layer(middleware::from_fn_with_state(state, require_admin))
}

async fn panel(viewer: Viewer) -> Response {
    page(
        StatusCode::OK,
        "admin",
        "Admin",
        html! {
            h1 { "Admin" }
            nav {
                ul {
                    li { a href="/admin/activity" { "Activity" } }
                    @if viewer.is_owner() {
                        li { a href="/admin/mail" { "Mail" } }
                    }
                }
            }
        },
    )
}

/// Anonymous: sign-in page. A plain user: forbidden. Owner and admins pass.
async fn require_admin(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let viewer = Viewer::resolve(&parts, &state).await;
    if viewer.user.is_none() {
        return redirect("/login");
    }
    if !viewer.is_admin() {
        return forbidden();
    }
    next.run(Request::from_parts(parts, body)).await
}

/// Only the owner passes; everyone else is forbidden.
async fn require_owner(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let viewer = Viewer::resolve(&parts, &state).await;
    if !viewer.is_owner() {
        return forbidden();
    }
    next.run(Request::from_parts(parts, body)).await
}
