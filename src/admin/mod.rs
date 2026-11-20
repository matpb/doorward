//! The admin panel. One nested router behind the admin check; the mail routes add the owner check.

mod activity;
mod invitations;
mod mail;
mod redirects;
mod servers;
#[cfg(test)]
mod tests;
mod users;

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
        .route(
            "/redirects",
            get(redirects::get_redirects).post(redirects::post_add),
        )
        .route("/redirects/{id}/disable", post(redirects::post_disable))
        .route("/redirects/{id}/enable", post(redirects::post_enable))
        .route(
            "/invitations",
            get(invitations::get_invitations).post(invitations::post_invitation),
        )
        .route("/invitations/{id}/revoke", post(invitations::post_revoke))
        .route("/users", get(users::get_users))
        .route("/users/{id}", get(users::get_user))
        .route("/users/{id}/role", post(users::post_role))
        .route("/users/{id}/disable", post(users::post_disable))
        .route("/users/{id}/enable", post(users::post_enable))
        .route("/users/{id}/delete", post(users::post_delete))
        .route("/users/{id}/servers", post(users::post_servers))
        .route(
            "/servers",
            get(servers::get_servers).post(servers::post_server),
        )
        .route(
            "/servers/{id}",
            get(servers::get_server).post(servers::post_update),
        )
        .route("/servers/{id}/delete", post(servers::post_delete))
        .route("/servers/{id}/users", post(servers::post_users))
        .route(
            "/servers/{id}/refresh-tools",
            post(servers::post_refresh_tools),
        )
        .route(
            "/servers/{id}/check-lockdown",
            post(servers::post_check_lockdown),
        )
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
                    li { a href="/admin/users" { "Users" } }
                    li { a href="/admin/invitations" { "Invitations" } }
                    li { a href="/admin/servers" { "Servers" } }
                    li { a href="/admin/redirects" { "Redirects" } }
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
