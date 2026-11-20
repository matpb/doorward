//! The admin panel. One nested router behind the admin check; the mail routes add the owner check.

mod activity;
mod invitations;
mod mail;
mod redirects;
mod rules;
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
use maud::{Markup, html};
use rusqlite::{Connection, params};

use crate::app::AppState;
use crate::web::{Viewer, forbidden, internal_error, page, redirect};

/// The newest activity rows the overview shows.
const LATEST_ROWS: i64 = 5;

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
        .route("/rules", get(rules::get_rules).post(rules::post_add))
        .route("/rules/{id}/delete", post(rules::post_delete))
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

async fn panel(viewer: Viewer, State(state): State<AppState>) -> Response {
    let now = state.clock.now().unix_timestamp();
    let counted = state.db.call(move |conn| counts_in(conn, now)).await;
    let latest = activity::latest(&state.db, LATEST_ROWS).await;
    match (counted, latest) {
        (Ok(counts), Ok(latest)) => page(
            StatusCode::OK,
            "admin",
            "Admin",
            html! {
                (panel_nav(&viewer, "/admin"))
                div.stack {
                    h1 { "Admin" }
                    (counts_markup(&counts))
                    section.card data-latest-activity {
                        h2 { "Latest activity" }
                        (latest)
                        p { a href="/admin/activity" { "All activity" } }
                    }
                }
            },
        ),
        (Err(err), _) | (_, Err(err)) => internal_error("admin overview", &err),
    }
}

/// The counts of the overview, read in one query. Open invitations are those not yet expired: an
/// accepted or revoked invitation is deleted, so this is the list of the invitations page.
struct Counts {
    servers: i64,
    users: i64,
    invitations: i64,
    rules: i64,
}

fn counts_in(conn: &Connection, now: i64) -> rusqlite::Result<Counts> {
    conn.query_row(
        "SELECT (SELECT COUNT(*) FROM servers), (SELECT COUNT(*) FROM users), \
         (SELECT COUNT(*) FROM invitations WHERE expires_at > ?1), (SELECT COUNT(*) FROM rules)",
        params![now],
        |row| {
            Ok(Counts {
                servers: row.get(0)?,
                users: row.get(1)?,
                invitations: row.get(2)?,
                rules: row.get(3)?,
            })
        },
    )
}

/// The four counts, each a card that links to its page.
fn counts_markup(counts: &Counts) -> Markup {
    html! {
        div.counts {
            (count_link("servers", "/admin/servers", "Servers", counts.servers))
            (count_link("users", "/admin/users", "Users", counts.users))
            (count_link("invitations", "/admin/invitations", "Open invitations", counts.invitations))
            (count_link("rules", "/admin/rules", "Rules", counts.rules))
        }
    }
}

fn count_link(key: &str, href: &str, label: &str, value: i64) -> Markup {
    html! {
        a.count.card data-count=(key) href=(href) {
            span.count-label { (label) }
            span.count-value data-count-value { (value) }
        }
    }
}

/// The links of the panel navigation: label, path, and whether only the owner sees it.
const PANEL_LINKS: [(&str, &str, bool); 9] = [
    ("Admin", "/admin", false),
    ("Users", "/admin/users", false),
    ("Invitations", "/admin/invitations", false),
    ("Servers", "/admin/servers", false),
    ("Rules", "/admin/rules", false),
    ("Redirects", "/admin/redirects", false),
    ("Activity", "/admin/activity", false),
    ("Mail", "/admin/mail", true),
    ("Your account", "/account", false),
];

/// The navigation of every page of the panel, first in main. `current` is the path of the
/// section shown; its link is marked as the current page.
fn panel_nav(viewer: &Viewer, current: &str) -> Markup {
    html! {
        nav data-nav="panel" {
            ul {
                @for (label, href, owner_only) in PANEL_LINKS {
                    @if !owner_only || viewer.is_owner() {
                        li {
                            a href=(href) aria-current=[(href == current).then_some("page")] { (label) }
                        }
                    }
                }
            }
        }
    }
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
