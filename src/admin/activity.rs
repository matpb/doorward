//! The activity page: the newest rows that match the user and server filters.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, params};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::app::AppState;
use crate::web::{Viewer, internal_error, page};

use super::panel_nav;

const ROW_LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct ActivityQuery {
    user: Option<String>,
    server: Option<String>,
}

/// A filter from the query: absent or empty, an id, or a value that matches no row.
#[derive(Clone, Copy)]
enum Filter {
    Any,
    Id(i64),
    Nothing,
}

impl Filter {
    fn of(text: Option<&str>) -> Filter {
        match text {
            None | Some("") => Filter::Any,
            Some(text) => text.parse::<i64>().map_or(Filter::Nothing, Filter::Id),
        }
    }

    fn id(self) -> Option<i64> {
        match self {
            Filter::Id(id) => Some(id),
            Filter::Any | Filter::Nothing => None,
        }
    }
}

/// One activity row as the page shows it.
struct Row {
    time: String,
    kind: String,
    user_email: String,
    server_slug: String,
    tool: String,
    decision: String,
    outcome: String,
    detail: String,
    duration_ms: Option<i64>,
}

/// What the activity page shows: the newest 500 matching rows and the choices of both filters.
struct Listing {
    rows: Vec<Row>,
    users: Vec<UserOption>,
    servers: Vec<ServerOption>,
}

/// A user the user filter offers.
struct UserOption {
    id: i64,
    email: String,
}

/// A server the server filter offers.
struct ServerOption {
    id: i64,
    name: String,
    slug: String,
}

pub async fn get_activity(
    viewer: Viewer,
    State(state): State<AppState>,
    Query(query): Query<ActivityQuery>,
) -> Response {
    let user = Filter::of(query.user.as_deref());
    let server = Filter::of(query.server.as_deref());
    let listing = state
        .db
        .call(move |conn| {
            let rows = match (user, server) {
                (Filter::Nothing, _) | (_, Filter::Nothing) => Vec::new(),
                (user, server) => rows_in(conn, user.id(), server.id())?,
            };
            Ok(Listing {
                rows,
                users: users_in(conn)?,
                servers: servers_in(conn)?,
            })
        })
        .await;
    match listing {
        Ok(listing) => activity_page(&viewer, user, server, &listing),
        Err(_) => internal_error(),
    }
}

/// Every user, ordered by email.
fn users_in(conn: &Connection) -> rusqlite::Result<Vec<UserOption>> {
    let mut statement = conn.prepare("SELECT id, email FROM users ORDER BY email")?;
    let rows = statement.query_map([], |row| {
        Ok(UserOption {
            id: row.get(0)?,
            email: row.get(1)?,
        })
    })?;
    rows.collect()
}

/// Every server, ordered by slug.
fn servers_in(conn: &Connection) -> rusqlite::Result<Vec<ServerOption>> {
    let mut statement = conn.prepare("SELECT id, name, slug FROM servers ORDER BY slug")?;
    let rows = statement.query_map([], |row| {
        Ok(ServerOption {
            id: row.get(0)?,
            name: row.get(1)?,
            slug: row.get(2)?,
        })
    })?;
    rows.collect()
}

fn rows_in(
    conn: &Connection,
    user: Option<i64>,
    server: Option<i64>,
) -> rusqlite::Result<Vec<Row>> {
    let mut statement = conn.prepare(
        "SELECT at, kind, user_email, server_slug, tool, decision, outcome, detail, duration_ms \
         FROM activity WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR server_id = ?2) \
         ORDER BY at DESC, id DESC LIMIT ?3",
    )?;
    let rows = statement.query_map(params![user, server, ROW_LIMIT], |row| {
        let at: i64 = row.get(0)?;
        Ok(Row {
            time: rfc3339(at)?,
            kind: row.get(1)?,
            user_email: row.get(2)?,
            server_slug: row.get(3)?,
            tool: row.get(4)?,
            decision: row.get(5)?,
            outcome: row.get(6)?,
            detail: row.get(7)?,
            duration_ms: row.get(8)?,
        })
    })?;
    rows.collect()
}

/// The UTC time of a unix timestamp as RFC 3339.
fn rfc3339(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    when.format(&Rfc3339).map_err(invalid_time)
}

fn invalid_time<E>(err: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

/// The filter form. Each select marks the option of the current filter as selected.
fn filter_form(
    user: Filter,
    server: Filter,
    users: &[UserOption],
    servers: &[ServerOption],
) -> Markup {
    html! {
        form method="get" action="/admin/activity" data-form="activity-filter" {
            label for="filter-user" { "User" }
            select id="filter-user" name="user" {
                option value="" { "Any user" }
                @for choice in users {
                    option value=(choice.id) selected[user.id() == Some(choice.id)] {
                        (choice.email)
                    }
                }
            }
            label for="filter-server" { "Server" }
            select id="filter-server" name="server" {
                option value="" { "Any server" }
                @for choice in servers {
                    option value=(choice.id) selected[server.id() == Some(choice.id)] {
                        (choice.name) " (" (choice.slug) ")"
                    }
                }
            }
            button type="submit" { "Filter" }
        }
    }
}

fn activity_page(viewer: &Viewer, user: Filter, server: Filter, listing: &Listing) -> Response {
    let rows = &listing.rows;
    page(
        StatusCode::OK,
        "activity",
        "Activity",
        html! {
            (panel_nav(viewer, "/admin/activity"))
            h1 { "Activity" }
            (filter_form(user, server, &listing.users, &listing.servers))
            @if rows.is_empty() {
                p { "No activity matches." }
            }
            ol.activity {
                @for row in rows {
                    li data-kind=(row.kind) data-user=(row.user_email) data-server=(row.server_slug)
                        data-tool=(row.tool) data-decision=(row.decision) data-outcome=(row.outcome)
                        data-time=(row.time) data-duration-ms=[row.duration_ms] {
                        p {
                            strong { (row.kind) }
                            " " (row.time)
                        }
                        p { (row.user_email) " " (row.server_slug) " " (row.tool) }
                        p { (row.decision) " " (row.outcome) }
                        @if !row.detail.is_empty() {
                            p.detail { (row.detail) }
                        }
                    }
                }
            }
        },
    )
}
