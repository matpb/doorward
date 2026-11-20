//! The activity page: the rows that match the user and server filters, one page at a time, and the
//! newest rows the overview shows.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use form_urlencoded::Serializer;
use maud::{Markup, html};
use rusqlite::{Connection, params};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description;
use time::format_description::well_known::Rfc3339;

use crate::app::AppState;
use crate::db::{Db, DbError};
use crate::web::{Viewer, internal_error, page};

use super::panel_nav;

/// Rows on one page of the activity page.
const PAGE_SIZE: i64 = 50;
/// The day, month, year and UTC time of a row, as the page reads them.
const PLAIN_TIME: &str =
    "[day padding:none] [month repr:short] [year] [hour repr:24]:[minute]:[second] UTC";

#[derive(Deserialize)]
pub struct ActivityQuery {
    user: Option<String>,
    server: Option<String>,
    page: Option<String>,
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

/// One activity row as the page shows it: the RFC 3339 time, and the same time in plain words.
struct Row {
    time: String,
    plain: String,
    kind: String,
    user_email: String,
    server_slug: String,
    tool: String,
    decision: String,
    outcome: String,
    detail: String,
    duration_ms: Option<i64>,
}

/// What the activity page shows: one page of the matching rows, how many rows match in all, and
/// the choices of both filters.
struct Listing {
    rows: Vec<Row>,
    total: i64,
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
    let number = page_number(query.page.as_deref());
    let offset = offset_of(number);
    let listing = state
        .db
        .call(move |conn| {
            let (rows, total) = match (user, server) {
                (Filter::Nothing, _) | (_, Filter::Nothing) => (Vec::new(), 0),
                (user, server) => (
                    rows_in(conn, user.id(), server.id(), PAGE_SIZE, offset)?,
                    count_in(conn, user.id(), server.id())?,
                ),
            };
            Ok(Listing {
                rows,
                total,
                users: users_in(conn)?,
                servers: servers_in(conn)?,
            })
        })
        .await;
    match listing {
        Ok(listing) => activity_page(&viewer, &query, number, &listing),
        Err(err) => internal_error("activity page", &err),
    }
}

/// The page a query asks for, from 1. A missing, empty, zero, negative or non-numeric value is page
/// 1; digits too large for u64 are the largest u64.
pub(super) fn page_number(text: Option<&str>) -> u64 {
    let number = match text {
        None => 0,
        Some(text) => match text.parse::<u64>() {
            Ok(number) => number,
            Err(_) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
                u64::MAX
            }
            Err(_) => 0,
        },
    };
    number.max(1)
}

/// The rows before a page, saturated at the largest i64 so that no page overflows.
pub(super) fn offset_of(number: u64) -> i64 {
    let rows = number
        .saturating_sub(1)
        .saturating_mul(PAGE_SIZE.unsigned_abs());
    i64::try_from(rows).unwrap_or(i64::MAX)
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

/// The rows that match the filters, newest first, from `offset`, at most `limit` of them.
fn rows_in(
    conn: &Connection,
    user: Option<i64>,
    server: Option<i64>,
    limit: i64,
    offset: i64,
) -> rusqlite::Result<Vec<Row>> {
    let mut statement = conn.prepare(
        "SELECT at, kind, user_email, server_slug, tool, decision, outcome, detail, duration_ms \
         FROM activity WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR server_id = ?2) \
         ORDER BY at DESC, id DESC LIMIT ?3 OFFSET ?4",
    )?;
    let rows = statement.query_map(params![user, server, limit, offset], |row| {
        let at: i64 = row.get(0)?;
        Ok(Row {
            time: rfc3339(at)?,
            plain: plain_time(at)?,
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

/// How many rows match the filters, in all.
fn count_in(conn: &Connection, user: Option<i64>, server: Option<i64>) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM activity \
         WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR server_id = ?2)",
        params![user, server],
        |row| row.get(0),
    )
}

/// The UTC time of a unix timestamp as RFC 3339.
fn rfc3339(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    when.format(&Rfc3339).map_err(invalid_time)
}

/// The UTC time of a unix timestamp in plain words, such as `20 Nov 2026 19:25:09 UTC`.
pub(super) fn plain_time(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    let format = format_description::parse_borrowed::<2>(PLAIN_TIME).map_err(invalid_time)?;
    when.format(&format).map_err(invalid_time)
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
        form.filters method="get" action="/admin/activity" data-form="activity-filter" {
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
            button type="submit" data-kind="secondary" { "Filter" }
        }
    }
}

/// The label of a row in plain words, and the tone of its marker when the row needs one.
pub(super) fn label_of(
    kind: &str,
    decision: &str,
    outcome: &str,
) -> (String, Option<&'static str>) {
    let (label, tone) = match kind {
        "tool_call" if decision == "deny" => ("Tool call refused", Some("bad")),
        "tool_call" if outcome == "ok" => ("Tool call", None),
        "tool_call" => ("Tool call failed", Some("bad")),
        "login" => ("Sign-in", None),
        "login_failed" => ("Sign-in refused", Some("bad")),
        "client_connected" => ("Client connected", None),
        "client_disconnected" => ("Client disconnected", None),
        "admin_change" => ("Admin change", None),
        "invitation" => ("Invitation", None),
        "mail_failed" => ("Mail not sent", Some("warn")),
        "owner_created" => ("Owner created", None),
        "reset" => ("Password reset", None),
        "password_change" => ("Password changed", None),
        "redirect_blocked" => ("Redirect blocked", Some("warn")),
        "tool_appeared" => ("New tool listed", None),
        "unlock" => ("Gateway unlocked", None),
        _ => return (unknown_label(kind), None),
    };
    (label.to_owned(), tone)
}

/// A kind no label names: its underscores become spaces and its first letter is upper case.
fn unknown_label(kind: &str) -> String {
    let spaced = kind.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// One row as an item of the list: its attributes, its label, its time and its detail.
fn row_item(row: &Row) -> Markup {
    let (label, tone) = label_of(&row.kind, &row.decision, &row.outcome);
    html! {
        li data-kind=(row.kind) data-user=(row.user_email) data-server=(row.server_slug)
            data-tool=(row.tool) data-decision=(row.decision) data-outcome=(row.outcome)
            data-time=(row.time) data-duration-ms=[row.duration_ms] {
            div.row-main {
                p.row-title {
                    span data-label data-tone=[tone] { (label) }
                }
                p.row-meta {
                    time datetime=(row.time) { (row.plain) }
                }
                p.row-meta { (row.user_email) " " (row.server_slug) " " (row.tool) }
                p.row-meta { (row.decision) " " (row.outcome) }
                @if !row.detail.is_empty() {
                    p.detail { (row.detail) }
                }
            }
        }
    }
}

/// The rows as an ordered list, newest first.
fn rows_list(rows: &[Row]) -> Markup {
    html! {
        ol.activity.rows {
            @for row in rows {
                (row_item(row))
            }
        }
    }
}

/// The newest `limit` rows of the activity log in the markup of the activity page, or a sentence
/// when there are none. Used by the overview.
pub(super) async fn latest(db: &Db, limit: i64) -> Result<Markup, DbError> {
    let rows = db
        .call(move |conn| rows_in(conn, None, None, limit, 0))
        .await?;
    Ok(html! {
        @if rows.is_empty() {
            p { "No activity yet." }
        } @else {
            (rows_list(&rows))
        }
    })
}

/// The page the newer link names: the one before this, or the last page with rows when this page
/// lies past the end.
fn newer_page(number: u64, total: i64) -> u64 {
    let last = u64::try_from(total)
        .unwrap_or(0)
        .div_ceil(PAGE_SIZE.unsigned_abs());
    if total > 0 && number > last {
        last
    } else {
        number.saturating_sub(1)
    }
}

/// The links to the pages before and after this one. Each keeps the filters as the filter form
/// submits them, with the page number.
fn pager(query: &ActivityQuery, number: u64, total: i64, older: bool) -> Markup {
    let user = query.user.as_deref().unwrap_or("");
    let server = query.server.as_deref().unwrap_or("");
    let link = |target: u64| {
        let query = Serializer::new(String::new())
            .append_pair("user", user)
            .append_pair("server", server)
            .append_pair("page", &target.to_string())
            .finish();
        format!("/admin/activity?{query}")
    };
    let newer = number > 1;
    html! {
        @if newer || older {
            nav.pager aria-label="Pages" {
                @if newer {
                    a.button data-kind="secondary" data-page-link="newer" href=(link(newer_page(number, total))) { "Newer" }
                }
                @if older {
                    a.button data-kind="secondary" data-page-link="older" href=(link(number.saturating_add(1))) { "Older" }
                }
            }
        }
    }
}

fn activity_page(
    viewer: &Viewer,
    query: &ActivityQuery,
    number: u64,
    listing: &Listing,
) -> Response {
    let user = Filter::of(query.user.as_deref());
    let server = Filter::of(query.server.as_deref());
    let rows = &listing.rows;
    let offset = offset_of(number);
    let end = offset.saturating_add(i64::try_from(rows.len()).unwrap_or(i64::MAX));
    let older = end < listing.total;
    page(
        StatusCode::OK,
        "activity",
        "Activity",
        html! {
            (panel_nav(viewer, "/admin/activity"))
            div.stack {
                h1 { "Activity" }
                (filter_form(user, server, &listing.users, &listing.servers))
                @if rows.is_empty() {
                    p { "No activity matches." }
                } @else {
                    p data-range {
                        (format!("Rows {} to {} of {}", offset.saturating_add(1), end, listing.total))
                    }
                    (rows_list(rows))
                }
                (pager(query, number, listing.total, older))
            }
        },
    )
}
