//! The activity page: the newest rows that match the user and server filters.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::html;
use rusqlite::{Connection, params};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::app::AppState;
use crate::db::DbError;
use crate::web::{internal_error, page};

const ROW_LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct ActivityQuery {
    user: Option<String>,
    server: Option<String>,
}

/// A filter from the query: absent, an id, or a value that matches no row.
#[derive(Clone, Copy)]
enum Filter {
    Any,
    Id(i64),
    Nothing,
}

impl Filter {
    fn of(text: Option<&str>) -> Filter {
        match text {
            None => Filter::Any,
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

/// The newest 500 rows that match, newest first.
pub async fn get_activity(
    State(state): State<AppState>,
    Query(query): Query<ActivityQuery>,
) -> Response {
    let user = Filter::of(query.user.as_deref());
    let server = Filter::of(query.server.as_deref());
    let rows: Result<Vec<Row>, DbError> = match (user, server) {
        (Filter::Nothing, _) | (_, Filter::Nothing) => Ok(Vec::new()),
        (user, server) => {
            state
                .db
                .call(move |conn| rows_in(conn, user.id(), server.id()))
                .await
        }
    };
    match rows {
        Ok(rows) => activity_page(&rows),
        Err(_) => internal_error(),
    }
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

fn activity_page(rows: &[Row]) -> Response {
    page(
        StatusCode::OK,
        "activity",
        "Activity",
        html! {
            h1 { "Activity" }
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
