//! The activity log: one row per event, inside the caller's transaction or on its own.

use rusqlite::{Connection, params};

use crate::app::AppState;
use crate::db::DbError;

const DETAIL_LIMIT: usize = 500;

/// One activity row. Never holds a password, token, setup code, mail secret or tool data.
#[derive(Default)]
pub struct Event<'a> {
    pub kind: &'a str,
    pub user_id: Option<i64>,
    pub user_email: &'a str,
    pub server_id: Option<i64>,
    pub server_slug: &'a str,
    pub tool: &'a str,
    pub client: &'a str,
    pub decision: &'a str,
    pub outcome: &'a str,
    pub detail: &'a str,
    pub duration_ms: Option<i64>,
}

/// The same fields as `Event`, owned, for callers that build the row in a closure.
#[derive(Default)]
pub struct OwnedEvent {
    pub kind: String,
    pub user_id: Option<i64>,
    pub user_email: String,
    pub server_id: Option<i64>,
    pub server_slug: String,
    pub tool: String,
    pub client: String,
    pub decision: String,
    pub outcome: String,
    pub detail: String,
    pub duration_ms: Option<i64>,
}

impl OwnedEvent {
    fn borrowed(&self) -> Event<'_> {
        Event {
            kind: &self.kind,
            user_id: self.user_id,
            user_email: &self.user_email,
            server_id: self.server_id,
            server_slug: &self.server_slug,
            tool: &self.tool,
            client: &self.client,
            decision: &self.decision,
            outcome: &self.outcome,
            detail: &self.detail,
            duration_ms: self.duration_ms,
        }
    }
}

/// Inserts one row. `detail` is cut to 500 characters. Works inside a caller's transaction.
pub fn record(conn: &Connection, at: i64, event: &Event<'_>) -> rusqlite::Result<()> {
    let detail: String = event.detail.chars().take(DETAIL_LIMIT).collect();
    conn.execute(
        "INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, \
         client, decision, outcome, detail, duration_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            at,
            event.kind,
            event.user_id,
            event.user_email,
            event.server_id,
            event.server_slug,
            event.tool,
            event.client,
            event.decision,
            event.outcome,
            detail,
            event.duration_ms,
        ],
    )?;
    Ok(())
}

/// Convenience for callers outside a transaction. An error is returned, never ignored here.
pub async fn record_now(state: &AppState, event: OwnedEvent) -> Result<(), DbError> {
    let at = state.clock.now().unix_timestamp();
    state
        .db
        .call(move |conn| record(conn, at, &event.borrowed()))
        .await
}
