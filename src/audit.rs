//! The activity log: one row per event, inside the caller's transaction or on its own.

use rusqlite::{Connection, params};

use crate::app::AppState;
use crate::db::DbError;
use crate::oauth::register::is_plain_char;

const DETAIL_LIMIT: usize = 500;
const TOOL_LIMIT: usize = 128;
/// The most refused tool calls one user may have rows for in any hour.
pub const REFUSED_ROWS_PER_HOUR: i64 = 100;
const HOUR: i64 = 3600;
/// Appended to the refused row that reaches REFUSED_ROWS_PER_HOUR.
const REFUSED_NOTICE: &str =
    " Further refused calls by this user are not recorded for up to an hour.";
const REPLACEMENT: char = '\u{FFFD}';

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

/// Inserts one row. `detail` is cut to 500 characters, `tool` to 128 and each non-plain
/// character of it is stored as U+FFFD. Works inside a caller's transaction.
pub fn record(conn: &Connection, at: i64, event: &Event<'_>) -> rusqlite::Result<()> {
    let detail: String = event.detail.chars().take(DETAIL_LIMIT).collect();
    insert(conn, at, event, &detail)
}

/// Inserts a refused call's row unless its user has REFUSED_ROWS_PER_HOUR in the hour before `at`.
/// The count and the write run in one connection call. The row that reaches the limit gets the notice.
pub fn record_refused(conn: &Connection, at: i64, event: &Event<'_>) -> rusqlite::Result<()> {
    let Some(user) = event.user_id else {
        return record(conn, at, event);
    };
    let seen: i64 = conn.query_row(
        "SELECT COUNT(*) FROM activity WHERE user_id = ?1 AND at > ?2 AND kind = 'tool_call' \
         AND decision = 'deny'",
        params![user, at.saturating_sub(HOUR)],
        |row| row.get(0),
    )?;
    if seen >= REFUSED_ROWS_PER_HOUR {
        return Ok(());
    }
    if seen + 1 == REFUSED_ROWS_PER_HOUR {
        let room = DETAIL_LIMIT - REFUSED_NOTICE.chars().count();
        let detail: String = event
            .detail
            .chars()
            .take(room)
            .chain(REFUSED_NOTICE.chars())
            .collect();
        return insert(conn, at, event, &detail);
    }
    record(conn, at, event)
}

fn insert(conn: &Connection, at: i64, event: &Event<'_>, detail: &str) -> rusqlite::Result<()> {
    let tool: String = event
        .tool
        .chars()
        .take(TOOL_LIMIT)
        .map(|c| if is_plain_char(c) { c } else { REPLACEMENT })
        .collect();
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
            tool,
            event.client,
            event.decision,
            event.outcome,
            detail,
            event.duration_ms,
        ],
    )?;
    Ok(())
}

/// Writes a `values_dropped` row: the user lost `count` stored header values. Holds no value.
pub fn values_dropped(
    conn: &Connection,
    at: i64,
    user_id: i64,
    email: &str,
    count: usize,
) -> rusqlite::Result<()> {
    let detail = format!("{count} stored header values were deleted");
    let event = Event {
        kind: "values_dropped",
        user_id: Some(user_id),
        user_email: email,
        detail: &detail,
        ..Default::default()
    };
    record(conn, at, &event)
}

/// Convenience for callers outside a transaction. An error is returned, never ignored here.
pub async fn record_now(state: &AppState, event: OwnedEvent) -> Result<(), DbError> {
    let at = state.clock.now().unix_timestamp();
    state
        .db
        .call(move |conn| record(conn, at, &event.borrowed()))
        .await
}

/// `record_now` for a refused tool call, under REFUSED_ROWS_PER_HOUR.
pub async fn record_refused_now(state: &AppState, event: OwnedEvent) -> Result<(), DbError> {
    let at = state.clock.now().unix_timestamp();
    state
        .db
        .call(move |conn| record_refused(conn, at, &event.borrowed()))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use tempfile::TempDir;

    fn open() -> (TempDir, Connection) {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("database");
        let conn = Connection::open(&path).expect("connection");
        (dir, conn)
    }

    /// Writes one tool_call row with this tool and detail, and returns the stored tool and detail.
    fn stored(conn: &Connection, tool: &str, detail: &str) -> (String, String) {
        let event = Event {
            kind: "tool_call",
            tool,
            decision: "deny",
            detail,
            ..Default::default()
        };
        record(conn, 1, &event).expect("the row is written");
        conn.query_row(
            "SELECT tool, detail FROM activity ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the row")
    }

    #[test]
    fn a_tool_longer_than_128_characters_is_stored_cut() {
        let (_dir, conn) = open();
        let (tool, _) = stored(&conn, &"x".repeat(300), "");
        assert_eq!(tool, "x".repeat(128));
    }

    #[test]
    fn a_tool_is_cut_by_characters_not_bytes() {
        let (_dir, conn) = open();
        let (tool, _) = stored(&conn, &"\u{e9}".repeat(200), "");
        assert_eq!(tool, "\u{e9}".repeat(128));
    }

    #[test]
    fn a_tool_of_exactly_128_characters_is_stored_whole() {
        let (_dir, conn) = open();
        let (tool, _) = stored(&conn, &"y".repeat(128), "");
        assert_eq!(tool, "y".repeat(128));
    }

    #[test]
    fn plain_text_in_a_tool_is_stored_as_it_is() {
        let (_dir, conn) = open();
        let name = "echo_tool-1.x \u{e9} \u{1F600}";
        let (tool, _) = stored(&conn, name, "");
        assert_eq!(tool, name);
    }

    #[test]
    fn each_character_that_is_not_plain_text_is_stored_as_the_replacement() {
        let (_dir, conn) = open();
        let (tool, _) = stored(&conn, "a\u{202E}b\u{7}c\u{200B}d", "");
        assert_eq!(tool, "a\u{FFFD}b\u{FFFD}c\u{FFFD}d");
    }

    #[test]
    fn the_cut_comes_before_the_replacement() {
        let (_dir, conn) = open();
        let name = format!("{}\u{202E}bbb", "a".repeat(127));
        let (tool, _) = stored(&conn, &name, "");
        assert_eq!(tool, format!("{}\u{FFFD}", "a".repeat(127)));
    }

    #[test]
    fn an_empty_tool_is_stored_empty() {
        let (_dir, conn) = open();
        let (tool, _) = stored(&conn, "", "");
        assert_eq!(tool, "");
    }

    #[test]
    fn a_detail_is_cut_to_500_characters() {
        let (_dir, conn) = open();
        let (_, detail) = stored(&conn, "echo", &"d".repeat(600));
        assert_eq!(detail, "d".repeat(500));
    }

    /// Writes a refused call row for `user` at `at` through `record_refused`.
    fn refused(conn: &Connection, at: i64, user: i64, detail: &str) {
        let event = Event {
            kind: "tool_call",
            user_id: Some(user),
            tool: "missing",
            decision: "deny",
            detail,
            ..Default::default()
        };
        record_refused(conn, at, &event).expect("the refused call's row is written");
    }

    fn rows_of(conn: &Connection, user: i64) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM activity WHERE user_id = ?1 AND decision = 'deny'",
            [user],
            |row| row.get(0),
        )
        .expect("the count")
    }

    #[test]
    fn the_hundredth_refused_row_carries_the_notice_and_the_next_writes_nothing() {
        let (_dir, conn) = open();
        for _ in 0..101 {
            refused(&conn, 1000, 1, "rule r");
        }
        assert_eq!(rows_of(&conn, 1), 100);
        let newest: String = conn
            .query_row(
                "SELECT detail FROM activity ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("the row");
        assert_eq!(newest, format!("rule r{REFUSED_NOTICE}"));
        let before: String = conn
            .query_row(
                "SELECT detail FROM activity ORDER BY id DESC LIMIT 1 OFFSET 1",
                [],
                |row| row.get(0),
            )
            .expect("the row");
        assert_eq!(
            before, "rule r",
            "the row before the hundredth has no notice"
        );
    }

    #[test]
    fn the_notice_fits_within_500_characters_after_a_long_detail() {
        let (_dir, conn) = open();
        for _ in 0..99 {
            refused(&conn, 1000, 1, "rule r");
        }
        refused(&conn, 1000, 1, &"d".repeat(600));
        let newest: String = conn
            .query_row(
                "SELECT detail FROM activity ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("the row");
        assert_eq!(newest.chars().count(), 500);
        assert!(newest.ends_with(REFUSED_NOTICE), "the notice is whole");
    }

    #[test]
    fn allowed_rows_are_never_counted() {
        let (_dir, conn) = open();
        for _ in 0..150 {
            let event = Event {
                kind: "tool_call",
                user_id: Some(1),
                tool: "echo",
                decision: "allow",
                ..Default::default()
            };
            record(&conn, 1000, &event).expect("the row");
        }
        refused(&conn, 1000, 1, "rule r");
        assert_eq!(
            rows_of(&conn, 1),
            1,
            "the first refused call writes its row"
        );
    }

    #[test]
    fn a_row_an_hour_old_no_longer_counts() {
        let (_dir, conn) = open();
        for _ in 0..100 {
            refused(&conn, 1000, 1, "rule r");
        }
        refused(&conn, 1000 + 3599, 1, "rule r");
        assert_eq!(
            rows_of(&conn, 1),
            100,
            "59 minutes 59 seconds later is still the hour"
        );
        refused(&conn, 1000 + 3600, 1, "rule r");
        assert_eq!(
            rows_of(&conn, 1),
            101,
            "an hour later the count starts again"
        );
    }

    #[test]
    fn each_user_has_their_own_hour() {
        let (_dir, conn) = open();
        for _ in 0..100 {
            refused(&conn, 1000, 1, "rule r");
        }
        refused(&conn, 1000, 2, "rule r");
        assert_eq!(rows_of(&conn, 2), 1);
    }
}
