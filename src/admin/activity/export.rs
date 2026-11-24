//! The CSV export of the activity page: the rows the filters match, oldest first, read in chunks and
//! streamed as the body.

use std::io;

use axum::body::{Body, Bytes};
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, header};
use axum::response::Response;
use futures_util::stream;
use rusqlite::types::Value;
use rusqlite::{Connection, params_from_iter};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::db::Db;
use crate::report;
use crate::web::{Viewer, internal_error, redirect};

use super::filters::{Criteria, Filters, criteria};
use super::{count_in, label_of, rfc3339};

/// Rows read from the table per chunk, so that one chunk at a time is in memory.
const CHUNK: i64 = 5000;
const HEADER: &str =
    "time_utc,event,user,server,tool,client,decision,outcome,detail,duration_ms\r\n";

/// GET /admin/activity.csv: the rows the filters match, oldest first. It writes one admin_change
/// row with their count, which is not one of them.
pub async fn get_export(
    viewer: Viewer,
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(actor) = viewer.user else {
        return redirect("/login");
    };
    let filters = Filters::of(raw.as_deref());
    let now = state.clock.now().unix_timestamp();
    let scope = criteria(&filters, now);
    let (actor_id, actor_email) = (actor.id, actor.email);
    let prepared = state
        .db
        .call(move |conn| {
            // Rows written after this count, the export row included, have a larger id and stay out.
            let bound = largest_id(conn)?;
            let mut scoped = scope;
            scoped.add("id <= ?", vec![Value::Integer(bound)]);
            let count = count_in(conn, &scoped)?;
            let detail = format!("exported activity ({count} rows)");
            audit::record(
                conn,
                now,
                &Event {
                    kind: "admin_change",
                    user_id: Some(actor_id),
                    user_email: &actor_email,
                    detail: &detail,
                    ..Default::default()
                },
            )?;
            Ok(scoped)
        })
        .await;
    match prepared {
        Ok(scope) => csv_response(state.db, scope),
        Err(err) => internal_error("activity export", &err),
    }
}

fn largest_id(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COALESCE(MAX(id), 0) FROM activity", [], |row| {
        row.get(0)
    })
}

/// The CSV response: the header line, then the rows in chunks, as the body streams.
fn csv_response(db: Db, scope: Criteria) -> Response {
    let walk = Walk {
        db,
        scope,
        last: (i64::MIN, i64::MIN),
        header_sent: false,
        done: false,
    };
    let mut response = Response::new(Body::from_stream(stream::unfold(walk, next_part)));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"doorward-activity.csv\""),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Where the body stream is: what is sent, and the (at, id) of the last row sent.
struct Walk {
    db: Db,
    scope: Criteria,
    last: (i64, i64),
    header_sent: bool,
    done: bool,
}

/// The next part of the body: the header line, then one chunk after the last row sent. A failed
/// read ends the body with an error, which the server reports by closing the response.
async fn next_part(mut walk: Walk) -> Option<(Result<Bytes, io::Error>, Walk)> {
    if !walk.header_sent {
        walk.header_sent = true;
        return Some((Ok(Bytes::from_static(HEADER.as_bytes())), walk));
    }
    if walk.done {
        return None;
    }
    let (scope, after) = (walk.scope.clone(), walk.last);
    match walk
        .db
        .call(move |conn| chunk_after(conn, &scope, after))
        .await
    {
        Ok(chunk) if chunk.count == 0 => None,
        Ok(chunk) => {
            walk.last = chunk.last;
            walk.done = chunk.count < usize::try_from(CHUNK).unwrap_or(usize::MAX);
            Some((Ok(Bytes::from(chunk.text)), walk))
        }
        Err(err) => {
            report::failure("activity export", &err);
            walk.done = true;
            Some((Err(io::Error::other("the activity export stopped")), walk))
        }
    }
}

/// The CSV lines of up to CHUNK rows after `after` in (at, id) order.
struct Chunk {
    text: String,
    count: usize,
    last: (i64, i64),
}

fn chunk_after(conn: &Connection, scope: &Criteria, after: (i64, i64)) -> rusqlite::Result<Chunk> {
    let mut keyed = scope.clone();
    keyed.add(
        "at >= ? AND (at > ? OR id > ?)",
        vec![
            Value::Integer(after.0),
            Value::Integer(after.0),
            Value::Integer(after.1),
        ],
    );
    let sql = format!(
        "SELECT id, at, kind, user_email, server_slug, tool, client, decision, outcome, detail, \
         duration_ms FROM activity{} ORDER BY at, id LIMIT {CHUNK}",
        keyed.clause()
    );
    let mut statement = conn.prepare_cached(&sql)?;
    let rows = statement.query_map(params_from_iter(keyed.values()), |row| {
        let id: i64 = row.get(0)?;
        let at: i64 = row.get(1)?;
        let kind: String = row.get(2)?;
        let decision: String = row.get(7)?;
        let outcome: String = row.get(8)?;
        let duration: Option<i64> = row.get(10)?;
        let cells = [
            rfc3339(at)?,
            label_of(&kind, &decision, &outcome).0,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            decision,
            outcome,
            row.get(9)?,
            duration.map_or_else(String::new, |ms| ms.to_string()),
        ];
        Ok(((at, id), cells))
    })?;
    let mut chunk = Chunk {
        text: String::new(),
        count: 0,
        last: after,
    };
    for row in rows {
        let (key, cells) = row?;
        push_record(&mut chunk.text, &cells);
        chunk.last = key;
        chunk.count += 1;
    }
    Ok(chunk)
}

/// One CSV record, its cells separated by commas and ended by CRLF.
fn push_record(out: &mut String, cells: &[String]) {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_cell(out, cell);
    }
    out.push_str("\r\n");
}

/// One cell. A cell that starts with a formula character gets a leading quote. A cell holding a
/// comma, a quote, a CR or an LF is wrapped in quotes, with each quote in it doubled.
fn push_cell(out: &mut String, cell: &str) {
    let quoted = cell.contains([',', '"', '\r', '\n']);
    let guarded = cell.starts_with(['=', '+', '-', '@', '\t', '\r']);
    if quoted {
        out.push('"');
    }
    if guarded {
        out.push('\'');
    }
    for ch in cell.chars() {
        if ch == '"' {
            out.push('"');
        }
        out.push(ch);
    }
    if quoted {
        out.push('"');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(text: &str) -> String {
        let mut out = String::new();
        push_cell(&mut out, text);
        out
    }

    #[test]
    fn a_plain_cell_is_unchanged() {
        assert_eq!(cell("bob@example.com"), "bob@example.com");
        assert_eq!(cell(""), "");
        assert_eq!(
            cell("a=1"),
            "a=1",
            "a formula character inside a cell is not guarded"
        );
    }

    #[test]
    fn a_cell_with_a_comma_quote_or_line_break_is_quoted_with_doubled_quotes() {
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("one\ntwo"), "\"one\ntwo\"");
        assert_eq!(cell("one\rtwo"), "\"one\rtwo\"");
    }

    #[test]
    fn each_formula_character_at_the_start_gets_a_leading_quote() {
        for (text, want) in [
            ("=1+1", "'=1+1"),
            ("+x", "'+x"),
            ("-x", "'-x"),
            ("@x", "'@x"),
            ("\tx", "'\tx"),
            ("\rx", "\"'\rx\""),
        ] {
            assert_eq!(cell(text), want, "{text:?} must be guarded");
        }
    }

    #[test]
    fn a_record_ends_in_crlf_and_separates_its_cells_with_commas() {
        let mut out = String::new();
        push_record(&mut out, &["a".into(), String::new(), "c,d".into()]);
        assert_eq!(out, "a,,\"c,d\"\r\n");
    }
}
