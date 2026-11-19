//! The redirect allowlist: the shipped table, the stored entries and the decision.

use rusqlite::{Connection, TransactionBehavior, params};

use super::uri::{self, Redirect};

/// (scheme, host, path prefix) of the shipped entries. A prefix ending in `/` covers its subtree.
pub const SHIPPED: [(&str, &str, &str); 5] = [
    ("https", "claude.ai", "/api/mcp/auth_callback"),
    ("https", "chatgpt.com", "/connector_platform_oauth_redirect"),
    ("https", "chatgpt.com", "/connector/oauth/"),
    ("https", "www.cursor.com", "/agents/mcp/oauth/callback"),
    ("cursor", "anysphere.cursor-mcp", "/oauth/callback"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Blocked,
}

/// One allowlist row as the admin page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: i64,
    pub scheme: String,
    pub host: String,
    pub path_prefix: String,
    pub source: String,
    pub enabled: bool,
}

/// Loopback: always Allowed. Web: Allowed only when an ENABLED entry has the same scheme,
/// the same host, and a path rule that matches.
pub fn decide(conn: &Connection, redirect: &Redirect<'_>) -> rusqlite::Result<Verdict> {
    let Redirect::Web { scheme, host, path } = redirect else {
        return Ok(Verdict::Allowed);
    };
    let mut statement = conn.prepare(
        "SELECT path_prefix FROM redirect_allow WHERE scheme = ?1 AND host = ?2 AND enabled = 1",
    )?;
    let prefixes: Vec<String> = statement
        .query_map(params![scheme, host], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let allowed = prefixes
        .iter()
        .any(|prefix| path_rule_matches(prefix, path));
    Ok(if allowed {
        Verdict::Allowed
    } else {
        Verdict::Blocked
    })
}

/// A prefix ending in `/` covers every path under it; any other prefix is the path itself.
pub fn path_rule_matches(prefix: &str, path: &str) -> bool {
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        prefix == path
    }
}

/// True when `scheme://host` + `path_prefix` parses as a web address with exactly those parts.
/// An http scheme never parses as a web address, so it is refused here too.
pub fn admin_entry_ok(scheme: &str, host: &str, path_prefix: &str) -> bool {
    let text = format!("{scheme}://{host}{path_prefix}");
    matches!(
        uri::parse(&text),
        Some(Redirect::Web {
            scheme: parsed_scheme,
            host: parsed_host,
            path: parsed_path,
        }) if parsed_scheme == scheme && parsed_host == host && parsed_path == path_prefix
    )
}

/// Runs at every start: writes the shipped table, and deletes shipped rows that left it.
pub fn sync_shipped(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (scheme, host, path_prefix) in SHIPPED {
        tx.execute(
            "INSERT OR IGNORE INTO redirect_allow (scheme, host, path_prefix, source, enabled) \
             VALUES (?1, ?2, ?3, 'shipped', 1)",
            params![scheme, host, path_prefix],
        )?;
    }
    let stored: Vec<(i64, String, String, String)> = {
        let mut statement = tx.prepare(
            "SELECT id, scheme, host, path_prefix FROM redirect_allow WHERE source = 'shipped'",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?
    };
    for (id, scheme, host, path_prefix) in stored {
        if !is_shipped(&scheme, &host, &path_prefix) {
            tx.execute("DELETE FROM redirect_allow WHERE id = ?1", params![id])?;
        }
    }
    tx.commit()
}

fn is_shipped(scheme: &str, host: &str, path_prefix: &str) -> bool {
    SHIPPED
        .iter()
        .any(|(s, h, p)| *s == scheme && *h == host && *p == path_prefix)
}

/// Every row, shipped and added, in id order.
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Entry>> {
    let mut statement = conn.prepare(
        "SELECT id, scheme, host, path_prefix, source, enabled FROM redirect_allow ORDER BY id",
    )?;
    let rows = statement.query_map([], entry_of)?;
    rows.collect()
}

/// One row by id, or None.
pub fn entry(conn: &Connection, id: i64) -> rusqlite::Result<Option<Entry>> {
    let mut statement = conn.prepare(
        "SELECT id, scheme, host, path_prefix, source, enabled FROM redirect_allow WHERE id = ?1",
    )?;
    let mut rows = statement.query_map(params![id], entry_of)?;
    rows.next().transpose()
}

/// Adds an admin entry, or enables the identical entry that exists already.
pub fn add(conn: &Connection, scheme: &str, host: &str, path_prefix: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO redirect_allow (scheme, host, path_prefix, source, enabled) \
         VALUES (?1, ?2, ?3, 'added', 1) \
         ON CONFLICT (scheme, host, path_prefix) DO UPDATE SET enabled = 1",
        params![scheme, host, path_prefix],
    )?;
    Ok(())
}

/// Sets the enabled flag of one row. False when no such row exists.
pub fn set_enabled(conn: &Connection, id: i64, enabled: bool) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE redirect_allow SET enabled = ?1 WHERE id = ?2",
        params![enabled, id],
    )?;
    Ok(changed == 1)
}

fn entry_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    Ok(Entry {
        id: row.get(0)?,
        scheme: row.get(1)?,
        host: row.get(2)?,
        path_prefix: row.get(3)?,
        source: row.get(4)?,
        enabled: row.get(5)?,
    })
}
