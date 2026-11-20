//! The upstream session ids the gateway relayed: stored as hashes, bound to a server, user and family.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::crypto::token_hash;
use crate::oauth::guard::Caller;

/// The most sessions one token family keeps on one server; the oldest beyond it are removed.
const SESSIONS_PER_FAMILY: i64 = 32;

/// Records an id the upstream issued to `caller`, in one immediate transaction. True when the id is
/// new for the server or already belongs to this caller's user and family; false when another owns it.
pub fn record(
    conn: &mut Connection,
    server_id: i64,
    session_id: &str,
    caller: &Caller,
    now: i64,
) -> rusqlite::Result<bool> {
    let hash = token_hash(session_id);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let owner: Option<(i64, i64)> = tx
        .query_row(
            "SELECT user_id, family_id FROM upstream_sessions WHERE server_id = ?1 AND id_hash = ?2",
            params![server_id, hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let relayed = match owner {
        Some(owner) => owner == (caller.user_id, caller.family_id),
        None => {
            tx.execute(
                "INSERT INTO upstream_sessions (server_id, id_hash, user_id, family_id, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![server_id, hash, caller.user_id, caller.family_id, now],
            )?;
            tx.execute(
                "DELETE FROM upstream_sessions WHERE server_id = ?1 AND family_id = ?2 \
                 AND rowid NOT IN (SELECT rowid FROM upstream_sessions \
                 WHERE server_id = ?1 AND family_id = ?2 ORDER BY created_at DESC, rowid DESC LIMIT ?3)",
                params![server_id, caller.family_id, SESSIONS_PER_FAMILY],
            )?;
            true
        }
    };
    tx.commit()?;
    Ok(relayed)
}

/// True when the id was recorded for this server, user and token family.
pub fn belongs(
    conn: &Connection,
    server_id: i64,
    session_id: &str,
    caller: &Caller,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM upstream_sessions \
         WHERE server_id = ?1 AND id_hash = ?2 AND user_id = ?3 AND family_id = ?4)",
        params![
            server_id,
            token_hash(session_id),
            caller.user_id,
            caller.family_id
        ],
        |row| row.get(0),
    )
}

/// Removes the id from the server's records, whether or not it was there.
pub fn forget(conn: &Connection, server_id: i64, session_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM upstream_sessions WHERE server_id = ?1 AND id_hash = ?2",
        params![server_id, token_hash(session_id)],
    )?;
    Ok(())
}
