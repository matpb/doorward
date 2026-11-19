use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::audit::{self, Event};
use crate::db::{Db, DbError};

use super::session;

/// The result of reserving one sign-in attempt.
pub enum Attempt {
    /// Refused before any password check, and not counted.
    Blocked,
    /// A failure is reserved. `phc` is the hash of an enabled account, else None.
    Counted {
        failure_id: i64,
        user_id: Option<i64>,
        phc: Option<String>,
    },
}

/// What the reservation transaction needs. `account` is the token hash of the email.
pub struct Reserve {
    pub account: String,
    pub address: String,
    pub email: String,
    pub now: i64,
    pub block_seconds: i64,
    pub account_failures: i64,
    pub address_failures: i64,
}

/// What a successful sign-in needs. `previous` is the cookie value the browser sent.
pub struct Success {
    pub account: String,
    pub failure_id: i64,
    pub user_id: i64,
    pub email: String,
    pub previous: Option<String>,
    pub now: i64,
    pub lifetime: i64,
}

/// Transaction T1: prunes old failures, checks both limits, reserves one failure and reads the user.
pub async fn reserve(db: &Db, input: Reserve) -> Result<Attempt, DbError> {
    db.call(move |conn| reserve_in(conn, &input)).await
}

/// Transaction T2: clears the account and the reservation, and signs the browser in.
pub async fn succeed(db: &Db, success: Success) -> Result<String, DbError> {
    db.call(move |conn| succeed_in(conn, &success)).await
}

fn reserve_in(conn: &mut Connection, input: &Reserve) -> rusqlite::Result<Attempt> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let oldest_kept = input.now.saturating_sub(input.block_seconds);
    tx.execute(
        "DELETE FROM login_failures WHERE at <= ?1",
        params![oldest_kept],
    )?;
    let address_rows: i64 = tx.query_row(
        "SELECT COUNT(*) FROM login_failures WHERE address = ?1",
        params![input.address],
        |row| row.get(0),
    )?;
    if address_rows > input.address_failures {
        tx.commit()?;
        return Ok(Attempt::Blocked);
    }
    let stored: Option<(i64, i64)> = tx
        .query_row(
            "SELECT failures, last_failed_at FROM login_blocks WHERE account_hash = ?1",
            params![input.account],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let failures = match stored {
        Some((failures, last_failed_at))
            if input.now < last_failed_at.saturating_add(input.block_seconds) =>
        {
            failures
        }
        _ => 0,
    };
    if failures >= input.account_failures {
        tx.commit()?;
        return Ok(Attempt::Blocked);
    }
    tx.execute(
        "INSERT INTO login_blocks (account_hash, failures, last_failed_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(account_hash) DO UPDATE SET \
         failures = excluded.failures, last_failed_at = excluded.last_failed_at",
        params![input.account, failures + 1, input.now],
    )?;
    tx.execute(
        "INSERT INTO login_failures (address, at) VALUES (?1, ?2)",
        params![input.address, input.now],
    )?;
    let failure_id = tx.last_insert_rowid();
    let user: Option<(i64, String, i64)> = tx
        .query_row(
            "SELECT id, password_hash, disabled FROM users WHERE email = ?1",
            params![input.email],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    tx.commit()?;
    let (user_id, phc) = match user {
        Some((id, hash, 0)) => (Some(id), Some(hash)),
        Some((id, _, _)) => (Some(id), None),
        None => (None, None),
    };
    Ok(Attempt::Counted {
        failure_id,
        user_id,
        phc,
    })
}

fn succeed_in(conn: &mut Connection, success: &Success) -> rusqlite::Result<String> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM login_blocks WHERE account_hash = ?1",
        params![success.account],
    )?;
    tx.execute(
        "DELETE FROM login_failures WHERE id = ?1",
        params![success.failure_id],
    )?;
    if let Some(previous) = &success.previous {
        session::delete(&tx, previous)?;
    }
    let token = session::insert(&tx, success.user_id, success.now, success.lifetime)?;
    let login = Event {
        kind: "login",
        user_id: Some(success.user_id),
        user_email: &success.email,
        ..Default::default()
    };
    audit::record(&tx, success.now, &login)?;
    tx.commit()?;
    Ok(token)
}
