use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::audit::{self, Event};
use crate::crypto::token_hash;
use crate::db::{Db, DbError};

use super::input::normalize_email;
use super::session;

/// The result of reserving one sign-in attempt.
pub enum Attempt {
    /// Refused before any password check, and not counted.
    Blocked,
    /// A failure is reserved. `phc` is the hash of an enabled account, else None.
    /// `epoch` is the account's auth epoch.
    Counted {
        failure_id: i64,
        user_id: Option<i64>,
        phc: Option<String>,
        epoch: Option<i64>,
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

/// What a successful sign-in needs. `previous` is the cookie value the browser sent. `phc` and
/// `epoch` are the hash that was verified and the auth epoch read with it.
pub struct Success {
    pub account: String,
    pub failure_id: i64,
    pub user_id: i64,
    pub email: String,
    pub previous: Option<String>,
    pub now: i64,
    pub lifetime: i64,
    pub phc: String,
    pub epoch: i64,
}

/// Transaction T1: prunes old failures, checks both limits, reserves one failure and reads the user.
pub async fn reserve(db: &Db, input: Reserve) -> Result<Attempt, DbError> {
    db.call(move |conn| reserve_in(conn, &input)).await
}

/// Transaction T2: clears the account and the reservation, and signs the browser in. None, with
/// nothing changed, when the user no longer matches the verified hash and epoch, or is disabled.
pub async fn succeed(db: &Db, success: Success) -> Result<Option<String>, DbError> {
    db.call(move |conn| succeed_in(conn, &success)).await
}

/// Deletes the login block of an account (the hash of its normalised email).
pub fn lift_block(conn: &Connection, email: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM login_blocks WHERE account_hash = ?1",
        params![token_hash(&normalize_email(email))],
    )?;
    Ok(())
}

/// Clears the account's block and its reserved failure, as a successful sign-in does.
pub fn clear_attempt(conn: &Connection, account: &str, failure_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM login_blocks WHERE account_hash = ?1",
        params![account],
    )?;
    conn.execute(
        "DELETE FROM login_failures WHERE id = ?1",
        params![failure_id],
    )?;
    Ok(())
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
    let user: Option<(i64, String, i64, i64)> = tx
        .query_row(
            "SELECT id, password_hash, disabled, auth_epoch FROM users WHERE email = ?1",
            params![input.email],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    tx.commit()?;
    let (user_id, phc, epoch) = match user {
        Some((id, hash, 0, epoch)) => (Some(id), Some(hash), Some(epoch)),
        Some((id, _, _, epoch)) => (Some(id), None, Some(epoch)),
        None => (None, None, None),
    };
    Ok(Attempt::Counted {
        failure_id,
        user_id,
        phc,
        epoch,
    })
}

fn succeed_in(conn: &mut Connection, success: &Success) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !still_current(&tx, success)? {
        return Ok(None);
    }
    clear_attempt(&tx, &success.account, success.failure_id)?;
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
    Ok(Some(token))
}

/// True when the user is enabled and still has the verified hash and auth epoch.
fn still_current(conn: &Connection, success: &Success) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1 AND password_hash = ?2 \
         AND auth_epoch = ?3 AND disabled = 0)",
        params![success.user_id, success.phc, success.epoch],
        |row| row.get(0),
    )
}
