use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::audit::{self, Event};
use crate::crypto::token_hash;
use crate::db::{Db, DbError};
use crate::vault::Unlocked;
use crate::vault::keys;

use super::input::normalize_email;
use super::session;

/// The result of reserving one sign-in attempt.
pub enum Attempt {
    /// Refused before any password check, and not counted.
    Blocked,
    /// A failure is reserved. `phc` is the hash of an enabled account, else None.
    /// `epoch` is the account's auth epoch.
    Counted {
        user_id: Option<i64>,
        phc: Option<String>,
        epoch: Option<i64>,
        /// The user's stored vault salt, when the account has a data key.
        salt: Option<[u8; 16]>,
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
    pub account_ceiling: i64,
    pub address_failures: i64,
}

/// What a successful sign-in needs. `previous` is the cookie value the browser sent. `phc` and
/// `epoch` are the hash that was verified and the auth epoch read with it.
pub struct Success {
    pub account: String,
    pub address: String,
    pub user_id: i64,
    pub email: String,
    pub previous: Option<String>,
    pub now: i64,
    pub lifetime: i64,
    pub phc: String,
    pub epoch: i64,
    /// The vault unlock made after the password matched; None leaves the session without a wrap.
    pub vault: Option<Unlocked>,
}

/// Transaction T1: prunes old failures, checks the three limits, reserves one failure and reads the user.
pub async fn reserve(db: &Db, input: Reserve) -> Result<Attempt, DbError> {
    db.call(move |conn| reserve_in(conn, &input)).await
}

/// Transaction T2: clears the account and the reservation, and signs the browser in. None, with
/// nothing changed, when the user no longer matches the verified hash and epoch, or is disabled.
pub async fn succeed(db: &Db, success: Success) -> Result<Option<String>, DbError> {
    db.call(move |conn| {
        let token = succeed_in(conn, &success)?;
        if let (Some(token), Some(vault)) = (&token, &success.vault)
            && let Err(err) = keys::heal(
                conn,
                vault,
                (success.user_id, &success.email),
                token,
                success.now,
            )
        {
            crate::report::failure(
                "password wrap repair",
                &format!("user {}: {err}", success.user_id),
            );
        }
        Ok(token)
    })
    .await
}

/// Deletes every counted failure of an account (the hash of its normalised email).
pub fn lift_block(conn: &Connection, email: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM login_failures WHERE account_hash = ?1",
        params![token_hash(&normalize_email(email))],
    )?;
    Ok(())
}

/// Deletes the counted failures of one account from one address, as a right password does.
pub fn clear_attempt(conn: &Connection, account: &str, address: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM login_failures WHERE account_hash = ?1 AND address = ?2",
        params![account, address],
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
    let account_rows: i64 = tx.query_row(
        "SELECT COUNT(*) FROM login_failures WHERE account_hash = ?1",
        params![input.account],
        |row| row.get(0),
    )?;
    if account_rows >= input.account_ceiling {
        tx.commit()?;
        return Ok(Attempt::Blocked);
    }
    let pair_rows: i64 = tx.query_row(
        "SELECT COUNT(*) FROM login_failures WHERE account_hash = ?1 AND address = ?2",
        params![input.account, input.address],
        |row| row.get(0),
    )?;
    if pair_rows >= input.account_failures {
        tx.commit()?;
        return Ok(Attempt::Blocked);
    }
    tx.execute(
        "INSERT INTO login_failures (account_hash, address, at) VALUES (?1, ?2, ?3)",
        params![input.account, input.address, input.now],
    )?;
    let user: Option<(i64, String, i64, i64, Option<String>)> = tx
        .query_row(
            "SELECT id, password_hash, disabled, auth_epoch, dek_salt FROM users WHERE email = ?1",
            params![input.email],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    tx.commit()?;
    let (user_id, phc, epoch, salt) = match user {
        Some((id, hash, 0, epoch, salt)) => (Some(id), Some(hash), Some(epoch), salt),
        Some((id, _, _, epoch, _)) => (Some(id), None, Some(epoch), None),
        None => (None, None, None, None),
    };
    Ok(Attempt::Counted {
        user_id,
        phc,
        epoch,
        salt: keys::parse_salt(salt.as_deref()),
    })
}

pub(super) fn succeed_in(
    conn: &mut Connection,
    success: &Success,
) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !still_current(&tx, success)? {
        return Ok(None);
    }
    clear_attempt(&tx, &success.account, &success.address)?;
    if let Some(previous) = &success.previous {
        session::delete(&tx, previous)?;
    }
    let token = session::insert(&tx, success.user_id, success.now, success.lifetime)?;
    if let Some(vault) = &success.vault {
        keys::sign_in(&tx, vault, success.user_id, &token)?;
    }
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

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    use super::{Attempt, Reserve, Success, lift_block, reserve_in, succeed_in};
    use crate::crypto::token_hash;
    use crate::db::Db;

    const NOW: i64 = 1_000;
    const WINDOW: i64 = 900;
    const X: &str = "x@example.com";
    const V: &str = "v@example.com";
    const A: &str = "192.0.2.10";
    const B: &str = "192.0.2.20";

    fn reserve(email: &str, address: &str, now: i64) -> Reserve {
        Reserve {
            account: token_hash(email),
            address: address.to_owned(),
            email: email.to_owned(),
            now,
            block_seconds: WINDOW,
            account_failures: 5,
            account_ceiling: 50,
            address_failures: 30,
        }
    }

    fn success(user_id: i64, phc: String, epoch: i64) -> Success {
        Success {
            account: token_hash(X),
            address: A.to_owned(),
            user_id,
            email: X.to_owned(),
            previous: None,
            now: NOW,
            lifetime: 3_600,
            phc,
            epoch,
            vault: None,
        }
    }

    fn open() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = Db::open(&dir.path().join("doorward.db")).expect("database");
        (dir, db)
    }

    fn insert_user(conn: &Connection, email: &str) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
            params![email],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn insert_failure(
        conn: &Connection,
        email: &str,
        address: &str,
        at: i64,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO login_failures (account_hash, address, at) VALUES (?1, ?2, ?3)",
            params![token_hash(email), address, at],
        )?;
        Ok(())
    }

    fn counted_rows(conn: &Connection, email: &str) -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT COUNT(*) FROM login_failures WHERE account_hash = ?1",
            params![token_hash(email)],
            |row| row.get(0),
        )
    }

    fn rows_at(conn: &Connection, address: &str) -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT COUNT(*) FROM login_failures WHERE address = ?1",
            params![address],
            |row| row.get(0),
        )
    }

    fn is_counted(attempt: &Attempt) -> bool {
        matches!(attempt, Attempt::Counted { .. })
    }

    /// The verified hash and epoch of a counted attempt on an enabled account.
    fn verified(attempt: Attempt) -> (String, i64) {
        match attempt {
            Attempt::Counted {
                user_id: Some(_),
                phc: Some(phc),
                epoch: Some(epoch),
                ..
            } => (phc, epoch),
            _ => panic!("the attempt must count an enabled account"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_success_cannot_erase_another_accounts_failure() {
        let (_dir, db) = open();
        let (first, second, v_rows, address_rows) = db
            .call(|conn| {
                let user_id = insert_user(conn, X)?;
                let (phc, epoch) = verified(reserve_in(conn, &reserve(X, A, NOW))?);
                let (late_phc, late_epoch) = verified(reserve_in(conn, &reserve(X, A, NOW))?);
                let first = succeed_in(conn, &success(user_id, phc, epoch))?;
                reserve_in(conn, &reserve(V, A, NOW))?;
                let second = succeed_in(conn, &success(user_id, late_phc, late_epoch))?;
                Ok((
                    first.is_some(),
                    second.is_some(),
                    counted_rows(conn, V)?,
                    rows_at(conn, A)?,
                ))
            })
            .await
            .expect("the sign-ins run");
        assert!(first && second, "both right passwords must sign in");
        assert_eq!(
            v_rows, 1,
            "the other account's failure must still be stored"
        );
        assert_eq!(address_rows, 1, "the address must still count that failure");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_success_after_an_unlock_cannot_erase_another_accounts_failure() {
        let (_dir, db) = open();
        let (signed_in, v_rows, address_rows) = db
            .call(|conn| {
                let user_id = insert_user(conn, X)?;
                let (phc, epoch) = verified(reserve_in(conn, &reserve(X, A, NOW))?);
                reserve_in(conn, &reserve(X, A, NOW))?;
                lift_block(conn, X)?;
                reserve_in(conn, &reserve(V, A, NOW))?;
                let late = succeed_in(conn, &success(user_id, phc, epoch))?;
                Ok((late.is_some(), counted_rows(conn, V)?, rows_at(conn, A)?))
            })
            .await
            .expect("the sign-ins run");
        assert!(signed_in, "the right password must sign in");
        assert_eq!(
            v_rows, 1,
            "the other account's failure must still be stored"
        );
        assert_eq!(address_rows, 1, "the address must still count that failure");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_address_rule_blocks_one_row_past_its_limit() {
        let (_dir, db) = open();
        let answers = db
            .call(|conn| {
                let mut answers = Vec::new();
                for email in [
                    "a1@example.com",
                    "a2@example.com",
                    "a3@example.com",
                    "a4@example.com",
                ] {
                    let mut input = reserve(email, A, NOW);
                    input.address_failures = 2;
                    answers.push(is_counted(&reserve_in(conn, &input)?));
                }
                Ok(answers)
            })
            .await
            .expect("reserve");
        assert_eq!(answers, vec![true, true, true, false]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_ceiling_blocks_at_exactly_its_count() {
        let (_dir, db) = open();
        let answers = db
            .call(|conn| {
                let mut answers = Vec::new();
                for address in [A, B, "192.0.2.30", "192.0.2.40"] {
                    let mut input = reserve(X, address, NOW);
                    input.account_ceiling = 3;
                    answers.push(is_counted(&reserve_in(conn, &input)?));
                }
                Ok(answers)
            })
            .await
            .expect("reserve");
        assert_eq!(answers, vec![true, true, true, false]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_pair_blocks_at_exactly_its_count_and_not_the_other_address() {
        let (_dir, db) = open();
        let answers = db
            .call(|conn| {
                let mut answers = Vec::new();
                for _ in 0..4 {
                    let mut input = reserve(X, A, NOW);
                    input.account_failures = 3;
                    answers.push(is_counted(&reserve_in(conn, &input)?));
                }
                let mut other = reserve(X, B, NOW);
                other.account_failures = 3;
                answers.push(is_counted(&reserve_in(conn, &other)?));
                Ok(answers)
            })
            .await
            .expect("reserve");
        assert_eq!(answers, vec![true, true, true, false, true]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_row_at_the_window_edge_is_pruned_and_one_second_newer_still_counts() {
        let (_dir, db) = open();
        let (pruned_counts, pruned_rows, newer_blocks) = db
            .call(|conn| {
                let mut pruned = reserve(X, A, NOW);
                pruned.account_failures = 1;
                pruned.account_ceiling = 1;
                insert_failure(conn, X, A, NOW - WINDOW)?;
                let pruned_counts = is_counted(&reserve_in(conn, &pruned)?);
                let pruned_rows = counted_rows(conn, X)?;
                let mut newer = reserve(V, A, NOW);
                newer.account_failures = 1;
                newer.account_ceiling = 1;
                insert_failure(conn, V, A, NOW - WINDOW + 1)?;
                let newer_blocks = !is_counted(&reserve_in(conn, &newer)?);
                Ok((pruned_counts, pruned_rows, newer_blocks))
            })
            .await
            .expect("reserve");
        assert!(
            pruned_counts,
            "a row at now minus the window must be pruned"
        );
        assert_eq!(
            pruned_rows, 1,
            "only the new row may remain for the account"
        );
        assert!(
            newer_blocks,
            "a row one second newer must still count against the pair"
        );
    }
}
