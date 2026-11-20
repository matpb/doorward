//! Token families: one grant of one client to one user for one server, with its token rows.

use rusqlite::{Connection, params};

use crate::config::Lifetimes;
use crate::crypto::{random_token, token_hash};

const MINUTE_SECONDS: i64 = 60;
const DAY_SECONDS: i64 = 86_400;
const HOUR_SECONDS: i64 = 3_600;
/// A code stays in the table this long after it expired, so its replay is still recognised.
const CODE_GRACE_SECONDS: i64 = 600;
/// A revoked family is kept this long, so its disconnect links and rows stay readable.
const REVOKED_KEEP_SECONDS: i64 = DAY_SECONDS;
/// An expired access token or family stays this long, so a call admitted before its expiry
/// is still answered.
const EXPIRED_GRACE_SECONDS: i64 = 3600;

/// What a new family belongs to.
pub struct NewFamily<'a> {
    pub user_id: i64,
    /// None for the combined endpoint.
    pub server_id: Option<i64>,
    pub client_id: &'a str,
    pub client_name: &'a str,
    pub auth_epoch: i64,
}

/// The two token texts of one pair. Only their hashes are stored. Deliberately not `Debug`.
pub struct Pair {
    pub access_token: String,
    pub refresh_token: String,
}

/// The access token lifetime in seconds.
pub fn access_seconds(lifetimes: &Lifetimes) -> i64 {
    scaled(lifetimes.access_token_minutes, MINUTE_SECONDS)
}

/// The refresh replay window in seconds; 0 means no window.
pub fn replay_window(lifetimes: &Lifetimes) -> i64 {
    scaled(lifetimes.refresh_replay_seconds, 1)
}

/// `count` units of `unit_seconds`, saturating instead of overflowing.
fn scaled(count: u64, unit_seconds: i64) -> i64 {
    i64::try_from(count)
        .unwrap_or(i64::MAX)
        .saturating_mul(unit_seconds)
}

/// Inserts a live family that expires `family_days` from now and returns its row id.
pub fn create(
    conn: &Connection,
    new: &NewFamily<'_>,
    now: i64,
    family_days: u64,
) -> rusqlite::Result<i64> {
    let expires_at = now.saturating_add(scaled(family_days, DAY_SECONDS));
    conn.execute(
        "INSERT INTO token_families (public_id, user_id, server_id, client_id, client_name, \
         auth_epoch, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            random_token("fam_"),
            new.user_id,
            new.server_id,
            new.client_id,
            new.client_name,
            new.auth_epoch,
            now,
            expires_at,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// A new access token and refresh token of the family. The refresh token never outlives the family.
pub fn mint_pair(
    conn: &Connection,
    family_id: i64,
    now: i64,
    lifetimes: &Lifetimes,
) -> rusqlite::Result<Pair> {
    let family_expires: i64 = conn.query_row(
        "SELECT expires_at FROM token_families WHERE id = ?1",
        params![family_id],
        |row| row.get(0),
    )?;
    let access_token = random_token("dw_at_");
    let refresh_token = random_token("dw_rt_");
    let access_expires = now.saturating_add(access_seconds(lifetimes));
    let refresh_expires = now
        .saturating_add(scaled(lifetimes.refresh_token_days, DAY_SECONDS))
        .min(family_expires);
    conn.execute(
        "INSERT INTO access_tokens (token_hash, family_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash(&access_token), family_id, access_expires],
    )?;
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![token_hash(&refresh_token), family_id, now, refresh_expires],
    )?;
    Ok(Pair {
        access_token,
        refresh_token,
    })
}

/// Ends the family: sets `revoked_at` once, then deletes its access and refresh rows.
pub fn revoke(conn: &Connection, family_id: i64, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE token_families SET revoked_at = COALESCE(revoked_at, ?2) WHERE id = ?1",
        params![family_id, now],
    )?;
    conn.execute(
        "DELETE FROM access_tokens WHERE family_id = ?1",
        params![family_id],
    )?;
    conn.execute(
        "DELETE FROM refresh_tokens WHERE family_id = ?1",
        params![family_id],
    )?;
    Ok(())
}

/// Revokes every family of one user on one server. Called when the assignment is removed.
pub fn revoke_pair(
    conn: &Connection,
    user_id: i64,
    server_id: i64,
    now: i64,
) -> rusqlite::Result<()> {
    let ids = family_ids(
        conn,
        "SELECT id FROM token_families WHERE user_id = ?1 AND server_id = ?2",
        params![user_id, server_id],
    )?;
    revoke_each(conn, &ids, now)
}

/// Revokes every family of one server and drops its unredeemed codes and pending requests.
pub fn revoke_server(
    conn: &Connection,
    server_id: i64,
    old_slug: &str,
    now: i64,
) -> rusqlite::Result<()> {
    let ids = family_ids(
        conn,
        "SELECT id FROM token_families WHERE server_id = ?1",
        params![server_id],
    )?;
    revoke_each(conn, &ids, now)?;
    conn.execute(
        "DELETE FROM auth_codes WHERE server_id = ?1",
        params![server_id],
    )?;
    conn.execute(
        "DELETE FROM auth_requests WHERE target_slug = ?1",
        params![old_slug],
    )?;
    Ok(())
}

fn family_ids(
    conn: &Connection,
    sql: &str,
    values: impl rusqlite::Params,
) -> rusqlite::Result<Vec<i64>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map(values, |row| row.get(0))?;
    rows.collect()
}

fn revoke_each(conn: &Connection, ids: &[i64], now: i64) -> rusqlite::Result<()> {
    for id in ids {
        revoke(conn, *id, now)?;
    }
    Ok(())
}

/// Nulls every replay copy whose refresh token was used more than `replay_seconds` ago.
pub fn clear_old_replays(conn: &Connection, now: i64, replay_seconds: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE refresh_tokens SET replay = NULL WHERE replay IS NOT NULL AND used_at + ?2 < ?1",
        params![now, replay_seconds],
    )?;
    Ok(())
}

/// Nulls the family's replay copies whose refresh token was used more than `replay_seconds` ago.
pub fn clear_old_replays_of(
    conn: &Connection,
    family_id: i64,
    now: i64,
    replay_seconds: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE refresh_tokens SET replay = NULL WHERE family_id = ?1 AND replay IS NOT NULL \
         AND used_at + ?3 < ?2",
        params![family_id, now, replay_seconds],
    )?;
    Ok(())
}

/// Housekeeping: drops what no longer decides anything and nulls replay copies past the window.
pub fn sweep(conn: &Connection, now: i64, replay_seconds: i64) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM auth_requests WHERE expires_at <= ?1",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM auth_codes WHERE expires_at + ?2 < ?1",
        params![now, CODE_GRACE_SECONDS],
    )?;
    conn.execute(
        "DELETE FROM access_tokens WHERE expires_at + ?2 <= ?1",
        params![now, EXPIRED_GRACE_SECONDS],
    )?;
    conn.execute(
        "DELETE FROM dcr_attempts WHERE at < ?1",
        params![now - HOUR_SECONDS],
    )?;
    conn.execute(
        "DELETE FROM token_families WHERE expires_at + ?3 <= ?1 \
         OR (revoked_at IS NOT NULL AND revoked_at < ?2)",
        params![now, now - REVOKED_KEEP_SECONDS, EXPIRED_GRACE_SECONDS],
    )?;
    clear_old_replays(conn, now, replay_seconds)
}
