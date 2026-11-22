//! The life of a user's data key in the database: the password wrap on `users`, the token wraps
//! on sessions, codes and tokens, and the re-seal or deletion of stored values. Callers run
//! these inside the transaction of the change they follow.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OptionalExtension, params};

use crate::audit;
use crate::crypto::{Keys, token_hash};
use crate::report;

use super::{
    DataKey, PasswordKey, Place, ValuePlace, open_value, seal_value, unwrap_with_password,
    unwrap_with_token, wrap_with_password, wrap_with_token,
};

/// What an accepted password yields for the vault; made in the hasher job, after the password was
/// accepted. `fresh` is true when `salt` is new because the user had none.
pub struct Unlock {
    pub salt: [u8; 16],
    pub key: PasswordKey,
    pub fresh: bool,
}

/// The server key and the unlock a transaction needs to open, make or wrap the user's data key.
pub struct Unlocked {
    pub keys: Arc<Keys>,
    pub unlock: Unlock,
}

/// The salt of a stored `dek_salt` text; None when it is not 16 bytes of base64url.
pub fn parse_salt(text: Option<&str>) -> Option<[u8; 16]> {
    URL_SAFE_NO_PAD.decode(text?).ok()?.try_into().ok()
}

/// The tables whose rows carry a token wrap, with the column that holds the row's hash.
#[derive(Clone, Copy)]
pub enum Table {
    Sessions,
    AuthCodes,
    AccessTokens,
    RefreshTokens,
}

impl Table {
    pub fn name(self) -> &'static str {
        match self {
            Table::Sessions => "sessions",
            Table::AuthCodes => "auth_codes",
            Table::AccessTokens => "access_tokens",
            Table::RefreshTokens => "refresh_tokens",
        }
    }

    fn column(self) -> &'static str {
        match self {
            Table::Sessions => "id_hash",
            Table::AuthCodes => "code_hash",
            Table::AccessTokens | Table::RefreshTokens => "token_hash",
        }
    }
}

/// The generation, password wrap and salt text of a user; None when there is no such user.
type Stored = (i64, Option<String>, Option<String>);

fn stored(conn: &Connection, user: i64) -> rusqlite::Result<Option<Stored>> {
    conn.query_row(
        "SELECT dek_gen, dek_wrap, dek_salt FROM users WHERE id = ?1",
        params![user],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
}

fn open_password_wrap(
    keys: &Keys,
    user: i64,
    generation: i64,
    unlock: &Unlock,
    wrap: &str,
) -> Option<DataKey> {
    let row = user.to_string();
    let place = Place {
        user,
        generation,
        table: "users",
        row: &row,
    };
    unwrap_with_password(keys, &place, &unlock.key, wrap).ok()
}

/// The user's data key from the password wrap; None when there is no wrap, the salt differs
/// from the one the key was derived with, or the wrap does not open.
pub fn open_password(
    tx: &Connection,
    keys: &Keys,
    user: i64,
    unlock: &Unlock,
) -> rusqlite::Result<Option<DataKey>> {
    let Some((generation, Some(wrap), Some(salt))) = stored(tx, user)? else {
        return Ok(None);
    };
    if salt != URL_SAFE_NO_PAD.encode(unlock.salt) {
        return Ok(None);
    }
    Ok(open_password_wrap(keys, user, generation, unlock, &wrap))
}

/// Opens the data key with the password key, or makes it when the user has none.
/// None when another sign-in stored a key under another salt or the wrap does not open.
pub fn open_or_create(
    tx: &Connection,
    keys: &Keys,
    user: i64,
    unlock: &Unlock,
) -> rusqlite::Result<Option<DataKey>> {
    let Some((generation, wrap, salt)) = stored(tx, user)? else {
        return Ok(None);
    };
    let ours = URL_SAFE_NO_PAD.encode(unlock.salt);
    if let Some(wrap) = wrap {
        if salt.as_deref() != Some(ours.as_str()) {
            return Ok(None);
        }
        return Ok(open_password_wrap(keys, user, generation, unlock, &wrap));
    }
    let usable = match salt.as_deref() {
        None => unlock.fresh,
        Some(stored_salt) => !unlock.fresh && stored_salt == ours,
    };
    if !usable {
        return Ok(None);
    }
    let key = DataKey::random();
    store_password_wrap(tx, keys, user, generation, unlock, &key)?;
    Ok(Some(key))
}

/// Writes the password wrap and salt of `user`; leaves both NULL when sealing fails.
fn store_password_wrap(
    tx: &Connection,
    keys: &Keys,
    user: i64,
    generation: i64,
    unlock: &Unlock,
    key: &DataKey,
) -> rusqlite::Result<()> {
    let row = user.to_string();
    let place = Place {
        user,
        generation,
        table: "users",
        row: &row,
    };
    let (wrap, salt) = match wrap_with_password(keys, &place, &unlock.key, key) {
        Ok(wrap) => (Some(wrap), Some(URL_SAFE_NO_PAD.encode(unlock.salt))),
        Err(_) => (None, None),
    };
    tx.execute(
        "UPDATE users SET dek_wrap = ?1, dek_salt = ?2 WHERE id = ?3",
        params![wrap, salt, user],
    )?;
    Ok(())
}

/// Wraps `key` onto the row of `token` in `table`. A failure to wrap leaves the row without one.
pub fn wrap_row(
    tx: &Connection,
    keys: &Keys,
    user: i64,
    table: Table,
    row_hash: &str,
    token: &str,
    key: &DataKey,
) -> rusqlite::Result<()> {
    let Some((generation, _, _)) = stored(tx, user)? else {
        return Ok(());
    };
    let place = Place {
        user,
        generation,
        table: table.name(),
        row: row_hash,
    };
    let Ok(wrap) = wrap_with_token(keys, &place, token, key) else {
        return Ok(());
    };
    tx.execute(
        &format!(
            "UPDATE {} SET dek_wrap = ?1 WHERE {} = ?2",
            table.name(),
            table.column()
        ),
        params![wrap, row_hash],
    )?;
    Ok(())
}

/// The data key the row of `token` carries; None when it has no wrap or the wrap does not open.
pub fn open_row(
    tx: &Connection,
    keys: &Keys,
    user: i64,
    table: Table,
    row_hash: &str,
    token: &str,
) -> rusqlite::Result<Option<DataKey>> {
    let Some((generation, _, _)) = stored(tx, user)? else {
        return Ok(None);
    };
    let wrap: Option<Option<String>> = tx
        .query_row(
            &format!(
                "SELECT dek_wrap FROM {} WHERE {} = ?1",
                table.name(),
                table.column()
            ),
            params![row_hash],
            |row| row.get(0),
        )
        .optional()?;
    let Some(Some(wrap)) = wrap else {
        return Ok(None);
    };
    let place = Place {
        user,
        generation,
        table: table.name(),
        row: row_hash,
    };
    Ok(unwrap_with_token(keys, &place, token, &wrap).ok())
}

/// Nulls the wrap of one row.
pub fn clear_row(tx: &Connection, table: Table, row_hash: &str) -> rusqlite::Result<()> {
    tx.execute(
        &format!(
            "UPDATE {} SET dek_wrap = NULL WHERE {} = ?1",
            table.name(),
            table.column()
        ),
        params![row_hash],
    )?;
    Ok(())
}

/// Nulls the wrap on every code, access token and refresh token of the user.
pub fn clear_user_tokens(tx: &Connection, user: i64) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE auth_codes SET dek_wrap = NULL WHERE user_id = ?1 AND dek_wrap IS NOT NULL",
        params![user],
    )?;
    for table in ["access_tokens", "refresh_tokens"] {
        tx.execute(
            &format!(
                "UPDATE {table} SET dek_wrap = NULL WHERE dek_wrap IS NOT NULL AND family_id IN \
                 (SELECT id FROM token_families WHERE user_id = ?1)"
            ),
            params![user],
        )?;
    }
    Ok(())
}

/// One stored value with everything its place needs.
struct Held {
    header_id: i64,
    sealed: String,
    server: i64,
    header: String,
    upstream_url: String,
}

fn held_values(tx: &Connection, user: i64) -> rusqlite::Result<Vec<Held>> {
    let mut statement = tx.prepare(
        "SELECT v.header_id, v.sealed, s.id, h.name_lower, s.upstream_url \
         FROM user_header_values v JOIN server_headers h ON h.id = v.header_id \
         JOIN servers s ON s.id = h.server_id WHERE v.user_id = ?1",
    )?;
    let rows = statement.query_map(params![user], |row| {
        Ok(Held {
            header_id: row.get(0)?,
            sealed: row.get(1)?,
            server: row.get(2)?,
            header: row.get(3)?,
            upstream_url: row.get(4)?,
        })
    })?;
    rows.collect()
}

/// A new data key one generation up: re-seals the user's values under it and stores its password
/// wrap. A value the old key cannot open is deleted, and a `values_dropped` row names the user.
pub fn rekey(
    tx: &Connection,
    keys: &Keys,
    user: i64,
    old: Option<&DataKey>,
    unlock: &Unlock,
    email: &str,
    now: i64,
) -> rusqlite::Result<DataKey> {
    let old_generation = stored(tx, user)?.map_or(0, |(generation, _, _)| generation);
    let generation = old_generation.saturating_add(1);
    let new = DataKey::random();
    let mut dropped = 0usize;
    for held in held_values(tx, user)? {
        let resealed = old.and_then(|old| {
            let before = ValuePlace {
                user,
                server: held.server,
                header: &held.header,
                generation: old_generation,
                upstream_url: &held.upstream_url,
            };
            let plain = open_value(old, &before, &held.sealed).ok()?;
            let after = ValuePlace {
                generation,
                ..before
            };
            seal_value(&new, &after, &plain).ok()
        });
        match resealed {
            Some(sealed) => {
                tx.execute(
                    "UPDATE user_header_values SET sealed = ?1 WHERE user_id = ?2 AND header_id = ?3",
                    params![sealed, user, held.header_id],
                )?;
            }
            None => {
                tx.execute(
                    "DELETE FROM user_header_values WHERE user_id = ?1 AND header_id = ?2",
                    params![user, held.header_id],
                )?;
                dropped += 1;
            }
        }
    }
    tx.execute(
        "UPDATE users SET dek_gen = ?1, values_version = values_version + ?2 WHERE id = ?3",
        params![generation, i64::from(dropped > 0), user],
    )?;
    store_password_wrap(tx, keys, user, generation, unlock, &new)?;
    if dropped > 0 {
        audit::values_dropped(tx, now, user, email, dropped)?;
    }
    Ok(new)
}

/// Deletes the user's values, the password wrap and salt, and moves the generation up.
/// Returns how many values were deleted.
pub fn forget(tx: &Connection, user: i64) -> rusqlite::Result<usize> {
    let deleted = tx.execute(
        "DELETE FROM user_header_values WHERE user_id = ?1",
        params![user],
    )?;
    tx.execute(
        "UPDATE users SET dek_wrap = NULL, dek_salt = NULL, dek_gen = dek_gen + 1, \
         values_version = values_version + ?2 WHERE id = ?1",
        params![user, i64::from(deleted > 0)],
    )?;
    Ok(deleted)
}

/// Deletes stored values of a server (one user's, one header's, or all), then raises each holder's
/// `values_version` and drops their upstream sessions there; `record` adds a `values_dropped` row each.
pub fn release(
    tx: &Connection,
    server: i64,
    user: Option<i64>,
    header: Option<i64>,
    now: i64,
    record: bool,
) -> rusqlite::Result<()> {
    let holders: Vec<(i64, String, i64)> = {
        let mut statement = tx.prepare(
            "SELECT v.user_id, u.email, COUNT(*) FROM user_header_values v \
             JOIN server_headers h ON h.id = v.header_id JOIN users u ON u.id = v.user_id \
             WHERE h.server_id = ?1 AND (?2 IS NULL OR v.user_id = ?2) AND (?3 IS NULL OR h.id = ?3) \
             GROUP BY v.user_id ORDER BY v.user_id",
        )?;
        statement
            .query_map(params![server, user, header], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<rusqlite::Result<_>>()?
    };
    if holders.is_empty() {
        return Ok(());
    }
    let slug: String = tx.query_row(
        "SELECT slug FROM servers WHERE id = ?1",
        params![server],
        |row| row.get(0),
    )?;
    tx.execute(
        "DELETE FROM user_header_values WHERE header_id IN \
         (SELECT id FROM server_headers WHERE server_id = ?1 AND (?3 IS NULL OR id = ?3)) \
         AND (?2 IS NULL OR user_id = ?2)",
        params![server, user, header],
    )?;
    for (holder, email, count) in &holders {
        tx.execute(
            "UPDATE users SET values_version = values_version + 1 WHERE id = ?1",
            params![holder],
        )?;
        tx.execute(
            "DELETE FROM upstream_sessions WHERE server_id = ?1 AND user_id = ?2",
            params![server, holder],
        )?;
        if record {
            let count = usize::try_from(*count).unwrap_or(usize::MAX);
            audit::values_dropped_on(tx, now, *holder, email, (server, &slug), count)?;
        }
    }
    Ok(())
}

/// After a sign-in whose accepted password cannot open the user's own password wrap: makes a new data key
/// one generation up, deletes the values (they are unreadable), and wraps the key onto the new session.
pub fn heal(
    conn: &mut Connection,
    unlocked: &Unlocked,
    (user, email): (i64, &str),
    session_token: &str,
    now: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let Some((generation, Some(wrap), Some(salt))) = stored(&tx, user)? else {
        return Ok(());
    };
    let unlock = &unlocked.unlock;
    if salt != URL_SAFE_NO_PAD.encode(unlock.salt)
        || open_password_wrap(&unlocked.keys, user, generation, unlock, &wrap).is_some()
    {
        return Ok(());
    }
    report::failure(
        "password wrap",
        &format!("does not open for user {user}, a new data key is made"),
    );
    let generation = generation.saturating_add(1);
    let deleted = tx.execute(
        "DELETE FROM user_header_values WHERE user_id = ?1",
        params![user],
    )?;
    tx.execute(
        "UPDATE users SET dek_gen = ?1, values_version = values_version + ?2 WHERE id = ?3",
        params![generation, i64::from(deleted > 0), user],
    )?;
    let key = DataKey::random();
    store_password_wrap(&tx, &unlocked.keys, user, generation, unlock, &key)?;
    if deleted > 0 {
        tx.execute(
            "DELETE FROM upstream_sessions WHERE user_id = ?1",
            params![user],
        )?;
        audit::values_dropped(&tx, now, user, email, deleted)?;
    }
    let row = token_hash(session_token);
    wrap_row(
        &tx,
        &unlocked.keys,
        user,
        Table::Sessions,
        &row,
        session_token,
        &key,
    )?;
    tx.commit()?;
    Ok(())
}

/// Sign-in, setup and invitation: opens or makes the data key and wraps it onto the new session.
pub fn sign_in(
    tx: &Connection,
    unlocked: &Unlocked,
    user: i64,
    session_token: &str,
) -> rusqlite::Result<()> {
    let keys = &unlocked.keys;
    if let Some(key) = open_or_create(tx, keys, user, &unlocked.unlock)? {
        let row = token_hash(session_token);
        wrap_row(tx, keys, user, Table::Sessions, &row, session_token, &key)?;
    }
    Ok(())
}
