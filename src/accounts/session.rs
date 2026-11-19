use rusqlite::{Connection, OptionalExtension, params};

use crate::crypto::{random_token, token_hash};
use crate::db::{Db, DbError};
use crate::web::{Role, SessionUser};

use super::input::to_i64;

const SESSION_PREFIX: &str = "dw_ss_";
const SECONDS_PER_HOUR: u64 = 3600;

/// The session lifetime in seconds for a configured number of hours.
pub fn lifetime_seconds(hours: u64) -> i64 {
    to_i64(hours.saturating_mul(SECONDS_PER_HOUR))
}

/// The user of a valid session: row present, not expired, user enabled, auth epoch current.
pub async fn find(db: &Db, token: &str, now: i64) -> Result<Option<SessionUser>, DbError> {
    let hash = token_hash(token);
    db.call(move |conn| {
        conn.query_row(
            "SELECT u.id, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.id_hash = ?1 AND s.expires_at > ?2 \
             AND s.auth_epoch = u.auth_epoch AND u.disabled = 0",
            params![hash, now],
            |row| {
                let role: String = row.get(2)?;
                Ok(SessionUser {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    role: role_of(&role),
                })
            },
        )
        .optional()
    })
    .await
}

/// Inserts a new session for `user_id` and returns its cookie value.
pub fn insert(
    conn: &Connection,
    user_id: i64,
    now: i64,
    lifetime: i64,
) -> rusqlite::Result<String> {
    let token = random_token(SESSION_PREFIX);
    conn.execute(
        "INSERT INTO sessions (id_hash, user_id, auth_epoch, created_at, expires_at) \
         SELECT ?1, id, auth_epoch, ?2, ?3 FROM users WHERE id = ?4",
        params![
            token_hash(&token),
            now,
            now.saturating_add(lifetime),
            user_id
        ],
    )?;
    Ok(token)
}

/// Deletes the session row of a cookie value, if it has one.
pub fn delete(conn: &Connection, token: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM sessions WHERE id_hash = ?1",
        params![token_hash(token)],
    )
}

/// The database holds only the CHECK-constrained roles, so anything unknown gets the least rights.
fn role_of(text: &str) -> Role {
    match text {
        "owner" => Role::Owner,
        "admin" => Role::Admin,
        _ => Role::User,
    }
}
