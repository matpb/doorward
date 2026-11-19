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

/// Ends every session of the user at once: increments users.auth_epoch and deletes the rows.
pub fn revoke_all(conn: &Connection, user_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?1",
        params![user_id],
    )?;
    conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
    Ok(())
}

/// The database holds only the CHECK-constrained roles, so anything unknown gets the least rights.
fn role_of(text: &str) -> Role {
    match text {
        "owner" => Role::Owner,
        "admin" => Role::Admin,
        _ => Role::User,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    const NOW: i64 = 1_000;
    const LIFETIME: i64 = 100;

    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_made_before_revoke_all_stops_resolving_and_one_after_resolves() {
        let dir = tempfile::tempdir().expect("dir");
        let db = Db::open(&dir.path().join("doorward.db")).expect("open");
        let (user_id, before) = db
            .call(|conn| {
                conn.execute(
                    "INSERT INTO users (email, password_hash, role, created_at) \
                     VALUES ('bob@example.com', 'hash', 'user', 0)",
                    [],
                )?;
                let user_id = conn.last_insert_rowid();
                let before = insert(conn, user_id, NOW, LIFETIME)?;
                Ok((user_id, before))
            })
            .await
            .expect("setup");
        assert!(
            find(&db, &before, NOW).await.expect("find").is_some(),
            "a fresh session must resolve"
        );
        db.call(move |conn| revoke_all(conn, user_id))
            .await
            .expect("revoke");
        assert!(
            find(&db, &before, NOW).await.expect("find").is_none(),
            "a session made before revoke_all must no longer resolve"
        );
        let after = db
            .call(move |conn| insert(conn, user_id, NOW, LIFETIME))
            .await
            .expect("insert");
        assert!(
            find(&db, &after, NOW).await.expect("find").is_some(),
            "a session made after revoke_all must resolve"
        );
    }
}
