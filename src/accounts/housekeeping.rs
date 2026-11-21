//! Housekeeping for the account tables: deletes the rows that no longer decide anything.

use rusqlite::{Connection, params};

use super::reset::{MAIL_WINDOW_SECONDS, REQUEST_GAP_SECONDS};

const DAY_SECONDS: i64 = 86_400;
/// An invitation stays in the table this long after it expired.
const INVITATION_KEEP_SECONDS: i64 = 7 * DAY_SECONDS;

/// Deletes rows that no longer decide anything.
pub fn sweep(
    conn: &Connection,
    now: i64,
    block_seconds: i64,
    activity_seconds: i64,
) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?;
    // A reset row also stays while its day's mail count is current.
    conn.execute(
        "DELETE FROM password_resets WHERE expires_at <= ?1 AND created_at <= ?2 \
         AND window_start <= ?3",
        params![
            now,
            now.saturating_sub(REQUEST_GAP_SECONDS),
            now.saturating_sub(MAIL_WINDOW_SECONDS)
        ],
    )?;
    conn.execute(
        "DELETE FROM invitations WHERE expires_at < ?1",
        params![now.saturating_sub(INVITATION_KEEP_SECONDS)],
    )?;
    conn.execute(
        "DELETE FROM login_failures WHERE at <= ?1",
        params![now.saturating_sub(block_seconds)],
    )?;
    conn.execute(
        "DELETE FROM activity WHERE at <= ?1",
        params![now.saturating_sub(activity_seconds)],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    const NOW: i64 = 1_000_000_000;
    const BLOCK: i64 = 900;
    const DAY: i64 = 86_400;

    fn add_user(conn: &Connection, email: &str) -> rusqlite::Result<i64> {
        conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
            params![email],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn insert_session(
        conn: &Connection,
        user_id: i64,
        label: &str,
        expires_at: i64,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO sessions (id_hash, user_id, auth_epoch, created_at, expires_at) \
             VALUES (?1, ?2, 0, 0, ?3)",
            params![label, user_id, expires_at],
        )?;
        Ok(())
    }

    /// One user per reset, because a user has one reset row.
    fn insert_reset(
        conn: &Connection,
        label: &str,
        created_at: i64,
        expires_at: i64,
    ) -> rusqlite::Result<()> {
        let user_id = add_user(conn, &format!("{label}@example.com"))?;
        conn.execute(
            "INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![user_id, label, created_at, expires_at],
        )?;
        Ok(())
    }

    fn insert_invitation(conn: &Connection, label: &str, expires_at: i64) -> rusqlite::Result<()> {
        let email = format!("{label}@example.com");
        conn.execute(
            "INSERT INTO invitations (email, role, token_hash, created_at, expires_at) \
             VALUES (?1, 'user', ?2, 0, ?3)",
            params![email, label, expires_at],
        )?;
        Ok(())
    }

    fn insert_failure(conn: &Connection, label: &str, at: i64) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO login_failures (account_hash, address, at) VALUES (?1, ?1, ?2)",
            params![label, at],
        )?;
        Ok(())
    }

    fn insert_activity(conn: &Connection, tool: &str, at: i64) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO activity (at, kind, tool) VALUES (?1, 'tool_call', ?2)",
            params![at, tool],
        )?;
        Ok(())
    }

    /// The values of one column of `sql`, in order.
    fn remaining(conn: &Connection, sql: &str) -> rusqlite::Result<Vec<String>> {
        let mut statement = conn.prepare(sql)?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
    }

    fn open_db(dir: &tempfile::TempDir) -> Db {
        Db::open(&dir.path().join("doorward.db")).expect("open")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_table_keeps_exactly_the_rows_on_the_live_side_of_its_boundary() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let kept = db
            .call(|conn| {
                let bob = add_user(conn, "bob@example.com")?;
                insert_session(conn, bob, "s_old", NOW - 1)?;
                insert_session(conn, bob, "s_edge", NOW)?;
                insert_session(conn, bob, "s_live", NOW + 1)?;
                insert_reset(conn, "r_old", 0, NOW - 1)?;
                insert_reset(conn, "r_edge", 0, NOW)?;
                insert_reset(conn, "r_live", 0, NOW + 1)?;
                let cutoff = NOW - 7 * DAY;
                insert_invitation(conn, "i_old", cutoff - 1)?;
                insert_invitation(conn, "i_edge", cutoff)?;
                insert_invitation(conn, "i_live", cutoff + 1)?;
                insert_failure(conn, "f_old", NOW - BLOCK - 1)?;
                insert_failure(conn, "f_edge", NOW - BLOCK)?;
                insert_failure(conn, "f_live", NOW - BLOCK + 1)?;
                sweep(conn, NOW, BLOCK, i64::MAX)?;
                Ok(vec![
                    remaining(conn, "SELECT id_hash FROM sessions ORDER BY id_hash")?,
                    remaining(
                        conn,
                        "SELECT token_hash FROM password_resets ORDER BY token_hash",
                    )?,
                    remaining(
                        conn,
                        "SELECT token_hash FROM invitations ORDER BY token_hash",
                    )?,
                    remaining(conn, "SELECT address FROM login_failures ORDER BY address")?,
                ])
            })
            .await
            .expect("sweep");
        assert_eq!(kept[0], vec!["s_live"], "sessions");
        assert_eq!(kept[1], vec!["r_live"], "password resets");
        assert_eq!(kept[2], vec!["i_edge", "i_live"], "invitations");
        assert_eq!(kept[3], vec!["f_live"], "login failures");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_reset_stays_while_its_request_gap_is_open() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let kept = db
            .call(|conn| {
                insert_reset(conn, "r_299", NOW - 299, NOW - 1)?;
                insert_reset(conn, "r_300", NOW - 300, NOW - 1)?;
                sweep(conn, NOW, BLOCK, i64::MAX)?;
                remaining(
                    conn,
                    "SELECT token_hash FROM password_resets ORDER BY token_hash",
                )
            })
            .await
            .expect("sweep");
        assert_eq!(kept, vec!["r_299"]);
    }

    /// Sets the window and the day's count of the reset row of `label`.
    fn set_window(conn: &Connection, label: &str, window_start: i64) -> rusqlite::Result<()> {
        conn.execute(
            "UPDATE password_resets SET window_start = ?1, sent = 5 WHERE token_hash = ?2",
            params![window_start, label],
        )?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_reset_stays_while_its_day_is_current() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let kept = db
            .call(|conn| {
                insert_reset(conn, "r_inside", NOW - 600, NOW - 1)?;
                insert_reset(conn, "r_last", NOW - 600, NOW - 1)?;
                set_window(conn, "r_inside", NOW - 100)?;
                set_window(conn, "r_last", NOW - DAY + 1)?;
                sweep(conn, NOW, BLOCK, i64::MAX)?;
                remaining(
                    conn,
                    "SELECT token_hash FROM password_resets ORDER BY token_hash",
                )
            })
            .await
            .expect("sweep");
        assert_eq!(kept, vec!["r_inside", "r_last"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_reset_goes_once_its_day_has_passed() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let kept = db
            .call(|conn| {
                insert_reset(conn, "r_edge", NOW - 600, NOW - 1)?;
                insert_reset(conn, "r_past", NOW - 600, NOW - 1)?;
                set_window(conn, "r_edge", NOW - DAY)?;
                set_window(conn, "r_past", NOW - DAY - 1)?;
                sweep(conn, NOW, BLOCK, i64::MAX)?;
                remaining(
                    conn,
                    "SELECT token_hash FROM password_resets ORDER BY token_hash",
                )
            })
            .await
            .expect("sweep");
        assert_eq!(kept, Vec::<String>::new());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failure_still_inside_its_window_is_never_swept() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let kept = db
            .call(|conn| {
                insert_failure(conn, "f_now", NOW)?;
                insert_failure(conn, "f_inside", NOW - 10)?;
                sweep(conn, NOW, BLOCK, i64::MAX)?;
                remaining(conn, "SELECT address FROM login_failures ORDER BY address")
            })
            .await
            .expect("sweep");
        assert_eq!(kept, vec!["f_inside", "f_now"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_huge_block_length_sweeps_no_login_rows() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let kept = db
            .call(|conn| {
                insert_failure(conn, "f_old", 0)?;
                sweep(conn, NOW, i64::MAX, i64::MAX)?;
                remaining(conn, "SELECT address FROM login_failures")
            })
            .await
            .expect("sweep");
        assert_eq!(kept, vec!["f_old"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_activity_row_keeps_exactly_the_rows_inside_its_period() {
        let dir = tempfile::tempdir().expect("dir");
        let db = open_db(&dir);
        let period = 90 * DAY;
        let kept = db
            .call(move |conn| {
                insert_activity(conn, "a_old", NOW - period - 1)?;
                insert_activity(conn, "a_edge", NOW - period)?;
                insert_activity(conn, "a_live", NOW - period + 1)?;
                sweep(conn, NOW, BLOCK, period)?;
                remaining(conn, "SELECT tool FROM activity ORDER BY tool")
            })
            .await
            .expect("sweep");
        assert_eq!(kept, vec!["a_live"]);
    }
}
