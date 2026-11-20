use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

const MIGRATIONS: [(i64, &str); 10] = [
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_accounts.sql")),
    (3, include_str!("../migrations/0003_activity.sql")),
    (4, include_str!("../migrations/0004_invitations.sql")),
    (5, include_str!("../migrations/0005_servers.sql")),
    (6, include_str!("../migrations/0006_oauth.sql")),
    (7, include_str!("../migrations/0007_indexes.sql")),
    (8, include_str!("../migrations/0008_proxy.sql")),
    (9, include_str!("../migrations/0009_lockout.sql")),
    (10, include_str!("../migrations/0010_rules.sql")),
];

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("cannot create database file: {0}")]
    File(#[from] std::io::Error),
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("database task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Opens or creates the database at `path` and applies pending migrations.
    pub fn open(path: &Path) -> Result<Db, DbError> {
        create_private_file(path)?;
        let mut conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; \
             PRAGMA secure_delete=ON;",
        )?;
        migrate(&mut conn)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` with the connection on a blocking thread.
    pub async fn call<T, F>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&mut Connection) -> Result<T, rusqlite::Error> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            // A panic cannot break the connection: an open transaction rolls back on drop.
            let mut guard = conn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&mut guard).map_err(DbError::from)
        })
        .await?
    }

    /// Returns the highest applied migration version, or 0 when none.
    pub fn schema_version(&self) -> Result<i64, DbError> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let version = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        Ok(version)
    }
}

/// The UTF-8 text of one row of the settings table, or None when the key is absent.
pub fn setting_text(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(err),
                )
            })
        })
        .transpose()
}

/// Creates the file with mode 0600 if missing; an existing file keeps its mode.
fn create_private_file(path: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?;
    Ok(())
}

fn migrate(conn: &mut Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations \
         (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);",
    )?;
    for (version, sql) in MIGRATIONS {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let applied: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = ?1)",
            params![version],
            |row| row.get(0),
        )?;
        if !applied {
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) \
                 VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![version],
            )?;
        }
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn the_connection_still_works_after_a_closure_panics() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = Db::open(&dir.path().join("doorward.db")).expect("database");
        let panicked = db
            .call(|_conn| -> Result<(), rusqlite::Error> { panic!("a closure that panics") })
            .await;
        assert!(panicked.is_err(), "the panic surfaces as a failed task");
        let applied = db
            .call(|conn| {
                conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .await
            .expect("the next call still works");
        assert_eq!(
            applied,
            MIGRATIONS.len() as i64,
            "every migration is counted"
        );
        assert_eq!(
            db.schema_version().expect("the version"),
            MIGRATIONS.len() as i64
        );
    }
}
