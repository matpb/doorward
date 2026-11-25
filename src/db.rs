use std::any::Any;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

/// The most values the panel's memo holds at once; a full memo is emptied before the next one.
const MEMO_LIMIT: usize = 256;

const MIGRATIONS: [(i64, &str); 20] = [
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
    (
        11,
        include_str!("../migrations/0011_unused_registrations.sql"),
    ),
    (12, include_str!("../migrations/0012_dcr_attempts_at.sql")),
    (13, include_str!("../migrations/0013_reset_cap.sql")),
    (14, include_str!("../migrations/0014_activity_user_at.sql")),
    (15, include_str!("../migrations/0015_custom_headers.sql")),
    (16, include_str!("../migrations/0016_stored_values.sql")),
    (17, include_str!("../migrations/0017_value_index.sql")),
    (18, include_str!("../migrations/0018_invitation_plans.sql")),
    (19, include_str!("../migrations/0019_dashboards.sql")),
    (20, include_str!("../migrations/0020_panel_reads.sql")),
];

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("cannot open the database {}: {}", .0.display(), .1)]
    Open(PathBuf, String),
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("database task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// The writer, used by the proxy, the bearer check and sign-in, and a read-only reader for the panel.
/// The reader is a second connection to the same WAL file, so a slow page never holds the writer.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    reader: Arc<Mutex<Connection>>,
    memo: Arc<Mutex<Memo>>,
}

impl Db {
    /// Opens or creates the database at `path` and applies pending migrations, then opens the reader.
    pub fn open(path: &Path) -> Result<Db, DbError> {
        let mut conn = connect(path)?;
        migrate(&mut conn)?;
        let reader = connect_reader(path)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
            reader: Arc::new(Mutex::new(reader)),
            memo: Arc::new(Mutex::new(Memo::default())),
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

    /// Runs `f` with the read-only connection on a blocking thread. Only the panel's reads use it.
    pub async fn read<T, F>(&self, f: F) -> Result<T, DbError>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.reader);
        tokio::task::spawn_blocking(move || {
            let guard = conn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&guard).map_err(DbError::from)
        })
        .await?
    }

    /// The value cached under `key` when it is a T; None when it is absent or holds another type.
    pub fn cached<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        let memo = self
            .memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        memo.entries
            .get(key)
            .and_then(|value| Arc::clone(value).downcast::<T>().ok())
    }

    /// Caches `value` under `key` and returns it. A memo that is full is emptied first.
    pub fn remember<T: Any + Send + Sync>(&self, key: String, value: T) -> Arc<T> {
        let value = Arc::new(value);
        let mut memo = self
            .memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if memo.entries.len() >= MEMO_LIMIT {
            memo.entries.clear();
        }
        memo.entries.insert(key, value.clone());
        value
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

/// Values the panel computed and keeps for a short time, by key. Each value keeps its own type.
#[derive(Default)]
struct Memo {
    entries: HashMap<String, Arc<dyn Any + Send + Sync>>,
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

/// The connection to the file at `path` with its pragmas. A failure names the path and the cause.
fn connect(path: &Path) -> Result<Connection, DbError> {
    let opened = create_private_file(path)
        .map_err(|err| err.to_string())
        .and_then(|()| Connection::open(path).map_err(|err| err.to_string()))
        .and_then(|conn| {
            // The journal is capped at 64 MB, so an idle writer hands its space back.
            conn.execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; \
                 PRAGMA journal_size_limit=67108864;",
            )
            .map_err(|err| err.to_string())?;
            let mode: String = conn
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .map_err(|err| err.to_string())?;
            Ok((conn, mode))
        });
    let (conn, mode) = opened.map_err(|cause| DbError::Open(path.to_path_buf(), cause))?;
    ensure_wal(path, &mode)?;
    Ok(conn)
}

/// Refuses a database that did not switch to WAL: the panel's reads need the WAL file.
fn ensure_wal(path: &Path, mode: &str) -> Result<(), DbError> {
    if mode == "wal" {
        return Ok(());
    }
    Err(DbError::Open(
        path.to_path_buf(),
        format!("journal_mode is {mode}, not wal"),
    ))
}

/// A read-only connection with the busy timeout, refusing every write.
fn connect_reader(path: &Path) -> Result<Connection, DbError> {
    let opened = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|err| err.to_string())
        .and_then(|conn| {
            conn.execute_batch("PRAGMA busy_timeout=5000; PRAGMA query_only=ON;")
                .map_err(|err| err.to_string())?;
            Ok(conn)
        });
    opened.map_err(|cause| DbError::Open(path.to_path_buf(), cause))
}

/// Holds the writer's connection on a blocking thread until the sender is sent to; returns once taken.
/// A read that waits for the writer cannot answer until then.
#[cfg(test)]
pub(crate) async fn hold_writer(
    db: &Db,
) -> (
    std::sync::mpsc::Sender<()>,
    tokio::task::JoinHandle<Result<(), DbError>>,
) {
    let (taken_tx, taken_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let db = db.clone();
    let holder = tokio::spawn(async move {
        db.call(move |_conn| {
            let _ = taken_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
        .await
    });
    taken_rx.await.expect("the writer is taken");
    (release_tx, holder)
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

    #[test]
    fn a_schema_14_database_upgrades_and_keeps_its_users_sessions_and_tokens() {
        let mut conn = Connection::open_in_memory().expect("memory database");
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);",
        )
        .expect("table");
        for (version, sql) in MIGRATIONS.iter().take(14) {
            conn.execute_batch(sql).expect("old migration");
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, 'then')",
                params![version],
            )
            .expect("recorded");
        }
        conn.execute_batch(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES ('bob@example.com', 'h', 'user', 0); \
             INSERT INTO sessions (id_hash, user_id, auth_epoch, created_at, expires_at) VALUES ('s1', 1, 0, 0, 100); \
             INSERT INTO token_families (public_id, user_id, client_id, client_name, auth_epoch, created_at, expires_at) \
               VALUES ('f1', 1, 'c', 'Client', 0, 0, 100); \
             INSERT INTO access_tokens (token_hash, family_id, expires_at) VALUES ('a1', 1, 100); \
             INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at) VALUES ('r1', 1, 0, 100);",
        )
        .expect("old rows");
        migrate(&mut conn).expect("upgrade");
        let count =
            |sql: &str| -> i64 { conn.query_row(sql, [], |row| row.get(0)).expect("count") };
        assert_eq!(
            count("SELECT MAX(version) FROM schema_migrations"),
            MIGRATIONS.len() as i64
        );
        assert_eq!(
            count(
                "SELECT COUNT(*) FROM users WHERE email = 'bob@example.com' AND dek_wrap IS NULL AND dek_salt IS NULL AND dek_gen = 0 AND values_version = 0"
            ),
            1
        );
        for table in ["sessions", "access_tokens", "refresh_tokens"] {
            assert_eq!(
                count(&format!(
                    "SELECT COUNT(*) FROM {table} WHERE dek_wrap IS NULL"
                )),
                1,
                "{table} keeps its row with no wrap"
            );
        }
        assert_eq!(count("SELECT COUNT(*) FROM token_families"), 1);
        assert_eq!(
            count(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'user_header_values_header'"
            ),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_reader_reads_and_refuses_every_write() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = Db::open(&dir.path().join("doorward.db")).expect("database");
        let applied = db
            .read(|conn| {
                conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .await
            .expect("the reader reads");
        assert_eq!(
            applied,
            MIGRATIONS.len() as i64,
            "the reader sees the migrations"
        );
        let refused = db
            .read(|conn| conn.execute("DELETE FROM schema_migrations", []))
            .await
            .expect_err("the reader refuses a write");
        assert!(
            matches!(
                refused,
                DbError::Sql(rusqlite::Error::SqliteFailure(ref code, _))
                    if code.code == rusqlite::ErrorCode::ReadOnly
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn the_reader_sets_query_only_and_its_read_only_flag_refuses_writes_once_query_only_is_off() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("the migrated database");
        let reader = connect_reader(&path).expect("the reader");
        let setting: i64 = reader
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .expect("the setting");
        assert_eq!(setting, 1, "the reader has query_only on");
        reader
            .execute_batch("PRAGMA query_only=OFF")
            .expect("query_only is off");
        let err = reader
            .execute("DELETE FROM schema_migrations WHERE version = -1", [])
            .expect_err("the read-only flag alone refuses the write");
        assert_eq!(err.sqlite_error_code(), Some(rusqlite::ErrorCode::ReadOnly));
    }

    #[test]
    fn query_only_alone_refuses_every_write_until_it_is_turned_off() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("the migrated database");
        let conn = Connection::open(&path).expect("a read-write connection");
        conn.execute_batch("PRAGMA query_only=ON")
            .expect("query_only is on");
        let setting: i64 = conn
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .expect("the setting");
        assert_eq!(setting, 1);
        let err = conn
            .execute("DELETE FROM schema_migrations WHERE version = -1", [])
            .expect_err("query_only refuses the write");
        assert_eq!(err.sqlite_error_code(), Some(rusqlite::ErrorCode::ReadOnly));
        conn.execute_batch("PRAGMA query_only=OFF")
            .expect("query_only is off");
        let removed = conn
            .execute("DELETE FROM schema_migrations WHERE version = -1", [])
            .expect("with query_only off the write runs");
        assert_eq!(removed, 0);
    }

    #[test]
    fn a_journal_mode_other_than_wal_refuses_to_open() {
        let err = ensure_wal(Path::new("/var/doorward/doorward.db"), "delete")
            .expect_err("delete is not wal");
        assert_eq!(
            err.to_string(),
            "cannot open the database /var/doorward/doorward.db: journal_mode is delete, not wal"
        );
        ensure_wal(Path::new("/var/doorward/doorward.db"), "wal").expect("wal opens");
    }

    #[tokio::test]
    async fn the_writer_limits_its_journal_to_64_mb() {
        let dir = tempfile::tempdir().expect("a directory");
        let db = Db::open(&dir.path().join("doorward.db")).expect("the migrated database");
        let limit: i64 = db
            .call(|conn| conn.query_row("PRAGMA journal_size_limit", [], |row| row.get(0)))
            .await
            .expect("the limit");
        assert_eq!(limit, 64 * 1024 * 1024);
    }

    #[test]
    fn no_trigger_is_left_by_the_migrations() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("the migrated database");
        let conn = Connection::open(&path).expect("a connection");
        let triggers: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'",
                [],
                |row| row.get(0),
            )
            .expect("the count");
        assert_eq!(triggers, 0, "the chart removals are logged by the handlers");
    }

    #[test]
    fn the_activity_table_keeps_the_server_and_time_index_and_not_the_server_alone() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("the migrated database");
        let conn = Connection::open(&path).expect("a connection");
        let mut statement = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'activity'",
            )
            .expect("the query");
        let names: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .expect("the names")
            .collect::<rusqlite::Result<_>>()
            .expect("each name");
        assert!(
            names.contains(&"activity_server_at".to_owned()),
            "{names:?}"
        );
        assert!(!names.contains(&"activity_server".to_owned()), "{names:?}");
    }

    #[test]
    fn the_memo_answers_its_own_type_and_is_emptied_when_full() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = Db::open(&dir.path().join("doorward.db")).expect("database");
        db.remember("first".to_owned(), 7_i64);
        assert_eq!(db.cached::<i64>("first").as_deref(), Some(&7));
        assert!(
            db.cached::<String>("first").is_none(),
            "another type is no hit"
        );
        for index in 0..MEMO_LIMIT {
            db.remember(format!("key{index}"), index);
        }
        assert!(
            db.cached::<i64>("first").is_none(),
            "a full memo is emptied"
        );
        assert_eq!(
            db.cached::<usize>(&format!("key{}", MEMO_LIMIT - 1))
                .as_deref(),
            Some(&(MEMO_LIMIT - 1))
        );
    }
}
