use std::path::{Path, PathBuf};
use std::process::Command;

use doorward::crypto::token_hash;
use doorward::db::Db;

const EMAIL: &str = "bob@example.com";

/// A config file in `dir` whose database is `dir/doorward.db`; returns the config path.
fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("doorward.toml");
    let text = format!(
        "public_url = \"http://127.0.0.1:8717\"\ndatabase = '{}'\n",
        dir.join("doorward.db").display()
    );
    std::fs::write(&path, text).expect("write config");
    path
}

/// How many counted failures the database holds for `EMAIL`.
fn block_count(database: &Path) -> i64 {
    let conn = rusqlite::Connection::open(database).expect("open database");
    conn.query_row(
        "SELECT COUNT(*) FROM login_failures WHERE account_hash = ?1",
        [token_hash(EMAIL)],
        |row| row.get(0),
    )
    .expect("count failures")
}

/// Five counted failures from one address: the pair is blocked.
fn insert_block(database: &Path) {
    let conn = rusqlite::Connection::open(database).expect("open database");
    for _ in 0..5 {
        conn.execute(
            "INSERT INTO login_failures (account_hash, address, at) VALUES (?1, '127.0.0.1', 1800000000)",
            [token_hash(EMAIL)],
        )
        .expect("insert failure");
    }
}

/// Creates the account of `EMAIL` in `database` with no block; returns its id.
fn insert_account(database: &Path) -> i64 {
    let conn = rusqlite::Connection::open(database).expect("open database");
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'not-a-hash', 'user', 0)",
        [EMAIL],
    )
    .expect("insert account");
    conn.last_insert_rowid()
}

/// The (user id, user email, detail) of every unlock row of the activity log, oldest first.
fn unlock_rows(database: &Path) -> Vec<(Option<i64>, String, String)> {
    let conn = rusqlite::Connection::open(database).expect("open database");
    let mut statement = conn
        .prepare(
            "SELECT user_id, user_email, detail FROM activity WHERE kind = 'unlock' ORDER BY id",
        )
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

fn unlock(config: &Path, email: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_doorward"))
        .arg("unlock")
        .arg("--config")
        .arg(config)
        .arg(email)
        .output()
        .expect("run doorward unlock")
}

#[test]
fn unlock_removes_the_block_and_prints_the_line() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = write_config(dir.path());
    let database = dir.path().join("doorward.db");
    Db::open(&database).expect("create the database");
    insert_block(&database);
    assert_eq!(
        block_count(&database),
        5,
        "the failures must be in place first"
    );

    let output = unlock(&config, EMAIL);
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("unlocked {EMAIL}\n")
    );
    assert_eq!(block_count(&database), 0, "the block row must be gone");
}

#[test]
fn unlock_does_not_create_a_missing_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = write_config(dir.path());
    let database = dir.path().join("doorward.db");

    let output = unlock(&config, EMAIL);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing database must exit 1"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("doorward: no database at {}\n", database.display())
    );
    assert!(!database.exists(), "unlock must not create the database");
    let entries = std::fs::read_dir(dir.path())
        .expect("read the directory")
        .count();
    assert_eq!(entries, 1, "only the config file may be in the directory");
}

#[test]
fn unlock_refuses_an_email_no_account_has() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = write_config(dir.path());
    let database = dir.path().join("doorward.db");
    Db::open(&database).expect("create the database");
    insert_block(&database);

    let output = unlock(&config, EMAIL);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an email no account has must exit 1"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "doorward: no account has that email address\n"
    );
    assert!(
        output.stdout.is_empty(),
        "nothing may be printed on standard output"
    );
    assert_eq!(
        block_count(&database),
        5,
        "a refused unlock must leave the failures in place"
    );
    assert!(
        unlock_rows(&database).is_empty(),
        "a refused unlock must write no activity row"
    );
}

#[test]
fn unlock_writes_an_activity_row() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = write_config(dir.path());
    let database = dir.path().join("doorward.db");
    Db::open(&database).expect("create the database");
    let account = insert_account(&database);
    insert_block(&database);

    let output = unlock(&config, EMAIL);
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert_eq!(
        unlock_rows(&database),
        vec![(
            Some(account),
            EMAIL.to_owned(),
            "from the command line".to_owned()
        )],
        "a successful unlock must write one unlock row for the account"
    );
}

#[test]
fn unlock_succeeds_when_no_block_exists() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = write_config(dir.path());
    let database = dir.path().join("doorward.db");
    Db::open(&database).expect("create the database");

    let output = unlock(&config, EMAIL);
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("unlocked {EMAIL}\n")
    );
}
