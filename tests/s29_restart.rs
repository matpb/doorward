mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::TestGateway;
use common::binary::{Run, write_file};

/// A config file in `dir` that names `database` and, when given, `key_file`; returns its path.
fn config_naming(dir: &Path, name: &str, database: &Path, key_file: Option<&Path>) -> String {
    let key_line = key_file
        .map(|key| format!("key_file = '{}'\n", key.display()))
        .unwrap_or_default();
    let text = format!(
        "public_url = \"http://127.0.0.1:8717\"\ndatabase = '{}'\n{key_line}",
        database.display()
    );
    write_file(dir, name, &text).display().to_string()
}

fn migration_rows(path: &Path) -> Vec<(i64, String)> {
    let conn = rusqlite::Connection::open(path).expect("open database");
    let mut stmt = conn
        .prepare("SELECT version, applied_at FROM schema_migrations ORDER BY version")
        .expect("prepare");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

#[tokio::test(flavor = "multi_thread")]
async fn s29_restart_keeps_data() {
    let mut gateway = TestGateway::start().await;
    {
        let conn = rusqlite::Connection::open(gateway.db_path()).expect("open database");
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)",
            rusqlite::params!["probe", b"kept".as_slice()],
        )
        .expect("insert");
    }
    gateway.restart().await;
    let response = gateway
        .http
        .get(gateway.url("/healthz"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let conn = rusqlite::Connection::open(gateway.db_path()).expect("open database");
    let value: Vec<u8> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            ["probe"],
            |row| row.get(0),
        )
        .expect("row survives restart");
    assert_eq!(value, b"kept");
}

#[test]
fn a_start_up_failure_names_the_file_and_the_cause() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();

    let absent = root.join("absent.toml");
    let absent_text = absent.display().to_string();
    let outcome = Run::spawn(&["--config", absent_text.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a missing config file must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot read the config file {absent_text}: No such file or directory (os error 2)\n"
        ),
        "the line must name the config file and the cause"
    );

    let missing = root.join("missing");
    let database = missing.join("doorward.db");
    let config = config_naming(root, "database.toml", &database, None);
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a database in a missing directory must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot open the database {}: No such file or directory (os error 2)\n",
            database.display()
        ),
        "the line must name the database and the cause"
    );
    assert!(
        !missing.exists(),
        "the missing directory must not be created"
    );

    let key = missing.join("doorward.key");
    let database = root.join("keyed.db");
    let config = config_naming(root, "key-missing.toml", &database, Some(&key));
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a key file that cannot be created must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot create the key file {}: No such file or directory (os error 2)\n",
            key.display()
        ),
        "the line must name the key file and the cause"
    );
    assert!(!key.exists(), "no key file may be created");

    let keydir = root.join("keydir");
    std::fs::create_dir(&keydir).expect("create the directory used as a key file");
    std::fs::set_permissions(&keydir, std::fs::Permissions::from_mode(0o700))
        .expect("make the directory private");
    let database = root.join("dir-key.db");
    let config = config_naming(root, "key-dir.toml", &database, Some(&keydir));
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a key file that cannot be read must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot read the key file {}: Is a directory (os error 21)\n",
            keydir.display()
        ),
        "the line must name the key file and the cause"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s29_migrations_apply_once() {
    let mut gateway = TestGateway::start().await;
    let after_start = migration_rows(&gateway.db_path());
    assert!(
        !after_start.is_empty(),
        "a first start must apply migrations"
    );
    for (index, row) in after_start.iter().enumerate() {
        assert_eq!(row.0, index as i64 + 1, "versions must run from 1 upward");
    }
    gateway.restart().await;
    let after_restart = migration_rows(&gateway.db_path());
    assert_eq!(after_restart, after_start);
}
