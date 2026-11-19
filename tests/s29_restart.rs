mod common;

use std::path::Path;

use common::TestGateway;

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
