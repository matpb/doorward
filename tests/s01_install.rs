mod common;

use std::os::unix::fs::PermissionsExt;

use std::path::Path;

use common::TestGateway;
use common::binary::{Run, free_port, http, lines_containing};
use common::world::{OWNER_EMAIL, PASSWORD};

/// Renames `from` to `to` in the database, which makes reads of the old name fail.
fn rename_table(database: &Path, from: &str, to: &str) {
    let conn = rusqlite::Connection::open(database).expect("open the database");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("set the busy timeout");
    conn.execute_batch(&format!("ALTER TABLE {from} RENAME TO {to};"))
        .expect("rename the table");
}

#[tokio::test(flavor = "multi_thread")]
async fn s01_health_answers() {
    let gateway = TestGateway::start().await;
    let response = gateway
        .http
        .get(gateway.url("/healthz"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.text().await.expect("body"), r#"{"status":"ok"}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn s01_unknown_path_is_404() {
    let gateway = TestGateway::start().await;
    let response = gateway
        .http
        .get(gateway.url("/no/such/page"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(response.text().await.expect("body"), "");
}

#[tokio::test(flavor = "multi_thread")]
async fn s01_a_possible_server_path_never_says_whether_it_exists() {
    let gateway = TestGateway::start().await;
    let response = gateway
        .http
        .get(gateway.url("/nope"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(response.text().await.expect("body"), "");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_root_address_leads_to_setup_then_to_sign_in() {
    let gateway = TestGateway::start().await;
    let before = gateway.client().get("/").await;
    assert_eq!(
        before.status, 303,
        "GET / must redirect while no owner exists"
    );
    assert_eq!(
        before.location().as_deref(),
        Some("/setup"),
        "GET / must lead to /setup while no owner exists"
    );

    let Some(code) = gateway.setup_code() else {
        panic!("the gateway must print a setup code while no owner exists");
    };
    let created = gateway
        .client()
        .setup_owner(&code, OWNER_EMAIL, PASSWORD)
        .await;
    assert_eq!(created.status, 303, "the setup must create the owner");

    let after = gateway.client().get("/").await;
    assert_eq!(
        after.status, 303,
        "GET / must redirect once an owner exists"
    );
    assert_eq!(
        after.location().as_deref(),
        Some("/login"),
        "GET / must lead to /login once an owner exists"
    );

    let unknown = gateway.client().get("/nothing-here").await;
    assert_eq!(
        unknown.status, 401,
        "GET /nothing-here must keep its answer of 401, the answer of a server path"
    );
}

#[test]
fn health_says_unavailable_when_the_database_fails() {
    let dir = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let listen = format!("127.0.0.1:{port}");
    let database = dir.path().join("doorward.db");
    let database_text = database.display().to_string();
    let env = [
        ("DOORWARD_PUBLIC_URL", url.as_str()),
        ("DOORWARD_LISTEN", listen.as_str()),
        ("DOORWARD_DATABASE", database_text.as_str()),
    ];
    let mut gateway = Run::spawn(&[], &env);
    gateway.wait_until_healthy(port);

    let ok = http(port, "GET", "/healthz", &[], &[]);
    assert_eq!(
        ok.status, 200,
        "healthz must answer 200 on a working database"
    );
    assert_eq!(ok.body, r#"{"status":"ok"}"#);

    rename_table(&database, "settings", "settings_hidden");
    let failed = http(port, "GET", "/healthz", &[], &[]);
    assert_eq!(
        failed.status, 503,
        "healthz must answer 503 while the database cannot be read"
    );
    assert_eq!(failed.body, r#"{"status":"unavailable"}"#);
    let stderr = gateway.stderr();
    let lines = lines_containing(&stderr, "doorward: health check failed: ");
    assert_eq!(
        lines.len(),
        1,
        "a failed health check must write one line; stderr:\n{stderr}"
    );

    rename_table(&database, "settings_hidden", "settings");
    let repaired = http(port, "GET", "/healthz", &[], &[]);
    assert_eq!(
        repaired.status, 200,
        "healthz must answer 200 again once the database works"
    );
    assert_eq!(repaired.body, r#"{"status":"ok"}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn s01_database_file_is_private() {
    let gateway = TestGateway::start().await;
    let path = gateway.db_path();
    assert!(path.exists(), "database file missing at {}", path.display());
    let mode = std::fs::metadata(&path)
        .expect("stat database")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
