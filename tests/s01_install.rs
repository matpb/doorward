mod common;

use std::os::unix::fs::PermissionsExt;

use common::TestGateway;

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
        .get(gateway.url("/nope"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(response.text().await.expect("body"), "");
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
