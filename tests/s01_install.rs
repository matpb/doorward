mod common;

use std::os::unix::fs::PermissionsExt;

use common::TestGateway;
use common::world::{OWNER_EMAIL, PASSWORD};

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
