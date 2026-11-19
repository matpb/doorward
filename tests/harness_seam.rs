mod common;

use common::TestGateway;
use doorward::cimd::UnavailableCimd;
use doorward::{CimdError, CimdFetcher, ClientMetadata};

const CLIENT: &str = "https://client.example.com/meta.json";

fn example_document() -> ClientMetadata {
    ClientMetadata {
        client_id: CLIENT.to_owned(),
        client_name: Some("Example".to_owned()),
        redirect_uris: vec!["http://127.0.0.1/callback".to_owned()],
        token_endpoint_auth_method: Some("none".to_owned()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn start_with_edits_config() {
    let gateway = TestGateway::start_with(|c| c.lifetimes.refresh_replay_seconds = 0).await;
    assert_eq!(gateway.config().lifetimes.refresh_replay_seconds, 0);
    let response = gateway
        .http
        .get(gateway.url("/healthz"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn fake_cimd_put_fetch_fail() {
    let gateway = TestGateway::start().await;
    let cimd = gateway.cimd();
    assert_eq!(
        CimdFetcher::fetch(cimd, CLIENT).await,
        Err(CimdError::Fetch("not found".into()))
    );
    cimd.put(CLIENT, "Example", &["http://127.0.0.1/callback"]);
    assert_eq!(
        CimdFetcher::fetch(cimd, CLIENT).await,
        Ok(example_document())
    );
    cimd.fail(CLIENT, CimdError::Invalid("bad".into()));
    assert_eq!(
        CimdFetcher::fetch(cimd, CLIENT).await,
        Err(CimdError::Invalid("bad".into()))
    );
    assert_eq!(cimd.fetches(CLIENT), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn cimd_survives_restart() {
    let mut gateway = TestGateway::start().await;
    gateway
        .cimd()
        .put(CLIENT, "Example", &["http://127.0.0.1/callback"]);
    gateway.restart().await;
    assert_eq!(
        CimdFetcher::fetch(gateway.cimd(), CLIENT).await,
        Ok(example_document())
    );
    let response = gateway
        .http
        .get(gateway.url("/healthz"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_code_is_readable() {
    let gateway = TestGateway::start().await;
    let _code: Option<String> = gateway.setup_code();
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_cimd_refuses() {
    assert_eq!(
        UnavailableCimd.fetch("https://client.example.com/x").await,
        Err(CimdError::Fetch(
            "client metadata fetching is not available".into()
        ))
    );
}
