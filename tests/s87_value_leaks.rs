//! Statement 87 beyond what `s84_stored_values` sees: the longest value, a value with its remove box,
//! and the log of the real binary after a store and a failed call.

mod common;

use std::path::PathBuf;

use common::admin::{self, ServerSpec};
use common::binary::{Run, free_port, write_file};
use common::client::{OAuthApp, TestClient};
use common::headers::{
    declare_header, header_id, received_calls, session_call, set_switches, stateless_call,
};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::values::{CANARY, remove_value, store_value, value_state};
use common::world::World;
use serde_json::json;
use tempfile::TempDir;

const BOB: &str = "bob@example.com";
const OWNER: &str = "owner@example.com";
const PASSWORD: &str = "correct horse battery staple";
const SLUG: &str = "demo";
const HEADER: &str = "X-Trace-Id";
const LOWER: &str = "x-trace-id";
const CALLBACK: &str = "http://127.0.0.1:8765/callback";

/// Bob, assigned to the demo server with the header declared and only the store switch on.
async fn demo_for_bob(w: &World) -> (FakeUpstream, String, TestClient) {
    let (upstream, id) = w.upstream(SLUG, UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    let declared = declare_header(&w.owner, &id, HEADER, false).await;
    assert_eq!(
        declared.status, 303,
        "declaring the header must be accepted"
    );
    let switched = set_switches(&w.owner, &id, false, true).await;
    assert_eq!(switched.status, 303, "the store switch must be saved");
    let hid = header_id(&w.owner, &id, HEADER)
        .await
        .expect("the declared header has a remove form");
    (upstream, hid, bob)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_value_of_4096_bytes_reaches_the_upstream_whole() {
    let w = World::start().await;
    let (upstream, hid, bob) = demo_for_bob(&w).await;
    let longest = format!("{CANARY}{}", "v".repeat(4096 - CANARY.len()));
    assert_eq!(longest.len(), 4096);
    let page = store_value(&bob, SLUG, &hid, &longest).await;
    assert_eq!(
        page.status, 303,
        "a value of exactly 4096 bytes is accepted"
    );

    let tokens = w.token(&bob, SLUG).await;
    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &tokens), "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    let carried: Vec<Option<String>> = received_calls(&upstream, "echo")
        .iter()
        .map(|call| call.header(LOWER).map(str::to_string))
        .collect();
    assert_eq!(carried, vec![Some(longest)], "the whole value must arrive");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_posted_with_its_remove_box_is_refused_and_changes_nothing() {
    let w = World::start().await;
    let (upstream, hid, bob) = demo_for_bob(&w).await;
    let stored = store_value(&bob, SLUG, &hid, CANARY).await;
    assert_eq!(stored.status, 303);

    let csrf = bob
        .get("/account")
        .await
        .csrf()
        .expect("the account page carries a csrf field");
    let value = format!("value_{hid}");
    let remove = format!("remove_{hid}");
    let page = bob
        .post(
            &format!("/account/values/{SLUG}"),
            &[
                ("csrf", csrf.as_str()),
                (value.as_str(), "another-value-1"),
                (remove.as_str(), "1"),
            ],
        )
        .await;
    assert_eq!(
        page.status, 400,
        "a value and its remove box together is 400"
    );
    assert_eq!(
        page.count(r#"div.notice[data-notice="error"][role="alert"]"#),
        1
    );
    assert!(!page.body.contains("another-value-1") && !page.body.contains(CANARY));
    assert_eq!(
        value_state(&bob, SLUG, LOWER).await.as_deref(),
        Some("set"),
        "the stored value must be untouched"
    );

    let tokens = w.token(&bob, SLUG).await;
    upstream.clear();
    let reply = session_call(&session(&w, &tokens).await, "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(
        received_calls(&upstream, "echo")[0].header(LOWER),
        Some(CANARY),
        "the old value must still be sent"
    );

    let removed = remove_value(&bob, SLUG, &hid).await;
    assert_eq!(
        removed.status, 303,
        "the remove box alone removes the value"
    );
    assert_eq!(
        value_state(&bob, SLUG, LOWER).await.as_deref(),
        Some("unset")
    );
}

async fn session(w: &World, tokens: &common::client::Tokens) -> McpClient {
    let client = w.session_mcp(SLUG, tokens);
    assert_eq!(client.initialize().await.status, 200);
    client
}

/// The real binary on a free loopback port, with its database in a temp dir.
struct Spawned {
    run: Run,
    base: String,
    _dir: TempDir,
}

impl Spawned {
    fn start() -> Spawned {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let db: PathBuf = dir.path().join("doorward.db");
        let text = format!(
            "public_url = \"http://127.0.0.1:{port}\"\nlisten = \"127.0.0.1:{port}\"\ndatabase = '{}'\n",
            db.display()
        );
        let config = write_file(dir.path(), "doorward.toml", &text);
        let config = config.display().to_string();
        let mut run = Run::spawn(&["--config", config.as_str()], &[]);
        run.wait_until_healthy(port);
        Spawned {
            run,
            base: format!("http://127.0.0.1:{port}"),
            _dir: dir,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn storing_a_value_and_a_failed_call_write_no_line_holding_the_value() {
    let gateway = Spawned::start();
    let code = gateway
        .run
        .stderr()
        .lines()
        .find_map(|line| {
            line.strip_prefix("doorward setup code: ")
                .map(str::to_owned)
        })
        .expect("the binary prints a setup code while no owner exists");
    let owner = TestClient::new(&gateway.base);
    let setup = owner.setup_owner(&code, OWNER, PASSWORD).await;
    assert_eq!(setup.status, 303, "setup must sign the owner in");

    let mut upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: SLUG,
            slug: SLUG,
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    assert_eq!(declare_header(&owner, &id, HEADER, false).await.status, 303);
    assert_eq!(set_switches(&owner, &id, false, true).await.status, 303);
    let owner_id = admin::user_id(&owner, OWNER)
        .await
        .expect("the owner is listed");
    assert_eq!(
        admin::assign(&owner, &owner_id, &[id.as_str()])
            .await
            .status,
        303
    );
    let hid = header_id(&owner, &id, HEADER)
        .await
        .expect("the declared header has a remove form");

    let stored = store_value(&owner, SLUG, &hid, CANARY).await;
    assert_eq!(stored.status, 303, "the owner stores a value");
    let refused = store_value(&owner, SLUG, &hid, &format!("{CANARY}\nnext")).await;
    assert_eq!(refused.status, 400, "a value with a line break is refused");

    let registered = owner.register("Probe Client", &[CALLBACK]).await;
    assert_eq!(registered.status, 201, "the probe client must register");
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: CALLBACK.to_owned(),
    };
    let resource = format!("{}/{SLUG}", gateway.base);
    let tokens = owner.connect(&app, &resource).await;
    let mcp = McpClient::stateless(&resource, Some(&tokens.access_token));
    let reply = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        reply.status, 200,
        "the call must reach the running upstream"
    );

    upstream.shutdown().await;
    let failed = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        failed.status, 502,
        "an unreachable upstream must answer 502"
    );

    let log = gateway.run.stderr();
    assert!(
        log.lines()
            .any(|line| line.starts_with("doorward: upstream demo failed")),
        "positive control: the failed call must have written its line; stderr:\n{log}"
    );
    assert!(
        !log.contains(CANARY),
        "no line of standard error may hold a stored value; stderr:\n{log}"
    );
}
