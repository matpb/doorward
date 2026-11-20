mod common;

use common::admin;
use common::binary::{Outcome, Run, free_port, write_file};
use common::client::Tokens;
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::world::World;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

const BOB: &str = "bob@example.com";
const FOREIGN: &str = "https://evil.example.com";
const ALLOWED: &str = "chrome-extension://abcdefghijklmnop";
const REFUSAL: &str =
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Origin not allowed"}}"#;
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test-client","version":"0"}}}"#;
const FORM: &str = "application/x-www-form-urlencoded";

/// Bob with the demo server assigned; returns the upstream and his tokens for /demo and /mcp.
async fn bob_on_demo(w: &World) -> (FakeUpstream, [(&'static str, Tokens); 2]) {
    let bob = w.user(BOB).await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let demo = w.token(&bob, "demo").await;
    let combined = w.token(&bob, "mcp").await;
    (upstream, [("demo", demo), ("mcp", combined)])
}

/// Asserts the exact refusal: 403, JSON content type, the exact body, and no challenge.
fn assert_refused(reply: &McpReply, case: &str) {
    assert_eq!(reply.status, 403, "{case}: status, body {}", reply.body);
    assert_eq!(
        reply.header("content-type").as_deref(),
        Some("application/json"),
        "{case}: Content-Type"
    );
    assert_eq!(reply.body, REFUSAL, "{case}: body");
    assert!(
        reply.header("www-authenticate").is_none(),
        "{case}: WWW-Authenticate must be absent"
    );
}

/// Asserts that no response header starts with access-control-.
fn assert_no_cors(headers: &HeaderMap, case: &str) {
    let found: Vec<&str> = headers
        .keys()
        .map(HeaderName::as_str)
        .filter(|name| name.starts_with("access-control-"))
        .collect();
    assert!(found.is_empty(), "{case}: CORS headers {found:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_origin_is_refused_before_anything_else() {
    let mut w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    let bob_id = w.user_id(BOB).await;
    let rows_before = admin::activity(&w.owner, Some(&bob_id), None).await.len();
    // The owner's reads share the address bucket: after this restart only one read and one
    // normal request are left to spend from a burst of three.
    w.tighten(|c| c.limits.general_burst = 3).await;
    upstream.clear();
    for (slug, tokens) in &paths {
        let reply = w
            .session_mcp(slug, tokens)
            .raw(INITIALIZE.as_bytes(), &[("Origin", FOREIGN)])
            .await;
        assert_refused(&reply, &format!("initialize on /{slug}"));
        let reply = w
            .stateless_mcp(slug, tokens)
            .list_tools_with(&[("Origin", FOREIGN)])
            .await;
        assert_refused(&reply, &format!("tools/list on /{slug}"));
    }
    for _ in 0..2 {
        let reply = w
            .stateless_mcp("demo", &paths[0].1)
            .list_tools_with(&[("Origin", FOREIGN)])
            .await;
        assert_refused(&reply, "a sixth refused tools/list on /demo");
    }
    assert!(
        upstream.requests().is_empty(),
        "the upstream must see no request, saw {}",
        upstream.requests().len()
    );
    assert_eq!(
        admin::activity(&w.owner, Some(&bob_id), None).await.len(),
        rows_before,
        "a refused request must write no activity row"
    );
    let normal = w.stateless_mcp("demo", &paths[0].1).list_tools().await;
    assert_eq!(
        normal.status, 200,
        "a normal request after six refusals must be answered: body {}",
        normal.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_origin_forms() {
    let w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    upstream.clear();
    let own = w.base().to_owned();
    let port = w.gw.config().listen.port();
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("another origin", vec![FOREIGN.to_owned()]),
        ("null", vec!["null".to_owned()]),
        ("an empty value", vec![String::new()]),
        ("a trailing slash", vec![format!("{own}/")]),
        (
            "an uppercase host",
            vec![format!("http://LOCALHOST:{port}")],
        ),
        (
            "an explicit default port",
            vec!["http://127.0.0.1:80".to_owned()],
        ),
        ("another scheme", vec![format!("https://127.0.0.1:{port}")]),
        ("an uppercase scheme", vec![own.replacen("http", "HTTP", 1)]),
        (
            "another port",
            vec![format!("http://127.0.0.1:{}", u32::from(port) + 1)],
        ),
        (
            "a look-alike",
            vec!["https://gw.example.com.evil.example.com".to_owned()],
        ),
        (
            "an own origin beside a foreign one",
            vec![own.clone(), FOREIGN.to_owned()],
        ),
        ("two own origins", vec![own.clone(), own.clone()]),
        (
            "a value that is not visible ASCII",
            vec!["https://ex\u{e9}mple.example.com".to_owned()],
        ),
    ];
    for (case, values) in &cases {
        let pairs: Vec<(&str, &str)> = values
            .iter()
            .map(|value| ("Origin", value.as_str()))
            .collect();
        for (slug, tokens) in &paths {
            let reply = w.stateless_mcp(slug, tokens).list_tools_with(&pairs).await;
            assert_refused(&reply, &format!("{case} on /{slug}"));
        }
    }
    assert!(
        upstream.requests().is_empty(),
        "no refused form may reach the upstream, {} did",
        upstream.requests().len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateways_own_origin_and_no_origin_pass() {
    let w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    upstream.clear();
    for (slug, tokens) in &paths {
        let client = w.stateless_mcp(slug, tokens);
        let plain = client.list_tools().await;
        assert_eq!(
            plain.status, 200,
            "a request with no Origin on /{slug} must be answered: body {}",
            plain.body
        );
        let own = client.list_tools_with(&[("Origin", w.base())]).await;
        assert_eq!(
            own.status, 200,
            "the gateway's own origin on /{slug} must be answered: body {}",
            own.body
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_origin_is_refused_without_a_token_too() {
    let w = World::start().await;
    let (upstream, _paths) = bob_on_demo(&w).await;
    upstream.clear();
    for slug in ["demo", "mcp"] {
        let anonymous = McpClient::stateless(&w.resource(slug), None);
        let plain = anonymous.list_tools().await;
        assert_eq!(
            plain.status, 401,
            "without a token and Origin, /{slug} answers 401: body {}",
            plain.body
        );
        assert!(
            plain.header("www-authenticate").is_some(),
            "without a token and Origin, /{slug} carries a challenge"
        );
        let reply = anonymous.list_tools_with(&[("Origin", FOREIGN)]).await;
        assert_refused(
            &reply,
            &format!("a foreign origin without a token on /{slug}"),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_and_delete_are_covered() {
    let w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    upstream.clear();
    for (slug, tokens) in &paths {
        let client = w.stateless_mcp(slug, tokens);
        for method in [Method::GET, Method::DELETE, Method::PUT, Method::OPTIONS] {
            let name = method.to_string();
            let reply = client.bodiless(method, &[("Origin", FOREIGN)]).await;
            assert_refused(&reply, &format!("{name} with a foreign origin on /{slug}"));
        }
    }
    let own = w.gw.config().public_url.clone();
    for (slug, tokens) in &paths {
        let client = w.stateless_mcp(slug, tokens);
        for method in [Method::PUT, Method::OPTIONS] {
            let name = method.to_string();
            let plain = client.bodiless(method.clone(), &[]).await;
            let good = client
                .bodiless(method.clone(), &[("Origin", own.as_str())])
                .await;
            assert_eq!(plain.status, 405, "{name} with no Origin on /{slug}");
            assert!(
                plain.body.is_empty(),
                "{name} with no Origin on /{slug}: body"
            );
            assert_eq!(good.status, 405, "{name} with the own origin on /{slug}");
            assert!(
                good.body.is_empty(),
                "{name} with the own origin on /{slug}: body"
            );
        }
    }
    assert!(
        upstream.requests().is_empty(),
        "no refused method may reach the upstream, {} did",
        upstream.requests().len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_paths_follow_the_same_rule() {
    let w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    upstream.clear();
    // Bob's demo token is valid for /demo only, so /zzz is an unknown slug he cannot pass.
    let zzz = w.stateless_mcp("zzz", &paths[0].1);
    let plain = zzz.bodiless(Method::GET, &[]).await;
    assert_eq!(
        plain.status, 401,
        "GET /zzz with no Origin: body {}",
        plain.body
    );
    let foreign = zzz.bodiless(Method::GET, &[("Origin", FOREIGN)]).await;
    assert_refused(&foreign, "GET /zzz with a foreign origin");
    let plain = zzz.raw(INITIALIZE.as_bytes(), &[]).await;
    assert_eq!(
        plain.status, 401,
        "POST /zzz with no Origin: body {}",
        plain.body
    );
    let foreign = zzz.raw(INITIALIZE.as_bytes(), &[("Origin", FOREIGN)]).await;
    assert_refused(&foreign, "POST /zzz with a foreign origin");
    assert!(
        upstream.requests().is_empty(),
        "no request to an unknown slug may reach the upstream, {} did",
        upstream.requests().len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_origin_passes() {
    let w = World::start_with(|c| c.allowed_origins = vec![ALLOWED.to_owned()]).await;
    let (_upstream, paths) = bob_on_demo(&w).await;
    for (slug, tokens) in &paths {
        let client = w.stateless_mcp(slug, tokens);
        let allowed = client.list_tools_with(&[("Origin", ALLOWED)]).await;
        assert_eq!(
            allowed.status, 200,
            "the allowed origin on /{slug} must be answered: body {}",
            allowed.body
        );
        let other = client
            .list_tools_with(&[("Origin", "chrome-extension://other")])
            .await;
        assert_refused(&other, &format!("an origin not listed, on /{slug}"));
        let appended = client
            .list_tools_with(&[("Origin", "chrome-extension://abcdefghijklmnopq")])
            .await;
        assert_refused(
            &appended,
            &format!("an allowed origin with a character appended, on /{slug}"),
        );
    }
}

/// The bad lists of `allowed_origins`, each with the message its start prints after "doorward: ".
fn refused_lists() -> Vec<(Vec<String>, String)> {
    let long = format!("https://{}", "a".repeat(249));
    let shown = format!("https://{}", "a".repeat(192));
    let many: Vec<String> = (0..33)
        .map(|index| format!("https://h{index}.example.com"))
        .collect();
    vec![
        (
            vec!["*".to_owned()],
            r#"invalid config: allowed_origins entry "*" is a wildcard, not an origin"#.to_owned(),
        ),
        (
            vec!["null".to_owned()],
            r#"invalid config: allowed_origins entry "null" is not an origin"#.to_owned(),
        ),
        (
            vec!["https://a.example.com".to_owned(), String::new()],
            "invalid config: allowed_origins has an empty entry".to_owned(),
        ),
        (
            vec!["https://gw.example.com/".to_owned()],
            r#"invalid config: allowed_origins entry "https://gw.example.com/" has a path, query, fragment or trailing slash"#.to_owned(),
        ),
        (
            vec!["https://gw.example.com/x".to_owned()],
            r#"invalid config: allowed_origins entry "https://gw.example.com/x" has a path, query, fragment or trailing slash"#.to_owned(),
        ),
        (
            vec!["https://gw.example.com?x=1".to_owned()],
            r#"invalid config: allowed_origins entry "https://gw.example.com?x=1" has a path, query, fragment or trailing slash"#.to_owned(),
        ),
        (
            vec!["https://gw.example.com#x".to_owned()],
            r#"invalid config: allowed_origins entry "https://gw.example.com#x" has a path, query, fragment or trailing slash"#.to_owned(),
        ),
        (
            vec!["https://ex\u{e9}mple.example.com".to_owned()],
            r#"invalid config: allowed_origins entry "https://ex?mple.example.com" has a character outside visible ASCII"#.to_owned(),
        ),
        (
            vec!["https://gw.example.com ".to_owned()],
            r#"invalid config: allowed_origins entry "https://gw.example.com?" has a character outside visible ASCII"#.to_owned(),
        ),
        (
            vec!["example.com".to_owned()],
            r#"invalid config: allowed_origins entry "example.com" must be scheme://host[:port]"#.to_owned(),
        ),
        (
            vec![long],
            format!(r#"invalid config: allowed_origins entry "{shown}" is over 256 bytes"#),
        ),
        (
            many,
            "invalid config: allowed_origins has 33 entries, at most 32 are allowed".to_owned(),
        ),
    ]
}

/// Asserts that a start was refused with exit 2 and that stderr holds `line`.
fn assert_refused_start(outcome: &Outcome, line: &str) {
    assert_eq!(
        outcome.code,
        Some(2),
        "the start must be refused with exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.lines().any(|text| text == line),
        "the refusal must print {line:?}; stderr:\n{}",
        outcome.stderr
    );
}

#[test]
fn bad_allowed_origins_stop_the_start() {
    for (entries, message) in refused_lists() {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let list = entries
            .iter()
            .map(|entry| format!("'{entry}'"))
            .collect::<Vec<String>>()
            .join(", ");
        let text = format!(
            "public_url = \"http://127.0.0.1:{port}\"\nlisten = \"127.0.0.1:{port}\"\ndatabase = '{}'\nallowed_origins = [{list}]\n",
            dir.path().join("doorward.db").display()
        );
        let config = write_file(dir.path(), "doorward.toml", &text);
        let config = config.display().to_string();
        let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
        assert_refused_start(&outcome, &format!("doorward: {message}"));
    }
    refused_variables();
}

/// The same refusals when the list comes from DOORWARD_ALLOWED_ORIGINS, comma separated.
fn refused_variables() {
    let cases = [
        (
            "https://a.example.com,*",
            r#"doorward: invalid config: allowed_origins entry "*" is a wildcard, not an origin"#,
        ),
        (
            "https://a.example.com,",
            "doorward: invalid config: allowed_origins has an empty entry",
        ),
    ];
    for (value, line) in cases {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let listen = format!("127.0.0.1:{port}");
        let url = format!("http://127.0.0.1:{port}");
        let database = dir.path().join("doorward.db").display().to_string();
        let outcome = Run::spawn(
            &[],
            &[
                ("DOORWARD_PUBLIC_URL", url.as_str()),
                ("DOORWARD_LISTEN", listen.as_str()),
                ("DOORWARD_DATABASE", database.as_str()),
                ("DOORWARD_ALLOWED_ORIGINS", value),
            ],
        )
        .wait_for_exit();
        assert_refused_start(&outcome, line);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_origin_costs_the_user_nothing() {
    let mut w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    w.tighten(|c| c.limits.mcp_burst = 2).await;
    upstream.clear();
    let client = w.stateless_mcp("demo", &paths[0].1);
    for attempt in 1..=3 {
        let reply = client.list_tools_with(&[("Origin", FOREIGN)]).await;
        assert_refused(&reply, &format!("refused request {attempt}"));
    }
    for attempt in 1..=2 {
        let reply = client.list_tools().await;
        assert_eq!(
            reply.status, 200,
            "normal request {attempt} after the refusals must be answered: body {}",
            reply.body
        );
    }
    assert_eq!(
        upstream.rpc_count("tools/list"),
        2,
        "only the two normal lists may reach the upstream"
    );
    // A refused request opens no slot: with the only slot held, it is refused, not limited.
    w.tighten(|c| {
        c.limits.mcp_burst = 100;
        c.limits.mcp_open = 1;
    })
    .await;
    upstream.clear();
    upstream.set_mode(Mode::Hang);
    let held = Arc::new(w.stateless_mcp("demo", &paths[0].1));
    held.set_timeout(Duration::from_secs(120));
    let held_call = Arc::clone(&held);
    let stream =
        tokio::spawn(async move { held_call.call_tool("echo", json!({"text": "held"})).await });
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.rpc_count("tools/call") != 1 {
        assert!(
            Instant::now() < deadline,
            "the held call must reach the upstream"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let refused = client.list_tools_with(&[("Origin", FOREIGN)]).await;
    assert_refused(&refused, "a refused request while the only slot is held");
    stream.abort();
    upstream.set_mode(Mode::Normal);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let reply = client.list_tools().await;
        if reply.status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a normal request after the held one finished must be answered, last status {}",
            reply.status
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_non_rules_hold() {
    let w = World::start().await;
    let (upstream, paths) = bob_on_demo(&w).await;
    upstream.clear();
    let demo = w.stateless_mcp("demo", &paths[0].1);
    let mcp = w.stateless_mcp("mcp", &paths[1].1);

    let host = demo.list_tools_with(&[("Host", "evil.example.com")]).await;
    assert_eq!(
        host.status, 200,
        "a foreign Host alone must be answered: body {}",
        host.body
    );
    assert_no_cors(&host.headers, "a foreign Host");

    let form = b"grant_type=refresh_token&refresh_token=bogus&client_id=bogus";
    let token_url = w.gw.url("/oauth/token");
    let plain = McpClient::session(&token_url, None)
        .raw(form, &[("Content-Type", FORM)])
        .await;
    let foreign = McpClient::session(&token_url, None)
        .raw(form, &[("Content-Type", FORM), ("Origin", FOREIGN)])
        .await;
    assert_eq!(
        foreign.status, plain.status,
        "/oauth/token answers a foreign origin as without it"
    );
    assert_eq!(
        foreign.body, plain.body,
        "/oauth/token answers a foreign origin with the same body"
    );
    assert_no_cors(&foreign.headers, "/oauth/token");

    let register_url = w.gw.url("/oauth/register");
    let plain = McpClient::session(&register_url, None)
        .raw(b"{}", &[])
        .await;
    let foreign = McpClient::session(&register_url, None)
        .raw(b"{}", &[("Origin", FOREIGN)])
        .await;
    assert_eq!(
        foreign.status, plain.status,
        "/oauth/register answers a foreign origin as without it"
    );
    assert_eq!(
        foreign.body, plain.body,
        "/oauth/register answers a foreign origin with the same body"
    );
    assert_no_cors(&foreign.headers, "/oauth/register");

    let preflight = mcp
        .bodiless(
            Method::OPTIONS,
            &[
                ("Origin", FOREIGN),
                ("Access-Control-Request-Method", "POST"),
            ],
        )
        .await;
    assert_no_cors(&preflight.headers, "an OPTIONS preflight to /mcp");

    let own = mcp.list_tools_with(&[("Origin", w.base())]).await;
    assert_eq!(
        own.status, 200,
        "the own origin on /mcp must be answered: body {}",
        own.body
    );
    assert_no_cors(&own.headers, "the own origin on /mcp");

    for path in [
        "/login",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource/demo",
    ] {
        let url = w.gw.url(path);
        let plain = McpClient::session(&url, None)
            .bodiless(Method::GET, &[])
            .await;
        let foreign = McpClient::session(&url, None)
            .bodiless(Method::GET, &[("Origin", FOREIGN)])
            .await;
        assert_eq!(
            foreign.status, plain.status,
            "{path} answers a foreign origin as without it"
        );
        assert_no_cors(&foreign.headers, path);
    }
}
