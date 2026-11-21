mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use common::client::{Page, TestClient, pkce, tokens};
use common::mcp::McpClient;
use common::upstream::{Mode, UpstreamOptions};
use common::world::{APP_ID, APP_REDIRECT, OWNER_EMAIL, PASSWORD, World};
use doorward::Config;
use doorward::config::{Range, SETTINGS};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rusqlite::Connection;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use url::form_urlencoded::Serializer;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const WRONG: &str = "definitely wrong";
const NEW_PASSWORD: &str = "a brand new passphrase";
const LOCAL_8787: &str = "http://localhost:8787/callback";
const FORM: &str = "application/x-www-form-urlencoded";
const JSON_TYPE: &str = "application/json";

/// Trusts the loopback peer, so X-Forwarded-For names the caller.
fn trust_loopback(c: &mut Config) {
    c.trusted_proxies = vec![Range::from(IpAddr::V4(Ipv4Addr::LOCALHOST))];
}

/// Every burst at 2.
fn bursts_of_two(c: &mut Config) {
    c.limits.general_burst = 2;
    c.limits.oauth_burst = 2;
    c.limits.credentials_burst = 2;
    c.limits.mcp_burst = 2;
}

/// Trusted loopback and bursts of 1000, so a test's refusal is the only limit it meets.
fn roomy(c: &mut Config) {
    trust_loopback(c);
    c.limits.general_burst = 1000;
    c.limits.oauth_burst = 1000;
    c.limits.credentials_burst = 1000;
    c.limits.mcp_burst = 1000;
}

/// Restarts `w` on the same database under the test limits, then `extra`.
async fn tight(w: &mut World, extra: impl FnOnce(&mut Config)) {
    w.tighten(move |c| {
        trust_loopback(c);
        bursts_of_two(c);
        extra(c);
    })
    .await;
}

/// Asserts a limited answer and returns its Retry-After in seconds.
fn assert_limited(status: u16, headers: &HeaderMap, what: &str) -> u64 {
    assert_eq!(
        status, 429,
        "{what}: expected 429 Too Many Requests, got {status}"
    );
    let retry = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("{what}: a limited answer needs an integer Retry-After"));
    assert!(
        retry >= 1,
        "{what}: Retry-After must be at least 1, got {retry}"
    );
    assert_eq!(
        headers
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "{what}: a limited answer must say Cache-Control: no-store"
    );
    assert!(
        headers.get("www-authenticate").is_none(),
        "{what}: a limited answer must not carry WWW-Authenticate"
    );
    retry
}

/// Asserts that a request was judged and not limited.
fn assert_answered(status: u16, what: &str) {
    assert_ne!(status, 429, "{what} must be answered, not limited");
}

/// Counts the rows of `sql`, read from the gateway's database file.
fn rows(w: &World, sql: &str) -> i64 {
    Connection::open(w.gw.db_path())
        .expect("the gateway database opens")
        .query_row(sql, [], |row| row.get(0))
        .expect("the count query runs")
}

/// Polls `ready` until it holds; panics when `within` has passed.
async fn wait_until(what: &str, within: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "{what} was not reached within {within:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A form body with the given fields.
fn form(fields: &[(&str, &str)]) -> String {
    let mut serializer = Serializer::new(String::new());
    serializer.extend_pairs(fields);
    serializer.finish()
}

async fn page_of(response: reqwest::Response) -> Page {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.text().await.expect("the body is read");
    Page {
        status,
        headers,
        body,
    }
}

/// A POST with an explicit X-Forwarded-For and no cookies.
async fn send_from(
    w: &World,
    forwarded: &str,
    path: &str,
    content_type: &str,
    body: String,
) -> Page {
    let response =
        w.gw.http
            .post(w.gw.url(path))
            .header("content-type", content_type)
            .header("X-Forwarded-For", forwarded)
            .body(body)
            .send()
            .await
            .unwrap_or_else(|err| panic!("POST {path} failed: {err}"));
    page_of(response).await
}

/// A token request from `forwarded`.
async fn token_from(w: &World, forwarded: &str, fields: &[(&str, &str)]) -> Page {
    send_from(w, forwarded, "/oauth/token", FORM, form(fields)).await
}

/// POSTs `size` bytes to `/nothing-here` from `forwarded`; returns the answer's status and headers.
/// The gateway may answer and close before the body is sent, so a failed write ends the send.
async fn post_body_from(w: &World, forwarded: &str, size: usize) -> (u16, HeaderMap) {
    let authority = w.gw.base.trim_start_matches("http://").to_owned();
    let head = format!(
        "POST /nothing-here HTTP/1.1\r\nHost: {authority}\r\nX-Forwarded-For: {forwarded}\r\n\
         Content-Length: {size}\r\nConnection: close\r\n\r\n"
    );
    let stream = TcpStream::connect(&authority)
        .await
        .expect("the gateway accepts a connection");
    let (mut reader, mut writer) = stream.into_split();
    let sender = tokio::spawn(async move {
        let _ = writer.write_all(head.as_bytes()).await;
        let _ = writer.write_all(&vec![0u8; size]).await;
    });
    let mut answer = Vec::new();
    let mut buffer = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            // A reset after the answer ends the read; the answer read so far is kept.
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => answer.extend_from_slice(&buffer[..n]),
            }
        }
    })
    .await;
    sender.abort();
    assert!(read.is_ok(), "the gateway must answer within 20 seconds");
    let text = String::from_utf8_lossy(&answer).into_owned();
    let head_end = text
        .find("\r\n\r\n")
        .unwrap_or_else(|| panic!("the gateway answered no head: {text:?}"));
    let mut lines = text[..head_end].split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("the status line carries a code");
    let mut headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.append(
                HeaderName::from_bytes(name.trim().as_bytes()).expect("a header name"),
                HeaderValue::from_str(value.trim()).expect("a header value"),
            );
        }
    }
    (status, headers)
}

/// A GET with the browser's cookies and an explicit X-Forwarded-For.
async fn get_from(browser: &TestClient, forwarded: &str, target: &str) -> Page {
    browser
        .get_with(target, &[("X-Forwarded-For", forwarded)])
        .await
}

/// A HEAD with an explicit X-Forwarded-For and no cookies.
async fn head_from(w: &World, forwarded: &str, path: &str) -> Page {
    let response =
        w.gw.http
            .head(w.gw.url(path))
            .header("X-Forwarded-For", forwarded)
            .send()
            .await
            .unwrap_or_else(|err| panic!("HEAD {path} failed: {err}"));
    page_of(response).await
}

/// The authorization request of the test app for `resource`.
fn authorize_path(resource: &str, state: &str, challenge: &str) -> String {
    let query = form(&[
        ("response_type", "code"),
        ("client_id", APP_ID),
        ("redirect_uri", APP_REDIRECT),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("resource", resource),
        ("state", state),
        ("scope", "mcp"),
    ]);
    format!("/oauth/authorize?{query}")
}

/// Approves the consent page `req` from `forwarded`.
async fn approve_from(browser: &TestClient, forwarded: &str, req: &str) -> Page {
    let page = get_from(browser, forwarded, &format!("/oauth/consent?req={req}")).await;
    let csrf = page.csrf().expect("the consent page carries a csrf token");
    browser
        .post_with(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req),
                ("decision", "approve"),
            ],
            &[("X-Forwarded-For", forwarded)],
        )
        .await
}

/// A sign-in attempt from `forwarded` with the csrf token of the login page.
async fn login_from(browser: &TestClient, forwarded: &str, email: &str, password: &str) -> Page {
    let page = get_from(browser, forwarded, "/login").await;
    let csrf = page.csrf().expect("the login page carries a csrf token");
    browser
        .post_with(
            "/login",
            &[
                ("csrf", csrf.as_str()),
                ("email", email),
                ("password", password),
            ],
            &[("X-Forwarded-For", forwarded)],
        )
        .await
}

/// A password change from `forwarded` with the csrf token of the account page.
async fn change_password_from(
    browser: &TestClient,
    forwarded: &str,
    current: &str,
    new: &str,
) -> Page {
    let page = get_from(browser, forwarded, "/account").await;
    let csrf = page.csrf().expect("the account page carries a csrf token");
    browser
        .post_with(
            "/account/password",
            &[
                ("csrf", csrf.as_str()),
                ("current_password", current),
                ("new_password", new),
            ],
            &[("X-Forwarded-For", forwarded)],
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn each_class_limits_after_its_burst() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let from = "192.0.2.10";
    let browser = w.client();
    let login = get_from(&browser, from, "/login").await;
    let csrf = login.csrf().expect("the login page carries a csrf token");
    for n in 1..=2 {
        let page = browser
            .post_with(
                "/login",
                &[
                    ("csrf", csrf.as_str()),
                    ("email", OWNER_EMAIL),
                    ("password", WRONG),
                ],
                &[("X-Forwarded-For", from)],
            )
            .await;
        assert_eq!(page.status, 401, "wrong password {n} must be answered 401");
    }
    let page = browser
        .post_with(
            "/login",
            &[
                ("csrf", csrf.as_str()),
                ("email", OWNER_EMAIL),
                ("password", WRONG),
            ],
            &[("X-Forwarded-For", from)],
        )
        .await;
    assert_limited(page.status, &page.headers, "the third sign-in attempt");
    assert_eq!(
        rows(&w, "SELECT COUNT(*) FROM login_failures"),
        2,
        "a limited sign-in must count no failure"
    );

    let page = get_from(&browser, from, "/nothing-here").await;
    assert_answered(page.status, "the second general request");
    let page = get_from(&browser, from, "/nothing-here").await;
    assert_limited(page.status, &page.headers, "the third general request");

    for n in 1..=2 {
        let page = token_from(&w, from, &[]).await;
        assert_answered(page.status, &format!("token request {n}"));
    }
    let page = token_from(&w, from, &[]).await;
    assert_limited(page.status, &page.headers, "the third token request");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_header_from_an_untrusted_peer_changes_nothing() {
    let mut w = World::start().await;
    w.tighten(|c| {
        c.shared_client_address = true;
        bursts_of_two(c);
    })
    .await;
    let browser = w.client();
    for forwarded in ["192.0.2.1", "192.0.2.2"] {
        let page = get_from(&browser, forwarded, "/nothing-here").await;
        assert_answered(page.status, "a request with a forged X-Forwarded-For");
    }
    let page = get_from(&browser, "192.0.2.3", "/nothing-here").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third request, with a third forged address",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn prepended_addresses_are_ignored() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let browser = w.client();
    for n in 1..=3 {
        let forwarded = format!("198.51.100.{n}, 192.0.2.10");
        let page = get_from(&browser, &forwarded, "/nothing-here").await;
        if n < 3 {
            assert_answered(page.status, &format!("request {n} behind the proxy"));
        } else {
            assert_limited(
                page.status,
                &page.headers,
                "the third request behind the proxy",
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_callers_have_two_buckets() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let browser = w.client();
    for _ in 0..2 {
        let page = get_from(&browser, "192.0.2.10", "/nothing-here").await;
        assert_answered(page.status, "a request from caller A");
    }
    let page = get_from(&browser, "192.0.2.10", "/nothing-here").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third request from caller A",
    );
    let page = get_from(&browser, "192.0.2.20", "/nothing-here").await;
    assert_answered(page.status, "the first request from caller B");
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv6_callers_are_counted_by_their_64() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let browser = w.client();
    for forwarded in ["2001:db8:1::1", "2001:db8:1::2"] {
        let page = get_from(&browser, forwarded, "/nothing-here").await;
        assert_answered(page.status, &format!("a request from {forwarded}"));
    }
    let page = get_from(&browser, "2001:db8:1::3", "/nothing-here").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third request from the same /64",
    );
    let page = get_from(&browser, "2001:db8:2::1", "/nothing-here").await;
    assert_answered(page.status, "the first request from another /64");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limited_refresh_keeps_the_token() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let first = w.token(&bob, "demo").await;
    tight(&mut w, |_| {}).await;
    let from = "192.0.2.10";
    let resource = w.resource("demo");
    for n in 1..=2 {
        let page = token_from(
            &w,
            from,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", "not-issued"),
                ("client_id", APP_ID),
            ],
        )
        .await;
        assert_answered(page.status, &format!("refresh request {n}"));
    }
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", first.refresh_token.as_str()),
        ("client_id", APP_ID),
        ("resource", resource.as_str()),
    ];
    let limited = token_from(&w, from, &refresh).await;
    let retry = assert_limited(
        limited.status,
        &limited.headers,
        "the refresh over the budget",
    );
    assert_eq!(
        limited.json(),
        Some(json!({
            "error": "too_many_requests",
            "error_description": "Too many requests. Try again later.",
        })),
        "a limited refresh must answer the too_many_requests JSON"
    );
    w.gw.clock.advance(time::Duration::seconds(retry as i64));
    let page = token_from(&w, from, &refresh).await;
    assert_eq!(
        page.status, 200,
        "the same refresh token must be accepted after the wait"
    );
    let renewed = tokens(&page).expect("the refresh must issue a new pair");
    w.gw.clock.advance(time::Duration::minutes(1));
    let next = [
        ("grant_type", "refresh_token"),
        ("refresh_token", renewed.refresh_token.as_str()),
        ("client_id", APP_ID),
        ("resource", resource.as_str()),
    ];
    let page = token_from(&w, from, &next).await;
    assert!(
        tokens(&page).is_some(),
        "the family must not be revoked: the new refresh token answered {}",
        page.status
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limited_exchange_keeps_the_code() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    tight(&mut w, |_| {}).await;
    let from = "192.0.2.10";
    let resource = w.resource("demo");
    let proof = pkce();
    let target = authorize_path(&resource, "limited-exchange", &proof.challenge);
    let authorized = get_from(&bob, from, &target).await;
    assert_eq!(
        authorized.status, 303,
        "the authorization must reach the consent page"
    );
    let req = authorized
        .query("req")
        .expect("the redirect names the consent request");
    let granted = approve_from(&bob, from, &req).await;
    let code = granted
        .query("code")
        .expect("the approval must issue a code");
    let page = token_from(
        &w,
        from,
        &[("grant_type", "authorization_code"), ("code", "not-issued")],
    )
    .await;
    assert_answered(page.status, "a token request inside the budget");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", APP_REDIRECT),
        ("client_id", APP_ID),
        ("code_verifier", proof.verifier.as_str()),
        ("resource", resource.as_str()),
    ];
    let limited = token_from(&w, from, &exchange).await;
    let retry = assert_limited(
        limited.status,
        &limited.headers,
        "the exchange over the budget",
    );
    w.gw.clock.advance(time::Duration::seconds(retry as i64));
    let page = token_from(&w, from, &exchange).await;
    assert_eq!(page.status, 200, "the code must still work after the wait");
    assert!(
        tokens(&page).is_some(),
        "the exchange after the wait must issue tokens"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_bearer_flood_is_limited_without_a_challenge() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    let bob_tokens = w.token(&bob, "demo").await;
    tight(&mut w, |_| {}).await;
    let forger = McpClient::stateless(&w.resource("demo"), Some("not-issued-by-the-gateway"));
    for n in 1..=2 {
        let reply = forger
            .list_tools_with(&[("X-Forwarded-For", "192.0.2.10")])
            .await;
        assert_eq!(reply.status, 401, "bad bearer {n} must be answered 401");
    }
    let limited = forger
        .list_tools_with(&[("X-Forwarded-For", "192.0.2.10")])
        .await;
    assert_limited(
        limited.status,
        &limited.headers,
        "the third bad bearer from one address",
    );
    assert_eq!(
        limited.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32029, "message": "Too many requests"},
        })),
        "a limited MCP request must answer the JSON-RPC error -32029 with id null"
    );
    let valid = w
        .stateless_mcp("demo", &bob_tokens)
        .list_tools_with(&[("X-Forwarded-For", "198.51.100.20")])
        .await;
    assert_eq!(
        valid.status, 200,
        "bob's valid token from another address must be answered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_is_limited_whatever_the_address() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let carol = w.user(CAROL).await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    w.grant(CAROL, &[id.as_str()]).await;
    let bob_tokens = w.token(&bob, "demo").await;
    let carol_tokens = w.token(&carol, "demo").await;
    tight(&mut w, |_| {}).await;
    let bob_mcp = w.stateless_mcp("demo", &bob_tokens);
    for forwarded in ["192.0.2.10", "192.0.2.11"] {
        let reply = bob_mcp
            .list_tools_with(&[("X-Forwarded-For", forwarded)])
            .await;
        assert_eq!(
            reply.status, 200,
            "bob's list from {forwarded} must be answered"
        );
    }
    let limited = bob_mcp
        .list_tools_with(&[("X-Forwarded-For", "192.0.2.12")])
        .await;
    assert_limited(
        limited.status,
        &limited.headers,
        "bob's third list, from a third address",
    );
    assert_eq!(
        upstream.rpc_count("tools/list"),
        2,
        "the limited list must not reach the upstream"
    );
    let reply = w
        .stateless_mcp("demo", &carol_tokens)
        .list_tools_with(&[("X-Forwarded-For", "192.0.2.13")])
        .await;
    assert_eq!(reply.status, 200, "carol's first list must be answered");
}

#[tokio::test(flavor = "multi_thread")]
async fn open_requests_are_capped_per_user() {
    let mut w = World::start().await;
    let bob = w.user(BOB).await;
    let (upstream, id) = w
        .upstream(
            "demo",
            UpstreamOptions {
                mode: Mode::Hang,
                ..Default::default()
            },
        )
        .await;
    w.grant(BOB, &[id.as_str()]).await;
    let bob_tokens = w.token(&bob, "demo").await;
    tight(&mut w, |c| {
        c.limits.mcp_burst = 100;
        c.limits.mcp_open = 2;
    })
    .await;
    let client = Arc::new(w.stateless_mcp("demo", &bob_tokens));
    client.set_timeout(Duration::from_secs(120));
    let mut streams = Vec::new();
    for _ in 0..2 {
        let held = Arc::clone(&client);
        streams.push(tokio::spawn(async move {
            held.call_tool("echo", json!({"text": "held"})).await
        }));
    }
    wait_until(
        "both streams reaching the upstream",
        Duration::from_secs(10),
        || upstream.rpc_count("tools/call") == 2,
    )
    .await;
    let limited = client
        .list_tools_with(&[("X-Forwarded-For", "192.0.2.10")])
        .await;
    let retry = assert_limited(
        limited.status,
        &limited.headers,
        "a third request while two streams are open",
    );
    assert_eq!(retry, 1, "the open-request limit must answer Retry-After 1");
    streams[0].abort();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let reply = client
            .list_tools_with(&[("X-Forwarded-For", "192.0.2.10")])
            .await;
        if reply.status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a request after one stream closed must be answered, last status {}",
            reply.status
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for stream in &streams {
        stream.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_limit_is_checked_before_the_body() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let from = "192.0.2.10";
    let browser = w.client();
    for n in 1..=2 {
        let page = get_from(&browser, from, "/nothing-here").await;
        assert_answered(page.status, &format!("general request {n}"));
    }
    let (status, headers) = post_body_from(&w, from, 10 * 1024 * 1024).await;
    assert_limited(status, &headers, "a 10 MiB POST to an exhausted bucket");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_table_is_bounded() {
    let mut w = World::start().await;
    tight(&mut w, |c| c.limits.rate_table_keys = 4).await;
    let browser = w.client();
    let caller = "192.0.2.1";
    for n in 1..=2 {
        let page = get_from(&browser, caller, "/nothing-here").await;
        assert_answered(page.status, &format!("request {n} from the caller"));
    }
    let page = get_from(&browser, caller, "/nothing-here").await;
    assert_limited(page.status, &page.headers, "the caller's third request");
    for n in 1..=100 {
        let forwarded = format!("198.51.100.{n}");
        get_from(&browser, &forwarded, "/nothing-here").await;
    }
    let page = get_from(&browser, caller, "/nothing-here").await;
    assert_limited(
        page.status,
        &page.headers,
        "the caller after the flood of other addresses",
    );
    for newcomer in ["203.0.113.1", "203.0.113.2"] {
        let page = get_from(&browser, newcomer, "/nothing-here").await;
        assert_limited(
            page.status,
            &page.headers,
            &format!("newcomer {newcomer} after the flood"),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_addresses_cannot_fill_the_request_tables() {
    let mut w = World::start().await;
    tight(&mut w, |c| {
        c.limits.auth_requests_max = 50;
        c.limits.unused_registrations = 50;
    })
    .await;
    let browser = w.client();
    let path = authorize_path(&w.resource("demo"), "rotating", &pkce().challenge);
    for n in 1..=200 {
        get_from(&browser, &format!("198.51.100.{n}"), &path).await;
    }
    let pending = rows(&w, "SELECT COUNT(*) FROM auth_requests");
    assert!(pending > 0, "the authorization requests must create rows");
    assert!(
        pending <= 50,
        "auth_requests holds {pending} rows, the cap is 50"
    );
    let body = json!({"client_name": "X", "redirect_uris": [LOCAL_8787]}).to_string();
    for n in 1..=200 {
        send_from(
            &w,
            &format!("203.0.113.{n}"),
            "/oauth/register",
            JSON_TYPE,
            body.clone(),
        )
        .await;
    }
    let registered = rows(&w, "SELECT COUNT(*) FROM oauth_clients");
    assert!(registered > 0, "the registrations must create clients");
    assert!(
        registered <= 50,
        "oauth_clients holds {registered} rows, the bound of unused registrations is 50"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_refusals_carry_retry_after() {
    let mut w = World::start().await;
    w.tighten(roomy).await;
    let browser = w.client();
    let from = "192.0.2.30";
    for n in 1..=5 {
        let page = login_from(&browser, from, OWNER_EMAIL, WRONG).await;
        assert_eq!(page.status, 401, "wrong password {n} must be answered 401");
    }
    let blocked = login_from(&browser, from, OWNER_EMAIL, PASSWORD).await;
    assert_limited(
        blocked.status,
        &blocked.headers,
        "a sign-in from a blocked address",
    );

    let mut w = World::start().await;
    w.tighten(roomy).await;
    let from = "192.0.2.31";
    for n in 1..=5 {
        let page = change_password_from(&w.owner, from, WRONG, NEW_PASSWORD).await;
        assert_eq!(
            page.status, 400,
            "wrong current password {n} must be answered 400"
        );
    }
    let blocked = change_password_from(&w.owner, from, WRONG, NEW_PASSWORD).await;
    assert_limited(
        blocked.status,
        &blocked.headers,
        "a password change after five wrong current passwords",
    );

    let mut w = World::start().await;
    w.tighten(|c| {
        roomy(c);
        c.limits.dcr_per_hour = 3;
    })
    .await;
    let from = "192.0.2.32";
    let body = json!({"client_name": "X", "redirect_uris": [LOCAL_8787]}).to_string();
    for n in 1..=3 {
        let page = send_from(&w, from, "/oauth/register", JSON_TYPE, body.clone()).await;
        assert_eq!(
            page.status, 201,
            "registration {n} of three must be allowed"
        );
    }
    let limited = send_from(&w, from, "/oauth/register", JSON_TYPE, body).await;
    assert_limited(
        limited.status,
        &limited.headers,
        "a registration over the per-address limit",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_limit_is_a_setting() {
    let pairs = [
        ("DOORWARD_LIMITS_GENERAL_BURST", "limits.general_burst"),
        (
            "DOORWARD_LIMITS_GENERAL_PER_MINUTE",
            "limits.general_per_minute",
        ),
        ("DOORWARD_LIMITS_OAUTH_BURST", "limits.oauth_burst"),
        (
            "DOORWARD_LIMITS_OAUTH_PER_MINUTE",
            "limits.oauth_per_minute",
        ),
        (
            "DOORWARD_LIMITS_CREDENTIALS_BURST",
            "limits.credentials_burst",
        ),
        (
            "DOORWARD_LIMITS_CREDENTIALS_PER_MINUTE",
            "limits.credentials_per_minute",
        ),
        ("DOORWARD_LIMITS_MCP_BURST", "limits.mcp_burst"),
        ("DOORWARD_LIMITS_MCP_PER_MINUTE", "limits.mcp_per_minute"),
        ("DOORWARD_LIMITS_MCP_OPEN", "limits.mcp_open"),
        ("DOORWARD_LIMITS_RATE_TABLE_KEYS", "limits.rate_table_keys"),
    ];
    for (variable, path) in pairs {
        assert!(
            SETTINGS
                .iter()
                .any(|setting| setting.variable == variable && setting.path == path),
            "{variable} must be a setting for {path}"
        );
    }

    let mut w = World::start().await;
    w.tighten(|c| {
        trust_loopback(c);
        c.limits.general_burst = 1;
    })
    .await;
    let browser = w.client();
    let from = "192.0.2.40";
    let first = get_from(&browser, from, "/nothing-here").await;
    assert_answered(first.status, "the first request with burst 1");
    let second = get_from(&browser, from, "/nothing-here").await;
    assert_limited(
        second.status,
        &second.headers,
        "the second request with burst 1",
    );
}

/// Renames the settings table from `from` to `to`; a read of it fails while it has the old name.
fn rename_settings(w: &World, from: &str, to: &str) {
    let conn = Connection::open(w.gw.db_path()).expect("the gateway database opens");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("set the busy timeout");
    conn.execute_batch(&format!("ALTER TABLE {from} RENAME TO {to};"))
        .expect("rename the settings table");
}

#[tokio::test(flavor = "multi_thread")]
async fn health_is_counted_for_a_caller_that_is_not_local() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let browser = w.client();
    let from = "192.0.2.10";
    for n in 1..=2 {
        let page = get_from(&browser, from, "/healthz").await;
        assert_eq!(
            page.status, 200,
            "health request {n} from the caller must be answered"
        );
    }
    let page = get_from(&browser, from, "/healthz").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third health request from the caller",
    );
    assert_eq!(
        page.json(),
        Some(json!({
            "error": "too_many_requests",
            "error_description": "Too many requests. Try again later.",
        })),
        "a limited health request must answer the too_many_requests JSON"
    );
    rename_settings(&w, "settings", "settings_hidden");
    let page = get_from(&browser, from, "/healthz").await;
    rename_settings(&w, "settings_hidden", "settings");
    assert_limited(
        page.status,
        &page.headers,
        "a health request over the limit while the settings cannot be read",
    );
    let page = get_from(&browser, "192.0.2.20", "/healthz").await;
    assert_eq!(
        page.status, 200,
        "the first health request from another address must be answered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_with_a_forwarded_header_from_the_host_is_counted() {
    let mut w = World::start().await;
    w.tighten(|c| c.limits.general_burst = 2).await;
    let browser = w.client();
    let from = "192.0.2.60";
    for n in 1..=2 {
        let page = get_from(&browser, from, "/healthz").await;
        assert_eq!(
            page.status, 200,
            "health request {n} with a forwarded header from the host must be answered"
        );
    }
    let page = get_from(&browser, from, "/healthz").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third health request with a forwarded header from the host",
    );
    assert_eq!(
        page.json(),
        Some(json!({
            "error": "too_many_requests",
            "error_description": "Too many requests. Try again later.",
        })),
        "a limited health request with a forwarded header must answer the too_many_requests JSON"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_from_the_host_itself_is_never_limited() {
    let mut w = World::start().await;
    tight(&mut w, |_| {}).await;
    let browser = w.client();
    for n in 1..=6 {
        let page = browser.get("/healthz").await;
        assert_eq!(
            page.status, 200,
            "health request {n} from the host itself must be answered"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_on_authorize_is_limited_at_the_same_count_as_a_get() {
    let mut w = World::start().await;
    w.tighten(|c| {
        trust_loopback(c);
        c.limits.oauth_burst = 2;
        c.limits.general_burst = 50;
    })
    .await;
    let browser = w.client();

    let by_get = "192.0.2.50";
    for n in 1..=2 {
        let page = get_from(&browser, by_get, "/oauth/authorize").await;
        assert_answered(page.status, &format!("GET authorize {n}"));
    }
    let page = head_from(&w, by_get, "/oauth/authorize").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third request to authorize, a HEAD after two GETs",
    );

    let by_head = "192.0.2.51";
    for n in 1..=2 {
        let page = head_from(&w, by_head, "/oauth/authorize").await;
        assert_answered(page.status, &format!("HEAD authorize {n}"));
    }
    let page = get_from(&browser, by_head, "/oauth/authorize").await;
    assert_limited(
        page.status,
        &page.headers,
        "the third request to authorize, a GET after two HEADs",
    );
}
