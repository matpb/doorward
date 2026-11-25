//! The combined endpoint's own methods and tools/list, over a fixture gateway and scripted upstreams.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use rusqlite::params;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::catalog;
use super::combined::{NOTES, handle, split};
use super::tests::{Fixture, Plan, Seen, TestUpstream, answer, fixture, fixture_with};
use crate::app::AppState;
use crate::config::Lifetimes;
use crate::crypto::token_hash;
use crate::oauth::families::{self, NewFamily};
use crate::oauth::guard::Caller;

const CLOSED: &str = "http://127.0.0.1:9/mcp";

/// A user row with the given id, assigned to the given servers.
async fn user(state: &AppState, id: i64, servers: Vec<i64>) {
    state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO users (id, email, password_hash, role, created_at) \
                 VALUES (?1, ?2, 'hash', 'user', 0)",
                params![id, format!("user{id}@example.com")],
            )?;
            for server in servers {
                conn.execute(
                    "INSERT INTO user_servers (user_id, server_id) VALUES (?1, ?2)",
                    params![id, server],
                )?;
            }
            Ok(())
        })
        .await
        .expect("user");
}

/// A server row with a new slug that points at `url`.
async fn server(state: &AppState, slug: &str, url: &str) -> i64 {
    let (slug, url) = (slug.to_owned(), url.to_owned());
    state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO servers (name, slug, upstream_url, created_at) VALUES (?1, ?1, ?2, 0)",
                params![slug, url],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .expect("server")
}

/// Points the fixture's own server at `url`.
async fn point(fx: &Fixture, url: &str) {
    let (id, url) = (fx.server_id, url.to_owned());
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
                params![url, id],
            )
        })
        .await
        .expect("point the server");
}

/// The caller of a user, as the bearer check gives it.
fn caller(user_id: i64) -> Caller {
    Caller {
        user_id,
        user_email: format!("user{user_id}@example.com"),
        family_id: user_id + 100,
        server_id: None,
        client_name: "test client".to_owned(),
        token_hash: "hash".to_owned(),
        admitted: 0,
        values_version: 0,
    }
}

/// A POST to `/mcp` with the given headers and body text.
fn request_of(method: &str, headers: &[(&str, &str)], body: Option<String>) -> Request {
    let mut builder = Request::builder().method(method).uri("/mcp");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body.map_or_else(Body::empty, Body::from);
    builder.body(body).expect("request")
}

/// What the combined endpoint answered.
struct Reply {
    status: u16,
    headers: HeaderMap,
    text: String,
    json: Option<Value>,
}

async fn send(
    state: &AppState,
    user_id: i64,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Reply {
    let body = body.map(|value| value.to_string());
    send_text(state, caller(user_id), method, headers, body).await
}

/// One request to `/mcp` as `caller`, with the body text exactly as given.
async fn send_text(
    state: &AppState,
    caller: Caller,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<String>,
) -> Reply {
    let request = request_of(method, headers, body);
    let response: Response = handle(state, caller, request).await;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1 << 22)
        .await
        .expect("the answer body");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let json = serde_json::from_str(&text).ok();
    Reply {
        status,
        headers,
        text,
        json,
    }
}

/// A session-style tools/list, with no version header.
async fn list(state: &AppState, user_id: i64) -> Reply {
    send(
        state,
        user_id,
        "POST",
        &[],
        Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
    )
    .await
}

/// The tool names of a list answer, which must be a 200 with a tools array.
fn names(reply: &Reply) -> Vec<String> {
    assert_eq!(
        reply.status, 200,
        "the list must answer 200: {}",
        reply.text
    );
    reply
        .json
        .as_ref()
        .and_then(|json| json["result"]["tools"].as_array())
        .expect("a tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

fn tool(name: &str) -> Value {
    json!({"name": name, "inputSchema": {"type": "object"}})
}

fn discover() -> Value {
    json!({
        "supportedVersions": ["2026-07-28"],
        "capabilities": {"tools": {}},
        "cacheScope": "public",
        "resultType": "complete",
    })
}

/// The JSON-RPC result answer to the request of `seen`.
fn reply_to(seen: &Seen, result: Value) -> Plan {
    let id = seen.json()["id"].clone();
    answer(
        200,
        None,
        Some("application/json"),
        &json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
    )
}

/// A stateless upstream: server/discover has a result and tools/list answers `tools`.
async fn stateless_up(tools: Vec<Value>) -> TestUpstream {
    TestUpstream::start(move |seen: &Seen| match seen.rpc().as_str() {
        "server/discover" => reply_to(seen, discover()),
        "tools/list" => reply_to(seen, json!({"tools": tools.clone()})),
        _ => reply_to(seen, json!({})),
    })
    .await
}

/// A stateless upstream whose tools/list never answers.
async fn hanging_up() -> TestUpstream {
    TestUpstream::start(|seen: &Seen| match seen.rpc().as_str() {
        "tools/list" => Plan::Silent,
        _ => reply_to(seen, discover()),
    })
    .await
}

/// A session-style upstream: refuses the stateless form, issues session s1 on initialize, lists `tools`.
async fn session_up(tools: Vec<Value>) -> TestUpstream {
    TestUpstream::start(move |seen: &Seen| {
        if seen.method == "DELETE" {
            return answer(200, None, None, "");
        }
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        let id = seen.json()["id"].clone();
        match seen.rpc().as_str() {
            "initialize" => answer(
                200,
                Some("s1"),
                Some("application/json"),
                &rpc_text(
                    &id,
                    json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
                ),
            ),
            _ if seen.header("mcp-session-id") != Some("s1") => answer(400, None, None, ""),
            "notifications/initialized" => answer(202, None, None, ""),
            "tools/list" => answer(
                200,
                None,
                Some("application/json"),
                &rpc_text(&id, json!({"tools": tools.clone()})),
            ),
            _ => answer(404, None, None, ""),
        }
    })
    .await
}

/// The JSON-RPC result text with the given id.
fn rpc_text(id: &Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

/// A tool with a 1900 byte description, so its page is about 2 KB.
fn padded(name: &str) -> Value {
    json!({"name": name, "description": "x".repeat(1900), "inputSchema": {"type": "object"}})
}

/// The catalog_error text of a server.
async fn catalog_error(state: &AppState, server_id: i64) -> Option<String> {
    state
        .db
        .call(move |conn| {
            conn.query_row(
                "SELECT catalog_error FROM servers WHERE id = ?1",
                params![server_id],
                |row| row.get(0),
            )
        })
        .await
        .expect("the catalog error")
}

/// The stored catalog time of a server and the number of tool_appeared rows.
async fn stored(state: &AppState, server_id: i64) -> (Option<i64>, i64) {
    state
        .db
        .call(move |conn| {
            let at = conn.query_row(
                "SELECT catalog_at FROM servers WHERE id = ?1",
                params![server_id],
                |row| row.get(0),
            )?;
            let appeared = conn.query_row(
                "SELECT COUNT(*) FROM activity WHERE kind = 'tool_appeared'",
                [],
                |row| row.get(0),
            )?;
            Ok((at, appeared))
        })
        .await
        .expect("the stored catalog")
}

#[tokio::test(flavor = "multi_thread")]
async fn replace_writes_nothing_when_the_tools_are_unchanged() {
    let fx = fixture().await;
    let id = fx.server_id;
    let first = vec![tool("echo"), tool("search")];
    let (state, first_copy) = (fx.state.clone(), first.clone());
    state
        .db
        .call(move |conn| catalog::replace(conn, id, &first_copy, 100))
        .await
        .expect("the first replace");
    let before = stored(&fx.state, id).await;
    let (state, same) = (fx.state.clone(), first);
    let added = state
        .db
        .call(move |conn| catalog::replace(conn, id, &same, 200))
        .await
        .expect("the unchanged replace");
    assert!(added.is_empty(), "no name is new when nothing changed");
    assert_eq!(
        stored(&fx.state, id).await,
        before,
        "unchanged tools must write nothing: catalog_at and tool_appeared rows keep their values"
    );
    let changed = vec![
        tool("echo"),
        json!({"name": "search", "description": "changed", "inputSchema": {"type": "object"}}),
    ];
    let state = fx.state.clone();
    state
        .db
        .call(move |conn| catalog::replace(conn, id, &changed, 300))
        .await
        .expect("the changed replace");
    assert_eq!(
        stored(&fx.state, id).await.0,
        Some(300),
        "a changed definition must be written at the new time"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_listed_twice_or_too_long_for_its_merged_name_lists_once() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo"), tool("echo"), tool(&"é".repeat(100))]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["demo__echo"],
        "a duplicate name lists once and a 200 character name is left out"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn names_that_are_not_plain_are_absent_and_not_logged() {
    let fx = fixture().await;
    let up = stateless_up(vec![
        tool("a b"),
        tool("béta"),
        tool("e\u{200b}cho"),
        tool("x\ny"),
        tool("ok"),
    ])
    .await;
    let logged = server(&fx.state, "logged", &up.url).await;
    user(&fx.state, 1, vec![logged]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["logged__ok"],
        "only the plain name is listed"
    );
    let notes: Vec<String> = NOTES
        .lock()
        .expect("notes")
        .iter()
        .filter(|line| line.contains("logged"))
        .cloned()
        .collect();
    for bad in ["a b", "béta", "e\u{200b}cho", "x\ny"] {
        assert!(
            notes.iter().all(|line| !line.contains(bad)),
            "the log must not name {bad:?}, got {notes:?}"
        );
    }
    assert!(
        notes
            .iter()
            .any(|line| line == "tools/list: logged left 2 tool(s) out"),
        "the list counts the two names the catalog kept and it leaves out, got {notes:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_upstream_tool_with_an_mcp_header_key_is_absent() {
    let fx = fixture().await;
    let headed = json!({
        "name": "headed",
        "inputSchema": {"type": "object", "properties": {"tenant": {"x-mcp-header": "Tenant"}}},
    });
    let up = stateless_up(vec![tool("plain"), headed]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["demo__plain"],
        "a tool with an x-mcp-header key must be left out of a stateless link's list"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hung_server_is_left_out_and_the_other_answers_in_time() {
    let fx = fixture().await;
    let hung = hanging_up().await;
    let fine = stateless_up(vec![tool("alpha")]).await;
    let hung_id = server(&fx.state, "hung", &hung.url).await;
    let fine_id = server(&fx.state, "fine", &fine.url).await;
    user(&fx.state, 1, vec![hung_id, fine_id]).await;
    let started = Instant::now();
    let reply = list(&fx.state, 1).await;
    assert!(
        started.elapsed() < Duration::from_secs(11),
        "the list must answer within 11 seconds, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        names(&reply),
        vec!["fine__alpha"],
        "the answering server's tools must be listed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_assigned_server_down_is_502_and_no_server_is_an_empty_list() {
    let fx = fixture().await;
    let down = server(&fx.state, "down", CLOSED).await;
    let gone = server(&fx.state, "gone", CLOSED).await;
    user(&fx.state, 1, vec![down, gone]).await;
    let reply = list(&fx.state, 1).await;
    assert_eq!(
        reply.status, 502,
        "every assigned server down must answer 502"
    );
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32000, "message": "Upstream mcp is unavailable"},
        })),
        "the 502 must name the combined endpoint as unavailable"
    );
    user(&fx.state, 2, Vec::new()).await;
    assert_eq!(
        names(&list(&fx.state, 2).await),
        Vec::<String>::new(),
        "a user with no servers must get an empty list"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_size_rule_leaves_out_the_large_server() {
    let fx = fixture_with(|config| config.limits.tools_list_bytes = 4000).await;
    // The listed entry of "aaa__big" is 3955 bytes: alone it fits 4000, with a small server it does not.
    let entry = |description: &str| {
        json!({"name": "aaa__big", "description": description, "inputSchema": {"type": "object"}})
            .to_string()
            .len()
    };
    let big = json!({
        "name": "big",
        "description": "d".repeat(3955 - entry("")),
        "inputSchema": {"type": "object"},
    });
    let raw = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [big.clone()]}}).to_string();
    assert!(
        raw.len() <= 4000,
        "the large upstream's answer must fit the cap"
    );
    let large = stateless_up(vec![big]).await;
    let bbb = stateless_up(vec![tool("s1")]).await;
    let ccc = stateless_up(vec![tool("s2")]).await;
    let aaa_id = server(&fx.state, "aaa", &large.url).await;
    let bbb_id = server(&fx.state, "bbb", &bbb.url).await;
    let ccc_id = server(&fx.state, "ccc", &ccc.url).await;
    user(&fx.state, 1, vec![aaa_id, bbb_id, ccc_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["bbb__s1", "ccc__s2"],
        "the two small servers are listed and the large one is left out"
    );
    let logged = NOTES
        .lock()
        .expect("notes")
        .iter()
        .any(|line| line == "tools/list: aaa left out, its tools are over the size limit");
    assert!(
        logged,
        "the left out server is logged as over the size limit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_lists_of_one_user_run_one_at_a_time() {
    let fx = fixture().await;
    let (url, peak) = peak_upstream(vec![tool("echo")]).await;
    point(&fx, &url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let (first, second) = tokio::join!(list(&fx.state, 1), list(&fx.state, 1));
    assert_eq!(names(&first), vec!["demo__echo"], "the first list answers");
    assert_eq!(
        names(&second),
        vec!["demo__echo"],
        "the second list answers"
    );
    assert_eq!(
        peak.most.load(Ordering::SeqCst),
        1,
        "the upstream must see at most one tools/list in flight for one user"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rules_read_that_fails_is_500_and_no_tool_is_listed() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    fx.state
        .db
        .call(|conn| conn.execute_batch("DROP TABLE rules"))
        .await
        .expect("drop the rules table");
    let reply = list(&fx.state, 1).await;
    assert_eq!(reply.status, 500, "a rules read that fails must answer 500");
    assert!(
        !reply.text.contains("echo"),
        "no tool may be listed when the rules cannot be read"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_id_is_404_and_get_or_delete_is_405() {
    let fx = fixture().await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let with_session = send(
        &fx.state,
        1,
        "POST",
        &[("mcp-session-id", "abc")],
        Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
    )
    .await;
    assert_eq!(
        with_session.status, 404,
        "a request carrying Mcp-Session-Id must be answered 404"
    );
    let get = send(&fx.state, 1, "GET", &[], None).await;
    assert_eq!(get.status, 405, "GET on /mcp must be answered 405");
    assert_eq!(
        get.headers
            .get("allow")
            .and_then(|value| value.to_str().ok()),
        Some("POST"),
        "the 405 names POST as the one allowed method"
    );
    let delete = send(&fx.state, 1, "DELETE", &[], None).await;
    assert_eq!(delete.status, 405, "DELETE on /mcp must be answered 405");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_list_that_waited_for_its_turn_still_has_its_full_deadline() {
    let fx = fixture_with(|config| config.limits.upstream_timeout_seconds = 1).await;
    let up = TestUpstream::start(|seen: &Seen| match seen.rpc().as_str() {
        "tools/list" => match reply_to(seen, json!({"tools": [tool("echo")]})) {
            Plan::Reply(response) => Plan::Late(Duration::from_millis(700), response),
            other => other,
        },
        _ => reply_to(seen, discover()),
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let (first, second) = tokio::join!(list(&fx.state, 1), list(&fx.state, 1));
    assert_eq!(names(&first), vec!["demo__echo"], "the first list answers");
    assert_eq!(
        names(&second),
        vec!["demo__echo"],
        "the list that waited for its turn answers with the tool"
    );
    let id = fx.server_id;
    let error: Option<String> = fx
        .state
        .db
        .call(move |conn| {
            conn.query_row(
                "SELECT catalog_error FROM servers WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
        })
        .await
        .expect("catalog error");
    assert_eq!(
        error, None,
        "no refresh may fail because of the wait for the turn"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_is_refused() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let reply = send(
        &fx.state,
        1,
        "POST",
        &[],
        Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"cursor": "x"}})),
    )
    .await;
    assert_eq!(
        reply.status, 200,
        "a refused cursor is answered in the JSON-RPC body"
    );
    assert_eq!(
        reply
            .json
            .as_ref()
            .and_then(|json| json["error"]["code"].as_i64()),
        Some(-32602),
        "a non-null cursor must be refused with -32602"
    );
    assert!(
        up.seen().iter().all(|seen| seen.rpc() != "tools/list"),
        "the upstream must see no tools/list for a refused cursor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_sent_response_is_refused() {
    let fx = fixture().await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let reply = send(
        &fx.state,
        1,
        "POST",
        &[],
        Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
    )
    .await;
    assert_eq!(
        reply.status, 400,
        "a client-sent response must be refused with 400"
    );
    assert_eq!(
        reply
            .json
            .as_ref()
            .and_then(|json| json["error"]["code"].as_i64()),
        Some(-32600),
        "a client-sent response must carry -32600"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_carry_the_inert_headers_and_no_session_id() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let init = send(
        &fx.state,
        1,
        "POST",
        &[],
        Some(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            }}),
        ),
    )
    .await;
    assert_eq!(init.status, 200, "initialize must be answered 200");
    let listed = list(&fx.state, 1).await;
    assert_eq!(listed.status, 200, "tools/list must be answered 200");
    for (method, reply) in [("initialize", &init), ("tools/list", &listed)] {
        let header = |name: &str| {
            reply
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
        };
        assert_eq!(
            header("x-content-type-options"),
            Some("nosniff"),
            "{method} must carry nosniff"
        );
        assert_eq!(
            header("content-security-policy"),
            Some("sandbox"),
            "{method} must carry the sandbox policy"
        );
        assert_eq!(
            header("content-type"),
            Some("application/json"),
            "{method} must be application/json"
        );
        assert_eq!(
            header("mcp-session-id"),
            None,
            "{method} must carry no session id"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_the_rules_refuse_is_absent() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("keep"), tool("drop")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let id = fx.server_id;
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO rules (user_id, effect, server_id, tool, created_at) \
                 VALUES (1, 'deny', ?1, 'drop', 0)",
                params![id],
            )
        })
        .await
        .expect("the deny rule");
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["demo__keep"],
        "a tool the user's rules refuse must be absent, the other present"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_assigned_to_another_user_is_not_listed() {
    let fx = fixture().await;
    let alpha = stateless_up(vec![tool("t")]).await;
    let beta = stateless_up(vec![tool("t")]).await;
    let alpha_id = server(&fx.state, "alpha", &alpha.url).await;
    let beta_id = server(&fx.state, "beta", &beta.url).await;
    user(&fx.state, 1, vec![alpha_id]).await;
    user(&fx.state, 2, vec![beta_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["alpha__t"],
        "user 1 must list only the server assigned to user 1"
    );
    assert_eq!(
        names(&list(&fx.state, 2).await),
        vec!["beta__t"],
        "user 2 must list only the server assigned to user 2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_with_a_dot_a_dash_and_an_underscore_is_listed() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("a.b-c_d9")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["demo__a.b-c_d9"],
        "dots, dashes and underscores are plain name characters"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_merged_name_of_128_bytes_is_listed_and_129_is_not() {
    let fx = fixture().await;
    // "demo__" is 6 bytes, so 122 more make the merged name 128 bytes and 123 make it 129.
    let longest = "a".repeat(122);
    let too_long = "b".repeat(123);
    let up = stateless_up(vec![tool(&too_long), tool(&longest)]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let merged = format!("demo__{longest}");
    assert_eq!(merged.len(), 128, "the merged name must be 128 bytes");
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec![merged],
        "a merged name of 128 bytes is listed and one of 129 bytes is left out"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_upstream_tool_with_an_mcp_header_key_is_listed() {
    let fx = fixture().await;
    let headed = json!({
        "name": "headed",
        "inputSchema": {"type": "object", "properties": {"tenant": {"x-mcp-header": "Tenant"}}},
    });
    let up = session_up(vec![tool("plain"), headed]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["demo__plain", "demo__headed"],
        "a tool with an x-mcp-header key is listed over a session link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_server_gets_a_failed_refresh_record_and_a_healthy_one_does_not() {
    let fx = fixture().await;
    let healthy = stateless_up(vec![tool("echo")]).await;
    let bad = server(&fx.state, "bad", CLOSED).await;
    let good = server(&fx.state, "good", &healthy.url).await;
    user(&fx.state, 1, vec![bad, good]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["good__echo"],
        "the answering server's tools are listed"
    );
    assert_eq!(
        catalog_error(&fx.state, bad).await,
        Some("The last refresh failed: the upstream did not answer with a tool list.".to_owned()),
        "the server that did not answer records its failed refresh"
    );
    assert_eq!(
        catalog_error(&fx.state, good).await,
        None,
        "the answering server records no failed refresh"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_that_together_pass_the_size_limit_leave_the_server_out() {
    let fx = fixture_with(|config| config.limits.tools_list_bytes = 4000).await;
    // Page one is about 2030 bytes and page two about 2010: each fits 4000, both together do not.
    let paged = TestUpstream::start(|seen: &Seen| match seen.rpc().as_str() {
        "server/discover" => reply_to(seen, discover()),
        "tools/list" if seen.json()["params"]["cursor"] == "next" => {
            reply_to(seen, json!({"tools": [padded("two")]}))
        }
        "tools/list" => reply_to(
            seen,
            json!({"tools": [padded("one")], "nextCursor": "next"}),
        ),
        _ => reply_to(seen, json!({})),
    })
    .await;
    point(&fx, &paged.url).await;
    let small = stateless_up(vec![tool("s1")]).await;
    let small_id = server(&fx.state, "bbb", &small.url).await;
    user(&fx.state, 1, vec![fx.server_id, small_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["bbb__s1"],
        "the server whose pages pass the limit together is left out"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_next_cursor_that_is_not_a_string_leaves_the_server_out() {
    let fx = fixture().await;
    let odd = TestUpstream::start(|seen: &Seen| match seen.rpc().as_str() {
        "server/discover" => reply_to(seen, discover()),
        "tools/list" => reply_to(seen, json!({"tools": [tool("one")], "nextCursor": 5})),
        _ => reply_to(seen, json!({})),
    })
    .await;
    point(&fx, &odd.url).await;
    let healthy = stateless_up(vec![tool("s1")]).await;
    let healthy_id = server(&fx.state, "bbb", &healthy.url).await;
    user(&fx.state, 1, vec![fx.server_id, healthy_id]).await;
    assert_eq!(
        names(&list(&fx.state, 1).await),
        vec!["bbb__s1"],
        "a server whose nextCursor is not a string is left out, the healthy one answers"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_and_ping_follow_the_generation() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let session_list = list(&fx.state, 1).await;
    assert_eq!(
        session_list
            .json
            .as_ref()
            .map(|json| json["result"].clone()),
        Some(json!({"tools": [{"name": "demo__echo", "inputSchema": {"type": "object"}}]})),
        "a session tools/list answers its tools array and nothing else"
    );
    let stateless_list = send(
        &fx.state,
        1,
        "POST",
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/list"),
        ],
        Some(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}})),
    )
    .await;
    assert_eq!(stateless_list.status, 200, "the stateless list must be 200");
    assert_eq!(
        stateless_list
            .json
            .as_ref()
            .map(|json| json["result"].clone()),
        Some(json!({
            "tools": [{"name": "demo__echo", "inputSchema": {"type": "object"}}],
            "resultType": "complete",
            "ttlMs": 60000,
            "cacheScope": "private",
        })),
        "a stateless tools/list carries resultType, ttlMs and cacheScope"
    );
    let ping = send(
        &fx.state,
        1,
        "POST",
        &[],
        Some(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})),
    )
    .await;
    assert_eq!(
        ping.json,
        Some(json!({"jsonrpc": "2.0", "id": 3, "result": {}})),
        "a session ping answers an empty result"
    );
    let stateless_ping = send(
        &fx.state,
        1,
        "POST",
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "ping"),
        ],
        Some(json!({"jsonrpc": "2.0", "id": 4, "method": "ping",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}}})),
    )
    .await;
    assert_eq!(stateless_ping.status, 404, "the stateless ping must be 404");
    assert_eq!(
        stateless_ping.json,
        Some(
            json!({"jsonrpc": "2.0", "id": 4, "error": {"code": -32601, "message": "Method not found"}})
        ),
        "a stateless ping is not answered with a result"
    );
}

/// A stateless upstream that holds each tools/list for 200 ms and records the most in flight at once.
struct Peak {
    now: AtomicUsize,
    most: AtomicUsize,
}

type PeakState = (Arc<Peak>, Arc<Vec<Value>>);

async fn peak_upstream(tools: Vec<Value>) -> (String, Arc<Peak>) {
    let peak = Arc::new(Peak {
        now: AtomicUsize::new(0),
        most: AtomicUsize::new(0),
    });
    let state: PeakState = (Arc::clone(&peak), Arc::new(tools));
    let app = Router::new()
        .route("/mcp", post(peak_answer))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (format!("http://{address}/mcp"), peak)
}

async fn peak_answer(State((peak, tools)): State<PeakState>, body: Bytes) -> Response {
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let result = match request["method"].as_str() {
        Some("tools/list") => {
            let now = peak.now.fetch_add(1, Ordering::SeqCst) + 1;
            peak.most.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(200)).await;
            peak.now.fetch_sub(1, Ordering::SeqCst);
            json!({"tools": tools.as_ref()})
        }
        _ => discover(),
    };
    Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result})).into_response()
}

/// A combined token family of `user_id` in the database, and the caller its access token gives.
async fn combined_caller(state: &AppState, user_id: i64) -> Caller {
    let now = state.clock.now().unix_timestamp();
    let (family_id, access) = state
        .db
        .call(move |conn| {
            let epoch: i64 = conn.query_row(
                "SELECT auth_epoch FROM users WHERE id = ?1",
                params![user_id],
                |row| row.get(0),
            )?;
            let new = NewFamily {
                user_id,
                server_id: None,
                client_id: "dcr_test",
                client_name: "test client",
                auth_epoch: epoch,
            };
            let family_id = families::create(conn, &new, now, 90)?;
            let pair = families::mint_pair(conn, family_id, now, &Lifetimes::default())?;
            Ok((family_id, pair.access_token))
        })
        .await
        .expect("a combined token");
    Caller {
        user_id,
        user_email: format!("user{user_id}@example.com"),
        family_id,
        server_id: None,
        client_name: "test client".to_owned(),
        token_hash: token_hash(&access),
        admitted: now,
        values_version: 0,
    }
}

/// Another caller of the same family as `caller`, so both calls share one upstream link.
fn same_family(caller: &Caller) -> Caller {
    Caller {
        user_id: caller.user_id,
        user_email: caller.user_email.clone(),
        family_id: caller.family_id,
        server_id: None,
        client_name: caller.client_name.clone(),
        token_hash: caller.token_hash.clone(),
        admitted: caller.admitted,
        values_version: caller.values_version,
    }
}

/// One tool_call activity row.
#[derive(Debug, PartialEq)]
struct CallRow {
    user: Option<i64>,
    server: Option<i64>,
    slug: String,
    tool: String,
    decision: String,
    outcome: String,
    detail: String,
}

/// The tool_call rows, oldest first.
async fn call_rows(state: &AppState) -> Vec<CallRow> {
    state
        .db
        .call(|conn| {
            let mut statement = conn.prepare(
                "SELECT user_id, server_id, server_slug, tool, decision, outcome, detail \
                 FROM activity WHERE kind = 'tool_call' ORDER BY id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(CallRow {
                    user: row.get(0)?,
                    server: row.get(1)?,
                    slug: row.get(2)?,
                    tool: row.get(3)?,
                    decision: row.get(4)?,
                    outcome: row.get(5)?,
                    detail: row.get(6)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<CallRow>>>()
        })
        .await
        .expect("the activity rows")
}

/// The tool_call rows, polled for up to 3 seconds until there are `wanted` of them.
async fn wait_for_rows(state: &AppState, wanted: usize) -> Vec<CallRow> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let rows = call_rows(state).await;
        if rows.len() >= wanted || Instant::now() >= deadline {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The requests of `up` that were tools/call.
fn calls(up: &TestUpstream) -> Vec<Seen> {
    up.seen()
        .into_iter()
        .filter(|seen| seen.rpc() == "tools/call")
        .collect()
}

/// How many requests of `up` carried the JSON-RPC `method`.
fn rpc_count(up: &TestUpstream, method: &str) -> usize {
    up.seen().iter().filter(|seen| seen.rpc() == method).count()
}

/// The answer that names the tool it was called with, sent at once.
fn echo_text(seen: &Seen) -> Plan {
    let name = seen.json()["params"]["name"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    reply_to(
        seen,
        json!({"content": [{"type": "text", "text": format!("called: {name}")}]}),
    )
}

/// The answer of `echo_text`, sent after `wait`.
fn echo_after(seen: &Seen, wait: Duration) -> Plan {
    match echo_text(seen) {
        Plan::Reply(response) => Plan::Late(wait, response),
        other => other,
    }
}

/// A stateless upstream: server/discover, `tools` as its list, and `call` as its answer to tools/call.
async fn stateless_with(
    tools: Vec<Value>,
    call: impl Fn(&Seen) -> Plan + Send + Sync + 'static,
) -> TestUpstream {
    TestUpstream::start(move |seen: &Seen| match seen.rpc().as_str() {
        "server/discover" => reply_to(seen, discover()),
        "tools/list" => reply_to(seen, json!({"tools": tools.clone()})),
        "tools/call" => call(seen),
        _ => reply_to(seen, json!({})),
    })
    .await
}

/// A session upstream whose list is read from `tools` at each request; tools/call answers with the name.
/// Each initialize gets a new session id, as a real upstream gives one.
async fn session_shared(tools: Arc<Mutex<Vec<Value>>>) -> TestUpstream {
    let issued = Arc::new(AtomicUsize::new(0));
    TestUpstream::start(move |seen: &Seen| {
        if seen.method == "DELETE" {
            return answer(200, None, None, "");
        }
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        let id = seen.json()["id"].clone();
        match seen.rpc().as_str() {
            "initialize" => {
                let session = format!("s{}", issued.fetch_add(1, Ordering::SeqCst) + 1);
                answer(
                    200,
                    Some(&session),
                    Some("application/json"),
                    &rpc_text(
                        &id,
                        json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
                    ),
                )
            }
            _ if !seen
                .header("mcp-session-id")
                .is_some_and(|id| id.starts_with('s')) =>
            {
                answer(400, None, None, "")
            }
            "notifications/initialized" => answer(202, None, None, ""),
            "tools/list" => {
                let listed = tools.lock().expect("the tool list").clone();
                answer(
                    200,
                    None,
                    Some("application/json"),
                    &rpc_text(&id, json!({"tools": listed})),
                )
            }
            "tools/call" => echo_text(seen),
            _ => answer(404, None, None, ""),
        }
    })
    .await
}

/// A session-style tools/call body for `name` with empty arguments.
fn call_body(id: i64, name: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": {}}})
        .to_string()
}

/// The same call as a stateless client sends it: the version in `_meta`.
fn stateless_call_body(id: i64, name: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": name,
        "arguments": {},
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}},
    }})
    .to_string()
}

/// The text of the first content item of a call answer.
fn call_text(reply: &Reply) -> Option<&str> {
    reply
        .json
        .as_ref()?
        .get("result")?
        .get("content")?
        .get(0)?
        .get("text")?
        .as_str()
}

/// Removes the assignment of `user_id` to `server_id`.
async fn unassign(state: &AppState, user_id: i64, server_id: i64) {
    state
        .db
        .call(move |conn| {
            conn.execute(
                "DELETE FROM user_servers WHERE user_id = ?1 AND server_id = ?2",
                params![user_id, server_id],
            )
        })
        .await
        .expect("the unassignment");
}

#[test]
fn split_takes_the_first_double_underscore_and_refuses_the_rest() {
    assert_eq!(split("a__b__c"), Some(("a", "b__c")));
    assert_eq!(split("a___echo"), Some(("a", "_echo")));
    assert_eq!(split("echo"), None);
    assert_eq!(split("__echo"), None);
    assert_eq!(split("a__"), None);
    assert_eq!(split("A__echo"), None);
    assert_eq!(split("a__b c"), None);
    let longest = format!("a__{}", "x".repeat(125));
    assert_eq!(longest.len(), 128);
    assert_eq!(split(&longest), Some(("a", &longest[3..])));
    let too_long = format!("a__{}", "x".repeat(126));
    assert_eq!(too_long.len(), 129);
    assert_eq!(split(&too_long), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_refusal_answers_the_same_and_writes_one_deny_row() {
    let fx = fixture().await;
    let hidden =
        json!({"name": "hidden", "inputSchema": {"type": "object", "x-mcp-header": "Region"}});
    let up = stateless_with(vec![tool("echo"), tool("denied"), hidden], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let other = server(&fx.state, "other", CLOSED).await;
    let demo = fx.server_id;
    fx.state
        .db
        .call(move |conn| {
            conn.execute(
                "INSERT INTO rules (user_id, effect, server_id, tool, created_at) \
                 VALUES (1, 'deny', ?1, 'denied', 0)",
                params![demo],
            )
        })
        .await
        .expect("the deny rule");
    let rule_id: i64 = fx
        .state
        .db
        .call(|conn| {
            conn.query_row("SELECT id FROM rules WHERE tool = 'denied'", [], |row| {
                row.get(0)
            })
        })
        .await
        .expect("the rule id");
    let denied = format!("rule {rule_id}");
    let missing = "not in the tool list";
    let headers = "the request headers do not match the call";
    let unassigned = "the server is not assigned";
    let cases: [(&str, Option<i64>, &str, &str, &str); 6] = [
        ("echo", None, "mcp", "echo", missing),
        ("nope__echo", None, "mcp", "nope__echo", missing),
        ("other__echo", Some(other), "other", "echo", unassigned),
        ("demo__missing", Some(demo), "demo", "missing", missing),
        ("demo__denied", Some(demo), "demo", "denied", &denied),
        ("demo__hidden", Some(demo), "demo", "hidden", headers),
    ];
    for (index, (name, server_id, slug, tool_name, detail)) in cases.into_iter().enumerate() {
        let caller = combined_caller(&fx.state, 1).await;
        let reply = send_text(
            &fx.state,
            caller,
            "POST",
            &[],
            Some(call_body(index as i64 + 2, name)),
        )
        .await;
        assert_eq!(reply.status, 200, "{name}: a refusal answers 200");
        assert_eq!(
            reply.json,
            Some(json!({
                "jsonrpc": "2.0",
                "id": index as i64 + 2,
                "error": {"code": -32602, "message": format!("Unknown tool: {name}")},
            })),
            "{name}: the refusal must name the tool as sent"
        );
        assert!(
            calls(&up).is_empty(),
            "{name}: the upstream must never see a tools/call"
        );
        let rows = call_rows(&fx.state).await;
        assert_eq!(
            rows.len(),
            index + 1,
            "{name}: exactly one row for the refusal"
        );
        assert_eq!(
            rows[index],
            CallRow {
                user: Some(1),
                server: server_id,
                slug: slug.to_owned(),
                tool: tool_name.to_owned(),
                decision: "deny".to_owned(),
                outcome: "refused".to_owned(),
                detail: detail.to_owned(),
            },
            "{name}: the refused row"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn arguments_reach_the_upstream_byte_for_byte() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let body = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demo__echo","arguments":{"n": 12345678901234567890123, "b": 1, "a": 2}}}"#;
    let reply = send_text(&fx.state, caller, "POST", &[], Some(body.to_owned())).await;
    assert_eq!(reply.status, 200, "the call must be answered");
    assert_eq!(call_text(&reply), Some("called: echo"));
    let sent = calls(&up);
    assert_eq!(sent.len(), 1, "the upstream must receive one tools/call");
    assert_eq!(sent[0].json()["params"]["name"], "echo");
    assert!(
        String::from_utf8_lossy(&sent[0].body)
            .contains(r#""arguments":{"n": 12345678901234567890123, "b": 1, "a": 2}"#),
        "the arguments must reach the upstream byte for byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_arguments_and_the_progress_token_reach_the_upstream() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let body = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"demo__echo","arguments":{},"requestState":"rs-1","_meta":{"progressToken":"p-1","vendor.example/x":"vendor-y","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}}}"#;
    let reply = send_text(&fx.state, caller, "POST", &[], Some(body.to_owned())).await;
    assert_eq!(reply.status, 200, "the call must be answered");
    let sent = calls(&up);
    assert_eq!(sent.len(), 1, "the upstream must receive one tools/call");
    let text = String::from_utf8_lossy(&sent[0].body).into_owned();
    for hidden in ["rs-1", "vendor.example/x", "vendor-y", "elicitation"] {
        assert!(
            !text.contains(hidden),
            "{hidden} must not reach the upstream: {text}"
        );
    }
    let upstream_body = sent[0].json();
    assert_eq!(
        upstream_body["params"]["_meta"]["progressToken"],
        json!("p-1"),
        "a string progress token must reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_calls_with_one_client_id_keep_it_and_reach_the_upstream_under_their_own_ids() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], |seen: &Seen| {
        echo_after(seen, Duration::from_millis(200))
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let first_caller = combined_caller(&fx.state, 1).await;
    let second_caller = same_family(&first_caller);
    let (first, second) = tokio::join!(
        send_text(
            &fx.state,
            first_caller,
            "POST",
            &[],
            Some(call_body(7, "demo__echo"))
        ),
        send_text(
            &fx.state,
            second_caller,
            "POST",
            &[],
            Some(call_body(7, "demo__echo"))
        ),
    );
    for reply in [&first, &second] {
        assert_eq!(
            reply.json.as_ref().map(|json| json["id"].clone()),
            Some(json!(7))
        );
        assert_eq!(call_text(reply), Some("called: echo"));
    }
    let ids: Vec<Value> = calls(&up)
        .iter()
        .map(|seen| seen.json()["id"].clone())
        .collect();
    assert_eq!(ids.len(), 2, "both calls must reach the upstream");
    assert_ne!(
        ids[0], ids[1],
        "the upstream ids of the two calls must differ"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_result_that_asks_for_input_is_a_tool_error_and_a_complete_one_is_plain() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("ask"), tool("done")], |seen: &Seen| {
        match seen.json()["params"]["name"].as_str() {
            Some("ask") => reply_to(
                seen,
                json!({"resultType": "input_required", "content": [{"type": "text", "text": "needs input"}]}),
            ),
            _ => reply_to(
                seen,
                json!({"resultType": "complete", "content": [{"type": "text", "text": "done"}]}),
            ),
        }
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let asked = json!({
        "content": [{"type": "text", "text": "This tool asked for input that this endpoint does not relay."}],
        "isError": true,
    });
    let session = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        session,
        "POST",
        &[],
        Some(call_body(1, "demo__ask")),
    )
    .await;
    assert_eq!(
        reply.json.as_ref().map(|json| json["result"].clone()),
        Some(asked.clone()),
        "a session client gets the tool error for input_required"
    );
    let session = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        session,
        "POST",
        &[],
        Some(call_body(2, "demo__done")),
    )
    .await;
    assert_eq!(
        reply.json.as_ref().map(|json| json["result"].clone()),
        Some(json!({"content": [{"type": "text", "text": "done"}]})),
        "a session client gets a complete result without resultType"
    );
    let stateless = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        stateless,
        "POST",
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "demo__ask"),
        ],
        Some(stateless_call_body(3, "demo__ask")),
    )
    .await;
    let mut stateless_asked = asked;
    stateless_asked["resultType"] = json!("complete");
    assert_eq!(
        reply.json.as_ref().map(|json| json["result"].clone()),
        Some(stateless_asked),
        "a stateless client gets the tool error marked complete"
    );
    let outcomes: Vec<(String, String)> = call_rows(&fx.state)
        .await
        .into_iter()
        .map(|row| (row.decision, row.outcome))
        .collect();
    assert_eq!(
        outcomes,
        vec![
            ("allow".to_owned(), "error".to_owned()),
            ("allow".to_owned(), "ok".to_owned()),
            ("allow".to_owned(), "error".to_owned()),
        ],
        "each answered call writes its own row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_answer_under_another_id_is_502_and_unavailable() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], |_seen: &Seen| {
        answer(
            200,
            None,
            Some("application/json"),
            &rpc_text(&json!(999), json!({"content": []})),
        )
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(5, "demo__echo")),
    )
    .await;
    assert_eq!(
        reply.status, 502,
        "a foreign answer is an unavailable upstream"
    );
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32000, "message": "Upstream demo is unavailable"},
        })),
    );
    let rows = call_rows(&fx.state).await;
    assert_eq!(
        rows,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "unavailable".to_owned(),
            detail: "an answer that is not an MCP answer".to_owned(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_unassigned_while_the_upstream_holds_the_answer_is_refused() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], |seen: &Seen| {
        echo_after(seen, Duration::from_millis(400))
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    list(&fx.state, 1).await;
    let caller = combined_caller(&fx.state, 1).await;
    let (reply, ()) = tokio::join!(
        send_text(
            &fx.state,
            caller,
            "POST",
            &[],
            Some(call_body(8, "demo__echo"))
        ),
        async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            unassign(&fx.state, 1, fx.server_id).await;
        },
    );
    assert_eq!(calls(&up).len(), 1, "the call must have gone upstream");
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 8,
            "error": {"code": -32602, "message": "Unknown tool: demo__echo"},
        })),
        "the answer the upstream held must be replaced by the refusal"
    );
    let rows = call_rows(&fx.state).await;
    assert_eq!(
        rows,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "refused".to_owned(),
            detail: "access was lost".to_owned(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_leaves_while_the_upstream_holds_the_answer_leaves_one_row() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], |_seen: &Seen| Plan::Silent).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    list(&fx.state, 1).await;
    let caller = combined_caller(&fx.state, 1).await;
    let state = fx.state.clone();
    let request = request_of("POST", &[], Some(call_body(9, "demo__echo")));
    let task = tokio::spawn(async move { handle(&state, caller, request).await });
    let deadline = Instant::now() + Duration::from_secs(3);
    while calls(&up).is_empty() {
        assert!(Instant::now() < deadline, "the upstream must hold the call");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let rows = wait_for_rows(&fx.state, 1).await;
    assert_eq!(
        rows,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "error".to_owned(),
            detail: "the client left before the answer".to_owned(),
        }]
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        call_rows(&fx.state).await.len(),
        1,
        "still one row 500 ms later"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_added_upstream_is_callable_and_a_missing_one_costs_no_list_in_the_interval() {
    let fx = fixture().await;
    let listed = Arc::new(Mutex::new(vec![tool("echo")]));
    let up = session_shared(Arc::clone(&listed)).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let family = combined_caller(&fx.state, 1).await;
    let list_body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
    let first = send_text(
        &fx.state,
        same_family(&family),
        "POST",
        &[],
        Some(list_body),
    )
    .await;
    assert_eq!(names(&first), vec!["demo__echo"]);
    listed.lock().expect("the tool list").push(tool("added"));
    let reply = send_text(
        &fx.state,
        same_family(&family),
        "POST",
        &[],
        Some(call_body(2, "demo__added")),
    )
    .await;
    assert_eq!(
        call_text(&reply),
        Some("called: added"),
        "a tool added after the last list must be callable"
    );
    assert_eq!(
        rpc_count(&up, "tools/list"),
        2,
        "the first list and one refresh for the new name"
    );
    assert_eq!(rpc_count(&up, "initialize"), 1, "no second initialize");
    let reply = send_text(
        &fx.state,
        same_family(&family),
        "POST",
        &[],
        Some(call_body(3, "demo__nope")),
    )
    .await;
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "error": {"code": -32602, "message": "Unknown tool: demo__nope"},
        })),
    );
    assert_eq!(
        rpc_count(&up, "tools/list"),
        2,
        "a missing tool within the refresh interval costs no list"
    );
    assert_eq!(calls(&up).len(), 1, "only the added tool was called");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rules_table_that_cannot_be_read_is_500_and_the_upstream_is_untouched() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    fx.state
        .db
        .call(|conn| conn.execute_batch("DROP TABLE rules"))
        .await
        .expect("the rules table is dropped");
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(11, "demo__echo")),
    )
    .await;
    assert_eq!(
        reply.status, 500,
        "a rules read that fails is an internal error"
    );
    assert!(up.seen().is_empty(), "the upstream must not be contacted");
    assert!(call_rows(&fx.state).await.is_empty(), "no row is written");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_table_that_cannot_be_read_answers_like_a_failed_rule_read_and_never_allows() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    fx.state
        .db
        .call(|conn| conn.execute_batch("DROP TABLE tool_switches"))
        .await
        .expect("the switch table is dropped");
    let rules = fixture().await;
    let rules_up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&rules, &rules_up.url).await;
    user(&rules.state, 1, vec![rules.server_id]).await;
    rules
        .state
        .db
        .call(|conn| conn.execute_batch("DROP TABLE rules"))
        .await
        .expect("the rules table is dropped");
    let listed = list(&fx.state, 1).await;
    let failed = list(&rules.state, 1).await;
    assert_eq!(
        listed.status, 500,
        "a switch read that fails is an internal error"
    );
    assert_eq!(
        (listed.status, &listed.text),
        (failed.status, &failed.text),
        "a failed switch read answers the list as a failed rule read does"
    );
    assert!(
        !listed.text.contains("echo"),
        "no tool may be listed when the switches cannot be read"
    );
    let before = up.seen().len();
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(11, "demo__echo")),
    )
    .await;
    let caller = combined_caller(&rules.state, 1).await;
    let failed = send_text(
        &rules.state,
        caller,
        "POST",
        &[],
        Some(call_body(11, "demo__echo")),
    )
    .await;
    assert_eq!(
        reply.status, 500,
        "a switch read that fails is an internal error"
    );
    assert_eq!(
        reply.status, failed.status,
        "a failed switch read answers the call as a failed rule read does"
    );
    assert_eq!(
        up.seen().len(),
        before,
        "the upstream must not see the call"
    );
    assert!(call_rows(&fx.state).await.is_empty(), "no row is written");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_call_writes_one_allow_row_under_the_real_server() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(12, "demo__echo")),
    )
    .await;
    assert_eq!(reply.status, 200, "the call must be answered");
    assert_eq!(call_text(&reply), Some("called: echo"));
    assert_eq!(
        call_rows(&fx.state).await,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "ok".to_owned(),
            detail: String::new(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_call_is_refused_without_an_upstream_or_a_row() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let number_name =
        r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":5,"arguments":{}}}"#;
    let reply = send_text(&fx.state, caller, "POST", &[], Some(number_name.to_owned())).await;
    assert_eq!(reply.status, 400, "a name that is not a string is a 400");
    assert_eq!(
        reply.json,
        Some(
            json!({"jsonrpc": "2.0", "id": 21, "error": {"code": -32600, "message": "Invalid request"}})
        ),
    );
    let caller = combined_caller(&fx.state, 1).await;
    let task = r#"{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"demo__echo","arguments":{},"task":{}}}"#;
    let reply = send_text(&fx.state, caller, "POST", &[], Some(task.to_owned())).await;
    assert_eq!(
        reply.json,
        Some(
            json!({"jsonrpc": "2.0", "id": 22, "error": {"code": -32601, "message": "Method not found"}})
        ),
        "a task parameter stays method not found"
    );
    let caller = combined_caller(&fx.state, 1).await;
    let no_id =
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"demo__echo","arguments":{}}}"#;
    let reply = send_text(&fx.state, caller, "POST", &[], Some(no_id.to_owned())).await;
    assert_eq!(
        reply.status, 400,
        "a call without an id is the intake refusal"
    );
    assert_eq!(
        reply.json,
        Some(
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Invalid request"}})
        ),
    );
    assert!(
        up.seen().is_empty(),
        "no malformed call reaches the upstream"
    );
    assert!(
        call_rows(&fx.state).await.is_empty(),
        "no malformed call writes a row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_to_an_unassigned_server_never_reaches_it_even_when_its_catalog_has_the_tool() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], echo_text).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![]).await;
    let demo = fx.server_id;
    fx.state
        .db
        .call(move |conn| catalog::replace(conn, demo, &[tool("echo")], 100))
        .await
        .expect("the stored catalog");
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(41, "demo__echo")),
    )
    .await;
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 41,
            "error": {"code": -32602, "message": "Unknown tool: demo__echo"},
        })),
    );
    assert!(
        up.seen().is_empty(),
        "the upstream must see no request at all, not even a handshake"
    );
    assert_eq!(
        call_rows(&fx.state).await,
        vec![CallRow {
            user: Some(1),
            server: Some(demo),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "deny".to_owned(),
            outcome: "refused".to_owned(),
            detail: "the server is not assigned".to_owned(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_upstream_tool_with_an_mcp_header_key_is_callable() {
    let fx = fixture().await;
    let listed = Arc::new(Mutex::new(vec![json!({
        "name": "hidden",
        "inputSchema": {"type": "object", "x-mcp-header": "Region"},
    })]));
    let up = session_shared(listed).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(42, "demo__hidden")),
    )
    .await;
    assert_eq!(
        reply.status, 200,
        "a session link may carry an x-mcp-header tool"
    );
    assert_eq!(call_text(&reply), Some("called: hidden"));
    assert_eq!(
        call_rows(&fx.state).await,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "hidden".to_owned(),
            decision: "allow".to_owned(),
            outcome: "ok".to_owned(),
            detail: String::new(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_json_rpc_error_is_returned_under_the_clients_id_with_an_error_row() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], |seen: &Seen| {
        let id = seen.json()["id"].clone();
        answer(
            200,
            None,
            Some("application/json"),
            &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "boom"}})
                .to_string(),
        )
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(41, "demo__echo")),
    )
    .await;
    assert_eq!(
        reply.status, 200,
        "an upstream error is answered in the body"
    );
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 41,
            "error": {"code": -32000, "message": "boom"},
        })),
        "the upstream error must carry the client's id"
    );
    assert_eq!(
        call_rows(&fx.state).await,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "error".to_owned(),
            detail: String::new(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_methods_the_endpoint_does_not_serve_are_404_and_the_session_form_200() {
    let fx = fixture().await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}});
    let stateless = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "resources/list"),
    ];
    let reply = send(
        &fx.state,
        1,
        "POST",
        &stateless,
        Some(
            json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list",
            "params": {"_meta": meta}}),
        ),
    )
    .await;
    assert_eq!(
        reply.status, 404,
        "a stateless resources/list on /mcp is 404"
    );
    assert_eq!(
        reply
            .json
            .as_ref()
            .map(|json| json["error"]["code"].clone()),
        Some(json!(-32601))
    );
    assert_eq!(
        reply.json.as_ref().map(|json| json["id"].clone()),
        Some(json!(3))
    );
    let session = send(
        &fx.state,
        1,
        "POST",
        &[],
        Some(json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}})),
    )
    .await;
    assert_eq!(session.status, 200, "a session resources/list stays 200");
    assert_eq!(
        session
            .json
            .as_ref()
            .map(|json| json["error"]["code"].clone()),
        Some(json!(-32601))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_list_without_a_protocol_version_is_invalid_params_on_mcp() {
    let fx = fixture().await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let stateless = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/list"),
    ];
    let reply = send(
        &fx.state,
        1,
        "POST",
        &stateless,
        Some(json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}})),
    )
    .await;
    assert_eq!(reply.status, 400, "a stateless list without _meta is a 400");
    assert_eq!(
        reply.json,
        Some(json!({"jsonrpc": "2.0", "id": 5, "error": {"code": -32602,
            "message": "Invalid params: missing _meta, protocol version or client capabilities"}}))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_listed_only_on_the_stateless_form_is_called_through_mcp() {
    let fx = fixture().await;
    let up = TestUpstream::start(|seen: &Seen| {
        let stateless = seen.header("mcp-protocol-version") == Some("2026-07-28");
        match seen.rpc().as_str() {
            "server/discover" => reply_to(seen, discover()),
            "tools/list" if stateless => {
                reply_to(seen, json!({"tools": [tool("echo"), tool("extra")]}))
            }
            "tools/list" => reply_to(seen, json!({"tools": [tool("echo")]})),
            "tools/call" => echo_text(seen),
            _ => reply_to(seen, json!({})),
        }
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}});
    let listed = send(
        &fx.state,
        1,
        "POST",
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/list"),
        ],
        Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": meta}})),
    )
    .await;
    assert_eq!(listed.status, 200, "the stateless list is answered");
    let names: Vec<String> = listed
        .json
        .as_ref()
        .and_then(|json| json["result"]["tools"].as_array())
        .expect("the tool list")
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect();
    assert!(
        names.iter().any(|name| name == "demo__extra"),
        "the stateless list holds demo__extra, got {names:?}"
    );
    let token = combined_caller(&fx.state, 1).await;
    let called = send_text(
        &fx.state,
        token,
        "POST",
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "demo__extra"),
        ],
        Some(stateless_call_body(2, "demo__extra")),
    )
    .await;
    assert_eq!(called.status, 200, "the call is answered");
    assert_eq!(
        call_text(&called),
        Some("called: extra"),
        "the answer was {}",
        called.text
    );
    let seen = calls(&up);
    assert_eq!(seen.len(), 1, "the call reaches the upstream once");
    assert_eq!(seen[0].json()["params"]["name"], "extra");
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_requests_need_client_capabilities_on_mcp() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let info = json!({"name": "test", "version": "0"});
    let headers = |method: &'static str| {
        [
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", method),
        ]
    };
    for (id, method) in [(21, "server/discover"), (22, "tools/list")] {
        let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": info});
        let reply = send(
            &fx.state,
            1,
            "POST",
            &headers(method),
            Some(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {"_meta": meta}})),
        )
        .await;
        assert_eq!(
            reply.status, 400,
            "{method} without client capabilities on /mcp"
        );
        assert_eq!(
            reply.json,
            Some(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602,
                "message": "Invalid params: missing _meta, protocol version or client capabilities"}}))
        );
    }
    assert_eq!(rpc_count(&up, "tools/list"), 0, "the upstream sees no list");
    for capabilities in [json!("x"), json!(null)] {
        let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities});
        let reply = send(
            &fx.state,
            1,
            "POST",
            &headers("server/discover"),
            Some(json!({"jsonrpc": "2.0", "id": 23, "method": "server/discover", "params": {"_meta": meta}})),
        )
        .await;
        assert_eq!(reply.status, 400, "{capabilities} is not an object");
        assert_eq!(
            reply
                .json
                .as_ref()
                .map(|json| json["error"]["code"].clone()),
            Some(json!(-32602))
        );
    }
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}});
    let discovered = send(
        &fx.state,
        1,
        "POST",
        &headers("server/discover"),
        Some(json!({"jsonrpc": "2.0", "id": 24, "method": "server/discover", "params": {"_meta": meta}})),
    )
    .await;
    assert_eq!(discovered.status, 200, "empty capabilities are accepted");
    assert!(
        discovered
            .json
            .as_ref()
            .is_some_and(|json| json["result"].is_object())
    );
    let note = send(
        &fx.state,
        1,
        "POST",
        &headers("notifications/cancelled"),
        Some(
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}}),
        ),
    )
    .await;
    assert_eq!(
        note.status, 202,
        "a notification needs no client capabilities"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stateless_notifications_need_no_metadata_on_mcp() {
    let fx = fixture().await;
    let up = stateless_up(vec![tool("echo")]).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let headers = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "notifications/cancelled"),
    ];
    let bodies = [
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled"}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 1, "_meta": {}}}),
    ];
    for body in bodies {
        let reply = send(&fx.state, 1, "POST", &headers, Some(body.clone())).await;
        assert_eq!(reply.status, 202, "{body} is accepted on /mcp");
    }
    let different = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}}});
    let reply = send(&fx.state, 1, "POST", &headers, Some(different)).await;
    assert_eq!(reply.status, 400, "a different version is refused on /mcp");
    assert_eq!(
        reply
            .json
            .as_ref()
            .map(|json| json["error"]["code"].clone()),
        Some(json!(-32020))
    );
    let not_a_string = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": 7}}});
    let reply = send(&fx.state, 1, "POST", &headers, Some(not_a_string)).await;
    assert_eq!(reply.status, 400, "a number version is refused on /mcp");
    assert_eq!(
        reply
            .json
            .as_ref()
            .map(|json| json["error"]["code"].clone()),
        Some(json!(-32602))
    );
    let no_method = [("MCP-Protocol-Version", "2026-07-28")];
    let body = json!({"jsonrpc": "2.0", "method": "notifications/cancelled"});
    let reply = send(&fx.state, 1, "POST", &no_method, Some(body)).await;
    assert_eq!(reply.status, 400, "a missing Mcp-Method is refused on /mcp");
    assert_eq!(
        reply
            .json
            .as_ref()
            .map(|json| json["error"]["code"].clone()),
        Some(json!(-32020))
    );
}

/// The error object of the refusal these tests script: a code, a message and data.
fn missing_capability() -> Value {
    json!({"code": -32021, "message": "MissingRequiredClientCapabilityError",
        "data": {"requiredCapabilities": {"sampling": {}}}})
}

/// A JSON-RPC error answer under `id`, as text.
fn error_text(id: &Value, error: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": error}).to_string()
}

/// A stateless upstream whose tools/call answers `status` with the body `body` builds from its id.
async fn refusing_up(
    status: u16,
    body: impl Fn(&Value) -> String + Send + Sync + 'static,
) -> TestUpstream {
    stateless_with(vec![tool("echo")], move |seen: &Seen| {
        let id = seen.json()["id"].clone();
        answer(
            status,
            None,
            Some("application/json; charset=utf-8"),
            &body(&id),
        )
    })
    .await
}

/// A stateless client's call (id 401) through `/mcp` to a stateless upstream, with the tool listed.
async fn stateless_refused_call(fx: &Fixture, up: &TestUpstream) -> Reply {
    point(fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    list(&fx.state, 1).await;
    let headers = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "demo__echo"),
    ];
    let caller = combined_caller(&fx.state, 1).await;
    send_text(
        &fx.state,
        caller,
        "POST",
        &headers,
        Some(stateless_call_body(401, "demo__echo")),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_client_gets_an_upstream_error_with_its_own_id() {
    let fx = fixture().await;
    let up = refusing_up(400, |id| error_text(id, missing_capability())).await;
    let reply = stateless_refused_call(&fx, &up).await;
    assert_eq!(
        reply.status, 400,
        "a stateless client gets the upstream's 400"
    );
    assert_eq!(
        reply.json,
        Some(json!({"jsonrpc": "2.0", "id": 401, "error": missing_capability()}))
    );
    assert_eq!(
        reply
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        call_rows(&fx.state).await,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "error".to_owned(),
            detail: String::new(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_client_gets_the_same_error_with_status_200() {
    let fx = fixture().await;
    let up = refusing_up(400, |id| error_text(id, missing_capability())).await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    list(&fx.state, 1).await;
    let caller = combined_caller(&fx.state, 1).await;
    let reply = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(402, "demo__echo")),
    )
    .await;
    assert_eq!(reply.status, 200, "a session client always gets 200");
    assert_eq!(
        reply.json,
        Some(json!({"jsonrpc": "2.0", "id": 402, "error": missing_capability()}))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_upstream_error_answered_200_is_relayed_with_200() {
    let fx = fixture().await;
    let error = json!({"code": -32602, "message": "Invalid params"});
    let up = refusing_up(200, move |id| error_text(id, error.clone())).await;
    let reply = stateless_refused_call(&fx, &up).await;
    assert_eq!(reply.status, 200, "a 200 error is relayed with 200");
    assert_eq!(
        reply.json,
        Some(
            json!({"jsonrpc": "2.0", "id": 401, "error": {"code": -32602, "message": "Invalid params"}})
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_client_gets_a_404_upstream_error_as_404() {
    let fx = fixture().await;
    let up = refusing_up(404, |id| error_text(id, missing_capability())).await;
    let reply = stateless_refused_call(&fx, &up).await;
    assert_eq!(
        reply.status, 404,
        "a stateless client gets the upstream's 404"
    );
    assert_eq!(
        reply.json,
        Some(json!({"jsonrpc": "2.0", "id": 401, "error": missing_capability()}))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_refusal_that_is_not_a_json_rpc_error_is_502() {
    type Body = Box<dyn Fn(&Value) -> String + Send + Sync>;
    let cases: Vec<(u16, Body)> = vec![
        (400, Box::new(|_| r#"{"oops":1}"#.to_owned())),
        (
            400,
            Box::new(|id| error_text(id, json!({"code": "-32021", "message": "x"}))),
        ),
        (
            400,
            Box::new(|id| error_text(id, json!({"message": "no code"}))),
        ),
        (
            400,
            Box::new(|_| error_text(&json!(999), missing_capability())),
        ),
        (404, Box::new(|_| "not found".to_owned())),
        (
            400,
            Box::new(|id| {
                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []},
                    "error": missing_capability()})
                .to_string()
            }),
        ),
        (
            400,
            Box::new(|id| json!({"id": id, "error": missing_capability()}).to_string()),
        ),
        (
            400,
            Box::new(|id| {
                json!({"jsonrpc": "1.0", "id": id, "error": missing_capability()}).to_string()
            }),
        ),
        (
            400,
            Box::new(|id| {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32021}}).to_string()
            }),
        ),
        (
            400,
            Box::new(|id| {
                json!({"jsonrpc": "2.0", "id": id,
                    "error": {"code": -32021, "message": 7}})
                .to_string()
            }),
        ),
    ];
    let mut failed = Vec::new();
    for (index, (status, body)) in cases.into_iter().enumerate() {
        let fx = fixture().await;
        let up = refusing_up(status, body).await;
        let reply = stateless_refused_call(&fx, &up).await;
        let rows = call_rows(&fx.state).await;
        let unavailable = Some(json!({"jsonrpc": "2.0", "id": null,
            "error": {"code": -32000, "message": "Upstream demo is unavailable"}}));
        if reply.status != 502
            || reply.json != unavailable
            || rows.len() != 1
            || rows[0].outcome != "unavailable"
        {
            failed.push(format!(
                "case {index} ({status}): status {}, body {}",
                reply.status, reply.text
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "a body that is not a well-formed error is a 502: {failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_upstream_error_is_502() {
    let fx = fixture_with(|config| config.limits.tools_list_bytes = 4000).await;
    let padded = json!({"code": -32021, "message": "big", "data": {"pad": "x".repeat(5000)}});
    let up = refusing_up(400, move |id| error_text(id, padded.clone())).await;
    let reply = stateless_refused_call(&fx, &up).await;
    assert_eq!(reply.status, 502, "an error over the cap is a 502");
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_relayed_error_the_next_call_on_the_session_link_succeeds() {
    let fx = fixture().await;
    let initializes = Arc::new(AtomicUsize::new(0));
    let calls_made = Arc::new(AtomicUsize::new(0));
    let (inits, calls_so_far) = (Arc::clone(&initializes), Arc::clone(&calls_made));
    let up = TestUpstream::start(move |seen: &Seen| {
        if seen.method == "DELETE" {
            return answer(200, None, None, "");
        }
        if seen.header("mcp-protocol-version") == Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        let id = seen.json()["id"].clone();
        match seen.rpc().as_str() {
            "initialize" => {
                // A session id is never shared by two links, so each handshake issues its own.
                let session = format!("s{}", inits.fetch_add(1, Ordering::SeqCst) + 1);
                answer(
                    200,
                    Some(&session),
                    Some("application/json"),
                    &rpc_text(&id, json!({"protocolVersion": "2025-11-25", "capabilities": {}})),
                )
            }
            _ if seen.header("mcp-session-id").is_none() => answer(400, None, None, ""),
            "notifications/initialized" => answer(202, None, None, ""),
            "tools/list" => answer(
                200,
                None,
                Some("application/json"),
                &rpc_text(&id, json!({"tools": [tool("echo")]})),
            ),
            "tools/call" if calls_so_far.fetch_add(1, Ordering::SeqCst) == 0 => answer(
                400,
                None,
                Some("application/json; charset=utf-8"),
                &error_text(&id, missing_capability()),
            ),
            "tools/call" => answer(
                200,
                None,
                Some("application/json"),
                &rpc_text(&id, json!({"content": [{"type": "text", "text": "called: echo"}], "isError": false})),
            ),
            _ => answer(404, None, None, ""),
        }
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    list(&fx.state, 1).await;
    let caller = combined_caller(&fx.state, 1).await;
    let first = send_text(
        &fx.state,
        same_family(&caller),
        "POST",
        &[],
        Some(call_body(501, "demo__echo")),
    )
    .await;
    assert_eq!(first.status, 200, "a session client always gets 200");
    assert_eq!(
        first.json,
        Some(json!({"jsonrpc": "2.0", "id": 501, "error": missing_capability()}))
    );
    let handshakes = initializes.load(Ordering::SeqCst);
    let second = send_text(
        &fx.state,
        caller,
        "POST",
        &[],
        Some(call_body(502, "demo__echo")),
    )
    .await;
    assert_eq!(
        second.status, 200,
        "the next call on the same link succeeds"
    );
    assert_eq!(call_text(&second), Some("called: echo"));
    assert_eq!(
        initializes.load(Ordering::SeqCst),
        handshakes,
        "the next call makes no new handshake"
    );
    let outcomes: Vec<String> = call_rows(&fx.state)
        .await
        .into_iter()
        .map(|row| row.outcome)
        .collect();
    assert_eq!(outcomes, vec!["error".to_owned(), "ok".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_unassigned_while_the_upstream_refuses_the_call_gets_the_refusal() {
    let fx = fixture().await;
    let up = stateless_with(vec![tool("echo")], |seen: &Seen| {
        let id = seen.json()["id"].clone();
        let refused = answer(
            400,
            None,
            Some("application/json; charset=utf-8"),
            &error_text(&id, missing_capability()),
        );
        match refused {
            Plan::Reply(response) => Plan::Late(Duration::from_millis(400), response),
            other => other,
        }
    })
    .await;
    point(&fx, &up.url).await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    list(&fx.state, 1).await;
    let caller = combined_caller(&fx.state, 1).await;
    let (reply, ()) = tokio::join!(
        send_text(
            &fx.state,
            caller,
            "POST",
            &[],
            Some(call_body(9, "demo__echo"))
        ),
        async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            unassign(&fx.state, 1, fx.server_id).await;
        },
    );
    assert_eq!(calls(&up).len(), 1, "the call must have gone upstream");
    assert_eq!(
        reply.json,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 9,
            "error": {"code": -32602, "message": "Unknown tool: demo__echo"},
        })),
        "the refusal the upstream held must be replaced by the refusal of the check"
    );
    let rows = call_rows(&fx.state).await;
    assert_eq!(
        rows,
        vec![CallRow {
            user: Some(1),
            server: Some(fx.server_id),
            slug: "demo".to_owned(),
            tool: "echo".to_owned(),
            decision: "allow".to_owned(),
            outcome: "refused".to_owned(),
            detail: "access was lost".to_owned(),
        }]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stateless_discover_on_mcp_names_the_server_in_result_meta() {
    let fx = fixture().await;
    user(&fx.state, 1, vec![fx.server_id]).await;
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}});
    let discovered = send(
        &fx.state,
        1,
        "POST",
        &[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "server/discover"),
        ],
        Some(
            json!({"jsonrpc": "2.0", "id": 31, "method": "server/discover",
            "params": {"_meta": meta}}),
        ),
    )
    .await;
    assert_eq!(
        discovered.status, 200,
        "server/discover on /mcp is answered"
    );
    let identity = json!({"name": "doorward", "version": env!("CARGO_PKG_VERSION")});
    assert_eq!(
        discovered.json,
        Some(json!({"jsonrpc": "2.0", "id": 31, "result": {
            "supportedVersions": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"],
            "capabilities": {"tools": {}},
            "serverInfo": identity,
            "_meta": {"io.modelcontextprotocol/serverInfo": identity},
            "cacheScope": "private",
            "resultType": "complete",
        }}))
    );
}

/// A stateless upstream whose tools/list waits `delay` before it answers `tools`.
async fn delayed_up(tools: Vec<Value>, delay: Duration) -> String {
    let state: DelayedState = (Arc::new(tools), delay);
    let app = Router::new()
        .route("/mcp", post(delayed_answer))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{address}/mcp")
}

type DelayedState = (Arc<Vec<Value>>, Duration);

async fn delayed_answer(State((tools, delay)): State<DelayedState>, body: Bytes) -> Response {
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let result = match request["method"].as_str() {
        Some("tools/list") => {
            tokio::time::sleep(delay).await;
            json!({"tools": tools.as_ref()})
        }
        _ => discover(),
    };
    Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result})).into_response()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_the_budget_refuses_is_left_out_and_keeps_no_refresh_error() {
    let fx = fixture().await;
    // About 20 KB of tools: five permits, more than the four left free below.
    let big = json!({
        "name": "big",
        "description": "d".repeat(20_000),
        "inputSchema": {"type": "object"},
    });
    let busy_url = delayed_up(vec![big], Duration::from_millis(1500)).await;
    let good = stateless_up(vec![tool("s1")]).await;
    let busy_id = server(&fx.state, "aaa", &busy_url).await;
    let good_id = server(&fx.state, "bbb", &good.url).await;
    user(&fx.state, 1, vec![busy_id, good_id]).await;
    // Another holder keeps all but four permits of the 32 MiB budget while the lists run.
    let mut others = fx.state.links.budget().reservation(None);
    assert!(
        others.set(33_554_432 - 4 * 4096),
        "the others take their bytes"
    );
    let reply = list(&fx.state, 1).await;
    assert_eq!(
        names(&reply),
        vec!["bbb__s1"],
        "the server the budget refuses is left out, the other one answers"
    );
    assert_eq!(
        catalog_error(&fx.state, busy_id).await,
        None,
        "a list the budget refused stores no refresh error"
    );
    assert_eq!(catalog_error(&fx.state, good_id).await, None);
    let logged = NOTES
        .lock()
        .expect("notes")
        .iter()
        .any(|line| line == "tools/list: aaa left out, the answer memory budget is exhausted");
    assert!(
        logged,
        "the left out server is logged with the budget as its cause"
    );
}

/// A declared header on a server, with pass-through on.
async fn declare_passed(state: &AppState, server_id: i64, name: &str, required: bool) {
    let name = name.to_owned();
    state
        .db
        .call(move |conn| {
            conn.execute(
                "UPDATE servers SET pass_headers = 1 WHERE id = ?1",
                params![server_id],
            )?;
            conn.execute(
                "INSERT INTO server_headers (server_id, name, name_lower, required, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                params![server_id, name, name.to_ascii_lowercase(), required],
            )?;
            Ok(())
        })
        .await
        .expect("declare a header");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_header_sent_twice_refuses_the_whole_list_before_any_upstream() {
    let fx = fixture().await;
    let one = stateless_up(vec![tool("echo")]).await;
    let two = stateless_up(vec![tool("alpha")]).await;
    let one_id = server(&fx.state, "one", &one.url).await;
    let two_id = server(&fx.state, "two", &two.url).await;
    user(&fx.state, 1, vec![one_id, two_id]).await;
    declare_passed(&fx.state, one_id, "X-Trace-Id", false).await;
    let reply = send(
        &fx.state,
        1,
        "POST",
        &[("X-Trace-Id", "a"), ("X-Trace-Id", "b")],
        Some(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
    )
    .await;
    assert_eq!(
        reply.status, 400,
        "a declared header sent twice must refuse the whole list"
    );
    assert!(one.seen().is_empty(), "no upstream may be contacted");
    assert!(two.seen().is_empty(), "no upstream may be contacted");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_to_a_server_missing_its_required_header_is_a_tool_error_not_a_502() {
    let fx = fixture().await;
    let one = stateless_up(vec![tool("echo")]).await;
    let two = stateless_up(vec![tool("alpha")]).await;
    let one_id = server(&fx.state, "one", &one.url).await;
    let two_id = server(&fx.state, "two", &two.url).await;
    user(&fx.state, 1, vec![one_id, two_id]).await;
    declare_passed(&fx.state, one_id, "X-Api-Key", true).await;
    let listed = list(&fx.state, 1).await;
    assert_eq!(
        names(&listed),
        vec!["two__alpha".to_string()],
        "the server missing its required header has no stored catalog yet, so it lists nothing and is not contacted"
    );
    assert!(one.seen().is_empty(), "nothing may be sent to that server");
    let call = send(
        &fx.state,
        1,
        "POST",
        &[],
        Some(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "one__echo", "arguments": {}}})),
    )
    .await;
    assert_eq!(
        call.status, 200,
        "a call to the left out server is a tool error"
    );
    let result = call.json.as_ref().and_then(|body| body.get("result"));
    assert_eq!(
        result.and_then(|result| result.get("isError")),
        Some(&json!(true))
    );
    assert!(one.seen().is_empty(), "the call must not reach that server");
}
