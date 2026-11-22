mod common;

use std::time::{Duration, Instant};

use common::admin::{self, ServerSpec};
use common::client::{self, OAuthApp, Pkce, TestClient, Tokens, pkce};
use common::headers::{
    add_server_named, declare_header, header_id, received_calls, remove_header, session_call,
    set_switches, stateless_call,
};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::values::{
    CANARY, any_wrap_opens, copied_files, copy_store, file_contains, live_db, needs_values,
    open_sealed, opens_any_row, password_opens, password_wrap, remove_value, request_reset,
    reset_link, sealed_of, store_value, stored_strings, token_data_key, token_wraps, value_state,
};
use common::world::{
    APP_NAME, APP_REDIRECT, OWNER_EMAIL, PASSWORD, SECRET_HEADER, World, secret_for,
};
use doorward::crypto::token_hash;
use doorward::vault::{self, Place, ValuePlace};
use rusqlite::{Connection, params};

const BOB: &str = "bob@example.com";
const ALICE: &str = "alice@example.com";
const ADMIN: &str = "admin@example.com";
const SLUG: &str = "demo";
const HEADER: &str = "X-Trace-Id";
const LOWER: &str = "x-trace-id";
const OTHER: &str = "canary-2b8e0d6f19a3c574";
const CLIENT_VALUE: &str = "client-41c8e07a";
const NEW_PASSWORD: &str = "a brand new passphrase";
const OTHER_APP_ID: &str = "https://other.example.com/app.json";
const OTHER_APP_NAME: &str = "Other Client";
const NOTICE: &str = r#"div.notice[data-notice="error"][role="alert"]"#;
const SESSION_COOKIE: &str = "__Host-doorward_session";
const DROPPED_SENTENCE: &str =
    "Resetting your password deletes the credentials you stored for servers.";

fn server_path(id: &str) -> String {
    format!("/admin/servers/{id}")
}

fn number(text: &str) -> i64 {
    text.parse().expect("ids are numbers")
}

async fn declare_ok(owner: &TestClient, id: &str, name: &str, required: bool) {
    let page = declare_header(owner, id, name, required).await;
    assert_eq!(page.status, 303, "declaring {name} must be accepted");
}

async fn switches_ok(owner: &TestClient, id: &str, pass: bool, store: bool) {
    let page = set_switches(owner, id, pass, store).await;
    assert_eq!(
        page.status, 303,
        "saving the header switches must be accepted"
    );
}

async fn header_of(owner: &TestClient, id: &str, name: &str) -> String {
    header_id(owner, id, name)
        .await
        .unwrap_or_else(|| panic!("the declared header {name} must have a remove form"))
}

async fn user_number(w: &World, email: &str) -> i64 {
    number(&w.user_id(email).await)
}

/// Stores a value and asserts the redirect back to the account page.
async fn store_ok(browser: &TestClient, slug: &str, header: &str, value: &str) {
    let page = store_value(browser, slug, header, value).await;
    assert_eq!(
        page.status, 303,
        "storing a value on {slug} must be accepted"
    );
    let location = page.location().unwrap_or_default();
    let path = location.split(['?', '#']).next().unwrap_or_default();
    assert_eq!(
        path, "/account",
        "a saved value must redirect to the account page, with an optional query and fragment"
    );
}

/// Bob, assigned to the demo server, with the header declared and only the store switch on.
async fn demo_for_bob(w: &World, required: bool) -> (FakeUpstream, String, String, TestClient) {
    let (upstream, id) = w.upstream(SLUG, UpstreamOptions::default()).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, required).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = header_of(&w.owner, &id, HEADER).await;
    (upstream, id, hid, bob)
}

/// A session client on `slug`, initialized; the handshake must be answered 200.
async fn session_on(w: &World, slug: &str, tokens: &Tokens) -> McpClient {
    let client = w.session_mcp(slug, tokens);
    let reply = client.initialize().await;
    assert_eq!(reply.status, 200, "initialize on {slug} must be answered");
    client
}

/// The values the upstream received for `tool`, one entry per call.
fn carried(upstream: &FakeUpstream, tool: &str) -> Vec<Option<String>> {
    received_calls(upstream, tool)
        .iter()
        .map(|call| call.header(LOWER).map(str::to_string))
        .collect()
}

fn any_request_carries(upstream: &FakeUpstream, value: &str) -> bool {
    upstream
        .requests()
        .iter()
        .any(|request| request.header_all(LOWER).contains(&value))
}

/// Whether `token` opens the wrap on its own row of `table` in the copy.
fn opens_own_row(
    conn: &Connection,
    keys: &doorward::crypto::Keys,
    table: &str,
    token: &str,
) -> bool {
    token_data_key(conn, keys, table, token).is_ok()
}

fn count_for(conn: &Connection, sql: &str, value: i64) -> i64 {
    conn.query_row(sql, [value], |row| row.get(0))
        .expect("the count reads")
}

/// Starts the code flow for `browser` and returns the code with its verifier.
async fn code_for(browser: &TestClient, app: &OAuthApp, resource: &str) -> (String, Pkce) {
    let pkce = pkce();
    let authorized = browser.authorize(app, resource, &pkce, "state-s84").await;
    let req = authorized
        .query("req")
        .expect("authorize answers with the consent request");
    let granted = browser.consent(&req, "approve").await;
    let code = granted.query("code").expect("consent answers with a code");
    (code, pkce)
}

/// Waits up to 5 seconds until the sweep has removed the access token `token`.
async fn wait_for_sweep(w: &World, token: &str) {
    let live = live_db(w);
    let hash = token_hash(token);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rows: i64 = live
            .query_row(
                "SELECT COUNT(*) FROM access_tokens WHERE token_hash = ?1",
                [hash.as_str()],
                |row| row.get(0),
            )
            .expect("the count reads");
        if rows == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the sweep must remove the expired access token within 5 seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_value_reaches_the_upstream_on_session_stateless_and_combined_calls() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;

    let session = session_on(&w, SLUG, &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the session call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the session call must carry the stored value"
    );

    upstream.clear();
    let stateless = w.stateless_mcp(SLUG, &tokens);
    let reply = stateless_call(&stateless, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the stateless call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the stateless call must carry the stored value"
    );

    let combined_tokens = w.token(&bob, "mcp").await;
    let combined = session_on(&w, "mcp", &combined_tokens).await;
    upstream.clear();
    let reply = session_call(&combined, "demo__echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the combined call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the combined endpoint must carry the stored value"
    );

    let account = bob.get("/account").await;
    assert!(
        !account.body.contains(CANARY),
        "the account page must never show a stored value"
    );
    assert_eq!(
        value_state(&bob, SLUG, LOWER).await.as_deref(),
        Some("set"),
        "the account page must show the value as set"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_stored_after_a_token_was_issued_is_used_by_its_next_call() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    let tokens = w.token(&bob, SLUG).await;
    let session = session_on(&w, SLUG, &tokens).await;

    store_ok(&bob, SLUG, &hid, CANARY).await;
    upstream.clear();
    let ended = session_call(&session, "echo", &[]).await;
    assert_eq!(
        ended.status, 404,
        "a session issued before the first store must be refused with 404"
    );
    assert!(upstream.requests().is_empty());
    let fresh = session_on(&w, SLUG, &tokens).await;
    upstream.clear();
    let reply = session_call(&fresh, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the token's next call must carry the value stored after the token was issued"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_header_wins_with_pass_through_on_and_is_ignored_with_it_off() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let session = session_on(&w, SLUG, &tokens).await;

    switches_ok(&w.owner, &id, true, true).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[(HEADER, CLIENT_VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CLIENT_VALUE.to_string())],
        "with pass-through on, the client's value must win over the stored one"
    );

    switches_ok(&w.owner, &id, false, true).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[(HEADER, CLIENT_VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "with pass-through off, the client's value must be ignored and the stored value used"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_servers_with_one_header_name_each_get_their_own_value() {
    let w = World::start().await;
    let (a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let b_options = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let (b, b_id) = w.upstream("b", b_options).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&a_id, &b_id]).await;
    declare_ok(&w.owner, &a_id, HEADER, false).await;
    declare_ok(&w.owner, &b_id, HEADER, false).await;
    switches_ok(&w.owner, &a_id, false, true).await;
    switches_ok(&w.owner, &b_id, false, true).await;
    let a_header = header_of(&w.owner, &a_id, HEADER).await;
    let b_header = header_of(&w.owner, &b_id, HEADER).await;
    store_ok(&bob, "a", &a_header, CANARY).await;
    store_ok(&bob, "b", &b_header, OTHER).await;

    let on_a = session_on(&w, "a", &w.token(&bob, "a").await).await;
    a.clear();
    let reply = session_call(&on_a, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "a's call must be answered"
    );
    assert_eq!(
        carried(&a, "echo"),
        vec![Some(CANARY.to_string())],
        "a must receive its own value"
    );
    assert!(
        !any_request_carries(&a, OTHER),
        "a must never receive the value of b"
    );

    let on_b = session_on(&w, "b", &w.token(&bob, "b").await).await;
    b.clear();
    let reply = session_call(&on_b, "alpha", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: alpha"),
        "b's call must be answered"
    );
    assert_eq!(
        carried(&b, "alpha"),
        vec![Some(OTHER.to_string())],
        "b must receive its own value"
    );
    assert!(
        !any_request_carries(&b, CANARY),
        "b must never receive the value of a"
    );

    let combined = session_on(&w, "mcp", &w.token(&bob, "mcp").await).await;
    a.clear();
    b.clear();
    let reply = session_call(&combined, "a__echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "a__echo must be answered"
    );
    let reply = session_call(&combined, "b__alpha", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: alpha"),
        "b__alpha must be answered"
    );
    assert_eq!(
        carried(&a, "echo"),
        vec![Some(CANARY.to_string())],
        "on /mcp a gets its value"
    );
    assert_eq!(
        carried(&b, "alpha"),
        vec![Some(OTHER.to_string())],
        "on /mcp b gets its value"
    );
    assert!(
        !any_request_carries(&a, OTHER),
        "on /mcp a never gets b's value"
    );
    assert!(
        !any_request_carries(&b, CANARY),
        "on /mcp b never gets a's value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_users_calls_never_carry_the_first_users_value() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let alice = w.user(ALICE).await;
    w.grant(ALICE, &[&id]).await;
    let bob_session = session_on(&w, SLUG, &w.token(&bob, SLUG).await).await;
    let alice_session = session_on(&w, SLUG, &w.token(&alice, SLUG).await).await;

    upstream.clear();
    let reply = session_call(&bob_session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "bob's call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "bob's call must carry bob's value"
    );

    upstream.clear();
    let reply = session_call(&alice_session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "alice's call must be answered"
    );
    assert!(
        !any_request_carries(&upstream, CANARY),
        "alice's call must never carry bob's value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_values_are_refused_with_400_and_never_sent_back() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let session = session_on(&w, SLUG, &tokens).await;

    let bad = [
        (
            "a value of 4097 bytes",
            format!("{CANARY}{}", "a".repeat(4097 - CANARY.len())),
        ),
        ("a value holding a CR", format!("{CANARY}\rnext")),
        ("a value holding an LF", format!("{CANARY}\nnext")),
        ("a value holding byte 0x7f", format!("{CANARY}\u{7f}")),
        ("a non-ASCII value", format!("{CANARY}caf\u{e9}")),
    ];
    for (what, value) in &bad {
        let page = store_value(&bob, SLUG, &hid, value).await;
        assert_eq!(page.status, 400, "{what} must be refused with 400");
        assert_eq!(page.count(NOTICE), 1, "{what} must show one error notice");
        assert!(
            !page.body.contains(CANARY),
            "{what}: the refusal must not send the value back"
        );
    }

    let blank = store_value(&bob, SLUG, &hid, "   ").await;
    assert_eq!(
        blank.status, 303,
        "a value empty after trimming keeps the stored one"
    );
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "refused values must leave the stored value as it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unassigned_server_and_a_server_with_the_switch_off_answer_404_on_the_values_route() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;

    let (_other, other_id) = w.upstream("other", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &other_id, HEADER, false).await;
    switches_ok(&w.owner, &other_id, false, true).await;
    let other_header = header_of(&w.owner, &other_id, HEADER).await;
    let page = store_value(&bob, "other", &other_header, OTHER).await;
    assert_eq!(
        page.status, 404,
        "a server the user is not assigned to must answer 404"
    );

    switches_ok(&w.owner, &id, false, false).await;
    let page = store_value(&bob, SLUG, &hid, OTHER).await;
    assert_eq!(
        page.status, 404,
        "a server with the store switch off must answer 404"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_server_page_shows_how_many_users_stored_a_value_and_never_the_value() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let page = w.owner.get(&server_path(&id)).await;
    assert_eq!(
        page.count(&format!(r#"tr[data-header="{LOWER}"][data-stored="1"]"#)),
        1,
        "one user with a value must be shown as data-stored 1"
    );

    let alice = w.user(ALICE).await;
    w.grant(ALICE, &[&id]).await;
    store_ok(&alice, SLUG, &hid, OTHER).await;
    let page = w.owner.get(&server_path(&id)).await;
    assert_eq!(
        page.count(&format!(r#"tr[data-header="{LOWER}"][data-stored="2"]"#)),
        1,
        "two users with a value must be shown as data-stored 2"
    );
    assert!(
        !page.body.contains(CANARY),
        "the admin page must never show a stored value"
    );
    assert!(
        !page.body.contains(OTHER),
        "the admin page must never show a stored value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_partial_set_of_required_values_reaches_no_upstream_and_names_the_account_page()
 {
    let w = World::start().await;
    let (upstream, id) = add_server_named(&w.owner, "Demo Server", SLUG, true).await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, true).await;
    declare_ok(&w.owner, &id, "X-Region", true).await;
    switches_ok(&w.owner, &id, false, true).await;
    let trace = header_of(&w.owner, &id, HEADER).await;
    store_ok(&bob, SLUG, &trace, CANARY).await;
    upstream.clear();

    let authorized = bob
        .authorize(&w.app(), &w.resource(SLUG), &pkce(), "state-s84")
        .await;
    let location = authorized
        .location()
        .expect("authorize redirects to the consent page");
    let consent = bob.get(&location).await;
    assert_eq!(consent.status, 200, "the consent page must be shown");
    let named = consent.text("[data-needs-values]").unwrap_or_default();
    assert!(
        named.starts_with("This server needs credentials you have not stored yet. After you approve, add them on your account page:"),
        "the consent page must say this server needs credentials, got {named:?}"
    );

    let tokens = w.token(&bob, SLUG).await;
    let stateless = w.stateless_mcp(SLUG, &tokens);
    let refused = stateless_call(&stateless, "echo", &[]).await;
    assert_eq!(
        refused.status, 200,
        "a partial set is a tool error on the server path, never 401 or 403"
    );
    let message = refused.text().unwrap_or_default();
    assert!(
        message.contains(&format!("{}/account", w.base())),
        "the refusal must name the account page, got {message:?}"
    );
    let session = w.session_mcp(SLUG, &tokens);
    let refused = session.initialize().await;
    assert_eq!(
        refused.status, 200,
        "a partial set is answered by the gateway on initialize"
    );
    assert!(
        upstream.requests().is_empty(),
        "no request may reach the upstream on the server path"
    );

    let combined_tokens = w.token(&bob, "mcp").await;
    let combined = session_on(&w, "mcp", &combined_tokens).await;
    upstream.clear();
    let listed = combined.list_tools().await;
    assert_eq!(listed.status, 200, "the combined tool list must answer 200");
    assert!(
        listed.tool_names().iter().any(|name| name == "demo__echo"),
        "the server with missing values is listed from its stored catalog"
    );
    assert!(
        upstream.requests().is_empty(),
        "no request may reach the upstream on /mcp"
    );

    assert_eq!(
        needs_values(&bob, SLUG).await.as_deref(),
        Some("yes"),
        "the account page must say the server needs values"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_copy_of_the_database_log_and_key_holds_no_value_and_opens_only_through_the_real_token() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let owner_id = user_number(&w, OWNER_EMAIL).await;
    let bob_id = user_number(&w, BOB).await;
    let header_no = number(&hid);

    let (dir, conn, keys) = copy_store(&w);
    for file in copied_files(&dir) {
        assert!(
            !file_contains(&file, CANARY.as_bytes()),
            "the canary must be in no copied file, found in {}",
            file.display()
        );
    }
    let key = token_data_key(&conn, &keys, "access_tokens", &tokens.access_token)
        .expect("positive control: the real access token opens its wrap");
    let value = open_sealed(&key, &sealed_of(&conn, bob_id, header_no))
        .expect("positive control: the data key opens the stored value");
    assert_eq!(
        value.as_slice(),
        CANARY.as_bytes(),
        "the stored value must open to the canary"
    );

    let wraps = token_wraps(&conn);
    let strings = stored_strings(&conn);
    assert!(
        strings.iter().all(|text| !text.contains(CANARY)),
        "the canary must be stored in no row"
    );
    for (index, text) in strings.iter().enumerate() {
        for prefix in ["", "dw_ss_", "dw_ac_", "dw_at_", "dw_rt_"] {
            let candidate = format!("{prefix}{text}");
            assert!(
                !any_wrap_opens(&keys, &wraps, &candidate),
                "stored string #{index} with prefix {prefix:?} must open no wrap"
            );
        }
    }

    assert!(
        password_opens(&keys, &conn, bob_id, PASSWORD).is_ok(),
        "positive control: the password opens the password wrap"
    );
    for user in [owner_id, bob_id] {
        for (index, text) in strings.iter().enumerate() {
            assert!(
                password_opens(&keys, &conn, user, text).is_err(),
                "stored string #{index} as a password must open no password wrap"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrap_or_value_moved_to_another_row_user_generation_server_header_or_address_does_not_open()
 {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let owner_id = user_number(&w, OWNER_EMAIL).await;
    let bob_id = user_number(&w, BOB).await;
    let header_no = number(&hid);

    let (_dir, conn, keys) = copy_store(&w);
    let own = token_wraps(&conn)
        .into_iter()
        .find(|wrap| wrap.table == "access_tokens" && wrap.row == token_hash(&tokens.access_token))
        .expect("positive control: the access token has its wrap");
    let key = token_data_key(&conn, &keys, "access_tokens", &tokens.access_token)
        .expect("positive control: the wrap opens on its own row");
    let other_row = token_hash(&tokens.refresh_token);
    let moved = [
        (
            "another row",
            Place {
                user: own.user,
                generation: own.generation,
                table: "access_tokens",
                row: other_row.as_str(),
            },
        ),
        (
            "another user",
            Place {
                user: owner_id,
                generation: own.generation,
                table: "access_tokens",
                row: own.row.as_str(),
            },
        ),
        (
            "another generation",
            Place {
                user: own.user,
                generation: own.generation + 1,
                table: "access_tokens",
                row: own.row.as_str(),
            },
        ),
        (
            "another table",
            Place {
                user: own.user,
                generation: own.generation,
                table: "sessions",
                row: own.row.as_str(),
            },
        ),
    ];
    for (what, place) in &moved {
        assert!(
            vault::unwrap_with_token(&keys, place, &tokens.access_token, &own.wrap).is_err(),
            "a wrap moved to {what} must not open"
        );
    }

    let sealed = sealed_of(&conn, bob_id, header_no);
    open_sealed(&key, &sealed).expect("positive control: the value opens in its own place");
    let header = sealed.header.as_str();
    let url = sealed.upstream_url.as_str();
    let moved_values = [
        (
            "another user",
            ValuePlace {
                user: owner_id,
                server: sealed.server,
                header,
                generation: sealed.generation,
                upstream_url: url,
            },
        ),
        (
            "another server",
            ValuePlace {
                user: sealed.user,
                server: sealed.server + 1,
                header,
                generation: sealed.generation,
                upstream_url: url,
            },
        ),
        (
            "another header",
            ValuePlace {
                user: sealed.user,
                server: sealed.server,
                header: "x-other",
                generation: sealed.generation,
                upstream_url: url,
            },
        ),
        (
            "another upstream address",
            ValuePlace {
                user: sealed.user,
                server: sealed.server,
                header,
                generation: sealed.generation,
                upstream_url: "http://127.0.0.1:1/elsewhere",
            },
        ),
        (
            "another generation",
            ValuePlace {
                user: sealed.user,
                server: sealed.server,
                header,
                generation: sealed.generation + 1,
                upstream_url: url,
            },
        ),
    ];
    for (what, place) in &moved_values {
        assert!(
            vault::open_value(&key, place, &sealed.sealed).is_err(),
            "a value moved to {what} must not open"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn swapping_two_users_sealed_rows_in_the_live_database_gives_neither_the_others_value() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let alice = w.user(ALICE).await;
    w.grant(ALICE, &[&id]).await;
    store_ok(&alice, SLUG, &hid, OTHER).await;
    let bob_session = session_on(&w, SLUG, &w.token(&bob, SLUG).await).await;
    let alice_session = session_on(&w, SLUG, &w.token(&alice, SLUG).await).await;

    upstream.clear();
    session_call(&bob_session, "echo", &[]).await;
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "before the swap bob's call carries bob's value"
    );
    upstream.clear();
    session_call(&alice_session, "echo", &[]).await;
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(OTHER.to_string())],
        "before the swap alice's call carries alice's value"
    );

    let bob_id = user_number(&w, BOB).await;
    let alice_id = user_number(&w, ALICE).await;
    let header_no = number(&hid);
    let live = live_db(&w);
    let sealed_text = |user: i64| -> String {
        live.query_row(
            "SELECT sealed FROM user_header_values WHERE user_id = ?1 AND header_id = ?2",
            params![user, header_no],
            |row| row.get(0),
        )
        .expect("the user has a stored value")
    };
    let bob_sealed = sealed_text(bob_id);
    let alice_sealed = sealed_text(alice_id);
    live.execute(
        "UPDATE user_header_values SET sealed = ?1 WHERE user_id = ?2 AND header_id = ?3",
        params![alice_sealed, bob_id, header_no],
    )
    .expect("bob's row takes alice's sealed value");
    live.execute(
        "UPDATE user_header_values SET sealed = ?1 WHERE user_id = ?2 AND header_id = ?3",
        params![bob_sealed, alice_id, header_no],
    )
    .expect("alice's row takes bob's sealed value");

    upstream.clear();
    session_call(&bob_session, "echo", &[]).await;
    assert!(
        !any_request_carries(&upstream, OTHER),
        "after the swap bob's call must never carry alice's value"
    );
    upstream.clear();
    session_call(&alice_session, "echo", &[]).await;
    assert!(
        !any_request_carries(&upstream, CANARY),
        "after the swap alice's call must never carry bob's value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_copy_taken_afterwards_opens_a_redeemed_code_a_rotated_token_a_signed_out_session_or_a_disconnected_app()
 {
    let mut w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    w.gw.cimd()
        .put(OTHER_APP_ID, OTHER_APP_NAME, &[APP_REDIRECT]);
    let app = w.app();
    let other = OAuthApp {
        client_id: OTHER_APP_ID.into(),
        redirect_uri: APP_REDIRECT.into(),
    };
    let resource = w.resource(SLUG);

    let (code, verifier) = code_for(&bob, &app, &resource).await;
    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        opens_own_row(&conn, &keys, "auth_codes", &code),
        "positive control: the code opens its wrap before redemption"
    );
    let issued = bob
        .token_code(&app, &code, &verifier.verifier, Some(&resource))
        .await;
    let first = client::tokens(&issued).expect("the code exchange issues a pair");
    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        !opens_any_row(&conn, &keys, &code),
        "a redeemed code must open no wrap"
    );

    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        opens_own_row(&conn, &keys, "refresh_tokens", &first.refresh_token),
        "positive control: the refresh token opens its wrap before rotation"
    );
    let rotated_reply = bob
        .token_refresh(&app, &first.refresh_token, Some(&resource))
        .await;
    let rotated = client::tokens(&rotated_reply).expect("the refresh rotates the pair");
    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        !opens_any_row(&conn, &keys, &first.refresh_token),
        "a rotated refresh token must open no wrap"
    );

    let family_two = bob.connect(&other, &resource).await;
    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        opens_own_row(&conn, &keys, "access_tokens", &rotated.access_token),
        "positive control: the access token opens its wrap before the disconnect"
    );
    assert!(
        opens_own_row(&conn, &keys, "refresh_tokens", &rotated.refresh_token),
        "positive control: the refresh token opens its wrap before the disconnect"
    );
    let family = bob
        .get("/account")
        .await
        .attr(
            &format!(r#"tr[data-client-name="{APP_NAME}"]"#),
            "data-family",
        )
        .expect("the first app is listed on the account page");
    let disconnected = bob
        .submit(
            "/account",
            &format!("/account/clients/{family}/disconnect"),
            &[],
        )
        .await;
    assert_eq!(
        disconnected.status, 303,
        "disconnecting the app must redirect"
    );

    let cookie = bob
        .cookie(SESSION_COOKIE)
        .expect("bob's browser holds a session cookie");
    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        opens_own_row(&conn, &keys, "sessions", &cookie),
        "positive control: the session cookie opens its wrap before sign-out"
    );
    let signed_out = bob.logout().await;
    assert_eq!(signed_out.status, 303, "signing out must redirect");

    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        opens_own_row(&conn, &keys, "access_tokens", &family_two.access_token),
        "positive control: the second app's access token opens its wrap before expiry"
    );
    w.gw.clock.advance(time::Duration::days(1));
    w.gw.restart().await;
    wait_for_sweep(&w, &family_two.access_token).await;

    let (_dir, conn, keys) = copy_store(&w);
    let spent = [
        ("the redeemed code", code.as_str()),
        ("the rotated refresh token", first.refresh_token.as_str()),
        (
            "the disconnected access token",
            rotated.access_token.as_str(),
        ),
        (
            "the disconnected refresh token",
            rotated.refresh_token.as_str(),
        ),
        ("the signed-out session cookie", cookie.as_str()),
        ("the expired access token", family_two.access_token.as_str()),
    ];
    for (what, token) in spent {
        assert!(
            !opens_any_row(&conn, &keys, token),
            "{what} must open no wrap in a copy taken afterwards"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_password_change_old_tokens_open_nothing_and_new_connections_get_the_values() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let bob_id = user_number(&w, BOB).await;

    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        opens_own_row(&conn, &keys, "access_tokens", &tokens.access_token),
        "positive control: the access token opens its wrap before the password change"
    );

    let changed = bob.change_password(PASSWORD, NEW_PASSWORD).await;
    assert_eq!(changed.status, 303, "the password change must redirect");
    let (_dir, conn, keys) = copy_store(&w);
    assert!(
        !opens_any_row(&conn, &keys, &tokens.access_token),
        "an old access token must open no wrap"
    );
    assert!(
        !opens_any_row(&conn, &keys, &tokens.refresh_token),
        "an old refresh token must open no wrap"
    );
    let left = token_wraps(&conn)
        .iter()
        .filter(|wrap| wrap.user == bob_id && wrap.table != "sessions")
        .count();
    assert_eq!(left, 0, "no wrap may remain on bob's code and token rows");
    let old = stateless_call(&w.stateless_mcp(SLUG, &tokens), "echo", &[]).await;
    assert_eq!(
        old.status, 401,
        "an old token must be refused after the password change"
    );

    let relogin = bob.login(BOB, NEW_PASSWORD).await;
    assert_eq!(
        relogin.status, 303,
        "bob must sign in with the new password"
    );
    let fresh = w.token(&bob, SLUG).await;
    let session = session_on(&w, SLUG, &fresh).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the stored values must reach the upstream for a newly connected app"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_wrap_copied_before_a_change_does_not_open_values_stored_after_it() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let bob_id = user_number(&w, BOB).await;
    let header_no = number(&hid);

    let (_dir, before, keys) = copy_store(&w);
    let old_key = password_opens(&keys, &before, bob_id, PASSWORD)
        .expect("positive control: the password opens the data key before the change");
    let old_value = open_sealed(&old_key, &sealed_of(&before, bob_id, header_no))
        .expect("positive control: the old key opens the value stored before the change");
    assert_eq!(
        old_value.as_slice(),
        CANARY.as_bytes(),
        "the old key must open the earlier value"
    );

    let changed = bob.change_password(PASSWORD, NEW_PASSWORD).await;
    assert_eq!(changed.status, 303, "the password change must redirect");
    let relogin = bob.login(BOB, NEW_PASSWORD).await;
    assert_eq!(
        relogin.status, 303,
        "bob must sign in with the new password"
    );
    store_ok(&bob, SLUG, &hid, OTHER).await;

    let (_dir, after, _keys) = copy_store(&w);
    assert!(
        open_sealed(&old_key, &sealed_of(&after, bob_id, header_no)).is_err(),
        "the password wrap copied before the change must not open a value stored after it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_reset_by_mail_the_values_are_gone_and_the_old_password_opens_nothing() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let bob_id = user_number(&w, BOB).await;
    let header_no = number(&hid);

    let (_dir, before, keys) = copy_store(&w);
    let old_key = password_opens(&keys, &before, bob_id, PASSWORD)
        .expect("positive control: the old password opens the data key");
    let old_value = open_sealed(&old_key, &sealed_of(&before, bob_id, header_no))
        .expect("positive control: the old password opens the stored value");
    assert_eq!(
        old_value.as_slice(),
        CANARY.as_bytes(),
        "the old password must open the value"
    );

    let anonymous = w.client();
    let requested = request_reset(&anonymous, BOB).await;
    assert_eq!(
        requested.status, 200,
        "a reset request must be answered 200"
    );
    let link = reset_link(&w, BOB).await;
    let form = anonymous.get(&link).await;
    assert!(
        form.body.contains(DROPPED_SENTENCE),
        "the reset page must say that a reset deletes the stored credentials"
    );
    let done = anonymous.reset_password(&link, NEW_PASSWORD).await;
    assert_eq!(done.status, 303, "completing the reset must redirect");

    let (_dir, after, keys) = copy_store(&w);
    assert_eq!(
        count_for(
            &after,
            "SELECT COUNT(*) FROM user_header_values WHERE user_id = ?1",
            bob_id
        ),
        0,
        "a reset must delete the user's stored values"
    );
    assert!(
        password_opens(&keys, &after, bob_id, PASSWORD).is_err(),
        "the old password must open nothing after a reset"
    );
    let refused = w.client().login(BOB, PASSWORD).await;
    assert_eq!(refused.status, 401, "the old password must be refused");

    let again = w.client();
    let signed_in = again.login(BOB, NEW_PASSWORD).await;
    assert_eq!(signed_in.status, 303, "the new password must sign in");
    assert_eq!(
        value_state(&again, SLUG, LOWER).await.as_deref(),
        Some("unset"),
        "the value must show as unset after a reset"
    );

    let rows = admin::activity(&w.owner, None, None).await;
    assert!(
        rows.iter()
            .any(|row| row.kind == "values_dropped" && row.user == BOB),
        "the reset must write a values_dropped activity row for bob"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn after_disable_and_enable_old_tokens_carry_no_wrap_and_values_work_after_sign_in() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let bob_id = user_number(&w, BOB).await;
    let bob_user = w.user_id(BOB).await;

    let (_dir, before, keys) = copy_store(&w);
    assert!(
        opens_own_row(&before, &keys, "access_tokens", &tokens.access_token),
        "positive control: the access token opens its wrap before disable"
    );

    let disabled = admin::user_action(&w.owner, &bob_user, "disable").await;
    assert_eq!(disabled.status, 303, "disabling bob must redirect");
    let (_dir, after, keys) = copy_store(&w);
    assert!(
        !opens_any_row(&after, &keys, &tokens.access_token),
        "an old access token must open no wrap after disable"
    );
    assert!(
        !opens_any_row(&after, &keys, &tokens.refresh_token),
        "an old refresh token must open no wrap after disable"
    );
    let left = token_wraps(&after)
        .iter()
        .filter(|wrap| wrap.user == bob_id && wrap.table != "sessions")
        .count();
    assert_eq!(
        left, 0,
        "no wrap may remain on bob's code and token rows after disable"
    );

    let enabled = admin::user_action(&w.owner, &bob_user, "enable").await;
    assert_eq!(enabled.status, 303, "enabling bob must redirect");
    let relogin = bob.login(BOB, PASSWORD).await;
    assert_eq!(relogin.status, 303, "bob must sign in again after enable");
    let fresh = w.token(&bob, SLUG).await;
    let session = session_on(&w, SLUG, &fresh).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the values must reach the upstream again after sign-in and a new connection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_refreshes_return_one_pair_and_a_replay_after_the_window_leaves_no_wrap() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let issued = w.token(&bob, SLUG).await;
    let bob_id = user_number(&w, BOB).await;
    let app = w.app();
    let resource = w.resource(SLUG);

    let (first, second) = tokio::join!(
        bob.token_refresh(&app, &issued.refresh_token, Some(&resource)),
        bob.token_refresh(&app, &issued.refresh_token, Some(&resource)),
    );
    let first = client::tokens(&first).expect("the first parallel refresh issues a pair");
    let second = client::tokens(&second).expect("the second parallel refresh issues a pair");
    assert_eq!(
        first.access_token, second.access_token,
        "parallel refreshes must return the same access token"
    );
    assert_eq!(
        first.refresh_token, second.refresh_token,
        "parallel refreshes must return the same refresh token"
    );

    let session = McpClient::session(&resource, Some(&first.access_token));
    let init = session.initialize().await;
    assert_eq!(init.status, 200, "the new access token must initialize");
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the new access token must attach the stored value"
    );

    let (_dir, before, _keys) = copy_store(&w);
    let wraps_before = token_wraps(&before)
        .iter()
        .filter(|wrap| wrap.user == bob_id && wrap.table != "sessions")
        .count();
    assert!(
        wraps_before > 0,
        "positive control: the family holds wraps before the replay"
    );

    w.gw.clock.advance(time::Duration::seconds(60));
    let replay = bob
        .token_refresh(&app, &issued.refresh_token, Some(&resource))
        .await;
    assert_ne!(
        replay.status, 200,
        "a replay after the window must be refused"
    );
    let (_dir, after, _keys) = copy_store(&w);
    let wraps_after = token_wraps(&after)
        .iter()
        .filter(|wrap| wrap.user == bob_id && wrap.table != "sessions")
        .count();
    assert_eq!(
        wraps_after, 0,
        "a replay after the window must leave no wrap on the family's rows"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnecting_one_app_leaves_another_app_of_the_same_user_working_with_the_values() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    w.gw.cimd()
        .put(OTHER_APP_ID, OTHER_APP_NAME, &[APP_REDIRECT]);
    let other = OAuthApp {
        client_id: OTHER_APP_ID.into(),
        redirect_uri: APP_REDIRECT.into(),
    };
    let first = w.token(&bob, SLUG).await;
    let second = bob.connect(&other, &w.resource(SLUG)).await;

    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &second), "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the second app must work before the disconnect"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the second app must carry the value"
    );

    let family = bob
        .get("/account")
        .await
        .attr(
            &format!(r#"tr[data-client-name="{APP_NAME}"]"#),
            "data-family",
        )
        .expect("the first app is listed on the account page");
    let disconnected = bob
        .submit(
            "/account",
            &format!("/account/clients/{family}/disconnect"),
            &[],
        )
        .await;
    assert_eq!(
        disconnected.status, 303,
        "disconnecting the first app must redirect"
    );

    let refused = stateless_call(&w.stateless_mcp(SLUG, &first), "echo", &[]).await;
    assert_eq!(
        refused.status, 401,
        "the disconnected app's token must be refused"
    );

    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &second), "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the second app must still be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the second app must still carry the value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_sign_ins_of_a_user_without_a_key_at_the_same_moment_leave_one_key_and_two_sessions() {
    let w = World::start().await;
    let (_upstream, _id, _hid, _bob) = demo_for_bob(&w, false).await;
    let bob_id = user_number(&w, BOB).await;
    let live = live_db(&w);
    live.execute(
        "UPDATE users SET dek_wrap = NULL, dek_salt = NULL WHERE id = ?1",
        [bob_id],
    )
    .expect("the user is made to hold no key, as before the upgrade");

    let first = w.client();
    let second = w.client();
    let (a, b) = tokio::join!(first.login(BOB, PASSWORD), second.login(BOB, PASSWORD));
    assert_eq!(a.status, 303, "the first sign-in must succeed");
    assert_eq!(b.status, 303, "the second sign-in must succeed");
    assert_eq!(
        first.get("/account").await.status,
        200,
        "the first browser must be signed in"
    );
    assert_eq!(
        second.get("/account").await.status,
        200,
        "the second browser must be signed in"
    );

    let (_dir, conn, keys) = copy_store(&w);
    let held = count_for(
        &conn,
        "SELECT COUNT(*) FROM users WHERE id = ?1 AND dek_wrap IS NOT NULL",
        bob_id,
    );
    assert_eq!(
        held, 1,
        "exactly one password wrap of the key must be stored"
    );
    let password_key = password_opens(&keys, &conn, bob_id, PASSWORD)
        .expect("the password wrap opens with the password");
    let (generation, _wrap, _salt) =
        password_wrap(&conn, bob_id).expect("the user holds a password wrap");
    let probe = ValuePlace {
        user: bob_id,
        server: 1,
        header: LOWER,
        generation,
        upstream_url: "https://example.com/probe",
    };
    for cookie in [first.cookie(SESSION_COOKIE), second.cookie(SESSION_COOKIE)] {
        let cookie = cookie.expect("each browser holds a session cookie");
        let session_key = token_data_key(&conn, &keys, "sessions", &cookie)
            .expect("each session holds a wrap of the key");
        let sealed =
            vault::seal_value(&session_key, &probe, b"probe").expect("the session's key seals");
        let opened = vault::open_value(&password_key, &probe, &sealed)
            .expect("the password's key opens what the session's key sealed");
        assert_eq!(
            opened.as_slice(),
            b"probe",
            "both sessions must hold the same key"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn with_every_wrap_damaged_sign_in_consent_exchange_and_refresh_still_work_and_values_say_reconnect()
 {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let issued = w.token(&bob, SLUG).await;
    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &issued), "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered before the damage"
    );

    let live = live_db(&w);
    for sql in [
        "UPDATE users SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
        "UPDATE sessions SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
        "UPDATE auth_codes SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
        "UPDATE access_tokens SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
        "UPDATE refresh_tokens SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
    ] {
        live.execute(sql, [])
            .expect("the wrap is replaced by garbage");
    }

    let signed_in = bob.login(BOB, PASSWORD).await;
    assert_eq!(
        signed_in.status, 303,
        "a damaged wrap must not fail sign-in"
    );
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let fresh = bob.connect(&w.app(), &w.resource(SLUG)).await;
    let refreshed_reply = bob
        .token_refresh(&w.app(), &issued.refresh_token, Some(&w.resource(SLUG)))
        .await;
    assert_eq!(
        refreshed_reply.status, 200,
        "a damaged wrap must not fail a refresh"
    );
    let refreshed = client::tokens(&refreshed_reply).expect("the refresh issues a pair");

    upstream.clear();
    let healed = stateless_call(&w.stateless_mcp(SLUG, &fresh), "echo", &[]).await;
    assert_eq!(
        healed.text().as_deref(),
        Some("called: echo"),
        "the sign-in healed the key, so the new connection carries the stored value again"
    );
    for (what, token) in [
        ("the old token", &issued),
        ("the refreshed pair", &refreshed),
    ] {
        let refused = stateless_call(&w.stateless_mcp(SLUG, token), "echo", &[]).await;
        assert_eq!(
            refused.status, 200,
            "{what} is answered by the gateway when its key cannot open, never 401 or 403"
        );
        assert_eq!(
            refused.result().and_then(|result| result.get("isError")),
            Some(&serde_json::json!(true))
        );
        let message = refused.text().unwrap_or_default();
        assert!(
            message.contains("Reconnect this app"),
            "{what} must say Reconnect this app, got {message:?}"
        );
    }
    assert_eq!(
        upstream.requests().len(),
        1,
        "the only request that reaches the upstream is the healed connection's call"
    );
    assert_eq!(upstream.calls_to("echo"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_upstream_address_in_the_panel_deletes_every_users_values() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let session = session_on(&w, SLUG, &w.token(&bob, SLUG).await).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered before the change"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the old upstream must carry the value first"
    );

    let moved = FakeUpstream::start(UpstreamOptions {
        require_header: Some((SECRET_HEADER.into(), secret_for(SLUG))),
        ..Default::default()
    })
    .await;
    let url = moved.url();
    let changed = admin::update_server(
        &w.owner,
        &id,
        &ServerSpec {
            name: SLUG,
            slug: SLUG,
            upstream_url: &url,
            secret: Some((SECRET_HEADER, secret_for(SLUG).as_str())),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    assert_eq!(
        changed.status, 303,
        "changing the upstream address must be accepted"
    );

    let live = live_db(&w);
    let left: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM user_header_values v JOIN server_headers h ON h.id = v.header_id \
             WHERE h.server_id = ?1",
            [number(&id)],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(
        left, 0,
        "changing the address must delete every user's values for the server"
    );
    assert_eq!(
        value_state(&bob, SLUG, LOWER).await.as_deref(),
        Some("unset"),
        "the account page must show the value as unset"
    );

    let fresh = w.token(&bob, SLUG).await;
    moved.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &fresh), "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered at the new address"
    );
    assert!(
        !moved.requests().is_empty(),
        "the new upstream must be contacted"
    );
    assert!(
        !any_request_carries(&moved, CANARY),
        "the canary must never reach the new upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn editing_the_upstream_address_in_the_database_keeps_the_canary_from_the_new_upstream() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let session = session_on(&w, SLUG, &w.token(&bob, SLUG).await).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered before the edit"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the old upstream must carry the value first"
    );

    let moved = FakeUpstream::start(UpstreamOptions {
        require_header: Some((SECRET_HEADER.into(), secret_for(SLUG))),
        ..Default::default()
    })
    .await;
    let live = live_db(&w);
    live.execute(
        "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
        params![moved.url(), number(&id)],
    )
    .expect("the database edit of the address is made");

    let fresh = w.token(&bob, SLUG).await;
    moved.clear();
    let refused = stateless_call(&w.stateless_mcp(SLUG, &fresh), "echo", &[]).await;
    assert_eq!(
        refused.status, 200,
        "a value sealed for the old address does not open, so the gateway answers with a tool error"
    );
    assert!(
        refused
            .text()
            .unwrap_or_default()
            .contains("cannot be opened"),
        "the refusal must say the stored credentials cannot be opened"
    );
    assert!(
        moved.requests().is_empty(),
        "the new upstream must see no request at all"
    );
    assert!(
        !any_request_carries(&moved, CANARY),
        "the canary must never reach the new upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_declared_header_deletes_its_stored_values() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let live = live_db(&w);
    let header_no = number(&hid);
    let stored: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM user_header_values WHERE header_id = ?1",
            [header_no],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(stored, 1, "the value must be stored before the removal");

    let removed = remove_header(&w.owner, &id, &hid).await;
    assert_eq!(removed.status, 303, "removing the header must be accepted");
    let left: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM user_header_values WHERE header_id = ?1",
            [header_no],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(
        left, 0,
        "removing a declared header must delete its stored values"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigning_a_user_deletes_that_users_values_for_the_server_and_nobody_elses() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let alice = w.user(ALICE).await;
    w.grant(ALICE, &[&id]).await;
    store_ok(&alice, SLUG, &hid, OTHER).await;
    let bob_id = user_number(&w, BOB).await;
    let alice_id = user_number(&w, ALICE).await;
    let header_no = number(&hid);
    let live = live_db(&w);
    let count = |user: i64| -> i64 {
        live.query_row(
            "SELECT COUNT(*) FROM user_header_values WHERE user_id = ?1 AND header_id = ?2",
            params![user, header_no],
            |row| row.get(0),
        )
        .expect("the count reads")
    };
    assert_eq!(
        count(bob_id),
        1,
        "bob's value must be stored before the unassignment"
    );
    assert_eq!(
        count(alice_id),
        1,
        "alice's value must be stored before the unassignment"
    );

    let alice_user = w.user_id(ALICE).await;
    let page = admin::assign_users(&w.owner, &id, &[alice_user.as_str()]).await;
    assert_eq!(page.status, 303, "unassigning bob must be accepted");
    assert_eq!(
        count(bob_id),
        0,
        "unassigning bob must delete bob's values for the server"
    );
    assert_eq!(
        count(alice_id),
        1,
        "unassigning bob must leave alice's values"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_server_deletes_every_stored_value() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let live = live_db(&w);
    let stored: i64 = live
        .query_row("SELECT COUNT(*) FROM user_header_values", [], |row| {
            row.get(0)
        })
        .expect("the count reads");
    assert_eq!(
        stored, 1,
        "the value must be stored before the server is deleted"
    );

    let deleted = admin::delete_server(&w.owner, &id).await;
    assert_eq!(deleted.status, 303, "deleting the server must be accepted");
    let left: i64 = live
        .query_row("SELECT COUNT(*) FROM user_header_values", [], |row| {
            row.get(0)
        })
        .expect("the count reads");
    assert_eq!(
        left, 0,
        "deleting the server must delete every stored value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_echoes_the_header_puts_the_canary_in_no_activity_row_or_admin_or_account_page()
 {
    let w = World::start().await;
    let (_upstream, id) = w
        .upstream(
            SLUG,
            UpstreamOptions {
                mode: Mode::EchoHeader(LOWER.to_string()),
                ..Default::default()
            },
        )
        .await;
    let bob = w.user(BOB).await;
    w.grant(BOB, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = header_of(&w.owner, &id, HEADER).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let session = session_on(&w, SLUG, &w.token(&bob, SLUG).await).await;

    let reply = session_call(&session, "echo", &[]).await;
    assert!(
        reply.text().is_some_and(|text| text.contains(CANARY)),
        "positive control: the upstream must echo the value back in its answer"
    );

    for (row, detail) in admin::activity_with_details(&w.owner, None, None).await {
        let text = format!("{row:?} {detail}");
        assert!(
            !text.contains(CANARY),
            "no activity row may hold the canary, row was {text}"
        );
    }
    assert!(
        !w.owner.get("/admin/activity").await.body.contains(CANARY),
        "the activity page must not show the canary"
    );
    assert!(
        !w.owner.get(&server_path(&id)).await.body.contains(CANARY),
        "the server page must not show the canary"
    );
    assert!(
        !bob.get("/account").await.body.contains(CANARY),
        "the account page must not show the canary"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn storing_replacing_and_removing_a_value_each_write_an_activity_row_without_the_value() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    store_ok(&bob, SLUG, &hid, OTHER).await;
    let removed = remove_value(&bob, SLUG, &hid).await;
    assert_eq!(removed.status, 303, "removing the value must redirect");

    let rows = admin::activity_with_details(&w.owner, None, None).await;
    let sets: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "value_set")
        .collect();
    let removals: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "value_removed")
        .collect();
    assert_eq!(
        sets.len(),
        2,
        "storing and replacing must each write a value_set row"
    );
    assert_eq!(
        removals.len(),
        1,
        "removing must write one value_removed row"
    );
    for (row, detail) in sets.iter().chain(removals.iter()) {
        assert_eq!(row.server, SLUG, "the row must name the server");
        assert_eq!(row.user, BOB, "the row must name the user");
        assert!(
            detail.to_ascii_lowercase().contains(LOWER),
            "the row must name the header, got {detail:?}"
        );
        assert!(
            !detail.contains(CANARY) && !detail.contains(OTHER),
            "the row must never hold a value, got {detail:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lock_down_check_and_refresh_by_an_admin_with_no_value_carry_no_user_header_and_with_a_value_carry_it()
 {
    let w = World::start().await;
    let (upstream, id) = w.upstream(SLUG, UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = header_of(&w.owner, &id, HEADER).await;
    let admin_browser = w.admin(ADMIN).await;
    w.grant(ADMIN, &[&id]).await;
    store_ok(&admin_browser, SLUG, &hid, CANARY).await;
    let removed = remove_value(&admin_browser, SLUG, &hid).await;
    assert_eq!(removed.status, 303, "the admin's value must be removed");

    upstream.clear();
    let locked = admin::check_lockdown(&admin_browser, &id).await;
    assert_eq!(locked.status, 303, "the lock-down check must be accepted");
    let refreshed = admin::refresh_tools(&admin_browser, &id).await;
    assert_eq!(refreshed.status, 303, "the refresh must be accepted");
    assert!(
        !upstream.requests().is_empty(),
        "the lock-down check and refresh must reach the upstream"
    );
    assert!(
        upstream
            .requests()
            .iter()
            .all(|request| request.header(LOWER).is_none()),
        "an admin with no stored value must send no user header"
    );

    store_ok(&admin_browser, SLUG, &hid, CANARY).await;
    upstream.clear();
    let refreshed = admin::refresh_tools(&admin_browser, &id).await;
    assert_eq!(refreshed.status, 303, "the refresh must be accepted");
    let listing: Vec<_> = upstream
        .requests()
        .into_iter()
        .filter(|request| request.rpc_method.as_deref() == Some("tools/list"))
        .collect();
    assert!(
        !listing.is_empty(),
        "the refresh must list the tools on the upstream"
    );
    assert!(
        listing
            .iter()
            .all(|request| request.header(LOWER) == Some(CANARY)),
        "a refresh by an admin with a stored value must carry that admin's value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_redirect_is_not_followed_and_the_redirect_target_sees_no_request() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let target = FakeUpstream::start(UpstreamOptions::default()).await;
    upstream.set_mode(Mode::Redirect(target.url()));
    let tokens = w.token(&bob, SLUG).await;

    let _ = stateless_call(&w.stateless_mcp(SLUG, &tokens), "echo", &[]).await;
    assert!(
        any_request_carries(&upstream, CANARY),
        "positive control: the redirecting upstream must receive the stored value"
    );
    assert!(
        target.requests().is_empty(),
        "the redirect target must see no request"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_replace_the_next_call_carries_the_new_value_and_an_old_session_is_refused_404() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let old_session = session_on(&w, SLUG, &tokens).await;
    upstream.clear();
    let reply = session_call(&old_session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the call must be answered before the replace"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CANARY.to_string())],
        "the call must carry the first value"
    );

    store_ok(&bob, SLUG, &hid, OTHER).await;
    upstream.clear();
    let refused = session_call(&old_session, "echo", &[]).await;
    assert_eq!(
        refused.status, 404,
        "a session issued under the old value must be refused with 404"
    );
    assert!(
        upstream.requests().is_empty(),
        "a refused session must not reach the upstream"
    );

    let fresh = session_on(&w, SLUG, &tokens).await;
    upstream.clear();
    let reply = session_call(&fresh, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the new session must be answered"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(OTHER.to_string())],
        "the next call must carry the replaced value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_credentials_lands_on_the_part_with_the_server_named_in_the_notice() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, true).await;
    let saved = store_value(&bob, SLUG, &hid, CANARY).await;
    assert_eq!(saved.status, 303, "storing a value must be accepted");
    assert_eq!(saved.query("done").as_deref(), Some("credentials-saved"));
    assert_eq!(saved.query("server").as_deref(), Some(SLUG));
    assert!(
        saved
            .location()
            .unwrap_or_default()
            .ends_with("#values-title"),
        "the redirect must land on the credentials part"
    );
    let shown = bob.follow(&saved).await;
    assert_eq!(
        shown.text(r#"div.notice[data-notice="ok"] > p"#).as_deref(),
        Some("Credentials saved for demo."),
        "the notice must name the server by its name"
    );
    assert!(
        !shown.body.contains(CANARY),
        "the notice and the page must never show the stored value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_saved_notice_is_the_first_child_of_that_servers_block_and_shown_once() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, true).await;
    let saved = store_value(&bob, SLUG, &hid, CANARY).await;
    let shown = bob.follow(&saved).await;
    assert_eq!(
        shown.count(&format!(
            r#"section[data-values-server="{SLUG}"] > div.notice[data-notice="ok"]:first-child"#
        )),
        1,
        "the saved notice must be the first child of the server's block"
    );
    assert_eq!(
        shown.count(r#"div.notice[data-notice="ok"]"#),
        1,
        "the saved notice must be rendered once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_saved_notice_counts_the_required_credentials_still_missing() {
    let w = World::start().await;
    let (_upstream, id, first, bob) = demo_for_bob(&w, true).await;
    declare_ok(&w.owner, &id, "X-Region", true).await;
    declare_ok(&w.owner, &id, "X-Tenant", true).await;
    let second = header_of(&w.owner, &id, "X-Region").await;
    let third = header_of(&w.owner, &id, "X-Tenant").await;

    let saved = store_value(&bob, SLUG, &first, CANARY).await;
    let shown = bob.follow(&saved).await;
    assert_eq!(
        shown.text(r#"div.notice[data-notice="ok"] > p"#).as_deref(),
        Some("Credentials saved for demo. 2 required credentials are still missing."),
        "two required credentials missing must be counted in the plural"
    );

    let saved = store_value(&bob, SLUG, &second, OTHER).await;
    let shown = bob.follow(&saved).await;
    assert_eq!(
        shown.text(r#"div.notice[data-notice="ok"] > p"#).as_deref(),
        Some("Credentials saved for demo. 1 required credential is still missing."),
        "one required credential missing must take the singular"
    );

    let saved = store_value(&bob, SLUG, &third, "tenant-1").await;
    let shown = bob.follow(&saved).await;
    assert_eq!(
        shown.text(r#"div.notice[data-notice="ok"] > p"#).as_deref(),
        Some("Credentials saved for demo."),
        "with every required credential stored the notice has no missing sentence"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn save_credentials_is_primary_only_while_a_required_credential_is_missing() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, true).await;
    let form = format!(r#"form[action="/account/values/{SLUG}"]"#);
    let page = bob.get("/account").await;
    assert_eq!(
        page.text(&format!(r#"{form} button[data-kind="primary"]"#))
            .as_deref(),
        Some("Save credentials"),
        "a server that needs credentials has the primary Save credentials"
    );
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let page = bob.get("/account").await;
    assert_eq!(
        page.count(&format!(r#"{form} button[data-kind="primary"]"#)),
        0,
        "once nothing is missing Save credentials is secondary"
    );
    assert_eq!(
        page.text(&format!(r#"{form} button[data-kind="secondary"]"#))
            .as_deref(),
        Some("Save credentials"),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_write_only_hint_shows_only_when_a_field_of_the_form_is_stored() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    let hint = "A stored credential is never shown again. Leave a field empty to keep it.";
    let page = bob.get("/account").await;
    assert!(
        !page
            .texts(&format!(r#"form[action="/account/values/{SLUG}"] p.muted"#))
            .iter()
            .any(|text| text == hint),
        "with nothing stored the form must not carry the write-only hint"
    );
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let page = bob.get("/account").await;
    assert!(
        page.texts(&format!(r#"form[action="/account/values/{SLUG}"] p.muted"#))
            .iter()
            .any(|text| text == hint),
        "with a stored field the form must carry the write-only hint"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_whose_key_does_not_open_shows_the_locked_credentials_part() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let live = live_db(&w);
    live.execute(
        "UPDATE sessions SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
        [],
    )
    .expect("the session's wrap is replaced by garbage");
    let page = bob.get("/account").await;
    assert_eq!(page.status, 200, "the account page must still answer 200");
    assert_eq!(
        page.count("[data-values-locked]"),
        1,
        "the locked part must replace the credentials form"
    );
    assert_eq!(
        page.count(r#"input[name^="value_"]"#),
        0,
        "a locked part must hold no credential input"
    );
    let block = page
        .text(r#"[data-values-locked] section[data-values-server="demo"] h3"#)
        .unwrap_or_default();
    assert!(
        block.contains("demo") && block.contains("Credentials stored"),
        "the locked part must name the server and its state, got {block:?}"
    );
    assert_eq!(
        page.text(r#"[data-values-locked] p"#).as_deref(),
        Some("Sign in again to store or change credentials."),
        "the locked part must say to sign in again"
    );
    assert_eq!(
        page.attr(r#"[data-values-locked] form[action="/logout"]"#, "method")
            .as_deref(),
        Some("post"),
        "the sign-out form must post"
    );
    assert_eq!(
        page.text(r#"[data-values-locked] form[action="/logout"] button"#)
            .as_deref(),
        Some("Sign out and sign in again"),
        "the locked part must offer the sign-out button"
    );
}

/// The detail of every tool_call row of the live database, oldest first.
fn tool_call_details(w: &World) -> Vec<String> {
    let live = live_db(w);
    let mut statement = live
        .prepare("SELECT detail FROM activity WHERE kind = 'tool_call' ORDER BY id")
        .expect("the activity query prepares");
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("the activity query runs")
        .map(|row| row.expect("a row reads"))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_combined_call_to_a_left_out_server_says_why_and_is_not_a_connection_failure() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, true).await;
    let combined = session_on(&w, "mcp", &w.token(&bob, "mcp").await).await;
    upstream.clear();

    let missing = session_call(&combined, "demo__echo", &[]).await;
    assert_eq!(missing.status, 200, "a tool error is a 200 answer");
    assert_eq!(
        missing.result().and_then(|result| result.get("isError")),
        Some(&serde_json::json!(true)),
        "the answer must be a tool result with isError true"
    );
    let text = missing.text().unwrap_or_default();
    assert!(
        text.contains("needs your credentials") && text.contains(&format!("{}/account", w.base())),
        "the answer must name the account page, got {text:?}"
    );
    assert!(
        upstream.requests().is_empty(),
        "no request may reach the upstream"
    );
    let details = tool_call_details(&w);
    assert!(
        details.iter().any(|detail| detail == "credentials missing"),
        "the row must say credentials missing, got {details:?}"
    );
    assert!(
        !details
            .iter()
            .any(|detail| detail.contains("no connection")),
        "no row may report a connection failure, got {details:?}"
    );

    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, "mcp").await;
    live_db(&w)
        .execute(
            "UPDATE access_tokens SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
            [],
        )
        .expect("the wrap is replaced by garbage");
    let locked_client = session_on(&w, "mcp", &tokens).await;
    upstream.clear();
    let locked = session_call(&locked_client, "demo__echo", &[]).await;
    assert_eq!(
        locked.result().and_then(|result| result.get("isError")),
        Some(&serde_json::json!(true))
    );
    assert!(
        locked
            .text()
            .unwrap_or_default()
            .contains("Reconnect this app to use demo"),
        "a locked connection must say to reconnect"
    );
    assert!(upstream.requests().is_empty());
    assert!(
        tool_call_details(&w)
            .iter()
            .any(|detail| detail == "reconnect needed"),
        "the row must say reconnect needed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locked_connection_whose_client_passes_the_header_itself_is_served() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    switches_ok(&w.owner, &id, true, true).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    live_db(&w)
        .execute(
            "UPDATE access_tokens SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
            [],
        )
        .expect("the wrap is replaced by garbage");
    let stateless = w.stateless_mcp(SLUG, &tokens);
    upstream.clear();
    let refused = stateless_call(&stateless, "echo", &[]).await;
    assert_eq!(
        refused.status, 200,
        "without the header the call is a tool error"
    );
    assert!(
        refused
            .text()
            .unwrap_or_default()
            .contains("Reconnect this app"),
        "without the header the connection is locked"
    );
    assert!(upstream.requests().is_empty());
    let served = stateless_call(&stateless, "echo", &[(HEADER, CLIENT_VALUE)]).await;
    assert_eq!(
        served.text().as_deref(),
        Some("called: echo"),
        "the client's own header serves the call"
    );
    assert_eq!(
        carried(&upstream, "echo"),
        vec![Some(CLIENT_VALUE.to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_password_wrap_heals_at_the_next_sign_in_and_values_can_be_stored_again() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let live = live_db(&w);
    let generation = |conn: &Connection| -> i64 {
        conn.query_row("SELECT dek_gen FROM users WHERE email = ?1", [BOB], |row| {
            row.get(0)
        })
        .expect("the generation reads")
    };
    let before = generation(&live);
    live.execute(
        "UPDATE users SET dek_wrap = 'garbage' WHERE email = ?1",
        [BOB],
    )
    .expect("the password wrap is replaced by garbage");

    let signed_in = bob.login(BOB, PASSWORD).await;
    assert_eq!(signed_in.status, 303, "the sign-in must still succeed");
    assert_eq!(
        generation(&live),
        before + 1,
        "a new key is one generation up"
    );
    let held: i64 = live
        .query_row("SELECT COUNT(*) FROM user_header_values", [], |row| {
            row.get(0)
        })
        .expect("the count reads");
    assert_eq!(held, 0, "the unreadable values are deleted");
    let dropped: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(dropped, 1, "a values_dropped row names the loss");
    assert_eq!(
        needs_values(&bob, SLUG).await.as_deref(),
        Some("no"),
        "the account page opens the form again"
    );
    store_ok(&bob, SLUG, &hid, OTHER).await;
    let tokens = w.token(&bob, SLUG).await;
    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &tokens), "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(carried(&upstream, "echo"), vec![Some(OTHER.to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_with_a_damaged_password_wrap_but_a_good_session_wrap_keeps_the_values() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    live_db(&w)
        .execute(
            "UPDATE users SET dek_wrap = 'garbage' WHERE email = ?1",
            [BOB],
        )
        .expect("the password wrap is replaced by garbage");

    let changed = bob.change_password(PASSWORD, NEW_PASSWORD).await;
    assert_eq!(changed.status, 303, "the password change must redirect");
    let dropped: i64 = live_db(&w)
        .query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(
        dropped, 0,
        "the session's wrap opened the key, so nothing is dropped"
    );
    let tokens = w.token(&bob, SLUG).await;
    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &tokens), "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(carried(&upstream, "echo"), vec![Some(CANARY.to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_store_switch_off_no_value_is_attached_and_the_user_can_delete_what_was_stored() {
    let w = World::start().await;
    let (upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let live = live_db(&w);
    let stored = |conn: &Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM user_header_values", [], |row| {
            row.get(0)
        })
        .expect("the count reads")
    };

    let csrf = common::values::account_csrf(&bob).await;
    let ignored = bob
        .post(
            &format!("/account/values/{SLUG}"),
            &[("csrf", csrf.as_str()), ("forget", "1")],
        )
        .await;
    assert_eq!(ignored.status, 303);
    assert_eq!(stored(&live), 1, "with the switch on, forget=1 is ignored");

    switches_ok(&w.owner, &id, false, false).await;
    upstream.clear();
    let reply = stateless_call(&w.stateless_mcp(SLUG, &tokens), "echo", &[]).await;
    assert_eq!(reply.text().as_deref(), Some("called: echo"));
    assert_eq!(
        carried(&upstream, "echo"),
        vec![None],
        "with the switch off no stored value is attached"
    );

    let account = bob.get("/account").await;
    assert_eq!(
        account
            .text(r#"section[data-values-retired="demo"] h3 > span.state[data-tone="muted"]"#)
            .as_deref(),
        Some("No longer uses stored credentials"),
        "the retired block's status reads No longer uses stored credentials"
    );
    assert_eq!(
        account.texts(r#"section[data-values-retired="demo"] p.muted"#),
        vec!["This cannot be undone.".to_owned()],
        "the only muted sentence of the block is the one after the button"
    );
    assert_eq!(
        account
            .text(r#"section[data-values-retired="demo"] button[data-kind="danger"]"#)
            .as_deref(),
        Some("Delete my stored credentials")
    );
    assert_eq!(
        account
            .text(r#"section[data-values-retired="demo"] div.confirm-body > p.muted"#)
            .as_deref(),
        Some("This cannot be undone."),
        "the muted sentence sits after the button in the closed disclosure"
    );
    assert_eq!(
        account.count(r#"section[data-values-retired="demo"] details[data-confirm]:not([open])"#),
        1,
        "the delete button sits in a closed disclosure"
    );
    assert_eq!(
        account.count(
            r#"section[aria-labelledby="values-title"] > div.part-body > section[data-values-retired="demo"]"#
        ),
        1,
        "the retired block is in the body of the credentials part, not beside it"
    );
    let csrf = account.csrf().expect("the page carries a csrf field");
    let forgotten = bob
        .post(
            &format!("/account/values/{SLUG}"),
            &[("csrf", csrf.as_str()), ("forget", "1")],
        )
        .await;
    assert_eq!(forgotten.status, 303, "the deletion must redirect");
    assert_eq!(forgotten.location().as_deref(), Some("/account"));
    assert_eq!(stored(&live), 0, "the user's values are gone");
    let removed: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'value_removed'",
            [],
            |row| row.get(0),
        )
        .expect("the count reads");
    assert_eq!(removed, 1, "one value_removed row per value");
    assert_eq!(
        bob.get("/account")
            .await
            .count(r#"section[data-values-retired="demo"]"#),
        0,
        "the block is gone once nothing is held"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_delete_while_the_values_are_locked_is_answered_and_the_session_is_forgotten() {
    let w = World::start().await;
    let (upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let tokens = w.token(&bob, SLUG).await;
    let session = session_on(&w, SLUG, &tokens).await;
    let live = live_db(&w);
    let sessions = |conn: &Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM upstream_sessions", [], |row| {
            row.get(0)
        })
        .expect("the count reads")
    };
    assert_eq!(sessions(&live), 1, "the gateway holds the session");
    live.execute(
        "UPDATE access_tokens SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
        [],
    )
    .expect("the wrap is replaced by garbage");
    upstream.clear();

    let closed = session.delete().await;
    assert_eq!(closed.status, 204, "the close is answered 204");
    assert!(
        upstream.requests().is_empty(),
        "the close must not reach the upstream"
    );
    assert_eq!(sessions(&live), 0, "the session id is forgotten");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_store_ends_the_upstream_sessions_of_that_user_on_that_server() {
    let w = World::start().await;
    let (_upstream, id, hid, bob) = demo_for_bob(&w, false).await;
    let (_other_up, other_id) = w.upstream("other", UpstreamOptions::default()).await;
    let alice = w.user(ALICE).await;
    w.grant(ALICE, &[&id]).await;
    w.grant(BOB, &[&id, &other_id]).await;
    let bob_demo = session_on(&w, SLUG, &w.token(&bob, SLUG).await).await;
    let bob_other = session_on(&w, "other", &w.token(&bob, "other").await).await;
    let alice_demo = session_on(&w, SLUG, &w.token(&alice, SLUG).await).await;
    assert_eq!(
        session_call(&bob_demo, "echo", &[]).await.text().as_deref(),
        Some("called: echo")
    );

    store_ok(&bob, SLUG, &hid, CANARY).await;

    assert_eq!(
        session_call(&bob_demo, "echo", &[]).await.status,
        404,
        "the user's session on that server is ended"
    );
    assert_eq!(
        session_call(&bob_other, "echo", &[])
            .await
            .text()
            .as_deref(),
        Some("called: echo"),
        "the same user's session on another server stays"
    );
    assert_eq!(
        session_call(&alice_demo, "echo", &[])
            .await
            .text()
            .as_deref(),
        Some("called: echo"),
        "another user's session on the same server stays"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_without_the_admins_openable_key_says_the_stored_credentials_were_not_sent() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream(SLUG, UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, false, true).await;
    w.grant(OWNER_EMAIL, &[&id]).await;
    let hid = header_of(&w.owner, &id, HEADER).await;
    store_ok(&w.owner, SLUG, &hid, CANARY).await;
    live_db(&w)
        .execute(
            "UPDATE sessions SET dek_wrap = 'garbage' WHERE dek_wrap IS NOT NULL",
            [],
        )
        .expect("the wrap is replaced by garbage");
    let path = server_path(&id);
    let done = w
        .owner
        .submit(&path, &format!("{path}/refresh-tools"), &[])
        .await;
    assert_eq!(done.status, 303);
    let page = w.owner.follow(&done).await;
    let notice = page
        .text(r#"div.notice[data-notice="warning"]"#)
        .unwrap_or_default();
    assert_eq!(
        notice,
        "Tools refreshed without your stored credentials. Sign out and sign in again to send them."
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_with_a_stored_value_that_does_not_open_says_the_stored_credentials_were_not_sent()
 {
    let w = World::start().await;
    let (_upstream, id) = w.upstream(SLUG, UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, false, true).await;
    w.grant(OWNER_EMAIL, &[&id]).await;
    let hid = header_of(&w.owner, &id, HEADER).await;
    store_ok(&w.owner, SLUG, &hid, CANARY).await;
    let moved = FakeUpstream::start(UpstreamOptions {
        require_header: Some((SECRET_HEADER.into(), secret_for(SLUG))),
        ..Default::default()
    })
    .await;
    live_db(&w)
        .execute(
            "UPDATE servers SET upstream_url = ?1 WHERE id = ?2",
            params![moved.url(), number(&id)],
        )
        .expect("the address is edited in the database");
    let path = server_path(&id);
    let done = w
        .owner
        .submit(&path, &format!("{path}/refresh-tools"), &[])
        .await;
    assert_eq!(done.status, 303);
    let page = w.owner.follow(&done).await;
    assert_eq!(
        page.text(r#"div.notice[data-notice="warning"]"#)
            .unwrap_or_default(),
        "Tools refreshed without your stored credentials. Sign out and sign in again to send them."
    );
    assert!(!any_request_carries(&moved, CANARY));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_saved_notice_shows_only_when_the_query_carries_the_saved_marker() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let bare = bob.get("/account?server=demo").await;
    assert!(!bare.body.contains("Credentials saved for"));
    let marked = bob.get("/account?done=credentials-saved&server=demo").await;
    assert!(marked.body.contains("Credentials saved for demo."));
}

#[tokio::test(flavor = "multi_thread")]
async fn forget_with_the_store_switch_on_does_not_redirect_with_the_saved_notice() {
    let w = World::start().await;
    let (_upstream, _id, hid, bob) = demo_for_bob(&w, false).await;
    store_ok(&bob, SLUG, &hid, CANARY).await;
    let csrf = common::values::account_csrf(&bob).await;
    let page = bob
        .post(
            &format!("/account/values/{SLUG}"),
            &[("csrf", csrf.as_str()), ("forget", "1")],
        )
        .await;
    assert_eq!(page.status, 303);
    let location = page.location().unwrap_or_default();
    assert!(!location.contains("credentials-saved"), "got {location:?}");
}
