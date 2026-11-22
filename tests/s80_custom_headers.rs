mod common;

use common::admin::{self, ServerSpec};
use common::client::{Page, TestClient, Tokens};
use common::headers::{
    add_server_named, declare_header, header_id, received_calls, remove_header, save_headers,
    session_call, set_switches, stateless_call,
};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::values::store_value;
use common::world::World;

const BOB: &str = "bob@example.com";
const HEADER: &str = "X-Trace-Id";
const LOWER: &str = "x-trace-id";
const VALUE: &str = "trace-7f3a";
const NOTICE: &str = r#"div.notice[data-notice="error"][role="alert"]"#;
const DIRECT: &str = "[data-direct-warning]";

fn server_path(id: &str) -> String {
    format!("/admin/servers/{id}")
}

async fn server_page(owner: &TestClient, id: &str) -> Page {
    owner.get(&server_path(id)).await
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

fn assert_refused(page: &Page, what: &str) {
    assert_eq!(page.status, 400, "{what} must be refused with 400");
    assert_eq!(page.count(NOTICE), 1, "{what} must show one error notice");
}

/// Bob, signed in and assigned to every server in `ids`.
async fn grant_bob(w: &World, ids: &[&str]) -> TestClient {
    let bob = w.user(BOB).await;
    w.grant(BOB, ids).await;
    bob
}

/// A session client on `slug`, initialized; the handshake must be answered 200.
async fn session_on(w: &World, slug: &str, tokens: &Tokens) -> McpClient {
    let client = w.session_mcp(slug, tokens);
    let reply = client.initialize().await;
    assert_eq!(reply.status, 200, "initialize on {slug} must be answered");
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_declares_a_header_and_the_page_lists_it_with_its_flag() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, true).await;
    declare_ok(&w.owner, &id, "X-Region", false).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"tr[data-header="x-trace-id"][data-required="yes"]"#),
        1,
        "the required header must be listed with data-required yes"
    );
    assert_eq!(
        page.count(r#"tr[data-header="x-region"][data-required="no"]"#),
        1,
        "the optional header must be listed with data-required no"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ninth_header_is_refused_with_400() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    for i in 1..=8 {
        declare_ok(&w.owner, &id, &format!("X-Custom-{i}"), false).await;
    }
    let page = declare_header(&w.owner, &id, "X-Custom-9", false).await;
    assert_refused(&page, "a ninth header");
    assert_eq!(
        server_page(&w.owner, &id).await.count("tr[data-header]"),
        8,
        "the eight declared headers must remain listed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_refused_name_is_refused_with_400() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let mut names: Vec<String> = [
        "Host",
        "Content-Type",
        "Cookie",
        "User-Agent",
        "Origin",
        "Referer",
        "Last-Event-ID",
        "Forwarded",
        "Via",
        "X-Real-IP",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "Mcp-Session-Id",
        "Mcp-Method",
        "Proxy-Authorization",
        "Proxy-Connection",
        "X Trace",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect();
    names.push(format!("x-{}", "a".repeat(63)));
    assert_eq!(
        names.last().map(String::len),
        Some(65),
        "the long name must be 65 characters"
    );
    for name in &names {
        let page = declare_header(&w.owner, &id, name, false).await;
        assert_refused(&page, &format!("the name {name:?}"));
    }
    assert_eq!(
        server_page(&w.owner, &id).await.count("tr[data-header]"),
        0,
        "no refused name may create a row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_name_in_another_case_is_refused_as_a_duplicate() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let page = declare_header(&w.owner, &id, "x-TRACE-id", false).await;
    assert_refused(&page, "a duplicate name in another case");
    assert_eq!(
        server_page(&w.owner, &id)
            .await
            .count(r#"tr[data-header="x-trace-id"]"#),
        1,
        "the first declaration must remain the only row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_name_and_the_secret_header_name_cannot_be_the_same() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let page = declare_header(&w.owner, &id, "X-Upstream-Secret", false).await;
    assert_refused(&page, "a declared name equal to the secret header name");
    assert_eq!(
        server_page(&w.owner, &id).await.count("tr[data-header]"),
        0,
        "the refused name must create no row"
    );
    declare_ok(&w.owner, &id, "X-App-Key", false).await;
    let url = upstream.url();
    let page = admin::update_server(
        &w.owner,
        &id,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: Some(("X-App-Key", "new-secret-value")),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    assert_eq!(
        page.status, 400,
        "a secret header named like a declared header must be refused with 400"
    );
    assert!(
        page.error().is_some(),
        "the refused secret header must show an error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authorization_can_be_declared() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, "Authorization", false).await;
    assert_eq!(
        server_page(&w.owner, &id)
            .await
            .count(r#"tr[data-header="authorization"][data-required="no"]"#),
        1,
        "Authorization must be listed as a declared header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_header_removes_its_row() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, true).await;
    let hid = header_id(&w.owner, &id, HEADER)
        .await
        .expect("the declared header must have a remove form");
    let page = remove_header(&w.owner, &id, &hid).await;
    assert_eq!(page.status, 303, "removing a header must be accepted");
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(&format!(r#"tr[data-header="{LOWER}"]"#)),
        0,
        "the removed header's row must be gone"
    );
    assert!(
        header_id(&w.owner, &id, HEADER).await.is_none(),
        "the removed header must have no remove form"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_two_switches_are_saved_and_shown_checked() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let (_bare_upstream, bare) = w.upstream("bare", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &bare, true, false).await;
    declare_ok(&w.owner, &bare, HEADER, false).await;
    let page = server_page(&w.owner, &bare).await;
    assert_eq!(
        page.count(r#"input[name="pass_headers"][checked]"#),
        1,
        "a switch saved while the server had no header must be shown checked once a header is declared"
    );
    assert_eq!(
        page.count(r#"input[name="store_headers"][checked]"#),
        0,
        "a switch saved off while the server had no header must stay unchecked"
    );
    switches_ok(&w.owner, &id, true, true).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"input[name="pass_headers"][checked]"#),
        1,
        "pass_headers must be shown checked after saving it on"
    );
    assert_eq!(
        page.count(r#"input[name="store_headers"][checked]"#),
        1,
        "store_headers must be shown checked after saving it on"
    );
    switches_ok(&w.owner, &id, false, true).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"input[name="pass_headers"][checked]"#),
        0,
        "pass_headers must be shown unchecked after saving it off"
    );
    assert_eq!(
        page.count(r#"input[name="store_headers"][checked]"#),
        1,
        "store_headers must stay checked when only pass_headers changes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_admins_declare_remove_and_switch_headers() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let hid = header_id(&w.owner, &id, HEADER)
        .await
        .expect("the declared header must have a remove form");
    let bob = w.user(BOB).await;
    let csrf = bob
        .get("/account")
        .await
        .csrf()
        .expect("the account page carries a csrf token");
    let path = server_path(&id);
    let declared = bob
        .post(
            &format!("{path}/headers"),
            &[
                ("csrf", csrf.as_str()),
                ("name", "X-Other"),
                ("required", "1"),
            ],
        )
        .await;
    assert_eq!(
        declared.status, 403,
        "a plain user declaring a header must answer 403"
    );
    assert_eq!(declared.kind().as_deref(), Some("forbidden"));
    let removed = bob
        .post(
            &format!("{path}/headers/{hid}/remove"),
            &[("csrf", csrf.as_str())],
        )
        .await;
    assert_eq!(
        removed.status, 403,
        "a plain user removing a header must answer 403"
    );
    assert_eq!(removed.kind().as_deref(), Some("forbidden"));
    let switched = bob
        .post(
            &format!("{path}/header-switches"),
            &[
                ("csrf", csrf.as_str()),
                ("pass_headers", "1"),
                ("store_headers", "1"),
            ],
        )
        .await;
    assert_eq!(
        switched.status, 403,
        "a plain user saving the switches must answer 403"
    );
    assert_eq!(switched.kind().as_deref(), Some("forbidden"));
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"tr[data-header="x-other"]"#),
        0,
        "a refused declaration must create no row"
    );
    assert_eq!(
        page.count(&format!(r#"tr[data-header="{LOWER}"]"#)),
        1,
        "a refused removal must keep the row"
    );
    assert_eq!(
        page.count(r#"input[name="pass_headers"][checked]"#)
            + page.count(r#"input[name="store_headers"][checked]"#),
        0,
        "a refused switch save must leave both switches off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pass_through_reaches_the_upstream_for_session_and_stateless_clients() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[(HEADER, VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the session call must be answered"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(
        calls.len(),
        1,
        "the session call must reach the upstream once"
    );
    assert_eq!(
        calls[0].header(LOWER),
        Some(VALUE),
        "the session client's header must reach the upstream with its value"
    );

    upstream.clear();
    let stateless = w.stateless_mcp("demo", &tokens);
    let reply = stateless_call(&stateless, "echo", &[(HEADER, VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the stateless call must be answered"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(
        calls.len(),
        1,
        "the stateless call must reach the upstream once"
    );
    assert_eq!(
        calls[0].header(LOWER),
        Some(VALUE),
        "the stateless client's header must reach the upstream with its value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn on_the_combined_endpoint_the_header_reaches_only_the_server_that_declares_it() {
    let w = World::start().await;
    let (a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let b_options = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let (b, b_id) = w.upstream("b", b_options).await;
    let bob = grant_bob(&w, &[&a_id, &b_id]).await;
    declare_ok(&w.owner, &a_id, HEADER, false).await;
    switches_ok(&w.owner, &a_id, true, false).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = session_on(&w, "mcp", &tokens).await;
    a.clear();
    b.clear();

    let echo = session_call(&client, "a__echo", &[(HEADER, VALUE)]).await;
    assert_eq!(
        echo.text().as_deref(),
        Some("called: echo"),
        "a__echo must be answered"
    );
    let alpha = session_call(&client, "b__alpha", &[(HEADER, VALUE)]).await;
    assert_eq!(
        alpha.text().as_deref(),
        Some("called: alpha"),
        "b__alpha must be answered"
    );

    let on_a = received_calls(&a, "echo");
    assert_eq!(on_a.len(), 1, "a must receive the echo call once");
    assert_eq!(
        on_a[0].header(LOWER),
        Some(VALUE),
        "the server that declares the header must receive it"
    );
    let on_b = received_calls(&b, "alpha");
    assert_eq!(on_b.len(), 1, "b must receive the alpha call once");
    assert_eq!(
        on_b[0].header(LOWER),
        None,
        "a server that does not declare the header must not receive it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn with_pass_through_off_the_declared_header_does_not_reach_the_upstream() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, false, false).await;
    let tokens = w.token(&bob, "demo").await;

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[(HEADER, VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the session call must be answered"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(
        calls.len(),
        1,
        "the session call must reach the upstream once"
    );
    assert_eq!(
        calls[0].header(LOWER),
        None,
        "the header must not pass with pass-through off"
    );

    upstream.clear();
    let stateless = w.stateless_mcp("demo", &tokens);
    let reply = stateless_call(&stateless, "echo", &[(HEADER, VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the stateless call must be answered"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(
        calls.len(),
        1,
        "the stateless call must reach the upstream once"
    );
    assert_eq!(
        calls[0].header(LOWER),
        None,
        "the header must not pass with pass-through off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_undeclared_header_does_not_reach_the_upstream_even_with_pass_through_on() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, "X-Region", false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[(HEADER, VALUE)]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the session call must be answered"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(
        calls.len(),
        1,
        "the session call must reach the upstream once"
    );
    assert_eq!(
        calls[0].header(LOWER),
        None,
        "an undeclared header must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_authorization_header_is_never_passed_through() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, "Authorization", false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the session call must be answered"
    );
    assert_eq!(
        received_calls(&upstream, "echo").len(),
        1,
        "the session call must reach the upstream once"
    );
    assert!(
        upstream
            .requests()
            .iter()
            .all(|request| request.header("authorization").is_none()),
        "the upstream must never see an authorization header"
    );

    upstream.clear();
    let stateless = w.stateless_mcp("demo", &tokens);
    let reply = stateless_call(&stateless, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the stateless call must be answered"
    );
    assert_eq!(
        received_calls(&upstream, "echo").len(),
        1,
        "the stateless call must reach the upstream once"
    );
    assert!(
        upstream
            .requests()
            .iter()
            .all(|request| request.header("authorization").is_none()),
        "the upstream must never see an authorization header from a stateless client"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_header_sent_twice_is_refused_before_the_upstream() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;
    let duplicated = [(HEADER, VALUE), (HEADER, "second-value")];

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &duplicated).await;
    assert_eq!(
        reply.status, 400,
        "a header sent twice must be refused with 400"
    );
    assert!(
        upstream.requests().is_empty(),
        "a refused session call must not reach the upstream"
    );

    let stateless = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    let reply = stateless_call(&stateless, "echo", &duplicated).await;
    assert_eq!(
        reply.status, 400,
        "a header sent twice must be refused with 400 on a stateless call"
    );
    assert!(
        upstream.requests().is_empty(),
        "a refused stateless call must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_header_values_are_refused_before_the_upstream() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;
    let bad_values = [
        ("an empty value", String::new()),
        ("a value of 4097 bytes", "a".repeat(4097)),
        ("a non-ASCII value", "caf\u{e9}".to_string()),
        ("a value holding byte 0x80", "\u{80}".to_string()),
    ];

    let session = session_on(&w, "demo", &tokens).await;
    let stateless = w.stateless_mcp("demo", &tokens);
    for (what, value) in &bad_values {
        upstream.clear();
        let reply = session_call(&session, "echo", &[(HEADER, value.as_str())]).await;
        assert_eq!(
            reply.status, 400,
            "{what} must be refused with 400 on a session call"
        );
        assert!(
            upstream.requests().is_empty(),
            "{what} must not reach the upstream on a session call"
        );
        upstream.clear();
        let reply = stateless_call(&stateless, "echo", &[(HEADER, value.as_str())]).await;
        assert_eq!(
            reply.status, 400,
            "{what} must be refused with 400 on a stateless call"
        );
        assert!(
            upstream.requests().is_empty(),
            "{what} must not reach the upstream on a stateless call"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_required_header_answers_403_on_the_server_path() {
    let w = World::start().await;
    let (upstream, id) = add_server_named(&w.owner, "Demo Server", "demo", true).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, true).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;

    let stateless = w.stateless_mcp("demo", &tokens);
    let refused = stateless_call(&stateless, "echo", &[]).await;
    assert_eq!(
        refused.status, 403,
        "a missing required header must answer 403"
    );
    let message = refused.error_message().unwrap_or_default();
    assert!(
        message.contains("Demo Server") && message.to_ascii_lowercase().contains(LOWER),
        "the refusal must name the server and the header, got {message:?}"
    );
    assert!(
        upstream.requests().is_empty(),
        "a refused call must not reach the upstream"
    );

    let session = w.session_mcp("demo", &tokens);
    let refused = session.initialize().await;
    assert_eq!(
        refused.status, 403,
        "a missing required header must answer 403 to initialize"
    );
    let message = refused.error_message().unwrap_or_default();
    assert!(
        message.contains("Demo Server") && message.to_ascii_lowercase().contains(LOWER),
        "the initialize refusal must name the server and the header, got {message:?}"
    );
    assert!(
        upstream.requests().is_empty(),
        "a refused initialize must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_required_header_leaves_its_server_out_of_the_combined_list() {
    let w = World::start().await;
    let (a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let b_options = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let (b, b_id) = w.upstream("b", b_options).await;
    let bob = grant_bob(&w, &[&a_id, &b_id]).await;
    declare_ok(&w.owner, &a_id, HEADER, true).await;
    switches_ok(&w.owner, &a_id, true, false).await;
    let tokens = w.token(&bob, "mcp").await;
    let client = session_on(&w, "mcp", &tokens).await;
    a.clear();
    b.clear();

    let listed = client.list_tools().await;
    assert_eq!(listed.status, 200, "the combined tool list must answer 200");
    assert_eq!(
        listed.tool_names(),
        vec!["b__alpha".to_string()],
        "the server with a missing required header must be left out of the list"
    );
    assert!(
        a.requests().is_empty(),
        "nothing may be sent to the server whose required header is missing"
    );
    let alpha = session_call(&client, "b__alpha", &[]).await;
    assert_eq!(
        alpha.text().as_deref(),
        Some("called: alpha"),
        "b__alpha must still be answered"
    );
    assert_eq!(b.calls_to("alpha"), 1, "b must receive the alpha call");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_header_that_is_not_required_and_is_missing_changes_nothing() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "a call without an optional header must succeed"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(calls.len(), 1, "the call must reach the upstream once");
    assert_eq!(
        calls[0].header(LOWER),
        None,
        "no optional header may be invented"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_without_a_secret_that_refuses_the_probe_is_not_reported_ok() {
    let w = World::start().await;
    let options = UpstreamOptions {
        require_header: Some(("x-gate".into(), "open-sesame".into())),
        ..Default::default()
    };
    let upstream = FakeUpstream::start(options).await;
    let url = upstream.url();
    let id = admin::add_server(
        &w.owner,
        &ServerSpec {
            name: "Elsewhere",
            slug: "elsewhere",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let checked = admin::check_lockdown(&w.owner, &id).await;
    assert_eq!(checked.status, 303, "the lock-down check must be accepted");
    assert!(
        !upstream.requests().is_empty(),
        "the probe must reach the upstream"
    );
    assert_eq!(
        admin::lockdown(&w.owner, &id).await.as_deref(),
        Some("nosecret"),
        "a server without a secret header that refuses the probe must be nosecret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_without_a_secret_that_declares_a_header_warns_on_its_page() {
    let w = World::start().await;
    let (_open, open_id) = add_server_named(&w.owner, "Open Demo", "open-demo", false).await;
    let (_gated, gated_id) = w.upstream("gated", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &open_id, HEADER, false).await;
    declare_ok(&w.owner, &gated_id, HEADER, false).await;
    let open = server_page(&w.owner, &open_id).await;
    assert_eq!(
        open.count(DIRECT),
        1,
        "a server without a secret header that declares a header must show the direct warning"
    );
    let warning = open.text(DIRECT).unwrap_or_default();
    assert!(
        warning.contains(
            "anyone who reaches the upstream directly bypasses the gateway's rules and its activity log"
        ),
        "the direct warning must say who passes the gateway's rules, got {warning:?}"
    );
    let gated = server_page(&w.owner, &gated_id).await;
    assert_eq!(
        gated.count(DIRECT),
        0,
        "a server with a secret header must not show the direct warning"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_of_64_characters_is_accepted() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let name = format!("x-{}", "a".repeat(62));
    assert_eq!(name.len(), 64, "the name must be 64 characters");
    declare_ok(&w.owner, &id, &name, false).await;
    assert_eq!(
        server_page(&w.owner, &id)
            .await
            .count(&format!(r#"tr[data-header="{name}"]"#)),
        1,
        "a 64 character name must be listed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_of_4096_bytes_with_inner_space_and_tab_reaches_the_upstream_unchanged() {
    let w = World::start().await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, true, false).await;
    let tokens = w.token(&bob, "demo").await;
    let value = format!("{} \t{}", "a".repeat(2046), "b".repeat(2048));
    assert_eq!(value.len(), 4096, "the value must be 4096 bytes");

    let session = session_on(&w, "demo", &tokens).await;
    upstream.clear();
    let reply = session_call(&session, "echo", &[(HEADER, value.as_str())]).await;
    assert_eq!(
        reply.text().as_deref(),
        Some("called: echo"),
        "the session call must be answered"
    );
    let calls = received_calls(&upstream, "echo");
    assert_eq!(calls.len(), 1, "the call must reach the upstream once");
    assert_eq!(
        calls[0].header(LOWER),
        Some(value.as_str()),
        "a 4096 byte value with inner space and tab must reach the upstream unchanged"
    );
}

/// The address of the confirm page of header `hid` on server `id`.
fn remove_path(id: &str, hid: &str) -> String {
    format!("{}/headers/{hid}/remove", server_path(id))
}

/// The id of the declared header `name` on server `id`, which the test expects to exist.
async fn id_of(w: &World, id: &str, name: &str) -> String {
    header_id(&w.owner, id, name)
        .await
        .unwrap_or_else(|| panic!("{name} must have a remove link"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_remove_link_opens_a_confirm_page_that_names_the_header_the_server_and_the_count() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, true).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = id_of(&w, &id, HEADER).await;
    let stored = store_value(&bob, "demo", &hid, VALUE).await;
    assert_eq!(
        stored.status, 303,
        "storing the credential must be accepted"
    );

    let page = w.owner.get(&remove_path(&id, &hid)).await;
    assert_eq!(page.status, 200, "the confirm page must answer 200");
    assert_eq!(page.kind().as_deref(), Some("remove-header"));
    assert_eq!(
        page.text("main > h1").as_deref(),
        Some("Remove X-Trace-Id?"),
        "the title must name the header"
    );
    assert_eq!(
        page.text("main > h1 > span").as_deref(),
        Some(HEADER),
        "the header name must sit in its own span"
    );
    assert_eq!(
        page.text("main > p.lede").as_deref(),
        Some(
            "1 of 1 people stored a credential for it on demo. That credential is deleted and cannot be recovered."
        ),
        "the sentence must count the people who stored one, and name the server"
    );
    assert_eq!(
        page.count(r#"main form input[name="csrf"]"#),
        1,
        "the removal form must carry the csrf field"
    );
    assert_eq!(
        page.text(r#"main form button[data-kind="danger"]"#)
            .as_deref(),
        Some("Remove header"),
        "the filled red button must remove the header"
    );
    assert_eq!(
        page.text(r#"main a.button[data-kind="secondary"]"#)
            .as_deref(),
        Some("Keep header"),
        "the keep link must be the secondary button"
    );
    let keep = format!("{}#headers-title", server_path(&id));
    assert_eq!(
        page.attr(r#"main a.button[data-kind="secondary"]"#, "href")
            .as_deref(),
        Some(keep.as_str()),
        "keep must return to the headers part"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_confirm_page_says_nobody_stored_a_credential_when_none_is_stored() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let hid = id_of(&w, &id, HEADER).await;
    let page = w.owner.get(&remove_path(&id, &hid)).await;
    assert_eq!(
        page.text("main > p.lede").as_deref(),
        Some("Nobody stored a credential for it on demo."),
        "the sentence for nobody must be the short one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_confirm_page_counts_every_person_who_stored_a_credential() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let bob = grant_bob(&w, &[&id]).await;
    let alice = w.user("alice@example.com").await;
    w.grant("alice@example.com", &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    switches_ok(&w.owner, &id, false, true).await;
    let hid = id_of(&w, &id, HEADER).await;
    assert_eq!(store_value(&bob, "demo", &hid, VALUE).await.status, 303);
    assert_eq!(
        store_value(&alice, "demo", &hid, "other-value")
            .await
            .status,
        303
    );
    let page = w.owner.get(&remove_path(&id, &hid)).await;
    assert_eq!(
        page.text("main > p.lede").as_deref(),
        Some(
            "2 of 2 people stored a credential for it on demo. Those credentials are deleted and cannot be recovered."
        ),
        "two people must read as 2 of 2 with the plural sentence"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_confirm_page_is_not_found_for_another_servers_header_or_an_unknown_one() {
    let w = World::start().await;
    let (_a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let (_b, b_id) = w.upstream("b", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &b_id, HEADER, false).await;
    let b_hid = id_of(&w, &b_id, HEADER).await;
    let other = w.owner.get(&remove_path(&a_id, &b_hid)).await;
    assert_eq!(
        other.status, 404,
        "a header of another server must answer like an unknown page"
    );
    let unknown = w.owner.get(&remove_path(&b_id, "999999")).await;
    assert_eq!(unknown.status, 404, "an unknown header must answer 404");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_user_cannot_open_the_confirm_page() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let hid = id_of(&w, &id, HEADER).await;
    let bob = w.user(BOB).await;
    let page = bob.get(&remove_path(&id, &hid)).await;
    assert_eq!(
        page.status, 403,
        "a plain user must be refused the confirm page"
    );
    assert_eq!(page.kind().as_deref(), Some("forbidden"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_remove_link_is_a_link_and_the_removal_answers_with_the_notice() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let hid = id_of(&w, &id, HEADER).await;
    let listing = server_page(&w.owner, &id).await;
    assert_eq!(
        listing.count(&format!(r#"tr[data-header="{LOWER}"] form"#)),
        0,
        "the row's Remove is a link, not a form"
    );
    assert_eq!(
        listing.attr(
            &format!(r#"tr[data-header="{LOWER}"] a[href$="/remove"]"#),
            "href"
        ),
        Some(remove_path(&id, &hid)),
        "the row's Remove link goes to the confirm page"
    );

    let page = remove_header(&w.owner, &id, &hid).await;
    assert_eq!(page.status, 303, "removing a header must be accepted");
    assert_eq!(page.query("done").as_deref(), Some("header-removed"));
    let location = page.location().unwrap_or_default();
    assert!(
        location.starts_with(&server_path(&id)) && location.ends_with("#headers-title"),
        "the removal must return to the headers part, got {location}"
    );
    let shown = w.owner.get(&server_path(&id)).await;
    assert_eq!(
        shown.count(&format!(r#"tr[data-header="{LOWER}"]"#)),
        0,
        "the removed row must be gone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn adding_a_header_redirects_to_the_part_with_its_name_in_the_notice() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let page = declare_header(&w.owner, &id, HEADER, false).await;
    assert_eq!(page.status, 303, "declaring a header must be accepted");
    assert_eq!(page.query("done").as_deref(), Some("header-added"));
    assert!(
        page.location()
            .unwrap_or_default()
            .ends_with("#headers-title"),
        "the redirect must land on the headers part"
    );
    let shown = w.owner.follow(&page).await;
    assert_eq!(
        shown.text(r#"div.notice[data-notice="ok"] > p"#).as_deref(),
        Some("X-Trace-Id added."),
        "the notice must name the header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_a_header_made_required_says_how_many_have_not_stored_it() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    grant_bob(&w, &[&id]).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let hid = id_of(&w, &id, HEADER).await;
    let saved = save_headers(&w.owner, &id, &[&hid], &[&hid], false, false).await;
    assert_eq!(saved.status, 303, "saving the headers must be accepted");
    assert_eq!(saved.query("done").as_deref(), Some("headers-saved"));
    let shown = w.owner.follow(&saved).await;
    assert_eq!(
        shown.text(r#"div.notice[data-notice="ok"] > p"#).as_deref(),
        Some("Headers saved. X-Trace-Id is now required. 1 of 1 users have not stored it."),
        "the notice must name the header made required and count the people without it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn save_headers_changes_required_only_for_the_rows_it_lists() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, "X-Alpha", false).await;
    declare_ok(&w.owner, &id, "X-Beta", false).await;
    let alpha = id_of(&w, &id, "X-Alpha").await;
    let beta = id_of(&w, &id, "X-Beta").await;
    let flags = |page: &Page| {
        (
            page.attr(r#"tr[data-header="x-alpha"]"#, "data-required"),
            page.attr(r#"tr[data-header="x-beta"]"#, "data-required"),
        )
    };

    let saved = save_headers(&w.owner, &id, &[&alpha, &beta], &[&beta], false, false).await;
    assert_eq!(saved.status, 303, "the save must be accepted");
    assert_eq!(
        flags(&server_page(&w.owner, &id).await),
        (Some("no".into()), Some("yes".into())),
        "a listed row takes the state of its box"
    );

    let saved = save_headers(&w.owner, &id, &[&alpha], &[], false, false).await;
    assert_eq!(saved.status, 303, "the save must be accepted");
    assert_eq!(
        flags(&server_page(&w.owner, &id).await),
        (Some("no".into()), Some("yes".into())),
        "an unlisted row keeps its flag"
    );

    let saved = save_headers(&w.owner, &id, &[&alpha], &[&alpha], false, false).await;
    assert_eq!(saved.status, 303, "the save must be accepted");
    assert_eq!(
        flags(&server_page(&w.owner, &id).await),
        (Some("yes".into()), Some("yes".into())),
        "a ticked box makes its listed row required and leaves the other row alone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_post_without_listed_fields_changes_no_required_flag() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    declare_ok(&w.owner, &id, HEADER, true).await;
    switches_ok(&w.owner, &id, true, true).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.attr(&format!(r#"tr[data-header="{LOWER}"]"#), "data-required")
            .as_deref(),
        Some("yes"),
        "the switch post must leave the required flag as it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_switches_form_is_absent_until_a_header_exists() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"form[action$="/header-switches"]"#),
        0,
        "with no header the switches form must not be rendered"
    );
    assert_eq!(
        page.count(r#"input[name="pass_headers"]"#),
        0,
        "with no header the pass switch must not be rendered"
    );
    assert_eq!(
        page.count(r#"form[action$="/headers"]"#),
        1,
        "the add form must follow the empty sentence"
    );
    declare_ok(&w.owner, &id, HEADER, false).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"form[action$="/header-switches"]"#),
        1,
        "with one header the switches form is rendered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn at_eight_headers_the_add_form_gives_way_to_one_sentence() {
    let w = World::start().await;
    let (_upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    for i in 1..=8 {
        declare_ok(&w.owner, &id, &format!("X-Custom-{i}"), false).await;
    }
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.count(r#"form[action$="/headers"]"#),
        0,
        "at 8 headers there is no add form"
    );
    assert_eq!(
        page.text("p[data-headers-full]").as_deref(),
        Some("This server has its 8 headers. Remove one to add another."),
        "at 8 headers one sentence says so"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_direct_warning_links_to_the_secret_header_field() {
    let w = World::start().await;
    let (_open, id) = add_server_named(&w.owner, "Open Demo", "open-demo", false).await;
    declare_ok(&w.owner, &id, HEADER, false).await;
    let page = server_page(&w.owner, &id).await;
    assert_eq!(
        page.attr(&format!("{DIRECT} a"), "href").as_deref(),
        Some("#secret-name"),
        "the warning's link must go to the secret header name field"
    );
    assert_eq!(
        page.text(&format!("{DIRECT} a")).as_deref(),
        Some("Go to secret header")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lockdown_note_of_a_server_without_a_secret_does_not_describe_a_passed_check() {
    let w = World::start().await;
    let options = UpstreamOptions {
        require_header: Some(("x-gate".into(), "open-sesame".into())),
        ..Default::default()
    };
    let upstream = FakeUpstream::start(options).await;
    let url = upstream.url();
    let id = admin::add_server(
        &w.owner,
        &ServerSpec {
            name: "Elsewhere",
            slug: "elsewhere",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let checked = admin::check_lockdown(&w.owner, &id).await;
    assert_eq!(checked.status, 303, "the lock-down check must be accepted");
    let page = server_page(&w.owner, &id).await;
    let note = page.text("p[data-lockdown-note]").unwrap_or_default();
    assert!(
        note.contains("no secret header"),
        "the note must be the no-secret text, got {note:?}"
    );
    assert!(
        !note.contains("refused a request without the secret"),
        "the note must not describe a passed check, got {note:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_servers_declaring_one_header_with_pass_through_on_both_receive_a_clients_value_on_mcp()
{
    let w = World::start().await;
    let (a, a_id) = w.upstream("a", UpstreamOptions::default()).await;
    let b_options = UpstreamOptions {
        tools: vec!["alpha".into()],
        ..Default::default()
    };
    let (b, b_id) = w.upstream("b", b_options).await;
    let bob = grant_bob(&w, &[&a_id, &b_id]).await;
    for id in [&a_id, &b_id] {
        declare_ok(&w.owner, id, HEADER, false).await;
        switches_ok(&w.owner, id, true, false).await;
    }
    let tokens = w.token(&bob, "mcp").await;
    let client = session_on(&w, "mcp", &tokens).await;
    a.clear();
    b.clear();

    let echo = session_call(&client, "a__echo", &[(HEADER, VALUE)]).await;
    assert_eq!(echo.text().as_deref(), Some("called: echo"));
    let alpha = session_call(&client, "b__alpha", &[(HEADER, VALUE)]).await;
    assert_eq!(alpha.text().as_deref(), Some("called: alpha"));
    assert_eq!(
        received_calls(&a, "echo")[0].header(LOWER),
        Some(VALUE),
        "a declares the name and passes headers through, so it receives the client's value"
    );
    assert_eq!(
        received_calls(&b, "alpha")[0].header(LOWER),
        Some(VALUE),
        "b declares the same name, so the same client value goes to it too"
    );
}
