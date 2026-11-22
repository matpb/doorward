mod common;

use common::admin::{self, ServerSpec};
use common::client::{Page, TestClient, Tokens};
use common::headers::{
    add_server_named, declare_header, header_id, received_calls, remove_header, session_call,
    set_switches, stateless_call,
};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
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
            "anyone who reaches the upstream directly passes the gateway's rules and its activity log"
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
