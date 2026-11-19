mod common;

use common::client::{self, TestClient};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::World;
use serde_json::{Value, json};

const BOB: &str = "bob@example.com";
const SESSION_COOKIE: &str = "__Host-doorward_session";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test-client","version":"0"}}}"#;

/// The WWW-Authenticate value that points at the metadata of `slug`.
fn challenge(base: &str, slug: &str) -> String {
    format!(
        r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/{slug}", scope="mcp""#
    )
}

/// The challenge for a request that presented a token which is not valid.
fn invalid_challenge(base: &str, slug: &str) -> String {
    format!(r#"{}, error="invalid_token""#, challenge(base, slug))
}

fn resource_metadata(base: &str, slug: &str) -> Value {
    json!({
        "resource": format!("{base}/{slug}"),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    })
}

fn authorization_metadata(base: &str) -> Value {
    json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["mcp"],
    })
}

/// A world with demo's upstream and no user.
async fn demo_world() -> (World, FakeUpstream) {
    let w = World::start().await;
    let (upstream, _id) = w.upstream("demo", UpstreamOptions::default()).await;
    (w, upstream)
}

/// A world where bob is assigned to demo and signed in.
async fn bob_on_demo() -> (World, TestClient, FakeUpstream) {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[id.as_str()]).await;
    (w, bob, upstream)
}

#[tokio::test(flavor = "multi_thread")]
async fn no_token_gets_401_with_the_metadata_pointer() {
    let (w, _upstream) = demo_world().await;
    let demo = McpClient::session(&w.resource("demo"), None)
        .initialize()
        .await;
    assert_eq!(
        demo.status, 401,
        "a request with no token must get 401 on /demo"
    );
    assert_eq!(demo.body, "", "the 401 on /demo must have an empty body");
    assert_eq!(
        demo.header("www-authenticate"),
        Some(challenge(w.base(), "demo")),
        "the 401 on /demo must point at the metadata of demo"
    );
    let mcp = McpClient::session(&w.resource("mcp"), None)
        .initialize()
        .await;
    assert_eq!(
        mcp.status, 401,
        "a request with no token must get 401 on /mcp"
    );
    assert_eq!(mcp.body, "", "the 401 on /mcp must have an empty body");
    assert_eq!(
        mcp.header("www-authenticate"),
        Some(challenge(w.base(), "mcp")),
        "the 401 on /mcp must point at the metadata of the combined endpoint"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_token_adds_invalid_token() {
    let (w, _upstream) = demo_world().await;
    let reply = McpClient::session(&w.resource("demo"), Some("dw_at_garbage"))
        .initialize()
        .await;
    assert_eq!(reply.status, 401, "a bad token must get 401");
    assert_eq!(
        reply.header("www-authenticate"),
        Some(invalid_challenge(w.base(), "demo")),
        "a bad token must add error=\"invalid_token\" to the challenge"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_and_unassigned_servers_look_the_same() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (_demo, demo_id) = w.upstream("demo", UpstreamOptions::default()).await;
    let (_other, _other_id) = w.upstream("other", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo_id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    let ghost = McpClient::session(&w.resource("ghost"), Some(&tokens.access_token))
        .list_tools()
        .await;
    let other = McpClient::session(&w.resource("other"), Some(&tokens.access_token))
        .list_tools()
        .await;
    assert_eq!(
        ghost.status, 401,
        "a token sent to a server that does not exist must get 401"
    );
    assert_eq!(
        other.status, ghost.status,
        "an unassigned server must answer the same status as a missing one"
    );
    assert_eq!(
        other.body, ghost.body,
        "an unassigned server must answer the same body as a missing one"
    );
    let ghost_header = ghost
        .header("www-authenticate")
        .expect("the missing server's 401 must carry the challenge");
    let other_header = other
        .header("www-authenticate")
        .expect("the unassigned server's 401 must carry the challenge");
    assert_eq!(
        other_header.replace("/other", "/SLUG"),
        ghost_header.replace("/ghost", "/SLUG"),
        "the challenges of a missing and an unassigned server must differ only by the slug"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_resource_metadata() {
    let w = World::start().await;
    let base = w.base();
    let client = w.client();
    let demo = client
        .get("/.well-known/oauth-protected-resource/demo")
        .await;
    assert_eq!(
        demo.status, 200,
        "the protected resource metadata of demo must be served"
    );
    assert_eq!(
        demo.json(),
        Some(resource_metadata(base, "demo")),
        "the metadata of demo must have exactly the documented fields"
    );
    let ghost = client
        .get("/.well-known/oauth-protected-resource/ghost")
        .await;
    assert_eq!(
        ghost.status, 200,
        "an unknown but valid slug must get the metadata too"
    );
    assert_eq!(
        ghost.json(),
        Some(resource_metadata(base, "ghost")),
        "the metadata of an unknown slug must have the same shape"
    );
    let bad = client
        .get("/.well-known/oauth-protected-resource/Bad_Slug")
        .await;
    assert_eq!(
        bad.status, 404,
        "a slug with a capital and an underscore must be 404"
    );
    let long_slug = "a".repeat(25);
    let long = client
        .get(&format!(
            "/.well-known/oauth-protected-resource/{long_slug}"
        ))
        .await;
    assert_eq!(long.status, 404, "a 25 character slug must be 404");
}

#[tokio::test(flavor = "multi_thread")]
async fn authorization_server_metadata() {
    let w = World::start().await;
    let page = w
        .client()
        .get("/.well-known/oauth-authorization-server")
        .await;
    assert_eq!(
        page.status, 200,
        "the authorization server metadata must be served"
    );
    assert_eq!(
        page.json(),
        Some(authorization_metadata(w.base())),
        "the authorization server metadata must have exactly the documented fields"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_ignores_request_headers() {
    let (w, _upstream) = demo_world().await;
    let base = w.base();
    let spoofed = [
        ("Host", "evil.example.com"),
        ("X-Forwarded-Host", "evil.example.com"),
        ("X-Forwarded-Proto", "https"),
    ];
    let metadata = w
        .client()
        .get_with("/.well-known/oauth-authorization-server", &spoofed)
        .await;
    assert_eq!(
        metadata.json(),
        Some(authorization_metadata(base)),
        "the issuer and endpoints must come from the config, not from request headers"
    );
    let resource = w
        .client()
        .get_with("/.well-known/oauth-protected-resource/demo", &spoofed)
        .await;
    assert_eq!(
        resource.json(),
        Some(resource_metadata(base, "demo")),
        "the resource of demo must come from the config, not from request headers"
    );
    let refused = McpClient::session(&w.resource("demo"), None)
        .raw(INIT.as_bytes(), &spoofed)
        .await;
    assert_eq!(
        refused.status, 401,
        "a spoofed request without a token must get 401"
    );
    assert_eq!(
        refused.header("www-authenticate"),
        Some(challenge(base, "demo")),
        "the 401 must point at the configured address, not at the spoofed host"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_and_delete_without_a_token_get_401() {
    let (w, _upstream) = demo_world().await;
    let client = McpClient::session(&w.resource("demo"), None);
    let get = client.get().await;
    assert_eq!(get.status, 401, "a GET without a token must get 401");
    assert_eq!(get.body, "", "the 401 for a GET must have an empty body");
    assert_eq!(
        get.header("www-authenticate"),
        Some(challenge(w.base(), "demo")),
        "the 401 for a GET must point at the metadata of demo"
    );
    let delete = client.delete().await;
    assert_eq!(delete.status, 401, "a DELETE without a token must get 401");
    assert_eq!(
        delete.body, "",
        "the 401 for a DELETE must have an empty body"
    );
    assert_eq!(
        delete.header("www-authenticate"),
        Some(challenge(w.base(), "demo")),
        "the 401 for a DELETE must point at the metadata of demo"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_in_the_query_is_not_read() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let tokens = w.token(&bob, "demo").await;
    let header_reply = w.session_mcp("demo", &tokens).initialize().await;
    assert_eq!(
        header_reply.status, 200,
        "the token must work in the header, so the refusal below is about the query"
    );
    let url = format!(
        "{}?access_token={}",
        w.resource("demo"),
        tokens.access_token
    );
    let reply = McpClient::session(&url, None).initialize().await;
    assert_eq!(
        reply.status, 401,
        "a token in the query string must not authenticate"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_cookie_does_not_open_mcp_paths() {
    let (w, bob, upstream) = bob_on_demo().await;
    let signed_in = bob.get("/account").await;
    assert_eq!(
        signed_in.status, 200,
        "bob must be signed in before his session cookie is tried"
    );
    let session = bob
        .cookie(SESSION_COOKIE)
        .expect("bob's browser must hold a session cookie");
    let cookie = format!("{SESSION_COOKIE}={session}");
    upstream.clear();
    let reply = McpClient::session(&w.resource("demo"), None)
        .raw(INIT.as_bytes(), &[("Cookie", cookie.as_str())])
        .await;
    assert_eq!(
        reply.status, 401,
        "a session cookie without a bearer token must not open an MCP path"
    );
    assert!(
        upstream.requests().is_empty(),
        "the upstream must not see a request that carries only a session cookie"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_access_token_is_refused_and_refresh_recovers() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let tokens = w.token(&bob, "demo").await;
    let before = w.session_mcp("demo", &tokens).initialize().await;
    assert_eq!(
        before.status, 200,
        "the access token must work before it expires"
    );
    w.gw.clock.advance(time::Duration::minutes(61));
    let expired = w.session_mcp("demo", &tokens).initialize().await;
    assert_eq!(
        expired.status, 401,
        "an access token must be refused 61 minutes after it was issued"
    );
    assert_eq!(
        expired.header("www-authenticate"),
        Some(invalid_challenge(w.base(), "demo")),
        "an expired token must add error=\"invalid_token\" to the challenge"
    );
    let resource = w.resource("demo");
    let refreshed = bob
        .token_refresh(&w.app(), &tokens.refresh_token, Some(resource.as_str()))
        .await;
    let fresh = client::tokens(&refreshed).expect("the refresh token must buy a new token pair");
    let reply = w.session_mcp("demo", &fresh).initialize().await;
    assert_eq!(
        reply.status, 200,
        "the access token from the refresh must work on demo"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_bearer_header_is_accepted() {
    let (w, bob, _upstream) = bob_on_demo().await;
    let tokens = w.token(&bob, "demo").await;
    let url = w.resource("demo");
    let bearer = format!("Bearer {}", tokens.access_token);
    let basic = McpClient::session(&url, None)
        .raw(INIT.as_bytes(), &[("Authorization", "Basic dXNlcjpwYXNz")])
        .await;
    assert_eq!(
        basic.status, 401,
        "an Authorization header with Basic must get 401"
    );
    let doubled = McpClient::session(&url, None)
        .raw(
            INIT.as_bytes(),
            &[
                ("Authorization", bearer.as_str()),
                ("Authorization", bearer.as_str()),
            ],
        )
        .await;
    assert_eq!(
        doubled.status, 401,
        "two Authorization headers must get 401"
    );
    let lower = format!("bearer {}", tokens.access_token);
    let accepted = McpClient::session(&url, None)
        .raw(INIT.as_bytes(), &[("Authorization", lower.as_str())])
        .await;
    assert_eq!(
        accepted.status, 200,
        "a single bearer header with the scheme in lower case must be accepted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_request_reaches_the_upstream_without_a_valid_token() {
    let (w, bob, upstream) = bob_on_demo().await;
    let tokens = w.token(&bob, "demo").await;
    let session = bob
        .cookie(SESSION_COOKIE)
        .expect("bob's browser must hold a session cookie");
    let cookie = format!("{SESSION_COOKIE}={session}");
    let url = w.resource("demo");
    let query_url = format!("{url}?access_token={}", tokens.access_token);
    upstream.clear();

    let no_token = McpClient::session(&url, None).initialize().await;
    assert_eq!(no_token.status, 401, "a request with no token must get 401");
    let bad = McpClient::session(&url, Some("dw_at_garbage"))
        .initialize()
        .await;
    assert_eq!(bad.status, 401, "a bad token must get 401");
    let get = McpClient::session(&url, None).get().await;
    assert_eq!(get.status, 401, "a GET without a token must get 401");
    let delete = McpClient::session(&url, None).delete().await;
    assert_eq!(delete.status, 401, "a DELETE without a token must get 401");
    let in_query = McpClient::session(&query_url, None).initialize().await;
    assert_eq!(
        in_query.status, 401,
        "a token in the query string must get 401"
    );
    let cookie_only = McpClient::session(&url, None)
        .raw(INIT.as_bytes(), &[("Cookie", cookie.as_str())])
        .await;
    assert_eq!(
        cookie_only.status, 401,
        "a session cookie without a bearer token must get 401"
    );
    assert!(
        upstream.requests().is_empty(),
        "no request without a valid token may reach the upstream"
    );
}
