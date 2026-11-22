use serde_json::json;

use super::admin::{self, ServerSpec};
use super::client::{Page, TestClient};
use super::mcp::{McpClient, McpReply};
use super::upstream::{FakeUpstream, Recorded, UpstreamOptions};
use super::world::{SECRET_HEADER, secret_for};

const SESSION_VERSION: &str = "2025-11-25";
const STATELESS_VERSION: &str = "2026-07-28";

fn server_path(id: &str) -> String {
    format!("/admin/servers/{id}")
}

/// Declares a custom header on the server; the answer is the redirect or the refusal.
pub async fn declare_header(
    owner: &TestClient,
    server_id: &str,
    name: &str,
    required: bool,
) -> Page {
    let path = server_path(server_id);
    let mut fields = vec![("name", name)];
    if required {
        fields.push(("required", "1"));
    }
    owner
        .submit(&path, &format!("{path}/headers"), &fields)
        .await
}

pub async fn remove_header(owner: &TestClient, server_id: &str, header_id: &str) -> Page {
    let path = server_path(server_id);
    owner
        .submit(&path, &format!("{path}/headers/{header_id}/remove"), &[])
        .await
}

pub async fn set_switches(owner: &TestClient, server_id: &str, pass: bool, store: bool) -> Page {
    let path = server_path(server_id);
    let mut fields = Vec::new();
    if pass {
        fields.push(("pass_headers", "1"));
    }
    if store {
        fields.push(("store_headers", "1"));
    }
    owner
        .submit(&path, &format!("{path}/header-switches"), &fields)
        .await
}

/// The id of the declared header `name` read from its remove form; None when no row holds it.
pub async fn header_id(owner: &TestClient, server_id: &str, name: &str) -> Option<String> {
    let page = owner.get(&server_path(server_id)).await;
    let selector = format!(r#"tr[data-header="{}"] form"#, name.to_ascii_lowercase());
    let action = page.attr(&selector, "action")?;
    let prefix = action.strip_suffix("/remove")?;
    prefix.rsplit('/').next().map(str::to_string)
}

/// Starts an upstream and adds it as `name` at `slug`, behind the secret gate when `gated`.
pub async fn add_server_named(
    owner: &TestClient,
    name: &str,
    slug: &str,
    gated: bool,
) -> (FakeUpstream, String) {
    let secret = secret_for(slug);
    let options = if gated {
        UpstreamOptions {
            require_header: Some((SECRET_HEADER.into(), secret.clone())),
            ..Default::default()
        }
    } else {
        UpstreamOptions::default()
    };
    let upstream = FakeUpstream::start(options).await;
    let url = upstream.url();
    let id = admin::add_server(
        owner,
        &ServerSpec {
            name,
            slug,
            upstream_url: &url,
            secret: gated.then_some((SECRET_HEADER, secret.as_str())),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let refreshed = admin::refresh_tools(owner, &id).await;
    assert_eq!(
        refreshed.status, 303,
        "refreshing the tools of {slug} must be accepted"
    );
    upstream.clear();
    (upstream, id)
}

/// The requests the upstream received for the tool `tool`, in arrival order.
pub fn received_calls(upstream: &FakeUpstream, tool: &str) -> Vec<Recorded> {
    upstream
        .requests()
        .into_iter()
        .filter(|request| request.tool.as_deref() == Some(tool))
        .collect()
}

/// A tools/call from a session-style client, sent with extra request headers. The session id is sent
/// when the client holds one; the combined endpoint issues none, so its calls carry none.
pub async fn session_call(client: &McpClient, tool: &str, headers: &[(&str, &str)]) -> McpReply {
    let session = client.session_id();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 90,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    });
    let mut all = vec![("MCP-Protocol-Version", SESSION_VERSION)];
    if let Some(session) = session.as_deref() {
        all.push(("Mcp-Session-Id", session));
    }
    all.extend_from_slice(headers);
    client.raw(body.to_string().as_bytes(), &all).await
}

/// A stateless tools/call sent with extra request headers.
pub async fn stateless_call(client: &McpClient, tool: &str, headers: &[(&str, &str)]) -> McpReply {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 91,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": STATELESS_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "0"},
            },
        },
    });
    let mut all = vec![
        ("MCP-Protocol-Version", STATELESS_VERSION),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", tool),
    ];
    all.extend_from_slice(headers);
    client.raw(body.to_string().as_bytes(), &all).await
}
