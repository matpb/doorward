mod common;

use common::admin::{self, ServerSpec};
use common::client::Tokens;
use common::mcp::McpReply;
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::world::{SECRET_HEADER, World, secret_for};
use serde_json::{Value, json};

/// Bob on demo: the demo upstream, its server id and his tokens.
async fn bob_on_demo(w: &World) -> (FakeUpstream, String, Tokens) {
    let bob = w.user("bob@example.com").await;
    let (upstream, id) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant("bob@example.com", &[id.as_str()]).await;
    let tokens = w.token(&bob, "demo").await;
    (upstream, id, tokens)
}

/// Saves demo with the given switch values, keeping its upstream address and secret.
async fn set_switches(
    w: &World,
    upstream: &FakeUpstream,
    id: &str,
    resources: bool,
    prompts: bool,
) {
    let url = upstream.url();
    let secret = secret_for("demo");
    let page = admin::update_server(
        &w.owner,
        id,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: Some((SECRET_HEADER, secret.as_str())),
            pass_resources: resources,
            pass_prompts: prompts,
        },
    )
    .await;
    assert_eq!(page.status, 303, "saving the switches must be accepted");
}

/// The capabilities object of a reply's result.
fn capabilities(reply: &McpReply) -> &Value {
    reply
        .result()
        .expect("the reply must carry a result")
        .get("capabilities")
        .expect("the result must carry capabilities")
}

#[tokio::test(flavor = "multi_thread")]
async fn resources_and_prompts_are_empty_by_default() {
    let w = World::start().await;
    let (upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let resources = client.request("resources/list", json!({})).await;
    assert_eq!(
        resources.result(),
        Some(&json!({"resources": []})),
        "resources/list must answer an empty list while the switch is off"
    );
    let templates = client.request("resources/templates/list", json!({})).await;
    assert_eq!(
        templates.result(),
        Some(&json!({"resourceTemplates": []})),
        "resources/templates/list must answer an empty list while the switch is off"
    );
    let prompts = client.request("prompts/list", json!({})).await;
    assert_eq!(
        prompts.result(),
        Some(&json!({"prompts": []})),
        "prompts/list must answer an empty list while the switch is off"
    );
    assert!(
        upstream.requests().is_empty(),
        "the upstream must not see the switched-off list requests"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reads_are_refused_while_off() {
    let w = World::start().await;
    let (upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let read = client
        .request("resources/read", json!({"uri": "file:///secret.txt"}))
        .await;
    assert_eq!(
        read.error_code(),
        Some(-32601),
        "resources/read must be refused while the switch is off"
    );
    let got = client
        .request("prompts/get", json!({"name": "greet"}))
        .await;
    assert_eq!(
        got.error_code(),
        Some(-32601),
        "prompts/get must be refused while the switch is off"
    );
    assert!(
        upstream.requests().is_empty(),
        "the refused reads must not be forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_are_removed_while_off() {
    let w = World::start().await;
    let (_upstream, _id, tokens) = bob_on_demo(&w).await;
    let session = w.session_mcp("demo", &tokens);
    let init = session.initialize().await;
    assert_eq!(init.status, 200, "initialize must be relayed");
    let caps = capabilities(&init);
    assert!(
        caps.get("resources").is_none(),
        "initialize must not advertise resources while the switch is off"
    );
    assert!(
        caps.get("prompts").is_none(),
        "initialize must not advertise prompts while the switch is off"
    );
    let stateless = w.stateless_mcp("demo", &tokens);
    let discover = stateless.discover().await;
    assert_eq!(discover.status, 200, "server/discover must be relayed");
    let caps = capabilities(&discover);
    assert!(
        caps.get("resources").is_none(),
        "server/discover must not advertise resources while the switch is off"
    );
    assert!(
        caps.get("prompts").is_none(),
        "server/discover must not advertise prompts while the switch is off"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_resources_switch_opens_resources_only() {
    let w = World::start().await;
    let (upstream, id, tokens) = bob_on_demo(&w).await;
    set_switches(&w, &upstream, &id, true, false).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    let listed = client.request("resources/list", json!({})).await;
    let resources = listed
        .result()
        .and_then(|result| result["resources"].as_array())
        .expect("resources/list must carry a resources array");
    assert_eq!(
        resources.len(),
        1,
        "with the switch on, resources/list must show the upstream's one resource"
    );
    let read = client
        .request("resources/read", json!({"uri": "file:///secret.txt"}))
        .await;
    assert_eq!(
        read.result()
            .and_then(|result| result["contents"][0]["text"].as_str()),
        Some("TOP-SECRET"),
        "with the switch on, resources/read must return the upstream's text"
    );
    let prompts = client.request("prompts/list", json!({})).await;
    assert_eq!(
        prompts.result(),
        Some(&json!({"prompts": []})),
        "the prompts switch is off, so prompts/list must stay empty"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_prompts_switch_opens_prompts_only() {
    let w = World::start().await;
    let (upstream, id, tokens) = bob_on_demo(&w).await;
    set_switches(&w, &upstream, &id, false, true).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    let listed = client.request("prompts/list", json!({})).await;
    let prompts = listed
        .result()
        .and_then(|result| result["prompts"].as_array())
        .expect("prompts/list must carry a prompts array");
    assert_eq!(
        prompts.len(),
        1,
        "with the switch on, prompts/list must show the upstream's one prompt"
    );
    let got = client
        .request("prompts/get", json!({"name": "greet"}))
        .await;
    assert_eq!(
        got.status, 200,
        "with the switch on, prompts/get must be answered"
    );
    assert_eq!(
        got.error_code(),
        None,
        "with the switch on, prompts/get must carry no JSON-RPC error"
    );
    assert_eq!(
        got.result(),
        Some(
            &json!({"messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}]})
        ),
        "prompts/get must return the upstream's answer"
    );
    let resources = client.request("resources/list", json!({})).await;
    assert_eq!(
        resources.result(),
        Some(&json!({"resources": []})),
        "the resources switch is off, so resources/list must stay empty"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateways_own_stateless_answers_are_well_formed() {
    let w = World::start().await;
    let (upstream, _id, tokens) = bob_on_demo(&w).await;
    let client = w.stateless_mcp("demo", &tokens);
    upstream.clear();
    for (method, key) in [
        ("resources/list", "resources"),
        ("resources/templates/list", "resourceTemplates"),
        ("prompts/list", "prompts"),
    ] {
        let reply = client.request(method, json!({})).await;
        assert_eq!(
            reply.status, 200,
            "{method} must be answered while the switch is off"
        );
        let result = reply.result().expect("a list answer must carry a result");
        assert_eq!(result[key], json!([]), "{method} must answer an empty list");
        assert_eq!(
            result["resultType"], "complete",
            "{method} must say resultType complete"
        );
        assert_eq!(result["ttlMs"], 60000, "{method} must say ttlMs 60000");
        assert_eq!(
            result["cacheScope"], "private",
            "{method} must say cacheScope private"
        );
    }
    assert!(
        upstream.requests().is_empty(),
        "the gateway must answer the switched-off lists itself"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn completion_needs_a_switch() {
    let w = World::start().await;
    let (upstream, id, tokens) = bob_on_demo(&w).await;
    let params = json!({
        "ref": {"type": "ref/prompt", "name": "greet"},
        "argument": {"name": "who", "value": "x"},
    });
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let refused = client.request("completion/complete", params.clone()).await;
    assert_eq!(
        refused.error_code(),
        Some(-32601),
        "completion/complete must be refused while both switches are off"
    );
    assert!(
        upstream.requests().is_empty(),
        "the refused completion must not be forwarded"
    );

    set_switches(&w, &upstream, &id, true, false).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let answered = client.request("completion/complete", params).await;
    assert_eq!(
        answered.status, 200,
        "with one switch on, completion/complete must be answered"
    );
    assert_eq!(
        answered.error_code(),
        Some(-32601),
        "the fake upstream answers completion/complete with its own -32601, which the client must receive"
    );
    assert_eq!(
        upstream.rpc_count("completion/complete"),
        1,
        "with one switch on, the upstream must receive completion/complete"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_completion_follows_the_switch_of_its_kind() {
    let w = World::start().await;
    let (upstream, id, tokens) = bob_on_demo(&w).await;
    let resource = json!({
        "ref": {"type": "ref/resource", "uri": "file:///secret.txt"},
        "argument": {"name": "uri", "value": "x"},
    });
    let prompt = json!({
        "ref": {"type": "ref/prompt", "name": "greet"},
        "argument": {"name": "who", "value": "x"},
    });

    set_switches(&w, &upstream, &id, true, false).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let forwarded = client
        .request("completion/complete", resource.clone())
        .await;
    assert_eq!(
        forwarded.status, 200,
        "with resources on, a ref/resource completion must be answered"
    );
    assert_eq!(
        upstream.rpc_count("completion/complete"),
        1,
        "with resources on and prompts off, a ref/resource completion must reach the upstream"
    );
    let refused = client.request("completion/complete", prompt.clone()).await;
    assert_eq!(
        refused.error_code(),
        Some(-32601),
        "with prompts off, a ref/prompt completion must be refused with -32601"
    );
    assert_eq!(
        refused.error_message(),
        Some("Method not found".to_string()),
        "the refused ref/prompt completion must carry the gateway's Method not found"
    );
    assert_eq!(
        upstream.rpc_count("completion/complete"),
        1,
        "with prompts off, a ref/prompt completion must not reach the upstream"
    );

    set_switches(&w, &upstream, &id, false, true).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let forwarded = client.request("completion/complete", prompt).await;
    assert_eq!(
        forwarded.status, 200,
        "with prompts on, a ref/prompt completion must be answered"
    );
    assert_eq!(
        upstream.rpc_count("completion/complete"),
        1,
        "with prompts on and resources off, a ref/prompt completion must reach the upstream"
    );
    let refused = client.request("completion/complete", resource).await;
    assert_eq!(
        refused.error_code(),
        Some(-32601),
        "with resources off, a ref/resource completion must be refused with -32601"
    );
    assert_eq!(
        upstream.rpc_count("completion/complete"),
        1,
        "with resources off, a ref/resource completion must not reach the upstream"
    );

    set_switches(&w, &upstream, &id, true, true).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let without_ref = json!({"argument": {"name": "who", "value": "x"}});
    let unknown_kind = json!({
        "ref": {"type": "ref/tool", "name": "echo"},
        "argument": {"name": "text", "value": "x"},
    });
    for (case, params) in [
        ("a completion with no ref", without_ref),
        ("a completion with an unknown ref.type", unknown_kind),
    ] {
        let reply = client.request("completion/complete", params).await;
        assert_eq!(
            reply.error_code(),
            Some(-32601),
            "{case} must be refused with -32601"
        );
    }
    assert_eq!(
        upstream.rpc_count("completion/complete"),
        0,
        "a completion that names no known kind must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn subscriptions_follow_the_resources_switch() {
    let w = World::start().await;
    let (upstream, id, tokens) = bob_on_demo(&w).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let refused = client
        .request("resources/subscribe", json!({"uri": "file:///secret.txt"}))
        .await;
    assert_eq!(
        refused.error_code(),
        Some(-32601),
        "resources/subscribe must be refused while the resources switch is off"
    );
    assert!(
        upstream.requests().is_empty(),
        "the refused subscription must not be forwarded"
    );

    set_switches(&w, &upstream, &id, true, false).await;
    let client = w.session_mcp("demo", &tokens);
    assert_eq!(
        client.initialize().await.status,
        200,
        "initialize must be relayed"
    );
    upstream.clear();
    let answered = client
        .request("resources/subscribe", json!({"uri": "file:///secret.txt"}))
        .await;
    assert_eq!(
        answered.status, 200,
        "with the resources switch on, resources/subscribe must be answered"
    );
    assert_eq!(
        answered.error_code(),
        Some(-32601),
        "the fake upstream answers resources/subscribe with its own -32601, which the client must receive"
    );
    assert_eq!(
        upstream.rpc_count("resources/subscribe"),
        1,
        "with the resources switch on, the upstream must receive resources/subscribe"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn switches_default_to_off_on_a_new_server() {
    let w = World::start().await;
    let (_upstream, id, _tokens) = bob_on_demo(&w).await;
    let page = w.owner.get(&format!("/admin/servers/{id}")).await;
    assert_eq!(page.status, 200, "the server page must render");
    assert_eq!(
        page.count(r#"input[name="pass_resources"]"#),
        1,
        "the server page must show the resources switch"
    );
    assert_eq!(
        page.count(r#"input[name="pass_prompts"]"#),
        1,
        "the server page must show the prompts switch"
    );
    assert_eq!(
        page.count(r#"input[name="pass_resources"][checked]"#),
        0,
        "the resources switch must be unchecked on a new server"
    );
    assert_eq!(
        page.count(r#"input[name="pass_prompts"][checked]"#),
        0,
        "the prompts switch must be unchecked on a new server"
    );
}
