mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::admin;
use common::mcp::{McpClient, McpReply};
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use common::world::World;
use serde_json::{Value, json};
use tokio::sync::mpsc;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
/// The text length of one held answer: about 200000 bytes in all.
const ANSWER: usize = 200_000;
/// `limits.tools_list_bytes` in every test here.
const TOOLS_LIST: u64 = 262_144;
/// `limits.answer_memory_bytes` for two answers and a little over.
const BUDGET: u64 = 524_288;
/// Concurrent calls in the burst tests.
const CALLS: usize = 6;
const BUSY: &str = "The gateway is busy";
const WAIT: Duration = Duration::from_secs(20);
/// How long the burst waits with no further answer before it releases the upstream.
const QUIET: Duration = Duration::from_secs(3);
/// Long enough for the gateway to read what the upstream has sent.
const SETTLE: Duration = Duration::from_secs(1);

/// A gateway with the two limits of these tests, and Bob signed in.
async fn world(budget: u64) -> (World, common::client::TestClient) {
    let w = World::start_with(move |c| {
        c.limits.tools_list_bytes = TOOLS_LIST;
        c.limits.answer_memory_bytes = budget;
    })
    .await;
    let bob = w.user(BOB).await;
    (w, bob)
}

/// The text of a successful echo answer, checked to be the whole held answer.
fn assert_whole(reply: &McpReply) {
    assert_eq!(reply.status, 200, "an answer that fits the budget is 200");
    assert_eq!(
        reply.text().map(|text| text.len()),
        Some(ANSWER),
        "the answer must come back whole"
    );
}

/// A refusal for the gateway's own budget: 503, Retry-After 1, no-store, JSON-RPC -32000 with a null id.
fn assert_busy(reply: &McpReply) {
    assert_eq!(reply.status, 503, "a refused call answers 503");
    assert_eq!(reply.header("retry-after").as_deref(), Some("1"));
    assert_eq!(reply.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(reply.error_code(), Some(-32000));
    assert_eq!(reply.error_message().as_deref(), Some(BUSY));
    assert_eq!(
        reply.json.as_ref().and_then(|json| json.get("id")),
        Some(&Value::Null)
    );
}

/// Starts `CALLS` echo calls at once and waits until the upstream holds all of them. Returns the
/// answers that arrived while it held them, and the answers that arrived after it was released.
async fn burst(
    client: Arc<McpClient>,
    upstream: &FakeUpstream,
) -> (Vec<(usize, McpReply)>, Vec<(usize, McpReply)>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    for index in 0..CALLS {
        let client = Arc::clone(&client);
        let tx = tx.clone();
        tokio::spawn(async move {
            let reply = client.call_tool("echo", json!({"text": "hi"})).await;
            let _ = tx.send((index, reply));
        });
    }
    drop(tx);
    assert!(
        upstream.wait_held(CALLS, WAIT).await,
        "the upstream began {} of {CALLS} answers",
        upstream.held_begun()
    );
    let mut early = Vec::new();
    while let Ok(Some(item)) = tokio::time::timeout(QUIET, rx.recv()).await {
        early.push(item);
    }
    upstream.release();
    let mut late = Vec::new();
    while early.len() + late.len() < CALLS {
        match tokio::time::timeout(WAIT, rx.recv()).await {
            Ok(Some(item)) => late.push(item),
            _ => break,
        }
    }
    (early, late)
}

/// The shared checks of a burst: a refusal arrives while the others are held, every call is 200 or 503,
/// and at most two whole answers fit the budget.
fn assert_burst(early: &[(usize, McpReply)], late: &[(usize, McpReply)]) {
    let statuses: Vec<u16> = early.iter().chain(late).map(|(_, r)| r.status).collect();
    let refused_early = early.iter().filter(|(_, r)| r.status == 503).count();
    assert!(
        refused_early >= 1,
        "while {CALLS} answers were held, no call was refused; statuses were {statuses:?}"
    );
    for (_, reply) in early.iter().filter(|(_, r)| r.status == 503) {
        assert_busy(reply);
    }
    let answered: Vec<&McpReply> = early
        .iter()
        .chain(late)
        .map(|(_, r)| r)
        .filter(|r| r.status == 200)
        .collect();
    assert_eq!(
        answered.len() + refused_early + late.iter().filter(|(_, r)| r.status == 503).count(),
        CALLS,
        "every call is answered 200 or 503, statuses were {statuses:?}"
    );
    assert!(
        answered.len() <= 2,
        "{BUDGET} bytes hold two answers of {ANSWER} bytes: {} were answered 200",
        answered.len()
    );
    for reply in answered {
        assert_whole(reply);
    }
}

/// A call after the burst: the budget is free again once the last answer has been written, so the call
/// is answered 200 within a few seconds.
async fn call_after(client: &McpClient) -> McpReply {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let reply = client.call_tool("echo", json!({"text": "hi"})).await;
        if reply.status == 200 || Instant::now() >= deadline {
            return reply;
        }
        assert_busy(&reply);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_past_the_budget_is_refused_while_held_and_the_budget_comes_back() {
    let (w, bob) = world(BUDGET).await;
    let (upstream, id) = w.upstream("burst", UpstreamOptions::default()).await;
    w.grant(BOB, &[&id]).await;
    let tokens = w.token(&bob, "burst").await;
    let client = Arc::new(w.session_mcp("burst", &tokens));
    client.initialize().await;
    upstream.set_mode(Mode::HeldAnswer { bytes: ANSWER });

    let (early, late) = burst(Arc::clone(&client), &upstream).await;
    assert_burst(&early, &late);

    let reply = call_after(&client).await;
    assert_whole(&reply);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_burst_on_the_stateless_generation() {
    let (w, bob) = world(BUDGET).await;
    let (upstream, id) = w
        .upstream("burst-stateless", UpstreamOptions::default())
        .await;
    w.grant(BOB, &[&id]).await;
    let tokens = w.token(&bob, "burst-stateless").await;
    upstream.set_mode(Mode::HeldAnswer { bytes: ANSWER });

    let client = Arc::new(w.stateless_mcp("burst-stateless", &tokens));
    let (early, late) = burst(client, &upstream).await;
    assert_burst(&early, &late);

    let reply = call_after(&w.stateless_mcp("burst-stateless", &tokens)).await;
    assert_whole(&reply);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_event_past_the_remaining_budget_ends_the_stream() {
    let (w, bob) = world(BUDGET).await;
    let (held, held_id) = w.upstream("held-answers", UpstreamOptions::default()).await;
    let (stream, stream_id) = w.upstream("held-stream", UpstreamOptions::default()).await;
    w.grant(BOB, &[&held_id, &stream_id]).await;
    let held_tokens = w.token(&bob, "held-answers").await;
    let stream_tokens = w.token(&bob, "held-stream").await;
    held.set_mode(Mode::HeldAnswer { bytes: ANSWER });
    stream.set_mode(Mode::HeldStream { bytes: ANSWER });

    // Five held answers hold 125 of the 128 permits while the stream runs.
    let held_client = Arc::new(w.stateless_mcp("held-answers", &held_tokens));
    let mut held_calls = Vec::new();
    for _ in 0..5 {
        let client = Arc::clone(&held_client);
        held_calls.push(tokio::spawn(async move {
            client.call_tool("echo", json!({"text": "hi"})).await
        }));
    }
    assert!(held.wait_held(5, WAIT).await, "five answers must begin");
    tokio::time::sleep(SETTLE).await;

    let streamed_client = w.stateless_mcp("held-stream", &stream_tokens);
    let streamed = tokio::spawn(async move {
        streamed_client
            .call_tool("echo", json!({"text": "hi"}))
            .await
    });
    assert!(stream.wait_held(1, WAIT).await, "the stream must begin");
    tokio::time::sleep(SETTLE).await;
    stream.release();
    let reply = streamed.await.expect("stream task");
    assert!(
        reply.result().is_none(),
        "the stream must end before its event is whole"
    );

    let rows = admin::activity_with_details(&w.owner, None, Some(&stream_id)).await;
    let calls: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call")
        .collect();
    assert_eq!(calls.len(), 1, "one tool_call row, rows were {rows:?}");
    assert_eq!(calls[0].0.outcome, "unavailable");
    assert_eq!(calls[0].1, "the answer memory budget is exhausted");

    held.release();
    for call in held_calls {
        call.await.expect("held call task");
    }
}

/// Alice's four held calls and Bob's one plain call, with a budget whose share for one user is 262144 bytes.
#[tokio::test(flavor = "multi_thread")]
async fn a_user_at_its_share_is_refused_and_another_user_still_answers() {
    let w = World::start_with(|c| {
        c.limits.tools_list_bytes = TOOLS_LIST;
        c.limits.answer_memory_bytes = 1_048_576;
    })
    .await;
    let alice = w.user(ALICE).await;
    let bob = w.user(BOB).await;
    let (held, held_id) = w.upstream("held-answers", UpstreamOptions::default()).await;
    let (plain, plain_id) = w
        .upstream("plain-answers", UpstreamOptions::default())
        .await;
    w.grant(ALICE, &[&held_id]).await;
    w.grant(BOB, &[&plain_id]).await;
    let alice_tokens = w.token(&alice, "held-answers").await;
    let bob_tokens = w.token(&bob, "plain-answers").await;
    held.set_mode(Mode::HeldAnswer { bytes: ANSWER });
    plain.set_mode(Mode::Oversized { bytes: ANSWER });

    let alice_client = Arc::new(w.stateless_mcp("held-answers", &alice_tokens));
    // Longer than WAIT, so a call that is still held is missing rather than timed out.
    alice_client.set_timeout(WAIT + Duration::from_secs(5));
    let (tx, mut rx) = mpsc::unbounded_channel();
    for _ in 0..4 {
        let client = Arc::clone(&alice_client);
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(client.call_tool("echo", json!({"text": "hi"})).await);
        });
    }
    drop(tx);
    assert!(held.wait_held(4, WAIT).await, "four answers must begin");

    // Alice's first two answers stay held; her next ones are refused by her share and answer at once.
    let mut refused = Vec::new();
    while refused.len() < 2 {
        match tokio::time::timeout(WAIT, rx.recv()).await {
            Ok(Some(reply)) => refused.push(reply),
            _ => break,
        }
    }
    assert!(
        refused.len() >= 2,
        "alice must be refused twice while her first answers are held, got {}",
        refused.len()
    );
    for reply in &refused {
        assert_busy(reply);
    }

    let bob_client = w.stateless_mcp("plain-answers", &bob_tokens);
    let reply = tokio::time::timeout(WAIT, bob_client.call_tool("echo", json!({"text": "hi"})))
        .await
        .expect("bob's answer must not wait for alice's held answers");
    assert_eq!(
        reply.status, 200,
        "bob's answer is within his own share and the budget"
    );
    assert!(reply.result().is_some(), "bob's answer must be a result");

    held.release();
    let mut answers = Vec::new();
    while let Ok(Some(reply)) = tokio::time::timeout(WAIT, rx.recv()).await {
        answers.push(reply);
    }
    assert_eq!(
        answers.len() + refused.len(),
        4,
        "every one of alice's calls is answered"
    );
    // Her share holds one whole answer: the second held answer is refused when its tail arrives.
    let answered: Vec<&McpReply> = answers.iter().filter(|r| r.status == 200).collect();
    assert_eq!(
        answered.len(),
        1,
        "alice's share holds one whole answer, so exactly one of her held answers completes"
    );
    assert_whole(answered[0]);
    for reply in answers.iter().filter(|r| r.status != 200) {
        assert_busy(reply);
    }
}

/// The notice an admin's refresh shows while the budget is used up.
const BUSY_PAGE: &str = "The gateway is busy. Try again in a moment.";

/// Two held answers of 262000 bytes take 32 permits each, which is the whole 64-permit budget here, so
/// the admin's refresh finds no memory and says so on the server page.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_the_budget_refuses_says_the_gateway_is_busy() {
    let w = World::start_with(|c| {
        c.limits.tools_list_bytes = TOOLS_LIST;
        c.limits.answer_memory_bytes = TOOLS_LIST;
    })
    .await;
    let alice = w.user(ALICE).await;
    let bob = w.user(BOB).await;
    let (held, id) = w.upstream("held-answers", UpstreamOptions::default()).await;
    w.grant(ALICE, &[&id]).await;
    w.grant(BOB, &[&id]).await;
    let alice_tokens = w.token(&alice, "held-answers").await;
    let bob_tokens = w.token(&bob, "held-answers").await;
    held.set_mode(Mode::HeldAnswer { bytes: 262_000 });

    let mut calls = Vec::new();
    for tokens in [alice_tokens, bob_tokens] {
        let client = w.stateless_mcp("held-answers", &tokens);
        calls.push(tokio::spawn(async move {
            client.call_tool("echo", json!({"text": "hi"})).await
        }));
    }
    assert!(held.wait_held(2, WAIT).await, "both answers must begin");

    let page = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(page.status, 503, "a refresh the budget refuses answers 503");
    assert!(
        page.texts(r#"[data-notice="error"]"#)
            .contains(&BUSY_PAGE.to_owned()),
        "the server page must say the gateway is busy"
    );

    // Once released, the two tails compete for the same 66 permits: each answer is 200 or refused.
    held.release();
    for call in calls {
        let reply = call.await.expect("call task");
        assert!(
            reply.status == 200 || reply.status == 503,
            "a held answer ends as 200 or 503, got {}",
            reply.status
        );
    }
}
