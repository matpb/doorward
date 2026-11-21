//! The combined endpoint's relay of a streamed tools/call: progress and the answer reach the client,
//! every other event is dropped, and the call's activity row is written when the stream ends.

use std::io;
use std::time::Duration;

use axum::body::{Body, Bytes};
use futures_util::stream;
use serde_json::{Value, json};
use tokio::sync::mpsc::Sender;
use tokio::time::{Interval, MissedTickBehavior};

use super::combined::reissue;
use super::sse::sse_events;
use super::stream::{ACCESS_LOST, CHECK_FAILED, Framing, Owned, detail_of, record};
use super::upstream::{self, Cause, time_limit};
use crate::mcp::json::parse_strict;
use crate::oauth::guard::{Recheck, combined_still_valid_at};
use crate::web::limit::HELD_FRAME;

/// Chunks the client may lag the upstream by before the reading waits.
const CHANNEL: usize = 8;
/// How often the caller's access is checked while the stream is open.
const CHECK_EVERY: Duration = Duration::from_secs(1);
/// The method of the progress notifications that reach the client.
const PROGRESS: &str = "notifications/progress";
/// The detail of the row of a stream the client left.
const LEFT: &str = "the client closed the stream";

/// What the relay of one streamed call needs.
pub(super) struct Call {
    pub owned: Owned,
    /// The bare tool name, for the row.
    pub tool: String,
    /// The name as the client sent it, for a refusal.
    pub name: String,
    /// The id the link sent upstream.
    pub upstream_id: Value,
    /// The id the client sent.
    pub client_id: Value,
    /// True when the client speaks the stateless rules.
    pub stateless: bool,
}

type Item = Result<Bytes, io::Error>;

/// How the relay ended. `Answered` carries the outcome and detail of the answer that was sent.
enum End {
    Answered(&'static str, &'static str),
    Unavailable(Cause),
    Refused,
    CheckFailed,
    ClientGone,
}

/// The client's body for a streamed call: filtered events as they arrive, from a task that ends the
/// stream on the first end condition and writes the call's one activity row.
pub(super) fn relay(call: Call, response: reqwest::Response) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Item>(CHANNEL);
    tokio::spawn(run(call, response, tx));
    Body::from_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

async fn run(call: Call, mut response: reqwest::Response, tx: Sender<Item>) {
    let limit = call.owned.state.config.limits.tools_list_bytes;
    let idle_for = time_limit(&call.owned.state);
    let mut ticks =
        tokio::time::interval_at(tokio::time::Instant::now() + CHECK_EVERY, CHECK_EVERY);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let idle = tokio::time::sleep(idle_for);
    tokio::pin!(idle);
    let mut framing = Framing::default();
    let mut pending: Vec<u8> = Vec::new();
    let mut held = call
        .owned
        .state
        .links
        .budget()
        .reservation(Some(call.owned.caller.user_id));
    let end = loop {
        let next = tokio::select! {
            biased;
            _ = tx.closed() => break End::ClientGone,
            _ = ticks.tick() => match valid(&call).await {
                Recheck::Live => continue,
                Recheck::Lost => break End::Refused,
                Recheck::Failed => break End::CheckFailed,
            },
            _ = &mut idle => break End::Unavailable(Cause::NoAnswerInTime),
            chunk = response.chunk() => chunk,
        };
        let bytes = match next {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break End::Unavailable(Cause::NotMcp),
            Err(_) => break End::Unavailable(Cause::NoConnection),
        };
        idle.as_mut().reset(tokio::time::Instant::now() + idle_for);
        if framing.feed(&bytes, limit) {
            break End::Unavailable(Cause::TooLarge);
        }
        pending.extend_from_slice(&bytes);
        let (datas, used) = sse_events(&pending);
        pending.drain(..used);
        // The open event counts in the framing and in the unread tail: the larger counts it once.
        let open = usize::try_from(framing.open).unwrap_or(usize::MAX);
        if !held.set(open.max(pending.len())) {
            break End::Unavailable(Cause::Busy);
        }
        match pass(&call, &tx, &mut ticks, datas).await {
            Ok(None) => {}
            Ok(Some((outcome, detail))) => break End::Answered(outcome, detail),
            Err(end) => break end,
        }
    };
    let end = match end {
        End::Unavailable(cause) => {
            match deliver(&tx, &mut ticks, &call, unavailable(&call)).await {
                Ok(()) => End::Unavailable(cause),
                Err(later) => later,
            }
        }
        other => other,
    };
    let (outcome, detail) = match end {
        End::Answered(outcome, detail) => (outcome, detail.to_owned()),
        End::Unavailable(cause) => ("unavailable", upstream::fail(&call.owned.slug, cause)),
        End::Refused => ("refused", ACCESS_LOST.to_owned()),
        End::CheckFailed => ("unavailable", CHECK_FAILED.to_owned()),
        End::ClientGone => ("error", LEFT.to_owned()),
    };
    record(&call.owned, &call.tool, "allow", outcome, &detail).await;
}

/// Sends the progress notifications among `datas`, in order, and stops at the answer: its outcome
/// once it is sent. Every other event is dropped.
async fn pass(
    call: &Call,
    tx: &Sender<Item>,
    ticks: &mut Interval,
    datas: Vec<Vec<u8>>,
) -> Result<Option<(&'static str, &'static str)>, End> {
    for data in datas {
        let Ok(value) = parse_strict(&data) else {
            continue;
        };
        if is_progress(&value) {
            deliver(tx, ticks, call, frame(&value)).await?;
        } else if answers(&value, &call.upstream_id) {
            let (reply, outcome, detail) = match valid(call).await {
                Recheck::Live => {
                    let (reply, outcome) = reissue(&call.client_id, &value, call.stateless);
                    (reply, outcome, detail_of(&value, outcome))
                }
                Recheck::Lost => (refusal(&call.client_id, &call.name), "refused", ACCESS_LOST),
                Recheck::Failed => return Err(End::CheckFailed),
            };
            deliver(tx, ticks, call, frame(&reply)).await?;
            return Ok(Some((outcome, detail)));
        }
    }
    Ok(None)
}

/// True for an object with the progress method and no `id` member.
fn is_progress(value: &Value) -> bool {
    value.get("method").and_then(Value::as_str) == Some(PROGRESS) && value.get("id").is_none()
}

/// True for an object with `id` equal to `expected` and exactly one of `result` and `error`.
fn answers(value: &Value, expected: &Value) -> bool {
    value.get("id") == Some(expected)
        && value.get("result").is_some() != value.get("error").is_some()
}

/// Hands one event to the client in pieces of at most `HELD_FRAME` bytes, each waiting for room in the
/// channel. The wait ends early when the client leaves or the caller is refused.
async fn deliver(
    tx: &Sender<Item>,
    ticks: &mut Interval,
    call: &Call,
    mut event: Bytes,
) -> Result<(), End> {
    while !event.is_empty() {
        let size = event.len().min(HELD_FRAME);
        send_piece(tx, ticks, call, event.split_to(size)).await?;
    }
    Ok(())
}

/// Waits for room in the channel and queues one piece.
async fn send_piece(
    tx: &Sender<Item>,
    ticks: &mut Interval,
    call: &Call,
    piece: Bytes,
) -> Result<(), End> {
    loop {
        tokio::select! {
            biased;
            _ = tx.closed() => return Err(End::ClientGone),
            _ = ticks.tick() => {
                match valid(call).await {
                    Recheck::Live => {}
                    Recheck::Lost => return Err(End::Refused),
                    Recheck::Failed => return Err(End::CheckFailed),
                }
            }
            permit = tx.reserve() => {
                return match permit {
                    Ok(permit) => {
                        permit.send(Ok(piece));
                        Ok(())
                    }
                    Err(_) => Err(End::ClientGone),
                };
            }
        }
    }
}

/// The re-check of the call's caller, its expiries compared at the second it was admitted.
async fn valid(call: &Call) -> Recheck {
    combined_still_valid_at(
        &call.owned.state,
        &call.owned.caller,
        call.owned.server_id,
        call.owned.caller.admitted,
    )
    .await
}

/// One event of the client's stream: the `message` event line and the compact JSON as its data.
fn frame(value: &Value) -> Bytes {
    Bytes::from(format!("event: message\ndata: {value}\n\n"))
}

/// The JSON-RPC error that ends a stream whose upstream cannot finish the call.
fn unavailable(call: &Call) -> Bytes {
    frame(&json!({
        "jsonrpc": "2.0",
        "id": call.client_id,
        "error": {"code": -32000, "message": format!("Upstream {} is unavailable", call.owned.slug)},
    }))
}

/// The JSON-RPC refusal of a call, under the client's id, as the stream sends it.
fn refusal(id: &Value, name: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32602, "message": format!("Unknown tool: {name}")},
    })
}
