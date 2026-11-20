//! The watched relay of an upstream event stream: bytes pass as they arrive, the caller's access is
//! checked every second, and the call's activity row is written when the stream ends.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use futures_util::stream;
use serde_json::Value;
use tokio::sync::mpsc::Sender;
use tokio::time::{Interval, MissedTickBehavior};

use super::catalog::answer_of;
use super::handle::{TOOL_LIMIT, cut};
use super::sse::sse_events;
use super::upstream::{Cause, fail, time_limit};
use crate::app::AppState;
use crate::audit::{self, OwnedEvent};
use crate::mcp::json::parse_strict;
use crate::oauth::guard::{Caller, still_valid};
use crate::report;

/// Chunks the client may lag the upstream by before the reading waits.
const CHANNEL: usize = 8;
/// How often the caller's access is checked while the stream is open.
const CHECK_EVERY: Duration = Duration::from_secs(1);

/// What the relay task needs after its handler has returned.
pub(super) struct Owned {
    pub(super) state: AppState,
    pub(super) slug: String,
    pub(super) server_id: i64,
    pub(super) caller: Arc<Caller>,
    pub(super) started: Instant,
}

/// The tools/call a stream answers, with its request id; `call` is None for any other request.
pub(super) struct Watch {
    pub call: Option<String>,
    pub id: Value,
}

/// The detail of a row whose caller lost access.
pub(super) const ACCESS_LOST: &str = "access was lost";
/// The detail of a row whose client left before the answer.
const CLOSED: &str = "the client closed the stream";
/// The detail of a row whose tool reported an error.
pub(super) const TOOL_ERROR: &str = "the tool reported an error";

/// Why the relay ended.
#[derive(Clone, Copy)]
enum End {
    Done,
    Broken,
    Idle,
    Oversize,
    Refused,
    ClientGone,
}

type Item = Result<Bytes, io::Error>;

/// The client's body of `response`: its bytes as they arrive, watched by a task that ends the stream
/// on the first of the end conditions.
pub(super) fn relay(ctx: Owned, response: reqwest::Response, watch: Watch) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Item>(CHANNEL);
    tokio::spawn(run(ctx, response, watch, tx));
    Body::from_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

async fn run(ctx: Owned, mut response: reqwest::Response, watch: Watch, tx: Sender<Item>) {
    let limit = ctx.state.config.limits.tools_list_bytes;
    let idle_for = time_limit(&ctx.state);
    let mut ticks =
        tokio::time::interval_at(tokio::time::Instant::now() + CHECK_EVERY, CHECK_EVERY);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let idle = tokio::time::sleep(idle_for);
    tokio::pin!(idle);
    let mut observer = Observer::default();
    let end = loop {
        let next = tokio::select! {
            biased;
            _ = tx.closed() => break End::ClientGone,
            _ = ticks.tick() => {
                if !still_valid(&ctx.state, &ctx.caller, &ctx.slug).await {
                    break End::Refused;
                }
                continue;
            }
            _ = &mut idle => break End::Idle,
            chunk = response.chunk() => chunk,
        };
        let bytes = match next {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break End::Done,
            Err(_) => break End::Broken,
        };
        idle.as_mut().reset(tokio::time::Instant::now() + idle_for);
        if let Err(end) = deliver(&tx, &mut ticks, &ctx, bytes.clone()).await {
            break end;
        }
        if observer.feed(&bytes, watch.call.is_some().then_some(&watch.id), limit) {
            break End::Oversize;
        }
    };
    if let Some(call) = watch.call.as_deref() {
        let (outcome, detail) = match (observer.answer.outcome, end) {
            (Some(outcome), End::ClientGone) => (outcome, CLOSED.to_owned()),
            (Some(outcome), _) => (outcome, observer.answer.detail.to_owned()),
            (None, End::Refused) => ("refused", ACCESS_LOST.to_owned()),
            (None, End::ClientGone) => ("error", CLOSED.to_owned()),
            (None, End::Broken) => ("unavailable", fail(&ctx.slug, Cause::NoConnection)),
            (None, End::Idle) => ("unavailable", fail(&ctx.slug, Cause::NoAnswerInTime)),
            (None, End::Oversize) => ("unavailable", fail(&ctx.slug, Cause::TooLarge)),
            (None, End::Done) => ("unavailable", fail(&ctx.slug, Cause::NotMcp)),
        };
        record(&ctx, call, "allow", outcome, &detail).await;
    }
}

/// Hands one chunk to the client, waiting for room in the channel. The wait ends early when the
/// client leaves or the caller is refused.
async fn deliver(
    tx: &Sender<Item>,
    ticks: &mut Interval,
    ctx: &Owned,
    bytes: Bytes,
) -> Result<(), End> {
    loop {
        tokio::select! {
            biased;
            _ = tx.closed() => return Err(End::ClientGone),
            _ = ticks.tick() => {
                if !still_valid(&ctx.state, &ctx.caller, &ctx.slug).await {
                    return Err(End::Refused);
                }
            }
            permit = tx.reserve() => {
                return match permit {
                    Ok(permit) => {
                        permit.send(Ok(bytes));
                        Ok(())
                    }
                    Err(_) => Err(End::ClientGone),
                };
            }
        }
    }
}

/// Counts the bytes since the last blank line, which is the open event, and the events that end.
/// A blank line is an empty line or a lone CR, as `sse_events` reads it.
#[derive(Default)]
pub(super) struct Framing {
    pub(super) open: u64,
    pub(super) ended: u64,
    line: Line,
}

/// What the current line holds so far.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Line {
    #[default]
    Empty,
    LoneCr,
    Text,
}

impl Framing {
    /// True once the open event passes `limit`.
    pub(super) fn feed(&mut self, chunk: &[u8], limit: u64) -> bool {
        for &byte in chunk {
            self.open += 1;
            if self.open > limit {
                return true;
            }
            match (byte, self.line) {
                (b'\n', Line::Text) => self.line = Line::Empty,
                (b'\n', _) => {
                    self.open = 0;
                    self.ended += 1;
                    self.line = Line::Empty;
                }
                (b'\r', Line::Empty) => self.line = Line::LoneCr,
                _ => self.line = Line::Text,
            }
        }
        false
    }
}

/// The unread tail of the stream and the call's outcome and detail once its answer is seen.
#[derive(Default)]
pub(super) struct Observed {
    pub(super) pending: Vec<u8>,
    pub(super) outcome: Option<&'static str>,
    pub(super) detail: &'static str,
    #[cfg(test)]
    pub(super) scans: usize,
}

impl Observed {
    /// Feeds one chunk; `ended` says it completed an event. True when the unread bytes pass `limit`.
    pub(super) fn feed(&mut self, chunk: &[u8], ended: bool, id: &Value, limit: u64) -> bool {
        if self.outcome.is_some() {
            return false;
        }
        self.pending.extend_from_slice(chunk);
        if ended {
            self.scan(id);
        }
        if self.outcome.is_some() {
            self.pending = Vec::new();
            return false;
        }
        self.pending.len() as u64 > limit
    }

    fn scan(&mut self, id: &Value) {
        #[cfg(test)]
        {
            self.scans += 1;
        }
        let (events, used) = sse_events(&self.pending);
        self.pending.drain(..used);
        for data in events {
            let answer = parse_strict(&data)
                .ok()
                .and_then(|value| answer_of(value, id));
            if let Some(answer) = answer {
                let (outcome, detail) = settled_by(&answer);
                self.outcome = Some(outcome);
                self.detail = detail;
                return;
            }
        }
    }
}

/// Both readers of the stream, fed one chunk at a time.
#[derive(Default)]
pub(super) struct Observer {
    pub(super) framing: Framing,
    pub(super) answer: Observed,
}

impl Observer {
    /// Feeds one chunk; `id` is the watched request's id, None when nothing is watched. True when the
    /// stream must end as oversize.
    pub(super) fn feed(&mut self, chunk: &[u8], id: Option<&Value>, limit: u64) -> bool {
        let before = self.framing.ended;
        if self.framing.feed(chunk, limit) {
            return true;
        }
        let ended = self.framing.ended != before;
        match id {
            Some(id) => self.answer.feed(chunk, ended, id, limit),
            None => false,
        }
    }
}

/// `ok` for a JSON-RPC result, `error` for anything else.
pub(super) fn outcome_of(answer: &Value) -> &'static str {
    if answer.get("result").is_some() && answer.get("error").is_none() {
        "ok"
    } else {
        "error"
    }
}

/// The outcome of an answer and its row detail: a result that reports a tool error keeps `ok` and says so.
pub(super) fn settled_by(answer: &Value) -> (&'static str, &'static str) {
    let outcome = outcome_of(answer);
    (outcome, detail_of(answer, outcome))
}

/// TOOL_ERROR for an ok outcome whose result reports a tool error; empty otherwise.
pub(super) fn detail_of(answer: &Value, outcome: &str) -> &'static str {
    let reported = answer.pointer("/result/isError") == Some(&Value::Bool(true));
    if outcome == "ok" && reported {
        TOOL_ERROR
    } else {
        ""
    }
}

/// One tool_call row. A failed write is reported and changes nothing else.
pub(super) async fn record(ctx: &Owned, tool: &str, decision: &str, outcome: &str, detail: &str) {
    let elapsed = i64::try_from(ctx.started.elapsed().as_millis()).unwrap_or(i64::MAX);
    let event = OwnedEvent {
        kind: "tool_call".to_owned(),
        user_id: Some(ctx.caller.user_id),
        user_email: ctx.caller.user_email.clone(),
        server_id: Some(ctx.server_id),
        server_slug: ctx.slug.clone(),
        tool: cut(tool, TOOL_LIMIT),
        client: ctx.caller.client_name.clone(),
        decision: decision.to_owned(),
        outcome: outcome.to_owned(),
        detail: detail.to_owned(),
        duration_ms: Some(elapsed),
    };
    if let Err(err) = audit::record_now(&ctx.state, event).await {
        report::failure("activity row", &err);
    }
}
