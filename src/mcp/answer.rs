//! The gateway's own JSON-RPC answers, each with the inert-content headers.

use axum::http::StatusCode;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;

use super::message::{Generation, Message};

#[derive(Serialize)]
struct Failure<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    error: Fault<'a>,
}

#[derive(Serialize)]
struct Fault<'a> {
    code: i64,
    message: &'a str,
}

#[derive(Serialize)]
struct Success<'a, R> {
    jsonrpc: &'static str,
    id: &'a Value,
    result: R,
}

/// An empty list under `key`; the stateless rules add the cache fields.
struct EmptyList<'a> {
    key: &'a str,
    stateless: bool,
}

impl Serialize for EmptyList<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(self.key, &Vec::<Value>::new())?;
        if self.stateless {
            map.serialize_entry("resultType", "complete")?;
            map.serialize_entry("ttlMs", &60_000)?;
            map.serialize_entry("cacheScope", "private")?;
        }
        map.end()
    }
}

/// A JSON-RPC error answer with the two inert-content headers and `application/json`.
pub fn error(status: StatusCode, id: Option<&Value>, code: i64, message: &str) -> Response {
    let null = Value::Null;
    let body = Failure {
        jsonrpc: "2.0",
        id: id.unwrap_or(&null),
        error: Fault { code, message },
    };
    respond(status, &body)
}

/// The 429 of a limited MCP request: JSON-RPC -32029 with a null id, and `Retry-After`.
pub fn limited(wait: u64) -> Response {
    crate::web::limit::retry_after(
        error(
            StatusCode::TOO_MANY_REQUESTS,
            None,
            -32029,
            "Too many requests",
        ),
        wait,
    )
}

/// The 502 answer for an upstream the gateway cannot use.
pub fn unavailable(slug: &str) -> Response {
    error(
        StatusCode::BAD_GATEWAY,
        None,
        -32000,
        &format!("Upstream {slug} is unavailable"),
    )
}

/// The answer for a `tools/call` whose name is not in the server's list.
pub fn unknown_tool(id: &Value, name: &str) -> Response {
    error(
        StatusCode::OK,
        Some(id),
        -32602,
        &format!("Unknown tool: {name}"),
    )
}

/// The empty list answer to `message`, with the cache fields under the stateless rules.
pub fn empty_list(message: &Message, key: &str) -> Response {
    let null = Value::Null;
    let body = Success {
        jsonrpc: "2.0",
        id: message.id.as_ref().unwrap_or(&null),
        result: EmptyList {
            key,
            stateless: message.generation == Generation::Stateless,
        },
    };
    respond(StatusCode::OK, &body)
}

fn respond<T: Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (
            status,
            [
                (CONTENT_TYPE, "application/json"),
                (X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (CONTENT_SECURITY_POLICY, "sandbox"),
            ],
            bytes,
        )
            .into_response(),
        // Unreachable: the bodies hold only strings, numbers and JSON values.
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
