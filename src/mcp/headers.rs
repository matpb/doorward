//! The stateless header rules: headers are only compared with the body, never trusted alone.

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::message::{Generation, Message, meta_version, param};

const BASE64_OPEN: &str = "=?base64?";
const BASE64_CLOSE: &str = "?=";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRefusal(pub String);

/// The stateless header rules of INTERFACE.md, checked against the body.
pub fn check_stateless(headers: &HeaderMap, message: &Message) -> Result<(), HeaderRefusal> {
    if message.generation == Generation::Session {
        return Ok(());
    }
    let version = meta_version(&message.value).and_then(Value::as_str);
    must_match(
        headers,
        "mcp-protocol-version",
        "MCP-Protocol-Version",
        version,
    )?;
    must_match(
        headers,
        "mcp-method",
        "Mcp-Method",
        message.method.as_deref(),
    )?;
    let name = match message.method.as_deref() {
        Some("tools/call" | "prompts/get") => param(&message.value, "name"),
        Some("resources/read") => param(&message.value, "uri"),
        _ => return Ok(()),
    };
    must_match(
        headers,
        "mcp-name",
        "Mcp-Name",
        name.and_then(Value::as_str),
    )
}

/// Decodes the `=?base64?...?=` form; any other value is returned as it is.
/// None when the payload is not base64 of UTF-8.
pub fn decoded(value: &str) -> Option<String> {
    let Some(payload) = value
        .strip_prefix(BASE64_OPEN)
        .and_then(|rest| rest.strip_suffix(BASE64_CLOSE))
    else {
        return Some(value.to_owned());
    };
    let bytes = STANDARD.decode(payload).ok()?;
    String::from_utf8(bytes).ok()
}

/// Refuses unless the header occurs once and its decoded value equals `expected`.
fn must_match(
    headers: &HeaderMap,
    name: &'static str,
    label: &str,
    expected: Option<&str>,
) -> Result<(), HeaderRefusal> {
    let mut values = headers.get_all(name).iter();
    let actual = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().and_then(decoded),
        _ => None,
    };
    match (actual, expected) {
        (Some(actual), Some(expected)) if actual == expected => Ok(()),
        _ => Err(HeaderRefusal(format!("Header mismatch: {label}"))),
    }
}
