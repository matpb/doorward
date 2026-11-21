//! The checks every POST passes before its method is looked at: encoding, body cap, JSON, shape and headers.

use axum::body::{Body, Bytes};
use axum::http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::Value;

use super::handle::{INVALID, PARSE, bare, version_of};
use crate::app::AppState;
use crate::mcp::answer;
use crate::mcp::headers::{HeaderRefusal, check_stateless};
use crate::mcp::json::{JsonRefusal, parse_strict};
use crate::mcp::message::{
    Generation, Message, Refusal, Shape, classify, meta_capabilities, meta_version,
};
use crate::web::body::{ReadError, read, timed_out};

const MISSING_META: &str = "Invalid params: missing _meta, protocol version or client capabilities";

/// A POST that passed intake: its classified message and its body bytes.
pub(super) struct Intake {
    pub message: Message,
    pub bytes: Bytes,
}

/// Content encoding and charset, the body cap, strict JSON, the shape, the version header rule and
/// the stateless header rules. Each refusal is the answer the server path always gave.
pub(super) async fn intake(
    state: &AppState,
    headers: &HeaderMap,
    body: Body,
) -> Result<Intake, Response> {
    if headers.contains_key(CONTENT_ENCODING) || !utf8_only(headers) {
        return Err(answer::error(
            StatusCode::BAD_REQUEST,
            None,
            -32600,
            INVALID,
        ));
    }
    let limit = usize::try_from(state.config.limits.body_bytes).unwrap_or(usize::MAX);
    let bytes = match read(body, limit, state.config.limits.body_read_seconds).await {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge) => return Err(bare(StatusCode::PAYLOAD_TOO_LARGE)),
        Err(ReadError::TimedOut) => return Err(timed_out()),
    };
    let value = match parse_strict(&bytes) {
        Ok(value) => value,
        Err(JsonRefusal::Encoding) => {
            return Err(answer::error(
                StatusCode::BAD_REQUEST,
                None,
                -32600,
                INVALID,
            ));
        }
        Err(JsonRefusal::Syntax) => {
            return Err(answer::error(StatusCode::BAD_REQUEST, None, -32700, PARSE));
        }
    };
    let (version, clean) = version_of(headers);
    let message = match classify(value, version) {
        Ok(message) => message,
        Err(Refusal::InvalidRequest) => {
            return Err(answer::error(
                StatusCode::BAD_REQUEST,
                None,
                -32600,
                INVALID,
            ));
        }
    };
    if !clean && message.generation == Generation::Session {
        return Err(answer::error(
            StatusCode::BAD_REQUEST,
            message.id.as_ref(),
            -32600,
            INVALID,
        ));
    }
    let missing_version = match meta_version(&message.value) {
        Some(version) => !version.is_string(),
        None => message.shape == Shape::Request,
    };
    if message.generation == Generation::Stateless && missing_version {
        return Err(missing_meta(&message));
    }
    if message.generation == Generation::Stateless
        && message.shape == Shape::Request
        && !meta_capabilities(&message.value).is_some_and(Value::is_object)
    {
        return Err(missing_meta(&message));
    }
    if let Err(HeaderRefusal(text)) = check_stateless(headers, &message) {
        return Err(answer::error(
            StatusCode::BAD_REQUEST,
            message.id.as_ref(),
            -32020,
            &text,
        ));
    }
    Ok(Intake { message, bytes })
}

/// The -32602 refusal of a stateless body without its protocol version or client capabilities.
fn missing_meta(message: &Message) -> Response {
    answer::error(
        StatusCode::BAD_REQUEST,
        message.id.as_ref(),
        -32602,
        MISSING_META,
    )
}

/// The client's Content-Type values are all readable and name no charset but UTF-8.
fn utf8_only(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_TYPE).iter().all(|value| {
        let Ok(text) = value.to_str() else {
            return false;
        };
        text.split(';')
            .skip(1)
            .filter_map(|param| param.split_once('='))
            .filter(|(key, _)| key.trim().eq_ignore_ascii_case("charset"))
            .all(|(_, charset)| {
                charset
                    .trim()
                    .trim_matches('"')
                    .eq_ignore_ascii_case("utf-8")
            })
    })
}
