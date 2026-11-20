//! Classifies one JSON-RPC message by generation, shape and method, and decides its fate.

use serde_json::Value;
use time::{Date, Month};

const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// The first revision of the stateless rules; well-formed dates compare as strings.
const STATELESS_FROM: &str = "2026-07-28";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    Session,
    Stateless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Request,
    Notification,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub generation: Generation,
    pub shape: Shape,
    pub method: Option<String>,
    pub id: Option<Value>,
    pub tool: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    InvalidRequest,
}

/// `version_header` is the single MCP-Protocol-Version value, when one was sent.
pub fn classify(value: Value, version_header: Option<&str>) -> Result<Message, Refusal> {
    let object = value.as_object().ok_or(Refusal::InvalidRequest)?;
    let id = object.get("id").cloned();
    if id.as_ref().is_some_and(|id| !is_valid_id(id)) {
        return Err(Refusal::InvalidRequest);
    }
    let (shape, method) = match object.get("method") {
        Some(Value::String(name)) if id.is_some() => (Shape::Request, Some(name.clone())),
        Some(Value::String(name)) => (Shape::Notification, Some(name.clone())),
        Some(_) => return Err(Refusal::InvalidRequest),
        None if object.contains_key("result") || object.contains_key("error") => {
            (Shape::Response, None)
        }
        None => return Err(Refusal::InvalidRequest),
    };
    let is_call = method.as_deref() == Some("tools/call");
    if is_call && id.is_none() {
        return Err(Refusal::InvalidRequest);
    }
    let generation = if stateless(version_header, &value) {
        Generation::Stateless
    } else {
        Generation::Session
    };
    if shape == Shape::Response && generation == Generation::Stateless {
        return Err(Refusal::InvalidRequest);
    }
    let tool = if is_call {
        param(&value, "name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };
    Ok(Message {
        generation,
        shape,
        method,
        id,
        tool,
        value,
    })
}

/// A string, or an i64 or u64 number; null, fractions, booleans, objects and arrays are refused.
fn is_valid_id(id: &Value) -> bool {
    match id {
        Value::String(_) => true,
        Value::Number(number) => number.is_i64() || number.is_u64(),
        _ => false,
    }
}

/// `params.<key>` of a message, when `params` is an object that has it.
pub(crate) fn param<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get("params")?.get(key)
}

/// The protocol version the body carries in `params._meta`, of any JSON type.
pub(crate) fn meta_version(value: &Value) -> Option<&Value> {
    param(value, "_meta")?.get(META_VERSION)
}

/// True when the version header is a well-formed date from 2026-07-28 on.
pub fn stateless_version(version_header: Option<&str>) -> bool {
    version_header.is_some_and(|version| is_calendar_date(version) && version >= STATELESS_FROM)
}

fn stateless(version_header: Option<&str>, value: &Value) -> bool {
    stateless_version(version_header) || meta_version(value).is_some()
}

/// True for `YYYY-MM-DD` that names a real calendar day.
fn is_calendar_date(text: &str) -> bool {
    let mut parts = text.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let digits = |part: &str, width: usize| {
        part.len() == width && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !(digits(year, 4) && digits(month, 2) && digits(day, 2)) {
        return false;
    }
    let month = month
        .parse::<u8>()
        .ok()
        .and_then(|m| Month::try_from(m).ok());
    match (year.parse::<i32>(), month, day.parse::<u8>()) {
        (Ok(year), Some(month), Ok(day)) => Date::from_calendar_date(year, month, day).is_ok(),
        _ => false,
    }
}

/// What the gateway allows of the two switchable groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switches {
    pub resources: bool,
    pub prompts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Forward,
    EmptyList(&'static str),
    MethodNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Always,
    Resources,
    Prompts,
    Completion,
}

const SESSION: &[(&str, Group)] = &[
    ("initialize", Group::Always),
    ("ping", Group::Always),
    ("tools/list", Group::Always),
    ("tools/call", Group::Always),
    ("logging/setLevel", Group::Always),
    ("notifications/initialized", Group::Always),
    ("notifications/cancelled", Group::Always),
    ("notifications/progress", Group::Always),
    ("notifications/roots/list_changed", Group::Always),
    ("resources/list", Group::Resources),
    ("resources/templates/list", Group::Resources),
    ("resources/read", Group::Resources),
    ("resources/subscribe", Group::Resources),
    ("resources/unsubscribe", Group::Resources),
    ("prompts/list", Group::Prompts),
    ("prompts/get", Group::Prompts),
    ("completion/complete", Group::Completion),
];

const STATELESS: &[(&str, Group)] = &[
    ("server/discover", Group::Always),
    ("tools/list", Group::Always),
    ("tools/call", Group::Always),
    ("notifications/cancelled", Group::Always),
    ("resources/list", Group::Resources),
    ("resources/templates/list", Group::Resources),
    ("resources/read", Group::Resources),
    ("prompts/list", Group::Prompts),
    ("prompts/get", Group::Prompts),
    ("completion/complete", Group::Completion),
];

/// What to do with a request or notification on `/{slug}`, by the method tables of INTERFACE.md.
pub fn decide(message: &Message, switches: Switches) -> Decision {
    let Some(method) = message.method.as_deref() else {
        return Decision::MethodNotFound;
    };
    if method.starts_with("tasks/") || param(&message.value, "task").is_some() {
        return Decision::MethodNotFound;
    }
    let Some(group) = group_of(method, message.generation) else {
        return Decision::MethodNotFound;
    };
    let enabled = match group {
        Group::Always => return Decision::Forward,
        Group::Resources => switches.resources,
        Group::Prompts => switches.prompts,
        Group::Completion => switches.resources || switches.prompts,
    };
    if enabled {
        return Decision::Forward;
    }
    match list_key(method) {
        Some(key) => Decision::EmptyList(key),
        None => Decision::MethodNotFound,
    }
}

fn group_of(method: &str, generation: Generation) -> Option<Group> {
    let table = match generation {
        Generation::Session => SESSION,
        Generation::Stateless => STATELESS,
    };
    table
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, group)| *group)
}

/// The result key of a list method whose group may be switched off.
fn list_key(method: &str) -> Option<&'static str> {
    match method {
        "resources/list" => Some("resources"),
        "resources/templates/list" => Some("resourceTemplates"),
        "prompts/list" => Some("prompts"),
        _ => None,
    }
}
