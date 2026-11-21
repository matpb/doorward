//! Unit tests of the strict parser, the classifier, the method tables, the header rules and the answers.

use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};

use super::answer;
use super::headers::{HeaderRefusal, check_stateless, decoded};
use super::json::{JsonRefusal, parse_strict};
use super::message::{Decision, Generation, Message, Refusal, Shape, Switches, classify, decide};

const SESSION_HEADER: &str = "2025-11-25";
const STATELESS_HEADER: &str = "2026-07-28";
const META: &str = "io.modelcontextprotocol/protocolVersion";

/// One classify row: a name, a body, the version header and the expected generation and shape.
type ClassifyRow = (
    &'static str,
    Value,
    Option<&'static str>,
    Result<(Generation, Shape), Refusal>,
);
/// One header row: a name, the headers sent, and the expected verdict.
type HeaderRow = (
    &'static str,
    Vec<(&'static str, &'static str)>,
    Result<(), HeaderRefusal>,
);

/// The four switch combinations, in the order of the expected arrays below.
const COMBOS: [Switches; 4] = [
    Switches {
        resources: false,
        prompts: false,
    },
    Switches {
        resources: true,
        prompts: false,
    },
    Switches {
        resources: false,
        prompts: true,
    },
    Switches {
        resources: true,
        prompts: true,
    },
];

fn message_for(method: &str, shape: Shape, generation: Generation) -> Message {
    let header = match generation {
        Generation::Session => SESSION_HEADER,
        Generation::Stateless => STATELESS_HEADER,
    };
    let value = match shape {
        Shape::Notification => json!({"jsonrpc": "2.0", "method": method}),
        _ => json!({"jsonrpc": "2.0", "id": 1, "method": method}),
    };
    classify(value, Some(header)).expect("classifies")
}

fn assert_decisions(message: &Message, expected: [Decision; 4], label: &str) {
    for (switches, want) in COMBOS.iter().zip(expected) {
        assert_eq!(
            decide(message, *switches),
            want,
            "{label} with {switches:?}"
        );
    }
}

#[test]
fn parse_strict_refusals_and_neighbours() {
    let deep = format!("{}1{}", "{\"a\":".repeat(3), "}".repeat(3));
    let rows: Vec<(&str, &[u8], Result<Value, JsonRefusal>)> = vec![
        (
            "duplicate key",
            br#"{"a":1,"a":2}"#,
            Err(JsonRefusal::Syntax),
        ),
        ("two keys", br#"{"a":1,"b":2}"#, Ok(json!({"a": 1, "b": 2}))),
        (
            "duplicate after unescaping",
            br#"{"a":1,"\u0061":2}"#,
            Err(JsonRefusal::Syntax),
        ),
        (
            "duplicate inside an array of objects",
            br#"[{"a":1},{"a":1,"a":2}]"#,
            Err(JsonRefusal::Syntax),
        ),
        (
            "duplicate at depth",
            br#"{"x":{"y":[{"z":1,"z":1}]}}"#,
            Err(JsonRefusal::Syntax),
        ),
        (
            "same key at two depths",
            br#"{"a":{"a":1}}"#,
            Ok(json!({"a": {"a": 1}})),
        ),
        (
            "lone high surrogate",
            br#""\ud800""#,
            Err(JsonRefusal::Syntax),
        ),
        (
            "lone low surrogate",
            br#""\udc00""#,
            Err(JsonRefusal::Syntax),
        ),
        ("surrogate pair", br#""\ud83d\ude00""#, Ok(json!("😀"))),
        ("raw emoji", "\"😀\"".as_bytes(), Ok(json!("😀"))),
        ("trailing data", b"{} x", Err(JsonRefusal::Syntax)),
        ("trailing whitespace", b"{} \n", Ok(json!({}))),
        ("second value", b"{}{}", Err(JsonRefusal::Syntax)),
        (
            "byte order mark",
            b"\xEF\xBB\xBF{}",
            Err(JsonRefusal::Encoding),
        ),
        (
            "byte order mark alone",
            b"\xEF\xBB\xBF",
            Err(JsonRefusal::Encoding),
        ),
        (
            "byte order mark after data",
            b"{} \xEF\xBB\xBF",
            Err(JsonRefusal::Syntax),
        ),
        (
            "one invalid UTF-8 byte",
            b"\"\xFF\"",
            Err(JsonRefusal::Encoding),
        ),
        ("invalid UTF-8 alone", b"\xFF", Err(JsonRefusal::Encoding)),
        ("empty input", b"", Err(JsonRefusal::Syntax)),
        ("unterminated object", b"{", Err(JsonRefusal::Syntax)),
        (
            "raw control character",
            b"\"a\x01\"",
            Err(JsonRefusal::Syntax),
        ),
        ("number out of range", b"[1e400]", Err(JsonRefusal::Syntax)),
        (
            "largest u64",
            b"[18446744073709551615]",
            Ok(json!([18446744073709551615u64])),
        ),
        ("padded array", b" [ 1 , 2 ] ", Ok(json!([1, 2]))),
        (
            "three deep object",
            deep.as_bytes(),
            Ok(json!({"a": {"a": {"a": 1}}})),
        ),
    ];
    for (name, input, expected) in rows {
        assert_eq!(parse_strict(input), expected, "{name}");
    }
}

#[test]
fn parse_strict_matches_serde_json_on_valid_documents() {
    let documents = [
        r#"{"a":[1,2.5,-3e2,true,false,null,"x\n\u00e9"]}"#,
        r#"{"jsonrpc":"2.0","id":"abc","method":"ping","params":{"_meta":{}}}"#,
        "[]",
        "0",
        r#""plain""#,
    ];
    for document in documents {
        let reference: Value = serde_json::from_str(document).expect("valid reference");
        assert_eq!(
            parse_strict(document.as_bytes()),
            Ok(reference),
            "{document}"
        );
    }
}

#[test]
fn parse_strict_depth_64_is_accepted_and_65_refused() {
    let arrays = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    assert!(parse_strict(arrays(64).as_bytes()).is_ok());
    assert_eq!(
        parse_strict(arrays(65).as_bytes()),
        Err(JsonRefusal::Syntax)
    );
    assert!(parse_strict(objects(64).as_bytes()).is_ok());
    assert_eq!(
        parse_strict(objects(65).as_bytes()),
        Err(JsonRefusal::Syntax)
    );
    let mixed = format!("{}1{}", "[{\"a\":".repeat(32), "}]".repeat(32));
    assert!(parse_strict(mixed.as_bytes()).is_ok());
    let mixed_deeper = format!("[{mixed}]");
    assert_eq!(
        parse_strict(mixed_deeper.as_bytes()),
        Err(JsonRefusal::Syntax)
    );
}

#[test]
fn parse_strict_refuses_very_deep_input_without_overflow() {
    let open = "[".repeat(10_000);
    let closed = format!("{}{}", open, "]".repeat(10_000));
    assert_eq!(parse_strict(open.as_bytes()), Err(JsonRefusal::Syntax));
    assert_eq!(parse_strict(closed.as_bytes()), Err(JsonRefusal::Syntax));
    let objects = format!("{}1{}", "{\"a\":".repeat(100_000), "}".repeat(100_000));
    assert_eq!(parse_strict(objects.as_bytes()), Err(JsonRefusal::Syntax));
}

#[test]
fn parse_strict_accepts_large_inputs() {
    let items = format!("[{}]", vec!["0"; 100_000].join(","));
    let parsed = parse_strict(items.as_bytes()).expect("large array");
    assert_eq!(parsed.as_array().map(Vec::len), Some(100_000));
    let keys: Vec<String> = (0..10_000).map(|i| format!("\"k{i}\":{i}")).collect();
    let object = format!("{{{}}}", keys.join(","));
    let reference: Value = serde_json::from_str(&object).expect("valid reference");
    assert_eq!(parse_strict(object.as_bytes()), Ok(reference));
    let text = format!("\"{}\"", "é".repeat(500_000));
    let reference: Value = serde_json::from_str(&text).expect("valid reference");
    assert_eq!(parse_strict(text.as_bytes()), Ok(reference));
}

#[test]
fn classify_refusals_and_shapes() {
    let rows: Vec<ClassifyRow> = vec![
        ("empty array", json!([]), None, Err(Refusal::InvalidRequest)),
        ("string", json!("x"), None, Err(Refusal::InvalidRequest)),
        ("number", json!(7), None, Err(Refusal::InvalidRequest)),
        ("null", Value::Null, None, Err(Refusal::InvalidRequest)),
        (
            "empty object",
            json!({}),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "id only",
            json!({"id": 1}),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "method is a number",
            json!({"id": 1, "method": 5}),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "method is null beside a result",
            json!({"id": 1, "method": null, "result": {}}),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "request",
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            None,
            Ok((Generation::Session, Shape::Request)),
        ),
        (
            "notification",
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            None,
            Ok((Generation::Session, Shape::Notification)),
        ),
        (
            "response with result",
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            None,
            Ok((Generation::Session, Shape::Response)),
        ),
        (
            "response with error",
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}),
            None,
            Ok((Generation::Session, Shape::Response)),
        ),
        (
            "response under the stateless rules",
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            Some(STATELESS_HEADER),
            Err(Refusal::InvalidRequest),
        ),
        (
            "tools/call without an id",
            json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "echo"}}),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "tools/call with an id",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo"}}),
            None,
            Ok((Generation::Session, Shape::Request)),
        ),
        (
            "tools/call with a null id is refused",
            json!({"id": null, "method": "tools/call", "params": {"name": "echo"}}),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "stateless request",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            Some(STATELESS_HEADER),
            Ok((Generation::Stateless, Shape::Request)),
        ),
    ];
    for (name, value, header, expected) in rows {
        let got = classify(value, header).map(|m| (m.generation, m.shape));
        assert_eq!(got, expected, "{name}");
    }
}

#[test]
fn classify_accepts_only_string_or_integer_ids() {
    let exponent: Value = serde_json::from_str(r#"{"id": 1e2, "method": "ping"}"#).expect("json");
    let rows: Vec<(&str, Value, Result<Shape, Refusal>)> = vec![
        (
            "null id on tools/call",
            json!({"id": null, "method": "tools/call", "params": {"name": "echo"}}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "null id on a request",
            json!({"id": null, "method": "ping"}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "null id on a response",
            json!({"id": null, "result": {}}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "fractional id",
            json!({"id": 1.5, "method": "ping"}),
            Err(Refusal::InvalidRequest),
        ),
        ("exponent id", exponent, Err(Refusal::InvalidRequest)),
        (
            "fractional id on a response",
            json!({"id": 1.5, "result": {}}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "true id",
            json!({"id": true, "method": "ping"}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "object id",
            json!({"id": {}, "method": "ping"}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "array id",
            json!({"id": [], "method": "ping"}),
            Err(Refusal::InvalidRequest),
        ),
        (
            "zero id",
            json!({"id": 0, "method": "ping"}),
            Ok(Shape::Request),
        ),
        (
            "negative id",
            json!({"id": -3, "method": "ping"}),
            Ok(Shape::Request),
        ),
        (
            "largest u64 id",
            json!({"id": 18446744073709551615u64, "method": "ping"}),
            Ok(Shape::Request),
        ),
        (
            "empty string id",
            json!({"id": "", "method": "ping"}),
            Ok(Shape::Request),
        ),
        (
            "string id",
            json!({"id": "abc", "method": "ping"}),
            Ok(Shape::Request),
        ),
        (
            "no id, notification",
            json!({"method": "ping"}),
            Ok(Shape::Notification),
        ),
        (
            "no id, response",
            json!({"result": {}}),
            Ok(Shape::Response),
        ),
    ];
    for (name, value, expected) in rows {
        let id = value.get("id").cloned();
        let got = classify(value, None);
        match expected {
            Ok(shape) => {
                let message = got.expect(name);
                assert_eq!(message.shape, shape, "{name}");
                assert_eq!(message.id, id, "{name}");
            }
            Err(refusal) => assert_eq!(got.map(|m| m.shape), Err(refusal), "{name}"),
        }
    }
}

#[test]
fn classify_generation_by_header_and_meta() {
    let plain = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let with_meta = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {"_meta": {META: "2026-07-28"}}});
    let with_null_meta = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {"_meta": {META: null}}});
    let other_meta = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {"_meta": {"io.modelcontextprotocol/other": "2026-07-28"}}});
    let rows: Vec<(&str, Value, Option<&str>, Generation)> = vec![
        (
            "header 2026-07-28",
            plain.clone(),
            Some("2026-07-28"),
            Generation::Stateless,
        ),
        (
            "header 2027-01-01",
            plain.clone(),
            Some("2027-01-01"),
            Generation::Stateless,
        ),
        (
            "header 2026-12-31",
            plain.clone(),
            Some("2026-12-31"),
            Generation::Stateless,
        ),
        (
            "header 2028-02-29",
            plain.clone(),
            Some("2028-02-29"),
            Generation::Stateless,
        ),
        (
            "header 2025-11-25",
            plain.clone(),
            Some("2025-11-25"),
            Generation::Session,
        ),
        (
            "header 2026-07-27",
            plain.clone(),
            Some("2026-07-27"),
            Generation::Session,
        ),
        (
            "header 2024-02-29",
            plain.clone(),
            Some("2024-02-29"),
            Generation::Session,
        ),
        ("header absent", plain.clone(), None, Generation::Session),
        (
            "header absent, meta present",
            with_meta.clone(),
            None,
            Generation::Stateless,
        ),
        (
            "meta with null value",
            with_null_meta,
            None,
            Generation::Stateless,
        ),
        (
            "header 2025-11-25, meta present",
            with_meta,
            Some("2025-11-25"),
            Generation::Stateless,
        ),
        ("other meta key", other_meta, None, Generation::Session),
        (
            "malformed 2026-7-28",
            plain.clone(),
            Some("2026-7-28"),
            Generation::Session,
        ),
        (
            "impossible 2026-02-30",
            plain.clone(),
            Some("2026-02-30"),
            Generation::Session,
        ),
        (
            "impossible 2027-02-29",
            plain.clone(),
            Some("2027-02-29"),
            Generation::Session,
        ),
        (
            "month 13",
            plain.clone(),
            Some("2026-13-01"),
            Generation::Session,
        ),
        (
            "trailing text",
            plain.clone(),
            Some("2026-07-28x"),
            Generation::Session,
        ),
        (
            "no separators",
            plain.clone(),
            Some("20260728"),
            Generation::Session,
        ),
        ("empty header", plain.clone(), Some(""), Generation::Session),
        (
            "leading space",
            plain.clone(),
            Some(" 2026-07-28"),
            Generation::Session,
        ),
        (
            "trailing space",
            plain.clone(),
            Some("2026-07-28 "),
            Generation::Session,
        ),
        ("a word", plain, Some("yesterday"), Generation::Session),
    ];
    for (name, value, header, expected) in rows {
        let message = classify(value, header).expect("classifies");
        assert_eq!(message.generation, expected, "{name}");
    }
}

#[test]
fn classify_fills_method_id_tool_and_keeps_the_value() {
    let call = json!({"id": "abc", "method": "tools/call",
        "params": {"name": "Echo ", "arguments": {}}});
    let message = classify(call.clone(), None).expect("classifies");
    assert_eq!(message.method.as_deref(), Some("tools/call"));
    assert_eq!(message.id, Some(json!("abc")));
    assert_eq!(message.tool.as_deref(), Some("Echo "));
    assert_eq!(message.value, call);

    let accented = json!({"id": 2, "method": "tools/call", "params": {"name": "é"}});
    let message = classify(accented, None).expect("classifies");
    assert_eq!(message.tool.as_deref(), Some("é"));

    let no_name = json!({"id": 3, "method": "tools/call", "params": {}});
    assert_eq!(classify(no_name, None).expect("classifies").tool, None);
    let numeric = json!({"id": 4, "method": "tools/call", "params": {"name": 5}});
    assert_eq!(classify(numeric, None).expect("classifies").tool, None);

    let ping = json!({"id": 5, "method": "ping", "params": {"name": "x"}});
    let message = classify(ping, None).expect("classifies");
    assert_eq!(message.tool, None);
    let notice = json!({"method": "notifications/cancelled"});
    assert_eq!(classify(notice, None).expect("classifies").id, None);
}

/// One text row: a name, a body as written, the version header and the expected generation and shape.
type TextRow = (
    &'static str,
    String,
    Option<&'static str>,
    Result<(Generation, Shape), Refusal>,
);

fn text_body(text: &str) -> Value {
    serde_json::from_str(text).expect("the test body is JSON")
}

#[test]
fn classify_refuses_member_names_the_upstream_may_read_differently() {
    let rows: Vec<TextRow> = vec![
        (
            "body A: Name beside name in params",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","Name":"search","arguments":{}}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "body B: Method beside method at top level",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","Method":"tools/call","params":{"Name":"search"}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "body C: Method, Params and result on a response",
            r#"{"jsonrpc":"2.0","id":5,"Method":"tools/call","Params":{"name":"search"},"result":{}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a top-level extra member",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a top-level member with a non-ASCII name",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","idé":1}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a top-level member that differs from id by case",
            r#"{"jsonrpc":"2.0","ID":1,"method":"ping"}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a top-level extra member on a stateless request",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":true,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.into(),
            Some(STATELESS_HEADER),
            Err(Refusal::InvalidRequest),
        ),
        (
            "a non-ASCII name in params",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","namé":1}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a fold-to-task key in params with U+017F and U+212A",
            format!(
                r#"{{"method":"tools/call","id":1,"jsonrpc":"2.0","params":{{"name":"echo","ta{}{}":"search"}}}}"#,
                '\u{017F}', '\u{212A}'
            ),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "an upper-case name in params",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"echo"}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "an upper-case _meta in params",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_Meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "ProgressToken in _meta",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"ProgressToken":1}}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a non-ASCII name in _meta",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"_meta":{"progressToken":1,"ü":2}}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a case variant of the io protocol version key in _meta",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"Io.ModelContextProtocol/protocolVersion":"2026-07-28"}}}"#.into(),
            Some(STATELESS_HEADER),
            Err(Refusal::InvalidRequest),
        ),
        (
            "a case variant of ref's type key",
            r#"{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"Type":"ref/prompt","name":"x"},"argument":{"name":"a","value":"b"}}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "a non-ASCII name in params.ref",
            r#"{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"typé":"ref/prompt"}}}"#.into(),
            None,
            Err(Refusal::InvalidRequest),
        ),
        (
            "body A with a stateless _meta",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","Name":"search","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#.into(),
            Some(STATELESS_HEADER),
            Err(Refusal::InvalidRequest),
        ),
        (
            "a plain request",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#.into(),
            None,
            Ok((Generation::Session, Shape::Request)),
        ),
        (
            "a plain notification",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.into(),
            None,
            Ok((Generation::Session, Shape::Notification)),
        ),
        (
            "a plain response",
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.into(),
            None,
            Ok((Generation::Session, Shape::Response)),
        ),
        (
            "mixed-case and non-ASCII names inside arguments",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"Name":"x","näme":"y"}}}"#.into(),
            None,
            Ok((Generation::Session, Shape::Request)),
        ),
        (
            "an ASCII key that folds to no decision key",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","Foo":1}}"#.into(),
            None,
            Ok((Generation::Session, Shape::Request)),
        ),
        (
            "a stateless _meta with an unlisted key",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"x"}}}}"#.into(),
            Some(STATELESS_HEADER),
            Ok((Generation::Stateless, Shape::Request)),
        ),
    ];
    let mut wrong = Vec::new();
    for (name, text, header, expected) in rows {
        let got = classify(text_body(&text), header).map(|m| (m.generation, m.shape));
        if got != expected {
            wrong.push(format!("{name}: got {got:?}, want {expected:?}"));
        }
    }
    assert!(wrong.is_empty(), "rows that differ:\n{}", wrong.join("\n"));
}

#[test]
fn classify_reads_the_tool_of_a_call_with_odd_argument_names() {
    let text = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"Name":"x","näme":"y"}}}"#;
    let message = classify(text_body(text), None).expect("classifies");
    assert_eq!(message.tool.as_deref(), Some("echo"));
}

#[test]
fn classify_applies_the_key_rules_to_large_bodies() {
    let mut wide =
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo"}});
    for i in 0..5000 {
        wide["params"][format!("key{i}")] = json!(i);
    }
    let message = classify(wide.clone(), None).expect("5000 unlisted keys in params classify");
    assert_eq!(message.tool.as_deref(), Some("echo"));

    wide["extra"] = json!(true);
    assert_eq!(
        classify(wide, None).map(|m| m.tool),
        Err(Refusal::InvalidRequest),
        "one extra top-level member beside 5000 params keys is refused"
    );

    let mut meta =
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo"}});
    for i in 0..5000 {
        meta["params"]["_meta"][format!("k{i}")] = json!(i);
    }
    meta["params"]["_meta"]["ProgressToken"] = json!(1);
    assert_eq!(
        classify(meta, None).map(|m| m.tool),
        Err(Refusal::InvalidRequest),
        "a case variant of progressToken is refused beside 5000 other _meta keys"
    );
}

#[test]
fn decide_session_table_under_every_switch_combination() {
    use Decision::{EmptyList as List, Forward as Fwd, MethodNotFound as Nope};
    let rows = [
        ("initialize", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        ("ping", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        ("tools/list", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        ("tools/call", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        ("logging/setLevel", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        (
            "notifications/initialized",
            Shape::Notification,
            [Fwd, Fwd, Fwd, Fwd],
        ),
        (
            "notifications/cancelled",
            Shape::Notification,
            [Fwd, Fwd, Fwd, Fwd],
        ),
        (
            "notifications/progress",
            Shape::Notification,
            [Fwd, Fwd, Fwd, Fwd],
        ),
        (
            "notifications/roots/list_changed",
            Shape::Notification,
            [Fwd, Fwd, Fwd, Fwd],
        ),
        (
            "resources/list",
            Shape::Request,
            [List("resources"), Fwd, List("resources"), Fwd],
        ),
        (
            "resources/templates/list",
            Shape::Request,
            [
                List("resourceTemplates"),
                Fwd,
                List("resourceTemplates"),
                Fwd,
            ],
        ),
        ("resources/read", Shape::Request, [Nope, Fwd, Nope, Fwd]),
        (
            "resources/subscribe",
            Shape::Request,
            [Nope, Fwd, Nope, Fwd],
        ),
        (
            "resources/unsubscribe",
            Shape::Request,
            [Nope, Fwd, Nope, Fwd],
        ),
        (
            "prompts/list",
            Shape::Request,
            [List("prompts"), List("prompts"), Fwd, Fwd],
        ),
        ("prompts/get", Shape::Request, [Nope, Nope, Fwd, Fwd]),
        (
            "completion/complete",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        ("server/discover", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "subscriptions/listen",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        ("tasks/list", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "sampling/createMessage",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        ("roots/list", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "elicitation/create",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        ("foo/bar", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "notifications/message",
            Shape::Notification,
            [Nope, Nope, Nope, Nope],
        ),
        (
            "resources/list",
            Shape::Notification,
            [List("resources"), Fwd, List("resources"), Fwd],
        ),
        (
            "completion/complete",
            Shape::Notification,
            [Nope, Nope, Nope, Nope],
        ),
        ("prompts/get", Shape::Notification, [Nope, Nope, Fwd, Fwd]),
        ("initialize", Shape::Notification, [Fwd, Fwd, Fwd, Fwd]),
        (
            "notifications/initialized",
            Shape::Request,
            [Fwd, Fwd, Fwd, Fwd],
        ),
        ("ping", Shape::Notification, [Fwd, Fwd, Fwd, Fwd]),
    ];
    for (method, shape, expected) in rows {
        let message = message_for(method, shape, Generation::Session);
        assert_decisions(&message, expected, method);
    }
}

#[test]
fn decide_stateless_table_under_every_switch_combination() {
    use Decision::{EmptyList as List, Forward as Fwd, MethodNotFound as Nope};
    let rows = [
        ("server/discover", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        ("tools/list", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        ("tools/call", Shape::Request, [Fwd, Fwd, Fwd, Fwd]),
        (
            "subscriptions/listen",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        (
            "notifications/cancelled",
            Shape::Notification,
            [Fwd, Fwd, Fwd, Fwd],
        ),
        (
            "resources/list",
            Shape::Request,
            [List("resources"), Fwd, List("resources"), Fwd],
        ),
        (
            "resources/templates/list",
            Shape::Request,
            [
                List("resourceTemplates"),
                Fwd,
                List("resourceTemplates"),
                Fwd,
            ],
        ),
        ("resources/read", Shape::Request, [Nope, Fwd, Nope, Fwd]),
        (
            "resources/subscribe",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        (
            "resources/unsubscribe",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        (
            "prompts/list",
            Shape::Request,
            [List("prompts"), List("prompts"), Fwd, Fwd],
        ),
        ("prompts/get", Shape::Request, [Nope, Nope, Fwd, Fwd]),
        (
            "completion/complete",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        ("initialize", Shape::Request, [Nope, Nope, Nope, Nope]),
        ("ping", Shape::Request, [Nope, Nope, Nope, Nope]),
        ("logging/setLevel", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "notifications/initialized",
            Shape::Notification,
            [Nope, Nope, Nope, Nope],
        ),
        (
            "notifications/progress",
            Shape::Notification,
            [Nope, Nope, Nope, Nope],
        ),
        (
            "notifications/roots/list_changed",
            Shape::Notification,
            [Nope, Nope, Nope, Nope],
        ),
        ("tasks/get", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "sampling/createMessage",
            Shape::Request,
            [Nope, Nope, Nope, Nope],
        ),
        ("foo/bar", Shape::Request, [Nope, Nope, Nope, Nope]),
        (
            "completion/complete",
            Shape::Notification,
            [Nope, Nope, Nope, Nope],
        ),
        ("ping", Shape::Notification, [Nope, Nope, Nope, Nope]),
    ];
    for (method, shape, expected) in rows {
        let message = message_for(method, shape, Generation::Stateless);
        assert_decisions(&message, expected, method);
    }
}

/// A completion answers to the switch of the kind its ref names, and is refused for any other kind.
#[test]
fn completion_follows_the_switch_of_its_kind() {
    let off = Switches {
        resources: false,
        prompts: false,
    };
    let resources_only = Switches {
        resources: true,
        prompts: false,
    };
    let prompts_only = Switches {
        resources: false,
        prompts: true,
    };
    let both = Switches {
        resources: true,
        prompts: true,
    };
    let cases = [
        (
            "ref/prompt",
            [
                Decision::MethodNotFound,
                Decision::MethodNotFound,
                Decision::Forward,
                Decision::Forward,
            ],
        ),
        (
            "ref/resource",
            [
                Decision::MethodNotFound,
                Decision::Forward,
                Decision::MethodNotFound,
                Decision::Forward,
            ],
        ),
        ("ref/other", [Decision::MethodNotFound; 4]),
    ];
    for header in [SESSION_HEADER, STATELESS_HEADER] {
        for (kind, expected) in cases {
            let value = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "completion/complete",
                "params": {"ref": {"type": kind}},
            });
            let message = classify(value, Some(header)).expect("classifies");
            let got = [off, resources_only, prompts_only, both]
                .map(|switches| decide(&message, switches));
            assert_eq!(got, expected, "{kind} under {header}");
        }
    }
}

#[test]
fn decide_refuses_look_alike_and_task_methods_in_both_generations() {
    let names = [
        "Tools/Call",
        "tools/call ",
        " tools/call",
        "tools/Call",
        "tools/call\u{200B}",
        "tools/call/",
        "Ping",
        "ping ",
        "resources/List",
        "prompts/list/",
        "completion/complete ",
        "notifications/Initialized",
        "tasks/list",
        "tasks/get",
        "tasks/",
        "tasks/cancel",
        "",
    ];
    for name in names {
        for generation in [Generation::Session, Generation::Stateless] {
            let message = message_for(name, Shape::Request, generation);
            assert_decisions(&message, [Decision::MethodNotFound; 4], name);
        }
    }
}

#[test]
fn decide_refuses_any_message_with_params_task() {
    let rows = [
        json!({"id": 1, "method": "tools/call", "params": {"name": "echo", "task": {}}}),
        json!({"id": 2, "method": "tools/list", "params": {"task": null}}),
        json!({"id": 3, "method": "resources/list", "params": {"task": 1}}),
        json!({"method": "notifications/cancelled", "params": {"task": "x"}}),
    ];
    for value in rows {
        let message = classify(value.clone(), Some(SESSION_HEADER)).expect("classifies");
        assert_decisions(&message, [Decision::MethodNotFound; 4], &value.to_string());
    }
    let top_level = json!({"id": 4, "method": "tools/call", "task": {},
        "params": {"name": "echo"}});
    let refused = classify(top_level, Some(SESSION_HEADER)).map(|message| message.method);
    assert_eq!(refused, Err(Refusal::InvalidRequest), "task outside params");
}

#[test]
fn decide_response_and_unchanged_message() {
    let response = classify(json!({"id": 1, "result": {}}), None).expect("classifies");
    assert_decisions(&response, [Decision::MethodNotFound; 4], "response");
    let before = response.clone();
    decide(&response, COMBOS[3]);
    assert_eq!(response, before);
}

/// The headers of a request, names in any case.
fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("header name");
        map.append(name, HeaderValue::from_str(value).expect("header value"));
    }
    map
}

fn call_message() -> Message {
    let value = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "echo", "arguments": {}, "_meta": {META: STATELESS_HEADER}}});
    classify(value, Some(STATELESS_HEADER)).expect("classifies")
}

fn mismatch(label: &str) -> Result<(), HeaderRefusal> {
    Err(HeaderRefusal(format!("Header mismatch: {label}")))
}

#[test]
fn check_stateless_header_rows() {
    const GOOD: [(&str, &str); 3] = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "echo"),
    ];
    let good = |index: usize, value: &'static str| -> Vec<(&'static str, &'static str)> {
        GOOD.iter()
            .enumerate()
            .map(|(i, (name, original))| (*name, if i == index { value } else { *original }))
            .collect()
    };
    let version_missing: Vec<(&str, &str)> = vec![GOOD[1], GOOD[2]];
    let method_missing: Vec<(&str, &str)> = vec![GOOD[0], GOOD[2]];
    let name_missing: Vec<(&str, &str)> = vec![GOOD[0], GOOD[1]];
    let mut version_repeated = GOOD.to_vec();
    version_repeated.push(GOOD[0]);
    let mut method_repeated = GOOD.to_vec();
    method_repeated.push(GOOD[1]);
    let mut name_repeated = GOOD.to_vec();
    name_repeated.push(GOOD[2]);
    let method_repeated_different = {
        let mut pairs = GOOD.to_vec();
        pairs.push(("Mcp-Method", "tools/list"));
        pairs
    };

    let rows: Vec<HeaderRow> = vec![
        ("all three equal", GOOD.to_vec(), Ok(())),
        (
            "version missing",
            version_missing,
            mismatch("MCP-Protocol-Version"),
        ),
        (
            "version repeated",
            version_repeated,
            mismatch("MCP-Protocol-Version"),
        ),
        (
            "version different",
            good(0, "2025-11-25"),
            mismatch("MCP-Protocol-Version"),
        ),
        (
            "version base64 equal",
            good(0, "=?base64?MjAyNi0wNy0yOA==?="),
            Ok(()),
        ),
        (
            "version base64 different",
            good(0, "=?base64?MjAyNi0wNy0yOQ==?="),
            mismatch("MCP-Protocol-Version"),
        ),
        ("method missing", method_missing, mismatch("Mcp-Method")),
        ("method repeated", method_repeated, mismatch("Mcp-Method")),
        (
            "method repeated, values differ",
            method_repeated_different,
            mismatch("Mcp-Method"),
        ),
        (
            "method different",
            good(1, "tools/list"),
            mismatch("Mcp-Method"),
        ),
        (
            "method with trailing space",
            good(1, "tools/call "),
            mismatch("Mcp-Method"),
        ),
        (
            "method in other case",
            good(1, "Tools/Call"),
            mismatch("Mcp-Method"),
        ),
        ("name missing", name_missing, mismatch("Mcp-Name")),
        ("name repeated", name_repeated, mismatch("Mcp-Name")),
        ("name different", good(2, "echo2"), mismatch("Mcp-Name")),
        ("name in other case", good(2, "Echo"), mismatch("Mcp-Name")),
        (
            "name with trailing space",
            good(2, "echo "),
            mismatch("Mcp-Name"),
        ),
        ("name base64 equal", good(2, "=?base64?ZWNobw==?="), Ok(())),
        (
            "name base64 different",
            good(2, "=?base64?ZWNobzI=?="),
            mismatch("Mcp-Name"),
        ),
        (
            "name base64 not base64",
            good(2, "=?base64?!!!?="),
            mismatch("Mcp-Name"),
        ),
        (
            "name base64 not UTF-8",
            good(2, "=?base64?/w==?="),
            mismatch("Mcp-Name"),
        ),
        (
            "name base64 marker in capitals",
            good(2, "=?BASE64?ZWNobw==?="),
            mismatch("Mcp-Name"),
        ),
    ];
    let message = call_message();
    for (name, pairs, expected) in rows {
        assert_eq!(
            check_stateless(&header_map(&pairs), &message),
            expected,
            "{name}"
        );
    }
}

#[test]
fn check_stateless_compares_body_values_and_skips_session() {
    let accented_pairs = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "=?base64?w6k=?="),
    ];
    let accented = classify(
        json!({"id": 1, "method": "tools/call",
            "params": {"name": "é", "_meta": {META: STATELESS_HEADER}}}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    assert_eq!(accented.tool.as_deref(), Some("é"));
    assert_eq!(
        check_stateless(&header_map(&accented_pairs), &accented),
        Ok(())
    );

    let read = classify(
        json!({"id": 2, "method": "resources/read",
            "params": {"uri": "file:///a", "_meta": {META: STATELESS_HEADER}}}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    let uri_ok = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "resources/read"),
        ("mcp-name", "file:///a"),
    ];
    let uri_missing = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "resources/read"),
    ];
    assert_eq!(check_stateless(&header_map(&uri_ok), &read), Ok(()));
    assert_eq!(
        check_stateless(&header_map(&uri_missing), &read),
        mismatch("Mcp-Name")
    );

    let prompt = classify(
        json!({"id": 3, "method": "prompts/get",
            "params": {"name": "greet", "_meta": {META: STATELESS_HEADER}}}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    let prompt_pairs = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "prompts/get"),
        ("mcp-name", "greeting"),
    ];
    assert_eq!(
        check_stateless(&header_map(&prompt_pairs), &prompt),
        mismatch("Mcp-Name")
    );
    let prompt_missing = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "prompts/get"),
    ];
    assert_eq!(
        check_stateless(&header_map(&prompt_missing), &prompt),
        mismatch("Mcp-Name")
    );
    let prompt_repeated = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "prompts/get"),
        ("mcp-name", "greet"),
        ("mcp-name", "greet"),
    ];
    assert_eq!(
        check_stateless(&header_map(&prompt_repeated), &prompt),
        mismatch("Mcp-Name")
    );
    let uri_repeated = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "resources/read"),
        ("mcp-name", "file:///a"),
        ("mcp-name", "file:///a"),
    ];
    assert_eq!(
        check_stateless(&header_map(&uri_repeated), &read),
        mismatch("Mcp-Name")
    );

    let list = classify(
        json!({"id": 4, "method": "tools/list", "params": {"_meta": {META: STATELESS_HEADER}}}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    let list_pairs = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/list"),
    ];
    assert_eq!(check_stateless(&header_map(&list_pairs), &list), Ok(()));
    let list_with_name = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/list"),
        ("mcp-name", "anything"),
    ];
    assert_eq!(check_stateless(&header_map(&list_with_name), &list), Ok(()));

    let cancelled = classify(
        json!({"method": "notifications/cancelled", "params": {"_meta": {META: STATELESS_HEADER}}}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    let cancelled_pairs = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "notifications/cancelled"),
    ];
    assert_eq!(
        check_stateless(&header_map(&cancelled_pairs), &cancelled),
        Ok(())
    );
    assert_eq!(
        check_stateless(&HeaderMap::new(), &cancelled),
        mismatch("MCP-Protocol-Version")
    );

    let no_meta = classify(
        json!({"id": 5, "method": "tools/list"}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    let pairs = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/list"),
    ];
    assert_eq!(
        check_stateless(&header_map(&pairs), &no_meta),
        mismatch("MCP-Protocol-Version")
    );

    let session = message_for("tools/call", Shape::Request, Generation::Session);
    let wrong = [("mcp-method", "ping"), ("mcp-name", "other")];
    assert_eq!(check_stateless(&header_map(&wrong), &session), Ok(()));
    assert_eq!(check_stateless(&HeaderMap::new(), &session), Ok(()));
}

#[test]
fn check_stateless_refuses_a_non_ascii_header_value() {
    let message = call_message();
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("mcp-protocol-version"),
        HeaderValue::from_static("2026-07-28"),
    );
    headers.insert(
        HeaderName::from_static("mcp-method"),
        HeaderValue::from_bytes(b"tools/call\xC3\xA9").expect("value"),
    );
    headers.insert(
        HeaderName::from_static("mcp-name"),
        HeaderValue::from_static("echo"),
    );
    assert_eq!(check_stateless(&headers, &message), mismatch("Mcp-Method"));
}

#[test]
fn decoded_forms() {
    let rows: [(&str, Option<&str>); 10] = [
        ("echo", Some("echo")),
        ("", Some("")),
        ("=?base64?ZWNobw==?=", Some("echo")),
        ("=?base64?w6k=?=", Some("é")),
        ("=?base64??=", Some("")),
        ("=?base64?/w==?=", None),
        ("=?base64?!!!?=", None),
        ("=?base64?ZWNobw==", Some("=?base64?ZWNobw==")),
        ("=?base64?ZWNobw==?= ", Some("=?base64?ZWNobw==?= ")),
        ("=?base64?=", Some("=?base64?=")),
    ];
    for (input, expected) in rows {
        assert_eq!(decoded(input), expected.map(str::to_owned), "{input:?}");
    }
}

/// The response's status, headers and body, read in full.
async fn read(response: Response) -> (StatusCode, HeaderMap, String) {
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.expect("body");
    let text = String::from_utf8(bytes.to_vec()).expect("utf-8 body");
    (parts.status, parts.headers, text)
}

fn assert_inert(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(CONTENT_TYPE)
            .map(|v| v.to_str().expect("ascii")),
        Some("application/json")
    );
    assert_eq!(
        headers
            .get(X_CONTENT_TYPE_OPTIONS)
            .map(|v| v.to_str().expect("ascii")),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get(CONTENT_SECURITY_POLICY)
            .map(|v| v.to_str().expect("ascii")),
        Some("sandbox")
    );
}

#[tokio::test]
async fn unavailable_answer_is_the_placeholder_shape() {
    let (status, headers, body) = read(answer::unavailable("demo")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_inert(&headers);
    assert_eq!(
        body,
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Upstream demo is unavailable"}}"#
    );
    let (_, _, quoted) = read(answer::unavailable("a\"b")).await;
    assert_eq!(
        quoted,
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Upstream a\"b is unavailable"}}"#
    );
}

#[tokio::test]
async fn unknown_tool_answer() {
    let (status, headers, body) = read(answer::unknown_tool(&json!(7), "delete_db")).await;
    assert_eq!(status, StatusCode::OK);
    assert_inert(&headers);
    assert_eq!(
        body,
        r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"Unknown tool: delete_db"}}"#
    );
    let (_, _, quoted) = read(answer::unknown_tool(&json!("x-1"), "de\"l")).await;
    assert_eq!(
        quoted,
        r#"{"jsonrpc":"2.0","id":"x-1","error":{"code":-32602,"message":"Unknown tool: de\"l"}}"#
    );
}

#[tokio::test]
async fn error_answer_echoes_the_id_or_null() {
    let rows: [(Option<Value>, &str); 3] = [
        (
            None,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#,
        ),
        (
            Some(json!(null)),
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#,
        ),
        (
            Some(json!("abc")),
            r#"{"jsonrpc":"2.0","id":"abc","error":{"code":-32600,"message":"Invalid Request"}}"#,
        ),
    ];
    for (id, expected) in rows {
        let (status, headers, body) = read(answer::error(
            StatusCode::BAD_REQUEST,
            id.as_ref(),
            -32600,
            "Invalid Request",
        ))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_inert(&headers);
        assert_eq!(body, expected);
    }
}

#[tokio::test]
async fn empty_list_answers_by_generation() {
    let stateless = message_for("prompts/list", Shape::Request, Generation::Stateless);
    let (status, headers, body) = read(answer::empty_list(&stateless, "prompts")).await;
    assert_eq!(status, StatusCode::OK);
    assert_inert(&headers);
    assert_eq!(
        body,
        r#"{"jsonrpc":"2.0","id":1,"result":{"prompts":[],"resultType":"complete","ttlMs":60000,"cacheScope":"private"}}"#
    );

    let session = message_for("prompts/list", Shape::Request, Generation::Session);
    let (_, _, body) = read(answer::empty_list(&session, "prompts")).await;
    assert_eq!(body, r#"{"jsonrpc":"2.0","id":1,"result":{"prompts":[]}}"#);

    let resources = classify(
        json!({"id": "r", "method": "resources/list", "params": {"_meta": {META: STATELESS_HEADER}}}),
        Some(STATELESS_HEADER),
    )
    .expect("classifies");
    let (_, _, body) = read(answer::empty_list(&resources, "resources")).await;
    assert_eq!(
        body,
        r#"{"jsonrpc":"2.0","id":"r","result":{"resources":[],"resultType":"complete","ttlMs":60000,"cacheScope":"private"}}"#
    );

    let templates = message_for(
        "resources/templates/list",
        Shape::Request,
        Generation::Session,
    );
    let (_, _, body) = read(answer::empty_list(&templates, "resourceTemplates")).await;
    assert_eq!(
        body,
        r#"{"jsonrpc":"2.0","id":1,"result":{"resourceTemplates":[]}}"#
    );

    let notice = message_for("prompts/list", Shape::Notification, Generation::Session);
    let (_, _, body) = read(answer::empty_list(&notice, "prompts")).await;
    assert_eq!(
        body,
        r#"{"jsonrpc":"2.0","id":null,"result":{"prompts":[]}}"#
    );
}
