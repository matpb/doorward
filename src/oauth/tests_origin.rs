//! Statement 48: the Origin rule, its refusal and its log line, as plain functions.

use axum::body::to_bytes;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use time::OffsetDateTime;

use crate::config::Config;

use super::origin::{Log, allowed, refusal, shown_value};

const OWN: &str = "http://127.0.0.1:8717";
const ENTRY: &str = "chrome-extension://abcdefghijklmnop";
const REFUSAL: &str =
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Origin not allowed"}}"#;

/// The instant `seconds` after a fixed moment.
fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).expect("a valid time")
}

/// A request's Origin headers, in order.
fn origins(values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values {
        let value = HeaderValue::from_bytes(value.as_bytes()).expect("a valid header value");
        headers.append(ORIGIN, value);
    }
    headers
}

/// The `public_url` a configuration stores for `public_url`, or the error text that refuses it.
fn stored_public_url(public_url: &str) -> Result<String, String> {
    let vars = vec![
        ("DOORWARD_PUBLIC_URL".to_owned(), public_url.to_owned()),
        (
            "DOORWARD_DATABASE".to_owned(),
            "/var/lib/doorward/doorward.db".to_owned(),
        ),
    ];
    Config::from_sources(None, &vars)
        .map(|config| config.public_url)
        .map_err(|err| err.to_string())
}

/// The public origin of a configuration loaded with `public_url`, as the rule compares it.
fn own_of(public_url: &str) -> String {
    stored_public_url(public_url).expect("the configuration loads")
}

#[test]
fn the_stored_public_url_is_the_text_a_browser_sends_as_origin() {
    let cases: [(&str, Result<&str, &str>); 7] = [
        ("https://gw.example.com/", Ok("https://gw.example.com")),
        ("https://GW.Example.com", Ok("https://gw.example.com")),
        ("https://gw.example.com:443", Ok("https://gw.example.com")),
        (
            "http://gw.example.com:80",
            Err("invalid public_url: http is allowed only for a loopback address"),
        ),
        (
            "https://gw.example.com/base",
            Err("invalid public_url: must not contain a path"),
        ),
        (
            "https://gw.example.com?",
            Err("invalid public_url: must not contain a query"),
        ),
        (
            "https://gw.example.com#",
            Err("invalid public_url: must not contain a fragment"),
        ),
    ];
    for (given, want) in cases {
        let got = stored_public_url(given);
        assert_eq!(got.as_deref().map_err(String::as_str), want, "{given}");
    }
}

#[test]
fn the_origin_rule_table() {
    let extra = [ENTRY.to_owned()];
    let cases: &[(&str, &str, &[&str], bool)] = &[
        ("no Origin header", OWN, &[], true),
        ("the own origin", OWN, &[OWN], true),
        (
            "the own origin with a port",
            "https://gw.example.com:8443",
            &["https://gw.example.com:8443"],
            true,
        ),
        (
            "the own origin over https",
            "https://gw.example.com",
            &["https://gw.example.com"],
            true,
        ),
        (
            "the own origin with a trailing slash",
            OWN,
            &["http://127.0.0.1:8717/"],
            false,
        ),
        (
            "an uppercase scheme",
            OWN,
            &["HTTP://127.0.0.1:8717"],
            false,
        ),
        (
            "an uppercase host",
            "https://gw.example.com",
            &["https://GW.example.com"],
            false,
        ),
        (
            "an explicit default port over http",
            "http://gw.example.com",
            &["http://gw.example.com:80"],
            false,
        ),
        (
            "an explicit default port over https",
            "https://gw.example.com",
            &["https://gw.example.com:443"],
            false,
        ),
        ("another port", OWN, &["http://127.0.0.1:8718"], false),
        ("another scheme", OWN, &["https://127.0.0.1:8717"], false),
        ("null", OWN, &["null"], false),
        ("an empty value", OWN, &[""], false),
        ("two headers, own and own", OWN, &[OWN, OWN], false),
        (
            "two headers, own and foreign",
            OWN,
            &[OWN, "https://evil.example.com"],
            false,
        ),
        (
            "a look-alike suffix",
            "https://gw.example.com",
            &["https://gw.example.com.evil.example.com"],
            false,
        ),
        (
            "a look-alike prefix",
            "https://gw.example.com",
            &["xhttps://gw.example.com"],
            false,
        ),
        ("an allowed entry", OWN, &[ENTRY], true),
        (
            "an entry differing by one character",
            OWN,
            &["chrome-extension://abcdefghijklmnoq"],
            false,
        ),
        (
            "an allowed entry with a character appended",
            OWN,
            &["chrome-extension://abcdefghijklmnopq"],
            false,
        ),
        (
            "an allowed entry with a domain appended",
            OWN,
            &["chrome-extension://abcdefghijklmnop.evil.example.com"],
            false,
        ),
        (
            "an allowed entry cut by one character",
            OWN,
            &["chrome-extension://abcdefghijklmno"],
            false,
        ),
        (
            "a header that is a prefix of an allowed entry",
            OWN,
            &["chrome-extension://"],
            false,
        ),
        (
            "a value with a byte above 0x7F",
            "https://gw.example.com",
            &["https://gw.example.com\u{e9}"],
            false,
        ),
        (
            "a value with a space",
            "https://gw.example.com",
            &["https://gw.example.com "],
            false,
        ),
    ];
    for (name, own, values, expected) in cases {
        assert_eq!(
            allowed(&origins(values), own, &extra),
            *expected,
            "{name}: the rule must answer {expected}"
        );
    }
}

#[test]
fn the_own_origin_is_the_normalised_public_url() {
    let cases = [
        ("http://127.0.0.1:8717", "http://127.0.0.1:8717"),
        ("https://gw.example.com", "https://gw.example.com"),
        ("https://gw.example.com:8443", "https://gw.example.com:8443"),
        ("http://[::1]:8717", "http://[::1]:8717"),
        ("HTTPS://GW.example.com:443/", "https://gw.example.com"),
    ];
    for (given, want) in cases {
        assert_eq!(own_of(given), want, "{given} must give its origin");
    }
}

#[tokio::test]
async fn the_refusal_is_the_exact_answer() {
    let response = refusal(&origins(&["https://evil.example.com"]), at(0));
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let headers = response.headers();
    assert_eq!(
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        headers
            .get(X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get(CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("sandbox")
    );
    assert!(headers.get(WWW_AUTHENTICATE).is_none());
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body is read");
    assert_eq!(body.as_ref(), REFUSAL.as_bytes());
}

/// The line a refusal of `shown` prints.
fn line(shown: &str) -> String {
    format!("doorward: refused an Origin that is not allowed: {shown}")
}

/// The line that reports `n` refusals past the budget.
fn more(n: u64) -> String {
    format!("doorward: {n} more refused Origin values were not shown")
}

#[test]
fn a_value_is_logged_once_a_minute() {
    let mut log = Log::new();
    assert_eq!(log.record("x", at(0)), vec![line("x")]);
    assert!(log.record("x", at(30)).is_empty());
    assert!(log.record("x", at(59)).is_empty());
    assert_eq!(log.record("x", at(60)), vec![line("x")]);
}

#[test]
fn the_same_value_twice_in_a_minute_uses_one_line_of_the_budget() {
    let mut log = Log::new();
    assert_eq!(log.record("v", at(0)), vec![line("v")]);
    assert!(log.record("v", at(30)).is_empty());
    for index in 0..19 {
        let shown = format!("w{index}");
        assert_eq!(log.record(&shown, at(30)), vec![line(&shown)]);
    }
    assert!(
        log.record("late", at(30)).is_empty(),
        "the budget of 20 lines is spent"
    );
    assert_eq!(log.record("next", at(60)), vec![more(1), line("next")]);
}

#[test]
fn twenty_lines_a_minute_and_the_rest_are_counted() {
    let mut log = Log::new();
    let mut printed = 0;
    for index in 0..25 {
        printed += log.record(&format!("v{index}"), at(0)).len();
    }
    assert_eq!(printed, 20, "twenty lines in the first minute");
    assert_eq!(
        log.record("v25", at(60)),
        vec![more(5), line("v25")],
        "the first refusal of the next window reports the five dropped"
    );
}

#[test]
fn a_refusal_past_the_budget_is_not_remembered() {
    let mut log = Log::new();
    for index in 0..1020 {
        log.record(&format!("v{index}"), at(0));
    }
    assert_eq!(
        log.remembered(),
        20,
        "only the values printed are remembered"
    );
}

#[test]
fn a_value_dropped_by_the_budget_prints_when_it_comes_again_in_the_next_window() {
    let mut log = Log::new();
    for index in 0..25 {
        log.record(&format!("v{index}"), at(0));
    }
    assert_eq!(log.record("v20", at(60)), vec![more(5), line("v20")]);
}

#[test]
fn the_more_line_does_not_use_the_new_budget() {
    let mut log = Log::new();
    for index in 0..25 {
        log.record(&format!("v{index}"), at(0));
    }
    let mut printed = Vec::new();
    for index in 25..50 {
        printed.extend(log.record(&format!("v{index}"), at(60)));
    }
    assert_eq!(printed.len(), 21, "the report line and twenty lines");
    assert_eq!(printed.first(), Some(&more(5)));
    assert_eq!(printed.last(), Some(&line("v44")));
}

#[test]
fn a_quiet_minute_with_nothing_dropped_prints_no_extra_line() {
    let mut log = Log::new();
    assert_eq!(log.record("a", at(0)), vec![line("a")]);
    assert_eq!(log.record("b", at(61)), vec![line("b")]);
}

#[test]
fn at_most_64_distinct_values_are_remembered() {
    let mut log = Log::new();
    // Twenty values a minute, so the budget never hides one of them.
    for index in 0..65 {
        let shown = format!("v{index}");
        assert_eq!(
            log.record(&shown, at(60 * (index / 20))),
            vec![line(&shown)]
        );
    }
    assert_eq!(log.remembered(), 64);
    assert!(
        log.record("v64", at(181)).is_empty(),
        "the newest value is still remembered"
    );
}

#[test]
fn a_shown_value_is_cut_to_200_bytes_and_other_bytes_are_question_marks() {
    assert_eq!(shown_value("a".repeat(300).as_bytes()), "a".repeat(200));
    assert_eq!(shown_value("\u{e9} \n".as_bytes()), "????");
    let edge = format!("{}\u{e9}", "a".repeat(199));
    assert_eq!(
        shown_value(edge.as_bytes()),
        format!("{}?", "a".repeat(199))
    );
    assert_eq!(
        shown_value(b"https://gw.example.com"),
        "https://gw.example.com"
    );
}
