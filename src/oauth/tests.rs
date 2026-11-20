//! Pure and storage tests of the redirect grammar, the allowlist, registration and metadata.

use std::path::Path;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

use crate::app::{Deps, assemble, serve};
use crate::config::{Config, Limits};
use crate::crypto::PasswordHasher;

use super::clients::{self, Client, is_document_id};
use super::metadata::{authorization_document, resource_document};
use super::policy::{self, SHIPPED, Verdict};
use super::register::{self, Decision, Refusal, Registration};
use super::uri::{self, Redirect};

const WEEK: i64 = 604_800;
const HOUR: i64 = 3_600;
const NOW: i64 = 1_800_000_000;
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

fn web<'a>(scheme: &'a str, host: &'a str, path: &'a str) -> Redirect<'a> {
    Redirect::Web { scheme, host, path }
}

fn loopback<'a>(host: &'a str, port: Option<&'a str>, path: &'a str) -> Redirect<'a> {
    Redirect::Loopback { host, port, path }
}

/// A fresh database file with every migration applied, and a connection to it.
fn open() -> (TempDir, Connection) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("doorward.db");
    crate::db::Db::open(&path).expect("database");
    let conn = Connection::open(&path).expect("connection");
    (dir, conn)
}

/// A database with the shipped allowlist written, as at a first start.
fn shipped() -> (TempDir, Connection) {
    let (dir, mut conn) = open();
    policy::sync_shipped(&mut conn).expect("sync");
    (dir, conn)
}

fn decide(conn: &Connection, text: &str) -> Verdict {
    let parsed = uri::parse(text).unwrap_or_else(|| panic!("{text} must parse"));
    policy::decide(conn, &parsed).expect("decision")
}

fn metadata(text: &str) -> Map<String, Value> {
    match serde_json::from_str::<Value>(text).expect("json") {
        Value::Object(map) => map,
        other => panic!("expected an object, got {other}"),
    }
}

// ---- The schema ----

#[test]
fn a_new_database_has_the_activity_and_request_indexes() {
    let (_dir, conn) = open();
    let mut statement = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
        .expect("statement");
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<String>>>()
        .expect("names");
    for index in ["activity_kind_at", "auth_requests_expires"] {
        assert!(names.iter().any(|name| name == index), "{index} must exist");
    }
}

// ---- The redirect grammar ----

#[test]
fn the_accepted_addresses_parse_to_their_exact_parts() {
    assert_eq!(
        uri::parse("cursor://anysphere.cursor-mcp/oauth/callback"),
        Some(web("cursor", "anysphere.cursor-mcp", "/oauth/callback"))
    );
    assert_eq!(
        uri::parse("https://www.cursor.com/agents/mcp/oauth/callback"),
        Some(web("https", "www.cursor.com", "/agents/mcp/oauth/callback"))
    );
    assert_eq!(
        uri::parse("http://localhost:8787/callback"),
        Some(loopback("localhost", Some("8787"), "/callback"))
    );
    assert_eq!(
        uri::parse("http://[::1]:9/callback"),
        Some(loopback("[::1]", Some("9"), "/callback"))
    );
    assert_eq!(
        uri::parse("http://127.0.0.1/callback"),
        Some(loopback("127.0.0.1", None, "/callback"))
    );
    assert_eq!(
        uri::parse("evilapp://callback"),
        Some(web("evilapp", "callback", ""))
    );
    assert_eq!(
        uri::parse("https://claude.ai/"),
        Some(web("https", "claude.ai", "/"))
    );
    assert_eq!(
        uri::parse("http://127.0.0.1:65535/cb"),
        Some(loopback("127.0.0.1", Some("65535"), "/cb"))
    );
    assert_eq!(
        uri::parse("http://127.0.0.1:1/cb"),
        Some(loopback("127.0.0.1", Some("1"), "/cb"))
    );
    assert_eq!(uri::parse("a+b.c-d://x/y"), Some(web("a+b.c-d", "x", "/y")));
    assert_eq!(
        uri::parse("https://a.b-c.example.com/x_y~z.d"),
        Some(web("https", "a.b-c.example.com", "/x_y~z.d"))
    );
}

#[test]
fn a_scheme_a_browser_handles_itself_is_never_an_address() {
    for scheme in [
        "javascript",
        "data",
        "vbscript",
        "file",
        "blob",
        "about",
        "filesystem",
        "view-source",
    ] {
        let text = format!("{scheme}://host/path");
        assert_eq!(uri::parse(&text), None, "{text} must be refused");
    }
    assert!(uri::parse("evilapp://callback").is_some());
    assert!(uri::parse("cursor://anysphere.cursor-mcp/oauth/callback").is_some());
    assert!(!policy::admin_entry_ok("javascript", "host", "/path"));
    let refused =
        register::check_metadata(&metadata(r#"{"redirect_uris":["javascript://host/path"]}"#));
    assert_eq!(
        refused,
        Err(Refusal::Metadata),
        "a javascript address is invalid_client_metadata"
    );
}

#[test]
fn the_scheme_and_the_length_have_limits() {
    let long_scheme = format!("a{}", "b".repeat(31));
    assert!(uri::parse(&format!("{long_scheme}://x/y")).is_some());
    let longest_scheme = format!("a{}", "b".repeat(32));
    assert_eq!(uri::parse(&format!("{longest_scheme}://x/y")), None);
    assert_eq!(uri::parse("1abc://x/y"), None);
    assert_eq!(uri::parse("HTTP://localhost/cb"), None);
    let longest = format!("https://claude.ai/{}", "a".repeat(1982));
    assert_eq!(longest.len(), 2000);
    assert!(uri::parse(&longest).is_some(), "2000 characters is allowed");
    let too_long = format!("https://claude.ai/{}", "a".repeat(1983));
    assert_eq!(too_long.len(), 2001);
    assert_eq!(uri::parse(&too_long), None, "2001 characters is refused");
}

#[test]
fn the_host_length_has_a_limit() {
    let three = format!("https://{}.ai/a", vec!["a".repeat(63); 3].join("."));
    assert!(
        uri::parse(&three).is_some(),
        "a 194 character host is allowed"
    );
    let four = format!("https://{}.ai/a", vec!["a".repeat(63); 4].join("."));
    assert_eq!(
        uri::parse(&four),
        None,
        "a host over 253 characters is refused"
    );
}

#[test]
fn the_addresses_the_grammar_refuses_parse_to_none() {
    let all_zero = format!("http://{0}.{0}.{0}.{0}:53535/callback", 0);
    let short_loopback = format!("http://{}.{}:53535/callback", 127, 1);
    let decimal_host = format!("https://{}/a", 2_130_706_433_u32);
    let userinfo = format!("https://{}@claude.ai/a", "user");
    let refused = [
        all_zero.as_str(),
        short_loopback.as_str(),
        decimal_host.as_str(),
        "https://claude.ai/api/mcp/auth_callback/../../evil",
        "https://claude.ai/%2e%2e/evil",
        "https://claude.ai//evil",
        "https://claude.ai/a?b=c",
        "https://claude.ai/a#b",
        "https://claude.ai:443/a",
        "https://CLAUDE.ai/a",
        "https://claude.ai./a",
        userinfo.as_str(),
        "https://claude.ai\\@evil.example.com/a",
        "https://xn--clade-gra.ai/a",
        "http://client.example.com/cb",
        "http://127.0.0.1:0/cb",
        "http://127.0.0.1:65536/cb",
        "http://127.0.0.1:08/cb",
        "http://[::ffff:127.0.0.1]/cb",
        "http://localhost.evil.example.com/cb",
        "https://cl\u{e4}ude.ai/a",
        "https://claude.ai",
        "https://0x7f000001/a",
        "https://a.0x1f/a",
        "https://127.0.0.1/cb",
        "http://localhost",
        "http://localhost:/cb",
        "http://localhost:123456/cb",
        "https://a..b/x",
        "https://-a.example.com/x",
        "https://a-.example.com/x",
        "https://claude.ai/a:b",
        "https://claude.ai/a@b",
        "https://claude.ai/a%20b",
        "https://claude.ai/a/.",
        "https://claude.ai/a/..",
        "https://claude.ai/a//",
        "https://claude.ai/a\n",
        "https://*.example.com/cb",
        "https://claude.ai/a b",
        "https://claude.ai/a?",
        "https://claude.ai/a#",
    ];
    for text in refused {
        assert_eq!(uri::parse(text), None, "{text:?} must be refused");
    }
    let four_labels = format!("https://{}.ai/a", vec!["a".repeat(63); 4].join("."));
    assert_eq!(uri::parse(&four_labels), None);
}

#[test]
fn the_redirect_must_match_exactly_for_web_addresses() {
    let registered = "https://www.cursor.com/agents/mcp/oauth/callback";
    assert!(uri::matches(registered, registered));
    assert!(!uri::matches(registered, &format!("{registered}x")));
    assert!(!uri::matches(registered, &format!("{registered}/extra")));
    assert!(!uri::matches(registered, &format!("{registered}?a=1")));
    assert!(!uri::matches(
        registered,
        &registered.replacen("https", "http", 1)
    ));
    assert!(!uri::matches(
        registered,
        &registered.replacen("www", "WWW", 1)
    ));
    assert!(!uri::matches(
        registered,
        &registered.replacen(".com", ".com.", 1)
    ));
    assert!(!uri::matches(
        registered,
        &registered.replacen(".com", ".com:444", 1)
    ));
}

#[test]
fn loopback_matches_ignore_the_port_only() {
    assert!(uri::matches(
        "http://localhost/callback",
        "http://localhost:53123/callback"
    ));
    assert!(uri::matches(
        "http://localhost:53123/callback",
        "http://localhost/callback"
    ));
    assert!(!uri::matches(
        "http://localhost/callback",
        "http://127.0.0.1:53123/callback"
    ));
    assert!(!uri::matches(
        "http://localhost/callback",
        "http://localhost:1/callback2"
    ));
    assert!(!uri::matches(
        "http://localhost/callback",
        "https://localhost/callback"
    ));
    assert!(!uri::matches("not an address", "not an address"));
}

#[test]
fn the_redirect_key_drops_only_a_loopback_port() {
    let with_port = uri::parse("http://localhost:8787/callback").expect("parse");
    assert_eq!(uri::redirect_key(&with_port), "http://localhost/callback");
    let without = uri::parse("http://[::1]/callback").expect("parse");
    assert_eq!(uri::redirect_key(&without), "http://[::1]/callback");
    let web_address = uri::parse("cursor://anysphere.cursor-mcp/oauth/callback").expect("parse");
    assert_eq!(
        uri::redirect_key(&web_address),
        "cursor://anysphere.cursor-mcp/oauth/callback"
    );
}

#[test]
fn a_path_may_hold_its_characters_and_dots_inside_segments() {
    assert_eq!(
        uri::parse("https://claude.ai/.well-known/x"),
        Some(web("https", "claude.ai", "/.well-known/x"))
    );
    assert_eq!(
        uri::parse("https://claude.ai/a./..b"),
        Some(web("https", "claude.ai", "/a./..b"))
    );
}

// ---- The allowlist ----

#[test]
fn every_shipped_entry_is_a_web_address_of_its_own_parts() {
    for (scheme, host, path) in SHIPPED {
        assert!(
            policy::admin_entry_ok(scheme, host, path),
            "shipped entry {scheme} {host} {path} must be a valid entry"
        );
    }
    assert_eq!(SHIPPED.len(), 5, "the shipped table has five rows");
    assert!(
        !SHIPPED.iter().any(|(_, host, _)| *host == "vscode.dev"),
        "vscode.dev is deliberately not shipped"
    );
}

#[test]
fn the_path_rule_is_exact_unless_the_prefix_ends_in_a_slash() {
    assert!(policy::path_rule_matches("/", "/anything"));
    assert!(policy::path_rule_matches("/a/", "/a/b"));
    assert!(policy::path_rule_matches("/a/", "/a/"));
    assert!(!policy::path_rule_matches("/a/", "/a"));
    assert!(policy::path_rule_matches("/a", "/a"));
    assert!(!policy::path_rule_matches("/a", "/a/b"));
    assert!(policy::path_rule_matches("", ""));
    assert!(!policy::path_rule_matches("", "/"));
}

#[test]
fn the_decision_table_holds_for_shipped_entries() {
    let (_dir, conn) = shipped();
    assert_eq!(
        decide(&conn, CLAUDE_CALLBACK),
        Verdict::Allowed,
        "exact entry"
    );
    assert_eq!(
        decide(&conn, &format!("{CLAUDE_CALLBACK}/x")),
        Verdict::Blocked,
        "a longer path than an exact entry"
    );
    assert_eq!(
        decide(&conn, "https://chatgpt.com/connector/oauth/abc123"),
        Verdict::Allowed,
        "prefix entry"
    );
    assert_eq!(
        decide(&conn, "https://chatgpt.com/connector/oauth"),
        Verdict::Blocked,
        "the prefix without its slash"
    );
    assert_eq!(
        decide(&conn, "cursor://anysphere.cursor-mcp/oauth/callback"),
        Verdict::Allowed,
        "private scheme entry"
    );
    assert_eq!(
        decide(&conn, "cursor://claude.ai/api/mcp/auth_callback"),
        Verdict::Blocked,
        "wrong scheme for a listed host"
    );
    assert_eq!(
        decide(&conn, "https://vscode.dev/redirect"),
        Verdict::Blocked,
        "an address that is not shipped"
    );
}

#[test]
fn the_decision_table_holds_for_admin_entries_and_disabled_rows() {
    let (_dir, conn) = shipped();
    policy::add(&conn, "https", "app.example.com", "/oauth/").expect("add");
    assert_eq!(
        decide(&conn, "https://app.example.com/oauth/x"),
        Verdict::Allowed,
        "an added prefix entry"
    );
    assert_eq!(
        decide(&conn, "https://app.example.com/"),
        Verdict::Blocked,
        "outside an added prefix"
    );
    conn.execute(
        "UPDATE redirect_allow SET enabled = 0 WHERE host = 'claude.ai'",
        [],
    )
    .expect("disable");
    assert_eq!(
        decide(&conn, CLAUDE_CALLBACK),
        Verdict::Blocked,
        "a disabled entry allows nothing"
    );
}

#[test]
fn an_empty_path_entry_matches_only_the_empty_path() {
    let (_dir, conn) = shipped();
    policy::add(&conn, "myapp", "callback", "").expect("add");
    assert_eq!(decide(&conn, "myapp://callback"), Verdict::Allowed);
    assert_eq!(decide(&conn, "myapp://callback/x"), Verdict::Blocked);
}

#[test]
fn loopback_is_always_allowed_even_with_an_empty_list() {
    let (_dir, conn) = shipped();
    conn.execute("DELETE FROM redirect_allow", [])
        .expect("clear");
    assert_eq!(
        decide(&conn, "http://127.0.0.1:53535/callback"),
        Verdict::Allowed
    );
    assert_eq!(
        decide(&conn, "http://localhost:9/callback"),
        Verdict::Allowed
    );
    assert_eq!(decide(&conn, "http://[::1]:9/callback"), Verdict::Allowed);
}

#[test]
fn shipped_entries_survive_a_restart_with_their_enabled_flag() {
    let (_dir, mut conn) = shipped();
    conn.execute(
        "UPDATE redirect_allow SET enabled = 0 WHERE host = 'claude.ai'",
        [],
    )
    .expect("disable");
    policy::sync_shipped(&mut conn).expect("restart");
    let rows = policy::list(&conn).expect("list");
    assert_eq!(rows.len(), 5, "no shipped row is duplicated or lost");
    let claude = rows
        .iter()
        .find(|row| row.host == "claude.ai")
        .expect("row");
    assert!(!claude.enabled, "a disabled shipped row stays disabled");
    assert_eq!(claude.source, "shipped");
    assert!(
        rows.iter()
            .filter(|row| row.host != "claude.ai")
            .all(|row| row.enabled),
        "the other shipped rows stay enabled"
    );
}

#[test]
fn a_shipped_row_removed_from_the_table_is_gone_after_a_restart() {
    let (_dir, mut conn) = shipped();
    conn.execute(
        "INSERT INTO redirect_allow (scheme, host, path_prefix, source, enabled) \
         VALUES ('https', 'old.example.com', '/x', 'shipped', 1)",
        [],
    )
    .expect("insert withdrawn row");
    conn.execute(
        "INSERT INTO redirect_allow (scheme, host, path_prefix, source, enabled) \
         VALUES ('https', 'mine.example.com', '/y', 'added', 1)",
        [],
    )
    .expect("insert admin row");
    policy::sync_shipped(&mut conn).expect("restart");
    let rows = policy::list(&conn).expect("list");
    assert!(
        !rows.iter().any(|row| row.host == "old.example.com"),
        "a shipped row that left the table is deleted"
    );
    assert!(
        rows.iter()
            .any(|row| row.host == "mine.example.com" && row.source == "added"),
        "an admin's row is never withdrawn"
    );
}

#[test]
fn an_admin_entry_is_exactly_its_three_parts() {
    assert!(policy::admin_entry_ok(
        "https",
        "claude.ai",
        "/api/mcp/auth_callback"
    ));
    assert!(policy::admin_entry_ok(
        "https",
        "app.example.com",
        "/oauth/"
    ));
    assert!(policy::admin_entry_ok("https", "app.example.com", "/"));
    assert!(policy::admin_entry_ok("myapp", "callback", ""));
    assert!(!policy::admin_entry_ok("https", "app.example.com", ""));
    assert!(!policy::admin_entry_ok("http", "localhost", "/cb"));
    assert!(!policy::admin_entry_ok("http", "example.com", "/cb"));
    assert!(!policy::admin_entry_ok("https", "127.0.0.1", "/cb"));
    assert!(!policy::admin_entry_ok("https", "claude.ai", "/a?b"));
    assert!(!policy::admin_entry_ok("https", "claude.ai", "evil"));
    assert!(!policy::admin_entry_ok("https", "claude.ai/x", "/y"));
    assert!(!policy::admin_entry_ok("https", "Claude.ai", "/a"));
    assert!(!policy::admin_entry_ok("", "claude.ai", "/a"));
}

// ---- Clients ----

#[test]
fn a_document_id_is_an_https_address_with_a_path() {
    assert!(is_document_id("https://client.example.com/app.json"));
    assert!(is_document_id("https://client.example.com/a"));
    assert!(!is_document_id("https://client.example.com/"));
    assert!(!is_document_id("https://client.example.com"));
    assert!(!is_document_id("http://client.example.com/app.json"));
    assert!(!is_document_id("https://127.0.0.1/app.json"));
    assert!(!is_document_id("dcr_abc"));
}

#[test]
fn find_returns_a_registered_client_and_a_document_and_nothing_else() {
    let (_dir, mut conn) = open();
    let checked = register::check_metadata(&metadata(
        r#"{"client_name":"Cursor","redirect_uris":["http://localhost:8787/callback"]}"#,
    ));
    let created = register::register_in(&mut conn, "addr-a", 5, NOW, checked).expect("register");
    let Decision::Created(body) = created else {
        panic!("a valid registration must be created, got {created:?}");
    };
    let client_id = body["client_id"].as_str().expect("client id").to_owned();
    assert_eq!(
        clients::find(&conn, &client_id).expect("find"),
        Some(Client::Registered {
            client_id: client_id.clone(),
            client_name: "Cursor".into(),
            redirect_uris: vec!["http://localhost:8787/callback".into()],
        })
    );
    assert_eq!(
        clients::find(&conn, "dcr_doesnotexist").expect("find"),
        None
    );
    assert_eq!(
        clients::find(&conn, "https://client.example.com/app.json").expect("find"),
        Some(Client::Document {
            client_id: "https://client.example.com/app.json".into()
        })
    );
    assert_eq!(
        clients::find(&conn, "https://client.example.com/").expect("find"),
        None
    );
    assert_eq!(clients::find(&conn, "random").expect("find"), None);
}

// ---- Registration: metadata checks ----

#[test]
fn a_valid_registration_is_checked_and_its_other_fields_are_ignored() {
    let object = metadata(
        r#"{"client_name":"  Cursor  ","redirect_uris":["cursor://anysphere.cursor-mcp/oauth/callback","http://localhost:8787/callback"],
            "token_endpoint_auth_method":"client_secret_basic","client_secret":"x"}"#,
    );
    assert_eq!(
        register::check_metadata(&object),
        Ok(Registration {
            client_name: "Cursor".into(),
            redirect_uris: vec![
                "cursor://anysphere.cursor-mcp/oauth/callback".into(),
                "http://localhost:8787/callback".into(),
            ],
        })
    );
}

#[test]
fn a_missing_or_blank_name_is_the_default() {
    for text in [
        r#"{"redirect_uris":["https://app.example.com/cb"]}"#,
        r#"{"client_name":"","redirect_uris":["https://app.example.com/cb"]}"#,
        r#"{"client_name":"   ","redirect_uris":["https://app.example.com/cb"]}"#,
    ] {
        let checked = register::check_metadata(&metadata(text)).expect("accepted");
        assert_eq!(checked.client_name, "Unnamed client", "for {text}");
    }
}

#[test]
fn the_name_limits_and_the_invisible_characters_are_enforced() {
    let uris = r#""redirect_uris":["https://app.example.com/cb"]"#;
    let name_of = |name: &str| {
        let text = format!(r#"{{"client_name":{},{uris}}}"#, json!(name));
        register::check_metadata(&metadata(&text))
    };
    assert!(
        name_of(&"n".repeat(100)).is_ok(),
        "100 characters is allowed"
    );
    assert_eq!(
        name_of(&"n".repeat(101)),
        Err(Refusal::Metadata),
        "101 is refused"
    );
    assert_eq!(
        name_of("Claude\u{202E}"),
        Err(Refusal::Metadata),
        "U+202E is refused"
    );
    assert_eq!(
        name_of("a\u{200B}b"),
        Err(Refusal::Metadata),
        "U+200B is refused"
    );
    assert_eq!(
        name_of("a\u{2066}b"),
        Err(Refusal::Metadata),
        "U+2066 is refused"
    );
    assert_eq!(
        name_of("a\u{FEFF}b"),
        Err(Refusal::Metadata),
        "U+FEFF is refused"
    );
    assert_eq!(
        name_of("a\nb"),
        Err(Refusal::Metadata),
        "a line break is refused"
    );
    assert_eq!(
        name_of("a\u{7}b"),
        Err(Refusal::Metadata),
        "a control character is refused"
    );
    assert_eq!(
        name_of("Caf\u{e9} \u{1F600}").map(|r| r.client_name),
        Ok("Caf\u{e9} \u{1F600}".into())
    );
    let not_text = metadata(&format!(r#"{{"client_name":5,{uris}}}"#));
    assert_eq!(register::check_metadata(&not_text), Err(Refusal::Metadata));
    let null_name = metadata(&format!(r#"{{"client_name":null,{uris}}}"#));
    assert_eq!(register::check_metadata(&null_name), Err(Refusal::Metadata));
}

#[test]
fn is_plain_text_refuses_every_invisible_and_direction_character() {
    let refused = [
        ("U+00AD", "a\u{AD}b"),
        ("U+061C", "a\u{61C}b"),
        ("U+2060", "a\u{2060}b"),
        ("U+2061", "a\u{2061}b"),
        ("U+2062", "a\u{2062}b"),
        ("U+2063", "a\u{2063}b"),
        ("U+2064", "a\u{2064}b"),
        ("U+180E", "a\u{180E}b"),
        ("U+115F", "a\u{115F}b"),
        ("U+1160", "a\u{1160}b"),
        ("U+3164", "a\u{3164}b"),
        ("U+FFA0", "a\u{FFA0}b"),
        ("U+2028", "a\u{2028}b"),
        ("U+2029", "a\u{2029}b"),
        ("U+200F", "a\u{200F}b"),
        ("U+202A", "a\u{202A}b"),
        ("U+2069", "a\u{2069}b"),
        ("U+FEFF", "a\u{FEFF}b"),
        ("U+0007", "a\u{7}b"),
    ];
    let accepted: Vec<&str> = refused
        .iter()
        .filter(|(_, text)| register::is_plain_text(text))
        .map(|(label, _)| *label)
        .collect();
    assert_eq!(
        accepted,
        Vec::<&str>::new(),
        "these characters must make a name refused"
    );
    for text in [
        "Claude Code",
        "Zed (preview)",
        "Caf\u{e9}",
        "\u{4F60}\u{597D} client",
        "Client \u{1F600}",
    ] {
        assert!(register::is_plain_text(text), "{text:?} must be plain text");
    }
}

#[test]
fn the_redirect_list_is_one_to_ten_strings() {
    let one_of =
        |list: &str| register::check_metadata(&metadata(&format!(r#"{{"redirect_uris":{list}}}"#)));
    let ten: Vec<String> = (0..10)
        .map(|n| format!("https://app{n}.example.com/cb"))
        .collect();
    assert!(
        one_of(&json!(ten).to_string()).is_ok(),
        "ten addresses are allowed"
    );
    let eleven: Vec<String> = (0..11)
        .map(|n| format!("https://app{n}.example.com/cb"))
        .collect();
    assert_eq!(
        one_of(&json!(eleven).to_string()),
        Err(Refusal::Metadata),
        "eleven are refused"
    );
    assert_eq!(
        one_of("[]"),
        Err(Refusal::Metadata),
        "an empty list is refused"
    );
    assert_eq!(
        one_of("\"https://app.example.com/cb\""),
        Err(Refusal::Metadata)
    );
    assert_eq!(
        one_of("[5]"),
        Err(Refusal::Metadata),
        "a list of non-strings"
    );
    assert!(
        register::check_metadata(&metadata("{}")).is_err(),
        "a missing list is refused"
    );
}

#[test]
fn a_bad_address_names_its_refusal_by_what_it_contains() {
    let refusal_of = |uri: &str| {
        register::check_metadata(&metadata(&json!({"redirect_uris": [uri]}).to_string()))
    };
    assert_eq!(
        refusal_of("https://www.cursor.com/callback#fragment"),
        Err(Refusal::RedirectUri)
    );
    assert_eq!(
        refusal_of("https://*.example.com/callback"),
        Err(Refusal::RedirectUri)
    );
    assert_eq!(
        refusal_of("http://client.example.com/callback"),
        Err(Refusal::RedirectUri)
    );
    assert_eq!(
        refusal_of("http://127.0.0.1:0/cb"),
        Err(Refusal::RedirectUri)
    );
    assert_eq!(refusal_of("myhost"), Err(Refusal::Metadata));
    assert_eq!(refusal_of("https://claude.ai"), Err(Refusal::Metadata));
    let first_bad_decides = metadata(
        r#"{"redirect_uris":["https://claude.ai","https://x.example.com/#"],"client_name":"a\u202Eb"}"#,
    );
    assert_eq!(
        register::check_metadata(&first_bad_decides),
        Err(Refusal::Metadata),
        "the first bad address decides, and an address refusal comes before a name refusal"
    );
    let address_before_name =
        metadata(r#"{"redirect_uris":["https://x.example.com/#"],"client_name":"a\u202Eb"}"#);
    assert_eq!(
        register::check_metadata(&address_before_name),
        Err(Refusal::RedirectUri)
    );
}

#[test]
fn the_content_type_is_compared_before_any_parameter() {
    let typed = |value: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(value).expect("value"));
        register::is_json(&headers)
    };
    assert!(typed("application/json"));
    assert!(typed("Application/JSON; charset=utf-8"));
    assert!(typed("application/json;charset=utf-8"));
    assert!(!typed("text/plain"));
    assert!(!typed("application/jsonx"));
    assert!(!typed("application/x-www-form-urlencoded"));
    assert!(
        !register::is_json(&HeaderMap::new()),
        "no content type is refused"
    );
}

#[test]
fn only_a_json_object_is_a_registration_body() {
    assert!(register::parse_object(b"this is not json").is_none());
    assert!(register::parse_object(b"[]").is_none());
    assert!(register::parse_object(b"\"text\"").is_none());
    assert!(register::parse_object(b"{}").is_some());
}

// ---- Registration: storage ----

fn valid_body() -> Registration {
    register::check_metadata(&metadata(
        r#"{"client_name":"X","redirect_uris":["http://localhost:8787/callback"]}"#,
    ))
    .expect("valid")
}

fn create(conn: &mut Connection, address: &str, limit: i64, now: i64) -> Decision {
    register::register_in(conn, address, limit, now, Ok(valid_body())).expect("register")
}

fn client_ids(conn: &Connection) -> Vec<String> {
    let mut statement = conn
        .prepare("SELECT client_id FROM oauth_clients ORDER BY client_id")
        .expect("prepare");
    statement
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

fn attempt_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM dcr_attempts", [], |row| row.get(0))
        .expect("count")
}

#[test]
fn a_created_registration_is_a_public_client_with_no_secret() {
    let (_dir, mut conn) = open();
    let Decision::Created(body) = create(&mut conn, "addr-a", 5, NOW) else {
        panic!("a valid registration must be created");
    };
    let client_id = body["client_id"].as_str().expect("client id");
    assert!(client_id.starts_with("dcr_"), "the id starts with dcr_");
    assert_eq!(client_id.len(), 4 + 43, "the id is dcr_ and 43 characters");
    assert_eq!(body["client_id_issued_at"], json!(NOW));
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(
        body["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(body["response_types"], json!(["code"]));
    assert_eq!(
        body["redirect_uris"],
        json!(["http://localhost:8787/callback"])
    );
    assert_eq!(body["client_name"], "X");
    assert!(
        body.get("client_secret").is_none(),
        "no secret is ever issued"
    );
}

#[test]
fn an_unused_registration_is_gone_after_seven_days_and_one_second() {
    let (_dir, mut conn) = open();
    let Decision::Created(old) = create(&mut conn, "addr-a", 100, NOW) else {
        panic!("created");
    };
    let old_id = old["client_id"].as_str().expect("id").to_owned();
    create(&mut conn, "addr-a", 100, NOW + WEEK);
    assert!(
        client_ids(&conn).contains(&old_id),
        "exactly seven days old is kept"
    );
    create(&mut conn, "addr-a", 100, NOW + WEEK + 1);
    assert!(
        !client_ids(&conn).contains(&old_id),
        "seven days and one second old is deleted"
    );
}

#[test]
fn a_used_registration_is_kept_whatever_its_age() {
    let (_dir, mut conn) = open();
    let Decision::Created(old) = create(&mut conn, "addr-a", 100, NOW) else {
        panic!("created");
    };
    let old_id = old["client_id"].as_str().expect("id").to_owned();
    conn.execute(
        "UPDATE oauth_clients SET used_at = ?1 WHERE client_id = ?2",
        params![NOW, old_id],
    )
    .expect("mark used");
    create(&mut conn, "addr-a", 100, NOW + 2 * WEEK);
    assert!(
        client_ids(&conn).contains(&old_id),
        "a used registration is kept"
    );
}

#[test]
fn a_refused_registration_uses_up_one_of_the_hourly_attempts() {
    let (_dir, mut conn) = open();
    let refused = register::register_in(&mut conn, "addr-a", 2, NOW, Err(Refusal::RedirectUri))
        .expect("register");
    assert!(matches!(refused, Decision::Refused(Refusal::RedirectUri)));
    assert!(
        client_ids(&conn).is_empty(),
        "a refused registration stores nothing"
    );
    assert!(matches!(
        create(&mut conn, "addr-a", 2, NOW),
        Decision::Created(_)
    ));
    assert!(
        matches!(create(&mut conn, "addr-a", 2, NOW), Decision::Limited),
        "the third attempt within the hour is limited"
    );
    assert_eq!(attempt_count(&conn), 2, "a limited attempt inserts no row");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_over_the_address_limit_waits_an_hour() {
    let dir = tempfile::tempdir().expect("dir");
    let base = gateway(dir.path(), 1).await;
    let http = reqwest::Client::new();
    let url = format!("{base}/oauth/register");
    let good = r#"{"client_name":"Cursor","redirect_uris":["http://localhost:8787/callback"]}"#;
    let created = http
        .post(&url)
        .header("content-type", "application/json")
        .body(good)
        .send()
        .await
        .expect("request");
    assert_eq!(created.status(), 201, "the first registration is created");
    let limited = http
        .post(&url)
        .header("content-type", "application/json")
        .body(good)
        .send()
        .await
        .expect("request");
    assert_eq!(
        limited.status(),
        429,
        "the second is over the address limit"
    );
    assert_eq!(limited.headers()["retry-after"], "3600");
}

#[test]
fn the_total_cap_limits_every_address_together_until_the_hour_passes() {
    let (_dir, mut conn) = open();
    let mut attempt = |address: &str, now: i64| {
        register::register_capped(&mut conn, address, 100, 2, now, Ok(valid_body()))
            .expect("register")
    };
    assert!(matches!(attempt("addr-a", NOW), Decision::Created(_)));
    assert!(matches!(attempt("addr-b", NOW), Decision::Created(_)));
    assert!(
        matches!(attempt("addr-c", NOW), Decision::Limited),
        "the third registration of all addresses within the hour is limited"
    );
    assert!(
        matches!(attempt("addr-c", NOW + HOUR + 1), Decision::Created(_)),
        "after the hour the attempts no longer count"
    );
}

#[test]
fn the_hourly_limit_is_per_address_and_sliding() {
    let (_dir, mut conn) = open();
    assert!(matches!(
        create(&mut conn, "addr-a", 1, NOW),
        Decision::Created(_)
    ));
    assert!(matches!(
        create(&mut conn, "addr-a", 1, NOW + HOUR),
        Decision::Limited
    ));
    assert!(
        matches!(
            create(&mut conn, "addr-b", 1, NOW + HOUR),
            Decision::Created(_)
        ),
        "another address is not limited"
    );
    assert!(
        matches!(
            create(&mut conn, "addr-a", 1, NOW + HOUR + 1),
            Decision::Created(_)
        ),
        "one hour and one second later the address may register again"
    );
}

#[test]
fn the_metadata_documents_are_exactly_the_interface_reference() {
    let base = "https://gateway.example.com";
    assert_eq!(
        authorization_document(base),
        json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "token_endpoint": format!("{base}/oauth/token"),
            "registration_endpoint": format!("{base}/oauth/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "client_id_metadata_document_supported": true,
            "authorization_response_iss_parameter_supported": true,
            "scopes_supported": ["mcp"],
        })
    );
    assert_eq!(
        resource_document(base, "demo"),
        json!({
            "resource": format!("{base}/demo"),
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
        })
    );
}

/// Starts a gateway on a free port in `dir` with the given hourly registration limit.
async fn gateway(dir: &Path, dcr_per_hour: u64) -> String {
    let hasher = PasswordHasher::new().await.expect("hasher");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let base = format!("http://{address}");
    let config = Config {
        public_url: base.clone(),
        listen: address,
        database: dir.join("doorward.db"),
        key_file: None,
        trusted_proxies: Vec::new(),
        shared_client_address: false,
        lifetimes: Default::default(),
        limits: Limits {
            dcr_per_hour,
            ..Default::default()
        },
        mail: Default::default(),
    };
    let gateway = assemble(config, Deps::system(), Arc::new(hasher))
        .await
        .expect("build");
    tokio::spawn(serve(listener, gateway.router, std::future::pending()));
    base
}

#[tokio::test(flavor = "multi_thread")]
async fn every_registration_answer_is_no_store_and_the_limit_counts_refusals() {
    let dir = tempfile::tempdir().expect("dir");
    let base = gateway(dir.path(), 2).await;
    let http = reqwest::Client::new();
    let url = format!("{base}/oauth/register");
    let good = r#"{"client_name":"Cursor","redirect_uris":["http://localhost:8787/callback"]}"#;

    let created = http
        .post(&url)
        .header("content-type", "Application/JSON; charset=utf-8")
        .body(good)
        .send()
        .await
        .expect("request");
    assert_eq!(created.status(), 201, "a JSON registration is created");
    assert_eq!(created.headers()["cache-control"], "no-store");

    let not_json = http
        .post(&url)
        .header("content-type", "text/plain")
        .body(good)
        .send()
        .await
        .expect("request");
    assert_eq!(not_json.status(), 400);
    assert_eq!(not_json.headers()["cache-control"], "no-store");
    let body: Value = not_json.json().await.expect("json");
    assert_eq!(body, json!({"error": "invalid_client_metadata"}));

    let refused = http
        .post(&url)
        .header("content-type", "application/json")
        .body(r#"{"redirect_uris":["https://x.example.com/cb#f"]}"#)
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 400);
    let body: Value = refused.json().await.expect("json");
    assert_eq!(body, json!({"error": "invalid_redirect_uri"}));

    let limited = http
        .post(&url)
        .header("content-type", "application/json")
        .body(good)
        .send()
        .await
        .expect("request");
    assert_eq!(
        limited.status(),
        429,
        "the refused attempt used the second slot"
    );
    assert_eq!(limited.headers()["cache-control"], "no-store");
    let body: Value = limited.json().await.expect("json");
    assert_eq!(
        body,
        json!({"error": "too_many_requests", "error_description": "Too many requests. Try again later."})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_metadata_documents_ignore_the_request_host() {
    let dir = tempfile::tempdir().expect("dir");
    let base = gateway(dir.path(), 20).await;
    let http = reqwest::Client::new();
    let forged = http
        .get(format!("{base}/.well-known/oauth-protected-resource/demo"))
        .header("host", "forged.example.com")
        .header("x-forwarded-host", "forged.example.com")
        .send()
        .await
        .expect("request");
    assert_eq!(forged.status(), 200);
    let body: Value = forged.json().await.expect("json");
    assert_eq!(body, resource_document(&base, "demo"));
    let combined = http
        .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .expect("request");
    assert_eq!(combined.status(), 200, "the combined path has metadata too");
    let reserved = http
        .get(format!("{base}/.well-known/oauth-protected-resource/oauth"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        reserved.status(),
        404,
        "a reserved word that is not mcp is a plain 404"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_registration_body_is_at_most_16_kib() {
    let dir = tempfile::tempdir().expect("dir");
    let base = gateway(dir.path(), 20).await;
    let http = reqwest::Client::new();
    let url = format!("{base}/oauth/register");
    let too_big = json!({
        "redirect_uris": ["http://localhost:8787/callback"],
        "pad": "x".repeat(16 * 1024 + 1),
    })
    .to_string();
    let refused = http
        .post(&url)
        .header("content-type", "application/json")
        .body(too_big)
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 400, "a body over 16 KiB is refused");
    let body: Value = refused.json().await.expect("json");
    assert_eq!(body, json!({"error": "invalid_client_metadata"}));

    let empty_pad = json!({
        "redirect_uris": ["http://localhost:8787/callback"],
        "pad": "",
    })
    .to_string();
    let pad = "x".repeat(16 * 1024 - empty_pad.len());
    let exact = json!({
        "redirect_uris": ["http://localhost:8787/callback"],
        "pad": pad,
    })
    .to_string();
    assert_eq!(
        exact.len(),
        16 * 1024,
        "the boundary body is exactly 16 KiB"
    );
    let created = http
        .post(&url)
        .header("content-type", "application/json")
        .body(exact)
        .send()
        .await
        .expect("request");
    assert_eq!(created.status(), 201, "a body of exactly 16 KiB is read");
}
