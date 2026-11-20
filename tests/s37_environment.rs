mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::Path;

use common::binary::{
    Run, free_port, http, lines_containing, required_vars, settings_of, write_file,
};
use doorward::Config;
use doorward::config::{Kind, SETTINGS, Setting};
use doorward::crypto::token_hash;
use doorward::db::Db;
use serde_json::Value;

const SHARED_WARNING: &str = "doorward: shared_client_address is set: every visitor shares one address for sign-in throttling and rate limits";

/// A temp dir with a database in it, and a free loopback port for the gateway.
struct Site {
    dir: tempfile::TempDir,
    port: u16,
    listen: String,
    database: String,
}

impl Site {
    fn new() -> Site {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let listen = format!("127.0.0.1:{port}");
        let database = dir.path().join("doorward.db").display().to_string();
        Site {
            dir,
            port,
            listen,
            database,
        }
    }

    /// The loopback address of the gateway, as a public address.
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The variables that start the gateway of this site with `public_url`.
    fn env<'a>(&'a self, public_url: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("DOORWARD_PUBLIC_URL", public_url),
            ("DOORWARD_LISTEN", self.listen.as_str()),
            ("DOORWARD_DATABASE", self.database.as_str()),
        ]
    }
}

#[test]
fn starts_from_variables_alone() {
    let site = Site::new();
    let url = site.url();
    let mut run = Run::spawn(&[], &site.env(&url));
    run.wait_until_healthy(site.port);
    let stderr = run.stderr();
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("doorward setup code: ")),
        "a fresh start with variables only must print the setup code line; stderr:\n{stderr}"
    );
}

#[test]
fn a_variable_beats_the_file() {
    let site = Site::new();
    let file_port = free_port();
    let text = format!(
        "public_url = \"http://127.0.0.1:{file_port}\"\nlisten = \"127.0.0.1:{file_port}\"\ndatabase = '{}'\n",
        site.database
    );
    let config = write_file(site.dir(), "doorward.toml", &text)
        .display()
        .to_string();
    let mut run = Run::spawn(
        &["--config", config.as_str()],
        &[("DOORWARD_LISTEN", site.listen.as_str())],
    );
    run.wait_until_healthy(site.port);
    let stderr = run.stderr();
    let listening = format!("doorward listening on http://127.0.0.1:{}", site.port);
    assert!(
        stderr.lines().any(|line| line == listening),
        "the variable's port must be the one listened on; stderr:\n{stderr}"
    );
    let file_listening = format!("doorward listening on http://127.0.0.1:{file_port}");
    assert!(
        !stderr.lines().any(|line| line == file_listening),
        "the port named in the file must not be listened on; stderr:\n{stderr}"
    );
}

#[test]
fn an_empty_variable_is_unset() {
    let site = Site::new();
    let url = site.url();
    let text = format!(
        "public_url = \"{url}\"\nlisten = \"{}\"\ndatabase = '{}'\n",
        site.listen, site.database
    );
    let config = write_file(site.dir(), "doorward.toml", &text)
        .display()
        .to_string();
    let mut run = Run::spawn(
        &[],
        &[
            ("DOORWARD_CONFIG", config.as_str()),
            ("DOORWARD_LISTEN", ""),
        ],
    );
    run.wait_until_healthy(site.port);
}

#[test]
fn an_unknown_variable_is_refused_and_named() {
    let site = Site::new();
    let url = site.url();
    let mut env = site.env(&url);
    env.push(("DOORWARD_LIMIT_BODY_BYTES", "1"));
    let outcome = Run::spawn(&[], &env).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "an unknown DOORWARD_ variable must refuse the start with exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.lines().any(|line| line
            == "doorward: unknown setting DOORWARD_LIMIT_BODY_BYTES: see docs/DOCKER.md for the list"),
        "the refusal must name the variable with the exact message; stderr:\n{}",
        outcome.stderr
    );
}

#[test]
fn a_bad_value_is_refused_without_echoing_it() {
    let site = Site::new();
    let url = site.url();
    let mut env = site.env(&url);
    env.push(("DOORWARD_LIMITS_BODY_BYTES", "hunter2-not-a-number"));
    let outcome = Run::spawn(&[], &env).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a value that does not parse must refuse the start with exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .lines()
            .any(|line| line == "doorward: DOORWARD_LIMITS_BODY_BYTES must be a whole number"),
        "the refusal must name the variable and the expected type; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains("hunter2") && !outcome.stderr.contains("hunter2"),
        "the refusal must never echo the value; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

/// The required variables, with `variable` set to `value` (added when it is not one of them).
fn vars_with(variable: &str, value: &str) -> Vec<(String, String)> {
    let mut vars = required_vars();
    match vars.iter_mut().find(|pair| pair.0 == variable) {
        Some(pair) => pair.1 = value.to_owned(),
        None => vars.push((variable.to_owned(), value.to_owned())),
    }
    vars
}

/// A value that is valid for `setting` and differs from its default.
fn valid_value(setting: &Setting, base: &BTreeMap<String, Value>) -> String {
    match setting.kind {
        Kind::Text => "https://other.example.com".to_owned(),
        Kind::Listen => "127.0.0.1:8718".to_owned(),
        Kind::Path => "/srv/doorward/other".to_owned(),
        Kind::Ranges => "127.0.0.1".to_owned(),
        Kind::Bool => "true".to_owned(),
        Kind::Whole => {
            let current = base[setting.path].as_u64().expect("a whole number default");
            (current + 1).to_string()
        }
    }
}

/// A value of the wrong type for `kind`.
fn wrong_value(kind: Kind) -> &'static str {
    match kind {
        Kind::Text => "not a url",
        Kind::Listen => "not an address",
        Kind::Path => "a\u{0}b",
        Kind::Ranges => "not-an-address",
        Kind::Bool => "yes",
        Kind::Whole => "a lot",
    }
}

/// The words the refusal of a wrong-typed value ends with, for `kind`.
fn expected_text(kind: Kind) -> &'static str {
    match kind {
        Kind::Text => "a URL",
        Kind::Listen => "an address and a port",
        Kind::Path => "a path",
        Kind::Ranges => "a comma separated list of addresses or ranges",
        Kind::Bool => "true or false",
        Kind::Whole => "a whole number",
    }
}

#[test]
fn every_setting_has_a_variable() {
    let base = Config::from_sources(None, &required_vars()).expect("the required variables load");
    let leaves = settings_of(&base);
    let fields: BTreeSet<&str> = leaves.keys().map(String::as_str).collect();
    let paths: BTreeSet<&str> = SETTINGS.iter().map(|setting| setting.path).collect();
    assert_eq!(
        paths, fields,
        "SETTINGS must have one row for every field of Config"
    );
    assert_eq!(
        SETTINGS.len(),
        fields.len(),
        "no field of Config may have two rows in SETTINGS"
    );
    for setting in SETTINGS {
        let valid = vars_with(setting.variable, &valid_value(setting, &leaves));
        let config = Config::from_sources(None, &valid).expect("a valid value loads");
        let after = settings_of(&config);
        let changed: Vec<&str> = leaves
            .iter()
            .filter(|(path, value)| after[path.as_str()] != **value)
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(
            changed,
            [setting.path],
            "{} must change exactly the setting {}",
            setting.variable,
            setting.path
        );
        let wrong = vars_with(setting.variable, wrong_value(setting.kind));
        let err = Config::from_sources(None, &wrong).expect_err("a wrong-typed value is refused");
        assert_eq!(
            err.to_string(),
            format!(
                "{} must be {}",
                setting.variable,
                expected_text(setting.kind)
            ),
            "the refusal for {} must name it and the expected type",
            setting.variable
        );
    }
}

#[test]
fn lists_and_booleans_parse() {
    let range = format!("{}/8", Ipv4Addr::new(10, 0, 0, 0));
    let proxies = format!("127.0.0.1, {range}");
    let site = Site::new();
    let mut env = site.env("https://doorward.example.com");
    env.push(("DOORWARD_TRUSTED_PROXIES", proxies.as_str()));
    let mut run = Run::spawn(&[], &env);
    run.wait_until_healthy(site.port);
    let stderr = run.stderr();
    assert!(
        lines_containing(&stderr, "every visitor shares").is_empty(),
        "a list with a proxy in it must start without the shared address warning; stderr:\n{stderr}"
    );

    let site = Site::new();
    let mut env = site.env("https://doorward.example.com");
    env.push(("DOORWARD_SHARED_CLIENT_ADDRESS", "true"));
    let mut run = Run::spawn(&[], &env);
    run.wait_until_healthy(site.port);
    let stderr = run.stderr();
    assert!(
        stderr.lines().any(|line| line == SHARED_WARNING),
        "DOORWARD_SHARED_CLIENT_ADDRESS=true must take effect and log its warning; stderr:\n{stderr}"
    );

    let site = Site::new();
    let url = site.url();
    let mut env = site.env(&url);
    env.push(("DOORWARD_SHARED_CLIENT_ADDRESS", "yes"));
    let outcome = Run::spawn(&[], &env).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "DOORWARD_SHARED_CLIENT_ADDRESS=yes must refuse the start with exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .lines()
            .any(|line| line == "doorward: DOORWARD_SHARED_CLIENT_ADDRESS must be true or false"),
        "the refusal must name the variable and the expected type; stderr:\n{}",
        outcome.stderr
    );
}

#[test]
fn orchestrator_variables_are_ignored() {
    let site = Site::new();
    let url = site.url();
    let mut env = site.env(&url);
    env.push(("DOORWARD_PORT", "arbitrary text"));
    env.push(("DOORWARD_PORT_8717_TCP", "arbitrary text"));
    env.push(("DOORWARD_SERVICE_HOST", "arbitrary text"));
    let mut run = Run::spawn(&[], &env);
    run.wait_until_healthy(site.port);
}

#[test]
fn the_key_never_reaches_the_output() {
    let key = "0123456789abcdef".repeat(4);
    let site = Site::new();
    let url = site.url();
    let mut env = site.env(&url);
    env.push(("DOORWARD_KEY", key.as_str()));
    env.push(("DOORWARD_LIMIT_BODY_BYTES", "1"));
    let outcome = Run::spawn(&[], &env).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "an unknown variable beside the key must refuse the start; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains("unknown setting DOORWARD_LIMIT_BODY_BYTES"),
        "the refusal must name the unknown variable; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains(&key) && !outcome.stderr.contains(&key),
        "the key must never be printed; stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
}

#[test]
fn subcommands_use_the_same_settings() {
    let site = Site::new();
    let url = site.url();
    let env = site.env(&url);
    let mut gateway = Run::spawn(&[], &env);
    gateway.wait_until_healthy(site.port);
    let running = Run::spawn(&["health"], &env).wait_for_exit();
    assert_eq!(
        running.code,
        Some(0),
        "doorward health must exit 0 while the gateway answers; stderr:\n{}",
        running.stderr
    );
    gateway.stop();
    let stopped = Run::spawn(&["health"], &env).wait_for_exit();
    assert_eq!(
        stopped.code,
        Some(1),
        "doorward health must exit 1 once the gateway has stopped; stderr:\n{}",
        stopped.stderr
    );

    let database = Path::new(&site.database);
    Db::open(database).expect("create the database");
    insert_block(database);
    let unlock = Run::spawn(&["unlock", EMAIL], &env).wait_for_exit();
    assert_eq!(
        unlock.code,
        Some(0),
        "doorward unlock must exit 0 with the database given by variable; stderr:\n{}",
        unlock.stderr
    );
    assert_eq!(
        unlock.stdout,
        format!("unlocked {EMAIL}\n"),
        "doorward unlock must print the unlocked line"
    );
    assert_eq!(
        block_count(database),
        0,
        "doorward unlock must remove the login block"
    );
}

/// The account whose login block the unlock test removes.
const EMAIL: &str = "bob@example.com";

/// Puts a login block for `EMAIL` into the database, as tests/cli_unlock.rs does.
fn insert_block(database: &Path) {
    let conn = rusqlite::Connection::open(database).expect("open database");
    conn.execute(
        "INSERT INTO login_blocks (account_hash, failures, last_failed_at) VALUES (?1, 5, 1800000000)",
        [token_hash(EMAIL)],
    )
    .expect("insert block");
}

/// How many login blocks the database holds for `EMAIL`.
fn block_count(database: &Path) -> i64 {
    let conn = rusqlite::Connection::open(database).expect("open database");
    conn.query_row(
        "SELECT COUNT(*) FROM login_blocks WHERE account_hash = ?1",
        [token_hash(EMAIL)],
        |row| row.get(0),
    )
    .expect("count blocks")
}

#[test]
fn health_opens_nothing() {
    let site = Site::new();
    let url = site.url();
    let closed = format!("127.0.0.1:{}", free_port());
    let env = [
        ("DOORWARD_PUBLIC_URL", url.as_str()),
        ("DOORWARD_LISTEN", closed.as_str()),
        ("DOORWARD_DATABASE", site.database.as_str()),
    ];
    let outcome = Run::spawn(&["health"], &env).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(1),
        "doorward health against a closed port must exit 1; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr.lines().count(),
        1,
        "doorward health must print one line on stderr; stderr:\n{}",
        outcome.stderr
    );
    let entries = std::fs::read_dir(site.dir())
        .expect("read the database directory")
        .count();
    assert_eq!(
        entries, 0,
        "doorward health must create nothing in the database directory"
    );
}

#[test]
fn pages_tell_browsers_to_stay_on_https() {
    let site = Site::new();
    let mut env = site.env("https://doorward.example.com");
    env.push(("DOORWARD_TRUSTED_PROXIES", "127.0.0.1"));
    let mut run = Run::spawn(&[], &env);
    run.wait_until_healthy(site.port);
    let page = http(site.port, "GET", "/login", &[], &[]);
    assert_eq!(
        page.header("Strict-Transport-Security"),
        ["max-age=31536000"],
        "a gateway with an https public address must send HSTS on its pages"
    );

    let plain = Site::new();
    let url = plain.url();
    let mut run = Run::spawn(&[], &plain.env(&url));
    run.wait_until_healthy(plain.port);
    for path in ["/login", "/healthz"] {
        let reply = http(plain.port, "GET", path, &[], &[]);
        assert!(
            reply.header("Strict-Transport-Security").is_empty(),
            "{path} on a loopback http gateway must not send Strict-Transport-Security"
        );
    }
}
