//! Panel access rules, mail settings and browser headers, over real HTTP in a temporary directory.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use reqwest::Method;
use reqwest::header::{CONTENT_TYPE, HeaderMap, ORIGIN, SET_COOKIE};
use rusqlite::OptionalExtension;
use scraper::{Html, Selector};
use tokio::net::TcpListener;
use url::form_urlencoded::Serializer;

use crate::app::{Deps, assemble, serve};
use crate::audit::{self, Event};
use crate::config::Config;
use crate::crypto::{Keys, PasswordHasher, token_hash};
use crate::servers::{Scope, set_assignments};
use crate::web::SESSION_COOKIE;

const PASSWORD: &str = "correct horse battery staple";
const OWNER: &str = "owner@example.com";
const PLAIN: &str = "plain@example.com";
const ADMIN: &str = "admin@example.com";
const SECRET: &str = "s3cret-value";
const SECRET_CONTEXT: &str = "settings.value:mail.smtp_password";
const BOB: &str = "bob@example.com";
const NOBODY: &str = "nobody@example.com";

struct Browser {
    http: reqwest::Client,
    base: String,
    cookies: BTreeMap<String, String>,
}

struct Answer {
    status: u16,
    headers: HeaderMap,
    body: String,
}

impl Answer {
    fn location(&self) -> Option<&str> {
        self.headers
            .get("location")
            .and_then(|value| value.to_str().ok())
    }

    fn kind(&self) -> Option<String> {
        attr_of(&self.body, "main", "data-page")
    }

    fn error(&self) -> Option<String> {
        text_of(&self.body, ".error")
    }
}

impl Browser {
    fn new(base: &str) -> Browser {
        Browser {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http client"),
            base: base.to_owned(),
            cookies: BTreeMap::new(),
        }
    }

    async fn get(&mut self, path: &str) -> Answer {
        let request = self.request(Method::GET, path);
        self.answer(request).await
    }

    /// Posts a form with the origin header and the cookies the browser holds.
    async fn post(&mut self, path: &str, fields: &[(&str, &str)]) -> Answer {
        let mut serializer = Serializer::new(String::new());
        serializer.extend_pairs(fields);
        let body = serializer.finish();
        let request = self.request(Method::POST, path).body(body);
        self.answer(request.header(CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .await
    }

    /// GETs `page`, then posts `fields` to `action` with the csrf value that page carries.
    async fn submit(&mut self, page: &str, action: &str, fields: &[(&str, &str)]) -> Answer {
        let form = self.get(page).await;
        let csrf = attr_of(&form.body, r#"input[name="csrf"]"#, "value")
            .unwrap_or_else(|| panic!("{page} has no csrf field (status {})", form.status));
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        self.post(action, &all).await
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header(ORIGIN, self.base.as_str());
        if !self.cookies.is_empty() {
            let header = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header("cookie", header);
        }
        request
    }

    async fn answer(&mut self, request: reqwest::RequestBuilder) -> Answer {
        let response = request.send().await.expect("request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        for value in headers.get_all(SET_COOKIE) {
            if let Ok(line) = value.to_str() {
                self.store_cookie(line);
            }
        }
        let body = response.text().await.expect("body");
        Answer {
            status,
            headers,
            body,
        }
    }

    fn store_cookie(&mut self, line: &str) {
        let (pair, attributes) = line.split_once(';').unwrap_or((line, ""));
        let Some((name, value)) = pair.split_once('=') else {
            return;
        };
        if attributes.to_ascii_lowercase().contains("max-age=0") {
            self.cookies.remove(name.trim());
        } else {
            self.cookies
                .insert(name.trim().to_owned(), value.trim().to_owned());
        }
    }
}

fn attr_of(body: &str, css: &str, attr: &str) -> Option<String> {
    let doc = Html::parse_document(body);
    let selector = Selector::parse(css).expect("selector");
    doc.select(&selector)
        .next()
        .and_then(|element| element.value().attr(attr))
        .map(str::to_owned)
}

fn text_of(body: &str, css: &str) -> Option<String> {
    let doc = Html::parse_document(body);
    let selector = Selector::parse(css).expect("selector");
    doc.select(&selector).next().map(|element| {
        element
            .text()
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn config_in(dir: &Path, base: &str) -> Config {
    let addr = base.trim_start_matches("http://").parse().expect("address");
    Config {
        public_url: base.to_owned(),
        listen: addr,
        database: dir.join("doorward.db"),
        key_file: None,
        trusted_proxies: Vec::new(),
        lifetimes: Default::default(),
        limits: Default::default(),
        mail: Default::default(),
    }
}

/// Starts a gateway on a free port in `dir`; returns its address and the setup code.
async fn start(dir: &Path) -> (String, String) {
    let hasher = PasswordHasher::new().await.expect("hasher");
    start_with(dir, Arc::new(hasher)).await
}

/// Like `start`, with the password hasher the test keeps a handle to.
async fn start_with(dir: &Path, hasher: Arc<PasswordHasher>) -> (String, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let gateway = assemble(config_in(dir, &base), Deps::system(), hasher)
        .await
        .expect("build");
    let code = gateway.setup_code.expect("setup code");
    tokio::spawn(serve(listener, gateway.router, std::future::pending()));
    (base, code)
}

/// Inserts an enabled account directly, so a test can make users of each role.
async fn add_user(dir: &Path, email: &str, role: &str) {
    let hasher = PasswordHasher::new().await.expect("hasher");
    let slot = hasher.try_slot().expect("slot");
    let phc = hasher.hash(slot, PASSWORD.to_owned()).await.expect("hash");
    let conn = rusqlite::Connection::open(dir.join("doorward.db")).expect("open");
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![email, phc, role],
    )
    .expect("insert user");
}

async fn sign_in(base: &str, email: &str) -> Browser {
    let mut browser = Browser::new(base);
    let page = browser
        .submit(
            "/login",
            "/login",
            &[("email", email), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(page.status, 303, "{email} must sign in");
    browser
}

/// The raw value of one settings row, read directly from the database.
fn stored(dir: &Path, key: &str) -> Option<Vec<u8>> {
    let conn = rusqlite::Connection::open(dir.join("doorward.db")).expect("open");
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .optional()
    .expect("settings query")
}

fn stored_text(dir: &Path, key: &str) -> Option<String> {
    stored(dir, key).map(|bytes| String::from_utf8(bytes).expect("utf-8"))
}

fn smtp_fields<'a>(host: &'a str, password: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("provider", "smtp"),
        ("from", "gateway@example.com"),
        ("smtp_host", host),
        ("smtp_port", "587"),
        ("smtp_username", "mailer"),
        ("smtp_password", password),
        ("smtp_tls", "starttls"),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn panel_and_mail_refuse_anonymous_and_plain_users() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, code) = start(dir.path()).await;
    let mut owner = Browser::new(&base);
    let setup = owner
        .submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", &code),
                ("email", OWNER),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(setup.status, 303, "the owner must be created");
    add_user(dir.path(), PLAIN, "user").await;
    add_user(dir.path(), ADMIN, "admin").await;

    let mut anon = Browser::new(&base);
    for path in ["/admin", "/admin/mail"] {
        let page = anon.get(path).await;
        assert_eq!(page.status, 303, "anonymous {path} must redirect");
        assert_eq!(
            page.location(),
            Some("/login"),
            "anonymous {path} goes to /login"
        );
    }
    let missing = anon.get("/admin/nothing-here").await;
    assert_eq!(
        missing.status, 404,
        "an unknown admin path must be a plain 404"
    );
    assert_eq!(
        missing.kind(),
        None,
        "an unknown admin path has no page kind"
    );

    let mut plain = sign_in(&base, PLAIN).await;
    let page = plain.get("/admin").await;
    assert_eq!(page.status, 403, "a user must be refused the panel");
    assert_eq!(page.kind().as_deref(), Some("forbidden"));
    let page = plain.get("/admin/mail").await;
    assert_eq!(page.status, 403, "a user must be refused the mail page");

    let mut admin = sign_in(&base, ADMIN).await;
    let page = admin.get("/admin").await;
    assert_eq!(page.status, 200, "an admin must reach the panel");
    assert_eq!(page.kind().as_deref(), Some("admin"));
    let page = admin.get("/admin/mail").await;
    assert_eq!(page.status, 403, "an admin must be refused the mail page");
    let page = admin.post("/admin/mail", &[("provider", "smtp")]).await;
    assert_eq!(
        page.status, 403,
        "an admin must be refused posting mail settings"
    );

    let page = owner.get("/admin/mail").await;
    assert_eq!(page.status, 200, "the owner must reach the mail page");
    assert_eq!(page.kind().as_deref(), Some("mail"));
}

#[tokio::test(flavor = "multi_thread")]
async fn html_pages_carry_the_browser_headers() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    let mut browser = Browser::new(&base);
    let page = browser.get("/login").await;
    let expected = [
        (
            "content-security-policy",
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("cache-control", "no-store"),
        ("referrer-policy", "same-origin"),
    ];
    for (name, value) in expected {
        assert_eq!(
            page.headers.get(name).and_then(|v| v.to_str().ok()),
            Some(value),
            "/login must send {name}"
        );
    }
    let css = browser.get("/assets/doorward.css").await;
    assert_eq!(css.status, 200);
    assert!(
        css.headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/css")),
        "the stylesheet must be text/css"
    );
    assert_eq!(
        css.headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mail_settings_are_checked_and_sealed() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, code) = start(dir.path()).await;
    let mut owner = Browser::new(&base);
    owner
        .submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", &code),
                ("email", OWNER),
                ("password", PASSWORD),
            ],
        )
        .await;

    let bad_port = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "smtp"),
                ("from", "gateway@example.com"),
                ("smtp_host", "smtp.example.com"),
                ("smtp_port", "0"),
                ("smtp_username", "mailer"),
                ("smtp_password", SECRET),
                ("smtp_tls", "starttls"),
            ],
        )
        .await;
    assert_eq!(bad_port.status, 400, "port 0 must be refused");
    assert_eq!(bad_port.kind().as_deref(), Some("mail"));
    assert_eq!(
        bad_port.error().as_deref(),
        Some("The SMTP port must be a number from 1 to 65535.")
    );
    assert_eq!(
        stored_text(dir.path(), "mail.provider"),
        None,
        "nothing may be stored"
    );

    let unknown = owner
        .submit("/admin/mail", "/admin/mail", &[("provider", "ftp")])
        .await;
    assert_eq!(unknown.status, 400, "an unknown provider must be refused");

    let control = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway\u{7}@example.com"),
                ("resend_api_key", "re_key"),
                ("resend_base_url", "https://api.example.com"),
            ],
        )
        .await;
    assert_eq!(control.status, 400, "a control character must be refused");
    assert_eq!(
        control.error().as_deref(),
        Some("A field contains a control character.")
    );

    let bad_tls = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "smtp"),
                ("from", "gateway@example.com"),
                ("smtp_host", "smtp.example.com"),
                ("smtp_port", "587"),
                ("smtp_username", "mailer"),
                ("smtp_password", SECRET),
                ("smtp_tls", "plain"),
            ],
        )
        .await;
    assert_eq!(bad_tls.status, 400, "an unknown TLS mode must be refused");

    let saved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &smtp_fields("smtp.example.com", SECRET),
        )
        .await;
    assert_eq!(saved.status, 303, "valid settings must be stored");
    assert_eq!(saved.location(), Some("/admin/mail"));
    let sealed = stored_text(dir.path(), "mail.smtp_password").expect("sealed secret");
    assert!(sealed.starts_with("v1."), "the secret must be sealed");
    assert!(!sealed.contains(SECRET));
    let config = config_in(dir.path(), &base);
    let keys = Keys::load(&config, None).expect("keys");
    assert_eq!(
        keys.open(SECRET_CONTEXT, &sealed).expect("open"),
        SECRET.as_bytes()
    );

    let page = owner.get("/admin/mail").await;
    assert!(
        !page.body.contains(SECRET) && !page.body.contains(&sealed),
        "a stored secret must never be rendered"
    );

    let kept = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &smtp_fields("smtp.example.com", ""),
        )
        .await;
    assert_eq!(kept.status, 303);
    assert_eq!(
        stored_text(dir.path(), "mail.smtp_password").as_deref(),
        Some(sealed.as_str()),
        "an empty secret keeps the stored one when the server is unchanged"
    );

    let moved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &smtp_fields("other.example.com", ""),
        )
        .await;
    assert_eq!(moved.status, 303);
    assert_eq!(
        stored(dir.path(), "mail.smtp_password"),
        None,
        "an empty secret is dropped when the server changes"
    );

    let resend = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway@example.com"),
                ("resend_api_key", "re_key"),
                ("resend_base_url", "https://api.example.com"),
            ],
        )
        .await;
    assert_eq!(resend.status, 303);
    assert_eq!(
        stored_text(dir.path(), "mail.provider").as_deref(),
        Some("resend")
    );
    assert_eq!(
        stored_text(dir.path(), "mail.smtp_host").as_deref(),
        Some("other.example.com"),
        "another provider's stored values stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_form_body_over_64_kib_is_forbidden() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, code) = start(dir.path()).await;
    let mut owner = Browser::new(&base);
    owner
        .submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", &code),
                ("email", OWNER),
                ("password", PASSWORD),
            ],
        )
        .await;
    let filler = "a".repeat(70 * 1024);
    let form = owner.get("/admin/mail").await;
    let csrf = attr_of(&form.body, r#"input[name="csrf"]"#, "value").expect("csrf");
    let page = owner
        .post(
            "/admin/mail",
            &[
                ("csrf", csrf.as_str()),
                ("provider", "smtp"),
                ("from", "gateway@example.com"),
                ("filler", filler.as_str()),
            ],
        )
        .await;
    assert_eq!(page.status, 403, "an oversized body must be refused");
    assert_eq!(page.kind().as_deref(), Some("forbidden"));
    let page = owner.get("/admin/mail").await;
    assert_eq!(page.status, 200, "the owner's session must still be valid");
}

/// Counted failures: the rows of `login_failures` and the sum of `login_blocks.failures`.
fn throttle_counts(dir: &Path) -> (i64, i64) {
    let conn = rusqlite::Connection::open(dir.join("doorward.db")).expect("open");
    let failures: i64 = conn
        .query_row("SELECT COUNT(*) FROM login_failures", [], |row| row.get(0))
        .expect("failures count");
    let blocked: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(failures), 0) FROM login_blocks",
            [],
            |row| row.get(0),
        )
        .expect("blocks count");
    (failures, blocked)
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_in_again_ends_the_previous_session() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let mut browser = sign_in(&base, OWNER).await;
    let first = browser
        .cookies
        .get(SESSION_COOKIE)
        .cloned()
        .expect("the first sign-in sets a session cookie");

    let again = browser
        .submit(
            "/login",
            "/login",
            &[("email", OWNER), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(again.status, 303, "signing in again must succeed");
    let second = browser
        .cookies
        .get(SESSION_COOKIE)
        .cloned()
        .expect("the second sign-in sets a session cookie");
    assert_ne!(
        first, second,
        "signing in again must issue a new session id"
    );
    assert_eq!(
        browser.get("/account").await.status,
        200,
        "the new session must be signed in"
    );

    browser.cookies.insert(SESSION_COOKIE.to_owned(), first);
    let old = browser.get("/account").await;
    assert_eq!(
        old.status, 303,
        "the previous session must no longer sign in"
    );
    assert_eq!(
        old.location(),
        Some("/login"),
        "a refused session must send the browser to the sign-in page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_free_hash_slot_answers_503_and_counts_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let hasher = Arc::new(PasswordHasher::new().await.expect("hasher"));
    let (base, _) = start_with(dir.path(), Arc::clone(&hasher)).await;
    add_user(dir.path(), OWNER, "owner").await;
    let mut browser = Browser::new(&base);

    let counted = browser
        .submit(
            "/login",
            "/login",
            &[("email", OWNER), ("password", "wrong password")],
        )
        .await;
    assert_eq!(counted.status, 401, "a wrong password must be counted");
    assert_eq!(
        throttle_counts(dir.path()),
        (1, 1),
        "one counted failure must be recorded in both throttle tables"
    );

    let mut held = Vec::new();
    while let Some(slot) = hasher.try_slot() {
        held.push(slot);
    }
    let busy = browser
        .submit(
            "/login",
            "/login",
            &[("email", OWNER), ("password", "wrong password")],
        )
        .await;
    assert_eq!(
        busy.status, 503,
        "a sign-in with no free hash slot must answer 503"
    );
    assert_eq!(
        busy.kind().as_deref(),
        Some("error"),
        "the 503 answer must be the busy page"
    );
    assert_eq!(
        throttle_counts(dir.path()),
        (1, 1),
        "a busy answer must not count a failure"
    );

    drop(held);
    let retried = browser
        .submit(
            "/login",
            "/login",
            &[("email", OWNER), ("password", "wrong password")],
        )
        .await;
    assert_eq!(
        retried.status, 401,
        "once a slot is free the same sign-in must be checked"
    );
    assert_eq!(
        throttle_counts(dir.path()),
        (2, 2),
        "the checked failure must now be counted"
    );
}

/// Each element matching `css`, as its attributes.
fn elements(body: &str, css: &str) -> Vec<BTreeMap<String, String>> {
    let doc = Html::parse_document(body);
    let selector = Selector::parse(css).expect("selector");
    doc.select(&selector)
        .map(|element| {
            element
                .value()
                .attrs()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect()
        })
        .collect()
}

fn open_db(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join("doorward.db")).expect("open")
}

/// Starts a gateway and makes the owner, who is then signed in.
async fn owner_gateway(dir: &Path) -> (String, Browser) {
    let (base, code) = start(dir).await;
    let mut owner = Browser::new(&base);
    let setup = owner
        .submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", &code),
                ("email", OWNER),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(setup.status, 303, "the owner must be created");
    (base, owner)
}

/// (user id, user email, detail) of each row of `kind`, oldest first.
fn rows_of(dir: &Path, kind: &str) -> Vec<(Option<i64>, String, String)> {
    let conn = open_db(dir);
    let mut statement = conn
        .prepare("SELECT user_id, user_email, detail FROM activity WHERE kind = ?1 ORDER BY id")
        .expect("prepare");
    statement
        .query_map([kind], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

const AT: i64 = 1_800_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_row_shows_every_attribute_on_the_activity_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let event = Event {
        kind: "tool_call",
        user_id: Some(7),
        user_email: "bob@example.com",
        server_id: Some(3),
        server_slug: "demo",
        tool: "echo",
        client: "claude-code",
        decision: "allow",
        outcome: "ok",
        detail: "hello",
        duration_ms: Some(42),
    };
    audit::record(&open_db(dir.path()), AT, &event).expect("record");

    let mut owner = sign_in(&base, OWNER).await;
    let page = owner.get("/admin/activity").await;
    assert_eq!(page.status, 200);
    assert_eq!(page.kind().as_deref(), Some("activity"));
    let rows = elements(&page.body, r#"[data-kind="tool_call"]"#);
    assert_eq!(rows.len(), 1, "one row must be shown");
    let row = &rows[0];
    assert_eq!(row["data-kind"], "tool_call");
    assert_eq!(row["data-user"], "bob@example.com");
    assert_eq!(row["data-server"], "demo");
    assert_eq!(row["data-tool"], "echo");
    assert_eq!(row["data-decision"], "allow");
    assert_eq!(row["data-outcome"], "ok");
    assert_eq!(row["data-time"], "2027-01-15T08:00:00Z");
    assert_eq!(row["data-duration-ms"], "42");
    assert!(page.body.contains("hello"), "the detail must be shown");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_row_without_a_duration_has_no_duration_attribute() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let event = Event {
        kind: "admin_change",
        ..Default::default()
    };
    audit::record(&open_db(dir.path()), AT, &event).expect("record");
    let mut owner = sign_in(&base, OWNER).await;
    let rows = elements(
        &owner.get("/admin/activity").await.body,
        r#"[data-kind="admin_change"]"#,
    );
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].contains_key("data-duration-ms"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_activity_page_filters_by_user_and_by_server() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let conn = open_db(dir.path());
    let rows = [
        (Some(1), "alice@example.com", Some(10), "alpha"),
        (Some(2), "bob@example.com", Some(10), "alpha"),
        (Some(1), "alice@example.com", Some(20), "beta"),
    ];
    for (offset, (user_id, user_email, server_id, server_slug)) in rows.iter().enumerate() {
        let event = Event {
            kind: "tool_call",
            user_id: *user_id,
            user_email,
            server_id: *server_id,
            server_slug,
            ..Default::default()
        };
        audit::record(&conn, AT + offset as i64, &event).expect("record");
    }
    let mut owner = sign_in(&base, OWNER).await;

    let tool_calls = r#"[data-kind="tool_call"]"#;
    let all = elements(&owner.get("/admin/activity").await.body, tool_calls);
    assert_eq!(all.len(), 3, "no filter shows every row");
    let by_user = elements(&owner.get("/admin/activity?user=1").await.body, tool_calls);
    assert_eq!(by_user.len(), 2, "user 1 has two rows");
    assert!(
        by_user
            .iter()
            .all(|row| row["data-user"] == "alice@example.com")
    );
    let by_server = elements(
        &owner.get("/admin/activity?server=20").await.body,
        tool_calls,
    );
    assert_eq!(by_server.len(), 1, "server 20 has one row");
    assert_eq!(by_server[0]["data-server"], "beta");
    let both = elements(
        &owner.get("/admin/activity?user=1&server=10").await.body,
        tool_calls,
    );
    assert_eq!(both.len(), 1, "user 1 on server 10 has one row");
    let not_a_number = elements(
        &owner.get("/admin/activity?user=alice").await.body,
        tool_calls,
    );
    assert!(
        not_a_number.is_empty(),
        "a value that is not a number means no rows"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_newest_row_comes_first() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let conn = open_db(dir.path());
    for (at, detail) in [(AT, "older"), (AT + 60, "newer")] {
        let event = Event {
            kind: "admin_change",
            detail,
            ..Default::default()
        };
        audit::record(&conn, at, &event).expect("record");
    }
    let mut owner = sign_in(&base, OWNER).await;
    let rows = elements(
        &owner.get("/admin/activity").await.body,
        r#"[data-kind="admin_change"]"#,
    );
    let times: Vec<&str> = rows.iter().map(|row| row["data-time"].as_str()).collect();
    assert_eq!(times, ["2027-01-15T08:01:00Z", "2027-01-15T08:00:00Z"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_detail_is_stored_cut_to_500_characters() {
    let dir = tempfile::tempdir().expect("dir");
    let _ = start(dir.path()).await;
    let conn = open_db(dir.path());
    let long = "é".repeat(600);
    let event = Event {
        kind: "login",
        detail: &long,
        ..Default::default()
    };
    audit::record(&conn, AT, &event).expect("record");
    let stored: String = conn
        .query_row("SELECT detail FROM activity", [], |row| row.get(0))
        .expect("stored detail");
    assert_eq!(stored.chars().count(), 500);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_detail_with_markup_is_escaped_on_the_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let event = Event {
        kind: "login",
        detail: "<b>x</b>",
        ..Default::default()
    };
    audit::record(&open_db(dir.path()), AT, &event).expect("record");
    let mut owner = sign_in(&base, OWNER).await;
    let page = owner.get("/admin/activity").await;
    assert!(
        page.body.contains("&lt;b&gt;x&lt;/b&gt;"),
        "the detail must be escaped"
    );
    assert!(
        !page.body.contains("<b>x</b>"),
        "no raw markup may be shown"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_activity_page_is_for_the_owner_and_admins_only() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    add_user(dir.path(), PLAIN, "user").await;
    add_user(dir.path(), ADMIN, "admin").await;

    let page = Browser::new(&base).get("/admin/activity").await;
    assert_eq!(page.status, 303, "anonymous visitors are sent to sign in");
    assert_eq!(page.location(), Some("/login"));

    let mut plain = sign_in(&base, PLAIN).await;
    let page = plain.get("/admin/activity").await;
    assert_eq!(page.status, 403, "a plain user is refused");
    assert_eq!(page.kind().as_deref(), Some("forbidden"));

    let mut admin = sign_in(&base, ADMIN).await;
    let page = admin.get("/admin/activity").await;
    assert_eq!(page.status, 200, "an admin reads the activity page");
    assert_eq!(page.kind().as_deref(), Some("activity"));
    let panel = admin.get("/admin").await;
    assert!(
        panel.body.contains(r#"href="/admin/activity""#),
        "the panel links to the activity page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_sign_in_writes_one_login_row() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let signed = login(&base, OWNER, PASSWORD).await;
    assert_eq!(signed.status, 303, "the right password must sign in");
    let rows = rows_of(dir.path(), "login");
    assert_eq!(rows.len(), 1, "one login row must be written");
    assert_eq!(rows[0].1, OWNER);
    assert!(rows[0].0.is_some(), "the login row must carry the user id");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_writes_one_login_failed_row_with_the_email() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let refused = login(&base, OWNER, "wrong password entirely").await;
    assert_eq!(refused.status, 401);
    let rows = rows_of(dir.path(), "login_failed");
    assert_eq!(rows.len(), 1, "one failed row must be written");
    assert!(rows[0].0.is_some(), "an existing account keeps its user id");
    assert_eq!(rows[0].1, OWNER);
    assert_eq!(rows[0].2, "", "the detail is empty for an existing account");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_address_writes_a_login_failed_row_without_the_email() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let typed = "nobody-typed-this-password";
    let refused = login(&base, "nobody@example.com", typed).await;
    assert_eq!(refused.status, 401);
    let rows = rows_of(dir.path(), "login_failed");
    assert_eq!(rows.len(), 1, "one failed row must be written");
    assert_eq!(rows[0].0, None, "no account, no user id");
    assert_eq!(rows[0].1, "", "the typed address is never stored");
    assert_eq!(rows[0].2, "unknown address");
    let stored: String = open_db(dir.path())
        .query_row(
            "SELECT group_concat(user_email || detail) FROM activity",
            [],
            |row| row.get(0),
        )
        .expect("activity text");
    assert!(
        !stored.contains(typed),
        "the typed password is never stored"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_sign_in_writes_no_row() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let mut browser = Browser::new(&base);
    for _ in 0..5 {
        let refused = browser
            .submit(
                "/login",
                "/login",
                &[("email", OWNER), ("password", "wrong password entirely")],
            )
            .await;
        assert_eq!(refused.status, 401);
    }
    let blocked = browser
        .submit(
            "/login",
            "/login",
            &[("email", OWNER), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(blocked.status, 429, "the account is blocked");
    assert_eq!(
        rows_of(dir.path(), "login_failed").len(),
        5,
        "the five counted failures are logged and the blocked attempt is not"
    );
    assert!(
        rows_of(dir.path(), "login").is_empty(),
        "no sign-in was made"
    );
}

/// Posts the sign-in form from a fresh browser.
async fn login(base: &str, email: &str, password: &str) -> Answer {
    let mut browser = Browser::new(base);
    browser
        .submit(
            "/login",
            "/login",
            &[("email", email), ("password", password)],
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_send_with_no_provider_is_shown_and_logged() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/mail",
            "/admin/mail/test",
            &[("to", "probe@example.com")],
        )
        .await;
    assert_eq!(page.status, 200);
    assert_eq!(page.kind().as_deref(), Some("mail"));
    assert_eq!(page.error().as_deref(), Some("Mail is not set up."));
    let rows = rows_of(dir.path(), "mail_failed");
    assert_eq!(rows.len(), 1, "one mail_failed row must be written");
    assert_eq!(rows[0].2, "Mail is not set up.");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_test_address_is_refused_with_the_mail_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/mail",
            "/admin/mail/test",
            &[("to", "not-an-address")],
        )
        .await;
    assert_eq!(page.status, 400);
    assert_eq!(page.kind().as_deref(), Some("mail"));
    assert_eq!(
        page.error().as_deref(),
        Some("Enter a valid email address.")
    );
    assert!(
        rows_of(dir.path(), "mail_failed").is_empty(),
        "nothing was sent"
    );
}

/// A local listener that answers every request with 500 and an empty body.
async fn failing_provider() -> String {
    let app = axum::Router::new().fallback(|| async { StatusCode::INTERNAL_SERVER_ERROR });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    base
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_http_send_never_shows_the_key() {
    const KEY: &str = "re_key_must_not_leak_8d1f";
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let provider = failing_provider().await;
    let saved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway@example.com"),
                ("resend_api_key", KEY),
                ("resend_base_url", provider.as_str()),
            ],
        )
        .await;
    assert_eq!(saved.status, 303);
    let page = owner
        .submit(
            "/admin/mail",
            "/admin/mail/test",
            &[("to", "probe@example.com")],
        )
        .await;
    assert_eq!(page.status, 200);
    let error = page.error().expect("the failure must be shown");
    assert_eq!(error, "Resend answered 500");
    assert!(!page.body.contains(KEY), "the page must not show the key");
    let logged = rows_of(dir.path(), "mail_failed");
    assert_eq!(logged.len(), 1);
    assert!(!logged[0].2.contains(KEY), "the log must not hold the key");
}

/// A listener that accepts connections and never answers them.
async fn silent_provider() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    base
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_never_answers_is_timed_out() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let silent = silent_provider().await;
    let saved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway@example.com"),
                ("resend_api_key", "re_key"),
                ("resend_base_url", silent.as_str()),
            ],
        )
        .await;
    assert_eq!(saved.status, 303);
    let page = owner
        .submit(
            "/admin/mail",
            "/admin/mail/test",
            &[("to", "probe@example.com")],
        )
        .await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.error().as_deref(),
        Some("The mail server did not answer in time.")
    );
    let logged = rows_of(dir.path(), "mail_failed");
    assert_eq!(logged.len(), 1, "the timed out send must be logged");
    assert_eq!(logged[0].2, "The mail server did not answer in time.");
}

/// A local listener that answers every request with 500 and a 1 MiB body.
async fn oversized_provider() -> String {
    let body = "x".repeat(1024 * 1024);
    let app = axum::Router::new().fallback(move || {
        let body = body.clone();
        async move { (StatusCode::INTERNAL_SERVER_ERROR, body) }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    base
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_answer_of_one_mebibyte_is_shown_within_300_characters() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let provider = oversized_provider().await;
    let saved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "mailgun"),
                ("from", "gateway@example.com"),
                ("mailgun_api_key", "key-test"),
                ("mailgun_domain", "mg.example.com"),
                ("mailgun_base_url", provider.as_str()),
            ],
        )
        .await;
    assert_eq!(saved.status, 303);
    let page = owner
        .submit(
            "/admin/mail",
            "/admin/mail/test",
            &[("to", "probe@example.com")],
        )
        .await;
    assert_eq!(page.status, 200);
    let error = page.error().expect("the failure must be shown");
    assert!(!error.is_empty());
    assert!(
        error.chars().count() <= 300,
        "the shown error is {} characters",
        error.chars().count()
    );
    let logged = rows_of(dir.path(), "mail_failed");
    assert_eq!(logged.len(), 1);
    assert!(logged[0].2.chars().count() <= 300);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_base_address_with_credentials_is_never_shown_or_logged() {
    const CREDENTIAL: &str = "hunter2secret";
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let base = format!("http://user:{CREDENTIAL}@127.0.0.1:9");
    let saved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[
                ("provider", "resend"),
                ("from", "gateway@example.com"),
                ("resend_api_key", "re_key"),
                ("resend_base_url", base.as_str()),
            ],
        )
        .await;
    assert_eq!(saved.status, 303);
    let page = owner
        .submit(
            "/admin/mail",
            "/admin/mail/test",
            &[("to", "probe@example.com")],
        )
        .await;
    assert_eq!(page.status, 200);
    let error = page.error().expect("the failure must be shown");
    assert!(!error.is_empty());
    assert!(
        !error.contains(CREDENTIAL),
        "the error must not show the credential"
    );
    let logged = rows_of(dir.path(), "mail_failed");
    assert_eq!(logged.len(), 1, "the failed send must be logged");
    assert!(
        !logged[0].2.contains(CREDENTIAL),
        "the log must not hold the credential"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_mail_settings_writes_one_admin_change_row() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let saved = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &smtp_fields("smtp.example.com", SECRET),
        )
        .await;
    assert_eq!(saved.status, 303);
    let rows = rows_of(dir.path(), "admin_change");
    assert_eq!(rows.len(), 1, "one admin_change row must be written");
    assert_eq!(rows[0].1, OWNER);
    assert_eq!(rows[0].2, "mail settings");
}

fn count(dir: &Path, sql: &str) -> i64 {
    open_db(dir)
        .query_row(sql, [], |row| row.get(0))
        .expect("count query")
}

fn user_id_of(dir: &Path, email: &str) -> i64 {
    open_db(dir)
        .query_row("SELECT id FROM users WHERE email = ?1", [email], |row| {
            row.get(0)
        })
        .expect("the user exists")
}

/// Stores an open reset row for `email` with a known token, as a mailed link would have.
fn insert_reset(dir: &Path, email: &str, token: &str) {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    open_db(dir)
        .execute(
            "INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![user_id_of(dir, email), token_hash(token), now, now + 3600],
        )
        .expect("insert reset");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_token_never_reaches_the_invitations_or_activity_pages() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    assert_eq!(page.kind().as_deref(), Some("invitation-created"));
    let link = attr_of(&page.body, "[data-invite-link]", "data-invite-link")
        .expect("the failed send must show the link");
    assert!(
        link.contains("/invite/dw_iv_"),
        "the link must hold a token"
    );
    let invitations = owner.get("/admin/invitations").await;
    assert_eq!(invitations.status, 200);
    assert!(
        !invitations.body.contains("dw_iv_"),
        "the invitations page must not show a token"
    );
    let activity = owner.get("/admin/activity").await;
    assert!(
        !activity.body.contains("dw_iv_"),
        "the activity page must not show a token"
    );
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM invitations"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_owner_is_offered_the_admin_role_in_the_invitation_form() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    let values = |page: &Answer| -> Vec<String> {
        elements(&page.body, r#"select[name="role"] option"#)
            .iter()
            .map(|option| option["value"].clone())
            .collect()
    };
    assert_eq!(
        values(&owner.get("/admin/invitations").await),
        ["user", "admin"],
        "the owner must be offered both roles"
    );
    assert_eq!(
        values(&admin.get("/admin/invitations").await),
        ["user"],
        "an admin must not be offered the admin role"
    );
}

/// The status each (viewer, target, action) must answer. Only the owner changes roles; the owner
/// is never a target; an admin acts on plain users only.
fn expected_status(viewer_is_owner: bool, target: &str, action: &str) -> u16 {
    if action == "role" {
        return match (viewer_is_owner, target) {
            (false, _) => 403,
            (true, "owner") => 400,
            _ => 303,
        };
    }
    match (viewer_is_owner, target) {
        (_, "owner") => 400,
        (false, "admin") => 403,
        _ => 303,
    }
}

fn action_fields(action: &str) -> Vec<(&str, &str)> {
    if action == "role" {
        vec![("role", "user")]
    } else {
        Vec::new()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_role_and_status_rules_answer_the_table() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    let owner_id = user_id_of(dir.path(), OWNER).to_string();
    let mut cell = 0;
    for (viewer_is_owner, target, action) in rule_cells() {
        cell += 1;
        let target_id = match target {
            "owner" => owner_id.clone(),
            kind => {
                let email = format!("cell{cell}-{kind}@example.com");
                add_user(dir.path(), &email, kind).await;
                user_id_of(dir.path(), &email).to_string()
            }
        };
        let browser = if viewer_is_owner {
            &mut owner
        } else {
            &mut admin
        };
        let page = browser
            .submit(
                "/account",
                &format!("/admin/users/{target_id}/{action}"),
                &action_fields(action),
            )
            .await;
        assert_eq!(
            page.status,
            expected_status(viewer_is_owner, target, action),
            "viewer owner={viewer_is_owner}, target {target}, action {action}"
        );
    }
    for (viewer_is_owner, action, want) in [
        (true, "role", 404),
        (false, "role", 403),
        (true, "disable", 404),
        (false, "disable", 404),
        (true, "delete", 404),
        (false, "delete", 404),
    ] {
        let browser = if viewer_is_owner {
            &mut owner
        } else {
            &mut admin
        };
        let page = browser
            .submit(
                "/account",
                &format!("/admin/users/999999/{action}"),
                &action_fields(action),
            )
            .await;
        assert_eq!(
            page.status, want,
            "an unknown id, viewer owner={viewer_is_owner}, action {action}"
        );
    }
}

/// Every (viewer is owner, target role, action) of the rules, in a fixed order.
fn rule_cells() -> Vec<(bool, &'static str, &'static str)> {
    let mut cells = Vec::new();
    for viewer_is_owner in [true, false] {
        for target in ["owner", "admin", "user"] {
            for action in ["role", "disable", "enable", "delete"] {
                cells.push((viewer_is_owner, target, action));
            }
        }
    }
    cells
}

#[tokio::test(flavor = "multi_thread")]
async fn accepting_after_the_address_got_an_account_creates_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    let link =
        attr_of(&page.body, "[data-invite-link]", "data-invite-link").expect("the invitation link");
    add_user(dir.path(), BOB, "user").await;
    let users = count(dir.path(), "SELECT COUNT(*) FROM users");
    let sessions = count(dir.path(), "SELECT COUNT(*) FROM sessions");
    let path = link
        .strip_prefix(base.as_str())
        .expect("the link is under the base");
    let mut browser = Browser::new(&base);
    let page = browser.submit(path, path, &[("password", PASSWORD)]).await;
    assert_eq!(page.status, 404, "the taken address must refuse the link");
    assert_eq!(page.kind().as_deref(), Some("link-invalid"));
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM users"), users);
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM sessions"), sessions);
    assert_eq!(
        rows_of(dir.path(), "invitation").len(),
        1,
        "only the invitation row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_accepts_of_one_invitation_make_one_user() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    let link =
        attr_of(&page.body, "[data-invite-link]", "data-invite-link").expect("the invitation link");
    let path = link
        .strip_prefix(base.as_str())
        .expect("the link is under the base")
        .to_owned();
    let mut first = Browser::new(&base);
    let mut second = Browser::new(&base);
    let form_a = first.get(&path).await;
    let form_b = second.get(&path).await;
    let csrf_a = attr_of(&form_a.body, r#"input[name="csrf"]"#, "value").expect("csrf");
    let csrf_b = attr_of(&form_b.body, r#"input[name="csrf"]"#, "value").expect("csrf");
    let fields_a = [("csrf", csrf_a.as_str()), ("password", PASSWORD)];
    let fields_b = [("csrf", csrf_b.as_str()), ("password", PASSWORD)];
    let (a, b) = tokio::join!(first.post(&path, &fields_a), second.post(&path, &fields_b));
    let mut statuses = [a.status, b.status];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [303, 404],
        "one accept wins, the other sees no link"
    );
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM users WHERE email = 'bob@example.com'"
        ),
        1,
        "exactly one user is made"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_resets_with_one_link_make_exactly_one_303() {
    const TOKEN: &str = "dw_rs_concurrent-reset-test-token-0123456789";
    const NEW: &str = "a second passphrase here";
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    insert_reset(dir.path(), BOB, TOKEN);
    let path = format!("/reset/{TOKEN}");
    let mut first = Browser::new(&base);
    let mut second = Browser::new(&base);
    let form_a = first.get(&path).await;
    let form_b = second.get(&path).await;
    let csrf_a = attr_of(&form_a.body, r#"input[name="csrf"]"#, "value").expect("csrf");
    let csrf_b = attr_of(&form_b.body, r#"input[name="csrf"]"#, "value").expect("csrf");
    let fields_a = [("csrf", csrf_a.as_str()), ("password", NEW)];
    let fields_b = [("csrf", csrf_b.as_str()), ("password", NEW)];
    let (a, b) = tokio::join!(first.post(&path, &fields_a), second.post(&path, &fields_b));
    let mut statuses = [a.status, b.status];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [303, 404],
        "one reset wins, the other sees no link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn forgot_writes_nothing_for_an_unknown_address_and_one_row_of_each_for_a_known_one() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    let mut browser = Browser::new(&base);
    let known_form = browser
        .submit("/forgot", "/forgot", &[("email", NOBODY)])
        .await;
    assert_eq!(known_form.status, 200);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM password_resets"), 0);
    assert!(
        rows_of(dir.path(), "reset").is_empty(),
        "no reset activity row"
    );

    let known = browser
        .submit("/forgot", "/forgot", &[("email", BOB)])
        .await;
    assert_eq!(known.status, 200);
    assert_eq!(
        known.body, known_form.body,
        "the same answer for both addresses"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while count(dir.path(), "SELECT COUNT(*) FROM password_resets") == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "no reset row within 2 seconds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM password_resets"), 1);
    assert_eq!(
        rows_of(dir.path(), "reset").len(),
        1,
        "one reset activity row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_role_change_is_saved_and_recorded() {
    let dir = tempfile::tempdir().expect("dir");
    let (_, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    let bob_path = format!("/admin/users/{}", user_id_of(dir.path(), BOB));
    let page = owner
        .submit(
            "/account",
            &format!("{bob_path}/role"),
            &[("role", "admin")],
        )
        .await;
    assert_eq!(page.status, 303, "the owner's role change must answer 303");
    assert_eq!(page.location(), Some(bob_path.as_str()));
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM users WHERE email = 'bob@example.com' AND role = 'admin'"
        ),
        1,
        "the role must be stored"
    );
    assert_eq!(rows_of(dir.path(), "admin_change").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_link_of_a_disabled_user_is_refused() {
    const TOKEN: &str = "dw_rs_disabled-user-reset-token-0123456789";
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    insert_reset(dir.path(), BOB, TOKEN);
    let bob_path = format!("/admin/users/{}", user_id_of(dir.path(), BOB));
    let page = owner
        .submit("/account", &format!("{bob_path}/disable"), &[])
        .await;
    assert_eq!(page.status, 303);
    let page = Browser::new(&base).get(&format!("/reset/{TOKEN}")).await;
    assert_eq!(
        page.status, 404,
        "a disabled user's reset link must be refused"
    );
    assert_eq!(page.kind().as_deref(), Some("link-invalid"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_ends_the_other_sessions_and_keeps_this_one() {
    const NEW: &str = "a second passphrase here";
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    let mut changing = sign_in(&base, BOB).await;
    let mut other = sign_in(&base, BOB).await;
    let old_cookie = changing
        .cookies
        .get(SESSION_COOKIE)
        .cloned()
        .expect("the signed-in browser holds a session cookie");

    let changed = changing
        .submit(
            "/account",
            "/account/password",
            &[("current_password", PASSWORD), ("new_password", NEW)],
        )
        .await;
    assert_eq!(changed.status, 303, "the correct change must answer 303");
    assert_eq!(changed.location(), Some("/account"));
    assert_eq!(
        changing.get("/account").await.status,
        200,
        "the browser that changed the password must stay signed in"
    );
    let other_account = other.get("/account").await;
    assert_eq!(other_account.status, 303, "the other session must end");
    assert_eq!(other_account.location(), Some("/login"));

    let mut old = Browser::new(&base);
    old.cookies.insert(SESSION_COOKIE.to_owned(), old_cookie);
    let old_account = old.get("/account").await;
    assert_eq!(old_account.status, 303, "the old session cookie must end");
    assert_eq!(old_account.location(), Some("/login"));

    assert_eq!(
        login(&base, BOB, PASSWORD).await.status,
        401,
        "the old password must no longer sign in"
    );
    assert_eq!(
        login(&base, BOB, NEW).await.status,
        303,
        "the new password must sign in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_ends_every_session_of_the_user() {
    const TOKEN: &str = "dw_rs_every-session-reset-token-0123456789";
    const NEW: &str = "a second passphrase here";
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    let mut signed_in = sign_in(&base, BOB).await;
    insert_reset(dir.path(), BOB, TOKEN);

    let path = format!("/reset/{TOKEN}");
    let mut anonymous = Browser::new(&base);
    let done = anonymous.submit(&path, &path, &[("password", NEW)]).await;
    assert_eq!(done.status, 303, "the reset must complete");
    assert_eq!(done.location(), Some("/login"));

    let account = signed_in.get("/account").await;
    assert_eq!(
        account.status, 303,
        "the reset must end the signed-in session"
    );
    assert_eq!(account.location(), Some("/login"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_invitation_is_gone() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    let link =
        attr_of(&page.body, "[data-invite-link]", "data-invite-link").expect("the invitation link");
    let path = link
        .strip_prefix(base.as_str())
        .expect("the link is under the base")
        .to_owned();
    let listed = owner.get("/admin/invitations").await;
    assert_eq!(
        elements(&listed.body, "[data-invitation-id]").len(),
        1,
        "the invitation must be listed before it is accepted"
    );

    let mut invitee = Browser::new(&base);
    let accepted = invitee
        .submit(&path, &path, &[("password", PASSWORD)])
        .await;
    assert_eq!(accepted.status, 303, "the invitation must be accepted");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitations"),
        0,
        "the accepted invitation row must be gone"
    );
    let after = owner.get("/admin/invitations").await;
    assert_eq!(after.status, 200);
    assert!(
        elements(&after.body, "[data-invitation-id]").is_empty(),
        "the accepted invitation must not be listed"
    );
}

const SERVER_URL: &str = "http://127.0.0.1:9/mcp";
const NEW_URL: &str = "https://mcp.example.com/mcp";
const SECRET_VALUE: &str = "tok-VALUE-7731";

/// A server create case: slug, upstream address, and the optional secret (name, value).
type Case<'a> = (&'a str, &'a str, Option<(&'a str, &'a str)>);
/// An assignment step: the scope, the ids, the pairs it removes and the pairs left after it.
type Step<'a> = (Scope, &'a [i64], Vec<(i64, i64)>, Vec<(i64, i64)>);

/// The fields of a server form named after its slug; the secret pair only when given.
fn server_form<'a>(
    slug: &'a str,
    url: &'a str,
    secret: Option<(&'a str, &'a str)>,
) -> Vec<(&'a str, &'a str)> {
    let mut fields = vec![("name", slug), ("slug", slug), ("upstream_url", url)];
    if let Some((name, value)) = secret {
        fields.push(("secret_header_name", name));
        fields.push(("secret_header_value", value));
    }
    fields
}

/// Posts the create form as the browser.
async fn add(browser: &mut Browser, slug: &str, url: &str, secret: Option<(&str, &str)>) -> Answer {
    browser
        .submit(
            "/admin/servers",
            "/admin/servers",
            &server_form(slug, url, secret),
        )
        .await
}

fn server_id_of(dir: &Path, slug: &str) -> i64 {
    open_db(dir)
        .query_row("SELECT id FROM servers WHERE slug = ?1", [slug], |row| {
            row.get(0)
        })
        .expect("the server exists")
}

/// (secret header name, sealed value) of one server row.
fn secret_row(dir: &Path, id: i64) -> (String, Option<String>) {
    open_db(dir)
        .query_row(
            "SELECT secret_header_name, secret_header_value FROM servers WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the server row")
}

fn lockdown_of(dir: &Path, id: i64) -> String {
    open_db(dir)
        .query_row("SELECT lockdown FROM servers WHERE id = ?1", [id], |row| {
            row.get(0)
        })
        .expect("the server row")
}

fn keys_of(dir: &Path, base: &str) -> Keys {
    Keys::load(&config_in(dir, base), None).expect("keys")
}

/// The plain value that `sealed` holds for row `id`, or None when it does not open for that row.
fn opened(keys: &Keys, id: i64, sealed: &str) -> Option<String> {
    let context = format!("servers.secret_header_value:{id}");
    keys.open(&context, sealed)
        .ok()
        .map(|bytes| String::from_utf8(bytes).expect("utf-8"))
}

/// The bytes of a file in the directory as text; empty when the file does not exist.
fn file_text(dir: &Path, name: &str) -> String {
    std::fs::read(dir.join(name))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// The values of the checked inputs that match `css` on the page.
fn checked_values(body: &str, css: &str) -> Vec<String> {
    elements(body, css)
        .iter()
        .filter_map(|element| element.get("value").cloned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_server_route_refuses_anonymous_and_plain_users() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    assert_eq!(add(&mut owner, "demo", SERVER_URL, None).await.status, 303);
    add_user(dir.path(), PLAIN, "user").await;
    let server = server_id_of(dir.path(), "demo");
    let plain_id = user_id_of(dir.path(), PLAIN);
    let routes = [
        (false, "/admin/servers".to_string()),
        (true, "/admin/servers".to_string()),
        (false, format!("/admin/servers/{server}")),
        (true, format!("/admin/servers/{server}")),
        (true, format!("/admin/servers/{server}/delete")),
        (true, format!("/admin/servers/{server}/users")),
        (true, format!("/admin/servers/{server}/refresh-tools")),
        (true, format!("/admin/users/{plain_id}/servers")),
    ];
    let mut anonymous = Browser::new(&base);
    let mut plain = sign_in(&base, PLAIN).await;
    for (post, path) in &routes {
        let answer = if *post {
            anonymous.post(path, &[]).await
        } else {
            anonymous.get(path).await
        };
        assert_eq!(answer.status, 303, "anonymous {path} must redirect");
        assert_eq!(
            answer.location(),
            Some("/login"),
            "anonymous {path} goes to /login"
        );
        let answer = if *post {
            plain.post(path, &[]).await
        } else {
            plain.get(path).await
        };
        assert_eq!(answer.status, 403, "a plain user must be refused {path}");
        assert_eq!(answer.kind().as_deref(), Some("forbidden"));
    }
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM servers"),
        1,
        "the refused posts must change nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_is_added_listed_and_recorded() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = add(&mut owner, "demo", SERVER_URL, None).await;
    assert_eq!(page.status, 303, "a valid server must be stored");
    let id = server_id_of(dir.path(), "demo");
    assert_eq!(
        page.location(),
        Some(format!("/admin/servers/{id}").as_str())
    );
    let list = owner.get("/admin/servers").await;
    assert_eq!(list.kind().as_deref(), Some("servers"));
    assert_eq!(
        attr_of(&list.body, r#"[data-slug="demo"]"#, "data-server-id"),
        Some(id.to_string())
    );
    assert_eq!(
        count(
            dir.path(),
            &format!(
                "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change' \
                 AND detail = 'added server demo' AND server_id = {id} AND server_slug = 'demo'"
            )
        ),
        1,
        "adding a server writes one admin_change row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_create_form_refuses_each_bad_field_and_stores_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let control = "x\u{1}";
    let cases: [Case; 9] = [
        ("Bad", SERVER_URL, None),
        ("admin", SERVER_URL, None),
        ("demo", "ftp://example.com/", None),
        ("demo", "https://example.com/mcp#x", None),
        ("demo", SERVER_URL, Some(("", "v"))),
        ("demo", SERVER_URL, Some(("x y", "v"))),
        ("demo", SERVER_URL, Some(("host", "v"))),
        ("demo", SERVER_URL, Some(("x-key", "tab\there"))),
        ("demo", SERVER_URL, Some(("x-key", control))),
    ];
    for (slug, url, secret) in cases {
        let page = add(&mut owner, slug, url, secret).await;
        assert_eq!(page.status, 400, "{slug} {url} {secret:?} must be refused");
        assert_eq!(page.kind().as_deref(), Some("servers"));
        assert!(page.error().is_some(), "the refusal must name the field");
    }
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM servers"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taken_slug_is_refused_by_the_unique_rule() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    assert_eq!(add(&mut owner, "demo", SERVER_URL, None).await.status, 303);
    let again = add(&mut owner, "demo", NEW_URL, None).await;
    assert_eq!(again.status, 400, "a second server on demo must be refused");
    assert_eq!(again.kind().as_deref(), Some("servers"));
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM servers WHERE slug = 'demo'"
        ),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_creates_with_one_slug_make_one_row() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _owner) = owner_gateway(dir.path()).await;
    let mut first = sign_in(&base, OWNER).await;
    let mut second = sign_in(&base, OWNER).await;
    let (a, b) = tokio::join!(
        add(&mut first, "twin", SERVER_URL, None),
        add(&mut second, "twin", SERVER_URL, None)
    );
    let mut statuses = [a.status, b.status];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [303, 400],
        "one create wins, the other is refused"
    );
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM servers WHERE slug = 'twin'"
        ),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_value_is_never_shown_and_never_stored_in_clear() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let secret = ("x-upstream-secret", SECRET_VALUE);
    assert_eq!(
        add(&mut owner, "demo", SERVER_URL, Some(secret))
            .await
            .status,
        303
    );
    let id = server_id_of(dir.path(), "demo");
    let page = owner.get(&format!("/admin/servers/{id}")).await;
    assert_eq!(page.status, 200);
    assert_eq!(page.kind().as_deref(), Some("server"));
    assert!(
        page.body.contains("A secret is stored"),
        "a stored secret is noted"
    );
    assert!(
        !page.body.contains(SECRET_VALUE),
        "the server page holds no value"
    );
    let list = owner.get("/admin/servers").await;
    assert!(!list.body.contains(SECRET_VALUE), "the list holds no value");
    let activity = owner.get("/admin/activity").await;
    assert!(
        !activity.body.contains(SECRET_VALUE),
        "the activity page holds no value"
    );
    for name in ["doorward.db", "doorward.db-wal"] {
        assert!(
            !file_text(dir.path(), name).contains(SECRET_VALUE),
            "{name} must not hold the value in clear"
        );
    }
    let (_, sealed) = secret_row(dir.path(), id);
    assert!(
        sealed.is_some_and(|text| text.starts_with("v1.")),
        "the value is sealed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sealed_secret_opens_only_for_its_own_row() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(
        &mut owner,
        "alpha",
        SERVER_URL,
        Some(("x-key", "alpha-VALUE")),
    )
    .await;
    add(
        &mut owner,
        "beta",
        SERVER_URL,
        Some(("x-key", "beta-VALUE")),
    )
    .await;
    let alpha = server_id_of(dir.path(), "alpha");
    let beta = server_id_of(dir.path(), "beta");
    let (_, sealed) = secret_row(dir.path(), alpha);
    let sealed = sealed.expect("alpha holds a secret");
    let keys = keys_of(dir.path(), &base);
    assert_eq!(
        opened(&keys, alpha, &sealed).as_deref(),
        Some("alpha-VALUE")
    );
    assert_eq!(
        opened(&keys, beta, &sealed),
        None,
        "a copy under another row id must not open"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_zero_value_is_a_secret_and_a_header_name_is_stored_in_lower_case() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("Authorization", "0"))).await;
    let id = server_id_of(dir.path(), "demo");
    let (name, sealed) = secret_row(dir.path(), id);
    assert_eq!(name, "authorization");
    let sealed = sealed.expect("a value of 0 is stored");
    assert_eq!(
        opened(&keys_of(dir.path(), &base), id, &sealed).as_deref(),
        Some("0")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_address_with_an_empty_value_deletes_the_stored_secret() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("x-key", "old-VALUE"))).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let page = owner
        .submit(&path, &path, &server_form("demo", NEW_URL, None))
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(secret_row(dir.path(), id), (String::new(), None));
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_the_address_with_a_new_value_keeps_the_new_one() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("x-key", "old-VALUE"))).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let page = owner
        .submit(
            &path,
            &path,
            &server_form("demo", NEW_URL, Some(("X-Other", "new-VALUE"))),
        )
        .await;
    assert_eq!(page.status, 303);
    let (name, sealed) = secret_row(dir.path(), id);
    assert_eq!(name, "x-other");
    let sealed = sealed.expect("the new value is stored");
    assert_eq!(
        opened(&keys_of(dir.path(), &base), id, &sealed).as_deref(),
        Some("new-VALUE")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_address_keeps_the_old_secret_whatever_the_posted_name() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(
        &mut owner,
        "demo",
        SERVER_URL,
        Some(("Authorization", "old-VALUE")),
    )
    .await;
    let id = server_id_of(dir.path(), "demo");
    let before = secret_row(dir.path(), id);
    let path = format!("/admin/servers/{id}");
    let missing = owner
        .submit(&path, &path, &server_form("demo", SERVER_URL, None))
        .await;
    assert_eq!(
        missing.status, 303,
        "no secret fields posted keeps the secret"
    );
    let refused_name = owner
        .submit(
            &path,
            &path,
            &server_form("demo", SERVER_URL, Some(("x y", ""))),
        )
        .await;
    assert_eq!(
        refused_name.status, 303,
        "an empty value keeps it whatever the name"
    );
    assert_eq!(
        secret_row(dir.path(), id),
        before,
        "the stored row is unchanged"
    );
    let sealed = before.1.expect("a secret is stored");
    assert_eq!(
        opened(&keys_of(dir.path(), &base), id, &sealed).as_deref(),
        Some("old-VALUE")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_secret_deletes_the_stored_secret() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("x-key", "old-VALUE"))).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let mut fields = server_form("demo", SERVER_URL, None);
    fields.push(("remove_secret", "on"));
    assert_eq!(owner.submit(&path, &path, &fields).await.status, 303);
    assert_eq!(secret_row(dir.path(), id), (String::new(), None));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_address_sets_the_lockdown_back_to_unknown() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let id = server_id_of(dir.path(), "demo");
    open_db(dir.path())
        .execute("UPDATE servers SET lockdown = 'ok' WHERE id = ?1", [id])
        .expect("set lockdown");
    let path = format!("/admin/servers/{id}");
    owner
        .submit(&path, &path, &server_form("demo", SERVER_URL, None))
        .await;
    assert_eq!(
        lockdown_of(dir.path(), id),
        "ok",
        "an unchanged address keeps it"
    );
    owner
        .submit(&path, &path, &server_form("demo", NEW_URL, None))
        .await;
    assert_eq!(
        lockdown_of(dir.path(), id),
        "unknown",
        "a changed address resets it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_to_a_taken_slug_is_refused_and_changes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    add(&mut owner, "beta", NEW_URL, None).await;
    let beta = server_id_of(dir.path(), "beta");
    let path = format!("/admin/servers/{beta}");
    let page = owner
        .submit(&path, &path, &server_form("alpha", NEW_URL, None))
        .await;
    assert_eq!(page.status, 400);
    assert_eq!(page.kind().as_deref(), Some("server"));
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM servers WHERE id = {beta} AND slug = 'beta'")
        ),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_server_and_user_ids_answer_404() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let plain = owner.get("/admin/servers/999").await;
    assert_eq!(plain.status, 404);
    assert_eq!(plain.kind(), None, "an unknown server is a plain 404");
    assert_eq!(owner.get("/admin/servers/abc").await.status, 404);
    let update = owner
        .submit(
            "/admin/servers",
            "/admin/servers/999",
            &server_form("x", SERVER_URL, None),
        )
        .await;
    assert_eq!(update.status, 404);
    let delete = owner
        .submit("/admin/servers", "/admin/servers/999/delete", &[])
        .await;
    assert_eq!(delete.status, 404);
    let users = owner
        .submit("/admin/servers", "/admin/servers/999/users", &[])
        .await;
    assert_eq!(users.status, 404);
    let servers = owner
        .submit("/admin/servers", "/admin/users/999/servers", &[])
        .await;
    assert_eq!(servers.status, 404);
    let refresh = owner
        .submit("/admin/servers", "/admin/servers/999/refresh-tools", &[])
        .await;
    assert_eq!(refresh.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_tools_answers_303_and_changes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("x-key", "v1"))).await;
    let id = server_id_of(dir.path(), "demo");
    let before = secret_row(dir.path(), id);
    let rows_before = count(dir.path(), "SELECT COUNT(*) FROM activity");
    let path = format!("/admin/servers/{id}");
    let page = owner
        .submit(&path, &format!("{path}/refresh-tools"), &[])
        .await;
    assert_eq!(page.status, 303, "refresh-tools answers 303");
    assert_eq!(page.location(), Some(path.as_str()));
    assert_eq!(secret_row(dir.path(), id), before, "nothing is changed");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM activity"),
        rows_before,
        "no activity row is written"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_server_drops_its_assignments_and_its_id_is_never_reused() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), PLAIN, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let first = server_id_of(dir.path(), "demo");
    let plain_id = user_id_of(dir.path(), PLAIN).to_string();
    let path = format!("/admin/servers/{first}");
    let assigned = owner
        .submit(
            &path,
            &format!("{path}/users"),
            &[("user_id", plain_id.as_str())],
        )
        .await;
    assert_eq!(assigned.status, 303);
    let deleted = owner.submit(&path, &format!("{path}/delete"), &[]).await;
    assert_eq!(deleted.status, 303);
    assert_eq!(deleted.location(), Some("/admin/servers"));
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM user_servers WHERE server_id = {first}")
        ),
        0,
        "the assignments go with the server"
    );
    add(&mut owner, "demo", SERVER_URL, None).await;
    let second = server_id_of(dir.path(), "demo");
    assert!(second > first, "a deleted server id is never reused");
    assert_eq!(
        count(
            dir.path(),
            &format!(
                "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change' \
                 AND detail = 'deleted server demo' AND server_id = {first}"
            )
        ),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn assignments_from_both_pages_refuse_unknown_ids_and_replace_the_set() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), PLAIN, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let server = server_id_of(dir.path(), "demo");
    let plain = user_id_of(dir.path(), PLAIN);
    let server_path = format!("/admin/servers/{server}/users");
    let user_path = format!("/admin/users/{plain}/servers");
    let unknown_user = owner
        .submit(
            &format!("/admin/servers/{server}"),
            &server_path,
            &[("user_id", "999")],
        )
        .await;
    assert_eq!(unknown_user.status, 400, "an unknown user id is refused");
    assert_eq!(unknown_user.kind().as_deref(), Some("server"));
    let zero = owner
        .submit(
            &format!("/admin/servers/{server}"),
            &server_path,
            &[("user_id", "0")],
        )
        .await;
    assert_eq!(zero.status, 400, "the id 0 is no user");
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM user_servers"), 0);

    let assigned = owner
        .submit(
            &format!("/admin/servers/{server}"),
            &server_path,
            &[("user_id", &plain.to_string())],
        )
        .await;
    assert_eq!(assigned.status, 303);
    let server_page = owner.get(&format!("/admin/servers/{server}")).await;
    assert_eq!(
        checked_values(&server_page.body, r#"input[name="user_id"][checked]"#),
        vec![plain.to_string()],
        "the server page shows the user checked"
    );
    let user_page = owner.get(&format!("/admin/users/{plain}")).await;
    assert_eq!(
        checked_values(&user_page.body, r#"input[name="server_id"][checked]"#),
        vec![server.to_string()],
        "the user page shows the server checked"
    );

    let unknown_server = owner
        .submit(
            &format!("/admin/users/{plain}"),
            &user_path,
            &[("server_id", "999")],
        )
        .await;
    assert_eq!(
        unknown_server.status, 400,
        "an unknown server id is refused"
    );
    assert_eq!(unknown_server.kind().as_deref(), Some("user"));
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM user_servers"),
        1,
        "a refused choice changes nothing"
    );

    let cleared = owner
        .submit(&format!("/admin/users/{plain}"), &user_path, &[])
        .await;
    assert_eq!(cleared.status, 303);
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM user_servers"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn set_assignments_replaces_the_set_and_returns_the_removed_pairs_for_both_scopes() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, _owner) = owner_gateway(dir.path()).await;
    for email in [
        "u1@example.com",
        "u2@example.com",
        "u3@example.com",
        "u4@example.com",
    ] {
        add_user(dir.path(), email, "user").await;
    }
    for slug in ["a", "b"] {
        open_db(dir.path())
            .execute(
                "INSERT INTO servers (name, slug, upstream_url, created_at) VALUES (?1, ?1, ?2, 0)",
                [slug, SERVER_URL],
            )
            .expect("insert server");
    }
    let mut conn = open_db(dir.path());
    let pairs = |conn: &rusqlite::Connection| -> Vec<(i64, i64)> {
        let mut statement = conn
            .prepare("SELECT user_id, server_id FROM user_servers ORDER BY user_id, server_id")
            .expect("prepare");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows")
    };
    let steps: [Step; 6] = [
        (Scope::Server(1), &[2, 3], vec![], vec![(2, 1), (3, 1)]),
        (
            Scope::Server(1),
            &[3, 4, 4],
            vec![(2, 1)],
            vec![(3, 1), (4, 1)],
        ),
        (Scope::User(3), &[2], vec![(3, 1)], vec![(3, 2), (4, 1)]),
        (Scope::User(3), &[], vec![(3, 2)], vec![(4, 1)]),
        (Scope::User(4), &[1, 1], vec![], vec![(4, 1)]),
        (Scope::Server(1), &[], vec![(4, 1)], vec![]),
    ];
    for (scope, ids, removed, after) in steps {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("transaction");
        let got = set_assignments(&tx, scope, ids).expect("replace");
        tx.commit().expect("commit");
        assert_eq!(got, removed, "removed pairs for {scope:?} {ids:?}");
        assert_eq!(pairs(&conn), after, "pairs after {scope:?} {ids:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_with_markup_is_escaped_on_the_list_the_server_page_and_the_activity_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let fields = [
        ("name", "<b>Bold</b>"),
        ("slug", "bold"),
        ("upstream_url", SERVER_URL),
    ];
    let page = owner
        .submit("/admin/servers", "/admin/servers", &fields)
        .await;
    assert_eq!(page.status, 303);
    let id = server_id_of(dir.path(), "bold");
    for body in [
        owner.get("/admin/servers").await.body,
        owner.get(&format!("/admin/servers/{id}")).await.body,
    ] {
        assert!(
            !body.contains("<b>Bold</b>"),
            "the name must not be raw markup"
        );
        assert!(
            body.contains("&lt;b&gt;Bold&lt;/b&gt;"),
            "the name is escaped"
        );
    }
    let activity = owner.get("/admin/activity").await;
    assert!(
        !activity.body.contains("<b>"),
        "the activity page shows no raw markup"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_page_carries_the_shared_identity_sentence_and_the_panel_links_to_servers() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let id = server_id_of(dir.path(), "demo");
    let page = owner.get(&format!("/admin/servers/{id}")).await;
    assert_eq!(page.kind().as_deref(), Some("server"));
    assert_eq!(
        attr_of(&page.body, "main", "data-lockdown"),
        Some("unknown".to_string()),
        "the stored lock-down value is on main"
    );
    assert!(page.body.contains(
        "Every user reaches this server under the same identity, so anything the server caches or remembers per caller is shared."
    ));
    let panel = owner.get("/admin").await;
    assert_eq!(
        attr_of(&panel.body, r#"a[href="/admin/servers"]"#, "href"),
        Some("/admin/servers".to_string())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upper_case_address_is_stored_canonically_and_reposted_it_keeps_the_secret() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let created = add(
        &mut owner,
        "demo",
        "https://MCP.Example.com/mcp",
        Some(("x-key", "old-VALUE")),
    )
    .await;
    assert_eq!(created.status, 303);
    let id = server_id_of(dir.path(), "demo");
    let stored: String = open_db(dir.path())
        .query_row(
            "SELECT upstream_url FROM servers WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .expect("the server row");
    assert_eq!(
        stored, "https://mcp.example.com/mcp",
        "the stored text is canonical"
    );
    let before = secret_row(dir.path(), id);
    let path = format!("/admin/servers/{id}");
    let page = owner
        .submit(
            &path,
            &path,
            &server_form("demo", "https://MCP.Example.com/mcp", None),
        )
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(
        secret_row(dir.path(), id),
        before,
        "the address did not change, so the secret is kept"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_redirects_page_refuses_anonymous_and_plain_users() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), PLAIN, "user").await;

    let mut anon = Browser::new(&base);
    let page = anon.get("/admin/redirects").await;
    assert_eq!(page.status, 303, "anonymous visitors are sent to sign in");
    assert_eq!(page.location(), Some("/login"));
    let page = anon.post("/admin/redirects", &[]).await;
    assert_eq!(page.status, 303, "an anonymous add is sent to sign in");

    let mut plain = sign_in(&base, PLAIN).await;
    let page = plain.get("/admin/redirects").await;
    assert_eq!(page.status, 403, "a plain user is refused the page");
    assert_eq!(page.kind().as_deref(), Some("forbidden"));
    let page = plain.post("/admin/redirects/1/disable", &[]).await;
    assert_eq!(page.status, 403, "a plain user is refused a change");

    let page = owner.get("/admin/redirects").await;
    assert_eq!(page.status, 200, "the owner reaches the page");
    assert_eq!(page.kind().as_deref(), Some("redirects"));
    let panel = owner.get("/admin").await;
    assert!(
        panel.body.contains(r#"href="/admin/redirects""#),
        "the panel links to the redirects page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shipped_addresses_are_listed_enabled() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner.get("/admin/redirects").await;
    let rows = elements(&page.body, "li[data-redirect-id]");
    assert_eq!(rows.len(), 5, "the five shipped addresses are listed");
    for (host, listed) in [
        ("claude.ai", 1),
        ("chatgpt.com", 2),
        ("www.cursor.com", 1),
        ("anysphere.cursor-mcp", 1),
    ] {
        let row = elements(&page.body, &format!(r#"li[data-host="{host}"]"#));
        assert_eq!(row.len(), listed, "{host} is listed {listed} time(s)");
        for entry in &row {
            assert_eq!(entry["data-source"], "shipped");
            assert_eq!(entry["data-enabled"], "yes");
        }
    }
    let cursor = elements(&page.body, r#"li[data-scheme="cursor"]"#);
    assert_eq!(cursor[0]["data-source"], "shipped");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_address_is_added_disabled_enabled_again_and_recorded() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let fields = [
        ("scheme", "https"),
        ("host", "app.example.com"),
        ("path_prefix", "/oauth/"),
    ];
    let added = owner
        .submit("/admin/redirects", "/admin/redirects", &fields)
        .await;
    assert_eq!(added.status, 303, "adding an address answers 303");
    assert_eq!(added.location(), Some("/admin/redirects"));
    let page = owner.get("/admin/redirects").await;
    let row = elements(&page.body, r#"li[data-host="app.example.com"]"#);
    assert_eq!(row.len(), 1, "the added address is listed once");
    assert_eq!(row[0]["data-source"], "added");
    assert_eq!(row[0]["data-enabled"], "yes");
    assert_eq!(row[0]["data-path-prefix"], "/oauth/");
    let id = row[0]["data-redirect-id"].clone();

    let disabled = owner
        .submit(
            "/admin/redirects",
            &format!("/admin/redirects/{id}/disable"),
            &[],
        )
        .await;
    assert_eq!(disabled.status, 303, "disabling answers 303");
    let page = owner.get("/admin/redirects").await;
    let row = elements(&page.body, r#"li[data-host="app.example.com"]"#);
    assert_eq!(row[0]["data-enabled"], "no", "the flag is off");

    let again = owner
        .submit("/admin/redirects", "/admin/redirects", &fields)
        .await;
    assert_eq!(again.status, 303);
    let page = owner.get("/admin/redirects").await;
    let row = elements(&page.body, r#"li[data-host="app.example.com"]"#);
    assert_eq!(
        row.len(),
        1,
        "the identical address is enabled, not repeated"
    );
    assert_eq!(row[0]["data-enabled"], "yes");
    assert_eq!(row[0]["data-redirect-id"], id);

    let changes = rows_of(dir.path(), "admin_change");
    assert_eq!(
        changes.len(),
        3,
        "the add, the disable and the add again are recorded"
    );
    assert_eq!(changes[0].1, OWNER);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_address_answers_400_and_stores_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    for fields in [
        [
            ("scheme", "http"),
            ("host", "app.example.com"),
            ("path_prefix", "/x"),
        ],
        [
            ("scheme", "https"),
            ("host", "app.example.com"),
            ("path_prefix", ""),
        ],
        [
            ("scheme", "https"),
            ("host", "127.0.0.1"),
            ("path_prefix", "/x"),
        ],
        [
            ("scheme", "https"),
            ("host", "app.example.com"),
            ("path_prefix", "/a?b"),
        ],
    ] {
        let page = owner
            .submit("/admin/redirects", "/admin/redirects", &fields)
            .await;
        assert_eq!(page.status, 400, "{fields:?} must be refused");
        assert_eq!(page.kind().as_deref(), Some("redirects"));
        assert!(page.error().is_some(), "the refusal is shown on the page");
    }
    let page = owner.get("/admin/redirects").await;
    assert_eq!(
        elements(&page.body, "li[data-redirect-id]").len(),
        5,
        "no refused address is stored"
    );
    assert!(rows_of(dir.path(), "admin_change").is_empty());
}

/// For each blocked attempt, newest first: whether its row offers a one-click allow form.
fn one_click_offers(body: &str) -> Vec<bool> {
    let doc = Html::parse_document(body);
    let rows = Selector::parse("li[data-blocked]").expect("selector");
    let field = Selector::parse(r#"input[name="path_prefix"]"#).expect("selector");
    doc.select(&rows)
        .map(|row| row.select(&field).next().is_some())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_attempt_offers_one_click_allow_only_when_it_may() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let long = format!("https://app.example.com/{}", "a".repeat(600));
    let conn = open_db(dir.path());
    for (client, detail) in [
        ("Good client", "https://app.example.com/oauth/cb"),
        ("Subtree client", "https://app.example.com/oauth/"),
        ("Long client", long.as_str()),
        ("Private client", "evilapp://callback"),
    ] {
        let event = Event {
            kind: "redirect_blocked",
            client,
            detail,
            ..Default::default()
        };
        audit::record(&conn, AT, &event).expect("record");
    }
    let page = owner.get("/admin/redirects").await;
    assert_eq!(
        elements(&page.body, "li[data-blocked]").len(),
        4,
        "every blocked attempt is listed"
    );
    assert!(
        elements(&page.body, "li[data-blocked][data-host]").is_empty(),
        "a blocked row never carries data-host"
    );
    assert!(
        elements(&page.body, "li[data-blocked][data-redirect-id]").is_empty(),
        "a blocked row never carries data-redirect-id"
    );
    assert_eq!(
        one_click_offers(&page.body),
        vec![true, false, false, true],
        "newest first: the private scheme and the plain address are offered; a subtree and a 600 character one are not"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_client_name_is_shown_as_a_claim_and_escaped() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let event = Event {
        kind: "redirect_blocked",
        client: "<b>Claude</b>",
        detail: "https://app.example.com/oauth/cb",
        ..Default::default()
    };
    audit::record(&open_db(dir.path()), AT, &event).expect("record");
    let page = owner.get("/admin/redirects").await;
    assert_eq!(
        text_of(&page.body, "li[data-blocked] p q").as_deref(),
        Some("<b>Claude</b>"),
        "the client name is text inside the q element"
    );
    assert_eq!(
        text_of(&page.body, "li[data-blocked] p").as_deref(),
        Some("Asked by a client that calls itself <b>Claude</b>"),
        "the first line says the name is a claim"
    );
    assert!(
        !page.body.contains("<b>Claude</b>"),
        "the markup of the name is escaped"
    );
}
