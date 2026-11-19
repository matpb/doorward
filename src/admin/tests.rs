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
use crate::crypto::{Keys, PasswordHasher};
use crate::web::SESSION_COOKIE;

const PASSWORD: &str = "correct horse battery staple";
const OWNER: &str = "owner@example.com";
const PLAIN: &str = "plain@example.com";
const ADMIN: &str = "admin@example.com";
const SECRET: &str = "s3cret-value";
const SECRET_CONTEXT: &str = "settings.value:mail.smtp_password";

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
