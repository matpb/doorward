//! Panel access rules, mail settings and browser headers, over real HTTP in a temporary directory.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use reqwest::Method;
use reqwest::header::{CONTENT_TYPE, HeaderMap, ORIGIN, SET_COOKIE};
use rusqlite::OptionalExtension;
use scraper::{Html, Selector};
use tokio::net::TcpListener;
use url::form_urlencoded::Serializer;

use crate::app::{Deps, assemble, serve};
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
