//! Panel access rules, mail settings and browser headers, over real HTTP in a temporary directory.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use reqwest::Method;
use reqwest::header::{CONTENT_TYPE, HeaderMap, ORIGIN, SET_COOKIE};
use rusqlite::OptionalExtension;
use scraper::{ElementRef, Html, Selector};
use serde_json::json;
use tokio::net::TcpListener;
use url::form_urlencoded::Serializer;

use super::activity::{label_of, offset_of, page_number, plain_time};
use super::mail::{
    MAILGUN_SECRET_HINT, RESEND_SECRET_HINT, SMTP_SECRET_HINT, mailgun_plan, open_provider,
    resend_plan, smtp_plan,
};
use super::servers::{Stored, store_lockdown};
use crate::app::{Deps, assemble, serve};
use crate::audit::{self, Event};
use crate::config::Config;
use crate::crypto::{Keys, PasswordHasher, token_hash};
use crate::db::Db;
use crate::policy;
use crate::proxy::tests::{TestUpstream, answer};
use crate::servers::{Scope, set_assignments};
use crate::web::{Role, SESSION_COOKIE, SessionUser};

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
        text_of(&self.body, r#".error, [data-notice="error"]"#)
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
        shared_client_address: false,
        allowed_origins: Vec::new(),
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
    tokio::spawn(serve(
        listener,
        gateway.router,
        std::time::Duration::from_secs(30),
        std::future::pending(),
    ));
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
    assert_eq!(missing.status, 404, "an unknown admin path must answer 404");
    assert_eq!(
        missing.kind().as_deref(),
        Some("not-found"),
        "an unknown admin path answers the not-found page"
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
            "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
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
        Some("The Raw SMTP settings were not saved. Go to the port field")
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
        Some("The Resend settings were not saved. Go to the from address field")
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

/// A valid post of one provider with `field` set to `value`.
fn mail_post<'a>(provider: &str, field: &str, value: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut fields = match provider {
        "smtp" => vec![
            ("provider", "smtp"),
            ("from", "gateway@example.com"),
            ("smtp_host", "smtp.example.com"),
            ("smtp_port", "587"),
            ("smtp_username", "mailer"),
            ("smtp_password", SECRET),
            ("smtp_tls", "starttls"),
        ],
        "resend" => vec![
            ("provider", "resend"),
            ("from", "gateway@example.com"),
            ("resend_api_key", "re_key"),
            ("resend_base_url", "https://api.example.com"),
        ],
        _ => vec![
            ("provider", "mailgun"),
            ("from", "gateway@example.com"),
            ("mailgun_api_key", "key-example"),
            ("mailgun_domain", "example.com"),
            ("mailgun_base_url", "https://api.example.com"),
        ],
    };
    for pair in fields.iter_mut().filter(|pair| pair.0 == field) {
        pair.1 = value;
    }
    fields
}

/// The elements of `doc` matching `css`.
fn matching<'a>(doc: &'a Html, css: &str) -> Vec<scraper::ElementRef<'a>> {
    doc.select(&Selector::parse(css).expect("selector"))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn each_refused_mail_field_is_the_one_marked_and_named() {
    // provider, posted field, posted value, id of its control, the sentence it must show.
    let cases = [
        (
            "smtp",
            "from",
            "gateway\u{7}@example.com",
            "smtp-from",
            "The from address contains a control character.",
        ),
        (
            "smtp",
            "smtp_host",
            "smtp\u{7}.example.com",
            "smtp-host",
            "The server contains a control character.",
        ),
        (
            "smtp",
            "smtp_port",
            "58\u{7}7",
            "smtp-port",
            "The port contains a control character.",
        ),
        (
            "smtp",
            "smtp_port",
            "0",
            "smtp-port",
            "The SMTP port must be a number from 1 to 65535.",
        ),
        (
            "smtp",
            "smtp_username",
            "mai\u{7}ler",
            "smtp-username",
            "The username contains a control character.",
        ),
        (
            "smtp",
            "smtp_password",
            "pass\u{7}word",
            "smtp-password",
            "The password contains a control character.",
        ),
        (
            "smtp",
            "smtp_tls",
            "plain",
            "smtp-tls",
            "Choose a TLS setting: off, starttls or implicit.",
        ),
        (
            "resend",
            "from",
            "gateway\u{7}@example.com",
            "resend-from",
            "The from address contains a control character.",
        ),
        (
            "resend",
            "resend_api_key",
            "re\u{7}key",
            "resend-key",
            "The API key contains a control character.",
        ),
        (
            "resend",
            "resend_base_url",
            "https://api\u{7}.example.com",
            "resend-base",
            "The base address contains a control character.",
        ),
        (
            "mailgun",
            "from",
            "gateway\u{7}@example.com",
            "mailgun-from",
            "The from address contains a control character.",
        ),
        (
            "mailgun",
            "mailgun_api_key",
            "key\u{7}example",
            "mailgun-key",
            "The API key contains a control character.",
        ),
        (
            "mailgun",
            "mailgun_domain",
            "example\u{7}.com",
            "mailgun-domain",
            "The domain contains a control character.",
        ),
        (
            "mailgun",
            "mailgun_base_url",
            "https://api\u{7}.example.com",
            "mailgun-base",
            "The base address contains a control character.",
        ),
    ];
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    for (provider, field, value, marked_id, sentence) in cases {
        let what = format!("{provider} with {field} refused");
        let answer = owner
            .submit(
                "/admin/mail",
                "/admin/mail",
                &mail_post(provider, field, value),
            )
            .await;
        assert_eq!(answer.status, 400, "{what} must answer 400");
        let doc = Html::parse_document(&answer.body);
        let open = matching(&doc, "details[open]");
        assert_eq!(open.len(), 1, "{what}: only the refused disclosure is open");
        assert_eq!(
            open[0].value().attr("data-provider"),
            Some(provider),
            "{what}: the open disclosure must be the refused provider"
        );
        let marked = matching(&doc, r#"[aria-invalid="true"]"#);
        assert_eq!(marked.len(), 1, "{what}: exactly one field is marked");
        assert_eq!(
            marked[0].value().attr("id"),
            Some(marked_id),
            "{what}: the marked field must be the one refused"
        );
        let described = marked[0]
            .value()
            .attr("aria-describedby")
            .expect("the marked field names its error");
        let error_id = format!("{marked_id}-error");
        assert!(
            described.split_whitespace().any(|id| id == error_id),
            "{what}: aria-describedby must name {error_id}, got {described}"
        );
        let error = matching(&doc, &format!(r#"[id="{error_id}"]"#));
        assert_eq!(error.len(), 1, "{what}: the named error must exist once");
        assert_eq!(
            error[0].text().collect::<String>(),
            sentence,
            "{what}: the error under the field"
        );
        let outcome = match provider {
            "smtp" => "The Raw SMTP settings were not saved.",
            "resend" => "The Resend settings were not saved.",
            _ => "The Mailgun settings were not saved.",
        };
        let lead = matching(
            &doc,
            &format!(
                r#"details[data-provider="{provider}"] div.notice[data-notice="error"] p strong"#
            ),
        );
        assert_eq!(lead.len(), 1, "{what}: one notice above the form");
        assert_eq!(
            lead[0].text().collect::<String>(),
            outcome,
            "{what}: the notice names the outcome"
        );
        let links = matching(
            &doc,
            &format!(r#"details[data-provider="{provider}"] div.notice[data-notice="error"] a"#),
        );
        assert_eq!(links.len(), 1, "{what}: the notice holds one link");
        assert_eq!(
            links[0].value().attr("href"),
            Some(format!("#{marked_id}").as_str()),
            "{what}: the link goes to the marked field"
        );
        let form = matching(&doc, &format!(r#"details[data-provider="{provider}"]"#));
        assert_eq!(
            form[0].text().collect::<String>().matches(sentence).count(),
            1,
            "{what}: the reason appears once, under the field"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_about_another_providers_field_marks_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let mut fields = mail_post("resend", "from", "gateway@example.com");
    fields.push(("smtp_host", "smtp\u{7}.example.com"));
    let answer = owner.submit("/admin/mail", "/admin/mail", &fields).await;
    assert_eq!(
        answer.status, 400,
        "the stray control character must be refused"
    );
    let doc = Html::parse_document(&answer.body);
    assert_eq!(
        matching(&doc, r#"[aria-invalid="true"]"#).len(),
        0,
        "no field of the resend form is about the server field"
    );
    let notice = matching(
        &doc,
        r#"details[data-provider="resend"] div.notice[data-notice="error"] p"#,
    );
    assert_eq!(
        notice.len(),
        1,
        "the refusal keeps its notice above the form"
    );
    assert_eq!(
        notice[0].text().collect::<String>(),
        "A field contains a control character.",
        "a field outside the form keeps the general sentence"
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

/// Counted failures: the rows of `login_failures`.
fn throttle_counts(dir: &Path) -> i64 {
    let conn = rusqlite::Connection::open(dir.join("doorward.db")).expect("open");
    conn.query_row("SELECT COUNT(*) FROM login_failures", [], |row| row.get(0))
        .expect("failures count")
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
        1,
        "one counted failure must be recorded"
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
        1,
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
        2,
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
    assert_eq!(
        text_of(&page.body, "span.detail").as_deref(),
        Some("<b>x</b>"),
        "the detail must read as its own text, escaped"
    );
    assert!(
        !page.body.contains("<b>x</b>"),
        "no raw markup may be shown"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_address_in_an_activity_detail_is_an_email_span() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let event = Event {
        kind: "login",
        detail: "invited bob@example.com as user",
        ..Default::default()
    };
    audit::record(&open_db(dir.path()), AT, &event).expect("record");
    let mut owner = sign_in(&base, OWNER).await;
    let page = owner.get("/admin/activity").await;
    assert_eq!(
        text_of(&page.body, "span.detail").as_deref(),
        Some("invited bob@example.com as user"),
        "the detail must read as stored"
    );
    assert_eq!(
        text_of(&page.body, "span.detail span.email").as_deref(),
        Some("bob@example.com"),
        "the address inside the detail must be a span.email"
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
    assert_eq!(rows[0].2, "test: Mail is not set up.");
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
    assert_eq!(logged[0].2, "test: The mail server did not answer in time.");
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
    let text = logged[0]
        .2
        .strip_prefix("test: ")
        .expect("the detail starts with its kind");
    assert!(text.chars().count() <= 300);
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
        assert_eq!(
            elements(&page.body, ".field-error").len(),
            1,
            "the refusal must name the field"
        );
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
        page.body.contains(
            "Stored, never shown again. Leave empty to keep it. If you change the upstream address, enter it again."
        ),
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
    assert_eq!(
        plain.kind().as_deref(),
        Some("not-found"),
        "an unknown server answers the not-found page"
    );
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

/// The fixed message of a refresh that the upstream did not answer.
const UNAVAILABLE: &str = "The last refresh failed: the upstream did not answer with a tool list.";

/// The tool names on a server page, in order.
fn catalog_of(body: &str) -> Vec<String> {
    elements(body, "[data-catalog-tool]")
        .iter()
        .filter_map(|tool| tool.get("data-catalog-tool").cloned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_tools_answers_303_and_records_a_failed_fetch() {
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
    assert_eq!(
        page.status, 303,
        "refresh-tools answers 303 when the fetch fails"
    );
    assert_eq!(page.location(), Some(path.as_str()));
    assert_eq!(
        secret_row(dir.path(), id),
        before,
        "the stored secret is not touched"
    );
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change' AND detail = 'tool refresh failed'"
        ),
        1,
        "the failed refresh is recorded"
    );
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM activity"),
        rows_before + 1,
        "one row is written"
    );
    let shown = owner.get(&path).await;
    assert_eq!(
        text_of(&shown.body, r#"[data-notice="error"]"#).as_deref(),
        Some(UNAVAILABLE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_refresh_shows_its_error_beside_the_old_tools_until_one_succeeds() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let healthy = Arc::new(AtomicBool::new(true));
    let switch = Arc::clone(&healthy);
    let upstream = TestUpstream::start(move |seen| {
        if !switch.load(Ordering::SeqCst) {
            return answer(401, None, None, "");
        }
        if seen.header("mcp-protocol-version") != Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        let listed = json!({"jsonrpc": "2.0", "id": seen.json()["id"].clone(),
            "result": {"tools": [{"name": "alpha"}]}});
        answer(200, None, Some("application/json"), &listed.to_string())
    })
    .await;
    add(&mut owner, "demo", &upstream.url, None).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let refresh = format!("{path}/refresh-tools");
    assert_eq!(owner.submit(&path, &refresh, &[]).await.status, 303);
    assert_eq!(catalog_of(&owner.get(&path).await.body), vec!["alpha"]);
    healthy.store(false, Ordering::SeqCst);
    assert_eq!(owner.submit(&path, &refresh, &[]).await.status, 303);
    let shown = owner.get(&path).await;
    assert_eq!(
        text_of(&shown.body, r#"[data-notice="error"]"#).as_deref(),
        Some(UNAVAILABLE)
    );
    assert_eq!(
        catalog_of(&shown.body),
        vec!["alpha"],
        "a failed refresh keeps the old tools listed"
    );
    healthy.store(true, Ordering::SeqCst);
    assert_eq!(owner.submit(&path, &refresh, &[]).await.status, 303);
    let shown = owner.get(&path).await;
    assert!(
        text_of(&shown.body, r#"[data-notice="error"]"#).is_none(),
        "a successful refresh removes the message"
    );
    assert_eq!(catalog_of(&shown.body), vec!["alpha"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn check_lockdown_stores_open_for_an_upstream_that_answers_without_the_secret() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let open = TestUpstream::start(|seen| {
        if seen.header("mcp-protocol-version") != Some("2026-07-28") {
            return answer(400, None, None, "");
        }
        let listed = json!({"jsonrpc": "2.0", "id": seen.json()["id"].clone(),
            "result": {"tools": []}});
        answer(200, None, Some("application/json"), &listed.to_string())
    })
    .await;
    add(&mut owner, "demo", &open.url, Some(("x-key", "v1"))).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let page = owner
        .submit(&path, &format!("{path}/check-lockdown"), &[])
        .await;
    assert_eq!(page.status, 303, "the lock-down check answers 303");
    assert_eq!(page.location(), Some(path.as_str()));
    assert_eq!(lockdown_of(dir.path(), id), "open");
    assert_eq!(
        attr_of(&owner.get(&path).await.body, "main", "data-lockdown").as_deref(),
        Some("open")
    );
    assert!(
        open.seen()
            .iter()
            .all(|request| request.header("x-key").is_none()),
        "the probe carries no secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn check_lockdown_stores_unknown_for_an_upstream_that_does_not_answer() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let page = owner
        .submit(&path, &format!("{path}/check-lockdown"), &[])
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(lockdown_of(dir.path(), id), "unknown");
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change' AND detail = 'lock-down checked: unknown'"
        ),
        1,
        "the check is recorded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_verdict_is_stored_only_for_the_address_that_was_probed() {
    let dir = tempfile::tempdir().expect("dir");
    let db = Db::open(&dir.path().join("doorward.db")).expect("database");
    add_user(dir.path(), PLAIN, "user").await;
    let id = db
        .call(|conn| {
            conn.execute(
                "INSERT INTO servers (name, slug, upstream_url, created_at) \
                 VALUES ('demo', 'demo', ?1, 0)",
                rusqlite::params![SERVER_URL],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .expect("server row");
    let actor = SessionUser {
        id: user_id_of(dir.path(), PLAIN),
        email: PLAIN.to_owned(),
        role: Role::User,
    };
    let (other, right, gone) = (actor.clone(), actor.clone(), actor);
    let moved = db
        .call(move |conn| store_lockdown(conn, id, "ok", "http://127.0.0.1:9/other", &other, AT))
        .await
        .expect("the store");
    assert!(matches!(moved, Stored::Changed));
    assert_eq!(lockdown_of(dir.path(), id), "unknown");
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change'"
        ),
        0,
        "no row for an address that changed"
    );
    let saved = db
        .call(move |conn| store_lockdown(conn, id, "ok", SERVER_URL, &right, AT))
        .await
        .expect("the store");
    assert!(matches!(saved, Stored::Saved));
    assert_eq!(lockdown_of(dir.path(), id), "ok");
    assert_eq!(
        count(
            dir.path(),
            &format!(
                "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change' \
                 AND server_id = {id} AND detail = 'lock-down checked: ok'"
            ),
        ),
        1
    );
    let missing = db
        .call(move |conn| store_lockdown(conn, id + 100, "open", SERVER_URL, &gone, AT))
        .await
        .expect("the store");
    assert!(matches!(missing, Stored::Missing));
    assert_eq!(
        count(
            dir.path(),
            "SELECT COUNT(*) FROM activity WHERE kind = 'admin_change'"
        ),
        1,
        "a server that is gone gets no row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lockdown_note_says_what_the_stored_result_means() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("X-Secret", "s3cret"))).await;
    let id = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{id}");
    let cases = [
        ("ok", "The upstream refused a request without the secret."),
        (
            "open",
            "The upstream answered a request without the secret: anyone who can reach its address can use it.",
        ),
        (
            "unknown",
            "Not checked yet, or the upstream did not answer the check.",
        ),
    ];
    for (verdict, words) in cases {
        open_db(dir.path())
            .execute(
                "UPDATE servers SET lockdown = ?1 WHERE id = ?2",
                rusqlite::params![verdict, id],
            )
            .expect("store the verdict");
        let body = owner.get(&path).await.body;
        assert_eq!(
            text_of(&body, "p[data-lockdown-note]").as_deref(),
            Some(words),
            "{verdict}"
        );
        assert!(
            !attr_of(&body, "p[data-lockdown-note]", "class")
                .unwrap_or_default()
                .contains("error"),
            "{verdict}: the note is not an error"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn check_lockdown_of_a_missing_server_answers_404() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let id = server_id_of(dir.path(), "demo");
    let form = owner.get(&format!("/admin/servers/{id}")).await;
    let csrf = attr_of(&form.body, r#"input[name="csrf"]"#, "value").expect("the csrf field");
    let gone = format!("/admin/servers/{}/check-lockdown", id + 100);
    let page = owner.post(&gone, &[("csrf", csrf.as_str())]).await;
    assert_eq!(page.status, 404);
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
async fn assignment_logs_say_one_or_many_in_the_same_words() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), PLAIN, "user").await;
    add_user(dir.path(), BOB, "user").await;
    add_user(dir.path(), "carol@example.com", "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    add(&mut owner, "other", SERVER_URL, None).await;
    let demo = server_id_of(dir.path(), "demo");
    let other = server_id_of(dir.path(), "other");
    let plain = user_id_of(dir.path(), PLAIN);
    let bob = user_id_of(dir.path(), BOB);
    let carol = user_id_of(dir.path(), "carol@example.com");
    let (plain, bob, carol) = (plain.to_string(), bob.to_string(), carol.to_string());
    let (demo, other) = (demo.to_string(), other.to_string());
    let server_path = format!("/admin/servers/{demo}/users");
    let server_page = format!("/admin/servers/{demo}");
    owner.submit(&server_page, &server_path, &[]).await;
    owner
        .submit(&server_page, &server_path, &[("user_id", plain.as_str())])
        .await;
    owner
        .submit(
            &server_page,
            &server_path,
            &[
                ("user_id", plain.as_str()),
                ("user_id", bob.as_str()),
                ("user_id", carol.as_str()),
            ],
        )
        .await;
    let user_path = format!("/admin/users/{plain}/servers");
    let user_page = format!("/admin/users/{plain}");
    owner.submit(&user_page, &user_path, &[]).await;
    owner
        .submit(&user_page, &user_path, &[("server_id", demo.as_str())])
        .await;
    owner
        .submit(
            &user_page,
            &user_path,
            &[("server_id", demo.as_str()), ("server_id", other.as_str())],
        )
        .await;
    let details: Vec<String> = rows_of(dir.path(), "admin_change")
        .into_iter()
        .map(|row| row.2)
        .filter(|detail| detail.starts_with("assignments of "))
        .collect();
    assert_eq!(
        details,
        vec![
            "assignments of demo set to 0 users",
            "assignments of demo set to 1 user",
            "assignments of demo set to 3 users",
            "assignments of plain@example.com set to 0 servers",
            "assignments of plain@example.com set to 1 server",
            "assignments of plain@example.com set to 2 servers",
        ]
    );
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
    let rows = elements(&page.body, "tr[data-redirect-id]");
    assert_eq!(rows.len(), 5, "the five shipped addresses are listed");
    for (host, listed) in [
        ("claude.ai", 1),
        ("chatgpt.com", 2),
        ("www.cursor.com", 1),
        ("anysphere.cursor-mcp", 1),
    ] {
        let row = elements(&page.body, &format!(r#"tr[data-host="{host}"]"#));
        assert_eq!(row.len(), listed, "{host} is listed {listed} time(s)");
        for entry in &row {
            assert_eq!(entry["data-source"], "shipped");
            assert_eq!(entry["data-enabled"], "yes");
        }
    }
    let cursor = elements(&page.body, r#"tr[data-scheme="cursor"]"#);
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
    let row = elements(&page.body, r#"tr[data-host="app.example.com"]"#);
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
    let row = elements(&page.body, r#"tr[data-host="app.example.com"]"#);
    assert_eq!(row[0]["data-enabled"], "no", "the flag is off");

    let again = owner
        .submit("/admin/redirects", "/admin/redirects", &fields)
        .await;
    assert_eq!(again.status, 303);
    let page = owner.get("/admin/redirects").await;
    let row = elements(&page.body, r#"tr[data-host="app.example.com"]"#);
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
        elements(&page.body, "tr[data-redirect-id]").len(),
        5,
        "no refused address is stored"
    );
    assert!(rows_of(dir.path(), "admin_change").is_empty());
}

/// For each blocked attempt, newest first: whether its row offers a one-click allow form.
fn one_click_offers(body: &str) -> Vec<bool> {
    let doc = Html::parse_document(body);
    let rows = Selector::parse("tr[data-blocked]").expect("selector");
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
        elements(&page.body, "tr[data-blocked]").len(),
        4,
        "every blocked attempt is listed"
    );
    assert!(
        elements(&page.body, "tr[data-blocked][data-host]").is_empty(),
        "a blocked row never carries data-host"
    );
    assert!(
        elements(&page.body, "tr[data-blocked][data-redirect-id]").is_empty(),
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
        text_of(&page.body, "tr[data-blocked] q").as_deref(),
        Some("<b>Claude</b>"),
        "the client name is text inside the q element"
    );
    assert_eq!(
        text_of(&page.body, "tr[data-blocked] td:nth-child(2)").as_deref(),
        Some("asked by a client that calls itself <b>Claude</b>"),
        "the client cell says the name is a claim"
    );
    assert!(
        !page.body.contains("<b>Claude</b>"),
        "the markup of the name is escaped"
    );
}

/// Stores the tool list the gateway would keep for the server, as a successful refresh does.
fn seed_catalog(dir: &Path, server: i64, names: &[&str]) {
    let tools: Vec<serde_json::Value> = names.iter().map(|name| json!({"name": name})).collect();
    let mut conn = open_db(dir);
    crate::proxy::catalog::replace(&mut conn, server, &tools, AT).expect("catalog");
}

/// Posts the add-rule form as the owner's browser and answers the page.
async fn add_rule(owner: &mut Browser, fields: &[(&str, &str)]) -> Answer {
    owner.submit("/admin/rules", "/admin/rules", fields).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_is_listed_with_its_subject_effect_scope_and_target() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let server = server_id_of(dir.path(), "demo").to_string();
    seed_catalog(dir.path(), server.parse().expect("id"), &["alpha", "beta"]);
    let bob = user_id_of(dir.path(), BOB).to_string();
    let tool_rule = add_rule(
        &mut owner,
        &[
            ("subject", &bob),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", &server),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(
        tool_rule.status, 303,
        "a tool rule on a listed tool is saved"
    );
    let everyone = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "allow"),
            ("scope", "all"),
        ],
    )
    .await;
    assert_eq!(everyone.status, 303, "an all-tools rule is saved");

    let page = owner.get("/admin/rules").await;
    assert_eq!(page.kind().as_deref(), Some("rules"));
    let rows = elements(&page.body, "tr[data-rule-id]");
    assert_eq!(rows.len(), 2, "both rules are listed");
    let tool = elements(&page.body, r#"tr[data-scope="tool"]"#);
    assert_eq!(tool.len(), 1);
    assert_eq!(tool[0]["data-subject"], BOB);
    assert_eq!(tool[0]["data-effect"], "deny");
    assert_eq!(tool[0]["data-server"], "demo");
    assert_eq!(tool[0]["data-tool"], "alpha");
    assert_eq!(tool[0]["data-stale"], "no");
    let all = elements(&page.body, r#"tr[data-scope="all"]"#);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["data-subject"], "everyone");
    assert_eq!(all[0]["data-effect"], "allow");
    assert_eq!(all[0]["data-server"], "");
    assert_eq!(all[0]["data-tool"], "");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_rule_for_a_tool_that_left_the_list_is_flagged_stale() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let server = server_id_of(dir.path(), "demo");
    seed_catalog(dir.path(), server, &["alpha"]);
    let server_text = server.to_string();
    let tool = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", &server_text),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(tool.status, 303);
    let whole = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "server"),
            ("server_id", &server_text),
        ],
    )
    .await;
    assert_eq!(whole.status, 303);
    seed_catalog(dir.path(), server, &["beta"]);

    let page = owner.get("/admin/rules").await;
    let stale = elements(&page.body, r#"tr[data-scope="tool"]"#);
    assert_eq!(stale[0]["data-stale"], "yes", "the tool left the list");
    let whole = elements(&page.body, r#"tr[data-scope="server"]"#);
    assert_eq!(
        whole[0]["data-stale"], "no",
        "a server rule never goes stale"
    );
}

/// The values of the options of `css` that carry the selected attribute.
fn picked(body: &str, css: &str) -> Vec<String> {
    elements(body, &format!("{css} option[selected]"))
        .iter()
        .map(|option| option.get("value").cloned().unwrap_or_default())
        .collect()
}

/// The values of the tool name suggestions on the page, in page order.
fn suggestions(body: &str) -> Vec<String> {
    elements(body, "datalist#rule-tools option")
        .iter()
        .map(|option| option.get("value").cloned().unwrap_or_default())
        .collect()
}

/// What a rule form says about the server `server` (name and slug alike): its add section, the tool
/// hint and the read-only text of the chosen server in the form that posts to `post_action`.
fn assert_rule_form_texts(body: &str, post_action: &str, server: &str) {
    assert_eq!(
        elements(body, r#"section#add-rule[aria-labelledby="add-title"]"#).len(),
        1,
        "the add form is the section with id add-rule"
    );
    let hint = format!(
        "Tools of {server}. To pick a tool of another server, choose the server above first."
    );
    assert_eq!(
        text_of(body, "p#rule-tool-hint").as_deref(),
        Some(hint.as_str()),
        "the tool name hint names the chosen server"
    );
    let chosen = text_of(
        body,
        &format!(r#"form[method="post"][action="{post_action}"] div.field > p:not(.hint)"#),
    );
    assert_eq!(
        chosen.as_deref(),
        Some(format!("Server: {server} ({server})").as_str()),
        "the chosen server is read-only text in the rule form"
    );
}

/// Two servers with other tools: `demo` offers alpha then beta, `other` zeta then alpha. Returns their ids.
async fn two_servers(dir: &Path, owner: &mut Browser) -> (String, String) {
    add(owner, "demo", SERVER_URL, None).await;
    add(owner, "other", SERVER_URL, None).await;
    let demo = server_id_of(dir, "demo");
    let other = server_id_of(dir, "other");
    seed_catalog(dir, demo, &["alpha", "beta"]);
    seed_catalog(dir, other, &["zeta", "alpha"]);
    (demo.to_string(), other.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rule_form_lists_only_the_tools_of_the_chosen_server() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let (demo, other) = two_servers(dir.path(), &mut owner).await;
    let chosen = owner.get(&format!("/admin/rules?server={other}")).await;
    assert_eq!(
        picked(&chosen.body, "select#rule-server"),
        vec![other.clone()],
        "the server named in the query is selected"
    );
    assert_eq!(
        suggestions(&chosen.body),
        ["zeta", "alpha"],
        "only that server's tools, in catalog order"
    );
    assert_rule_form_texts(&chosen.body, "/admin/rules", "other");
    let twice = owner
        .get(&format!("/admin/rules?server={other}&server={demo}"))
        .await;
    assert_eq!(twice.status, 200, "a repeated server key is not refused");
    assert_eq!(
        picked(&twice.body, "select#rule-server"),
        vec![other.clone()],
        "the first server value wins"
    );
    assert_eq!(suggestions(&twice.body), ["zeta", "alpha"]);
    let default = owner.get("/admin/rules").await;
    assert_eq!(
        picked(&default.body, "select#rule-server"),
        vec![demo.clone()],
        "with no server named, the first server is selected"
    );
    assert_eq!(
        suggestions(&default.body),
        ["alpha", "beta"],
        "with no server named, the first server's tools are listed"
    );
    for query in ["999", "abc", "2x", ""] {
        let page = owner.get(&format!("/admin/rules?server={query}")).await;
        assert_eq!(
            picked(&page.body, "select#rule-server"),
            vec![demo.clone()],
            "{query:?} is not a server, so the first is selected"
        );
        assert_eq!(
            suggestions(&page.body),
            ["alpha", "beta"],
            "{query:?} is not a server, so the first server's tools are listed"
        );
    }
    let bare = tempfile::tempdir().expect("dir");
    let (_base, mut empty) = owner_gateway(bare.path()).await;
    let page = empty.get("/admin/rules").await;
    assert!(
        suggestions(&page.body).is_empty(),
        "with no server, no tool is suggested"
    );
    assert!(picked(&page.body, "select#rule-server").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invitation_rule_form_lists_only_the_tools_of_the_chosen_server() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let (demo, other) = two_servers(dir.path(), &mut owner).await;
    invite_with(&mut owner, CAROL, "user", &[]).await;
    let path = plan_path(invitation_id_of(dir.path(), CAROL));
    let chosen = owner.get(&format!("{path}?server={other}")).await;
    assert_eq!(
        picked(&chosen.body, "select#rule-server"),
        vec![other.clone()],
        "the server named in the query is selected"
    );
    assert_eq!(
        suggestions(&chosen.body),
        ["zeta", "alpha"],
        "only that server's tools, in catalog order"
    );
    assert_rule_form_texts(&chosen.body, &format!("{path}/rules"), "other");
    let twice = owner
        .get(&format!("{path}?server={other}&server={demo}"))
        .await;
    assert_eq!(twice.status, 200, "a repeated server key is not refused");
    assert_eq!(
        picked(&twice.body, "select#rule-server"),
        vec![other.clone()],
        "the first server value wins"
    );
    assert_eq!(suggestions(&twice.body), ["zeta", "alpha"]);
    let default = owner.get(&path).await;
    assert_eq!(
        picked(&default.body, "select#rule-server"),
        vec![demo.clone()],
        "with no server named, the first server is selected"
    );
    assert_eq!(
        suggestions(&default.body),
        ["alpha", "beta"],
        "with no server named, the first server's tools are listed"
    );
    for query in ["999", "abc", "2x", ""] {
        let page = owner.get(&format!("{path}?server={query}")).await;
        assert_eq!(
            picked(&page.body, "select#rule-server"),
            vec![demo.clone()],
            "{query:?} is not a server, so the first is selected"
        );
        assert_eq!(
            suggestions(&page.body),
            ["alpha", "beta"],
            "{query:?} is not a server, so the first server's tools are listed"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_picker_is_a_get_form_without_the_csrf_token() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let (_demo, other) = two_servers(dir.path(), &mut owner).await;
    let page = owner.get(&format!("/admin/rules?server={other}")).await;
    let picker = elements(&page.body, "form#rule-pick-server");
    assert_eq!(picker.len(), 1, "the picker is one form");
    assert_eq!(
        picker[0]["method"], "get",
        "the picker reloads the page by GET"
    );
    assert_eq!(picker[0]["action"], "/admin/rules#add-rule");
    assert_eq!(
        text_of(&page.body, "form#rule-pick-server p#rule-server-hint").as_deref(),
        Some(
            "Choose the server first: picking it reloads the page, and the other choices typed in this form are not kept."
        ),
        "the picker's hint says the other choices are not kept"
    );
    assert!(
        elements(&page.body, r#"form#rule-pick-server input[name="csrf"]"#).is_empty(),
        "the picker's URL must not carry the csrf token"
    );
    assert_eq!(
        elements(
            &page.body,
            r#"form#rule-pick-server select#rule-server[name="server"]"#
        )
        .len(),
        1,
        "the picker's select is named server"
    );
    assert_eq!(
        text_of(
            &page.body,
            r#"form#rule-pick-server button[name="show"][value="tools"]"#
        )
        .as_deref(),
        Some("Show its tools"),
        "the picker holds the Show its tools button"
    );
    let post = r#"form[method="post"][action="/admin/rules"]"#;
    assert_eq!(
        elements(&page.body, &format!(r#"{post} input[name="csrf"]"#)).len(),
        1,
        "the rule form keeps its csrf token"
    );
    let hidden = elements(
        &page.body,
        &format!(r#"{post} input[type="hidden"][name="server_id"]"#),
    );
    assert_eq!(hidden.len(), 1, "the rule form posts the chosen server");
    assert_eq!(
        hidden[0]["value"], other,
        "the hidden field holds the server"
    );
    assert!(
        elements(&page.body, &format!("{post} select#rule-server")).is_empty(),
        "the rule form holds no server select"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_posted_from_the_form_uses_the_chosen_server() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let (_demo, other) = two_servers(dir.path(), &mut owner).await;
    let page_path = format!("/admin/rules?server={other}");
    let form = owner.get(&page_path).await;
    let posted = attr_of(
        &form.body,
        r#"form[method="post"] input[name="server_id"]"#,
        "value",
    )
    .expect("the form carries the chosen server");
    let answer = owner
        .submit(
            &page_path,
            "/admin/rules",
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "tool"),
                ("server_id", posted.as_str()),
                ("tool", "zeta"),
            ],
        )
        .await;
    assert_eq!(answer.status, 303, "a tool of the chosen server is saved");
    let stored: (i64, String) = open_db(dir.path())
        .query_row("SELECT server_id, tool FROM rules", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("one rule is stored");
    assert_eq!(
        stored,
        (other.parse::<i64>().expect("an id"), "zeta".to_owned()),
        "the rule is for the server chosen in the form"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_refused_rule_answers_400_with_its_message_and_stores_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), PLAIN, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let server = server_id_of(dir.path(), "demo").to_string();
    seed_catalog(dir.path(), server.parse().expect("id"), &["alpha"]);
    let plain = user_id_of(dir.path(), PLAIN).to_string();
    let valid = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", &server),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(valid.status, 303, "the first rule is saved");
    let refused: [(&[(&str, &str)], &str); 9] = [
        (
            &[
                ("subject", "everyone"),
                ("effect", "maybe"),
                ("scope", "all"),
            ],
            "Choose the effect allow or deny.",
        ),
        (
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "some"),
            ],
            "Choose the scope all tools, one server or one tool.",
        ),
        (
            &[
                ("subject", "no-such-user"),
                ("effect", "deny"),
                ("scope", "all"),
            ],
            "Choose everyone or a user that exists.",
        ),
        (
            &[("subject", "9999"), ("effect", "deny"), ("scope", "all")],
            "Choose everyone or a user that exists.",
        ),
        (
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "server"),
            ],
            "A server or tool rule needs a server that exists.",
        ),
        (
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "server"),
                ("server_id", "9999"),
            ],
            "A server or tool rule needs a server that exists.",
        ),
        (
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "tool"),
                ("server_id", &server),
            ],
            "A tool rule needs the tool name.",
        ),
        (
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "tool"),
                ("server_id", &server),
                ("tool", "nope"),
            ],
            "The server's tool list has no tool with that name.",
        ),
        (
            &[
                ("subject", "everyone"),
                ("effect", "deny"),
                ("scope", "tool"),
                ("server_id", &server),
                ("tool", "alpha"),
            ],
            "A rule for that subject and target already exists.",
        ),
    ];
    for (fields, message) in refused {
        let page = add_rule(&mut owner, fields).await;
        assert_eq!(page.status, 400, "{fields:?} must be refused");
        assert_eq!(
            page.kind().as_deref(),
            Some("rules"),
            "the refusal is the rules page"
        );
        let notice = page.error().unwrap_or_default();
        assert!(
            notice.starts_with("The rule was not added. ") && notice.contains(message),
            "{fields:?} shows its message in the refusal notice, got {notice:?}"
        );
    }
    let duplicate = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "allow"),
            ("scope", "tool"),
            ("server_id", &server),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(
        duplicate.status, 400,
        "the other effect for the same target is a duplicate"
    );
    assert_eq!(
        elements(&owner.get("/admin/rules").await.body, "tr[data-rule-id]").len(),
        1,
        "no refused rule is stored"
    );
    let other_user = add_rule(
        &mut owner,
        &[
            ("subject", &plain),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", &server),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(
        other_user.status, 303,
        "the same target for another subject is a new rule"
    );
    assert_eq!(
        elements(&owner.get("/admin/rules").await.body, "tr[data-rule-id]").len(),
        2,
        "the other subject's rule is stored"
    );
    assert_eq!(
        rows_of(dir.path(), "admin_change").len(),
        3,
        "the server add and the two saved rules are recorded, nothing refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_ignores_the_fields_its_scope_does_not_use() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let server = server_id_of(dir.path(), "demo").to_string();
    seed_catalog(dir.path(), server.parse().expect("id"), &["alpha"]);
    let all = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "all"),
            ("server_id", "9999"),
            ("tool", "nope"),
        ],
    )
    .await;
    assert_eq!(
        all.status, 303,
        "an all-tools rule ignores its server and tool"
    );
    let whole = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "allow"),
            ("scope", "server"),
            ("server_id", &server),
            ("tool", "nope"),
        ],
    )
    .await;
    assert_eq!(whole.status, 303, "a server rule ignores its tool");
    let page = owner.get("/admin/rules").await;
    let all = elements(&page.body, r#"tr[data-scope="all"]"#);
    assert_eq!(all[0]["data-server"], "");
    assert_eq!(all[0]["data-tool"], "");
    let whole = elements(&page.body, r#"tr[data-scope="server"]"#);
    assert_eq!(whole[0]["data-server"], "demo");
    assert_eq!(whole[0]["data-tool"], "");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_is_deleted_and_recorded_and_an_unknown_id_changes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let added = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "all"),
        ],
    )
    .await;
    assert_eq!(added.status, 303);
    let page = owner.get("/admin/rules").await;
    let id = elements(&page.body, "tr[data-rule-id]")[0]["data-rule-id"].clone();
    let changes = rows_of(dir.path(), "admin_change");
    assert_eq!(changes.len(), 1, "the add is recorded once");
    assert_eq!(changes[0].1, OWNER);
    assert_eq!(changes[0].2, "added rule 1: everyone deny all tools");

    let deleted = owner
        .submit("/admin/rules", &format!("/admin/rules/{id}/delete"), &[])
        .await;
    assert_eq!(deleted.status, 303, "the delete answers 303");
    assert_eq!(deleted.location(), Some("/admin/rules"));
    assert!(
        elements(&owner.get("/admin/rules").await.body, "tr[data-rule-id]").is_empty(),
        "the rule is gone"
    );
    let changes = rows_of(dir.path(), "admin_change");
    assert_eq!(changes.len(), 2, "the delete is recorded");
    assert_eq!(changes[1].2, "deleted rule 1: everyone deny all tools");

    for path in ["/admin/rules/9999/delete", "/admin/rules/abc/delete"] {
        let page = owner.submit("/admin/rules", path, &[]).await;
        assert_eq!(page.status, 303, "{path} answers 303");
        assert_eq!(page.location(), Some("/admin/rules"));
    }
    assert_eq!(
        rows_of(dir.path(), "admin_change").len(),
        2,
        "an unknown id records nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_user_page_names_the_deciding_rule_for_each_tool() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let server = server_id_of(dir.path(), "demo");
    seed_catalog(dir.path(), server, &["alpha", "beta"]);
    let bob = user_id_of(dir.path(), BOB);
    let (server_text, bob_text) = (server.to_string(), bob.to_string());
    let assigned = owner
        .submit(
            &format!("/admin/users/{bob}"),
            &format!("/admin/users/{bob}/servers"),
            &[("server_id", server_text.as_str())],
        )
        .await;
    assert_eq!(assigned.status, 303, "bob is assigned to demo");
    let deny_all = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "all"),
        ],
    )
    .await;
    assert_eq!(deny_all.status, 303);
    let allow_alpha = add_rule(
        &mut owner,
        &[
            ("subject", &bob_text),
            ("effect", "allow"),
            ("scope", "tool"),
            ("server_id", &server_text),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(allow_alpha.status, 303);
    let rule_ids: Vec<String> = elements(&owner.get("/admin/rules").await.body, "tr[data-rule-id]")
        .iter()
        .map(|row| row["data-rule-id"].clone())
        .collect();

    let page = owner.get(&format!("/admin/users/{bob}")).await;
    let tools = elements(&page.body, "tr[data-tool]");
    assert_eq!(
        tools.len(),
        2,
        "one element per tool of the assigned server"
    );
    let alpha = elements(&page.body, r#"tr[data-tool="alpha"]"#);
    assert_eq!(alpha[0]["data-server"], "demo");
    assert_eq!(alpha[0]["data-verdict"], "allow");
    assert_eq!(
        alpha[0]["data-rule"], rule_ids[1],
        "the user's allow decides alpha"
    );
    let beta = elements(&page.body, r#"tr[data-tool="beta"]"#);
    assert_eq!(beta[0]["data-verdict"], "deny");
    assert_eq!(
        beta[0]["data-rule"], rule_ids[0],
        "the everyone deny decides beta"
    );
    assert_eq!(page.kind().as_deref(), Some("user"));
    let panel = owner.get("/admin").await;
    assert!(
        panel.body.contains(r#"href="/admin/rules""#),
        "the panel links to the rules page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_user_page_lists_no_tool_of_a_server_the_user_is_not_assigned_to() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    add(&mut owner, "other", SERVER_URL, None).await;
    let demo = server_id_of(dir.path(), "demo");
    let other = server_id_of(dir.path(), "other");
    seed_catalog(dir.path(), demo, &["alpha", "beta"]);
    seed_catalog(dir.path(), other, &["gamma"]);
    let bob = user_id_of(dir.path(), BOB);
    let other_text = other.to_string();
    let assigned = owner
        .submit(
            &format!("/admin/users/{bob}"),
            &format!("/admin/users/{bob}/servers"),
            &[("server_id", other_text.as_str())],
        )
        .await;
    assert_eq!(assigned.status, 303, "bob is assigned to other only");
    let allow = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "allow"),
            ("scope", "server"),
            ("server_id", &demo.to_string()),
        ],
    )
    .await;
    assert_eq!(allow.status, 303, "the everyone allow on demo is saved");

    let page = owner.get(&format!("/admin/users/{bob}")).await;
    let tools = elements(&page.body, "tr[data-tool]");
    assert_eq!(
        tools.len(),
        1,
        "only the tool of the assigned server is listed"
    );
    assert_eq!(tools[0]["data-server"], "other");
    assert_eq!(tools[0]["data-tool"], "gamma");
    assert!(
        elements(&page.body, r#"tr[data-server="demo"]"#).is_empty(),
        "no tool of the unassigned server is listed, even under an allow"
    );
}

/// The text of the first element under `row` that matches `css`, or panics when there is none.
fn text_under(body: &str, row: &str, css: &str) -> String {
    text_of(body, &format!("{row} {css}")).unwrap_or_else(|| panic!("{row} must hold {css}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_list_counts_tools_and_assigned_users_and_shows_the_lock_down_state() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    add(&mut owner, "other", SERVER_URL, None).await;
    let demo = server_id_of(dir.path(), "demo");
    let other = server_id_of(dir.path(), "other");
    seed_catalog(dir.path(), demo, &["alpha", "beta", "gamma"]);
    seed_catalog(dir.path(), other, &["alpha"]);
    let bob = user_id_of(dir.path(), BOB);
    let bob_text = bob.to_string();
    let assigned = owner
        .submit(
            &format!("/admin/servers/{demo}"),
            &format!("/admin/servers/{demo}/users"),
            &[("user_id", bob_text.as_str())],
        )
        .await;
    assert_eq!(assigned.status, 303, "bob must be assigned to demo");

    let body = owner.get("/admin/servers").await.body;
    let demo_row = r#"tr[data-slug="demo"]"#;
    let other_row = r#"tr[data-slug="other"]"#;
    assert_eq!(text_under(&body, demo_row, "[data-tool-count]"), "3 tools");
    assert_eq!(text_under(&body, demo_row, "[data-user-count]"), "1 user");
    assert_eq!(text_under(&body, other_row, "[data-tool-count]"), "1 tool");
    assert_eq!(text_under(&body, other_row, "[data-user-count]"), "0 users");
    assert_eq!(text_under(&body, demo_row, "code"), "demo");
    assert_eq!(text_under(&body, demo_row, "[data-pill]"), "Not checked");
    assert_eq!(
        attr_of(&body, &format!("{demo_row} [data-pill]"), "data-tone").as_deref(),
        Some("warn")
    );
    assert_eq!(elements(&body, &format!("{demo_row} [data-pill]")).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lock_down_pill_names_the_stored_state_on_the_list_and_the_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "demo", SERVER_URL, Some(("x-key", "v1"))).await;
    let demo = server_id_of(dir.path(), "demo");
    let path = format!("/admin/servers/{demo}");
    let cases = [
        ("ok", "Locked down", "ok"),
        ("open", "Answers without the gateway", "bad"),
        ("unknown", "Not checked", "warn"),
    ];
    for (verdict, word, tone) in cases {
        open_db(dir.path())
            .execute(
                "UPDATE servers SET lockdown = ?1 WHERE id = ?2",
                rusqlite::params![verdict, demo],
            )
            .expect("store the verdict");
        let list = owner.get("/admin/servers").await.body;
        let row = r#"tr[data-slug="demo"]"#;
        assert_eq!(text_under(&list, row, "[data-pill]"), word, "{verdict}");
        assert_eq!(
            attr_of(&list, &format!("{row} [data-pill]"), "data-tone").as_deref(),
            Some(tone),
            "{verdict}"
        );
        let detail = owner.get(&path).await.body;
        let lockdown = r#"section[aria-labelledby="lockdown-title"] [data-pill]"#;
        assert_eq!(elements(&detail, lockdown).len(), 1, "{verdict}");
        assert_eq!(
            text_of(&detail, lockdown).as_deref(),
            Some(word),
            "{verdict}"
        );
    }
    add(&mut owner, "bare", SERVER_URL, None).await;
    let bare = server_id_of(dir.path(), "bare");
    open_db(dir.path())
        .execute(
            "UPDATE servers SET lockdown = 'ok' WHERE id = ?1",
            rusqlite::params![bare],
        )
        .expect("store the verdict");
    let list = owner.get("/admin/servers").await.body;
    let row = r#"tr[data-slug="bare"]"#;
    assert_eq!(
        text_under(&list, row, "[data-pill]"),
        "No secret header",
        "an ok result without a secret header must read as no secret header"
    );
    let detail = owner.get(&format!("/admin/servers/{bare}")).await.body;
    let lockdown = r#"section[aria-labelledby="lockdown-title"] [data-pill]"#;
    assert_eq!(
        text_of(&detail, lockdown).as_deref(),
        Some("No secret header"),
        "the page must read no secret header for an ok result without a secret"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_user_list_counts_assigned_servers_and_shows_active_or_disabled() {
    const CAROL: &str = "carol@example.com";
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add_user(dir.path(), CAROL, "user").await;
    open_db(dir.path())
        .execute(
            "UPDATE users SET disabled = 1 WHERE email = ?1",
            rusqlite::params![CAROL],
        )
        .expect("disable carol");
    add(&mut owner, "demo", SERVER_URL, None).await;
    let demo = server_id_of(dir.path(), "demo");
    let bob = user_id_of(dir.path(), BOB);
    let demo_text = demo.to_string();
    owner
        .submit(
            &format!("/admin/users/{bob}"),
            &format!("/admin/users/{bob}/servers"),
            &[("server_id", demo_text.as_str())],
        )
        .await;

    let body = owner.get("/admin/users").await.body;
    let bob_row = format!(r#"tr[data-email="{BOB}"]"#);
    let carol_row = format!(r#"tr[data-email="{CAROL}"]"#);
    assert_eq!(
        text_under(&body, &bob_row, "[data-server-count]"),
        "1 server"
    );
    assert_eq!(text_under(&body, &bob_row, "[data-pill]"), "Active");
    assert_eq!(
        attr_of(&body, &format!("{bob_row} [data-pill]"), "data-tone").as_deref(),
        Some("ok")
    );
    assert_eq!(
        text_under(&body, &carol_row, "[data-server-count]"),
        "0 servers"
    );
    assert_eq!(text_under(&body, &carol_row, "[data-pill]"), "Disabled");
    assert_eq!(
        attr_of(&body, &format!("{carol_row} [data-pill]"), "data-tone").as_deref(),
        Some("muted")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_row_holds_one_pill_and_names_its_target_in_words() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let added = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "all"),
        ],
    )
    .await;
    assert_eq!(added.status, 303, "the everyone deny rule must be saved");
    let body = owner.get("/admin/rules").await.body;
    let row = "tr[data-rule-id]";
    assert_eq!(elements(&body, row).len(), 1);
    assert_eq!(text_under(&body, row, "td.lead"), "Everyone");
    assert_eq!(text_under(&body, row, "td:nth-child(4)"), "all tools");
    assert_eq!(text_under(&body, row, "[data-pill]"), "Deny");
    assert_eq!(
        attr_of(&body, &format!("{row} [data-pill]"), "data-tone").as_deref(),
        Some("bad")
    );
    assert_eq!(elements(&body, &format!("{row} [data-pill]")).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_address_shows_enabled_or_disabled_and_its_toggle_is_secondary() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let body = owner.get("/admin/redirects").await.body;
    let first = elements(&body, "tr[data-redirect-id]");
    assert!(!first.is_empty(), "the shipped addresses must be listed");
    let id = first[0]["data-redirect-id"].clone();
    let row = format!(r#"tr[data-redirect-id="{id}"]"#);
    assert_eq!(text_under(&body, &row, "[data-pill]"), "Enabled");
    assert_eq!(
        attr_of(&body, &format!("{row} [data-pill]"), "data-tone").as_deref(),
        Some("ok")
    );
    assert_eq!(
        attr_of(&body, &format!(r#"{row} button"#), "data-kind").as_deref(),
        Some("secondary")
    );
    let disabled = owner
        .submit(
            "/admin/redirects",
            &format!("/admin/redirects/{id}/disable"),
            &[],
        )
        .await;
    assert_eq!(disabled.status, 303, "the address must be disabled");
    let body = owner.get("/admin/redirects").await.body;
    assert_eq!(text_under(&body, &row, "[data-pill]"), "Disabled");
    assert_eq!(
        attr_of(&body, &format!("{row} [data-pill]"), "data-tone").as_deref(),
        Some("muted")
    );
    assert_eq!(text_under(&body, &row, "button"), "Enable");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invitation_link_after_a_failed_send_sits_in_a_copy_code() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    assert_eq!(page.kind().as_deref(), Some("invitation-created"));
    assert_eq!(elements(&page.body, "code.copy[data-invite-link]").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_invitation_without_mail_links_the_owner_to_the_mail_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    assert_eq!(page.kind().as_deref(), Some("invitation-created"));
    assert!(
        page.body.contains(
            r#"<div class="notice" data-notice="warning"><p>Mail is not set up. <a href="/admin/mail" data-link="mail">Set up mail</a></p></div>"#
        ),
        "the owner must see the mail link in the warning, got {}",
        page.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_invitation_without_mail_gives_an_admin_no_mail_link() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    let page = admin
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    assert_eq!(page.kind().as_deref(), Some("invitation-created"));
    assert!(
        page.body.contains(
            r#"<div class="notice" data-notice="warning"><p>Mail is not set up.</p></div>"#
        ),
        "an admin who is not the owner must see the sentence alone, got {}",
        page.body
    );
    assert_eq!(
        elements(&page.body, r#"[data-link="mail"]"#).len(),
        0,
        "an admin who is not the owner must not see the mail link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_role_cell_holds_the_role_after_a_unit_span() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", BOB), ("role", "user")],
        )
        .await;
    owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", "carol@example.com"), ("role", "admin")],
        )
        .await;
    let page = owner.get("/admin/invitations").await;
    assert!(
        page.body
            .contains(r#"<td class="half"><span class="unit">as </span>user</td>"#),
        "the role cell of bob must hold the unit span, got {}",
        page.body
    );
    assert!(
        page.body
            .contains(r#"<td class="half"><span class="unit">as </span>admin</td>"#),
        "the role cell of carol must hold the unit span, got {}",
        page.body
    );
    assert_eq!(
        text_of(&page.body, r#"tr[data-email="bob@example.com"] > td.half"#).as_deref(),
        Some("as user"),
        "the role cell of bob must read as user"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_button_on_the_in_scope_pages_says_its_kind() {
    const DANGER: [&str; 4] = ["Delete", "Revoke", "Remove", "Disconnect"];
    const SECONDARY: [&str; 5] = [
        "Disable",
        "Enable",
        "Refresh tools",
        "Check lock-down",
        "Allow this address",
    ];
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let demo = server_id_of(dir.path(), "demo");
    let bob = user_id_of(dir.path(), BOB);
    let pages = [
        "/admin/servers".to_string(),
        format!("/admin/servers/{demo}"),
        "/admin/users".to_string(),
        format!("/admin/users/{bob}"),
        "/admin/rules".to_string(),
        "/admin/redirects".to_string(),
        "/admin/invitations".to_string(),
    ];
    let primary = Selector::parse(r#"button[data-kind="primary"]"#).expect("selector");
    let forms = Selector::parse("form").expect("selector");
    let buttons = Selector::parse("button").expect("selector");
    for path in pages {
        let body = owner.get(&path).await.body;
        let doc = Html::parse_document(&body);
        for form in doc.select(&forms) {
            let count = form.select(&primary).count();
            assert!(count <= 1, "{path}: a form holds {count} primary buttons");
        }
        for button in doc.select(&buttons) {
            let text = button.text().collect::<String>();
            let text = text.trim();
            let kind = button.value().attr("data-kind").unwrap_or("");
            assert!(
                matches!(kind, "primary" | "secondary" | "danger"),
                "{path}: the button {text:?} must carry a kind, got {kind:?}"
            );
            if DANGER.iter().any(|word| text.starts_with(word)) {
                assert_eq!(kind, "danger", "{path}: the button {text:?}");
            }
            if SECONDARY.iter().any(|word| text.starts_with(word)) {
                assert_eq!(kind, "secondary", "{path}: the button {text:?}");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_row_of_the_user_page_holds_one_allow_or_deny_pill_by_its_verdict() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    add(&mut owner, "demo", SERVER_URL, None).await;
    let demo = server_id_of(dir.path(), "demo");
    seed_catalog(dir.path(), demo, &["alpha", "beta"]);
    let bob = user_id_of(dir.path(), BOB);
    let (demo_text, bob_text) = (demo.to_string(), bob.to_string());
    owner
        .submit(
            &format!("/admin/users/{bob}"),
            &format!("/admin/users/{bob}/servers"),
            &[("server_id", demo_text.as_str())],
        )
        .await;
    let denied = add_rule(
        &mut owner,
        &[
            ("subject", bob_text.as_str()),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", demo_text.as_str()),
            ("tool", "alpha"),
        ],
    )
    .await;
    assert_eq!(denied.status, 303, "the deny rule must be saved");

    let body = owner.get(&format!("/admin/users/{bob}")).await.body;
    let alpha = r#"tr[data-tool="alpha"]"#;
    let beta = r#"tr[data-tool="beta"]"#;
    assert_eq!(text_under(&body, alpha, "[data-pill]"), "Deny");
    assert_eq!(
        attr_of(&body, &format!("{alpha} [data-pill]"), "data-tone").as_deref(),
        Some("bad")
    );
    assert_eq!(text_under(&body, beta, "[data-pill]"), "Allow");
    assert_eq!(
        attr_of(&body, &format!("{beta} [data-pill]"), "data-tone").as_deref(),
        Some("ok")
    );
    assert_eq!(elements(&body, "tr[data-tool] [data-pill]").len(), 2);
}

#[test]
fn every_activity_kind_has_a_plain_label_and_a_tone_where_it_needs_one() {
    let cases = [
        ("tool_call", "allow", "ok", "Tool call", None),
        (
            "tool_call",
            "deny",
            "refused",
            "Tool call refused",
            Some("bad"),
        ),
        (
            "tool_call",
            "allow",
            "error",
            "Tool call failed",
            Some("bad"),
        ),
        (
            "tool_call",
            "allow",
            "unavailable",
            "Tool call failed",
            Some("bad"),
        ),
        ("login", "", "", "Sign-in", None),
        ("login_failed", "", "", "Sign-in refused", Some("bad")),
        ("client_connected", "", "", "Client connected", None),
        ("client_disconnected", "", "", "Client disconnected", None),
        ("admin_change", "", "", "Admin change", None),
        ("invitation", "", "", "Invitation", None),
        ("mail_failed", "", "", "Mail not sent", Some("bad")),
        ("owner_created", "", "", "Owner created", None),
        ("reset", "", "", "Password reset", None),
        ("password_change", "", "", "Password changed", None),
        ("redirect_blocked", "", "", "Redirect blocked", Some("bad")),
        ("tool_appeared", "", "", "New tool listed", None),
        ("unlock", "", "", "Gateway unlocked", None),
        ("value_set", "", "", "Credential stored", None),
        ("value_removed", "", "", "Credential removed", None),
        ("values_dropped", "", "", "Credentials deleted", None),
        ("made_up_kind", "", "", "Made up kind", None),
    ];
    for (kind, decision, outcome, label, tone) in cases {
        assert_ne!(
            label_of(kind, decision, outcome).1,
            Some("warn"),
            "the label of {kind} must not be amber: amber is for what cannot be verified or is not set up"
        );
        assert_eq!(
            label_of(kind, decision, outcome),
            (label.to_owned(), tone),
            "the label of {kind} with decision {decision:?} and outcome {outcome:?}"
        );
    }
}

#[test]
fn the_plain_time_reads_day_month_year_and_utc() {
    // The reference values are Python's datetime, converted to unix seconds.
    let cases = [
        (1_801_440_000, "1 Feb 2027 00:00:00 UTC"),
        (1_835_442_309, "29 Feb 2028 13:05:09 UTC"),
        (1_798_761_599, "31 Dec 2026 23:59:59 UTC"),
        (1_805_068_800, "15 Mar 2027 00:00:00 UTC"),
        (1_795_202_709, "20 Nov 2026 19:25:09 UTC"),
    ];
    for (at, text) in cases {
        assert_eq!(plain_time(at).expect("the time formats"), text, "unix {at}");
    }
}

#[test]
fn a_page_number_is_positive_and_anything_else_is_the_first_page() {
    assert_eq!(page_number(None), 1, "a missing page is the first");
    for text in ["", "0", "-1", "abc", "1.5", " 2"] {
        assert_eq!(page_number(Some(text)), 1, "page {text:?}");
    }
    assert_eq!(page_number(Some("3")), 3);
    assert_eq!(page_number(Some("0003")), 3);
    assert_eq!(page_number(Some("99999999999999999999999")), u64::MAX);
}

#[test]
fn a_page_offset_is_fifty_rows_per_page_and_saturates() {
    assert_eq!(offset_of(1), 0);
    assert_eq!(offset_of(3), 100);
    assert_eq!(offset_of(u64::MAX), i64::MAX);
}

#[tokio::test(flavor = "multi_thread")]
async fn each_row_reads_in_plain_words_beside_its_time_element() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let conn = open_db(dir.path());
    let allowed = Event {
        kind: "tool_call",
        decision: "allow",
        outcome: "ok",
        ..Default::default()
    };
    let refused = Event {
        kind: "tool_call",
        decision: "deny",
        outcome: "refused",
        ..Default::default()
    };
    let failed = Event {
        kind: "mail_failed",
        detail: "invitation: refused",
        ..Default::default()
    };
    audit::record(&conn, AT, &allowed).expect("record");
    audit::record(&conn, AT + 1, &refused).expect("record");
    audit::record(&conn, AT + 2, &failed).expect("record");
    let mut owner = sign_in(&base, OWNER).await;
    let body = owner.get("/admin/activity").await.body;

    let rows = [
        (
            "2027-01-15T08:00:02Z",
            "15 Jan 2027 08:00:02 UTC",
            "Mail not sent",
            Some("bad"),
        ),
        (
            "2027-01-15T08:00:01Z",
            "15 Jan 2027 08:00:01 UTC",
            "Tool call refused",
            Some("bad"),
        ),
        (
            "2027-01-15T08:00:00Z",
            "15 Jan 2027 08:00:00 UTC",
            "Tool call",
            None,
        ),
    ];
    for (stamp, shown, label, tone) in rows {
        let row = format!(r#"tr[data-time="{stamp}"]"#);
        assert_eq!(
            text_of(&body, &format!("{row} [data-label]")).as_deref(),
            Some(label),
            "the row at {stamp} must read {label}"
        );
        assert_eq!(
            attr_of(&body, &format!("{row} [data-label]"), "data-tone").as_deref(),
            tone,
            "the tone of the row at {stamp}"
        );
        assert_eq!(
            attr_of(&body, &format!("{row} time"), "datetime").as_deref(),
            Some(stamp),
            "the time of the row at {stamp} must carry its data-time"
        );
        assert_eq!(
            text_of(&body, &format!("{row} time")).as_deref(),
            Some(shown),
            "the time of the row at {stamp} must read in plain words"
        );
    }
}

/// Inserts `count` activity rows of one user and server, one second apart from AT.
fn insert_activity(dir: &Path, count: i64) {
    let conn = open_db(dir);
    for offset in 0..count {
        let event = Event {
            kind: "tool_call",
            user_id: Some(7),
            user_email: "alice@example.com",
            server_id: Some(10),
            server_slug: "alpha",
            tool: "echo",
            decision: "allow",
            outcome: "ok",
            ..Default::default()
        };
        audit::record(&conn, AT + offset, &event).expect("record");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_activity_pages_hold_fifty_rows_and_link_with_the_filters() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    // With the sign-in row that the owner's visit writes, the log holds 120 rows.
    insert_activity(dir.path(), 119);
    let mut owner = sign_in(&base, OWNER).await;

    let first = owner.get("/admin/activity").await.body;
    assert_eq!(
        elements(&first, "tr[data-kind]").len(),
        50,
        "page one holds 50 rows"
    );
    assert_eq!(
        text_of(&first, "[data-range]").as_deref(),
        Some("Rows 1 to 50 of 120")
    );
    assert_eq!(
        attr_of(&first, r#"a[data-page-link="older"]"#, "href").as_deref(),
        Some("/admin/activity?user=&server=&page=2")
    );
    assert_eq!(
        attr_of(&first, r#"a[data-page-link="newer"]"#, "href"),
        None
    );

    let second = owner.get("/admin/activity?page=2").await.body;
    assert_eq!(
        text_of(&second, "[data-range]").as_deref(),
        Some("Rows 51 to 100 of 120")
    );
    assert_eq!(
        attr_of(&second, r#"a[data-page-link="newer"]"#, "href").as_deref(),
        Some("/admin/activity?user=&server=&page=1")
    );
    assert_eq!(
        attr_of(&second, r#"a[data-page-link="older"]"#, "href").as_deref(),
        Some("/admin/activity?user=&server=&page=3")
    );

    let last = owner.get("/admin/activity?page=3").await.body;
    assert_eq!(
        text_of(&last, "[data-range]").as_deref(),
        Some("Rows 101 to 120 of 120")
    );
    assert_eq!(attr_of(&last, r#"a[data-page-link="older"]"#, "href"), None);

    let past = owner.get("/admin/activity?page=4").await.body;
    assert!(
        elements(&past, "tr[data-kind]").is_empty(),
        "a page past the end holds no rows"
    );
    assert!(past.contains("No activity matches."));
    assert_eq!(
        attr_of(&past, r#"a[data-page-link="newer"]"#, "href").as_deref(),
        Some("/admin/activity?user=&server=&page=3")
    );

    let filtered = owner
        .get("/admin/activity?user=7&server=10&page=2")
        .await
        .body;
    assert_eq!(
        attr_of(&filtered, r#"a[data-page-link="newer"]"#, "href").as_deref(),
        Some("/admin/activity?user=7&server=10&page=1")
    );
    assert_eq!(
        attr_of(&filtered, r#"a[data-page-link="older"]"#, "href").as_deref(),
        Some("/admin/activity?user=7&server=10&page=3")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_link_past_the_end_goes_to_the_last_page_with_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    // With the sign-in row that the owner's visit writes, the log holds 120 rows: three pages.
    insert_activity(dir.path(), 119);
    let mut owner = sign_in(&base, OWNER).await;

    for number in [4, 6, 40] {
        let past = owner
            .get(&format!("/admin/activity?page={number}"))
            .await
            .body;
        assert!(
            elements(&past, "tr[data-kind]").is_empty(),
            "page {number} holds no rows"
        );
        assert_eq!(
            attr_of(&past, r#"a[data-page-link="newer"]"#, "href").as_deref(),
            Some("/admin/activity?user=&server=&page=3"),
            "the newer link of page {number} must go to the last page with rows"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_counts_its_rows_and_shows_the_newest_five_activity_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    add_user(dir.path(), ADMIN, "admin").await;
    add_user(dir.path(), PLAIN, "user").await;
    let conn = open_db(dir.path());
    conn.execute(
        "INSERT INTO servers (name, slug, upstream_url, created_at) \
         VALUES ('Demo', 'demo', 'http://127.0.0.1:9/mcp', 0)",
        [],
    )
    .expect("server");
    let server_id: i64 = conn
        .query_row("SELECT id FROM servers", [], |row| row.get(0))
        .expect("server id");
    for (email, token, expires) in [
        ("open@example.com", "hash-open", 4_102_444_800_i64),
        ("old@example.com", "hash-old", 1),
    ] {
        conn.execute(
            "INSERT INTO invitations (email, role, token_hash, invited_by, created_at, expires_at) \
             VALUES (?1, 'user', ?2, NULL, 0, ?3)",
            rusqlite::params![email, token, expires],
        )
        .expect("invitation");
    }
    conn.execute(
        "INSERT INTO rules (user_id, effect, server_id, tool, created_at) VALUES (NULL, 'allow', ?1, NULL, 0)",
        rusqlite::params![server_id],
    )
    .expect("rule");
    conn.execute(
        "INSERT INTO rules (user_id, effect, server_id, tool, created_at) VALUES (NULL, 'deny', ?1, 'echo', 0)",
        rusqlite::params![server_id],
    )
    .expect("rule");
    for offset in 0..6 {
        let event = Event {
            kind: "admin_change",
            detail: "mail settings",
            ..Default::default()
        };
        audit::record(&conn, AT + offset, &event).expect("record");
    }
    let mut owner = sign_in(&base, OWNER).await;
    let body = owner.get("/admin").await.body;

    for (key, value) in [
        ("servers", "1"),
        ("users", "3"),
        ("invitations", "1"),
        ("rules", "2"),
    ] {
        assert_eq!(
            text_of(
                &body,
                &format!(r#"a[data-count="{key}"] [data-count-value]"#)
            )
            .as_deref(),
            Some(value),
            "the {key} count"
        );
    }
    let stamps: Vec<String> = elements(&body, "section[data-latest-activity] tr[data-kind]")
        .iter()
        .map(|row| row["data-time"].clone())
        .collect();
    assert_eq!(
        stamps,
        [
            "2027-01-15T08:00:05Z",
            "2027-01-15T08:00:04Z",
            "2027-01-15T08:00:03Z",
            "2027-01-15T08:00:02Z",
            "2027-01-15T08:00:01Z",
        ],
        "the overview shows the five newest rows, newest first"
    );
    assert!(
        body.contains(r#"href="/admin/activity""#),
        "the latest activity links to the whole page"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overview_without_activity_says_so() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let mut owner = sign_in(&base, OWNER).await;
    // The sign-in writes its own row, so the log is emptied before the overview is read.
    open_db(dir.path())
        .execute("DELETE FROM activity", [])
        .expect("the log is emptied");
    let body = owner.get("/admin").await.body;
    assert!(
        body.contains("No activity yet."),
        "the overview must say there is no activity"
    );
    assert!(elements(&body, "section[data-latest-activity] tr[data-kind]").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_naming_no_provider_is_refused_at_the_top_of_the_mail_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, _) = start(dir.path()).await;
    add_user(dir.path(), OWNER, "owner").await;
    let mut owner = sign_in(&base, OWNER).await;
    let refused = owner
        .submit(
            "/admin/mail",
            "/admin/mail",
            &[("provider", "bogus"), ("from", "")],
        )
        .await;
    assert_eq!(
        refused.status, 400,
        "a post naming no provider must be refused"
    );
    assert_eq!(
        text_of(&refused.body, r#"[data-notice="error"] p"#).as_deref(),
        Some("Choose a provider: smtp, resend or mailgun.")
    );
    assert!(
        elements(&refused.body, "details[open]").is_empty(),
        "no provider disclosure may open for a post that names none"
    );
}

#[test]
fn the_open_provider_is_the_refused_one_else_the_one_in_use_else_none() {
    assert_eq!(open_provider(Some("smtp"), Some("resend")), Some("resend"));
    assert_eq!(open_provider(Some("smtp"), None), Some("smtp"));
    assert_eq!(open_provider(None, None), None);
}

/// The posted fields as a getter: a name not in `pairs` reads as "".
fn posted_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    move |name: &str| {
        owned
            .iter()
            .find(|(key, _)| key == name)
            .map_or(String::new(), |(_, value)| value.clone())
    }
}

/// The hint names the label of every connection field, and `labels` lists exactly those fields.
fn names_each_field(hint: &str, connection: &[(&str, String)], labels: &[(&str, &str)]) {
    assert_eq!(
        connection.len(),
        labels.len(),
        "every connection field must have its label listed in the test"
    );
    for (key, _) in connection {
        let label = labels
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, label)| *label)
            .unwrap_or_else(|| panic!("{key} has no label listed in the test"));
        assert!(
            hint.contains(&format!("the {label}")),
            "the hint must name the {label} field ({key}): {hint:?}"
        );
    }
}

#[test]
fn the_smtp_hint_names_every_connection_field_of_its_plan() {
    let dir = tempfile::tempdir().expect("dir");
    let keys = keys_of(dir.path(), "http://127.0.0.1:8080");
    let posted = posted_of(&[
        ("smtp_host", "mail.example.com"),
        ("smtp_port", "587"),
        ("smtp_username", "mailer"),
        ("smtp_tls", "starttls"),
    ]);
    let Ok(plan) = smtp_plan(posted, &keys, String::new()) else {
        panic!("the smtp plan must be built from a valid post");
    };
    names_each_field(
        SMTP_SECRET_HINT,
        &plan.connection,
        &[
            ("mail.smtp_host", "server"),
            ("mail.smtp_port", "port"),
            ("mail.smtp_username", "username"),
            ("mail.smtp_tls", "TLS setting"),
        ],
    );
    assert_eq!(
        SMTP_SECRET_HINT,
        "Leave empty to keep the stored one. If you change the server, the port, the username or the TLS setting, enter it again."
    );
}

#[test]
fn the_resend_hint_names_every_connection_field_of_its_plan() {
    let dir = tempfile::tempdir().expect("dir");
    let keys = keys_of(dir.path(), "http://127.0.0.1:8080");
    let posted = posted_of(&[("resend_base_url", "https://api.example.com")]);
    let Ok(plan) = resend_plan(posted, &keys, String::new()) else {
        panic!("the resend plan must be built from a valid post");
    };
    names_each_field(
        RESEND_SECRET_HINT,
        &plan.connection,
        &[("mail.resend_base_url", "base address")],
    );
    assert_eq!(
        RESEND_SECRET_HINT,
        "Leave empty to keep the stored one. If you change the base address, enter it again."
    );
}

#[test]
fn the_mailgun_hint_names_every_connection_field_of_its_plan() {
    let dir = tempfile::tempdir().expect("dir");
    let keys = keys_of(dir.path(), "http://127.0.0.1:8080");
    let posted = posted_of(&[
        ("mailgun_domain", "mail.example.com"),
        ("mailgun_base_url", "https://api.example.com"),
    ]);
    let Ok(plan) = mailgun_plan(posted, &keys, String::new()) else {
        panic!("the mailgun plan must be built from a valid post");
    };
    names_each_field(
        MAILGUN_SECRET_HINT,
        &plan.connection,
        &[
            ("mail.mailgun_domain", "domain"),
            ("mail.mailgun_base_url", "base address"),
        ],
    );
    assert_eq!(
        MAILGUN_SECRET_HINT,
        "Leave empty to keep the stored one. If you change the domain or the base address, enter it again."
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_names_every_open_server_in_name_order_and_cuts_none() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    for slug in ["gamma", "alpha", "delta", "beta"] {
        assert_eq!(add(&mut owner, slug, SERVER_URL, None).await.status, 303);
    }
    open_db(dir.path())
        .execute(
            "UPDATE servers SET lockdown = 'open' WHERE slug != 'delta'",
            [],
        )
        .expect("three servers are open");
    let body = owner.get("/admin").await.body;
    let notice = r#"div.notice[data-notice="error"][data-open-servers="3"]"#;
    assert_eq!(elements(&body, notice).len(), 1, "one notice counts three");
    assert_eq!(
        text_of(&body, notice).as_deref(),
        Some(
            "3 servers answer without the gateway. Anyone who can reach their addresses can use them: alpha, beta and gamma."
        )
    );
    for slug in ["alpha", "beta", "gamma"] {
        let id = server_id_of(dir.path(), slug);
        assert_eq!(
            elements(
                &body,
                &format!(r#"{notice} a[href="/admin/servers/{id}#lockdown-title"]"#)
            )
            .len(),
            1,
            "{slug} must be a link to its lock-down part"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_activity_row_without_a_user_has_an_empty_user_cell() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let event = Event {
        kind: "unlock",
        ..Default::default()
    };
    audit::record(&open_db(dir.path()), AT + 100, &event).expect("record");
    let body = owner.get("/admin").await.body;
    let cell = r#"tr[data-kind="unlock"] td.user"#;
    assert_eq!(
        elements(&body, cell).len(),
        1,
        "the row must be on the overview"
    );
    assert_eq!(text_of(&body, cell).as_deref(), Some(""));
    assert!(
        body.contains(r#"<td class="user"></td>"#),
        "the cell must hold nothing, not even a space"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_server_form_says_so_and_marks_its_path_field() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    assert_eq!(add(&mut owner, "demo", SERVER_URL, None).await.status, 303);
    let page = add(&mut owner, "demo", NEW_URL, None).await;
    assert_eq!(page.status, 400, "a taken path must refuse the form");
    assert_eq!(
        text_of(
            &page.body,
            r#"div.notice[data-notice="error"][role="alert"]"#
        )
        .as_deref(),
        Some(
            "The server was not added. Another server already uses that path. Go to the path field"
        )
    );
    assert!(
        page.body.contains(
            r##"<div class="notice" data-notice="error" role="alert"><p><strong>The server was not added.</strong> Another server already uses that path. <a href="#server-slug">Go to the path field</a></p></div>"##
        ),
        "the refused server notice must be exactly its markup"
    );
    assert_eq!(
        attr_of(&page.body, r##"a[href="#server-slug"]"##, "href").as_deref(),
        Some("#server-slug")
    );
    assert_eq!(
        attr_of(&page.body, "input#server-slug", "aria-invalid").as_deref(),
        Some("true")
    );
    assert_eq!(
        attr_of(&page.body, "input#server-slug", "aria-describedby").as_deref(),
        Some("server-slug-error")
    );
    assert_eq!(
        text_of(&page.body, "p#server-slug-error").as_deref(),
        Some("Another server already uses that path.")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_server_page_says_the_server_was_not_saved() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    assert_eq!(add(&mut owner, "demo", SERVER_URL, None).await.status, 303);
    assert_eq!(add(&mut owner, "other", NEW_URL, None).await.status, 303);
    let path = format!("/admin/servers/{}", server_id_of(dir.path(), "other"));
    let page = owner
        .submit(&path, &path, &server_form("demo", NEW_URL, None))
        .await;
    assert_eq!(page.status, 400, "a taken path must refuse the save");
    assert_eq!(
        text_of(
            &page.body,
            r#"div.notice[data-notice="error"][role="alert"]"#
        )
        .as_deref(),
        Some(
            "The server was not saved. Another server already uses that path. Go to the path field"
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_invitation_says_so_and_marks_its_email_field() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", "not-an-address"), ("role", "user")],
        )
        .await;
    assert_eq!(page.status, 400, "a bad address must refuse the invitation");
    assert_eq!(
        page.error().as_deref(),
        Some("The invitation was not sent. Enter a valid email address. Go to the email field"),
        "the refusal notice names the invitation and links to the email field"
    );
    assert_eq!(
        attr_of(&page.body, "input#invite-email", "aria-invalid").as_deref(),
        Some("true")
    );
    assert_eq!(
        attr_of(&page.body, "input#invite-email", "aria-describedby").as_deref(),
        Some("invite-email-error")
    );
    assert_eq!(
        text_of(&page.body, "p#invite-email-error").as_deref(),
        Some("Enter a valid email address.")
    );
    assert!(
        rows_of(dir.path(), "invitation").is_empty(),
        "a refused invitation stores nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_rule_says_so_and_marks_the_field_it_is_about() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = add_rule(
        &mut owner,
        &[
            ("subject", "everyone"),
            ("effect", "maybe"),
            ("scope", "all"),
        ],
    )
    .await;
    assert_eq!(page.status, 400, "a bad effect must refuse the rule");
    assert_eq!(
        page.error().as_deref(),
        Some("The rule was not added. Choose the effect allow or deny. Go to the effect field"),
    );
    assert_eq!(
        attr_of(&page.body, "select#rule-effect", "aria-invalid").as_deref(),
        Some("true")
    );
    assert_eq!(
        text_of(&page.body, "p#rule-effect-error").as_deref(),
        Some("Choose the effect allow or deny.")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_address_says_so_and_names_no_field() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner
        .submit(
            "/admin/redirects",
            "/admin/redirects",
            &[
                ("scheme", "http"),
                ("host", "app.example.com"),
                ("path_prefix", "/x"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "a plain http address must be refused");
    let notice = page.error().unwrap_or_default();
    assert!(
        notice.starts_with(
            "The address was not added. The scheme, host and path prefix must form a web address:"
        ),
        "the refusal notice names the address, got {notice:?}"
    );
    assert_eq!(
        elements(&page.body, r#"[data-notice="error"] a"#).len(),
        0,
        "a refusal about no one field has no link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_role_on_the_user_page_marks_the_role_field() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), BOB, "user").await;
    let bob = user_id_of(dir.path(), BOB);
    let path = format!("/admin/users/{bob}");
    let page = owner
        .submit(&path, &format!("{path}/role"), &[("role", "root")])
        .await;
    assert_eq!(
        page.status, 400,
        "a role that is not admin or user is refused"
    );
    assert_eq!(
        page.error().as_deref(),
        Some("Choose the role admin or user. Go to the role field"),
    );
    assert_eq!(
        attr_of(&page.body, "select#user-role", "aria-invalid").as_deref(),
        Some("true")
    );
    assert_eq!(
        text_of(&page.body, "p#user-role-error").as_deref(),
        Some("Choose the role admin or user.")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_attempt_that_cannot_be_allowed_gives_its_reason() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let conn = open_db(dir.path());
    for (client, detail) in [
        ("Plain client", "http://intranet.example.com/cb"),
        ("Subtree client", "https://app.example.com/oauth/"),
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
    let doc = Html::parse_document(&page.body);
    let rows = Selector::parse("tr[data-blocked]").expect("selector");
    let reason = Selector::parse("td.reason").expect("selector");
    let reasons: Vec<Option<String>> = doc
        .select(&rows)
        .map(|row| {
            row.select(&reason)
                .next()
                .map(|cell| cell.text().collect::<String>())
        })
        .collect();
    assert_eq!(
        reasons,
        vec![
            Some("Add it by hand below.".to_owned()),
            Some("Plain http cannot be allowed.".to_owned()),
        ],
        "newest first: the subtree needs adding by hand, plain http cannot be allowed"
    );
}

/// The first form of `doc` that holds an element matching `inner`.
fn form_holding<'a>(doc: &'a Html, inner: &str) -> ElementRef<'a> {
    let inner = Selector::parse(inner).expect("selector");
    let forms = Selector::parse("form").expect("selector");
    doc.select(&forms)
        .find(|form| form.select(&inner).next().is_some())
        .expect("a form holding the element")
}

/// The `div.fields` rows of `form` in order: each row's data-cols, its number of `div.field`, and
/// the ids of its controls.
fn field_rows(form: ElementRef<'_>) -> Vec<(Option<String>, usize, Vec<String>)> {
    let rows = Selector::parse("div.fields").expect("selector");
    let fields = Selector::parse("div.field").expect("selector");
    let controls =
        Selector::parse("div.field > input[id], div.field > select[id]").expect("selector");
    form.select(&rows)
        .map(|row| {
            let ids = row
                .select(&controls)
                .filter_map(|control| control.value().attr("id"))
                .map(str::to_owned)
                .collect();
            let cols = row.value().attr("data-cols").map(str::to_owned);
            (cols, row.select(&fields).count(), ids)
        })
        .collect()
}

/// One expected row for `field_rows`.
fn row(cols: Option<&str>, fields: usize, ids: &[&str]) -> (Option<String>, usize, Vec<String>) {
    (
        cols.map(str::to_owned),
        fields,
        ids.iter().map(|id| (*id).to_owned()).collect(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invitation_email_has_a_row_of_its_own_and_the_role_a_narrower_one() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner.get("/admin/invitations").await;
    let doc = Html::parse_document(&page.body);
    assert_eq!(
        field_rows(form_holding(&doc, "#invite-email")),
        vec![
            row(None, 1, &["invite-email"]),
            row(Some("2"), 1, &["invite-role"]),
            row(None, 1, &[]),
        ],
        "the email must sit alone in a row, the role alone in a data-cols 2 row, the servers after them"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_redirect_scheme_has_a_wide_row_and_the_host_a_row_of_its_own() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner.get("/admin/redirects").await;
    let doc = Html::parse_document(&page.body);
    assert_eq!(
        field_rows(form_holding(&doc, "#redirect-scheme")),
        vec![
            row(Some("2"), 1, &["redirect-scheme"]),
            row(None, 1, &["redirect-host"]),
            row(None, 1, &["redirect-path"]),
        ],
        "the scheme must sit in a data-cols 2 row, the host alone, the path prefix after them"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_raw_smtp_form_puts_server_alone_then_port_and_tls_then_the_credentials() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner.get("/admin/mail").await;
    let doc = Html::parse_document(&page.body);
    let form = form_holding(&doc, r#"input[name="provider"][value="smtp"]"#);
    assert_eq!(
        field_rows(form),
        vec![
            row(None, 1, &["smtp-from"]),
            row(None, 1, &["smtp-host"]),
            row(Some("2"), 2, &["smtp-port", "smtp-tls"]),
            row(Some("2"), 2, &["smtp-username", "smtp-password"]),
        ],
        "the SMTP rows must group the fields as the design gives them"
    );
    let controls = Selector::parse("input[id], select[id]").expect("selector");
    let order: Vec<&str> = form
        .select(&controls)
        .filter_map(|control| control.value().attr("id"))
        .collect();
    assert_eq!(
        order,
        [
            "smtp-from",
            "smtp-host",
            "smtp-port",
            "smtp-tls",
            "smtp-username",
            "smtp-password",
        ],
        "in the document the server must come before the port, the TLS mode before the username"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limited_page_does_not_mark_its_heading_as_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let mut config = config_in(dir.path(), &base);
    config.limits.general_burst = 1;
    config.limits.general_per_minute = 1;
    let hasher = PasswordHasher::new().await.expect("hasher");
    let gateway = assemble(config, Deps::system(), Arc::new(hasher))
        .await
        .expect("build");
    tokio::spawn(serve(
        listener,
        gateway.router,
        std::time::Duration::from_secs(30),
        std::future::pending(),
    ));
    let mut browser = Browser::new(&base);
    let first = browser.get("/login").await;
    assert_ne!(first.status, 429, "the first request takes the only token");
    let limited = browser
        .answer(
            browser
                .request(Method::GET, "/login")
                .header("accept", "text/html"),
        )
        .await;
    assert_eq!(limited.status, 429, "the second request must be limited");
    assert_eq!(
        text_of(&limited.body, "main h1").as_deref(),
        Some("Too many requests"),
        "the limited page must head itself Too many requests"
    );
    assert_eq!(
        attr_of(&limited.body, "main h1", "data-tone"),
        None,
        "the limited page is not a verdict on the person"
    );
}

const CAROL: &str = "carol@example.com";

/// Posts the invite form as `browser` with each server of `servers` ticked.
async fn invite_with(browser: &mut Browser, email: &str, role: &str, servers: &[i64]) -> Answer {
    let ids: Vec<String> = servers.iter().map(i64::to_string).collect();
    let mut fields = vec![("email", email), ("role", role)];
    fields.extend(ids.iter().map(|id| ("server_id", id.as_str())));
    browser
        .submit("/admin/invitations", "/admin/invitations", &fields)
        .await
}

fn plan_path(invitation: i64) -> String {
    format!("/admin/invitations/{invitation}")
}

/// The id of the invitation stored for `email`.
fn invitation_id_of(dir: &Path, email: &str) -> i64 {
    open_db(dir)
        .query_row(
            "SELECT id FROM invitations WHERE email = ?1",
            [email],
            |row| row.get(0),
        )
        .expect("the invitation exists")
}

/// Posts one rule to an invitation's plan from the plan page's form.
async fn plan_rule(browser: &mut Browser, invitation: i64, fields: &[(&str, &str)]) -> Answer {
    let path = plan_path(invitation);
    browser
        .submit(&path, &format!("{path}/rules"), fields)
        .await
}

/// Replaces the servers of an invitation's plan with the ids given.
async fn plan_servers(browser: &mut Browser, invitation: i64, ids: &[&str]) -> Answer {
    let path = plan_path(invitation);
    let fields: Vec<(&str, &str)> = ids.iter().map(|id| ("server_id", *id)).collect();
    browser
        .submit(&path, &format!("{path}/servers"), &fields)
        .await
}

/// Accepts the invitation whose link the invite answer shows, from a browser of its own.
async fn accept_link(base: &str, answer: &Answer) -> Answer {
    let link = attr_of(&answer.body, "[data-invite-link]", "data-invite-link")
        .expect("the invitation link");
    let path = link
        .strip_prefix(base)
        .expect("the link is under the base")
        .to_owned();
    let mut invitee = Browser::new(base);
    invitee
        .submit(&path, &path, &[("password", PASSWORD)])
        .await
}

/// Adds a tool to a server's tool list, as a refresh of the server's tools would.
fn list_tool(dir: &Path, server: i64, name: &str) {
    open_db(dir)
        .execute(
            "INSERT INTO tool_catalog (server_id, position, name, definition) VALUES (?1, 0, ?2, '{}')",
            rusqlite::params![server, name],
        )
        .expect("insert tool");
}

/// The ids that `sql` selects for the one parameter, in the order it selects them.
fn ids_of(dir: &Path, sql: &str, param: i64) -> Vec<i64> {
    let conn = open_db(dir);
    let mut statement = conn.prepare(sql).expect("prepare");
    statement
        .query_map([param], |row| row.get(0))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

/// (effect, server id, tool) of each rule that `sql` selects for the one parameter.
fn rule_triples(dir: &Path, sql: &str, param: i64) -> Vec<(String, Option<i64>, Option<String>)> {
    let conn = open_db(dir);
    let mut statement = conn.prepare(sql).expect("prepare");
    statement
        .query_map([param], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_plan_is_applied_on_accept() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    for slug in ["alpha", "beta", "gamma"] {
        assert_eq!(add(&mut owner, slug, SERVER_URL, None).await.status, 303);
    }
    let alpha = server_id_of(dir.path(), "alpha");
    let gamma = server_id_of(dir.path(), "gamma");
    list_tool(dir.path(), alpha, "search");
    let invite = invite_with(&mut owner, BOB, "user", &[alpha, gamma]).await;
    assert_eq!(invite.kind().as_deref(), Some("invitation-created"));
    let invitation = invitation_id_of(dir.path(), BOB);
    let plan = plan_path(invitation);

    let listed = owner.get("/admin/invitations").await;
    assert_eq!(
        attr_of(&listed.body, &format!(r#"a[href="{plan}"]"#), "href").as_deref(),
        Some(plan.as_str()),
        "the email links to the plan"
    );
    assert_eq!(
        text_of(&listed.body, "[data-server-count]").as_deref(),
        Some("2 servers"),
        "the row counts the ticked servers"
    );

    let alpha_text = alpha.to_string();
    let gamma_text = gamma.to_string();
    let replaced = plan_servers(
        &mut owner,
        invitation,
        &[alpha_text.as_str(), gamma_text.as_str()],
    )
    .await;
    assert_eq!(replaced.status, 303, "the servers of the plan are saved");
    // The allow on gamma is planned first, so the plan order differs from (server_id, tool) order.
    let allowed = plan_rule(
        &mut owner,
        invitation,
        &[
            ("effect", "allow"),
            ("scope", "server"),
            ("server_id", gamma_text.as_str()),
        ],
    )
    .await;
    assert_eq!(allowed.status, 303, "the allow rule is planned");
    let denied = plan_rule(
        &mut owner,
        invitation,
        &[
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", alpha_text.as_str()),
            ("tool", "search"),
        ],
    )
    .await;
    assert_eq!(denied.status, 303, "the deny rule is planned");
    assert_eq!(
        rows_of(dir.path(), "admin_change")
            .iter()
            .map(|row| row.2.as_str())
            .filter(|detail| detail.contains("invitation"))
            .collect::<Vec<_>>(),
        [
            "invitation servers of bob@example.com set to 2 servers",
            "invitation servers of bob@example.com set to 2 servers",
            "added invitation rule 1: bob@example.com allow server gamma",
            "added invitation rule 2: bob@example.com deny tool search on server alpha",
        ],
        "the invite and each plan change are recorded, naming the invited address"
    );

    let accepted = accept_link(&base, &invite).await;
    assert_eq!(accepted.status, 303, "the invitation is accepted");
    let user = user_id_of(dir.path(), BOB);
    assert_eq!(
        ids_of(
            dir.path(),
            "SELECT server_id FROM user_servers WHERE user_id = ?1 ORDER BY server_id",
            user
        ),
        vec![alpha, gamma],
        "the planned servers are assigned"
    );
    assert_eq!(
        rule_triples(
            dir.path(),
            "SELECT effect, server_id, tool FROM rules WHERE user_id = ?1 ORDER BY id",
            user
        ),
        vec![
            ("allow".to_owned(), Some(gamma), None),
            ("deny".to_owned(), Some(alpha), Some("search".to_owned())),
        ],
        "the planned rules are the new user's rules, in plan order"
    );
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_servers"),
        0
    );
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        0
    );
    let deny_id: i64 = open_db(dir.path())
        .query_row("SELECT id FROM rules WHERE effect = 'deny'", [], |row| {
            row.get(0)
        })
        .expect("the deny rule");
    let conn = open_db(dir.path());
    let loaded = policy::load(&conn, user, alpha).expect("the rules of the user");
    assert_eq!(
        policy::decide(&loaded, user, alpha, "search"),
        policy::Verdict {
            allowed: false,
            rule: Some(deny_id),
        },
        "the planned deny refuses the tool"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_plan_is_invisible_to_policy_while_pending() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    add_user(dir.path(), PLAIN, "user").await;
    let plain = user_id_of(dir.path(), PLAIN);
    open_db(dir.path())
        .execute(
            "INSERT INTO user_servers (user_id, server_id) VALUES (?1, ?2)",
            rusqlite::params![plain, alpha],
        )
        .expect("assign the existing user");
    invite_with(&mut owner, BOB, "user", &[alpha]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let planned = plan_rule(
        &mut owner,
        invitation,
        &[("effect", "deny"), ("scope", "all")],
    )
    .await;
    assert_eq!(planned.status, 303, "the deny on all tools is planned");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM rules"),
        0,
        "a pending rule is no row of rules"
    );
    let conn = open_db(dir.path());
    let loaded = policy::load(&conn, plain, alpha).expect("the rules of the user");
    assert!(loaded.is_empty(), "no rule applies to the existing user");
    assert_eq!(
        policy::decide(&loaded, plain, alpha, "search"),
        policy::Verdict {
            allowed: true,
            rule: None,
        },
        "the existing user is still allowed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_or_expired_invitation_leaves_no_plan() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    invite_with(&mut owner, BOB, "user", &[alpha]).await;
    let revoked = invitation_id_of(dir.path(), BOB);
    let planned = plan_rule(&mut owner, revoked, &[("effect", "deny"), ("scope", "all")]).await;
    assert_eq!(planned.status, 303);
    assert_eq!(
        ids_of(
            dir.path(),
            "SELECT server_id FROM invitation_servers WHERE invitation_id = ?1",
            revoked
        ),
        vec![alpha]
    );
    let gone = owner
        .submit(
            "/admin/invitations",
            &format!("{}/revoke", plan_path(revoked)),
            &[],
        )
        .await;
    assert_eq!(gone.status, 303, "the invitation is revoked");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_servers"),
        0
    );
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        0
    );

    let invite = invite_with(&mut owner, CAROL, "user", &[alpha]).await;
    let expired = invitation_id_of(dir.path(), CAROL);
    let planned = plan_rule(&mut owner, expired, &[("effect", "deny"), ("scope", "all")]).await;
    assert_eq!(planned.status, 303);
    let link = attr_of(&invite.body, "[data-invite-link]", "data-invite-link")
        .expect("the invitation link");
    let path = link
        .strip_prefix(base.as_str())
        .expect("the link is under the base")
        .to_owned();
    let mut invitee = Browser::new(&base);
    let form = invitee.get(&path).await;
    let csrf = attr_of(&form.body, r#"input[name="csrf"]"#, "value").expect("the csrf field");
    open_db(dir.path())
        .execute(
            "UPDATE invitations SET expires_at = 1 WHERE id = ?1",
            [expired],
        )
        .expect("expire the invitation");
    let accepted = invitee
        .post(&path, &[("csrf", csrf.as_str()), ("password", PASSWORD)])
        .await;
    assert_eq!(accepted.status, 404, "an expired link is refused");
    assert_eq!(accepted.kind().as_deref(), Some("link-invalid"));
    assert_eq!(
        owner.get(&plan_path(expired)).await.status,
        404,
        "an expired invitation has no plan page"
    );
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM users WHERE email = '{CAROL}'")
        ),
        0
    );
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM user_servers"), 0);
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM rules"), 0);
    invite_with(&mut owner, CAROL, "user", &[alpha]).await;
    let renewed = invitation_id_of(dir.path(), CAROL);
    assert_ne!(renewed, expired, "the expired invitation is replaced");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitation_rules WHERE invitation_id = {renewed}")
        ),
        0,
        "an invitation made after the expiry carries no rules of the expired one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_plan_refuses_unknown_ids() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    list_tool(dir.path(), alpha, "search");
    let alpha_text = alpha.to_string();
    invite_with(&mut owner, BOB, "user", &[alpha]).await;
    let invitation = invitation_id_of(dir.path(), BOB);

    let refused = invite_with(&mut owner, CAROL, "user", &[999]).await;
    assert_eq!(
        refused.status, 400,
        "an unknown server is refused on invite"
    );
    assert_eq!(
        refused.error().as_deref(),
        Some("The invitation was not sent. Choose only servers that exist.")
    );
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitations WHERE email = '{CAROL}'")
        ),
        0,
        "a refused invitation stores nothing"
    );

    let servers = plan_servers(&mut owner, invitation, &["999"]).await;
    assert_eq!(
        servers.status, 400,
        "an unknown server is refused on the plan"
    );
    assert_eq!(
        servers.error().as_deref(),
        Some("The servers were not saved. Choose only servers that exist.")
    );
    assert_eq!(
        ids_of(
            dir.path(),
            "SELECT server_id FROM invitation_servers WHERE invitation_id = ?1",
            invitation
        ),
        vec![alpha],
        "a refused set changes nothing"
    );

    // Each case: the posted fields, the Rules page message, and the link the notice adds.
    let cases = [
        (
            vec![("effect", "maybe"), ("scope", "all")],
            "Choose the effect allow or deny.",
            " Go to the effect field",
        ),
        (
            vec![("effect", "allow"), ("scope", "galaxy")],
            "Choose the scope all tools, one server or one tool.",
            "",
        ),
        (
            vec![
                ("effect", "allow"),
                ("scope", "server"),
                ("server_id", "999"),
            ],
            "A server or tool rule needs a server that exists.",
            " Go to the server field",
        ),
        (
            vec![
                ("effect", "allow"),
                ("scope", "tool"),
                ("server_id", alpha_text.as_str()),
                ("tool", "missing"),
            ],
            "The server's tool list has no tool with that name.",
            " Go to the tool name field",
        ),
        (
            vec![
                ("effect", "allow"),
                ("scope", "tool"),
                ("server_id", alpha_text.as_str()),
                ("tool", ""),
            ],
            "A tool rule needs the tool name.",
            " Go to the tool name field",
        ),
    ];
    for (fields, message, link) in cases {
        let answer = plan_rule(&mut owner, invitation, &fields).await;
        assert_eq!(answer.status, 400, "refused: {message}");
        assert_eq!(
            answer.error().as_deref(),
            Some(format!("The rule was not added. {message}{link}").as_str())
        );
    }
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        0
    );

    assert_eq!(owner.get("/admin/invitations/999999").await.status, 404);
    let unknown = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations/999999/servers",
            &[("server_id", "999")],
        )
        .await;
    assert_eq!(unknown.status, 404, "an unknown invitation has no servers");
    let unknown = owner
        .submit(
            "/admin/invitations",
            "/admin/invitations/999999/rules",
            &[("effect", "allow"), ("scope", "all")],
        )
        .await;
    assert_eq!(unknown.status, 404, "an unknown invitation has no rules");

    let carol = invite_with(&mut owner, CAROL, "user", &[]).await;
    let accepted_id = invitation_id_of(dir.path(), CAROL);
    assert_eq!(accept_link(&base, &carol).await.status, 303);
    assert_eq!(owner.get(&plan_path(accepted_id)).await.status, 404);
    let accepted = owner
        .submit(
            "/admin/invitations",
            &format!("{}/servers", plan_path(accepted_id)),
            &[("server_id", alpha_text.as_str())],
        )
        .await;
    assert_eq!(accepted.status, 404, "an accepted invitation has no plan");
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_plan_routes_refuse_anonymous_and_plain_users() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    add_user(dir.path(), PLAIN, "user").await;
    invite_with(&mut owner, BOB, "user", &[]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let planned = plan_rule(
        &mut owner,
        invitation,
        &[("effect", "deny"), ("scope", "all")],
    )
    .await;
    assert_eq!(planned.status, 303);
    let rule = ids_of(
        dir.path(),
        "SELECT id FROM invitation_rules WHERE invitation_id = ?1",
        invitation,
    )[0];
    let plan = plan_path(invitation);
    let alpha_text = alpha.to_string();
    let server_fields = [("server_id", alpha_text.as_str())];
    let rule_fields = [("effect", "allow"), ("scope", "all")];
    type Field<'a> = (&'a str, &'a str);
    let no_fields: [Field; 0] = [];
    // Each route with the fields its form posts; the plain user's posts carry a valid csrf token.
    let routes: [(bool, String, &[Field<'_>]); 4] = [
        (false, plan.clone(), &no_fields),
        (true, format!("{plan}/servers"), &server_fields),
        (true, format!("{plan}/rules"), &rule_fields),
        (true, format!("{plan}/rules/{rule}/delete"), &no_fields),
    ];
    let mut anonymous = Browser::new(&base);
    let mut plain = sign_in(&base, PLAIN).await;
    for (post, path, fields) in &routes {
        let answer = if *post {
            anonymous.post(path, fields).await
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
            plain.submit("/account", path, fields).await
        } else {
            plain.get(path).await
        };
        assert_eq!(answer.status, 403, "a plain user must be refused {path}");
        assert_eq!(answer.kind().as_deref(), Some("forbidden"));
    }
    for (_, path, fields) in &routes[1..] {
        let answer = owner.post(path, fields).await;
        assert_eq!(answer.status, 403, "a post without csrf is refused {path}");
    }
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_servers"),
        0
    );
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        1,
        "the refused posts change nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cannot_plan_an_admin_invitation() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let alpha_text = alpha.to_string();
    invite_with(&mut owner, CAROL, "admin", &[]).await;
    let invitation = invitation_id_of(dir.path(), CAROL);
    let planned = plan_rule(
        &mut owner,
        invitation,
        &[("effect", "deny"), ("scope", "all")],
    )
    .await;
    assert_eq!(planned.status, 303);
    let rule = ids_of(
        dir.path(),
        "SELECT id FROM invitation_rules WHERE invitation_id = ?1",
        invitation,
    )[0];
    let plan = plan_path(invitation);

    assert_eq!(
        admin.get(&plan).await.status,
        403,
        "an admin cannot open it"
    );
    let servers = admin
        .submit(
            "/admin/invitations",
            &format!("{plan}/servers"),
            &[("server_id", alpha_text.as_str())],
        )
        .await;
    assert_eq!(servers.status, 403, "an admin cannot set its servers");
    let rules = admin
        .submit(
            "/admin/invitations",
            &format!("{plan}/rules"),
            &[("effect", "allow"), ("scope", "all")],
        )
        .await;
    assert_eq!(rules.status, 403, "an admin cannot add a rule to it");
    let deleted = admin
        .submit(
            "/admin/invitations",
            &format!("{plan}/rules/{rule}/delete"),
            &[],
        )
        .await;
    assert_eq!(deleted.status, 403, "an admin cannot delete its rule");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        1,
        "the refused posts change nothing"
    );
    assert_eq!(owner.get(&plan).await.status, 200, "the owner can open it");
    assert_eq!(
        plan_servers(&mut owner, invitation, &[alpha_text.as_str()])
            .await
            .status,
        303,
        "the owner can set its servers"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reinviting_an_address_keeps_its_rules_and_takes_the_new_servers() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    for slug in ["alpha", "beta", "gamma"] {
        add(&mut owner, slug, SERVER_URL, None).await;
    }
    let alpha = server_id_of(dir.path(), "alpha");
    let beta = server_id_of(dir.path(), "beta");
    let gamma = server_id_of(dir.path(), "gamma");
    invite_with(&mut owner, BOB, "user", &[alpha]).await;
    let first = invitation_id_of(dir.path(), BOB);
    let planned = plan_rule(&mut owner, first, &[("effect", "deny"), ("scope", "all")]).await;
    assert_eq!(planned.status, 303);

    invite_with(&mut owner, BOB, "user", &[beta, gamma]).await;
    let second = invitation_id_of(dir.path(), BOB);
    assert_ne!(second, first, "the invitation is replaced");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitations WHERE id = {first}")
        ),
        0,
        "the old invitation is gone"
    );
    assert_eq!(
        ids_of(
            dir.path(),
            "SELECT server_id FROM invitation_servers WHERE invitation_id = ?1",
            second
        ),
        vec![beta, gamma],
        "the servers ticked in the new form"
    );
    assert_eq!(
        rule_triples(
            dir.path(),
            "SELECT effect, server_id, tool FROM invitation_rules WHERE invitation_id = ?1",
            second
        ),
        vec![("deny".to_owned(), None, None)],
        "the rules of the old invitation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_invitation_rule_is_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let alpha_text = alpha.to_string();
    invite_with(&mut owner, BOB, "user", &[]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let first = plan_rule(
        &mut owner,
        invitation,
        &[
            ("effect", "allow"),
            ("scope", "server"),
            ("server_id", alpha_text.as_str()),
        ],
    )
    .await;
    assert_eq!(first.status, 303);
    let second = plan_rule(
        &mut owner,
        invitation,
        &[
            ("effect", "deny"),
            ("scope", "server"),
            ("server_id", alpha_text.as_str()),
        ],
    )
    .await;
    assert_eq!(second.status, 400, "the same target twice is refused");
    assert_eq!(
        second.error().as_deref(),
        Some("The rule was not added. A rule for that subject and target already exists.")
    );
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        1,
        "the second rule is not stored"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_server_drops_it_from_plans() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    add(&mut owner, "beta", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let beta = server_id_of(dir.path(), "beta");
    invite_with(&mut owner, BOB, "user", &[alpha, beta]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let alpha_text = alpha.to_string();
    let planned = plan_rule(
        &mut owner,
        invitation,
        &[
            ("effect", "allow"),
            ("scope", "server"),
            ("server_id", alpha_text.as_str()),
        ],
    )
    .await;
    assert_eq!(planned.status, 303);

    let path = format!("/admin/servers/{alpha}");
    let deleted = owner.submit(&path, &format!("{path}/delete"), &[]).await;
    assert_eq!(deleted.status, 303, "the server is deleted");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitation_servers WHERE server_id = {alpha}")
        ),
        0
    );
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitation_rules WHERE server_id = {alpha}")
        ),
        0
    );
    assert_eq!(
        ids_of(
            dir.path(),
            "SELECT server_id FROM invitation_servers WHERE invitation_id = ?1",
            invitation
        ),
        vec![beta],
        "the other server stays in the plan"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plan_page_uses_the_panel_layout_like_the_user_page() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), PLAIN, "user").await;
    let plain = user_id_of(dir.path(), PLAIN);
    invite_with(&mut owner, BOB, "user", &[]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let plan = plan_path(invitation);
    let user = owner.get(&format!("/admin/users/{plain}")).await;
    let layout = |body: &str| attr_of(body, "body", "data-layout");
    assert_eq!(layout(&user.body).as_deref(), Some("panel"));
    let page = owner.get(&plan).await;
    assert_eq!(page.status, 200);
    assert_eq!(
        layout(&page.body),
        layout(&user.body),
        "the plan page must use the panel layout of the user page"
    );
    assert_eq!(
        attr_of(&page.body, "main", "data-page").as_deref(),
        Some("invitations"),
        "the plan page is data-page invitations, as docs/INTERFACE.md says"
    );
    assert_eq!(
        text_of(
            &page.body,
            r#"section[aria-labelledby="plan-revoke-title"] .part-head > p"#
        )
        .as_deref(),
        Some("Their link stops working and this plan is deleted."),
        "the Revoke section says what revoking does"
    );
    let refused = plan_rule(
        &mut owner,
        invitation,
        &[("effect", "maybe"), ("scope", "all")],
    )
    .await;
    assert_eq!(refused.status, 400);
    assert_eq!(
        layout(&refused.body),
        layout(&user.body),
        "the refused plan page keeps the panel layout"
    );
    assert_eq!(
        elements(
            &page.body,
            r#"details[data-confirm] form[action$="/revoke"]"#
        )
        .len(),
        1,
        "revoke sits in a confirm disclosure at the foot of the page"
    );
}

/// The role of the invitation of `email`, as stored.
fn role_of_invitation(dir: &Path, email: &str) -> String {
    open_db(dir)
        .query_row(
            "SELECT role FROM invitations WHERE email = ?1",
            [email],
            |row| row.get(0),
        )
        .expect("the invitation exists")
}

#[tokio::test(flavor = "multi_thread")]
async fn reinviting_with_another_role_carries_no_rules() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let alpha_text = alpha.to_string();

    invite_with(&mut owner, CAROL, "admin", &[]).await;
    let as_admin = invitation_id_of(dir.path(), CAROL);
    let planned = plan_rule(
        &mut owner,
        as_admin,
        &[("effect", "deny"), ("scope", "all")],
    )
    .await;
    assert_eq!(planned.status, 303);
    invite_with(&mut owner, CAROL, "user", &[]).await;
    let as_user = invitation_id_of(dir.path(), CAROL);
    assert_ne!(as_user, as_admin, "the invitation is replaced");
    assert_eq!(role_of_invitation(dir.path(), CAROL), "user");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitation_rules WHERE invitation_id = {as_user}")
        ),
        0,
        "an admin invitation's rule is not carried to a user invitation"
    );

    let planned = plan_rule(
        &mut owner,
        as_user,
        &[
            ("effect", "allow"),
            ("scope", "server"),
            ("server_id", alpha_text.as_str()),
        ],
    )
    .await;
    assert_eq!(planned.status, 303);
    invite_with(&mut owner, CAROL, "admin", &[]).await;
    let back_as_admin = invitation_id_of(dir.path(), CAROL);
    assert_eq!(role_of_invitation(dir.path(), CAROL), "admin");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitation_rules WHERE invitation_id = {back_as_admin}")
        ),
        0,
        "a user invitation's rule is not carried to an admin invitation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cannot_revoke_or_replace_an_admin_invitation() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    invite_with(&mut owner, CAROL, "admin", &[]).await;
    let invitation = invitation_id_of(dir.path(), CAROL);
    let planned = plan_rule(
        &mut owner,
        invitation,
        &[("effect", "deny"), ("scope", "all")],
    )
    .await;
    assert_eq!(planned.status, 303);

    let revoked = admin
        .submit(
            "/admin/invitations",
            &format!("{}/revoke", plan_path(invitation)),
            &[],
        )
        .await;
    assert_eq!(
        revoked.status, 403,
        "an admin cannot revoke an admin invitation"
    );
    assert_eq!(revoked.kind().as_deref(), Some("forbidden"));
    let replaced = admin
        .submit(
            "/admin/invitations",
            "/admin/invitations",
            &[("email", CAROL), ("role", "user")],
        )
        .await;
    assert_eq!(
        replaced.status, 403,
        "an admin cannot replace an admin invitation"
    );
    assert_eq!(replaced.kind().as_deref(), Some("forbidden"));
    assert_eq!(
        invitation_id_of(dir.path(), CAROL),
        invitation,
        "the owner's invitation stays"
    );
    assert_eq!(role_of_invitation(dir.path(), CAROL), "admin");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        1,
        "the plan stays"
    );

    invite_with(&mut owner, CAROL, "admin", &[]).await;
    let replaced_by_owner = invitation_id_of(dir.path(), CAROL);
    assert_ne!(replaced_by_owner, invitation, "the owner can replace it");
    let revoked = owner
        .submit(
            "/admin/invitations",
            &format!("{}/revoke", plan_path(replaced_by_owner)),
            &[],
        )
        .await;
    assert_eq!(revoked.status, 303, "the owner can revoke it");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitations WHERE email = '{CAROL}'")
        ),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_can_plan_a_user_invitation() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let alpha_text = alpha.to_string();
    invite_with(&mut owner, BOB, "user", &[]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let plan = plan_path(invitation);

    assert_eq!(admin.get(&plan).await.status, 200, "an admin opens it");
    let servers = admin
        .submit(
            "/admin/invitations",
            &format!("{plan}/servers"),
            &[("server_id", alpha_text.as_str())],
        )
        .await;
    assert_eq!(servers.status, 303, "an admin sets its servers");
    let added = admin
        .submit(
            "/admin/invitations",
            &format!("{plan}/rules"),
            &[
                ("effect", "deny"),
                ("scope", "server"),
                ("server_id", alpha_text.as_str()),
            ],
        )
        .await;
    assert_eq!(added.status, 303, "an admin adds a rule");
    let rule = ids_of(
        dir.path(),
        "SELECT id FROM invitation_rules WHERE invitation_id = ?1",
        invitation,
    )[0];
    let deleted = admin
        .submit(
            "/admin/invitations",
            &format!("{plan}/rules/{rule}/delete"),
            &[],
        )
        .await;
    assert_eq!(deleted.status, 303, "an admin deletes the rule");
    assert_eq!(
        count(dir.path(), "SELECT COUNT(*) FROM invitation_rules"),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_failure_leaves_no_account() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let invite = invite_with(&mut owner, BOB, "user", &[alpha]).await;
    let invitation = invitation_id_of(dir.path(), BOB);
    let planned = plan_rule(
        &mut owner,
        invitation,
        &[("effect", "deny"), ("scope", "all")],
    )
    .await;
    assert_eq!(planned.status, 303);
    // Makes the copy of the plan fail after the account row is written.
    open_db(dir.path())
        .execute_batch(
            "CREATE TRIGGER refuse_plan_copy BEFORE INSERT ON rules \
             BEGIN SELECT RAISE(ABORT, 'plan copy refused'); END;",
        )
        .expect("the trigger");
    let accepted = accept_link(&base, &invite).await;
    assert_eq!(accepted.status, 500, "a failed accept is an internal error");
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM users WHERE email = '{BOB}'")
        ),
        0,
        "no account is created"
    );
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM user_servers"), 0);
    assert_eq!(count(dir.path(), "SELECT COUNT(*) FROM rules"), 0);
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitations WHERE id = {invitation}")
        ),
        1,
        "the invitation stays"
    );
    assert_eq!(
        ids_of(
            dir.path(),
            "SELECT server_id FROM invitation_servers WHERE invitation_id = ?1",
            invitation
        ),
        vec![alpha],
        "its servers stay"
    );
    assert_eq!(
        count(
            dir.path(),
            &format!("SELECT COUNT(*) FROM invitation_rules WHERE invitation_id = {invitation}")
        ),
        1,
        "its rules stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_form_servers_are_recorded() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    add(&mut owner, "alpha", SERVER_URL, None).await;
    add(&mut owner, "gamma", SERVER_URL, None).await;
    let alpha = server_id_of(dir.path(), "alpha");
    let gamma = server_id_of(dir.path(), "gamma");
    invite_with(&mut owner, BOB, "user", &[alpha, gamma]).await;
    assert_eq!(
        rows_of(dir.path(), "admin_change")
            .iter()
            .map(|row| row.2.as_str())
            .filter(|detail| detail.contains("bob@example.com"))
            .collect::<Vec<_>>(),
        ["invitation servers of bob@example.com set to 2 servers"],
        "the servers ticked on the invite form are recorded"
    );
    assert_eq!(
        rows_of(dir.path(), "invitation")
            .iter()
            .map(|row| row.2.as_str())
            .collect::<Vec<_>>(),
        ["invited bob@example.com as user"],
        "the invited row is unchanged"
    );
    invite_with(&mut owner, CAROL, "user", &[]).await;
    assert_eq!(
        rows_of(dir.path(), "admin_change")
            .iter()
            .filter(|row| row.2.contains("carol@example.com"))
            .count(),
        0,
        "an invitation with no servers records no server change"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invite_form_note_says_to_restrict_tools_first() {
    let dir = tempfile::tempdir().expect("dir");
    let (_base, mut owner) = owner_gateway(dir.path()).await;
    let page = owner.get("/admin/invitations").await;
    assert_eq!(
        text_of(&page.body, "#invite-servers-hint").as_deref(),
        Some(
            "What they can reach as soon as they accept. To restrict tools first, send the invitation with no servers, then set rules and servers on its page."
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_viewer_gets_no_link_to_an_admin_invitation() {
    let dir = tempfile::tempdir().expect("dir");
    let (base, mut owner) = owner_gateway(dir.path()).await;
    add_user(dir.path(), ADMIN, "admin").await;
    let mut admin = sign_in(&base, ADMIN).await;
    invite_with(&mut owner, CAROL, "admin", &[]).await;
    let as_admin = plan_path(invitation_id_of(dir.path(), CAROL));
    invite_with(&mut owner, BOB, "user", &[]).await;
    let as_user = plan_path(invitation_id_of(dir.path(), BOB));
    let seen_by_admin = admin.get("/admin/invitations").await;
    assert_eq!(
        attr_of(
            &seen_by_admin.body,
            &format!(r#"a[href="{as_user}"]"#),
            "href"
        )
        .as_deref(),
        Some(as_user.as_str()),
        "an admin still gets the link to a user invitation"
    );
    assert!(
        attr_of(
            &seen_by_admin.body,
            &format!(r#"a[href="{as_admin}"]"#),
            "href"
        )
        .is_none(),
        "an admin gets no link to an admin invitation"
    );
    assert!(
        seen_by_admin.body.contains(CAROL),
        "the address is still shown"
    );
    let seen_by_owner = owner.get("/admin/invitations").await;
    assert_eq!(
        attr_of(
            &seen_by_owner.body,
            &format!(r#"a[href="{as_admin}"]"#),
            "href"
        )
        .as_deref(),
        Some(as_admin.as_str()),
        "the owner gets the link to an admin invitation"
    );
}
