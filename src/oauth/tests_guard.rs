//! The bearer guard, the account list and the disconnect pages over real HTTP. The helpers follow
//! `tests_token.rs`; the database is read directly for what HTTP does not show.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue};
use form_urlencoded::Serializer;
use rusqlite::{Connection, params};
use scraper::{Html, Selector};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::accounts::session;
use crate::app::{AppState, Deps, assemble, serve};
use crate::cimd::UnavailableCimd;
use crate::clock::Clock;
use crate::config::{Config, Lifetimes, Limits};
use crate::crypto::{Keys, PasswordHasher, random_token, token_hash};
use crate::db::Db;
use crate::web::SESSION_COOKIE;

use super::families::{self, NewFamily};
use super::guard::{
    Caller, Recheck, Refusal, Target, bearer_token, check, combined_still_valid, is_token_shape,
    still_valid,
};

/// The fixed instant every test starts at, in unix seconds.
const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const SESSION_SECONDS: i64 = 10 * DAY;
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const FORM: &str = "application/x-www-form-urlencoded";
const CLIENT: &str = "Example Client";
const JSON_TYPE: &str = "application/json";

/// A clock the test moves by hand; it starts at `NOW`.
struct SetClock(AtomicI64);

impl SetClock {
    fn set(&self, at: i64) {
        self.0.store(at, Ordering::SeqCst);
    }
}

impl Clock for SetClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("instant")
    }
}

/// A started gateway with its database path and its clock.
struct Gateway {
    base: String,
    db: PathBuf,
    clock: Arc<SetClock>,
    _dir: TempDir,
}

impl Gateway {
    async fn start() -> Gateway {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = dir.path().join("doorward.db");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let base = format!("http://{address}");
        let config = Config {
            public_url: base.clone(),
            listen: address,
            database: db.clone(),
            key_file: None,
            trusted_proxies: Vec::new(),
            shared_client_address: false,
            allowed_origins: Vec::new(),
            lifetimes: Lifetimes::default(),
            limits: Limits::default(),
            mail: Default::default(),
        };
        let clock = Arc::new(SetClock(AtomicI64::new(NOW)));
        let deps = Deps {
            clock: clock.clone(),
            cimd: Arc::new(UnavailableCimd),
        };
        let hasher = PasswordHasher::new().await.expect("hasher");
        let gateway = assemble(config, deps, Arc::new(hasher))
            .await
            .expect("build");
        tokio::spawn(serve(listener, gateway.router, std::future::pending()));
        Gateway {
            base,
            db,
            clock,
            _dir: dir,
        }
    }

    fn http(&self) -> Http {
        Http::new(&self.base)
    }

    fn conn(&self) -> Connection {
        let conn = Connection::open(&self.db).expect("connection");
        conn.busy_timeout(Duration::from_secs(5)).expect("timeout");
        conn
    }
}

/// One integer read from the database.
fn scalar(gw: &Gateway, sql: &str, values: impl rusqlite::Params) -> i64 {
    gw.conn()
        .query_row(sql, values, |row| row.get(0))
        .expect("scalar")
}

fn revoked(gw: &Gateway, family: i64) -> bool {
    scalar(
        gw,
        "SELECT revoked_at IS NOT NULL FROM token_families WHERE id = ?1",
        params![family],
    ) == 1
}

fn activity_count(gw: &Gateway, kind: &str) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM activity WHERE kind = ?1",
        params![kind],
    )
}

fn add_user(gw: &Gateway, email: &str, role: &str) -> i64 {
    let conn = gw.conn();
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', ?2, 0)",
        params![email, role],
    )
    .expect("user");
    conn.last_insert_rowid()
}

/// A user assigned to every server of `servers`.
fn user_with(gw: &Gateway, email: &str, servers: &[i64]) -> i64 {
    let user = add_user(gw, email, "user");
    for server in servers {
        assign(gw, user, *server);
    }
    user
}

fn add_server(gw: &Gateway, slug: &str) -> i64 {
    let conn = gw.conn();
    conn.execute(
        "INSERT INTO servers (name, slug, upstream_url, created_at) \
         VALUES (?1, ?1, 'http://127.0.0.1:9', 0)",
        params![slug],
    )
    .expect("server");
    conn.last_insert_rowid()
}

fn assign(gw: &Gateway, user_id: i64, server_id: i64) {
    gw.conn()
        .execute(
            "INSERT INTO user_servers (user_id, server_id) VALUES (?1, ?2)",
            params![user_id, server_id],
        )
        .expect("assignment");
}

/// A family and its pair, made the way the token endpoint makes them.
struct Issued {
    family: i64,
    public_id: String,
    access: String,
    refresh: String,
}

fn issue(gw: &Gateway, user_id: i64, server_id: Option<i64>, client_name: &str) -> Issued {
    let conn = gw.conn();
    let epoch: i64 = conn
        .query_row(
            "SELECT auth_epoch FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .expect("epoch");
    let new = NewFamily {
        user_id,
        server_id,
        client_id: "dcr_test",
        client_name,
        auth_epoch: epoch,
    };
    let family = families::create(&conn, &new, NOW, 90).expect("family");
    let pair = families::mint_pair(&conn, family, NOW, &Lifetimes::default()).expect("pair");
    let public_id: String = conn
        .query_row(
            "SELECT public_id FROM token_families WHERE id = ?1",
            params![family],
            |row| row.get(0),
        )
        .expect("public id");
    Issued {
        family,
        public_id,
        access: pair.access_token,
        refresh: pair.refresh_token,
    }
}

/// Inserts a disconnect link for `family` and returns its text.
fn add_link(gw: &Gateway, family: i64) -> String {
    let token = random_token("dw_dl_");
    gw.conn()
        .execute(
            "INSERT INTO disconnect_links (token_hash, family_id, created_at) VALUES (?1, ?2, ?3)",
            params![token_hash(&token), family, NOW],
        )
        .expect("link");
    token
}

/// The challenge of a refused request that presented a token, for `slug`.
fn invalid_challenge(base: &str, slug: &str) -> String {
    format!(
        r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/{slug}", scope="mcp", error="invalid_token""#
    )
}

/// The challenge of a refused request that presented no token, for `slug`.
fn plain_challenge(base: &str, slug: &str) -> String {
    format!(
        r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/{slug}", scope="mcp""#
    )
}

/// The status, headers and body of one answer. Every header is kept, in order.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    set_cookies: Vec<(String, String)>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }

    /// Everything a client sees except the date, which the server stamps.
    fn answer(&self) -> (u16, Vec<(String, String)>, String) {
        let headers = self
            .headers
            .iter()
            .filter(|(key, _)| key != "date")
            .cloned()
            .collect();
        (self.status, headers, self.body.clone())
    }

    fn attr(&self, css: &str, name: &str) -> Option<String> {
        self.attrs(css, name).into_iter().next()
    }

    fn attrs(&self, css: &str, name: &str) -> Vec<String> {
        let doc = Html::parse_document(&self.body);
        let selector = Selector::parse(css).expect("selector");
        doc.select(&selector)
            .filter_map(|element| element.value().attr(name).map(str::to_owned))
            .collect()
    }

    /// The `data-page` of the main element, or None.
    fn kind(&self) -> Option<String> {
        self.attr("main", "data-page")
    }

    fn csrf(&self) -> String {
        self.attr(r#"input[name="csrf"]"#, "value")
            .expect("the page carries a csrf token")
    }
}

/// A client that sends only the headers it is given, and reads every answer in full.
struct Http {
    base: String,
    client: reqwest::Client,
}

impl Http {
    fn new(base: &str) -> Http {
        Http {
            base: base.to_owned(),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: Vec<(&str, String)>,
        body: Option<String>,
    ) -> Reply {
        let mut builder = self.client.request(method, format!("{}{path}", self.base));
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }
        let response = builder.send().await.expect("request");
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let set_cookies = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(cookie_pair)
            .collect();
        let body = response.text().await.expect("body");
        Reply {
            status,
            headers,
            body,
            set_cookies,
        }
    }

    /// A GET or POST with `Authorization: Bearer <token>`.
    async fn bearer(&self, method: reqwest::Method, path: &str, token: &str) -> Reply {
        let headers = vec![("authorization", format!("Bearer {token}"))];
        self.request(method, path, headers, None).await
    }
}

/// The name and value of a Set-Cookie line.
fn cookie_pair(line: &str) -> Option<(String, String)> {
    let pair = line.split(';').next()?;
    let (name, value) = pair.split_once('=')?;
    Some((name.trim().to_owned(), value.trim().to_owned()))
}

fn form_body(fields: &[(&str, &str)]) -> String {
    let mut body = Serializer::new(String::new());
    body.extend_pairs(fields);
    body.finish()
}

/// A browser: it keeps the cookies the gateway sets and sends them back.
struct Browser {
    http: Http,
    jar: Mutex<Vec<(String, String)>>,
}

impl Browser {
    fn new(gw: &Gateway) -> Browser {
        Browser {
            http: gw.http(),
            jar: Mutex::new(Vec::new()),
        }
    }

    /// A browser signed in as `user_id`.
    fn signed_in(gw: &Gateway, user_id: i64) -> Browser {
        let browser = Browser::new(gw);
        let token = session::insert(&gw.conn(), user_id, NOW, SESSION_SECONDS).expect("session");
        browser
            .jar
            .lock()
            .expect("jar")
            .push((SESSION_COOKIE.to_owned(), token));
        browser
    }

    fn cookie_header(&self) -> Vec<(&'static str, String)> {
        let jar = self.jar.lock().expect("jar");
        if jar.is_empty() {
            return Vec::new();
        }
        let text: Vec<String> = jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        vec![("cookie", text.join("; "))]
    }

    fn keep(&self, reply: &Reply) {
        let mut jar = self.jar.lock().expect("jar");
        for (name, value) in &reply.set_cookies {
            jar.retain(|(key, _)| key != name);
            jar.push((name.clone(), value.clone()));
        }
    }

    async fn get(&self, path: &str) -> Reply {
        let reply = self
            .http
            .request(reqwest::Method::GET, path, self.cookie_header(), None)
            .await;
        self.keep(&reply);
        reply
    }

    async fn post(&self, path: &str, fields: &[(&str, &str)]) -> Reply {
        let mut headers = self.cookie_header();
        headers.push(("origin", self.http.base.clone()));
        headers.push(("content-type", FORM.to_owned()));
        let body = form_body(fields);
        let reply = self
            .http
            .request(reqwest::Method::POST, path, headers, Some(body))
            .await;
        self.keep(&reply);
        reply
    }
}

/// A page that shows a client name shows it escaped, never as markup.
fn assert_escaped(body: &str, what: &str) {
    assert!(
        !body.contains("<b>"),
        "{what} must not carry the raw client name"
    );
    assert!(
        body.contains("&lt;b&gt;Evil"),
        "{what} must show the client name escaped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_refusal_is_the_same_answer() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let other = add_server(&gw, "other");
    let mut cases: Vec<(&str, &str, String)> = Vec::new();

    let user = user_with(&gw, "a@example.com", &[demo]);
    cases.push((
        "no server with that slug",
        "/ghost",
        issue(&gw, user, Some(demo), CLIENT).access,
    ));

    let user = user_with(&gw, "b@example.com", &[demo, other]);
    cases.push((
        "a server the family is not for",
        "/demo",
        issue(&gw, user, Some(other), CLIENT).access,
    ));

    let user = add_user(&gw, "c@example.com", "user");
    cases.push((
        "an unassigned pair",
        "/demo",
        issue(&gw, user, Some(demo), CLIENT).access,
    ));

    let user = user_with(&gw, "d@example.com", &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    gw.conn()
        .execute(
            "UPDATE access_tokens SET expires_at = ?1 WHERE family_id = ?2",
            params![NOW, issued.family],
        )
        .expect("expire the access token");
    cases.push(("an expired access token", "/demo", issued.access));

    let user = user_with(&gw, "e@example.com", &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    families::revoke(&gw.conn(), issued.family, NOW).expect("revoke");
    cases.push(("a revoked family", "/demo", issued.access));

    let user = user_with(&gw, "f@example.com", &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    gw.conn()
        .execute(
            "UPDATE token_families SET expires_at = ?1 WHERE id = ?2",
            params![NOW, issued.family],
        )
        .expect("expire the family");
    cases.push(("an expired family", "/demo", issued.access));

    let user = user_with(&gw, "g@example.com", &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    gw.conn()
        .execute("UPDATE users SET disabled = 1 WHERE id = ?1", params![user])
        .expect("disable");
    cases.push(("a disabled user", "/demo", issued.access));

    let user = user_with(&gw, "h@example.com", &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    session::revoke_all(&gw.conn(), user).expect("reset");
    cases.push(("a bumped epoch", "/demo", issued.access));

    let user = user_with(&gw, "i@example.com", &[demo]);
    cases.push((
        "a combined token on a server path",
        "/demo",
        issue(&gw, user, None, CLIENT).access,
    ));

    let user = user_with(&gw, "j@example.com", &[demo]);
    cases.push((
        "a server token on the combined path",
        "/mcp",
        issue(&gw, user, Some(demo), CLIENT).access,
    ));

    let user = user_with(&gw, "k@example.com", &[demo]);
    cases.push((
        "a token of the wrong shape",
        "/demo",
        issue(&gw, user, Some(demo), CLIENT).refresh,
    ));

    let user = user_with(&gw, "l@example.com", &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    gw.conn()
        .execute(
            "UPDATE token_families SET revoked_at = ?1 WHERE id = ?2",
            params![NOW, issued.family],
        )
        .expect("mark revoked");
    cases.push((
        "a family marked revoked whose token rows remain",
        "/demo",
        issued.access,
    ));

    cases.push(("a token never issued", "/demo", random_token("dw_at_")));

    let http = gw.http();
    for method in [
        reqwest::Method::GET,
        reqwest::Method::POST,
        reqwest::Method::DELETE,
    ] {
        for (label, path, token) in &cases {
            let reference = http
                .bearer(method.clone(), path, &random_token("dw_at_"))
                .await;
            let slug = path.trim_start_matches('/');
            assert_eq!(reference.status, 401, "{method} {path} must refuse");
            assert_eq!(
                reference.header("www-authenticate"),
                Some(invalid_challenge(&gw.base, slug)),
                "{method} {path} must carry error=invalid_token"
            );
            let reply = http.bearer(method.clone(), path, token).await;
            assert_eq!(
                reply.answer(),
                reference.answer(),
                "{method} {path}: {label} must answer exactly like a token never issued"
            );
            assert_eq!(reply.body, "", "{label} must have an empty body");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_that_passes_reaches_the_handler() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let server = issue(&gw, user, Some(demo), CLIENT);
    let combined = issue(&gw, user, None, CLIENT);
    let http = gw.http();
    let reply = http
        .bearer(reqwest::Method::GET, "/demo", &server.access)
        .await;
    assert_eq!(
        reply.status, 405,
        "GET /demo without a session must be answered 405 by the handler"
    );
    assert_eq!(
        reply.header("allow").as_deref(),
        Some("POST"),
        "the 405 names the allowed method"
    );
    let reply = http
        .request(
            reqwest::Method::POST,
            "/demo",
            vec![
                ("authorization", format!("Bearer {}", server.access)),
                ("content-type", JSON_TYPE.to_owned()),
            ],
            Some(String::new()),
        )
        .await;
    assert_eq!(
        reply.status, 400,
        "POST /demo with an empty body must be refused by the handler"
    );
    assert_eq!(
        reply.body,
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#,
        "the empty body is a parse error"
    );
    let reply = http
        .bearer(reqwest::Method::DELETE, "/demo", &server.access)
        .await;
    assert_eq!(
        reply.status, 405,
        "DELETE /demo without a session must be answered 405 by the handler"
    );
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let reply = http.bearer(method.clone(), "/mcp", &combined.access).await;
        assert_eq!(reply.status, 405, "{method} /mcp must be answered 405");
    }
    let reply = http
        .request(
            reqwest::Method::POST,
            "/mcp",
            vec![
                ("authorization", format!("Bearer {}", combined.access)),
                ("content-type", JSON_TYPE.to_owned()),
            ],
            Some(String::new()),
        )
        .await;
    assert_eq!(
        reply.status, 400,
        "POST /mcp with an empty body must be refused by the handler"
    );
    assert_eq!(
        reply.body,
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#,
        "the empty body is a parse error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_authorization_header_is_refused_without_the_invalid_token_text() {
    let gw = Gateway::start().await;
    let http = gw.http();
    for path in ["/demo", "/mcp"] {
        let slug = path.trim_start_matches('/');
        let reply = http
            .request(reqwest::Method::GET, path, Vec::new(), None)
            .await;
        assert_eq!(reply.status, 401, "{path} with no token must refuse");
        assert_eq!(reply.body, "", "the refusal has an empty body");
        assert_eq!(
            reply.header("www-authenticate"),
            Some(plain_challenge(&gw.base, slug)),
            "{path} without a token must not say invalid_token"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn any_authorization_header_makes_the_refusal_invalid_token() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let http = gw.http();
    let valid = format!("Bearer {}", issued.access);
    let cases = [
        vec![
            ("authorization", valid.clone()),
            ("authorization", valid.clone()),
        ],
        vec![("authorization", "Basic dXNlcjpwYXNz".to_owned())],
        vec![("authorization", "Bearer".to_owned())],
        vec![("authorization", "Bearer dw_at_garbage".to_owned())],
        vec![
            ("authorization", "Basic dXNlcjpwYXNz".to_owned()),
            ("authorization", valid.clone()),
        ],
    ];
    for headers in cases {
        let label = headers[0].1.clone();
        let reply = http
            .request(reqwest::Method::GET, "/demo", headers, None)
            .await;
        assert_eq!(reply.status, 401, "{label:?} must refuse");
        assert_eq!(reply.body, "", "{label:?} has an empty body");
        assert_eq!(
            reply.header("www-authenticate"),
            Some(invalid_challenge(&gw.base, "demo")),
            "{label:?} must say invalid_token"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_is_any_case_and_the_spacing_is_exact() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let http = gw.http();
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let headers = vec![("authorization", format!("{scheme} {}", issued.access))];
        let reply = http
            .request(reqwest::Method::GET, "/demo", headers, None)
            .await;
        assert_eq!(
            reply.status, 405,
            "{scheme} with a valid token must be accepted"
        );
    }
    // A trailing space never reaches the guard: the HTTP parser removes it first, so it is
    // covered by `bearer_token_reads_one_exact_value` instead.
    for value in [
        format!("Bearer  {}", issued.access),
        format!("Bearer\t{}", issued.access),
    ] {
        let headers = vec![("authorization", value.clone())];
        let reply = http
            .request(reqwest::Method::GET, "/demo", headers, None)
            .await;
        assert_eq!(reply.status, 401, "{value:?} must be refused");
        assert_eq!(
            reply.header("www-authenticate"),
            Some(invalid_challenge(&gw.base, "demo")),
            "{value:?} must say invalid_token"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_challenge_comes_from_the_configuration_not_the_request() {
    let gw = Gateway::start().await;
    let http = gw.http();
    let spoofed = vec![
        ("host", "evil.example.com".to_owned()),
        ("x-forwarded-host", "evil.example.com".to_owned()),
        ("x-forwarded-proto", "https".to_owned()),
    ];
    for (path, slug) in [("/demo", "demo"), ("/mcp", "mcp")] {
        let reply = http
            .request(reqwest::Method::GET, path, spoofed.clone(), None)
            .await;
        assert_eq!(
            reply.status, 401,
            "{path} must refuse a request with no token"
        );
        assert_eq!(
            reply.header("www-authenticate"),
            Some(plain_challenge(&gw.base, slug)),
            "{path} must name the configured address and its own slug"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_in_the_query_or_a_cookie_is_never_read() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let http = gw.http();
    let query = format!("/demo?access_token={}", issued.access);
    let reply = http
        .request(reqwest::Method::GET, &query, Vec::new(), None)
        .await;
    assert_eq!(
        reply.status, 401,
        "a token in the query string must not open the path"
    );
    assert_eq!(
        reply.header("www-authenticate"),
        Some(plain_challenge(&gw.base, "demo")),
        "a query token leaves no invalid_token text, since no header was sent"
    );
    let cookies = vec![(
        "cookie",
        format!(
            "access_token={}; __Host-doorward_session={}",
            issued.access, issued.access
        ),
    )];
    let reply = http
        .request(reqwest::Method::GET, "/demo", cookies, None)
        .await;
    assert_eq!(
        reply.status, 401,
        "a token in a cookie must not open the path"
    );
    assert_eq!(
        reply.header("www-authenticate"),
        Some(plain_challenge(&gw.base, "demo")),
        "a cookie token leaves no invalid_token text"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn paths_that_are_not_slugs_are_plain_404s() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let http = gw.http();
    let paths = [
        "/Bad_Slug",
        "/oauth",
        "/a/b",
        "/demo/extra",
        "/mcp/extra",
        "/-",
        "/robots.txt",
        "/invite",
    ];
    for path in paths {
        for headers in [
            Vec::new(),
            vec![("authorization", format!("Bearer {}", issued.access))],
        ] {
            let reply = http
                .request(reqwest::Method::GET, path, headers, None)
                .await;
            assert_eq!(reply.status, 404, "{path} must be a plain 404");
            assert_eq!(reply.body, "", "{path} has an empty 404");
            assert_eq!(
                reply.header("www-authenticate"),
                None,
                "{path} must carry no challenge"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_routes_still_answer() {
    let gw = Gateway::start().await;
    let http = gw.http();
    let health = http
        .request(reqwest::Method::GET, "/healthz", Vec::new(), None)
        .await;
    assert_eq!(health.status, 200, "/healthz must answer 200");
    let login = http
        .request(reqwest::Method::GET, "/login", Vec::new(), None)
        .await;
    assert_eq!(login.status, 200, "/login must answer 200");
    let account = Browser::new(&gw).get("/account").await;
    assert_eq!(account.status, 303, "/account must send a visitor away");
    assert_eq!(account.header("location").as_deref(), Some("/login"));
    let css = http
        .request(
            reqwest::Method::GET,
            "/assets/doorward.css",
            Vec::new(),
            None,
        )
        .await;
    assert_eq!(css.status, 200, "the stylesheet must still be served");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_account_disconnect_is_a_no_op() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, bob, Some(demo), CLIENT);
    let browser = Browser::signed_in(&gw, bob);
    let csrf = browser.get("/account").await.csrf();
    let path = format!("/account/clients/{}/disconnect", issued.public_id);
    let first = browser.post(&path, &[("csrf", csrf.as_str())]).await;
    assert_eq!(first.status, 303, "the first disconnect must answer 303");
    let revoked_at = || {
        scalar(
            &gw,
            "SELECT revoked_at FROM token_families WHERE id = ?1",
            params![issued.family],
        )
    };
    assert_eq!(revoked_at(), NOW, "the first disconnect revokes at once");
    gw.clock.set(NOW + 60);
    let second = browser.post(&path, &[("csrf", csrf.as_str())]).await;
    assert_eq!(
        second.status, 303,
        "a repeated disconnect must answer 303, not an error"
    );
    assert_eq!(second.header("location").as_deref(), Some("/account"));
    assert_eq!(revoked_at(), NOW, "revoked_at keeps its first value");
    assert_eq!(
        activity_count(&gw, "client_disconnected"),
        1,
        "the disconnect is recorded once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_password_change_still_lists_the_connected_clients() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, bob, Some(demo), CLIENT);
    let browser = Browser::signed_in(&gw, bob);
    let csrf = browser.get("/account").await.csrf();
    let wrong = browser
        .post(
            "/account/password",
            &[
                ("csrf", csrf.as_str()),
                ("current_password", "not-the-password"),
                ("new_password", "a-new-password-12"),
            ],
        )
        .await;
    assert_eq!(
        wrong.status, 400,
        "a wrong current password must answer 400"
    );
    assert_eq!(
        wrong.attrs("[data-family]", "data-family"),
        vec![issued.public_id.clone()],
        "the refused page must still list the live family"
    );
    let short = browser
        .post(
            "/account/password",
            &[
                ("csrf", csrf.as_str()),
                ("current_password", "not-the-password"),
                ("new_password", "short"),
            ],
        )
        .await;
    assert_eq!(short.status, 400, "a short new password must answer 400");
    assert_eq!(
        short.attrs("[data-family]", "data-family"),
        vec![issued.public_id],
        "a short password must also keep the list"
    );
}

/// The header value as the guard sees it, built without the HTTP parser so that a trailing space
/// survives.
#[test]
fn bearer_token_reads_one_exact_value() {
    let token = format!("dw_at_{}", "a".repeat(43));
    let header = |value: String| {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_str(&value).expect("value"));
        headers
    };
    assert_eq!(
        bearer_token(&header(format!("Bearer {token}"))),
        Some(token.as_str())
    );
    assert_eq!(
        bearer_token(&header(format!("bearer {token}"))),
        Some(token.as_str())
    );
    assert_eq!(
        bearer_token(&header(format!("BEARER {token}"))),
        Some(token.as_str())
    );
    for refused in [
        format!("Bearer {token} "),
        format!("Bearer  {token}"),
        format!("Bearer\t{token}"),
        format!("Bearer {token}x"),
        format!("Basic {token}"),
        format!("Bearer{token}"),
    ] {
        assert_eq!(
            bearer_token(&header(refused.clone())),
            None,
            "{refused:?} must be refused"
        );
    }
    let mut twice = header(format!("Bearer {token}"));
    twice.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("value"),
    );
    assert_eq!(
        bearer_token(&twice),
        None,
        "two Authorization headers must be refused"
    );
    assert_eq!(
        bearer_token(&HeaderMap::new()),
        None,
        "no header is no token"
    );
}

#[test]
fn the_token_shape_is_exact() {
    let body = "a".repeat(43);
    assert!(is_token_shape(&format!("dw_at_{body}"), "dw_at_"));
    assert!(!is_token_shape(
        &format!("dw_at_{}", "a".repeat(42)),
        "dw_at_"
    ));
    assert!(!is_token_shape(
        &format!("dw_at_{}", "a".repeat(44)),
        "dw_at_"
    ));
    assert!(!is_token_shape(
        &format!("dw_at_{}+", "a".repeat(42)),
        "dw_at_"
    ));
    assert!(!is_token_shape(&format!("dw_rt_{body}"), "dw_at_"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_account_page_lists_live_families_with_their_attributes() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let server = issue(&gw, bob, Some(demo), CLIENT);
    let combined = issue(&gw, bob, None, "Other App");
    let browser = Browser::signed_in(&gw, bob);
    let page = browser.get("/account").await;
    assert_eq!(page.status, 200, "/account must answer 200 to its owner");
    assert_eq!(
        page.attrs("[data-family]", "data-family"),
        vec![server.public_id.clone(), combined.public_id.clone()],
        "both live families must be listed"
    );
    assert_eq!(
        page.attr(
            &format!(r#"[data-family="{}"]"#, server.public_id),
            "data-client-name"
        ),
        Some(CLIENT.to_owned())
    );
    assert_eq!(
        page.attr(
            &format!(r#"[data-family="{}"]"#, server.public_id),
            "data-server"
        ),
        Some("demo".to_owned())
    );
    assert_eq!(
        page.attr(
            &format!(r#"[data-family="{}"]"#, combined.public_id),
            "data-server"
        ),
        Some("all servers".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dead_and_foreign_families_are_not_listed() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let carol = user_with(&gw, CAROL, &[demo]);
    issue(&gw, bob, Some(demo), "Before Reset");
    session::revoke_all(&gw.conn(), bob).expect("reset");
    // Both families below are of bob's current epoch, so only their own state hides them.
    let revoked_family = issue(&gw, bob, Some(demo), "Revoked App");
    families::revoke(&gw.conn(), revoked_family.family, NOW).expect("revoke");
    let expired = issue(&gw, bob, Some(demo), "Expired App");
    gw.conn()
        .execute(
            "UPDATE token_families SET expires_at = ?1 WHERE id = ?2",
            params![NOW, expired.family],
        )
        .expect("expire");
    let live = issue(&gw, bob, Some(demo), CLIENT);
    issue(&gw, carol, Some(demo), "Carol App");
    let browser = Browser::signed_in(&gw, bob);
    let page = browser.get("/account").await;
    assert_eq!(
        page.attrs("[data-family]", "data-family"),
        vec![live.public_id],
        "only the live family of bob's current epoch is listed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pre_reset_family_is_absent_while_a_later_one_is_listed() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let carol = user_with(&gw, CAROL, &[demo]);
    issue(&gw, bob, Some(demo), "Before Reset");
    issue(&gw, carol, Some(demo), "Carol App");
    session::revoke_all(&gw.conn(), bob).expect("reset");
    let fresh = issue(&gw, bob, Some(demo), "After Reset");
    let browser = Browser::signed_in(&gw, bob);
    let page = browser.get("/account").await;
    assert_eq!(
        page.attrs("[data-family]", "data-family"),
        vec![fresh.public_id],
        "only the family made after the reset is listed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnecting_from_the_account_page_revokes_and_the_guard_refuses() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, bob, Some(demo), CLIENT);
    let browser = Browser::signed_in(&gw, bob);
    let csrf = browser.get("/account").await.csrf();
    let path = format!("/account/clients/{}/disconnect", issued.public_id);
    let reply = browser.post(&path, &[("csrf", csrf.as_str())]).await;
    assert_eq!(reply.status, 303, "disconnecting must answer 303");
    assert_eq!(reply.header("location").as_deref(), Some("/account"));
    assert!(revoked(&gw, issued.family), "the family must be revoked");
    assert_eq!(
        activity_count(&gw, "client_disconnected"),
        1,
        "the disconnect must be recorded once"
    );
    let refused = gw
        .http()
        .bearer(reqwest::Method::GET, "/demo", &issued.access)
        .await;
    assert_eq!(
        refused.status, 401,
        "the disconnected token must be refused"
    );
    assert_eq!(
        refused.header("www-authenticate"),
        Some(invalid_challenge(&gw.base, "demo"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_users_client_is_a_plain_404_and_is_not_revoked() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let carol = user_with(&gw, CAROL, &[demo]);
    let issued = issue(&gw, bob, Some(demo), CLIENT);
    let browser = Browser::signed_in(&gw, carol);
    let csrf = browser.get("/account").await.csrf();
    let path = format!("/account/clients/{}/disconnect", issued.public_id);
    let reply = browser.post(&path, &[("csrf", csrf.as_str())]).await;
    assert_eq!(
        reply.status, 404,
        "another user's client must be a plain 404"
    );
    assert_eq!(reply.body, "", "the 404 has an empty body");
    assert!(!revoked(&gw, issued.family), "the family must stay live");
    assert_eq!(activity_count(&gw, "client_disconnected"), 0);
    let live = gw
        .http()
        .bearer(reqwest::Method::GET, "/demo", &issued.access)
        .await;
    assert_eq!(live.status, 405, "bob's token must still pass the guard");
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnecting_needs_the_csrf_token() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, bob, Some(demo), CLIENT);
    let browser = Browser::signed_in(&gw, bob);
    let path = format!("/account/clients/{}/disconnect", issued.public_id);
    let missing = browser.post(&path, &[]).await;
    assert_eq!(missing.status, 403, "a post without csrf must be refused");
    assert_eq!(missing.kind().as_deref(), Some("forbidden"));
    let wrong = browser.post(&path, &[("csrf", "not-the-token")]).await;
    assert_eq!(
        wrong.status, 403,
        "a post with a wrong csrf must be refused"
    );
    assert!(
        !revoked(&gw, issued.family),
        "a refused post revokes nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mailed_link_shows_then_disconnects_once() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, bob, Some(demo), CLIENT);
    let link = add_link(&gw, issued.family);
    let path = format!("/account/disconnect/{link}");
    let anonymous = Browser::new(&gw);
    let view = anonymous.get(&path).await;
    assert_eq!(view.status, 200, "the mailed link must open the page");
    assert_eq!(view.kind().as_deref(), Some("disconnect"));
    assert_eq!(
        view.attr("main", "data-client-name").as_deref(),
        Some(CLIENT)
    );
    assert_eq!(view.attr("main", "data-server").as_deref(), Some("demo"));
    let again = anonymous.get(&path).await;
    assert_eq!(again.status, 200, "a second GET must still open the page");
    assert!(!revoked(&gw, issued.family), "a GET must change nothing");
    let live = gw
        .http()
        .bearer(reqwest::Method::GET, "/demo", &issued.access)
        .await;
    assert_eq!(live.status, 405, "the token must still pass after two GETs");
    let csrf = view.csrf();
    let bare = anonymous.post(&path, &[]).await;
    assert_eq!(bare.status, 403, "the link post needs the csrf token");
    assert!(
        !revoked(&gw, issued.family),
        "a refused post changes nothing"
    );
    let done = anonymous.post(&path, &[("csrf", csrf.as_str())]).await;
    assert_eq!(done.status, 200, "the confirmed disconnect must answer 200");
    assert_eq!(done.kind().as_deref(), Some("disconnected"));
    assert!(revoked(&gw, issued.family), "the family must be revoked");
    assert_eq!(
        scalar(&gw, "SELECT COUNT(*) FROM disconnect_links", params![]),
        0,
        "the link row must be deleted"
    );
    assert_eq!(activity_count(&gw, "client_disconnected"), 1);
    let refused = gw
        .http()
        .bearer(reqwest::Method::GET, "/demo", &issued.access)
        .await;
    assert_eq!(
        refused.status, 401,
        "the disconnected token must be refused"
    );
    let second_get = anonymous.get(&path).await;
    assert_eq!(second_get.status, 404);
    assert_eq!(second_get.kind().as_deref(), Some("link-invalid"));
    let second_post = anonymous.post(&path, &[("csrf", csrf.as_str())]).await;
    assert_eq!(second_post.status, 404);
    assert_eq!(second_post.kind().as_deref(), Some("link-invalid"));
    assert_eq!(
        activity_count(&gw, "client_disconnected"),
        1,
        "no second record"
    );
}

/// A browser's csrf token, read from the sign-in page, which every browser may open.
async fn anonymous_csrf(browser: &Browser) -> String {
    browser.get("/login").await.csrf()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_link_is_the_invalid_page() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let before_reset = issue(&gw, bob, Some(demo), CLIENT);
    session::revoke_all(&gw.conn(), bob).expect("reset");
    // The two families below are of bob's current epoch, so only their own state refuses them.
    let revoked_one = issue(&gw, bob, Some(demo), CLIENT);
    families::revoke(&gw.conn(), revoked_one.family, NOW).expect("revoke");
    let expired = issue(&gw, bob, Some(demo), CLIENT);
    gw.conn()
        .execute(
            "UPDATE token_families SET expires_at = ?1 WHERE id = ?2",
            params![NOW, expired.family],
        )
        .expect("expire");
    let mut links = vec![
        add_link(&gw, revoked_one.family),
        add_link(&gw, expired.family),
        add_link(&gw, before_reset.family),
    ];
    links.push("dw_dl_short".to_owned());
    links.push(format!("dw_dl_{}", "+".repeat(43)));
    let anonymous = Browser::new(&gw);
    let csrf = anonymous_csrf(&anonymous).await;
    for link in links {
        let path = format!("/account/disconnect/{link}");
        let view = anonymous.get(&path).await;
        assert_eq!(view.status, 404, "{path} must be refused");
        assert_eq!(view.kind().as_deref(), Some("link-invalid"));
        let posted = anonymous.post(&path, &[("csrf", csrf.as_str())]).await;
        assert_eq!(posted.status, 404, "a post to {path} must be refused");
        assert_eq!(posted.kind().as_deref(), Some("link-invalid"));
    }
    assert_eq!(activity_count(&gw, "client_disconnected"), 0);
    assert!(
        !revoked(&gw, expired.family),
        "a refused post must change nothing: the expired family stays unrevoked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_names_are_escaped_on_every_page_that_shows_them() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let bob = user_with(&gw, BOB, &[demo]);
    let evil = "<b>Evil</b>";
    let issued = issue(&gw, bob, Some(demo), evil);
    let browser = Browser::signed_in(&gw, bob);
    let account = browser.get("/account").await;
    assert_escaped(&account.body, "the account page");
    assert_eq!(
        account
            .attr(
                &format!(r#"[data-family="{}"]"#, issued.public_id),
                "data-client-name"
            )
            .as_deref(),
        Some(evil),
        "the attribute reads back as the raw name"
    );
    let link = add_link(&gw, issued.family);
    let path = format!("/account/disconnect/{link}");
    let anonymous = Browser::new(&gw);
    let view = anonymous.get(&path).await;
    assert_escaped(&view.body, "the disconnect page");
    let done = anonymous
        .post(&path, &[("csrf", view.csrf().as_str())])
        .await;
    assert_escaped(&done.body, "the disconnected page");
}

/// The state a handler of this gateway sees: the same database, key and clock.
async fn state_of(gw: &Gateway) -> AppState {
    let config = Config {
        public_url: gw.base.clone(),
        listen: "127.0.0.1:0".parse().expect("address"),
        database: gw.db.clone(),
        key_file: None,
        trusted_proxies: Vec::new(),
        shared_client_address: false,
        allowed_origins: Vec::new(),
        lifetimes: Lifetimes::default(),
        limits: Limits::default(),
        mail: Default::default(),
    };
    let limiter = Arc::new(crate::rate::Limiter::new(&config.limits));
    AppState {
        keys: Arc::new(Keys::load(&config, None).expect("keys")),
        db: Db::open(&gw.db).expect("database"),
        clock: gw.clock.clone(),
        cimd: Arc::new(UnavailableCimd),
        hasher: Arc::new(PasswordHasher::new().await.expect("hasher")),
        setup_code: None,
        http: reqwest::Client::new(),
        reset_requests: Arc::new(Semaphore::new(1)),
        limiter,
        links: Arc::new(crate::proxy::links::Links::new()),
        turns: Arc::new(crate::proxy::combined::Turns::default()),
        config,
    }
}

/// A gateway with bob assigned to `demo` and a token for it, and the state to check it with.
async fn live_token() -> (Gateway, AppState, i64, Issued) {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let state = state_of(&gw).await;
    (gw, state, user, issued)
}

/// The state of `gw` with the limits `edit` changes, on the same clock.
async fn state_with(gw: &Gateway, edit: impl FnOnce(&mut Limits)) -> AppState {
    let mut state = state_of(gw).await;
    edit(&mut state.config.limits);
    state.limiter = Arc::new(crate::rate::Limiter::new(&state.config.limits));
    state
}

fn bearer_headers(access: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {access}")).expect("header"),
    );
    headers
}

/// The caller that the bearer check gives the access token on `slug`.
async fn caller_of(state: &AppState, access: &str, slug: &str) -> Caller {
    let (caller, _open) = check(
        state,
        Ipv4Addr::LOCALHOST.into(),
        &bearer_headers(access),
        Target::Server(slug),
    )
    .await
    .unwrap_or_else(|_| panic!("the token must pass the bearer check"));
    caller
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admitted_request_gives_its_address_take_back() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let state = state_with(&gw, |limits| limits.general_burst = 1).await;
    let headers = bearer_headers(&issued.access);
    for attempt in 1..=3 {
        let admitted = check(
            &state,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &headers,
            Target::Server("demo"),
        )
        .await;
        assert!(admitted.is_ok(), "valid request {attempt} is admitted");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_over_the_user_budget_keeps_its_address_take() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let state = state_with(&gw, |limits| {
        limits.general_burst = 1;
        limits.mcp_burst = 1;
    })
    .await;
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let headers = bearer_headers(&issued.access);
    let first = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(first.is_ok(), "the first valid request is admitted");
    let second = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        matches!(second, Err(Refusal::Limited(_))),
        "the second valid request is over the user budget"
    );
    let now = crate::web::limit::now_nanos(state.clock.as_ref());
    let address = crate::rate::Key::address(peer);
    assert!(
        state
            .limiter
            .take(crate::rate::Class::General, address, now)
            .is_err(),
        "the over-budget request kept its address take"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_bearer_keeps_its_address_take() {
    let gw = Gateway::start().await;
    let state = state_with(&gw, |limits| limits.general_burst = 1).await;
    let unknown = format!("dw_at_{}", "A".repeat(43));
    let headers = bearer_headers(&unknown);
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let first = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        matches!(first, Err(Refusal::Challenge(_))),
        "the first unknown token gets the challenge"
    );
    let second = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        matches!(second, Err(Refusal::Limited(_))),
        "the next request from the address is limited, not challenged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_slot_is_held_until_its_response_is_dropped() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let state = state_with(&gw, |limits| limits.mcp_open = 1).await;
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let headers = bearer_headers(&issued.access);
    let Ok((_caller, open)) = check(&state, peer, &headers, Target::Server("demo")).await else {
        panic!("the first valid request is admitted");
    };
    let second = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        matches!(second, Err(Refusal::Limited(1))),
        "while the first slot is held the second request is limited with Retry-After 1"
    );
    drop(open);
    let third = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        third.is_ok(),
        "once the slot is dropped a request is admitted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_refused_for_open_slots_gives_its_user_take_back() {
    let gw = Gateway::start().await;
    let demo = add_server(&gw, "demo");
    let user = user_with(&gw, BOB, &[demo]);
    let issued = issue(&gw, user, Some(demo), CLIENT);
    let state = state_with(&gw, |limits| {
        limits.mcp_open = 1;
        limits.mcp_burst = 2;
    })
    .await;
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let headers = bearer_headers(&issued.access);
    let Ok((_caller, open)) = check(&state, peer, &headers, Target::Server("demo")).await else {
        panic!("the first valid request is admitted");
    };
    let second = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        matches!(second, Err(Refusal::Limited(1))),
        "with the only slot held the second request is limited with Retry-After 1"
    );
    drop(open);
    let third = check(&state, peer, &headers, Target::Server("demo")).await;
    assert!(
        third.is_ok(),
        "the refused request gave its user take back, so the third is admitted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_is_true_for_a_live_token() {
    let (_gw, state, _user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Live,
        "a live token stays valid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_is_false_once_the_user_is_disabled() {
    let (gw, state, user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    gw.conn()
        .execute("UPDATE users SET disabled = 1 WHERE id = ?1", params![user])
        .expect("disable");
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Lost,
        "a disabled user's token is no longer valid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_is_false_once_the_family_is_revoked() {
    let (gw, state, _user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    families::revoke(&gw.conn(), issued.family, NOW).expect("revoke");
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Lost,
        "a revoked family is no longer valid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_is_false_after_a_password_reset() {
    let (gw, state, user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    session::revoke_all(&gw.conn(), user).expect("reset");
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Lost,
        "a reset bumps the sign-in generation and ends the family"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_is_false_once_the_access_token_expires() {
    let (gw, state, _user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    gw.clock.set(NOW + 3601);
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Lost,
        "an access token past its hour is no longer valid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_is_false_once_the_user_is_unassigned() {
    let (gw, state, user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    gw.conn()
        .execute("DELETE FROM user_servers WHERE user_id = ?1", params![user])
        .expect("unassign");
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Lost,
        "an unassigned user's token is no longer valid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn still_valid_fails_on_a_database_error() {
    let (gw, state, _user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    gw.conn()
        .execute_batch("ALTER TABLE access_tokens RENAME TO access_tokens_gone;")
        .expect("rename");
    assert_eq!(
        still_valid(&state, &caller, "demo").await,
        Recheck::Failed,
        "a database error is a check that could not be made, not a lost access"
    );
}

/// The caller that the bearer check gives the access token on `/mcp`.
async fn combined_caller_of(state: &AppState, access: &str) -> Caller {
    let (caller, _open) = check(
        state,
        Ipv4Addr::LOCALHOST.into(),
        &bearer_headers(access),
        Target::Combined,
    )
    .await
    .unwrap_or_else(|_| panic!("the combined token must pass the bearer check"));
    caller
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_still_valid_follows_the_token_and_the_assignment() {
    let (gw, state, user, server_token) = live_token().await;
    let demo = scalar(&gw, "SELECT id FROM servers WHERE slug = 'demo'", []);
    let other = add_server(&gw, "other");
    let carol = user_with(&gw, CAROL, &[other]);
    let combined = issue(&gw, user, None, CLIENT);
    let caller = combined_caller_of(&state, &combined.access).await;
    assert_eq!(
        combined_still_valid(&state, &caller, demo).await,
        Recheck::Live,
        "a live combined token of an assigned server stays valid"
    );
    assert_eq!(
        combined_still_valid(&state, &caller, other).await,
        Recheck::Lost,
        "bob's token must not pass for a server bob is not assigned to"
    );
    let carol_combined = issue(&gw, carol, None, CLIENT);
    let carol_caller = combined_caller_of(&state, &carol_combined.access).await;
    assert_eq!(
        combined_still_valid(&state, &carol_caller, demo).await,
        Recheck::Lost,
        "carol's token must not pass for demo, which carol is not assigned to"
    );
    gw.conn()
        .execute(
            "DELETE FROM user_servers WHERE user_id = ?1 AND server_id = ?2",
            params![user, demo],
        )
        .expect("unassign");
    assert_eq!(
        combined_still_valid(&state, &caller, demo).await,
        Recheck::Lost,
        "an unassigned user's combined token is no longer valid"
    );
    assign(&gw, user, demo);
    let server_caller = caller_of(&state, &server_token.access, "demo").await;
    assert_eq!(
        combined_still_valid(&state, &server_caller, demo).await,
        Recheck::Lost,
        "a token of a server path is not a combined token"
    );
    families::revoke(&gw.conn(), combined.family, NOW).expect("revoke");
    assert_eq!(
        combined_still_valid(&state, &caller, demo).await,
        Recheck::Lost,
        "a revoked combined family is no longer valid"
    );
    let fresh = issue(&gw, user, None, CLIENT);
    let fresh_caller = combined_caller_of(&state, &fresh.access).await;
    assert_eq!(
        combined_still_valid(&state, &fresh_caller, demo).await,
        Recheck::Live,
        "a fresh combined token stays valid"
    );
    gw.clock.set(NOW + 3601);
    assert_eq!(
        combined_still_valid(&state, &fresh_caller, demo).await,
        Recheck::Lost,
        "an expired combined access token is no longer valid"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn combined_still_valid_follows_the_family_and_the_user() {
    let (gw, state, user, _server_token) = live_token().await;
    let demo = scalar(&gw, "SELECT id FROM servers WHERE slug = 'demo'", []);

    let revoked = issue(&gw, user, None, CLIENT);
    let revoked_caller = combined_caller_of(&state, &revoked.access).await;
    assert_eq!(
        combined_still_valid(&state, &revoked_caller, demo).await,
        Recheck::Live,
        "precondition: the family is live"
    );
    gw.conn()
        .execute(
            "UPDATE token_families SET revoked_at = ?1 WHERE id = ?2",
            params![NOW, revoked.family],
        )
        .expect("revoke the family row only");
    assert_eq!(
        combined_still_valid(&state, &revoked_caller, demo).await,
        Recheck::Lost,
        "a revoked family is refused while its access token is unexpired"
    );

    let lapsed = issue(&gw, user, None, CLIENT);
    let lapsed_caller = combined_caller_of(&state, &lapsed.access).await;
    gw.conn()
        .execute(
            "UPDATE token_families SET expires_at = ?1 WHERE id = ?2",
            params![NOW - 1, lapsed.family],
        )
        .expect("expire the family row only");
    assert_eq!(
        combined_still_valid(&state, &lapsed_caller, demo).await,
        Recheck::Lost,
        "a family past its own lifetime is refused while its access token is unexpired"
    );

    let dave = user_with(&gw, "dave@example.com", &[demo]);
    let disabled = issue(&gw, dave, None, CLIENT);
    let disabled_caller = combined_caller_of(&state, &disabled.access).await;
    assert_eq!(
        combined_still_valid(&state, &disabled_caller, demo).await,
        Recheck::Live,
        "precondition: dave is live"
    );
    gw.conn()
        .execute("UPDATE users SET disabled = 1 WHERE id = ?1", params![dave])
        .expect("disable dave");
    assert_eq!(
        combined_still_valid(&state, &disabled_caller, demo).await,
        Recheck::Lost,
        "a disabled user's combined token is refused"
    );

    let erin = user_with(&gw, "erin@example.com", &[demo]);
    let raised = issue(&gw, erin, None, CLIENT);
    let raised_caller = combined_caller_of(&state, &raised.access).await;
    assert_eq!(
        combined_still_valid(&state, &raised_caller, demo).await,
        Recheck::Live,
        "precondition: erin is live"
    );
    gw.conn()
        .execute(
            "UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?1",
            params![erin],
        )
        .expect("raise erin's sign-in generation");
    assert_eq!(
        combined_still_valid(&state, &raised_caller, demo).await,
        Recheck::Lost,
        "a raised sign-in generation, as a password change makes, refuses the family"
    );

    let last = issue(&gw, user, None, CLIENT);
    let last_caller = combined_caller_of(&state, &last.access).await;
    assert_eq!(
        combined_still_valid(&state, &last_caller, demo).await,
        Recheck::Live,
        "precondition: bob's last token is live"
    );
    gw.conn()
        .execute_batch("ALTER TABLE user_servers RENAME TO user_servers_gone;")
        .expect("rename");
    assert_eq!(
        combined_still_valid(&state, &last_caller, demo).await,
        Recheck::Failed,
        "a database error is a check that could not be made, not a lost access"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn check_records_the_hash_the_lookup_used() {
    let (_gw, state, _user, issued) = live_token().await;
    let caller = caller_of(&state, &issued.access, "demo").await;
    assert_eq!(caller.token_hash, token_hash(&issued.access));
}

#[test]
fn a_caller_debug_text_never_shows_the_token_hash() {
    let hash = token_hash("dw_at_probe");
    let caller = Caller {
        user_id: 1,
        user_email: BOB.to_owned(),
        family_id: 2,
        server_id: Some(3),
        client_name: CLIENT.to_owned(),
        token_hash: hash.clone(),
        admitted: NOW,
    };
    let text = format!("{caller:?}");
    assert!(
        text.contains("user_id"),
        "the debug text names the fields: {text}"
    );
    assert!(
        !text.contains(&hash),
        "the debug text must not show the hash"
    );
}
