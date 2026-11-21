//! The token endpoint over real HTTP, the admin wiring of families, and the housekeeping. The
//! helpers follow `tests_consent.rs`; the database is read directly for what HTTP does not show.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use form_urlencoded::Serializer;
use futures_util::future::join_all;
use rusqlite::{Connection, params};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::net::TcpListener;

use crate::accounts::session;
use crate::app::{Deps, assemble, serve};
use crate::cimd::UnavailableCimd;
use crate::clock::Clock;
use crate::config::{Config, Lifetimes, Limits};
use crate::crypto::{Keys, PasswordHasher, open_with_token, random_token, token_hash};
use crate::db::Db;
use crate::web::SESSION_COOKIE;

use super::families::{self, NewFamily};

/// The fixed instant every test starts at, in unix seconds.
const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const SESSION_SECONDS: i64 = 10 * DAY;
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const OWNER: &str = "owner@example.com";
const REDIRECT: &str = "http://127.0.0.1:53535/callback";
const OTHER_REDIRECT: &str = "http://localhost:8787/callback";
const FORM: &str = "application/x-www-form-urlencoded";
const BODY_LIMIT: usize = 16 * 1024;

/// A clock that the test moves by hand.
struct FakeClock(Mutex<OffsetDateTime>);

impl FakeClock {
    fn advance(&self, by: time::Duration) {
        let mut now = self.0.lock().expect("clock lock");
        *now += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

/// A started gateway with its database path, its clock and its encryption keys.
struct Gateway {
    base: String,
    db: PathBuf,
    clock: Arc<FakeClock>,
    keys: Keys,
    _dir: TempDir,
}

impl Gateway {
    async fn start() -> Gateway {
        Gateway::start_with(|_| {}).await
    }

    async fn start_with(edit: impl FnOnce(&mut Config)) -> Gateway {
        let dir = tempfile::tempdir().expect("temporary directory");
        let db = dir.path().join("doorward.db");
        Gateway::start_on(dir, db, edit).await
    }

    /// Starts a gateway on the database file `db`, which lives inside `dir`.
    async fn start_on(dir: TempDir, db: PathBuf, edit: impl FnOnce(&mut Config)) -> Gateway {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let base = format!("http://{address}");
        let mut config = Config {
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
        edit(&mut config);
        let keys = Keys::load(&config, None).expect("keys");
        let clock = Arc::new(FakeClock(Mutex::new(
            OffsetDateTime::from_unix_timestamp(NOW).expect("instant"),
        )));
        let deps = Deps {
            clock: clock.clone(),
            cimd: Arc::new(UnavailableCimd),
        };
        let hasher = PasswordHasher::new().await.expect("hasher");
        let gateway = assemble(config, deps, Arc::new(hasher))
            .await
            .expect("build");
        tokio::spawn(serve(
            listener,
            gateway.router,
            std::time::Duration::from_secs(30),
            std::future::pending(),
        ));
        Gateway {
            base,
            db,
            clock,
            keys,
            _dir: dir,
        }
    }

    fn http(&self) -> Http {
        Http::new(&self.base)
    }

    fn conn(&self) -> Connection {
        open(&self.db)
    }

    /// The database file with its write-ahead and shared-memory files, as bytes.
    fn stored_bytes(&self) -> Vec<u8> {
        let mut bytes = std::fs::read(&self.db).expect("database file");
        for suffix in ["-wal", "-shm"] {
            let mut name = self.db.as_os_str().to_owned();
            name.push(suffix);
            let path = PathBuf::from(name);
            if path.exists() {
                bytes.extend(std::fs::read(&path).expect("sidecar file"));
            }
        }
        bytes
    }
}

fn open(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("connection");
    conn.busy_timeout(Duration::from_secs(5)).expect("timeout");
    conn
}

/// One integer read from the database.
fn scalar(gw: &Gateway, sql: &str, values: impl rusqlite::Params) -> i64 {
    gw.conn()
        .query_row(sql, values, |row| row.get(0))
        .expect("scalar")
}

/// A client that sends no cookie. Redirects are not followed.
struct Http {
    base: String,
    client: reqwest::Client,
}

/// A status, the headers the tests read, and the body text.
struct Reply {
    status: u16,
    cache_control: Option<String>,
    content_type: Option<String>,
    location: Option<String>,
    body: String,
}

impl Reply {
    fn error(&self) -> Option<String> {
        serde_json::from_str::<Value>(&self.body)
            .ok()?
            .get("error")?
            .as_str()
            .map(str::to_owned)
    }
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

    async fn send(&self, request: reqwest::RequestBuilder) -> Reply {
        let response = request.send().await.expect("request");
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let reply_headers = (
            header("cache-control"),
            header("content-type"),
            header("location"),
        );
        let status = response.status().as_u16();
        let body = response.text().await.expect("body");
        Reply {
            status,
            cache_control: reply_headers.0,
            content_type: reply_headers.1,
            location: reply_headers.2,
            body,
        }
    }

    async fn get(&self, path: &str) -> Reply {
        self.send(self.client.get(format!("{}{path}", self.base)))
            .await
    }

    /// A token request with the given form fields, in order, repeats included.
    async fn token(&self, fields: &[(&str, &str)]) -> Reply {
        self.send(
            self.client
                .post(format!("{}/oauth/token", self.base))
                .header("content-type", FORM)
                .body(form_body(fields)),
        )
        .await
    }

    /// A POST of raw text under the given media type.
    async fn post_raw(&self, path: &str, content_type: &str, body: String) -> Reply {
        self.send(
            self.client
                .post(format!("{}{path}", self.base))
                .header("content-type", content_type)
                .body(body),
        )
        .await
    }
}

fn form_body(fields: &[(&str, &str)]) -> String {
    let mut body = Serializer::new(String::new());
    body.extend_pairs(fields);
    body.finish()
}

/// A signed-in browser: one session cookie, sent with every request.
struct Session {
    http: Http,
    cookie: String,
}

impl Session {
    async fn get(&self, path: &str) -> Reply {
        let request = self
            .http
            .client
            .get(format!("{}{path}", self.http.base))
            .header("cookie", &self.cookie);
        self.http.send(request).await
    }

    async fn post(&self, path: &str, fields: &[(&str, &str)]) -> Reply {
        let request = self
            .http
            .client
            .post(format!("{}{path}", self.http.base))
            .header("origin", &self.http.base)
            .header("content-type", FORM)
            .header("cookie", &self.cookie)
            .body(form_body(fields));
        self.http.send(request).await
    }
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

fn sign_in(gw: &Gateway, user_id: i64) -> Session {
    let token = session::insert(&gw.conn(), user_id, NOW, SESSION_SECONDS).expect("session");
    Session {
        http: gw.http(),
        cookie: format!("{SESSION_COOKIE}={token}"),
    }
}

/// A server whose name and path are both `slug`.
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

/// Registers a public client through the registration endpoint and returns its id.
async fn register(http: &Http, name: &str, redirect: &str) -> String {
    let body = json!({"client_name": name, "redirect_uris": [redirect]}).to_string();
    let reply = http
        .post_raw("/oauth/register", "application/json", body)
        .await;
    assert_eq!(reply.status, 201, "registration must answer 201");
    serde_json::from_str::<Value>(&reply.body).expect("json")["client_id"]
        .as_str()
        .expect("client_id")
        .to_owned()
}

/// A code and the verifier that redeems it.
struct Issued {
    verifier: String,
    code: String,
}

/// The value of one query parameter of a Location, relative or absolute.
fn query_of(location: Option<&str>, name: &str) -> String {
    let base = url::Url::parse("http://localhost/").expect("base");
    let target = base.join(location.expect("a location")).expect("a url");
    target
        .query_pairs()
        .find(|pair| pair.0 == name)
        .map(|pair| pair.1.into_owned())
        .expect("the parameter")
}

fn csrf_in(body: &str) -> String {
    let doc = Html::parse_document(body);
    let selector = Selector::parse(r#"input[name="csrf"]"#).expect("selector");
    doc.select(&selector)
        .next()
        .and_then(|input| input.attr("value"))
        .map(str::to_owned)
        .expect("the page carries a csrf token")
}

/// Authorizes as the signed-in browser, renders the consent page, approves, and returns the code.
async fn issue(browser: &Session, client: &str, redirect: &str, resource: &str) -> Issued {
    let verifier = random_token("");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut query = Serializer::new(String::new());
    query.extend_pairs([
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", redirect),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("resource", resource),
        ("state", "s1"),
    ]);
    let started = browser
        .get(&format!("/oauth/authorize?{}", query.finish()))
        .await;
    assert_eq!(started.status, 303, "authorize must answer 303");
    let req = query_of(started.location.as_deref(), "req");
    let page = browser.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(page.status, 200, "the consent page must render");
    let csrf = csrf_in(&page.body);
    let granted = browser
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_eq!(
        granted.status, 303,
        "approval must answer 303, body {}",
        granted.body
    );
    Issued {
        verifier,
        code: query_of(granted.location.as_deref(), "code"),
    }
}

/// Redeems a code. `redirect` and `resource` are sent only when given.
async fn redeem(
    http: &Http,
    client: &str,
    issued: &Issued,
    redirect: Option<&str>,
    resource: Option<&str>,
) -> Reply {
    let mut fields = vec![
        ("grant_type", "authorization_code"),
        ("code", issued.code.as_str()),
        ("client_id", client),
        ("code_verifier", issued.verifier.as_str()),
    ];
    if let Some(redirect) = redirect {
        fields.push(("redirect_uri", redirect));
    }
    if let Some(resource) = resource {
        fields.push(("resource", resource));
    }
    http.token(&fields).await
}

async fn refresh(http: &Http, client: &str, token: &str, resource: Option<&str>) -> Reply {
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", token),
        ("client_id", client),
    ];
    if let Some(resource) = resource {
        fields.push(("resource", resource));
    }
    http.token(&fields).await
}

/// The access and refresh token texts of a successful answer.
fn tokens_of(reply: &Reply) -> (String, String) {
    assert_eq!(reply.status, 200, "a pair must be issued: {}", reply.body);
    assert_headers(reply, "an issued pair");
    let json: Value = serde_json::from_str(&reply.body).expect("json");
    (
        json["access_token"].as_str().expect("access").to_owned(),
        json["refresh_token"].as_str().expect("refresh").to_owned(),
    )
}

/// Every answer carries no-store and a JSON media type.
fn assert_headers(reply: &Reply, case: &str) {
    assert_eq!(
        reply.cache_control.as_deref(),
        Some("no-store"),
        "{case} must say no-store"
    );
    assert_eq!(
        reply.content_type.as_deref(),
        Some("application/json"),
        "{case} must be JSON"
    );
}

fn assert_refused(reply: &Reply, error: &str, case: &str) {
    assert_eq!(reply.status, 400, "{case} must be 400, body {}", reply.body);
    assert_eq!(
        reply.error().as_deref(),
        Some(error),
        "{case} must carry {error}"
    );
    assert_headers(reply, case);
}

/// Bob, signed in and assigned `demo`, with one registered client on `REDIRECT`.
struct Scene {
    gw: Gateway,
    bob: Session,
    bob_id: i64,
    client: String,
}

impl Scene {
    fn resource(&self) -> String {
        format!("{}/demo", self.gw.base)
    }
}

async fn scene() -> Scene {
    scene_with(|_| {}).await
}

async fn scene_with(edit: impl FnOnce(&mut Config)) -> Scene {
    let gw = Gateway::start_with(edit).await;
    let bob_id = add_user(&gw, BOB, "user");
    let demo = add_server(&gw, "demo");
    assign(&gw, bob_id, demo);
    let bob = sign_in(&gw, bob_id);
    let client = register(&gw.http(), "Cursor", REDIRECT).await;
    Scene {
        gw,
        bob,
        bob_id,
        client,
    }
}

/// Issues a code for the scene's client and redeems it; returns the pair.
async fn connect(scene: &Scene) -> (String, String) {
    let issued = issue(&scene.bob, &scene.client, REDIRECT, &scene.resource()).await;
    let reply = redeem(
        &scene.gw.http(),
        &scene.client,
        &issued,
        Some(REDIRECT),
        None,
    )
    .await;
    tokens_of(&reply)
}

fn family_of(gw: &Gateway, refresh_token: &str) -> i64 {
    scalar(
        gw,
        "SELECT family_id FROM refresh_tokens WHERE token_hash = ?1",
        params![token_hash(refresh_token)],
    )
}

fn is_revoked(gw: &Gateway, family: i64) -> bool {
    scalar(
        gw,
        "SELECT COUNT(*) FROM token_families WHERE id = ?1 AND revoked_at IS NOT NULL",
        params![family],
    ) == 1
}

fn access_rows(gw: &Gateway, family: i64) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM access_tokens WHERE family_id = ?1",
        params![family],
    )
}

fn refresh_rows(gw: &Gateway, family: i64) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = ?1",
        params![family],
    )
}

fn activity_count(gw: &Gateway, kind: &str, detail: &str) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM activity WHERE kind = ?1 AND detail = ?2",
        params![kind, detail],
    )
}

/// Inserts a live family of `user` on `server` directly, with one pair, and returns its id.
fn direct_family(gw: &Gateway, user: i64, server: i64) -> i64 {
    let conn = gw.conn();
    let family = NewFamily {
        user_id: user,
        server_id: Some(server),
        client_id: "dcr_direct",
        client_name: "Direct",
        auth_epoch: 0,
    };
    let id = families::create(&conn, &family, NOW, 90).expect("family");
    families::mint_pair(&conn, id, NOW, &Lifetimes::default()).expect("pair");
    id
}

/// Eight parallel calls, all answered before the test looks at them.
async fn eight<F, Fut>(call: F) -> Vec<Reply>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Reply>,
{
    join_all((0..8).map(|_| call())).await
}

#[tokio::test(flavor = "multi_thread")]
async fn eight_redemptions_of_one_code_give_one_200() {
    let s = scene().await;
    let http = s.gw.http();
    let issued = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let replies = eight(|| redeem(&http, &s.client, &issued, Some(REDIRECT), None)).await;
    let successes = replies.iter().filter(|reply| reply.status == 200).count();
    assert_eq!(
        successes, 1,
        "exactly one of eight simultaneous redemptions must succeed"
    );
    for reply in replies.iter().filter(|reply| reply.status != 200) {
        assert_refused(reply, "invalid_grant", "a redemption that lost the race");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn eight_refreshes_give_identical_bodies_and_one_unused_row() {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let replies = eight(|| refresh(&http, &s.client, &refresh_token, None)).await;
    for reply in &replies {
        assert_eq!(reply.status, 200, "every parallel refresh must be answered");
        assert_eq!(
            reply.body, replies[0].body,
            "every parallel refresh must get the identical pair"
        );
    }
    let unused = scalar(
        &s.gw,
        "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = ?1 AND used_at IS NULL",
        params![family],
    );
    assert_eq!(unused, 1, "exactly one refresh row may be unused");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_replay_after_the_window_revokes_the_family() {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let rotated = refresh(&http, &s.client, &refresh_token, None).await;
    let (_, successor) = tokens_of(&rotated);
    s.gw.clock.advance(time::Duration::seconds(31));
    let replay = refresh(&http, &s.client, &refresh_token, None).await;
    assert_refused(&replay, "invalid_grant", "a replay after the window");
    assert!(is_revoked(&s.gw, family), "the family must be revoked");
    assert_eq!(access_rows(&s.gw, family), 0, "no access row may remain");
    assert_eq!(refresh_rows(&s.gw, family), 0, "no refresh row may remain");
    assert_eq!(
        activity_count(&s.gw, "client_disconnected", "refresh replay"),
        1,
        "one client_disconnected row must name the refresh replay"
    );
    let after = refresh(&http, &s.client, &successor, None).await;
    assert_refused(
        &after,
        "invalid_grant",
        "the successor after the chain ended",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn with_no_window_the_second_use_revokes_at_once() {
    let s = scene_with(|config| config.lifetimes.refresh_replay_seconds = 0).await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let first = refresh(&http, &s.client, &refresh_token, None).await;
    tokens_of(&first);
    let second = refresh(&http, &s.client, &refresh_token, None).await;
    assert_refused(&second, "invalid_grant", "a second use with no window");
    assert!(
        is_revoked(&s.gw, family),
        "the family must be revoked at once"
    );
    assert_eq!(
        activity_count(&s.gw, "client_disconnected", "refresh replay"),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_with_an_unknown_token_clears_no_other_familys_copy() {
    let s = scene().await;
    let http = s.gw.http();
    let other = register(&http, "Other", OTHER_REDIRECT).await;
    let issued = issue(&s.bob, &other, OTHER_REDIRECT, &s.resource()).await;
    let (_, other_refresh) =
        tokens_of(&redeem(&http, &other, &issued, Some(OTHER_REDIRECT), None).await);
    tokens_of(&refresh(&http, &other, &other_refresh, None).await);
    let copy = token_hash(&other_refresh);
    assert_eq!(
        copy_rows(&s.gw, &copy),
        1,
        "the copy exists inside the window"
    );
    s.gw.clock.advance(time::Duration::seconds(31));
    let unknown = random_token("dw_rt_");
    let stranger = refresh(&http, &s.client, &unknown, None).await;
    assert_refused(&stranger, "invalid_grant", "an unknown refresh token");
    assert_eq!(
        copy_rows(&s.gw, &copy),
        1,
        "a stranger's refresh leaves the other family's old copy"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_after_the_window_clears_its_own_familys_old_copy() {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let (_, successor) = tokens_of(&refresh(&http, &s.client, &refresh_token, None).await);
    let copy = token_hash(&refresh_token);
    assert_eq!(
        copy_rows(&s.gw, &copy),
        1,
        "the copy exists inside the window"
    );
    s.gw.clock.advance(time::Duration::seconds(31));
    tokens_of(&refresh(&http, &s.client, &successor, None).await);
    assert_eq!(
        copy_rows(&s.gw, &copy),
        0,
        "the family's own refresh clears its old copy"
    );
}

/// 1 when the refresh row of `hash` still holds its replay copy, else 0.
fn copy_rows(gw: &Gateway, hash: &str) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?1 AND replay IS NOT NULL",
        params![hash],
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stored_replay_opens_only_with_the_token_and_no_token_text_is_stored() {
    let s = scene().await;
    let http = s.gw.http();
    let (access, refresh_token) = connect(&s).await;
    let used = refresh(&http, &s.client, &refresh_token, None).await;
    let (successor_access, successor_refresh) = tokens_of(&used);
    let hash = token_hash(&refresh_token);
    let sealed: String = scalar_text(
        &s.gw,
        "SELECT replay FROM refresh_tokens WHERE token_hash = ?1",
        params![hash],
    );
    let context = format!("refresh_tokens.replay:{hash}");
    let opened = open_with_token(&refresh_token, &context, &sealed).expect("the token opens it");
    assert_eq!(
        opened,
        used.body.as_bytes(),
        "the replay copy is the answer"
    );
    assert!(
        open_with_token(&hash, &context, &sealed).is_err(),
        "the token hash text must not open the replay copy"
    );
    let stored = s.gw.stored_bytes();
    for (name, text) in [
        ("the first access token", &access),
        ("the first refresh token", &refresh_token),
        ("the successor access token", &successor_access),
        ("the successor refresh token", &successor_refresh),
    ] {
        assert!(
            !contains(&stored, text.as_bytes()),
            "{name} must not appear in the database files"
        );
    }
}

/// One text value read from the database.
fn scalar_text(gw: &Gateway, sql: &str, values: impl rusqlite::Params) -> String {
    gw.conn()
        .query_row(sql, values, |row| row.get(0))
        .expect("text")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_client_refresh_changes_nothing() {
    let s = scene().await;
    let http = s.gw.http();
    let other = register(&http, "Other", OTHER_REDIRECT).await;
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let wrong = refresh(&http, &other, &refresh_token, None).await;
    assert_refused(&wrong, "invalid_grant", "a refresh by another client");
    assert!(!is_revoked(&s.gw, family), "a wrong client revokes nothing");
    let right = refresh(&http, &s.client, &refresh_token, None).await;
    assert_eq!(
        right.status, 200,
        "the right client must still refresh: {}",
        right.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_presented_twice_revokes_the_first_family() {
    let s = scene().await;
    let http = s.gw.http();
    let issued = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let first = redeem(&http, &s.client, &issued, Some(REDIRECT), None).await;
    let (_, refresh_token) = tokens_of(&first);
    let family = family_of(&s.gw, &refresh_token);
    let second = redeem(&http, &s.client, &issued, Some(REDIRECT), None).await;
    assert_refused(
        &second,
        "invalid_grant",
        "a code used twice with its verifier",
    );
    assert!(
        is_revoked(&s.gw, family),
        "the first family must be revoked"
    );
    assert_eq!(access_rows(&s.gw, family), 0);
    assert_eq!(
        activity_count(&s.gw, "client_disconnected", "code replay"),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_used_code_with_a_wrong_verifier_or_client_revokes_nothing() {
    let s = scene().await;
    let http = s.gw.http();
    let other = register(&http, "Other", OTHER_REDIRECT).await;
    let issued = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let first = redeem(&http, &s.client, &issued, Some(REDIRECT), None).await;
    let (_, refresh_token) = tokens_of(&first);
    let family = family_of(&s.gw, &refresh_token);
    let guessed = Issued {
        verifier: random_token(""),
        code: issued.code.clone(),
    };
    let wrong_verifier = redeem(&http, &s.client, &guessed, Some(REDIRECT), None).await;
    assert_refused(
        &wrong_verifier,
        "invalid_grant",
        "a used code with a wrong verifier",
    );
    let wrong_client = redeem(&http, &other, &issued, Some(REDIRECT), None).await;
    assert_refused(
        &wrong_client,
        "invalid_grant",
        "a used code with another client",
    );
    assert!(
        !is_revoked(&s.gw, family),
        "neither attempt may revoke the family"
    );
    let rotated = refresh(&http, &s.client, &refresh_token, None).await;
    assert_eq!(
        rotated.status, 200,
        "the first refresh token must still rotate: {}",
        rotated.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_approved_before_revoke_all_is_invalid_and_makes_no_family() {
    let s = scene().await;
    let http = s.gw.http();
    let issued = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    session::revoke_all(&s.gw.conn(), s.bob_id).expect("revoke_all");
    let reply = redeem(&http, &s.client, &issued, Some(REDIRECT), None).await;
    assert_refused(&reply, "invalid_grant", "a code approved before a reset");
    let families = scalar(
        &s.gw,
        "SELECT COUNT(*) FROM token_families WHERE user_id = ?1",
        params![s.bob_id],
    );
    assert_eq!(families, 0, "no family may be made from that code");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_uri_is_optional_and_a_different_one_leaves_the_code_usable() {
    let s = scene().await;
    let http = s.gw.http();
    let issued = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let different = redeem(&http, &s.client, &issued, Some(OTHER_REDIRECT), None).await;
    assert_refused(&different, "invalid_grant", "a different redirect address");
    let exact = redeem(&http, &s.client, &issued, Some(REDIRECT), None).await;
    assert_eq!(
        exact.status, 200,
        "the code must still redeem: {}",
        exact.body
    );
    let omitted = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let without = redeem(&http, &s.client, &omitted, None, None).await;
    assert_eq!(
        without.status, 200,
        "no redirect_uri must succeed: {}",
        without.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resource_that_differs_is_invalid_target_and_the_code_stays_usable() {
    let s = scene().await;
    let http = s.gw.http();
    let issued = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let other_resource = format!("{}/other", s.gw.base);
    let wrong = redeem(&http, &s.client, &issued, None, Some(&other_resource)).await;
    assert_refused(&wrong, "invalid_target", "another resource");
    let right = redeem(&http, &s.client, &issued, None, Some(&s.resource())).await;
    assert_eq!(
        right.status, 200,
        "the code must still redeem: {}",
        right.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_code_a_disabled_user_and_an_unassigned_user_are_invalid_grant() {
    let expired = scene().await;
    let issued = issue(&expired.bob, &expired.client, REDIRECT, &expired.resource()).await;
    expired.gw.clock.advance(time::Duration::seconds(61));
    let late = redeem(&expired.gw.http(), &expired.client, &issued, None, None).await;
    assert_refused(&late, "invalid_grant", "a code redeemed after 60 seconds");

    let disabled = scene().await;
    let issued = issue(
        &disabled.bob,
        &disabled.client,
        REDIRECT,
        &disabled.resource(),
    )
    .await;
    disabled
        .gw
        .conn()
        .execute(
            "UPDATE users SET disabled = 1 WHERE id = ?1",
            params![disabled.bob_id],
        )
        .expect("disable");
    let reply = redeem(&disabled.gw.http(), &disabled.client, &issued, None, None).await;
    assert_refused(&reply, "invalid_grant", "a code of a disabled user");

    let unassigned = scene().await;
    let issued = issue(
        &unassigned.bob,
        &unassigned.client,
        REDIRECT,
        &unassigned.resource(),
    )
    .await;
    unassigned
        .gw
        .conn()
        .execute(
            "DELETE FROM user_servers WHERE user_id = ?1",
            params![unassigned.bob_id],
        )
        .expect("unassign");
    let reply = redeem(
        &unassigned.gw.http(),
        &unassigned.client,
        &issued,
        None,
        None,
    )
    .await;
    assert_refused(&reply, "invalid_grant", "a code of an unassigned user");
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_requests_name_their_errors_and_carry_the_headers() {
    let s = scene().await;
    let http = s.gw.http();
    let verifier = "v".repeat(43);
    let code = format!("dw_ac_{}", "A".repeat(43));
    let repeated = http
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("code", code.as_str()),
            ("client_id", s.client.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .await;
    assert_refused(&repeated, "invalid_request", "a repeated code field");

    let missing = http.token(&[("client_id", s.client.as_str())]).await;
    assert_refused(&missing, "invalid_request", "a missing grant_type");

    let password = http
        .token(&[("grant_type", "password"), ("client_id", s.client.as_str())])
        .await;
    assert_refused(&password, "unsupported_grant_type", "another grant type");

    let refresh_token = format!("dw_rt_{}", "A".repeat(43));
    let unknown = http
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", "dcr_nobody"),
        ])
        .await;
    assert_refused(&unknown, "invalid_client", "an unknown client");

    let json_body = http
        .post_raw(
            "/oauth/token",
            "application/json",
            r#"{"grant_type":"refresh_token"}"#.to_owned(),
        )
        .await;
    assert_refused(&json_body, "invalid_request", "a JSON body");

    let head = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={refresh_token}&pad=",
        s.client
    );
    let over = format!("{head}{}", "a".repeat(BODY_LIMIT - head.len() + 1));
    let too_big = http.post_raw("/oauth/token", FORM, over).await;
    assert_refused(&too_big, "invalid_request", "a body over 16 KiB");

    let exact = format!("{head}{}", "a".repeat(BODY_LIMIT - head.len()));
    let at_limit = http.post_raw("/oauth/token", FORM, exact).await;
    assert_refused(&at_limit, "invalid_grant", "a body of exactly 16 KiB");

    let get = http.get("/oauth/token").await;
    assert_eq!(get.status, 405, "a GET must be answered 405");
    assert_headers(&get, "a GET");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_keeps_the_previous_access_row() {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let first_row = scalar(
        &s.gw,
        "SELECT expires_at FROM access_tokens WHERE family_id = ?1",
        params![family],
    );
    s.gw.clock.advance(time::Duration::seconds(5));
    let rotated = refresh(&http, &s.client, &refresh_token, None).await;
    tokens_of(&rotated);
    assert_eq!(
        access_rows(&s.gw, family),
        2,
        "the previous access row must stay until its own expiry"
    );
    let kept = scalar(
        &s.gw,
        "SELECT COUNT(*) FROM access_tokens WHERE family_id = ?1 AND expires_at = ?2",
        params![family, first_row],
    );
    assert_eq!(kept, 1, "the earlier row keeps its expiry");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_token_never_outlives_its_family() {
    let s = scene_with(|config| config.lifetimes.family_days = 1).await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let family_expires = scalar(
        &s.gw,
        "SELECT expires_at FROM token_families WHERE id = ?1",
        params![family],
    );
    let refresh_expires = scalar(
        &s.gw,
        "SELECT expires_at FROM refresh_tokens WHERE token_hash = ?1",
        params![token_hash(&refresh_token)],
    );
    assert_eq!(
        refresh_expires, family_expires,
        "a refresh token of 30 days must end with a 1 day family"
    );
    s.gw.clock.advance(time::Duration::seconds(DAY + 1));
    let late = refresh(&http, &s.client, &refresh_token, None).await;
    assert_refused(&late, "invalid_grant", "a refresh after the family ended");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_redemption_records_one_connection_and_mails_once() {
    let s = scene().await;
    let http = s.gw.http();
    let hits = Arc::new(AtomicUsize::new(0));
    let resend = start_resend(Arc::clone(&hits)).await;
    enable_mail(&s.gw, &resend);
    let first = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let reply = redeem(&http, &s.client, &first, Some(REDIRECT), None).await;
    assert_eq!(reply.status, 200, "the first redemption: {}", reply.body);
    wait_for_hits(&hits, 1).await;
    assert_eq!(
        scalar(&s.gw, "SELECT COUNT(*) FROM known_clients", params![]),
        1,
        "one known_clients row"
    );
    let key: String = scalar_text(&s.gw, "SELECT redirect_key FROM known_clients", params![]);
    assert_eq!(
        key, "http://127.0.0.1/callback",
        "the port is left out of the key"
    );
    assert_eq!(
        scalar(&s.gw, "SELECT COUNT(*) FROM disconnect_links", params![]),
        1,
        "one disconnect link"
    );
    assert_eq!(
        activity_count_kind(&s.gw, "client_connected"),
        1,
        "the redemption records client_connected"
    );

    let second = issue(&s.bob, &s.client, REDIRECT, &s.resource()).await;
    let again = redeem(&http, &s.client, &second, Some(REDIRECT), None).await;
    assert_eq!(again.status, 200, "the second redemption: {}", again.body);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the second connection sends no mail"
    );
    assert_eq!(
        scalar(&s.gw, "SELECT COUNT(*) FROM known_clients", params![]),
        1,
        "no second known_clients row"
    );
    assert_eq!(
        scalar(&s.gw, "SELECT COUNT(*) FROM disconnect_links", params![]),
        1,
        "no second disconnect link"
    );
}

fn activity_count_kind(gw: &Gateway, kind: &str) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM activity WHERE kind = ?1",
        params![kind],
    )
}

/// Waits until the counter reaches `count`, for at most five seconds.
async fn wait_for_hits(hits: &AtomicUsize, count: usize) {
    for _ in 0..50 {
        if hits.load(Ordering::SeqCst) >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), count, "the mail was not sent");
}

/// A local stand-in for the Resend API that counts the mails it is sent.
async fn start_resend(hits: Arc<AtomicUsize>) -> String {
    let app = Router::new().fallback(move || {
        let hits = Arc::clone(&hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            (StatusCode::OK, "{}")
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{address}")
}

/// Turns on Resend mail with a sealed key that points at `base`.
fn enable_mail(gw: &Gateway, base: &str) {
    let sealed = gw
        .keys
        .seal("settings.value:mail.resend_api_key", b"re_example_key")
        .expect("seal");
    let conn = gw.conn();
    for (key, value) in [
        ("mail.provider", "resend"),
        ("mail.from", "doorward@example.com"),
        ("mail.resend_base_url", base),
        ("mail.resend_api_key", sealed.as_str()),
    ] {
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value.as_bytes()],
        )
        .expect("setting");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigning_on_the_user_page_revokes_that_pair_only() {
    let gw = Gateway::start().await;
    let owner = sign_in(&gw, add_user(&gw, OWNER, "owner"));
    let bob = add_user(&gw, BOB, "user");
    let carol = add_user(&gw, CAROL, "user");
    let demo = add_server(&gw, "demo");
    let other = add_server(&gw, "other");
    assign(&gw, bob, demo);
    assign(&gw, bob, other);
    assign(&gw, carol, demo);
    let bob_demo = direct_family(&gw, bob, demo);
    let bob_other = direct_family(&gw, bob, other);
    let carol_demo = direct_family(&gw, carol, demo);

    let page = owner.get(&format!("/admin/users/{bob}")).await;
    assert_eq!(page.status, 200, "the user page must render");
    let csrf = csrf_in(&page.body);
    let other_id = other.to_string();
    let saved = owner
        .post(
            &format!("/admin/users/{bob}/servers"),
            &[("csrf", csrf.as_str()), ("server_id", other_id.as_str())],
        )
        .await;
    assert_eq!(saved.status, 303, "the assignment must answer 303");
    assert!(
        is_revoked(&gw, bob_demo),
        "the removed pair's family is revoked"
    );
    assert!(!is_revoked(&gw, bob_other), "the kept pair is untouched");
    assert!(
        !is_revoked(&gw, carol_demo),
        "another user's family is untouched"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_a_slug_revokes_that_server_only() {
    let gw = Gateway::start().await;
    let owner = sign_in(&gw, add_user(&gw, OWNER, "owner"));
    let carol = add_user(&gw, CAROL, "user");
    let demo = add_server(&gw, "demo");
    let other = add_server(&gw, "other");
    assign(&gw, carol, demo);
    assign(&gw, carol, other);
    let on_demo = direct_family(&gw, carol, demo);
    let on_other = direct_family(&gw, carol, other);

    let page = owner.get(&format!("/admin/servers/{demo}")).await;
    let csrf = csrf_in(&page.body);
    let renamed = owner
        .post(
            &format!("/admin/servers/{demo}"),
            &[
                ("csrf", csrf.as_str()),
                ("name", "Demo"),
                ("slug", "demo2"),
                ("upstream_url", "http://127.0.0.1:9"),
            ],
        )
        .await;
    assert_eq!(
        renamed.status, 303,
        "the rename must answer 303: {}",
        renamed.body
    );
    assert!(
        is_revoked(&gw, on_demo),
        "the renamed server's family is revoked"
    );
    assert!(
        !is_revoked(&gw, on_other),
        "another server's family is untouched"
    );
}

/// Starts an authorization as the signed-in browser and returns its request id, without consent.
async fn start_request(browser: &Session, client: &str, redirect: &str, resource: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(b"a pending request"));
    let mut query = Serializer::new(String::new());
    query.extend_pairs([
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", redirect),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("resource", resource),
        ("state", "s1"),
    ]);
    let started = browser
        .get(&format!("/oauth/authorize?{}", query.finish()))
        .await;
    assert_eq!(started.status, 303, "authorize must answer 303");
    query_of(started.location.as_deref(), "req")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rename_drops_the_codes_and_requests_of_that_path_only() {
    let gw = Gateway::start().await;
    let owner = sign_in(&gw, add_user(&gw, OWNER, "owner"));
    let bob_id = add_user(&gw, BOB, "user");
    let bob = sign_in(&gw, bob_id);
    let demo = add_server(&gw, "demo");
    let other = add_server(&gw, "other");
    assign(&gw, bob_id, demo);
    assign(&gw, bob_id, other);
    let http = gw.http();
    let client = register(&http, "Cursor", REDIRECT).await;
    let demo_resource = format!("{}/demo", gw.base);
    let other_resource = format!("{}/other", gw.base);
    let early = issue(&bob, &client, REDIRECT, &demo_resource).await;
    let other_code = issue(&bob, &client, REDIRECT, &other_resource).await;
    let old_request = start_request(&bob, &client, REDIRECT, &demo_resource).await;
    let other_request = start_request(&bob, &client, REDIRECT, &other_resource).await;

    let page = owner.get(&format!("/admin/servers/{demo}")).await;
    let csrf = csrf_in(&page.body);
    let renamed = owner
        .post(
            &format!("/admin/servers/{demo}"),
            &[
                ("csrf", csrf.as_str()),
                ("name", "Demo"),
                ("slug", "demo2"),
                ("upstream_url", "http://127.0.0.1:9"),
            ],
        )
        .await;
    assert_eq!(
        renamed.status, 303,
        "the rename must answer 303: {}",
        renamed.body
    );

    let early_reply = redeem(&http, &client, &early, Some(REDIRECT), None).await;
    assert_refused(
        &early_reply,
        "invalid_grant",
        "a code issued before the rename",
    );
    assert_eq!(
        scalar(&gw, "SELECT COUNT(*) FROM token_families", []),
        0,
        "the refused code makes no family"
    );

    let gone = bob.get(&format!("/oauth/consent?req={old_request}")).await;
    let unknown = bob
        .get(&format!("/oauth/consent?req={}", random_token("dw_rq_")))
        .await;
    assert_eq!(
        (gone.status, gone.body.as_str()),
        (unknown.status, unknown.body.as_str()),
        "a pending request of the old path answers as an unknown one"
    );
    let kept = bob
        .get(&format!("/oauth/consent?req={other_request}"))
        .await;
    assert_eq!(
        kept.status, 200,
        "a pending request of another server is kept"
    );
    tokens_of(&redeem(&http, &client, &other_code, Some(REDIRECT), None).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_without_a_slug_change_revokes_nothing() {
    let gw = Gateway::start().await;
    let owner = sign_in(&gw, add_user(&gw, OWNER, "owner"));
    let carol = add_user(&gw, CAROL, "user");
    let other = add_server(&gw, "other");
    assign(&gw, carol, other);
    let on_other = direct_family(&gw, carol, other);

    let page = owner.get(&format!("/admin/servers/{other}")).await;
    let csrf = csrf_in(&page.body);
    let saved = owner
        .post(
            &format!("/admin/servers/{other}"),
            &[
                ("csrf", csrf.as_str()),
                ("name", "Renamed"),
                ("slug", "other"),
                ("upstream_url", "http://127.0.0.1:9"),
            ],
        )
        .await;
    assert_eq!(
        saved.status, 303,
        "the save must answer 303: {}",
        saved.body
    );
    assert!(
        !is_revoked(&gw, on_other),
        "a save with the same path revokes nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_housekeeping_deletes_what_is_dead_and_keeps_the_rest() {
    let gw = Gateway::start().await;
    let bob = add_user(&gw, BOB, "user");
    let conn = gw.conn();
    let live = family_row(&conn, bob, NOW + DAY, None);
    let expired = family_row(&conn, bob, NOW - 3601, None);
    let grace_family = family_row(&conn, bob, NOW - 1800, None);
    let revoked_long = family_row(&conn, bob, NOW + DAY, Some(NOW - 25 * 3600));
    let revoked_short = family_row(&conn, bob, NOW + DAY, Some(NOW - 3600));
    for family in [expired, revoked_long] {
        add_pair_rows(&conn, family, NOW + 3600, NOW + DAY);
    }
    let replay_old = token_hash(&random_token("dw_rt_"));
    let replay_new = token_hash(&random_token("dw_rt_"));
    for (hash, used, replay) in [
        (&replay_old, NOW - 31, "old"),
        (&replay_new, NOW - 10, "new"),
    ] {
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at, used_at, replay) \
             VALUES (?1, ?2, 0, ?3, ?4, ?5)",
            params![hash, live, NOW + DAY, used, replay],
        )
        .expect("refresh row");
    }
    let live_access = token_hash(&random_token("dw_at_"));
    let grace_access = token_hash(&random_token("dw_at_"));
    let dead_access = token_hash(&random_token("dw_at_"));
    for (hash, expires) in [
        (&live_access, NOW + 3600),
        (&grace_access, NOW - 1800),
        (&dead_access, NOW - 3601),
    ] {
        conn.execute(
            "INSERT INTO access_tokens (token_hash, family_id, expires_at) VALUES (?1, ?2, ?3)",
            params![hash, live, expires],
        )
        .expect("access row");
    }
    let stale_request = token_hash(&random_token("dw_rq_"));
    let live_request = token_hash(&random_token("dw_rq_"));
    for (hash, expires) in [(&stale_request, NOW - 1), (&live_request, NOW + 600)] {
        conn.execute(
            "INSERT INTO auth_requests (id_hash, client_id, redirect_uri, code_challenge, address, \
             created_at, expires_at) VALUES (?1, 'dcr_x', ?2, 'c', '127.0.0.1', 0, ?3)",
            params![hash, REDIRECT, expires],
        )
        .expect("request row");
    }
    let old_code = token_hash(&random_token("dw_ac_"));
    let recent_code = token_hash(&random_token("dw_ac_"));
    for (hash, expires) in [(&old_code, NOW - 660), (&recent_code, NOW - 540)] {
        conn.execute(
            "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, user_id, combined, \
             client_name, code_challenge, auth_epoch, created_at, expires_at) \
             VALUES (?1, 'dcr_x', ?2, ?3, 1, 'C', 'c', 0, 0, ?4)",
            params![hash, REDIRECT, bob, expires],
        )
        .expect("code row");
    }
    for (address, at) in [("203.0.113.5", NOW - 3601), ("203.0.113.6", NOW - 3000)] {
        conn.execute(
            "INSERT INTO dcr_attempts (address, at) VALUES (?1, ?2)",
            params![address, at],
        )
        .expect("attempt");
    }

    families::sweep(&conn, NOW, 30).expect("sweep");

    assert_eq!(count_family(&conn, live), 1, "a live family is kept");
    assert_eq!(
        count_family(&conn, revoked_short),
        1,
        "a family revoked an hour ago is kept"
    );
    assert_eq!(
        count_family(&conn, grace_family),
        1,
        "a family expired 30 minutes ago is kept"
    );
    assert_eq!(
        count_family(&conn, expired),
        0,
        "a family expired more than an hour ago is deleted"
    );
    assert_eq!(
        count_family(&conn, revoked_long),
        0,
        "a family revoked 25 hours ago is deleted"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM access_tokens WHERE family_id = ?1",
            params![revoked_long]
        ),
        0,
        "the tokens of a deleted family go with it"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM disconnect_links WHERE family_id = ?1",
            params![revoked_long]
        ),
        0,
        "the links of a deleted family go with it"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM access_tokens WHERE token_hash = ?1",
            params![dead_access]
        ),
        0,
        "an access row expired more than an hour ago is deleted"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM access_tokens WHERE token_hash = ?1",
            params![grace_access]
        ),
        1,
        "an access row expired 30 minutes ago is kept"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM access_tokens WHERE token_hash = ?1",
            params![live_access]
        ),
        1,
        "a live access row is kept"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM auth_requests WHERE id_hash = ?1",
            params![stale_request]
        ),
        0,
        "an expired request is deleted"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM auth_codes WHERE code_hash = ?1",
            params![old_code]
        ),
        0,
        "a code more than ten minutes past expiry is deleted"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM auth_codes WHERE code_hash = ?1",
            params![recent_code]
        ),
        1,
        "a code less than ten minutes past expiry is kept"
    );
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM dcr_attempts WHERE at < ?1",
            params![NOW - 3600]
        ),
        0,
        "a registration attempt older than an hour is deleted"
    );
    assert_eq!(
        scalar_text(
            &gw,
            "SELECT COALESCE(replay, 'gone') FROM refresh_tokens WHERE token_hash = ?1",
            params![replay_old]
        ),
        "gone",
        "a replay older than the window is nulled"
    );
    assert_eq!(
        scalar_text(
            &gw,
            "SELECT COALESCE(replay, 'gone') FROM refresh_tokens WHERE token_hash = ?1",
            params![replay_new]
        ),
        "new",
        "a replay inside the window is kept"
    );
}

/// Inserts a family row of `user` with the given expiry and optional revocation time.
fn family_row(conn: &Connection, user: i64, expires: i64, revoked: Option<i64>) -> i64 {
    conn.execute(
        "INSERT INTO token_families (public_id, user_id, client_id, client_name, auth_epoch, \
         created_at, expires_at, revoked_at) VALUES (?1, ?2, 'dcr_x', 'C', 0, 0, ?3, ?4)",
        params![random_token("fam_"), user, expires, revoked],
    )
    .expect("family row");
    conn.last_insert_rowid()
}

/// One access row and one refresh row and one disconnect link for `family`.
fn add_pair_rows(conn: &Connection, family: i64, access_expires: i64, refresh_expires: i64) {
    conn.execute(
        "INSERT INTO access_tokens (token_hash, family_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash(&random_token("dw_at_")), family, access_expires],
    )
    .expect("access row");
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at) \
         VALUES (?1, ?2, 0, ?3)",
        params![token_hash(&random_token("dw_rt_")), family, refresh_expires],
    )
    .expect("refresh row");
    conn.execute(
        "INSERT INTO disconnect_links (token_hash, family_id, created_at) VALUES (?1, ?2, 0)",
        params![token_hash(&random_token("dw_dl_")), family],
    )
    .expect("link row");
}

fn count_family(conn: &Connection, family: i64) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM token_families WHERE id = ?1",
        params![family],
        |row| row.get(0),
    )
    .expect("count")
}

/// Refresh rows of `family` that no refresh has used yet.
fn unused_rows(gw: &Gateway, family: i64) -> i64 {
    scalar(
        gw,
        "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = ?1 AND used_at IS NULL",
        params![family],
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_under_another_media_type_is_refused_and_a_case_variant_is_read() {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let body = form_body(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_id", s.client.as_str()),
    ]);
    let plain = http
        .post_raw("/oauth/token", "text/plain", body.clone())
        .await;
    assert_refused(&plain, "invalid_request", "a text/plain body");
    assert_eq!(
        unused_rows(&s.gw, family),
        1,
        "a refused body must not use the token"
    );
    let accepted = http
        .post_raw(
            "/oauth/token",
            "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
            body,
        )
        .await;
    tokens_of(&accepted);
}

/// Connects, applies `change` to the stored state, then checks that a refresh is refused and
/// that it adds no row and uses no token.
async fn refresh_refused_after(change: impl FnOnce(&Scene), case: &str) {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let access = access_rows(&s.gw, family);
    let refresh_count = refresh_rows(&s.gw, family);
    change(&s);
    let refused = refresh(&http, &s.client, &refresh_token, None).await;
    assert_refused(&refused, "invalid_grant", case);
    assert_eq!(
        access_rows(&s.gw, family),
        access,
        "{case}: no access row may be added"
    );
    assert_eq!(
        refresh_rows(&s.gw, family),
        refresh_count,
        "{case}: no refresh row may be added"
    );
    assert_eq!(
        unused_rows(&s.gw, family),
        1,
        "{case}: the token must stay unused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_for_a_revoked_disabled_or_unassigned_user_is_refused_and_writes_nothing() {
    refresh_refused_after(
        |s| {
            session::revoke_all(&s.gw.conn(), s.bob_id).expect("revoke_all");
        },
        "after revoke_all",
    )
    .await;
    refresh_refused_after(
        |s| {
            s.gw.conn()
                .execute(
                    "UPDATE users SET disabled = 1 WHERE id = ?1",
                    params![s.bob_id],
                )
                .expect("disable");
        },
        "after disabling",
    )
    .await;
    refresh_refused_after(
        |s| {
            s.gw.conn()
                .execute(
                    "DELETE FROM user_servers WHERE user_id = ?1",
                    params![s.bob_id],
                )
                .expect("unassign");
        },
        "after unassignment",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_naming_another_server_is_invalid_target_and_the_token_stays_unused() {
    let s = scene().await;
    let http = s.gw.http();
    let (_, refresh_token) = connect(&s).await;
    let family = family_of(&s.gw, &refresh_token);
    let other = format!("{}/other", s.gw.base);
    let wrong = refresh(&http, &s.client, &refresh_token, Some(other.as_str())).await;
    assert_refused(&wrong, "invalid_target", "a refresh for another server");
    assert_eq!(
        unused_rows(&s.gw, family),
        1,
        "a refused refresh must not use the token"
    );
    let demo = s.resource();
    let right = refresh(&http, &s.client, &refresh_token, Some(demo.as_str())).await;
    tokens_of(&right);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_refresh_lifetime_ends_at_thirty_days_and_not_before() {
    let inside = scene().await;
    let http = inside.gw.http();
    let (_, kept) = connect(&inside).await;
    inside
        .gw
        .clock
        .advance(time::Duration::seconds(30 * DAY - 1));
    tokens_of(&refresh(&http, &inside.client, &kept, None).await);

    let late = scene().await;
    let http = late.gw.http();
    let (_, expired) = connect(&late).await;
    let family = family_of(&late.gw, &expired);
    late.gw.clock.advance(time::Duration::seconds(30 * DAY + 1));
    let reply = refresh(&http, &late.client, &expired, None).await;
    assert_refused(&reply, "invalid_grant", "a refresh 30 days and 1 second on");
    let family_expires = scalar(
        &late.gw,
        "SELECT expires_at FROM token_families WHERE id = ?1",
        params![family],
    );
    assert!(
        family_expires > NOW + 30 * DAY + 1,
        "the refusal must come from the refresh token, not the family"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unassigning_on_the_server_page_revokes_that_pair_only() {
    let gw = Gateway::start().await;
    let owner = sign_in(&gw, add_user(&gw, OWNER, "owner"));
    let bob = add_user(&gw, BOB, "user");
    let carol = add_user(&gw, CAROL, "user");
    let demo = add_server(&gw, "demo");
    let other = add_server(&gw, "other");
    assign(&gw, bob, demo);
    assign(&gw, bob, other);
    assign(&gw, carol, demo);
    let bob_demo = direct_family(&gw, bob, demo);
    let bob_other = direct_family(&gw, bob, other);
    let carol_demo = direct_family(&gw, carol, demo);

    let page = owner.get(&format!("/admin/servers/{demo}")).await;
    assert_eq!(page.status, 200, "the server page must render");
    let csrf = csrf_in(&page.body);
    let carol_id = carol.to_string();
    let saved = owner
        .post(
            &format!("/admin/servers/{demo}/users"),
            &[("csrf", csrf.as_str()), ("user_id", carol_id.as_str())],
        )
        .await;
    assert_eq!(
        saved.status, 303,
        "the assignment must answer 303: {}",
        saved.body
    );
    assert!(
        is_revoked(&gw, bob_demo),
        "the removed pair's family is revoked"
    );
    assert!(
        !is_revoked(&gw, carol_demo),
        "the kept user's family on the server is untouched"
    );
    assert!(
        !is_revoked(&gw, bob_other),
        "the same user's family on another server is untouched"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweep_runs_on_start_and_leaves_the_live_family() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let db = dir.path().join("doorward.db");
    Db::open(&db).expect("database with its schema");
    let conn = open(&db);
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
        params![BOB],
    )
    .expect("user");
    let bob = conn.last_insert_rowid();
    let family = family_row(&conn, bob, NOW + DAY, None);
    add_pair_rows(&conn, family, NOW - 3601, NOW + DAY);
    drop(conn);

    let gw = Gateway::start_on(dir, db, |_| {}).await;
    for _ in 0..30 {
        if access_rows(&gw, family) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        access_rows(&gw, family),
        0,
        "the access row expired more than an hour ago must be swept within 3 seconds"
    );
    assert!(!is_revoked(&gw, family), "the live family is not revoked");
    assert_eq!(
        count_family(&gw.conn(), family),
        1,
        "the live family must remain"
    );
    assert_eq!(refresh_rows(&gw, family), 1, "the live refresh row remains");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweep_on_start_deletes_expired_sessions_and_keeps_live_ones() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let db = dir.path().join("doorward.db");
    Db::open(&db).expect("database with its schema");
    let conn = open(&db);
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
        params![BOB],
    )
    .expect("user");
    let bob = conn.last_insert_rowid();
    for (id_hash, expires_at) in [("expired_session", NOW - 1), ("live_session", NOW + DAY)] {
        conn.execute(
            "INSERT INTO sessions (id_hash, user_id, auth_epoch, created_at, expires_at) \
             VALUES (?1, ?2, 0, 0, ?3)",
            params![id_hash, bob, expires_at],
        )
        .expect("session");
    }
    drop(conn);

    fn rows(gw: &Gateway, id_hash: &str) -> i64 {
        scalar(
            gw,
            "SELECT COUNT(*) FROM sessions WHERE id_hash = ?1",
            params![id_hash],
        )
    }

    let gw = Gateway::start_on(dir, db, |_| {}).await;
    for _ in 0..30 {
        if rows(&gw, "expired_session") == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        rows(&gw, "expired_session"),
        0,
        "the expired session must be swept within 3 seconds"
    );
    assert_eq!(rows(&gw, "live_session"), 1, "the live session remains");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_combined_endpoint_code_needs_no_assignment_and_names_its_resource() {
    let gw = Gateway::start().await;
    let bob = sign_in(&gw, add_user(&gw, BOB, "user"));
    let http = gw.http();
    let client = register(&http, "Cursor", REDIRECT).await;
    let combined = format!("{}/mcp", gw.base);
    let demo = format!("{}/demo", gw.base);
    let issued = issue(&bob, &client, REDIRECT, &combined).await;

    let wrong = redeem(&http, &client, &issued, Some(REDIRECT), Some(demo.as_str())).await;
    assert_refused(&wrong, "invalid_target", "a server path for combined code");

    let reply = redeem(
        &http,
        &client,
        &issued,
        Some(REDIRECT),
        Some(combined.as_str()),
    )
    .await;
    let (_, refresh_token) = tokens_of(&reply);
    let family = family_of(&gw, &refresh_token);
    assert_eq!(
        scalar(
            &gw,
            "SELECT COUNT(*) FROM token_families WHERE id = ?1 AND server_id IS NULL",
            params![family],
        ),
        1,
        "the combined code's family has no server"
    );
    let again = refresh(&http, &client, &refresh_token, Some(combined.as_str())).await;
    tokens_of(&again);
}
