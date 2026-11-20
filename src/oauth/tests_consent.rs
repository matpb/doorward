//! Authorize, the sign-in hand-over and consent: pure checks and gateway tests of the storage rules.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use form_urlencoded::Serializer;
use rusqlite::{Connection, params};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

use crate::accounts::login;
use crate::accounts::session;
use crate::app::{Deps, assemble, serve};
use crate::cimd::CimdFuture;
use crate::clock::SystemClock;
use crate::config::{Config, Limits};
use crate::crypto::{PasswordHasher, token_hash};
use crate::web::{CSRF_COOKIE, SESSION_COOKIE, content_security_policy};
use crate::{CimdError, CimdFetcher, ClientMetadata};

use super::authorize::{Params, Resource, back_url, check_request, is_request_id, resource_of};
use super::consent::{document_name, fetch_within};

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ISSUER: &str = "https://auth.example.com";
const REDIRECT: &str = "http://127.0.0.1:53535/callback";
const DOC_ID: &str = "https://client.example.com/app.json";
const BLOCKED: &str = "https://attacker.example.com/cb";

// ---- Pure checks ----

fn query(pairs: &[(&str, &str)]) -> Params {
    let mut text = Serializer::new(String::new());
    text.extend_pairs(pairs);
    Params::parse(&text.finish()).expect("no repeated names")
}

/// Request parameters as name and value pairs.
type Pairs<'a> = Vec<(&'a str, &'a str)>;

/// The parameters of a valid S256 request for `resource`.
fn pairs_for(resource: &str) -> Pairs<'_> {
    vec![
        ("response_type", "code"),
        ("client_id", DOC_ID),
        ("redirect_uri", REDIRECT),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", resource),
        ("state", "s1"),
    ]
}

fn without<'a>(mut pairs: Vec<(&'a str, &'a str)>, name: &str) -> Vec<(&'a str, &'a str)> {
    pairs.retain(|(key, _)| *key != name);
    pairs
}

fn replacing<'a>(
    pairs: Vec<(&'a str, &'a str)>,
    name: &'a str,
    value: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut pairs = without(pairs, name);
    pairs.push((name, value));
    pairs
}

#[test]
fn a_request_id_has_the_prefix_and_43_base64url_characters() {
    let body = "a".repeat(43);
    assert!(is_request_id(&format!("dw_rq_{body}")));
    assert!(is_request_id(&format!("dw_rq_{}a", "-_".repeat(21))));
    assert!(!is_request_id(&format!("dw_ac_{body}")), "another prefix");
    assert!(
        !is_request_id(&format!("dw_rq_{}", "a".repeat(42))),
        "42 characters"
    );
    assert!(
        !is_request_id(&format!("dw_rq_{}", "a".repeat(44))),
        "44 characters"
    );
    assert!(
        !is_request_id(&format!("dw_rq_{}+", "a".repeat(42))),
        "a plus sign"
    );
    assert!(
        !is_request_id(&format!("dw_rq_{}.", "a".repeat(42))),
        "a dot"
    );
    assert!(!is_request_id("dw_rq_"), "the prefix alone");
    assert!(!is_request_id(""), "empty");
}

#[test]
fn a_sign_in_goes_to_consent_only_for_a_request_id() {
    let req = format!("dw_rq_{}", "b".repeat(43));
    assert_eq!(
        login::after_sign_in(&req),
        format!("/oauth/consent?req={req}")
    );
    assert_eq!(login::after_sign_in("dw_rq_short"), "/account");
    assert_eq!(login::after_sign_in(""), "/account");
    assert_eq!(
        login::after_sign_in("https://evil.example.com/"),
        "/account"
    );
}

#[test]
fn a_document_name_of_direction_characters_is_the_host() {
    let host = "client.example.com";
    assert_eq!(
        document_name(Some("Example Client"), host),
        "Example Client"
    );
    assert_eq!(document_name(Some("\u{202E}\u{202E}"), host), host);
    assert_eq!(document_name(Some("evil\u{202E}name"), host), host);
    assert_eq!(document_name(Some("zero\u{200B}width"), host), host);
    assert_eq!(
        document_name(Some("line\nbreak"), host),
        host,
        "a control character"
    );
    assert_eq!(document_name(None, host), host, "an absent name");
    assert_eq!(document_name(Some(""), host), host, "an empty name");
    assert_eq!(document_name(Some("  \t "), host), host, "a blank name");
    let long = "n".repeat(150);
    assert_eq!(
        document_name(Some(long.as_str()), host),
        "n".repeat(100),
        "cut to 100 characters"
    );
    assert_eq!(document_name(Some("  Padded  "), host), "Padded");
}

#[test]
fn a_repeated_name_or_a_request_parameter_refuses_the_query() {
    assert!(Params::parse("a=1&a=2").is_none(), "a repeated name");
    assert!(Params::parse("request=x").is_none(), "request");
    assert!(
        Params::parse("request_uri=urn%3Ax").is_none(),
        "request_uri"
    );
    let params = Params::parse("state=a+b%20c&x=").expect("parsed");
    assert_eq!(
        params.get("state"),
        Some("a b c"),
        "values are form-decoded"
    );
    assert_eq!(params.get("x"), Some(""), "a present empty value");
    assert_eq!(params.get("missing"), None);
}

#[test]
fn each_step_four_problem_names_its_error() {
    let mcp = format!("{ISSUER}/mcp");
    let long_state = "s".repeat(1025);
    let cases: Vec<(&str, Pairs<'_>, Option<&str>)> = vec![
        ("the valid request", pairs_for(&mcp), None),
        (
            "response_type=token",
            replacing(pairs_for(&mcp), "response_type", "token"),
            Some("invalid_request"),
        ),
        (
            "no code_challenge",
            without(pairs_for(&mcp), "code_challenge"),
            Some("invalid_request"),
        ),
        (
            "a short challenge",
            replacing(pairs_for(&mcp), "code_challenge", "short"),
            Some("invalid_request"),
        ),
        (
            "plain method",
            replacing(pairs_for(&mcp), "code_challenge_method", "plain"),
            Some("invalid_request"),
        ),
        (
            "no resource",
            without(pairs_for(&mcp), "resource"),
            Some("invalid_target"),
        ),
        (
            "foreign resource",
            replacing(pairs_for(&mcp), "resource", "https://evil.example.com/demo"),
            Some("invalid_target"),
        ),
        (
            "a resource at /Bad_Slug",
            replacing(
                pairs_for(&mcp),
                "resource",
                "https://auth.example.com/Bad_Slug",
            ),
            Some("invalid_target"),
        ),
        (
            "prompt none",
            replacing(pairs_for(&mcp), "prompt", "none"),
            Some("interaction_required"),
        ),
        (
            "a state of 1024 bytes",
            replacing(pairs_for(&mcp), "state", &long_state[..1024]),
            None,
        ),
        (
            "a state of 1025 bytes",
            replacing(pairs_for(&mcp), "state", &long_state),
            Some("invalid_request"),
        ),
    ];
    for (step, pairs, error) in cases {
        assert_eq!(check_request(&query(&pairs), ISSUER).err(), error, "{step}");
    }
}

#[test]
fn a_server_resource_is_kept_as_its_slug() {
    let demo = format!("{ISSUER}/demo");
    let pairs = pairs_for(&demo);
    let asked = check_request(&query(&pairs), ISSUER).expect("valid");
    assert_eq!(asked.target_slug.as_deref(), Some("demo"));
    assert_eq!(asked.challenge, CHALLENGE);
}

#[test]
fn a_resource_is_the_issuer_with_mcp_or_a_valid_slug() {
    assert_eq!(
        resource_of(Some("https://auth.example.com/mcp"), ISSUER),
        Some(Resource::Combined)
    );
    assert_eq!(
        resource_of(Some("https://auth.example.com/demo"), ISSUER),
        Some(Resource::Server("demo".to_owned()))
    );
    for text in [
        "https://auth.example.com/",
        "https://auth.example.com",
        "https://auth.example.com/Bad_Slug",
        "https://auth.example.com/a/b",
        "https://auth.example.com/oauth",
        "https://evil.example.com/demo",
        "https://auth.example.com.evil.example.com/demo",
    ] {
        assert_eq!(resource_of(Some(text), ISSUER), None, "{text}");
    }
    assert_eq!(resource_of(None, ISSUER), None, "a missing resource");
}

#[test]
fn a_back_address_carries_the_pair_then_state_then_iss() {
    assert_eq!(
        back_url(ISSUER, REDIRECT, ("code", "dw_ac_x"), Some("a b&c")),
        "http://127.0.0.1:53535/callback?code=dw_ac_x&state=a+b%26c&iss=https%3A%2F%2Fauth.example.com"
    );
    assert_eq!(
        back_url(ISSUER, REDIRECT, ("error", "access_denied"), None),
        "http://127.0.0.1:53535/callback?error=access_denied&iss=https%3A%2F%2Fauth.example.com"
    );
}

// ---- The gateway ----

/// Answers every metadata fetch with one fixed result.
struct Fixed(Result<ClientMetadata, CimdError>);

impl CimdFetcher for Fixed {
    fn fetch<'a>(&'a self, _client_id: &'a str) -> CimdFuture<'a> {
        Box::pin(std::future::ready(self.0.clone()))
    }
}

fn fixed(result: Result<ClientMetadata, CimdError>) -> Arc<dyn CimdFetcher> {
    Arc::new(Fixed(result))
}

/// A metadata document for DOC_ID that lists REDIRECT.
fn document(name: Option<&str>) -> ClientMetadata {
    ClientMetadata {
        client_id: DOC_ID.to_owned(),
        client_name: name.map(str::to_owned),
        redirect_uris: vec![REDIRECT.to_owned()],
        token_endpoint_auth_method: Some("none".to_owned()),
    }
}

struct Gateway {
    base: String,
    db: PathBuf,
    _dir: TempDir,
}

async fn start(cimd: Arc<dyn CimdFetcher>) -> Gateway {
    start_with(cimd, |_| {}).await
}

async fn start_with(cimd: Arc<dyn CimdFetcher>, edit: impl FnOnce(&mut Config)) -> Gateway {
    let dir = tempfile::tempdir().expect("temporary directory");
    let hasher = PasswordHasher::new().await.expect("hasher");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let base = format!("http://{address}");
    let db = dir.path().join("doorward.db");
    let mut config = Config {
        public_url: base.clone(),
        listen: address,
        database: db.clone(),
        key_file: None,
        trusted_proxies: Vec::new(),
        shared_client_address: false,
        allowed_origins: Vec::new(),
        lifetimes: Default::default(),
        limits: Limits::default(),
        mail: Default::default(),
    };
    edit(&mut config);
    let deps = Deps {
        clock: Arc::new(SystemClock),
        cimd,
    };
    let gateway = assemble(config, deps, Arc::new(hasher))
        .await
        .expect("build");
    tokio::spawn(serve(listener, gateway.router, std::future::pending()));
    Gateway {
        base,
        db,
        _dir: dir,
    }
}

/// A browser that sends its cookie by hand and never follows redirects.
struct Browser {
    base: String,
    cookie: Option<String>,
    http: reqwest::Client,
}

/// A status, a Location and a body.
struct Reply {
    status: u16,
    location: Option<String>,
    body: String,
    /// The pre-session csrf cookie as `name=value`, when the answer set one.
    csrf_cookie: Option<String>,
    retry_after: Option<String>,
}

impl Reply {
    fn query(&self, name: &str) -> Option<String> {
        let origin = url::Url::parse("http://localhost/").ok()?;
        let target = origin.join(self.location.as_deref()?).ok()?;
        target
            .query_pairs()
            .find(|pair| pair.0 == name)
            .map(|pair| pair.1.into_owned())
    }

    fn main_attr(&self, name: &str) -> Option<String> {
        let doc = Html::parse_document(&self.body);
        let selector = Selector::parse("main").expect("selector");
        doc.select(&selector)
            .next()
            .and_then(|main| main.attr(name))
            .map(str::to_owned)
    }

    fn kind(&self) -> Option<String> {
        self.main_attr("data-page")
    }

    fn is_error(&self) -> bool {
        self.status == 400 && self.kind().as_deref() == Some("error")
    }
}

impl Browser {
    fn new(base: &str, cookie: Option<String>) -> Browser {
        Browser {
            base: base.to_owned(),
            cookie,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
        }
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Reply {
        let request = match &self.cookie {
            Some(cookie) => request.header("cookie", cookie.as_str()),
            None => request,
        };
        let response = request.send().await.expect("request");
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let csrf_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|line| line.starts_with(&format!("{CSRF_COOKIE}=")))
            .and_then(|line| line.split(';').next())
            .map(str::to_owned);
        let body = response.text().await.expect("body");
        Reply {
            status,
            location,
            body,
            csrf_cookie,
            retry_after,
        }
    }

    async fn get(&self, path: &str) -> Reply {
        self.send(self.http.get(format!("{}{path}", self.base)))
            .await
    }

    async fn post(&self, path: &str, fields: &[(&str, &str)]) -> Reply {
        let mut body = Serializer::new(String::new());
        body.extend_pairs(fields);
        self.send(
            self.http
                .post(format!("{}{path}", self.base))
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", self.base.as_str())
                .body(body.finish()),
        )
        .await
    }

    /// The csrf token of this browser's session, read from the account page.
    async fn csrf(&self) -> String {
        csrf_in(&self.get("/account").await.body)
    }

    /// Starts an authorization and returns the reply.
    async fn authorize(&self, client_id: &str, redirect: &str, resource: &str) -> Reply {
        let mut query = Serializer::new(String::new());
        query.extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("resource", resource),
            ("state", "s1"),
        ]);
        self.get(&format!("/oauth/authorize?{}", query.finish()))
            .await
    }

    /// The request id of an authorization that answered 303.
    async fn request_of(&self, client_id: &str, redirect: &str, resource: &str) -> String {
        let started = self.authorize(client_id, redirect, resource).await;
        assert_eq!(started.status, 303, "authorize must answer 303");
        started.query("req").expect("the 303 carries req")
    }

    /// Registers a public client and returns its id.
    async fn register(&self, name: &str, redirect: &str) -> String {
        let body = serde_json::json!({"client_name": name, "redirect_uris": [redirect]});
        let reply = self
            .send(
                self.http
                    .post(format!("{}/oauth/register", self.base))
                    .header("content-type", "application/json")
                    .body(body.to_string()),
            )
            .await;
        assert_eq!(reply.status, 201, "registration must answer 201");
        let json: serde_json::Value = serde_json::from_str(&reply.body).expect("json");
        json["client_id"].as_str().expect("client_id").to_owned()
    }
}

fn open(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("connection");
    conn.busy_timeout(Duration::from_secs(5)).expect("timeout");
    conn
}

fn count(path: &Path, sql: &str) -> i64 {
    open(path)
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

/// Inserts a user and a session for it; the returned browser presents that session.
fn signed_in(gw: &Gateway, email: &str) -> Browser {
    let conn = open(&gw.db);
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
        [email],
    )
    .expect("user");
    let user = conn.last_insert_rowid();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = session::insert(&conn, user, now, 86_400).expect("session");
    Browser::new(&gw.base, Some(format!("{SESSION_COOKIE}={token}")))
}

fn anonymous(gw: &Gateway) -> Browser {
    Browser::new(&gw.base, None)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_concurrent_approvals_give_one_code() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let shown = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(shown.status, 200, "the consent page must render");
    let csrf = bob.csrf().await;
    let fields = [
        ("csrf", csrf.as_str()),
        ("req", req.as_str()),
        ("decision", "approve"),
    ];
    let (first, second) = tokio::join!(
        bob.post("/oauth/consent", &fields),
        bob.post("/oauth/consent", &fields)
    );
    let replies = [first, second];
    let codes = replies
        .iter()
        .filter(|reply| reply.status == 303 && reply.query("code").is_some())
        .count();
    let errors = replies.iter().filter(|reply| reply.is_error()).count();
    assert_eq!(
        (codes, errors),
        (1, 1),
        "of two concurrent approvals one gives a code and the other an error page"
    );
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_without_a_rendered_page_mints_nothing() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let csrf = bob.csrf().await;
    let never_opened = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(never_opened.is_error(), "an approval never rendered is 400");
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 0);

    let failing = start(fixed(Err(CimdError::Fetch("down".into())))).await;
    let bob = signed_in(&failing, "bob@example.com");
    let combined = format!("{}/mcp", failing.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let page = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert!(page.is_error(), "a failed document fetch is 400");
    let csrf = bob.csrf().await;
    let approved = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(
        approved.is_error(),
        "an approval after a failed fetch is 400"
    );
    assert_eq!(count(&failing.db, "SELECT COUNT(*) FROM auth_codes"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deny_by_another_session_is_refused_and_the_request_stays() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let carol = signed_in(&gw, "carol@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let shown = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(shown.status, 200);
    let carols_csrf = carol.csrf().await;
    let denied = carol
        .post(
            "/oauth/consent",
            &[
                ("csrf", carols_csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "deny"),
            ],
        )
        .await;
    assert!(denied.is_error(), "another session's deny is 400");
    let hash = token_hash(&req);
    let rows = count(
        &gw.db,
        &format!("SELECT COUNT(*) FROM auth_requests WHERE id_hash = '{hash}'"),
    );
    assert_eq!(rows, 1, "the request stays after another session's deny");
    let csrf = bob.csrf().await;
    let approved = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(
        approved.query("code").is_some(),
        "the owner can still approve"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deny_without_a_rendered_page_is_refused_and_the_request_stays() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let csrf = bob.csrf().await;
    let denied = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "deny"),
            ],
        )
        .await;
    assert!(denied.is_error(), "a deny never rendered is 400");
    assert!(
        denied.location.is_none(),
        "a refused deny carries no redirect"
    );
    let hash = token_hash(&req);
    let rows = count(
        &gw.db,
        &format!("SELECT COUNT(*) FROM auth_requests WHERE id_hash = '{hash}'"),
    );
    assert_eq!(rows, 1, "the request stays after a refused deny");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_started_signed_in_is_closed_to_other_browsers() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let carol = signed_in(&gw, "carol@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let peek = carol.get(&format!("/oauth/consent?req={req}")).await;
    assert!(peek.is_error(), "another signed-in browser's GET is 400");
    let carols_csrf = carol.csrf().await;
    let poke = carol
        .post(
            "/oauth/consent",
            &[
                ("csrf", carols_csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(
        poke.is_error(),
        "another signed-in browser's approval is 400"
    );
    let owner_page = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(owner_page.status, 200, "the owner still sees the page");
    let csrf = bob.csrf().await;
    let approved = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(approved.query("code").is_some(), "the owner approves");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_201st_live_request_evicts_the_oldest() {
    let gw = start_with(fixed(Ok(document(None))), |config| {
        config.limits.oauth_burst = 1000;
    })
    .await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    let mut first = None;
    let mut last = String::new();
    for index in 0..201 {
        let reply = browser.authorize(DOC_ID, REDIRECT, &combined).await;
        assert_eq!(reply.status, 303, "request {index} must be answered 303");
        let req = reply.query("req").expect("req");
        if index == 0 {
            first = Some(req.clone());
        }
        last = req;
    }
    let first = first.expect("the first request");
    assert_eq!(
        count(
            &gw.db,
            &format!(
                "SELECT COUNT(*) FROM auth_requests WHERE id_hash = '{}'",
                token_hash(&first)
            )
        ),
        0,
        "the oldest request is evicted"
    );
    assert_eq!(
        count(
            &gw.db,
            &format!(
                "SELECT COUNT(*) FROM auth_requests WHERE id_hash = '{}'",
                token_hash(&last)
            )
        ),
        1,
        "the newest request is kept"
    );
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM auth_requests WHERE address = '127.0.0.1'"
        ),
        200,
        "one address holds at most 200 live requests"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_identical_blocked_redirect_writes_no_second_row() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let client_id = browser.register("Attacker", BLOCKED).await;
    let combined = format!("{}/mcp", gw.base);
    for _ in 0..2 {
        let refused = browser.authorize(&client_id, BLOCKED, &combined).await;
        assert!(refused.is_error(), "a blocked redirect is an error page");
    }
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM activity WHERE kind = 'redirect_blocked'"
        ),
        1,
        "the second identical block is not recorded again"
    );
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM activity WHERE kind = 'redirect_blocked' AND detail = 'https://attacker.example.com/cb'"
        ),
        1,
        "the recorded detail is the address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_url_shaped_client_writes_no_blocked_row() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    for index in 0..60 {
        let redirect = format!("https://n{index}.attacker.example.com/cb");
        let reply = browser
            .authorize("https://any.example.com/x", &redirect, &combined)
            .await;
        assert!(reply.is_error(), "request {index} is an error page");
        assert!(
            reply.body.contains(&format!(
                "Doorward will not send you to n{index}.attacker.example.com."
            )),
            "request {index} names its redirect host as before"
        );
    }
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM activity WHERE kind = 'redirect_blocked'"
        ),
        0,
        "a document client that is not fetched yet writes no row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registered_client_blocked_twice_writes_one_row() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let client_id = browser.register("Attacker", BLOCKED).await;
    let combined = format!("{}/mcp", gw.base);
    for _ in 0..2 {
        let refused = browser.authorize(&client_id, BLOCKED, &combined).await;
        assert!(refused.is_error(), "a blocked redirect is an error page");
    }
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM activity WHERE kind = 'redirect_blocked' AND client = 'Attacker'"
        ),
        1,
        "a registered client's blocked redirect writes one row, and not a second"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn blocked_rows_stop_at_fifty_an_hour_and_resume_after_it() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let conn = open(&gw.db);
    for index in 0..50 {
        conn.execute(
            "INSERT INTO activity (at, kind, client, detail) \
             VALUES (?1, 'redirect_blocked', 'Seed', ?2)",
            params![now, format!("https://seed{index}.attacker.example.com/cb")],
        )
        .expect("seed row");
    }
    let late = "https://n51.attacker.example.com/cb";
    let client_id = browser.register("Attacker", late).await;
    let refused = browser.authorize(&client_id, late, &combined).await;
    assert!(refused.is_error(), "the 51st address is refused");
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM activity WHERE kind = 'redirect_blocked'"
        ),
        50,
        "a 51st distinct address writes nothing while 50 rows are inside the hour"
    );
    conn.execute(
        "UPDATE activity SET at = at - 3601 WHERE kind = 'redirect_blocked'",
        [],
    )
    .expect("the rows age past the hour");
    let again = browser.authorize(&client_id, late, &combined).await;
    assert!(again.is_error(), "the 51st address is still refused");
    assert_eq!(
        count(
            &gw.db,
            &format!("SELECT COUNT(*) FROM activity WHERE detail = '{late}'")
        ),
        1,
        "once the rows are older than an hour, the address is written"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_req_of_the_wrong_shape_is_refused() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let anonymous = anonymous(&gw);
    assert!(bob.get("/oauth/consent?req=dw_rq_short").await.is_error());
    assert!(bob.get("/oauth/consent").await.is_error(), "no req at all");
    assert!(
        anonymous
            .get("/oauth/consent?req=dw_rq_short")
            .await
            .is_error(),
        "a bad req is refused before the sign-in redirect"
    );
    let csrf = bob.csrf().await;
    let posted = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", "dw_rq_short"),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(posted.is_error(), "a bad req in a post is 400");
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_client_named_by_direction_characters_shows_its_host() {
    let gw = start(fixed(Ok(document(Some("\u{202E}\u{202E}evil"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let page = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.main_attr("data-client-name").as_deref(),
        Some("client.example.com"),
        "a name of direction characters is replaced by the host"
    );
    assert_eq!(
        page.main_attr("data-client-verified").as_deref(),
        Some("yes")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_state_over_1024_bytes_goes_back_without_an_echo() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    let long_state = "s".repeat(1025);
    let mut query = Serializer::new(String::new());
    query.extend_pairs([
        ("response_type", "code"),
        ("client_id", DOC_ID),
        ("redirect_uri", REDIRECT),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", combined.as_str()),
        ("state", long_state.as_str()),
    ]);
    let reply = browser
        .get(&format!("/oauth/authorize?{}", query.finish()))
        .await;
    assert_eq!(reply.status, 303, "the refusal goes back to the client");
    let location = reply.location.clone().expect("a Location");
    assert!(location.starts_with(REDIRECT), "to the client: {location}");
    assert_eq!(reply.query("error").as_deref(), Some("invalid_request"));
    assert_eq!(
        reply.query("state"),
        None,
        "an oversized state is not echoed"
    );
    assert_eq!(reply.query("iss").as_deref(), Some(gw.base.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_scope_parameter_is_ignored() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    let mut query = Serializer::new(String::new());
    query.extend_pairs([
        ("response_type", "code"),
        ("client_id", DOC_ID),
        ("redirect_uri", REDIRECT),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", combined.as_str()),
        ("scope", "admin everything"),
    ]);
    let reply = browser
        .get(&format!("/oauth/authorize?{}", query.finish()))
        .await;
    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.location.as_deref().and_then(|l| l.split('?').next()),
        Some("/login"),
        "a request with another scope is stored like any other"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_address_that_does_not_parse_is_not_recorded() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    let odd = "https://attacker.example.com/a?b=c";
    let reply = browser.authorize(DOC_ID, odd, &combined).await;
    assert!(
        reply.is_error(),
        "an address outside the grammar is an error page"
    );
    assert!(
        reply.body.contains("attacker.example.com"),
        "the page names the host"
    );
    assert_eq!(
        count(
            &gw.db,
            "SELECT COUNT(*) FROM activity WHERE kind = 'redirect_blocked'"
        ),
        0,
        "an address that does not parse is not something an admin could allow"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_anonymous_approval_with_a_pre_session_token_goes_to_sign_in() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let combined = format!("{}/mcp", gw.base);
    let browser = anonymous(&gw);
    let req = browser.request_of(DOC_ID, REDIRECT, &combined).await;
    let login = browser.get(&format!("/login?req={req}")).await;
    let cookie = login
        .csrf_cookie
        .clone()
        .expect("the sign-in page sets the pre-session csrf cookie");
    let csrf = csrf_in(&login.body);
    let armed = Browser::new(&gw.base, Some(cookie));
    let reply = armed
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_eq!(reply.status, 303, "an anonymous approval answers 303");
    assert_eq!(reply.location.as_deref(), Some("/login"));
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_is_refused_once_the_server_is_unassigned() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    assign(&gw, "bob@example.com", "demo");
    let req = bob
        .request_of(DOC_ID, REDIRECT, &format!("{}/demo", gw.base))
        .await;
    let shown = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(shown.status, 200, "the page renders while assigned");
    open(&gw.db)
        .execute(
            "DELETE FROM user_servers WHERE user_id = (SELECT id FROM users WHERE email = 'bob@example.com')",
            [],
        )
        .expect("unassign");
    let csrf = bob.csrf().await;
    let refused = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_eq!(refused.status, 403, "an approval after unassignment is 403");
    assert_eq!(refused.kind().as_deref(), Some("no-access"));
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_is_refused_once_the_address_is_blocked_again() {
    let gw = start(fixed(Ok(document(None)))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let address = "https://app.example.com/cb";
    open(&gw.db)
        .execute(
            "INSERT INTO redirect_allow (scheme, host, path_prefix, source, enabled) \
             VALUES ('https', 'app.example.com', '/cb', 'added', 1)",
            [],
        )
        .expect("allow");
    let client_id = bob.register("App", address).await;
    let req = bob
        .request_of(&client_id, address, &format!("{}/mcp", gw.base))
        .await;
    assert_eq!(
        bob.get(&format!("/oauth/consent?req={req}")).await.status,
        200
    );
    open(&gw.db)
        .execute(
            "UPDATE redirect_allow SET enabled = 0 WHERE host = 'app.example.com'",
            [],
        )
        .expect("disable");
    let csrf = bob.csrf().await;
    let refused = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(refused.is_error(), "a blocked address at approval is 400");
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_is_refused_once_the_registration_is_gone() {
    let gw = start(fixed(Ok(document(None)))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let client_id = bob.register("Cursor", REDIRECT).await;
    let req = bob
        .request_of(&client_id, REDIRECT, &format!("{}/mcp", gw.base))
        .await;
    assert_eq!(
        bob.get(&format!("/oauth/consent?req={req}")).await.status,
        200
    );
    open(&gw.db)
        .execute(
            "DELETE FROM oauth_clients WHERE client_id = ?1",
            [client_id.as_str()],
        )
        .expect("delete");
    let csrf = bob.csrf().await;
    let refused = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    assert!(refused.is_error(), "a registration gone at approval is 400");
    assert_eq!(count(&gw.db, "SELECT COUNT(*) FROM auth_codes"), 0);
}

/// Inserts a server with this slug and assigns it to the user, directly in the database.
fn assign(gw: &Gateway, email: &str, slug: &str) -> i64 {
    let conn = open(&gw.db);
    conn.execute(
        "INSERT INTO servers (name, slug, upstream_url, created_at) VALUES (?1, ?1, 'http://127.0.0.1:9', 0)",
        [slug],
    )
    .expect("server");
    let server = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO user_servers (user_id, server_id) SELECT id, ?1 FROM users WHERE email = ?2",
        rusqlite::params![server, email],
    )
    .expect("assignment");
    server
}

/// The fields of the one code row, as the approval stored them.
fn code_row(
    gw: &Gateway,
    code: &str,
) -> (
    String,
    String,
    i64,
    Option<i64>,
    i64,
    String,
    String,
    i64,
    i64,
) {
    open(&gw.db)
        .query_row(
            "SELECT client_id, redirect_uri, user_id, server_id, combined, client_name, \
             code_challenge, auth_epoch, expires_at - created_at FROM auth_codes WHERE code_hash = ?1",
            [token_hash(code)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .expect("the code row")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_stores_the_code_it_promises() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    open(&gw.db)
        .execute(
            "UPDATE users SET auth_epoch = 7 WHERE email = 'bob@example.com'",
            [],
        )
        .expect("user epoch");
    open(&gw.db)
        .execute(
            "UPDATE sessions SET auth_epoch = 7 WHERE user_id = \
             (SELECT id FROM users WHERE email = 'bob@example.com')",
            [],
        )
        .expect("session epoch");
    let server = assign(&gw, "bob@example.com", "demo");
    let demo = format!("{}/demo", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &demo).await;
    let shown = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(shown.status, 200);
    let csrf = bob.csrf().await;
    let granted = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    let code = granted.query("code").expect("an approval carries a code");
    assert!(code.starts_with("dw_ac_"), "the code prefix");
    let user: i64 = open(&gw.db)
        .query_row(
            "SELECT id FROM users WHERE email = 'bob@example.com'",
            [],
            |row| row.get(0),
        )
        .expect("bob");
    let stored = code_row(&gw, &code);
    assert_eq!(
        stored,
        (
            DOC_ID.to_owned(),
            REDIRECT.to_owned(),
            user,
            Some(server),
            0,
            "Example Client".to_owned(),
            CHALLENGE.to_owned(),
            7,
            60,
        ),
        "the code is bound to the client, redirect, user, server, challenge and epoch, for 60 seconds"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registered_client_is_marked_used_by_its_code() {
    let gw = start(fixed(Ok(document(None)))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let combined = format!("{}/mcp", gw.base);
    let client_id = bob.register("Cursor", REDIRECT).await;
    let req = bob.request_of(&client_id, REDIRECT, &combined).await;
    let page = bob.get(&format!("/oauth/consent?req={req}")).await;
    assert_eq!(
        page.main_attr("data-client-verified").as_deref(),
        Some("no")
    );
    assert_eq!(
        page.main_attr("data-client-name").as_deref(),
        Some("Cursor")
    );
    let csrf = bob.csrf().await;
    let granted = bob
        .post(
            "/oauth/consent",
            &[
                ("csrf", csrf.as_str()),
                ("req", req.as_str()),
                ("decision", "approve"),
            ],
        )
        .await;
    let code = granted.query("code").expect("a code");
    assert_eq!(
        code_row(&gw, &code).5,
        "Cursor",
        "the stored name is the registered name"
    );
    let used: Option<i64> = open(&gw.db)
        .query_row(
            "SELECT used_at FROM oauth_clients WHERE client_id = ?1",
            [client_id.as_str()],
            |row| row.get(0),
        )
        .expect("the registration row");
    assert!(
        used.is_some(),
        "the registration is marked used by its code"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_consent_page_shows_its_parts_in_order_with_two_decisions() {
    let gw = start(fixed(Ok(document(Some("Example Client"))))).await;
    let bob = signed_in(&gw, "bob@example.com");
    let combined = format!("{}/mcp", gw.base);
    let req = bob.request_of(DOC_ID, REDIRECT, &combined).await;
    let page = bob.get(&format!("/oauth/consent?req={req}")).await;
    let body = page.body.clone();
    let places: Vec<usize> = [
        "You will be sent to",
        "Example Client published by client.example.com",
        "Server: all servers",
        "Signed in as",
    ]
    .iter()
    .map(|text| body.find(text).unwrap_or_else(|| panic!("{text} missing")))
    .collect();
    assert!(
        places.windows(2).all(|pair| pair[0] < pair[1]),
        "headline, client, server, then the signed-in user: {places:?}"
    );
    assert!(
        body.contains("This app runs on your computer."),
        "a loopback redirect carries the local-app sentence"
    );
    assert!(
        body.contains("Approve only if you started this sign-in yourself."),
        "every consent page carries the notice"
    );
    let doc = Html::parse_document(&body);
    let forms = Selector::parse(r#"form[action="/oauth/consent"]"#).expect("selector");
    let decisions: Vec<String> = doc
        .select(&forms)
        .map(|form| {
            let field = |name: &str| {
                let selector =
                    Selector::parse(&format!(r#"input[name="{name}"]"#)).expect("selector");
                form.select(&selector)
                    .next()
                    .and_then(|input| input.attr("value"))
                    .map(str::to_owned)
                    .unwrap_or_default()
            };
            assert_eq!(field("req"), req, "each form carries the request id");
            assert!(!field("csrf").is_empty(), "each form carries a csrf token");
            field("decision")
        })
        .collect();
    assert_eq!(
        decisions,
        ["approve", "deny"],
        "two forms, approve then deny"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attacker_chosen_host_text_is_never_printed() {
    let gw = start(fixed(Ok(document(None)))).await;
    let browser = anonymous(&gw);
    let combined = format!("{}/mcp", gw.base);
    let prose = browser
        .authorize(DOC_ID, "x://Your account is locked. Call now/cb", &combined)
        .await;
    assert!(
        prose.is_error(),
        "an address outside the grammar is an error page"
    );
    assert!(
        !prose.body.contains("locked") && !prose.body.contains("Call now"),
        "free text in the authority is not printed"
    );
    let markup = browser
        .authorize(DOC_ID, "https://evil.example.com<b>/cb", &combined)
        .await;
    assert!(
        markup.is_error(),
        "markup in the authority is an error page"
    );
    assert!(
        !markup.body.contains("<b>") && !markup.body.contains("evil.example.com"),
        "a host with markup is not printed"
    );
}

/// Never answers a metadata fetch.
struct Never;

impl CimdFetcher for Never {
    fn fetch<'a>(&'a self, _client_id: &'a str) -> CimdFuture<'a> {
        Box::pin(std::future::pending::<Result<ClientMetadata, CimdError>>())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_that_never_answers_is_cut_off() {
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        fetch_within(&Never, DOC_ID, Duration::from_millis(50)),
    )
    .await
    .expect("the time limit must end the fetch within 2 seconds");
    assert!(outcome.is_none(), "a fetch past its limit is refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_that_answers_at_once_is_used() {
    let fetcher = Fixed(Ok(document(Some("Example Client"))));
    let outcome = fetch_within(&fetcher, DOC_ID, Duration::from_secs(5)).await;
    assert_eq!(
        outcome.and_then(|metadata| metadata.client_name),
        Some("Example Client".to_owned())
    );
}

#[test]
fn the_policy_text_is_fixed_and_takes_one_form_target() {
    let standard = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; \
                    frame-ancestors 'none'; base-uri 'none'";
    assert_eq!(content_security_policy(None), standard);
    assert_eq!(
        content_security_policy(Some("https://a.example.com")),
        standard.replace(
            "form-action 'self';",
            "form-action 'self' https://a.example.com;"
        )
    );
}

/// The csrf token of the first form in a page.
fn csrf_in(body: &str) -> String {
    let doc = Html::parse_document(body);
    let selector = Selector::parse(r#"input[name="csrf"]"#).expect("selector");
    doc.select(&selector)
        .next()
        .and_then(|input| input.attr("value"))
        .map(str::to_owned)
        .expect("the page carries a csrf token")
}

/// Every request may be made once, then one per minute.
fn tight(config: &mut Config) {
    config.limits.general_burst = 1;
    config.limits.general_per_minute = 1;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limited_page_keeps_its_policy_and_a_limited_metadata_answer_is_json() {
    let gw = start_with(fixed(Ok(document(None))), tight).await;
    let http = reqwest::Client::new();
    let first = http
        .get(format!("{}/login", gw.base))
        .send()
        .await
        .expect("request");
    assert_eq!(first.status(), 200, "the first page is within the burst");
    let policy = first.headers()["content-security-policy"].clone();

    let limited = http
        .get(format!("{}/login", gw.base))
        .send()
        .await
        .expect("request");
    assert_eq!(limited.status(), 429, "the second page is limited");
    assert!(
        limited.headers()["content-type"]
            .to_str()
            .expect("text")
            .starts_with("text/html"),
        "a limited page answers HTML"
    );
    let wait: u64 = limited.headers()["retry-after"]
        .to_str()
        .expect("text")
        .parse()
        .expect("seconds");
    assert!(
        (1..=60).contains(&wait),
        "Retry-After is {wait}, not 1 to 60"
    );
    assert_eq!(limited.headers()["cache-control"], "no-store");
    assert_eq!(
        limited.headers()["content-security-policy"],
        policy,
        "the limited page carries the page's policy"
    );

    let metadata = http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            gw.base
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(metadata.status(), 429, "the metadata is limited too");
    assert_eq!(metadata.headers()["content-type"], "application/json");
    let body: Value = metadata.json().await.expect("json");
    assert_eq!(
        body,
        json!({
            "error": "too_many_requests",
            "error_description": "Too many requests. Try again later."
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_is_never_limited() {
    let gw = start_with(fixed(Ok(document(None))), tight).await;
    let http = reqwest::Client::new();
    for attempt in 1..=3 {
        let reply = http
            .get(format!("{}/healthz", gw.base))
            .send()
            .await
            .expect("request");
        assert_eq!(
            reply.status(),
            200,
            "health check {attempt} is never limited"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_path_is_limited_like_any_other_page() {
    let gw = start_with(fixed(Ok(document(None))), tight).await;
    let http = reqwest::Client::new();
    let first = http
        .get(format!("{}/no/such/page", gw.base))
        .send()
        .await
        .expect("request");
    assert_eq!(
        first.status(),
        404,
        "the first unknown path is within the burst"
    );
    let second = http
        .get(format!("{}/no/such/page", gw.base))
        .send()
        .await
        .expect("request");
    assert_eq!(second.status(), 429, "the second unknown path is limited");
    assert!(
        second.headers().contains_key("retry-after"),
        "with Retry-After"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_sign_in_waits_for_the_whole_block() {
    let gw = start_with(fixed(Ok(document(None))), |config| {
        config.limits.account_failures = 1;
        config.limits.block_minutes = 7;
    })
    .await;
    let page = anonymous(&gw).get("/login").await;
    let csrf = csrf_in(&page.body);
    let browser = Browser::new(&gw.base, page.csrf_cookie.clone());
    let fields = [
        ("csrf", csrf.as_str()),
        ("email", "nobody@example.com"),
        ("password", "a-wrong-password"),
        ("req", ""),
    ];
    let first = browser.post("/login", &fields).await;
    assert_ne!(
        first.status, 429,
        "the first attempt is counted, not blocked"
    );
    let blocked = browser.post("/login", &fields).await;
    assert_eq!(blocked.status, 429, "the second attempt is blocked");
    assert_eq!(
        blocked.retry_after.as_deref(),
        Some("420"),
        "the block lasts block_minutes * 60 seconds"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_throttled_password_change_waits_for_the_whole_block() {
    let gw = start_with(fixed(Ok(document(None))), |config| {
        config.limits.account_failures = 1;
        config.limits.block_minutes = 7;
    })
    .await;
    let bob = signed_in(&gw, "bob@example.com");
    let csrf = bob.csrf().await;
    let fields = [
        ("csrf", csrf.as_str()),
        ("current_password", "a-wrong-password"),
        ("new_password", "a-new-long-password"),
    ];
    let first = bob.post("/account/password", &fields).await;
    assert_ne!(
        first.status, 429,
        "the first change is counted, not blocked"
    );
    let blocked = bob.post("/account/password", &fields).await;
    assert_eq!(blocked.status, 429, "the second change is blocked");
    assert_eq!(
        blocked.retry_after.as_deref(),
        Some("420"),
        "the throttle lasts block_minutes * 60 seconds"
    );
}
