#[path = "common/admin.rs"]
mod admin;
#[path = "common/client.rs"]
mod client;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use admin::{ActivityRow, ServerSpec};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use client::{OAuthApp, TestClient, pkce, tokens};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const SESSION: &str = "__Host-doorward_session";
const CSRF: &str = "__Host-doorward_csrf";
const COOKIE_ATTRS: &str = "Path=/; Secure; HttpOnly; SameSite=Lax";
const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "http://127.0.0.1:9/cb";
const LOGIN_FIELDS: &str =
    r#"<input type="email" name="email"><input type="password" name="password">"#;
const TEST_PAGE: &str = r#"<p class="error">  Wrong   email
 or password. </p><p class="notice">Saved</p><form method="post"><input type="hidden" name="csrf" value="tok-123"><input type="text" name="email" value="owner@example.com"><a class="item" href="/a" data-x="1">First  link</a><a class="item" href="/b">Second</a><a class="item">Third</a></form>"#;
const ACTIVITY_ROWS: &str = r#"<ul><li data-kind="tool_call" data-user="7" data-server="demo" data-tool="echo" data-decision="allow" data-outcome="ok"></li><li data-kind="login" data-user="7" data-decision="allow" data-outcome="ok"></li></ul>"#;
const EFFECTIVE_TOOLS: &str = r#"<ul><li data-tool="echo" data-verdict="allow"></li><li data-tool="delete_db" data-verdict="deny"></li></ul>"#;

/// One request as the stub received it.
#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(given, _)| given == name)
            .map(|(_, value)| value.as_str())
    }

    fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(given, _)| given == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Form fields of the body, without the csrf field.
    fn fields(&self) -> Vec<(String, String)> {
        form_pairs(&self.body)
            .into_iter()
            .filter(|(key, _)| key != "csrf")
            .collect()
    }
}

fn form_pairs(text: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn form_value(req: &Recorded, name: &str) -> Option<String> {
    form_pairs(&req.body)
        .into_iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn query_value(req: &Recorded, name: &str) -> Option<String> {
    form_pairs(&req.query)
        .into_iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn cookie_value(req: &Recorded, name: &str) -> Option<String> {
    req.headers_named("cookie")
        .iter()
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

fn random_hex() -> String {
    format!("{:032x}", rand::random::<u128>())
}

#[derive(Clone)]
struct Grant {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    resource: Option<String>,
    state: Option<String>,
}

#[derive(Default)]
struct Store {
    requests: Vec<Recorded>,
    sessions: HashSet<String>,
    auth_requests: HashMap<String, Grant>,
    codes: HashMap<String, Grant>,
    refresh: HashMap<String, (String, Option<String>)>,
    servers: Vec<(String, String)>,
    rules: Vec<String>,
    next_server: u32,
    next_rule: u32,
}

struct Shared {
    base: String,
    consent_fails: bool,
    store: Mutex<Store>,
}

/// A small in-memory stand-in for the gateway, serving the paths the helpers use.
struct Stub {
    base: String,
    shared: Arc<Shared>,
}

impl Stub {
    async fn start() -> Stub {
        Stub::spawn(false).await
    }

    async fn start_failing_consent() -> Stub {
        Stub::spawn(true).await
    }

    async fn spawn(consent_fails: bool) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let base = format!("http://{}", listener.local_addr().expect("stub address"));
        let shared = Arc::new(Shared {
            base: base.clone(),
            consent_fails,
            store: Mutex::new(Store::default()),
        });
        let app = Router::new().fallback(handle).with_state(shared.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve stub") });
        Stub { base, shared }
    }

    fn base(&self) -> &str {
        &self.base
    }

    fn requests(&self) -> Vec<Recorded> {
        self.shared
            .store
            .lock()
            .expect("stub store")
            .requests
            .clone()
    }

    /// The latest request with this method and path (query ignored).
    fn last(&self, method: &str, path: &str) -> Recorded {
        self.requests()
            .into_iter()
            .rev()
            .find(|req| req.method == method && req.path == path)
            .unwrap_or_else(|| panic!("no {method} {path} was recorded"))
    }
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.expect("stub request body");
    let recorded = Recorded {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or("").to_string(),
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: String::from_utf8_lossy(&bytes).into_owned(),
    };
    shared
        .store
        .lock()
        .expect("stub store")
        .requests
        .push(recorded.clone());
    route(&shared, &recorded).into_response()
}

/// A reply, rendered into a response by `into_response`.
struct Reply {
    status: u16,
    location: Option<String>,
    cookies: Vec<String>,
    content_type: &'static str,
    body: String,
}

impl Reply {
    fn html(status: u16, kind: &str, inner: &str) -> Reply {
        Reply {
            status,
            location: None,
            cookies: Vec::new(),
            content_type: "text/html; charset=utf-8",
            body: format!(
                "<!doctype html><html><head><title>stub</title></head><body><main data-page=\"{kind}\">{inner}</main></body></html>"
            ),
        }
    }

    fn redirect(location: &str) -> Reply {
        Reply {
            status: 303,
            location: Some(location.to_string()),
            cookies: Vec::new(),
            content_type: "text/plain; charset=utf-8",
            body: String::new(),
        }
    }

    fn json(status: u16, value: Value) -> Reply {
        Reply {
            status,
            location: None,
            cookies: Vec::new(),
            content_type: "application/json",
            body: value.to_string(),
        }
    }

    fn cookie(mut self, line: String) -> Reply {
        self.cookies.push(line);
        self
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut builder = Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, self.content_type);
        if let Some(location) = &self.location {
            builder = builder.header(LOCATION, location.as_str());
        }
        for cookie in &self.cookies {
            builder = builder.header(SET_COOKIE, cookie.as_str());
        }
        builder.body(Body::from(self.body)).expect("stub reply")
    }
}

fn form_page(req: &Recorded, kind: &str, inputs: &str) -> Reply {
    let csrf = cookie_value(req, CSRF).unwrap_or_else(random_hex);
    let inner = format!(
        "<form method=\"post\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">{inputs}</form>"
    );
    Reply::html(200, kind, &inner).cookie(format!("{CSRF}={csrf}; {COOKIE_ATTRS}"))
}

fn hidden_input(name: &str, value: &str) -> String {
    format!("<input type=\"hidden\" name=\"{name}\" value=\"{value}\">")
}

fn forbidden() -> Reply {
    Reply::html(403, "forbidden", "<p class=\"error\">Forbidden.</p>")
}

fn error_page(status: u16, message: &str) -> Reply {
    Reply::html(
        status,
        "error",
        &format!("<p class=\"error\">{message}</p>"),
    )
}

fn oauth_error(status: u16, code: &str) -> Reply {
    Reply::json(status, json!({"error": code}))
}

fn session_cookie(token: &str) -> String {
    format!("{SESSION}={token}; {COOKIE_ATTRS}")
}

fn new_session(store: &mut Store) -> String {
    let token = random_hex();
    store.sessions.insert(token.clone());
    token
}

fn session_active(store: &Store, req: &Recorded) -> bool {
    cookie_value(req, SESSION).is_some_and(|token| store.sessions.contains(&token))
}

/// Same-origin Origin and a csrf field equal to the csrf cookie.
fn form_allowed(base: &str, req: &Recorded) -> bool {
    let origins_ok = req
        .headers_named("origin")
        .iter()
        .all(|origin| *origin == base);
    match (cookie_value(req, CSRF), form_value(req, "csrf")) {
        (Some(cookie), Some(field)) => origins_ok && !cookie.is_empty() && cookie == field,
        _ => false,
    }
}

fn token_pair(store: &mut Store, client_id: &str, resource: Option<String>) -> Reply {
    let refresh = format!("dw_rt_{}", random_hex());
    store
        .refresh
        .insert(refresh.clone(), (client_id.to_string(), resource));
    Reply::json(
        200,
        json!({
            "access_token": format!("dw_at_{}", random_hex()),
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh,
            "scope": "mcp",
        }),
    )
}

fn token_endpoint(store: &mut Store, req: &Recorded) -> Reply {
    match form_value(req, "grant_type").as_deref() {
        Some("authorization_code") => {
            let Some(code) = form_value(req, "code") else {
                return oauth_error(400, "invalid_request");
            };
            let Some(grant) = store.codes.remove(&code) else {
                return oauth_error(400, "invalid_grant");
            };
            let verifier = form_value(req, "code_verifier").unwrap_or_default();
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes()));
            let matches = challenge == grant.challenge
                && form_value(req, "client_id").as_deref() == Some(grant.client_id.as_str())
                && form_value(req, "redirect_uri").as_deref() == Some(grant.redirect_uri.as_str());
            if !matches {
                return oauth_error(400, "invalid_grant");
            }
            let resource_ok = form_value(req, "resource")
                .is_none_or(|resource| grant.resource.as_deref() == Some(resource.as_str()));
            if !resource_ok {
                return oauth_error(400, "invalid_target");
            }
            token_pair(store, &grant.client_id, grant.resource)
        }
        Some("refresh_token") => {
            let Some(token) = form_value(req, "refresh_token") else {
                return oauth_error(400, "invalid_request");
            };
            let Some((client_id, resource)) = store.refresh.remove(&token) else {
                return oauth_error(400, "invalid_grant");
            };
            if form_value(req, "client_id").as_deref() != Some(client_id.as_str()) {
                return oauth_error(400, "invalid_grant");
            }
            let resource_ok = form_value(req, "resource")
                .is_none_or(|given| resource.as_deref() == Some(given.as_str()));
            if !resource_ok {
                return oauth_error(400, "invalid_target");
            }
            token_pair(store, &client_id, resource)
        }
        Some(_) => oauth_error(400, "unsupported_grant_type"),
        None => oauth_error(400, "invalid_request"),
    }
}

fn route(shared: &Shared, req: &Recorded) -> Reply {
    let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();
    let mut store = shared.store.lock().expect("stub store");
    let base = shared.base.as_str();
    let csrf_ok = form_allowed(base, req);
    match (req.method.as_str(), segments.as_slice()) {
        ("GET", ["login"]) => {
            let hidden = query_value(req, "req")
                .map(|id| hidden_input("req", &id))
                .unwrap_or_default();
            form_page(req, "login", &format!("{LOGIN_FIELDS}{hidden}"))
        }
        ("POST", ["login"]) => {
            if !csrf_ok {
                return forbidden();
            }
            let session = new_session(&mut store);
            let location = match form_value(req, "req").filter(|id| !id.is_empty()) {
                Some(id) => format!("/oauth/consent?req={id}"),
                None => "/account".to_string(),
            };
            Reply::redirect(&location).cookie(session_cookie(&session))
        }
        ("POST", ["logout"]) => {
            if !csrf_ok {
                return forbidden();
            }
            if let Some(token) = cookie_value(req, SESSION) {
                store.sessions.remove(&token);
            }
            Reply::redirect("/login").cookie(format!("{SESSION}=; Max-Age=0; {COOKIE_ATTRS}"))
        }
        ("GET", ["setup"]) => form_page(req, "setup", LOGIN_FIELDS),
        ("POST", ["setup"]) => {
            if !csrf_ok {
                return forbidden();
            }
            let session = new_session(&mut store);
            Reply::redirect("/admin").cookie(session_cookie(&session))
        }
        ("GET", ["account"]) => {
            if !session_active(&store, req) {
                return Reply::redirect("/login");
            }
            form_page(req, "account", "")
        }
        ("POST", ["account", "password"]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect("/account")
        }
        ("GET", ["invite", _]) => form_page(req, "invite", "<input name=\"password\">"),
        ("POST", ["invite", _]) => {
            if !csrf_ok {
                return forbidden();
            }
            let session = new_session(&mut store);
            Reply::redirect("/account").cookie(session_cookie(&session))
        }
        ("GET", ["reset", _]) => form_page(req, "reset", "<input name=\"password\">"),
        ("POST", ["reset", _]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect("/login")
        }
        ("GET", ["oauth", "authorize"]) => {
            let grant = Grant {
                client_id: query_value(req, "client_id").unwrap_or_default(),
                redirect_uri: query_value(req, "redirect_uri").unwrap_or_default(),
                challenge: query_value(req, "code_challenge").unwrap_or_default(),
                resource: query_value(req, "resource"),
                state: query_value(req, "state"),
            };
            let id = random_hex();
            store.auth_requests.insert(id.clone(), grant);
            if session_active(&store, req) {
                Reply::redirect(&format!("/oauth/consent?req={id}"))
            } else {
                Reply::redirect(&format!("/login?req={id}"))
            }
        }
        ("GET", ["oauth", "consent"]) => {
            if !session_active(&store, req) {
                return Reply::redirect("/login");
            }
            let id = query_value(req, "req").unwrap_or_default();
            if !store.auth_requests.contains_key(&id) {
                return error_page(400, "Unknown request.");
            }
            form_page(req, "consent", &hidden_input("req", &id))
        }
        ("POST", ["oauth", "consent"]) => {
            if !csrf_ok {
                return forbidden();
            }
            if shared.consent_fails {
                return error_page(400, "Consent failed.");
            }
            let id = form_value(req, "req").unwrap_or_default();
            let Some(grant) = store.auth_requests.remove(&id) else {
                return error_page(400, "Unknown request.");
            };
            let state = grant.state.clone().unwrap_or_default();
            if form_value(req, "decision").as_deref() == Some("approve") {
                let code = random_hex();
                let location = format!(
                    "{}?code={code}&state={state}&iss={base}",
                    grant.redirect_uri
                );
                store.codes.insert(code, grant);
                Reply::redirect(&location)
            } else {
                Reply::redirect(&format!(
                    "{}?error=access_denied&state={state}&iss={base}",
                    grant.redirect_uri
                ))
            }
        }
        ("POST", ["oauth", "register"]) => {
            let Ok(body) = serde_json::from_str::<Value>(&req.body) else {
                return oauth_error(400, "invalid_client_metadata");
            };
            Reply::json(
                201,
                json!({
                    "client_id": format!("dcr_{}", random_hex()),
                    "client_id_issued_at": 1893456000,
                    "redirect_uris": body["redirect_uris"],
                    "client_name": body["client_name"],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                }),
            )
        }
        ("POST", ["oauth", "token"]) => token_endpoint(&mut store, req),
        ("GET", ["admin", "servers"]) => {
            let rows: String = store
                .servers
                .iter()
                .map(|(id, slug)| format!("<li data-server-id=\"{id}\" data-slug=\"{slug}\"></li>"))
                .collect();
            form_page(req, "servers", &rows)
        }
        ("POST", ["admin", "servers"]) => {
            if !csrf_ok {
                return forbidden();
            }
            let slug = form_value(req, "slug").unwrap_or_default();
            let upstream = form_value(req, "upstream_url").unwrap_or_default();
            let reserved = ["admin", "mcp", "oauth"].contains(&slug.as_str());
            let taken = store.servers.iter().any(|(_, existing)| *existing == slug);
            let url_ok = upstream.starts_with("http://") || upstream.starts_with("https://");
            if reserved || taken || !url_ok {
                return error_page(400, "Invalid server.");
            }
            store.next_server += 1;
            let id = format!("srv-{}", store.next_server);
            store.servers.push((id.clone(), slug));
            Reply::redirect(&format!("/admin/servers/{id}"))
        }
        ("GET", ["admin", "servers", _]) => form_page(
            req,
            "server",
            "<p data-lockdown=\"unknown\">Not checked.</p>",
        ),
        ("POST", ["admin", "servers", id]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect(&format!("/admin/servers/{id}"))
        }
        ("POST", ["admin", "servers", id, action]) => {
            if !csrf_ok {
                return forbidden();
            }
            if *action == "delete" {
                Reply::redirect("/admin/servers")
            } else {
                Reply::redirect(&format!("/admin/servers/{id}"))
            }
        }
        ("GET", ["admin", "users"]) => form_page(
            req,
            "users",
            "<ul><li data-user-id=\"7\" data-email=\"bob@example.com\"></li></ul>",
        ),
        ("GET", ["admin", "users", _]) => form_page(req, "user", EFFECTIVE_TOOLS),
        ("POST", ["admin", "users", id, _]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect(&format!("/admin/users/{id}"))
        }
        ("GET", ["admin", "invitations"]) => form_page(req, "invitations", ""),
        ("POST", ["admin", "invitations"]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect("/admin/invitations")
        }
        ("GET", ["admin", "rules"]) => {
            let rows: String = store
                .rules
                .iter()
                .map(|id| format!("<li data-rule-id=\"{id}\"></li>"))
                .collect();
            form_page(req, "rules", &rows)
        }
        ("POST", ["admin", "rules"]) => {
            if !csrf_ok {
                return forbidden();
            }
            store.next_rule += 1;
            let id = format!("r-{}", store.next_rule);
            store.rules.push(id);
            Reply::redirect("/admin/rules")
        }
        ("POST", ["admin", "rules", id, "delete"]) => {
            if !csrf_ok {
                return forbidden();
            }
            store.rules.retain(|rule| rule.as_str() != *id);
            Reply::redirect("/admin/rules")
        }
        ("GET", ["admin", "redirects"]) => form_page(req, "redirects", ""),
        ("POST", ["admin", "redirects"]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect("/admin/redirects")
        }
        ("GET", ["admin", "mail"]) => form_page(req, "mail", ""),
        ("POST", ["admin", "mail"]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::redirect("/admin/mail")
        }
        ("POST", ["admin", "mail", "test"]) => {
            if !csrf_ok {
                return forbidden();
            }
            Reply::html(200, "mail", "<p class=\"notice\">Test email sent.</p>")
        }
        ("GET", ["admin", "activity"]) => Reply::html(200, "activity", ACTIVITY_ROWS),
        ("GET", ["test", "page"]) => Reply::html(200, "login", TEST_PAGE),
        ("GET", ["test", "plain"]) => Reply::html(200, "plain", "<p>No form here.</p>"),
        ("GET", ["test", "json"]) | ("POST", ["test", "json"]) => {
            Reply::json(200, json!({"ok": true}))
        }
        ("GET", ["test", "code"]) => Reply::redirect("/x?code=a%20b&state=s"),
        ("GET", ["test", "redirect"]) => Reply::redirect("/test/landing"),
        ("GET", ["test", "landing"]) => Reply::html(200, "landing", "landed"),
        ("GET", ["test", "cookies"]) => Reply::html(200, "cookies", "")
            .cookie("a=1; Path=/".to_string())
            .cookie("b=2; Path=/; HttpOnly".to_string()),
        ("GET", ["test", "expire-b"]) => {
            Reply::html(200, "cookies", "").cookie("b=gone; Max-Age=0; Path=/".to_string())
        }
        ("POST", ["test", "form"]) => Reply::html(200, "form", "<p>ok</p>"),
        _ => Reply::html(404, "not-found", ""),
    }
}

fn assert_fields(recorded: &Recorded, expected: &[(&str, &str)]) {
    let owned: Vec<(String, String)> = expected
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    assert_eq!(recorded.fields(), owned);
}

fn assert_query(recorded: &Recorded, expected: &[(&str, &str)]) {
    let owned: Vec<(String, String)> = expected
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    assert_eq!(form_pairs(&recorded.query), owned);
}

async fn signed_in(stub: &Stub) -> TestClient {
    let c = TestClient::new(stub.base());
    let page = c.login("owner@example.com", PASSWORD).await;
    assert_eq!(page.status, 303);
    c
}

async fn registered_app(c: &TestClient) -> OAuthApp {
    let page = c.register("Demo app", &[REDIRECT]).await;
    assert_eq!(page.status, 201);
    let client_id = page
        .json()
        .and_then(|body| body["client_id"].as_str().map(str::to_string))
        .expect("client_id in registration answer");
    OAuthApp {
        client_id,
        redirect_uri: REDIRECT.to_string(),
    }
}

fn demo_spec() -> ServerSpec<'static> {
    ServerSpec {
        name: "Demo",
        slug: "demo",
        upstream_url: "http://127.0.0.1:9/mcp",
        secret: Some(("x-upstream-key", "s3cret")),
        pass_resources: true,
        pass_prompts: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn page_reads_html() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let page = c.get("/test/page").await;
    assert_eq!(page.status, 200);
    assert_eq!(page.kind().as_deref(), Some("login"));
    assert_eq!(page.csrf().as_deref(), Some("tok-123"));
    assert_eq!(page.field("email").as_deref(), Some("owner@example.com"));
    assert_eq!(page.field("missing"), None);
    assert_eq!(page.error().as_deref(), Some("Wrong email or password."));
    assert_eq!(page.notice().as_deref(), Some("Saved"));
    assert_eq!(page.text(".item").as_deref(), Some("First link"));
    assert_eq!(page.texts(".item"), ["First link", "Second", "Third"]);
    assert_eq!(page.attr(".item", "href").as_deref(), Some("/a"));
    assert_eq!(page.attrs(".item", "href"), ["/a", "/b"]);
    assert_eq!(page.count(".item"), 3);
    assert_eq!(page.count(".absent"), 0);
    assert_eq!(page.json(), None);
    let json = c.get("/test/json").await;
    assert_eq!(json.json(), Some(json!({"ok": true})));
    let redirect = c.get("/test/code").await;
    assert_eq!(redirect.status, 303);
    assert_eq!(
        redirect.location().as_deref(),
        Some("/x?code=a%20b&state=s")
    );
    assert_eq!(redirect.query("code").as_deref(), Some("a b"));
    assert_eq!(redirect.query("state").as_deref(), Some("s"));
    assert_eq!(redirect.query("missing"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn cookie_jar_round_trip() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    c.get("/test/landing").await;
    assert_eq!(stub.last("GET", "/test/landing").header("cookie"), None);
    c.get("/test/cookies").await;
    assert_eq!(c.cookie("a").as_deref(), Some("1"));
    assert_eq!(c.cookie("b").as_deref(), Some("2"));
    c.get("/test/landing").await;
    assert_eq!(
        stub.last("GET", "/test/landing").header("cookie"),
        Some("a=1; b=2")
    );
    assert_eq!(c.cookie_attributes("a").as_deref(), Some("path=/"));
    assert!(
        c.cookie_attributes("b")
            .expect("attributes")
            .contains("httponly")
    );
    c.get("/test/expire-b").await;
    assert_eq!(c.cookie("b"), None);
    c.get("/test/landing").await;
    assert_eq!(
        stub.last("GET", "/test/landing").header("cookie"),
        Some("a=1")
    );
    c.set_cookie("c", "3");
    c.get("/test/landing").await;
    assert_eq!(
        stub.last("GET", "/test/landing").header("cookie"),
        Some("a=1; c=3")
    );
    c.remove_cookie("c");
    assert_eq!(c.cookie("c"), None);
    c.clear_cookies();
    assert_eq!(c.cookie("a"), None);
    c.get("/test/landing").await;
    assert_eq!(stub.last("GET", "/test/landing").header("cookie"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_not_followed() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let page = c.get("/test/redirect").await;
    assert_eq!(page.status, 303);
    assert_eq!(page.location().as_deref(), Some("/test/landing"));
    let landings = stub
        .requests()
        .iter()
        .filter(|req| req.path == "/test/landing")
        .count();
    assert_eq!(landings, 0);
    let landed = c.follow(&page).await;
    assert_eq!(landed.status, 200);
    assert_eq!(landed.kind().as_deref(), Some("landing"));
}

#[tokio::test(flavor = "multi_thread")]
async fn absolute_target_on_base_works() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    assert_eq!(c.base(), stub.base());
    let page = c.get(&format!("{}/test/landing", stub.base())).await;
    assert_eq!(page.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "other.example.com")]
async fn targets_must_stay_on_base() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    c.get("https://other.example.com/").await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "must start with")]
async fn lookalike_port_is_refused() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    c.get(&format!("{}5/test/landing", stub.base())).await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "request to /test/landing failed")]
async fn transport_error_names_target() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);
    let c = TestClient::new(&base);
    c.get("/test/landing").await;
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "follow: status 200 has no Location")]
async fn follow_without_location_panics() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let page = c.get("/test/landing").await;
    c.follow(&page).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn post_sends_origin_and_exact_fields() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let page = c
        .post("/test/form", &[("b", "2"), ("a", "1"), ("note", "x y&z")])
        .await;
    assert_eq!(page.status, 200);
    let sent = stub.last("POST", "/test/form");
    assert_eq!(sent.header("origin"), Some(stub.base()));
    assert_eq!(
        sent.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(sent.body, "b=2&a=1&note=x+y%26z");
    assert_fields(&sent, &[("b", "2"), ("a", "1"), ("note", "x y&z")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_with_overrides_and_omits() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    c.post_with(
        "/test/form",
        &[("x", "1")],
        &[("ORIGIN", "https://evil.example.com")],
    )
    .await;
    assert_eq!(
        stub.last("POST", "/test/form").headers_named("origin"),
        ["https://evil.example.com"]
    );
    c.post_with("/test/form", &[("x", "1")], &[("Origin", "")])
        .await;
    assert!(
        stub.last("POST", "/test/form")
            .headers_named("origin")
            .is_empty()
    );
    c.post_with(
        "/test/form",
        &[("x", "1")],
        &[("X-Dup", "one"), ("X-Dup", "two")],
    )
    .await;
    assert_eq!(
        stub.last("POST", "/test/form").headers_named("x-dup"),
        ["one", "two"]
    );
    c.post_json("/test/json", &json!({"a": 1})).await;
    let sent = stub.last("POST", "/test/json");
    assert!(sent.headers_named("origin").is_empty());
    assert_eq!(sent.header("content-type"), Some("application/json"));
    assert_eq!(sent.body, r#"{"a":1}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_reads_csrf() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let page = c.login("owner@example.com", PASSWORD).await;
    assert_eq!(page.status, 303);
    assert_eq!(page.location().as_deref(), Some("/account"));
    assert!(c.cookie(SESSION).is_some());
    let sent = stub.last("POST", "/login");
    assert_eq!(form_pairs(&sent.body)[0].0, "csrf");
    assert_fields(
        &sent,
        &[("email", "owner@example.com"), ("password", PASSWORD)],
    );
    let rejected = c
        .post(
            "/login",
            &[("email", "owner@example.com"), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(rejected.status, 403);
    assert_eq!(rejected.kind().as_deref(), Some("forbidden"));
    let wrong = c
        .post(
            "/login",
            &[
                ("csrf", "wrong"),
                ("email", "owner@example.com"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(wrong.status, 403);
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "/test/plain has no csrf field (status 200, kind Some(\"plain\"))")]
async fn submit_without_csrf_panics() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    c.submit("/test/plain", "/test/form", &[]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn account_helpers() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let setup = c
        .setup_owner("setup-code-1", "owner@example.com", PASSWORD)
        .await;
    assert_eq!(setup.status, 303);
    assert_eq!(setup.location().as_deref(), Some("/admin"));
    assert_fields(
        &stub.last("POST", "/setup"),
        &[
            ("setup_code", "setup-code-1"),
            ("email", "owner@example.com"),
            ("password", PASSWORD),
        ],
    );
    let out = c.logout().await;
    assert_eq!(out.status, 303);
    assert_eq!(out.location().as_deref(), Some("/login"));
    assert_eq!(c.cookie(SESSION), None);
    assert_fields(&stub.last("POST", "/logout"), &[]);
    let consent = c.login_for("abc", "owner@example.com", PASSWORD).await;
    assert_eq!(consent.status, 303);
    assert_eq!(
        consent.location().as_deref(),
        Some("/oauth/consent?req=abc")
    );
    assert_fields(
        &stub.last("POST", "/login"),
        &[
            ("email", "owner@example.com"),
            ("password", PASSWORD),
            ("req", "abc"),
        ],
    );
    let invited = c.accept_invite("/invite/tok-1", "new-password-000").await;
    assert_eq!(invited.location().as_deref(), Some("/account"));
    assert_fields(
        &stub.last("POST", "/invite/tok-1"),
        &[("password", "new-password-000")],
    );
    let reset = c.reset_password("/reset/tok-2", "reset-password-000").await;
    assert_eq!(reset.location().as_deref(), Some("/login"));
    assert_fields(
        &stub.last("POST", "/reset/tok-2"),
        &[("password", "reset-password-000")],
    );
    let changed = c
        .change_password("reset-password-000", "changed-password-000")
        .await;
    assert_eq!(changed.status, 303);
    assert_eq!(changed.location().as_deref(), Some("/account"));
    assert_fields(
        &stub.last("POST", "/account/password"),
        &[
            ("current_password", "reset-password-000"),
            ("new_password", "changed-password-000"),
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pkce_is_s256() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let first = pkce();
    let second = pkce();
    assert_eq!(first.verifier.len(), 43);
    assert!(
        first
            .verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    );
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(first.verifier.as_bytes()));
    assert_eq!(first.challenge, expected);
    assert_ne!(first.verifier, second.verifier);
    let rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(rfc_verifier.as_bytes())),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authorize_sends_standard_parameters() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let app = OAuthApp {
        client_id: "dcr_test".to_string(),
        redirect_uri: REDIRECT.to_string(),
    };
    let resource = format!("{}/demo", stub.base());
    let pk = pkce();
    c.authorize(&app, &resource, &pk, "st-1").await;
    assert_query(
        &stub.last("GET", "/oauth/authorize"),
        &[
            ("response_type", "code"),
            ("client_id", "dcr_test"),
            ("redirect_uri", REDIRECT),
            ("code_challenge", pk.challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", resource.as_str()),
            ("state", "st-1"),
            ("scope", "mcp"),
        ],
    );
    c.authorize_raw(&[
        ("state", "a"),
        ("state", "b"),
        ("client_id", "x"),
        ("response_type", "code"),
    ])
    .await;
    assert_query(
        &stub.last("GET", "/oauth/authorize"),
        &[
            ("state", "a"),
            ("state", "b"),
            ("client_id", "x"),
            ("response_type", "code"),
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_runs_the_flow() {
    let stub = Stub::start().await;
    let c = signed_in(&stub).await;
    let app = registered_app(&c).await;
    let resource = format!("{}/demo", stub.base());
    let issued = c.connect(&app, &resource).await;
    assert!(issued.access_token.starts_with("dw_at_"));
    assert!(issued.refresh_token.starts_with("dw_rt_"));
    assert_eq!(issued.expires_in, 3600);
    assert_eq!(issued.scope, "mcp");
    let authorize = stub.last("GET", "/oauth/authorize");
    let challenge = query_value(&authorize, "code_challenge").expect("code_challenge");
    let state = query_value(&authorize, "state").expect("state");
    assert_query(
        &authorize,
        &[
            ("response_type", "code"),
            ("client_id", app.client_id.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", resource.as_str()),
            ("state", state.as_str()),
            ("scope", "mcp"),
        ],
    );
    let exchange = stub.last("POST", "/oauth/token");
    let code = form_value(&exchange, "code").expect("code in token request");
    let verifier = form_value(&exchange, "code_verifier").expect("verifier in token request");
    assert_fields(
        &exchange,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("client_id", app.client_id.as_str()),
            ("code_verifier", verifier.as_str()),
            ("resource", resource.as_str()),
        ],
    );
    let refreshed = c
        .token_refresh(&app, &issued.refresh_token, Some(&resource))
        .await;
    assert_eq!(refreshed.status, 200);
    let renewed = tokens(&refreshed).expect("refreshed tokens");
    assert_ne!(renewed.refresh_token, issued.refresh_token);
    assert_fields(
        &stub.last("POST", "/oauth/token"),
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", issued.refresh_token.as_str()),
            ("client_id", app.client_id.as_str()),
            ("resource", resource.as_str()),
        ],
    );
    let bad = c.token_refresh(&app, "dw_rt_unknown", None).await;
    assert_eq!(bad.status, 400);
    assert_eq!(tokens(&bad), None);
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "consent step answered 400")]
async fn connect_reports_a_broken_step() {
    let stub = Stub::start_failing_consent().await;
    let c = signed_in(&stub).await;
    let app = registered_app(&c).await;
    let resource = format!("{}/demo", stub.base());
    c.connect(&app, &resource).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn token_raw_sends_no_cookies_or_origin() {
    let stub = Stub::start().await;
    let c = signed_in(&stub).await;
    assert!(c.cookie(SESSION).is_some());
    let page = c
        .token_raw(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "dw_rt_x"),
            ("client_id", "dcr_x"),
        ])
        .await;
    assert_eq!(page.status, 400);
    let sent = stub.last("POST", "/oauth/token");
    assert_eq!(sent.header("cookie"), None);
    assert_eq!(sent.header("origin"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_posts_json() {
    let stub = Stub::start().await;
    let c = TestClient::new(stub.base());
    let page = c.register("Demo app", &[REDIRECT]).await;
    assert_eq!(page.status, 201);
    let sent = stub.last("POST", "/oauth/register");
    let body: Value = serde_json::from_str(&sent.body).expect("json body");
    assert_eq!(
        body,
        json!({"client_name": "Demo app", "redirect_uris": [REDIRECT]})
    );
    assert_eq!(sent.header("content-type"), Some("application/json"));
    let client_id = page.json().expect("json answer")["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    assert!(client_id.starts_with("dcr_"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_server_helpers() {
    let stub = Stub::start().await;
    let c = signed_in(&stub).await;
    let id = admin::add_server(&c, &demo_spec()).await;
    assert_eq!(id, "srv-1");
    assert_fields(
        &stub.last("POST", "/admin/servers"),
        &[
            ("name", "Demo"),
            ("slug", "demo"),
            ("upstream_url", "http://127.0.0.1:9/mcp"),
            ("secret_header_name", "x-upstream-key"),
            ("secret_header_value", "s3cret"),
            ("pass_resources", "on"),
        ],
    );
    assert_eq!(admin::server_id(&c, "demo").await.as_deref(), Some("srv-1"));
    assert_eq!(admin::server_id(&c, "other").await, None);
    let update = ServerSpec {
        name: "Demo renamed",
        slug: "demo",
        upstream_url: "http://127.0.0.1:9/mcp",
        secret: None,
        pass_resources: false,
        pass_prompts: true,
    };
    let page = admin::update_server(&c, &id, &update).await;
    assert_eq!(page.status, 303);
    assert_fields(
        &stub.last("POST", "/admin/servers/srv-1"),
        &[
            ("name", "Demo renamed"),
            ("slug", "demo"),
            ("upstream_url", "http://127.0.0.1:9/mcp"),
            ("pass_prompts", "on"),
        ],
    );
    assert_eq!(admin::refresh_tools(&c, &id).await.status, 303);
    assert_fields(
        &stub.last("POST", "/admin/servers/srv-1/refresh-tools"),
        &[],
    );
    assert_eq!(admin::check_lockdown(&c, &id).await.status, 303);
    assert_fields(
        &stub.last("POST", "/admin/servers/srv-1/check-lockdown"),
        &[],
    );
    let deleted = admin::delete_server(&c, &id).await;
    assert_eq!(deleted.location().as_deref(), Some("/admin/servers"));
    assert_fields(&stub.last("POST", "/admin/servers/srv-1/delete"), &[]);
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "add_server answered 400 with error Some(\"Invalid server.\")")]
async fn add_server_panics_on_error() {
    let stub = Stub::start().await;
    let c = signed_in(&stub).await;
    let reserved = ServerSpec {
        slug: "mcp",
        ..demo_spec()
    };
    admin::add_server(&c, &reserved).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_user_and_rule_helpers() {
    let stub = Stub::start().await;
    let c = signed_in(&stub).await;
    let invited = admin::invite(&c, "carol@example.com", "user").await;
    assert_eq!(invited.location().as_deref(), Some("/admin/invitations"));
    assert_fields(
        &stub.last("POST", "/admin/invitations"),
        &[("email", "carol@example.com"), ("role", "user")],
    );
    assert_eq!(
        admin::user_id(&c, "bob@example.com").await.as_deref(),
        Some("7")
    );
    assert_eq!(admin::user_id(&c, "nobody@example.com").await, None);
    admin::assign(&c, "7", &["srv-1", "srv-2"]).await;
    assert_fields(
        &stub.last("POST", "/admin/users/7/servers"),
        &[("server_id", "srv-1"), ("server_id", "srv-2")],
    );
    admin::set_role(&c, "7", "admin").await;
    assert_fields(
        &stub.last("POST", "/admin/users/7/role"),
        &[("role", "admin")],
    );
    admin::user_action(&c, "7", "disable").await;
    assert_fields(&stub.last("POST", "/admin/users/7/disable"), &[]);
    admin::add_rule(
        &c,
        "everyone",
        "deny",
        "tool",
        Some("srv-1"),
        Some("delete_db"),
    )
    .await;
    assert_fields(
        &stub.last("POST", "/admin/rules"),
        &[
            ("subject", "everyone"),
            ("effect", "deny"),
            ("scope", "tool"),
            ("server_id", "srv-1"),
            ("tool", "delete_db"),
        ],
    );
    admin::add_rule(&c, "7", "allow", "server", None, None).await;
    assert_fields(
        &stub.last("POST", "/admin/rules"),
        &[("subject", "7"), ("effect", "allow"), ("scope", "server")],
    );
    assert_eq!(admin::rule_ids(&c).await, ["r-1", "r-2"]);
    admin::delete_rule(&c, "r-1").await;
    assert_fields(&stub.last("POST", "/admin/rules/r-1/delete"), &[]);
    assert_eq!(admin::rule_ids(&c).await, ["r-2"]);
    assert_eq!(
        admin::effective_tools(&c, "7").await,
        vec![
            ("echo".to_string(), "allow".to_string()),
            ("delete_db".to_string(), "deny".to_string()),
        ]
    );
    admin::add_redirect(&c, "https", "callback.example.com", "/cb/").await;
    assert_fields(
        &stub.last("POST", "/admin/redirects"),
        &[
            ("scheme", "https"),
            ("host", "callback.example.com"),
            ("path_prefix", "/cb/"),
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_mail_and_activity_helpers() {
    let stub = Stub::start().await;
    let c = signed_in(&stub).await;
    let from = "doorward@example.com";
    admin::mail_smtp(&c, from, "smtp.example.com", 587, "doorward", "pw-1", true).await;
    assert_fields(
        &stub.last("POST", "/admin/mail"),
        &[
            ("provider", "smtp"),
            ("from", from),
            ("smtp_host", "smtp.example.com"),
            ("smtp_port", "587"),
            ("smtp_username", "doorward"),
            ("smtp_password", "pw-1"),
            ("smtp_tls", "on"),
        ],
    );
    admin::mail_smtp(&c, from, "smtp.example.com", 25, "doorward", "pw-1", false).await;
    assert_fields(
        &stub.last("POST", "/admin/mail"),
        &[
            ("provider", "smtp"),
            ("from", from),
            ("smtp_host", "smtp.example.com"),
            ("smtp_port", "25"),
            ("smtp_username", "doorward"),
            ("smtp_password", "pw-1"),
        ],
    );
    admin::mail_resend(&c, from, "re-key-1", "https://resend.example.com").await;
    assert_fields(
        &stub.last("POST", "/admin/mail"),
        &[
            ("provider", "resend"),
            ("from", from),
            ("resend_api_key", "re-key-1"),
            ("resend_base_url", "https://resend.example.com"),
        ],
    );
    admin::mail_mailgun(
        &c,
        from,
        "mg-key-1",
        "mg.example.com",
        "https://mailgun.example.com",
    )
    .await;
    assert_fields(
        &stub.last("POST", "/admin/mail"),
        &[
            ("provider", "mailgun"),
            ("from", from),
            ("mailgun_api_key", "mg-key-1"),
            ("mailgun_domain", "mg.example.com"),
            ("mailgun_base_url", "https://mailgun.example.com"),
        ],
    );
    let test = admin::mail_test(&c, "bob@example.com").await;
    assert_eq!(test.status, 200);
    assert_eq!(test.notice().as_deref(), Some("Test email sent."));
    assert_fields(
        &stub.last("POST", "/admin/mail/test"),
        &[("to", "bob@example.com")],
    );
    let rows = admin::activity(&c, Some("7"), None).await;
    assert_eq!(stub.last("GET", "/admin/activity").query, "user=7");
    assert_eq!(
        rows,
        vec![
            ActivityRow {
                kind: "tool_call".to_string(),
                user: "7".to_string(),
                server: "demo".to_string(),
                tool: "echo".to_string(),
                decision: "allow".to_string(),
                outcome: "ok".to_string(),
            },
            ActivityRow {
                kind: "login".to_string(),
                user: "7".to_string(),
                server: String::new(),
                tool: String::new(),
                decision: "allow".to_string(),
                outcome: "ok".to_string(),
            },
        ]
    );
}
