use std::collections::BTreeMap;
use std::sync::Mutex;

use base64::Engine as _;
use reqwest::header::{HeaderMap, SET_COOKIE};
use scraper::{ElementRef, Html, Selector};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::form_urlencoded::Serializer;

const FORM_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_TYPE: &str = "application/json";
const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A response with readers for the parts the tests check.
#[derive(Clone, Debug)]
pub struct Page {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
}

impl Page {
    pub fn kind(&self) -> Option<String> {
        self.attr("main", "data-page")
    }

    pub fn location(&self) -> Option<String> {
        self.header("location")
    }

    pub fn query(&self, name: &str) -> Option<String> {
        self.location_url()?
            .query_pairs()
            .find(|pair| pair.0 == name)
            .map(|pair| pair.1.into_owned())
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers_all(name).into_iter().next()
    }

    pub fn headers_all(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect()
    }

    pub fn csrf(&self) -> Option<String> {
        self.attr(r#"input[name="csrf"]"#, "value")
    }

    pub fn field(&self, name: &str) -> Option<String> {
        self.attr(&format!(r#"input[name="{name}"]"#), "value")
    }

    pub fn error(&self) -> Option<String> {
        self.text(r#".error, [data-notice="error"]"#)
    }

    pub fn notice(&self) -> Option<String> {
        self.text(".notice")
    }

    pub fn text(&self, css: &str) -> Option<String> {
        let doc = Html::parse_document(&self.body);
        select(&doc, css)
            .first()
            .map(|element| collapse(&element.text().collect::<String>()))
    }

    pub fn texts(&self, css: &str) -> Vec<String> {
        let doc = Html::parse_document(&self.body);
        select(&doc, css)
            .iter()
            .map(|element| collapse(&element.text().collect::<String>()))
            .collect()
    }

    pub fn attr(&self, css: &str, attr: &str) -> Option<String> {
        let doc = Html::parse_document(&self.body);
        select(&doc, css)
            .first()
            .and_then(|element| element.attr(attr))
            .map(str::to_string)
    }

    pub fn attrs(&self, css: &str, attr: &str) -> Vec<String> {
        let doc = Html::parse_document(&self.body);
        select(&doc, css)
            .iter()
            .filter_map(|element| element.attr(attr))
            .map(str::to_string)
            .collect()
    }

    pub fn count(&self, css: &str) -> usize {
        let doc = Html::parse_document(&self.body);
        select(&doc, css).len()
    }

    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }

    fn location_url(&self) -> Option<url::Url> {
        let origin = url::Url::parse("http://localhost/").expect("static url");
        origin.join(&self.location()?).ok()
    }
}

fn select<'a>(doc: &'a Html, css: &str) -> Vec<ElementRef<'a>> {
    let selector =
        Selector::parse(css).unwrap_or_else(|err| panic!("bad selector {css:?}: {err:?}"));
    doc.select(&selector).collect()
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn form_body(fields: &[(&str, &str)]) -> String {
    let mut serializer = Serializer::new(String::new());
    serializer.extend_pairs(fields);
    serializer.finish()
}

/// Cookie jar, redirect-free HTTP client, scripted like a browser.
pub struct TestClient {
    base: String,
    http: reqwest::Client,
    jar: Mutex<BTreeMap<String, String>>,
    attributes: Mutex<BTreeMap<String, String>>,
    forwarded_for: Option<String>,
}

impl TestClient {
    pub fn new(base: &str) -> TestClient {
        TestClient::build(base, None)
    }

    /// A browser whose every request carries `X-Forwarded-For: address`.
    // harness_client includes this file on its own and never calls this constructor.
    #[allow(dead_code)]
    pub fn at(base: &str, address: &str) -> TestClient {
        TestClient::build(base, Some(address.to_string()))
    }

    fn build(base: &str, forwarded_for: Option<String>) -> TestClient {
        TestClient {
            base: base.to_string(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http client"),
            jar: Mutex::new(BTreeMap::new()),
            attributes: Mutex::new(BTreeMap::new()),
            forwarded_for,
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub async fn get(&self, target: &str) -> Page {
        self.get_with(target, &[]).await
    }

    pub async fn get_with(&self, target: &str, headers: &[(&str, &str)]) -> Page {
        let headers = self.request_headers(true, Vec::new(), headers);
        self.send(reqwest::Method::GET, target, headers, None).await
    }

    pub async fn post(&self, target: &str, fields: &[(&str, &str)]) -> Page {
        self.post_with(target, fields, &[]).await
    }

    pub async fn post_with(
        &self,
        target: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Page {
        let defaults = vec![
            ("content-type", FORM_TYPE.to_string()),
            ("origin", self.base.clone()),
        ];
        let headers = self.request_headers(true, defaults, headers);
        self.send(
            reqwest::Method::POST,
            target,
            headers,
            Some(form_body(fields)),
        )
        .await
    }

    pub async fn post_json(&self, target: &str, body: &serde_json::Value) -> Page {
        let defaults = vec![("content-type", JSON_TYPE.to_string())];
        let headers = self.request_headers(true, defaults, &[]);
        self.send(
            reqwest::Method::POST,
            target,
            headers,
            Some(body.to_string()),
        )
        .await
    }

    /// GETs `form_page`, then posts `fields` to `action` with the page's csrf token first.
    pub async fn submit(&self, form_page: &str, action: &str, fields: &[(&str, &str)]) -> Page {
        let form = self.get(form_page).await;
        let token = form.csrf().unwrap_or_else(|| {
            panic!(
                "{form_page} has no csrf field (status {}, kind {:?})",
                form.status,
                form.kind()
            )
        });
        let mut all = Vec::with_capacity(fields.len() + 1);
        all.push(("csrf", token.as_str()));
        all.extend_from_slice(fields);
        self.post(action, &all).await
    }

    pub async fn follow(&self, page: &Page) -> Page {
        let location = page
            .location()
            .unwrap_or_else(|| panic!("follow: status {} has no Location", page.status));
        self.get(&location).await
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.jar.lock().expect("cookie jar").get(name).cloned()
    }

    pub fn cookie_attributes(&self, name: &str) -> Option<String> {
        self.attributes
            .lock()
            .expect("cookie attributes")
            .get(name)
            .cloned()
    }

    pub fn set_cookie(&self, name: &str, value: &str) {
        self.jar
            .lock()
            .expect("cookie jar")
            .insert(name.to_string(), value.to_string());
    }

    pub fn remove_cookie(&self, name: &str) {
        self.jar.lock().expect("cookie jar").remove(name);
    }

    pub fn clear_cookies(&self) {
        self.jar.lock().expect("cookie jar").clear();
    }

    /// Builds the header list: defaults the caller does not name, then the caller's non-empty headers.
    fn request_headers(
        &self,
        cookies: bool,
        mut defaults: Vec<(&str, String)>,
        caller: &[(&str, &str)],
    ) -> Vec<(String, String)> {
        if cookies && let Some(header) = self.cookie_header() {
            defaults.push(("cookie", header));
        }
        if let Some(address) = &self.forwarded_for {
            defaults.push(("x-forwarded-for", address.clone()));
        }
        let mut headers: Vec<(String, String)> = defaults
            .into_iter()
            .filter(|(name, _)| {
                !caller
                    .iter()
                    .any(|(given, _)| given.eq_ignore_ascii_case(name))
            })
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        headers.extend(
            caller
                .iter()
                .filter(|(_, value)| !value.is_empty())
                .map(|(name, value)| (name.to_string(), value.to_string())),
        );
        headers
    }

    fn cookie_header(&self) -> Option<String> {
        let jar = self.jar.lock().expect("cookie jar");
        if jar.is_empty() {
            return None;
        }
        Some(
            jar.iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    fn store_cookie(&self, line: &str) {
        let (pair, attributes) = line.split_once(';').unwrap_or((line, ""));
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            return;
        }
        self.attributes
            .lock()
            .expect("cookie attributes")
            .insert(name.to_string(), attributes.trim().to_ascii_lowercase());
        let mut jar = self.jar.lock().expect("cookie jar");
        if value.is_empty() || expires_now(attributes) {
            jar.remove(name);
        } else {
            jar.insert(name.to_string(), value.to_string());
        }
    }

    fn url_for(&self, target: &str) -> String {
        if target.starts_with('/') {
            return format!("{}{}", self.base, target);
        }
        match target.strip_prefix(self.base.as_str()) {
            Some(rest) if rest.is_empty() || rest.starts_with(['/', '?', '#']) => {
                target.to_string()
            }
            _ => panic!("target {target} must start with / or with {}", self.base),
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        target: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
    ) -> Page {
        let url = self.url_for(target);
        let mut request = self.http.request(method, url);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|err| panic!("request to {target} failed: {err}"));
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        for value in headers.get_all(SET_COOKIE) {
            self.store_cookie(&String::from_utf8_lossy(value.as_bytes()));
        }
        let body = response
            .text()
            .await
            .unwrap_or_else(|err| panic!("reading the body of {target} failed: {err}"));
        Page {
            status,
            headers,
            body,
        }
    }
}

/// True when the attributes hold Max-Age of zero or less, which removes the cookie.
fn expires_now(attributes: &str) -> bool {
    attributes.split(';').any(|attribute| {
        attribute.split_once('=').is_some_and(|(key, value)| {
            key.trim().eq_ignore_ascii_case("max-age")
                && value.trim().parse::<i64>().is_ok_and(|secs| secs <= 0)
        })
    })
}

/// Random characters drawn from `alphabet`.
fn random_from(alphabet: &[u8], len: usize) -> String {
    (0..len)
        .map(|_| alphabet[rand::random_range::<usize, _>(0..alphabet.len())] as char)
        .collect()
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

pub fn pkce() -> Pkce {
    let verifier = random_from(UNRESERVED, 43);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

#[derive(Clone, Debug)]
pub struct OAuthApp {
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub scope: String,
}

pub fn tokens(page: &Page) -> Option<Tokens> {
    if page.status != 200 {
        return None;
    }
    let json = page.json()?;
    Some(Tokens {
        access_token: json["access_token"].as_str()?.to_string(),
        refresh_token: json["refresh_token"].as_str()?.to_string(),
        expires_in: json["expires_in"].as_u64()?,
        scope: json["scope"].as_str()?.to_string(),
    })
}

fn fail_step(step: &str, page: &Page) -> ! {
    panic!(
        "connect: {step} step answered {} (kind {:?}, location {:?})",
        page.status,
        page.kind(),
        page.location()
    )
}

impl TestClient {
    pub async fn register(&self, client_name: &str, redirect_uris: &[&str]) -> Page {
        self.post_json(
            "/oauth/register",
            &json!({"client_name": client_name, "redirect_uris": redirect_uris}),
        )
        .await
    }

    pub async fn authorize(
        &self,
        app: &OAuthApp,
        resource: &str,
        pkce: &Pkce,
        state: &str,
    ) -> Page {
        self.authorize_raw(&[
            ("response_type", "code"),
            ("client_id", app.client_id.as_str()),
            ("redirect_uri", app.redirect_uri.as_str()),
            ("code_challenge", pkce.challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", resource),
            ("state", state),
            ("scope", "mcp"),
        ])
        .await
    }

    pub async fn authorize_raw(&self, params: &[(&str, &str)]) -> Page {
        self.get(&format!("/oauth/authorize?{}", form_body(params)))
            .await
    }

    pub async fn consent(&self, req: &str, decision: &str) -> Page {
        self.submit(
            &format!("/oauth/consent?req={req}"),
            "/oauth/consent",
            &[("req", req), ("decision", decision)],
        )
        .await
    }

    pub async fn token_code(
        &self,
        app: &OAuthApp,
        code: &str,
        verifier: &str,
        resource: Option<&str>,
    ) -> Page {
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", app.redirect_uri.as_str()),
            ("client_id", app.client_id.as_str()),
            ("code_verifier", verifier),
        ];
        if let Some(resource) = resource {
            fields.push(("resource", resource));
        }
        self.token_raw(&fields).await
    }

    pub async fn token_refresh(
        &self,
        app: &OAuthApp,
        refresh_token: &str,
        resource: Option<&str>,
    ) -> Page {
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", app.client_id.as_str()),
        ];
        if let Some(resource) = resource {
            fields.push(("resource", resource));
        }
        self.token_raw(&fields).await
    }

    /// POSTs a token request with no Origin header and no cookies.
    pub async fn token_raw(&self, fields: &[(&str, &str)]) -> Page {
        let headers =
            self.request_headers(false, vec![("content-type", FORM_TYPE.to_string())], &[]);
        self.send(
            reqwest::Method::POST,
            "/oauth/token",
            headers,
            Some(form_body(fields)),
        )
        .await
    }

    /// Runs authorize, consent and token exchange for a signed-in client.
    pub async fn connect(&self, app: &OAuthApp, resource: &str) -> Tokens {
        let pkce = pkce();
        let state = random_from(ALNUM, 16);
        let authorized = self.authorize(app, resource, &pkce, &state).await;
        let on_consent = authorized
            .location_url()
            .is_some_and(|url| url.path() == "/oauth/consent");
        let req = match authorized.query("req") {
            Some(req) if authorized.status == 303 && on_consent => req,
            _ => fail_step("authorize", &authorized),
        };
        let granted = self.consent(&req, "approve").await;
        let code = match granted.query("code") {
            Some(code)
                if granted.status == 303
                    && granted
                        .location()
                        .is_some_and(|location| location.starts_with(&app.redirect_uri))
                    && granted.query("state").as_deref() == Some(state.as_str())
                    && granted.query("iss").as_deref() == Some(self.base.as_str()) =>
            {
                code
            }
            _ => fail_step("consent", &granted),
        };
        let issued = self
            .token_code(app, &code, &pkce.verifier, Some(resource))
            .await;
        tokens(&issued).unwrap_or_else(|| fail_step("token", &issued))
    }
}

impl TestClient {
    pub async fn setup_owner(&self, setup_code: &str, email: &str, password: &str) -> Page {
        self.submit(
            "/setup",
            "/setup",
            &[
                ("setup_code", setup_code),
                ("email", email),
                ("password", password),
            ],
        )
        .await
    }

    pub async fn login(&self, email: &str, password: &str) -> Page {
        self.submit(
            "/login",
            "/login",
            &[("email", email), ("password", password)],
        )
        .await
    }

    pub async fn login_for(&self, req: &str, email: &str, password: &str) -> Page {
        self.submit(
            &format!("/login?req={req}"),
            "/login",
            &[("email", email), ("password", password), ("req", req)],
        )
        .await
    }

    pub async fn logout(&self) -> Page {
        self.submit("/account", "/logout", &[]).await
    }

    pub async fn accept_invite(&self, link: &str, password: &str) -> Page {
        self.submit(link, link, &[("password", password)]).await
    }

    pub async fn reset_password(&self, link: &str, password: &str) -> Page {
        self.submit(link, link, &[("password", password)]).await
    }

    pub async fn change_password(&self, current: &str, new: &str) -> Page {
        self.submit(
            "/account",
            "/account/password",
            &[("current_password", current), ("new_password", new)],
        )
        .await
    }
}
