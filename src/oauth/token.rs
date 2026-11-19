//! `POST /oauth/token`: code redemption with PKCE, and refresh rotation with replay handling.

use std::collections::HashSet;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::config::Lifetimes;
use crate::crypto::{
    CryptoError, constant_time_eq, open_with_token, random_token, seal_with_token, token_hash,
};
use crate::mail::{self, templates};

use super::clients;
use super::families::{self, NewFamily, Pair};
use super::uri;

const BODY_LIMIT: usize = 16 * 1024;
const FORM_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_TYPE: &str = "application/json";
const CODE_GRANT: &str = "authorization_code";
const REFRESH_GRANT: &str = "refresh_token";
const CODE_PREFIX: &str = "dw_ac_";
const REFRESH_PREFIX: &str = "dw_rt_";
const TOKEN_BODY_LEN: usize = 43;
const REPLAY_CONTEXT: &str = "refresh_tokens.replay:";
const SCOPE: &str = "mcp";
const CODE_REPLAY: &str = "code replay";
const REFRESH_REPLAY: &str = "refresh replay";
const INVALID_REQUEST: &str = "invalid_request";
const INVALID_GRANT: &str = "invalid_grant";
const INVALID_CLIENT: &str = "invalid_client";
const INVALID_TARGET: &str = "invalid_target";
const UNSUPPORTED_GRANT: &str = "unsupported_grant_type";

/// The fields of a form body. Every name appears once.
struct Form(Vec<(String, String)>);

impl Form {
    /// The pairs of `bytes`, or None when a name appears twice.
    fn parse(bytes: &[u8]) -> Option<Form> {
        let pairs: Vec<(String, String)> = form_urlencoded::parse(bytes)
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let mut names: HashSet<&str> = HashSet::with_capacity(pairs.len());
        if pairs.iter().any(|(name, _)| !names.insert(name.as_str())) {
            return None;
        }
        Some(Form(pairs))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The two grants the endpoint answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Grant {
    Code,
    Refresh,
}

/// What one request decided. A refusal is an outcome, so the transaction still commits.
enum Outcome {
    Issued {
        body: Vec<u8>,
        welcome: Option<Welcome>,
    },
    Refused(&'static str),
}

/// The new-connection mail, sent after the commit.
struct Welcome {
    email: String,
    token: String,
}

/// What the transaction needs from the request and the configuration.
struct Job {
    form: Form,
    grant: Grant,
    now: i64,
    lifetimes: Lifetimes,
    issuer: String,
}

/// The user, server and client name an activity row names.
struct Grantee<'a> {
    user_id: i64,
    server_id: Option<i64>,
    client_name: &'a str,
}

struct StoredCode {
    client_id: String,
    redirect_uri: String,
    user_id: i64,
    server_id: Option<i64>,
    client_name: String,
    challenge: String,
    auth_epoch: i64,
    expires_at: i64,
    used_at: Option<i64>,
    family_id: Option<i64>,
}

struct StoredRefresh {
    token_hash: String,
    family_id: i64,
    expires_at: i64,
    used_at: Option<i64>,
    replay: Option<String>,
}

struct StoredFamily {
    id: i64,
    user_id: i64,
    server_id: Option<i64>,
    client_id: String,
    client_name: String,
    auth_epoch: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
}

struct UserRow {
    email: String,
    disabled: bool,
    auth_epoch: i64,
}

/// Answers every token request. Reads no cookie and checks no Origin.
pub async fn post_token(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Some(form) = read_form(&parts.headers, body).await else {
        return refuse(INVALID_REQUEST);
    };
    let grant = match precheck(&form) {
        Ok(grant) => grant,
        Err(error) => return refuse(error),
    };
    let job = Job {
        form,
        grant,
        now: state.clock.now().unix_timestamp(),
        lifetimes: state.config.lifetimes.clone(),
        issuer: state.config.public_url.clone(),
    };
    match state.db.call(move |conn| decide_in(conn, &job)).await {
        Ok(Outcome::Issued { body, welcome }) => {
            if let Some(welcome) = welcome {
                send_welcome(&state, welcome);
            }
            answer(StatusCode::OK, body)
        }
        Ok(Outcome::Refused(error)) => refuse(error),
        Err(err) => {
            eprintln!("doorward: cannot decide a token request: {err}");
            answer(StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
        }
    }
}

/// Any method other than POST: 405, with the same headers as every other answer.
pub async fn not_post() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(CACHE_CONTROL, "no-store"), (CONTENT_TYPE, JSON_TYPE)],
    )
        .into_response()
}

/// A JSON answer with the headers every token answer carries.
fn answer(status: StatusCode, body: Vec<u8>) -> Response {
    (
        status,
        [(CACHE_CONTROL, "no-store"), (CONTENT_TYPE, JSON_TYPE)],
        body,
    )
        .into_response()
}

fn refuse(error: &str) -> Response {
    answer(
        StatusCode::BAD_REQUEST,
        json!({ "error": error }).to_string().into_bytes(),
    )
}

/// The body as a form: a form media type, at most 16 KiB, and no name twice. None otherwise.
async fn read_form(headers: &HeaderMap, body: Body) -> Option<Form> {
    if !is_media_type(headers, FORM_TYPE) {
        return None;
    }
    let bytes = to_bytes(body, BODY_LIMIT).await.ok()?;
    Form::parse(&bytes)
}

/// The media type before any `;`, compared without regard to letter case.
fn is_media_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(expected))
}

/// The checks that need no database: the grant, the client field, and the shape of the
/// fields that grant uses.
fn precheck(form: &Form) -> Result<Grant, &'static str> {
    let grant = match form.get("grant_type") {
        None => return Err(INVALID_REQUEST),
        Some(CODE_GRANT) => Grant::Code,
        Some(REFRESH_GRANT) => Grant::Refresh,
        Some(_) => return Err(UNSUPPORTED_GRANT),
    };
    if form.get("client_id").is_none() {
        return Err(INVALID_REQUEST);
    }
    if shapes_ok(form, grant) {
        Ok(grant)
    } else {
        Err(INVALID_GRANT)
    }
}

/// A present code, verifier or refresh token of the requested grant has the right shape.
fn shapes_ok(form: &Form, grant: Grant) -> bool {
    match grant {
        Grant::Code => {
            form.get("code")
                .is_none_or(|code| has_shape(code, CODE_PREFIX))
                && form.get("code_verifier").is_none_or(verifier_has_shape)
        }
        Grant::Refresh => form
            .get("refresh_token")
            .is_none_or(|token| has_shape(token, REFRESH_PREFIX)),
    }
}

/// `prefix` followed by exactly 43 base64url characters.
fn has_shape(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix)
        .is_some_and(|body| body.len() == TOKEN_BODY_LEN && body.bytes().all(is_base64url))
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// 43 to 128 characters of A-Z, a-z, 0-9, `.`, `_`, `~` and `-`.
fn verifier_has_shape(text: &str) -> bool {
    (43..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

/// One immediate transaction for the whole request. The outcome is committed, refusals included.
fn decide_in(conn: &mut Connection, job: &Job) -> rusqlite::Result<Outcome> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = decide(&tx, job)?;
    tx.commit()?;
    Ok(outcome)
}

fn decide(tx: &Transaction<'_>, job: &Job) -> rusqlite::Result<Outcome> {
    let Some(client_id) = job.form.get("client_id") else {
        return Ok(Outcome::Refused(INVALID_REQUEST));
    };
    if clients::find(tx, client_id)?.is_none() {
        return Ok(Outcome::Refused(INVALID_CLIENT));
    }
    match job.grant {
        Grant::Code => redeem_code(tx, job),
        Grant::Refresh => refresh(tx, job),
    }
}

/// Authorization code: the steps of the brief, in order.
fn redeem_code(tx: &Transaction<'_>, job: &Job) -> rusqlite::Result<Outcome> {
    let (Some(code), Some(verifier)) = (job.form.get("code"), job.form.get("code_verifier")) else {
        return Ok(Outcome::Refused(INVALID_REQUEST));
    };
    let code_hash = token_hash(code);
    let Some(stored) = load_code(tx, &code_hash)? else {
        return Ok(Outcome::Refused(INVALID_GRANT));
    };
    if !binds_request(job, &stored) || !pkce_matches(verifier, &stored.challenge) {
        return Ok(Outcome::Refused(INVALID_GRANT));
    }
    if stored.used_at.is_some() {
        return code_replay(tx, job, &stored);
    }
    if job.now >= stored.expires_at {
        return Ok(Outcome::Refused(INVALID_GRANT));
    }
    if !resource_ok(tx, job, stored.server_id)? {
        return Ok(Outcome::Refused(INVALID_TARGET));
    }
    let Some(user) = load_user(tx, stored.user_id)? else {
        return Ok(Outcome::Refused(INVALID_GRANT));
    };
    if !may_use(
        tx,
        &user,
        stored.auth_epoch,
        stored.user_id,
        stored.server_id,
    )? {
        return Ok(Outcome::Refused(INVALID_GRANT));
    }
    issue_from_code(tx, job, &code_hash, &stored, user)
}

/// The request names the client and, when it sends one, the redirect address of the code.
fn binds_request(job: &Job, stored: &StoredCode) -> bool {
    job.form.get("client_id") == Some(stored.client_id.as_str())
        && job
            .form
            .get("redirect_uri")
            .is_none_or(|redirect| redirect == stored.redirect_uri)
}

/// base64url(SHA-256(verifier)) equals the stored challenge.
fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// A used code: the family it made is revoked, when that family still exists.
fn code_replay(tx: &Transaction<'_>, job: &Job, stored: &StoredCode) -> rusqlite::Result<Outcome> {
    if let Some(family_id) = stored.family_id {
        families::revoke(tx, family_id, job.now)?;
        let who = Grantee {
            user_id: stored.user_id,
            server_id: stored.server_id,
            client_name: &stored.client_name,
        };
        record(tx, job.now, "client_disconnected", &who, CODE_REPLAY)?;
    }
    Ok(Outcome::Refused(INVALID_GRANT))
}

/// Marks the code used, makes its family and pair, and records the connection.
fn issue_from_code(
    tx: &Transaction<'_>,
    job: &Job,
    code_hash: &str,
    stored: &StoredCode,
    user: UserRow,
) -> rusqlite::Result<Outcome> {
    let family = NewFamily {
        user_id: stored.user_id,
        server_id: stored.server_id,
        client_id: &stored.client_id,
        client_name: &stored.client_name,
        auth_epoch: stored.auth_epoch,
    };
    let family_id = families::create(tx, &family, job.now, job.lifetimes.family_days)?;
    tx.execute(
        "UPDATE auth_codes SET used_at = ?1, family_id = ?2 WHERE code_hash = ?3",
        params![job.now, family_id, code_hash],
    )?;
    let pair = families::mint_pair(tx, family_id, job.now, &job.lifetimes)?;
    let who = Grantee {
        user_id: stored.user_id,
        server_id: stored.server_id,
        client_name: &stored.client_name,
    };
    record(tx, job.now, "client_connected", &who, "")?;
    let welcome = first_connection(tx, job.now, family_id, stored, user)?;
    Ok(Outcome::Issued {
        body: token_body(&pair, &job.lifetimes),
        welcome,
    })
}

/// The first redemption of a client for a user makes a disconnect link and asks for the mail.
fn first_connection(
    tx: &Transaction<'_>,
    now: i64,
    family_id: i64,
    stored: &StoredCode,
    user: UserRow,
) -> rusqlite::Result<Option<Welcome>> {
    let redirect_key = redirect_key_of(&stored.redirect_uri);
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO known_clients (user_id, client_id, redirect_key, first_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![stored.user_id, stored.client_id, redirect_key, now],
    )?;
    if inserted == 0 {
        return Ok(None);
    }
    let token = random_token("dw_dl_");
    tx.execute(
        "INSERT INTO disconnect_links (token_hash, family_id, created_at) VALUES (?1, ?2, ?3)",
        params![token_hash(&token), family_id, now],
    )?;
    Ok(Some(Welcome {
        email: user.email,
        token,
    }))
}

/// The redirect address without its loopback port; the text itself when it does not parse.
fn redirect_key_of(text: &str) -> String {
    uri::parse(text).map_or_else(|| text.to_owned(), |redirect| uri::redirect_key(&redirect))
}

/// The success body of the interface reference.
fn token_body(pair: &Pair, lifetimes: &Lifetimes) -> Vec<u8> {
    json!({
        "access_token": pair.access_token,
        "token_type": "Bearer",
        "expires_in": families::access_seconds(lifetimes),
        "refresh_token": pair.refresh_token,
        "scope": SCOPE,
    })
    .to_string()
    .into_bytes()
}

/// Refresh token: the steps of the brief, in order.
fn refresh(tx: &Transaction<'_>, job: &Job) -> rusqlite::Result<Outcome> {
    let Some(token) = job.form.get("refresh_token") else {
        return Ok(Outcome::Refused(INVALID_REQUEST));
    };
    let Some(row) = load_refresh(tx, &token_hash(token))? else {
        return Ok(Outcome::Refused(INVALID_GRANT));
    };
    let Some(family) = load_family(tx, row.family_id)? else {
        return Ok(Outcome::Refused(INVALID_GRANT));
    };
    families::clear_old_replays_of(
        tx,
        family.id,
        job.now,
        families::replay_window(&job.lifetimes),
    )?;
    if job.form.get("client_id") != Some(family.client_id.as_str()) {
        return Ok(Outcome::Refused(INVALID_GRANT));
    }
    if !resource_ok(tx, job, family.server_id)? {
        return Ok(Outcome::Refused(INVALID_TARGET));
    }
    if !family_is_live(tx, job.now, &family)? {
        return Ok(Outcome::Refused(INVALID_GRANT));
    }
    match row.used_at {
        Some(used_at) => reuse(tx, job, token, &row, &family, used_at),
        None => rotate(tx, job, token, &row),
    }
}

/// A used refresh token gets the stored answer inside the window; otherwise the family ends.
fn reuse(
    tx: &Transaction<'_>,
    job: &Job,
    token: &str,
    row: &StoredRefresh,
    family: &StoredFamily,
    used_at: i64,
) -> rusqlite::Result<Outcome> {
    if let Some(body) = replayed_body(job, token, row, used_at) {
        return Ok(Outcome::Issued {
            body,
            welcome: None,
        });
    }
    families::revoke(tx, family.id, job.now)?;
    let who = Grantee {
        user_id: family.user_id,
        server_id: family.server_id,
        client_name: &family.client_name,
    };
    record(tx, job.now, "client_disconnected", &who, REFRESH_REPLAY)?;
    Ok(Outcome::Refused(INVALID_GRANT))
}

/// The stored answer, when the window is on, the use is inside it, and the token opens the copy.
fn replayed_body(job: &Job, token: &str, row: &StoredRefresh, used_at: i64) -> Option<Vec<u8>> {
    let window = families::replay_window(&job.lifetimes);
    if window == 0 || job.now > used_at.saturating_add(window) {
        return None;
    }
    let sealed = row.replay.as_deref()?;
    open_with_token(token, &replay_context(&row.token_hash), sealed).ok()
}

/// A fresh pair. The used row keeps the answer, sealed under the presented token, for the window.
fn rotate(
    tx: &Transaction<'_>,
    job: &Job,
    token: &str,
    row: &StoredRefresh,
) -> rusqlite::Result<Outcome> {
    if job.now >= row.expires_at {
        return Ok(Outcome::Refused(INVALID_GRANT));
    }
    let pair = families::mint_pair(tx, row.family_id, job.now, &job.lifetimes)?;
    let body = token_body(&pair, &job.lifetimes);
    let replay = sealed_replay(job, token, row, &body)?;
    tx.execute(
        "UPDATE refresh_tokens SET used_at = ?1, replay = ?2 WHERE token_hash = ?3",
        params![job.now, replay, row.token_hash],
    )?;
    Ok(Outcome::Issued {
        body,
        welcome: None,
    })
}

/// The answer sealed under the presented token; None when the replay window is off.
fn sealed_replay(
    job: &Job,
    token: &str,
    row: &StoredRefresh,
    body: &[u8],
) -> rusqlite::Result<Option<String>> {
    if families::replay_window(&job.lifetimes) == 0 {
        return Ok(None);
    }
    // A sealing failure becomes a database error, so the whole request rolls back.
    seal_with_token(token, &replay_context(&row.token_hash), body)
        .map(Some)
        .map_err(seal_failure)
}

fn seal_failure(err: CryptoError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(err))
}

fn replay_context(token_hash: &str) -> String {
    format!("{REPLAY_CONTEXT}{token_hash}")
}

/// True when the request's `resource`, if sent, names the address of the family's target.
fn resource_ok(tx: &Transaction<'_>, job: &Job, server_id: Option<i64>) -> rusqlite::Result<bool> {
    let Some(resource) = job.form.get("resource") else {
        return Ok(true);
    };
    Ok(target_of(tx, &job.issuer, server_id)?.as_deref() == Some(resource))
}

/// The address a server path or the combined endpoint is named by; None when the server is gone.
fn target_of(
    conn: &Connection,
    issuer: &str,
    server_id: Option<i64>,
) -> rusqlite::Result<Option<String>> {
    let Some(id) = server_id else {
        return Ok(Some(format!("{issuer}/mcp")));
    };
    Ok(server_slug(conn, id)?.map(|slug| format!("{issuer}/{slug}")))
}

/// The family is not revoked or expired, and its user may still use the server.
fn family_is_live(conn: &Connection, now: i64, family: &StoredFamily) -> rusqlite::Result<bool> {
    if family.revoked_at.is_some() || now >= family.expires_at {
        return Ok(false);
    }
    let Some(user) = load_user(conn, family.user_id)? else {
        return Ok(false);
    };
    may_use(
        conn,
        &user,
        family.auth_epoch,
        family.user_id,
        family.server_id,
    )
}

/// The user is enabled, on the given auth epoch, and assigned to the server when there is one.
fn may_use(
    conn: &Connection,
    user: &UserRow,
    auth_epoch: i64,
    user_id: i64,
    server_id: Option<i64>,
) -> rusqlite::Result<bool> {
    if user.disabled || user.auth_epoch != auth_epoch {
        return Ok(false);
    }
    let Some(server) = server_id else {
        return Ok(true);
    };
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM user_servers WHERE user_id = ?1 AND server_id = ?2)",
        params![user_id, server],
        |row| row.get(0),
    )
}

/// One activity row for a grant. It names the user, server and client, never a secret.
fn record(
    conn: &Connection,
    now: i64,
    kind: &str,
    who: &Grantee<'_>,
    detail: &str,
) -> rusqlite::Result<()> {
    let email = load_user(conn, who.user_id)?
        .map(|user| user.email)
        .unwrap_or_default();
    let slug = match who.server_id {
        Some(id) => server_slug(conn, id)?.unwrap_or_default(),
        None => String::new(),
    };
    audit::record(
        conn,
        now,
        &Event {
            kind,
            user_id: Some(who.user_id),
            user_email: &email,
            server_id: who.server_id,
            server_slug: &slug,
            client: who.client_name,
            detail,
            ..Default::default()
        },
    )
}

/// Mails the disconnect link after the commit. The mail module records any failure itself.
fn send_welcome(state: &AppState, welcome: Welcome) {
    let state = state.clone();
    tokio::spawn(async move {
        let link = format!(
            "{}/account/disconnect/{}",
            state.config.public_url, welcome.token
        );
        let message = templates::new_connection(&link).to(welcome.email);
        // mail::send has already recorded any failure in the activity log.
        let _ = mail::send(&state, message).await;
    });
}

fn load_code(conn: &Connection, code_hash: &str) -> rusqlite::Result<Option<StoredCode>> {
    conn.query_row(
        "SELECT client_id, redirect_uri, user_id, server_id, client_name, code_challenge, \
         auth_epoch, expires_at, used_at, family_id FROM auth_codes WHERE code_hash = ?1",
        params![code_hash],
        |row| {
            Ok(StoredCode {
                client_id: row.get(0)?,
                redirect_uri: row.get(1)?,
                user_id: row.get(2)?,
                server_id: row.get(3)?,
                client_name: row.get(4)?,
                challenge: row.get(5)?,
                auth_epoch: row.get(6)?,
                expires_at: row.get(7)?,
                used_at: row.get(8)?,
                family_id: row.get(9)?,
            })
        },
    )
    .optional()
}

fn load_refresh(conn: &Connection, token_hash: &str) -> rusqlite::Result<Option<StoredRefresh>> {
    conn.query_row(
        "SELECT token_hash, family_id, expires_at, used_at, replay FROM refresh_tokens \
         WHERE token_hash = ?1",
        params![token_hash],
        |row| {
            Ok(StoredRefresh {
                token_hash: row.get(0)?,
                family_id: row.get(1)?,
                expires_at: row.get(2)?,
                used_at: row.get(3)?,
                replay: row.get(4)?,
            })
        },
    )
    .optional()
}

fn load_family(conn: &Connection, family_id: i64) -> rusqlite::Result<Option<StoredFamily>> {
    conn.query_row(
        "SELECT id, user_id, server_id, client_id, client_name, auth_epoch, expires_at, revoked_at \
         FROM token_families WHERE id = ?1",
        params![family_id],
        |row| {
            Ok(StoredFamily {
                id: row.get(0)?,
                user_id: row.get(1)?,
                server_id: row.get(2)?,
                client_id: row.get(3)?,
                client_name: row.get(4)?,
                auth_epoch: row.get(5)?,
                expires_at: row.get(6)?,
                revoked_at: row.get(7)?,
            })
        },
    )
    .optional()
}

fn load_user(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<UserRow>> {
    conn.query_row(
        "SELECT email, disabled, auth_epoch FROM users WHERE id = ?1",
        params![user_id],
        |row| {
            Ok(UserRow {
                email: row.get(0)?,
                disabled: row.get(1)?,
                auth_epoch: row.get(2)?,
            })
        },
    )
    .optional()
}

fn server_slug(conn: &Connection, server_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT slug FROM servers WHERE id = ?1",
        params![server_id],
        |row| row.get(0),
    )
    .optional()
}
