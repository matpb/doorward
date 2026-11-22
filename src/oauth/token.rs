//! `POST /oauth/token`: code redemption with PKCE, and refresh rotation with replay handling.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::config::Lifetimes;
use crate::crypto::{
    CryptoError, Keys, constant_time_eq, open_with_token, random_token, seal_with_token, token_hash,
};
use crate::mail::{self, templates};
use crate::report;
use crate::vault::DataKey;
use crate::vault::keys::{self, Table};
use crate::web::body::{ReadError, read, timed_out};

use super::clients;
use super::consent::shown_host;
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
const EVERY_SERVER: &str = "every server assigned to you";
const SERVER_LIMIT: usize = 60;
const DESTINATION_LIMIT: usize = 80;
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
    /// A refusal with no token behind it: the error, and nothing logged.
    Refused(&'static str),
    /// A refusal of a token that exists: the error, and the reason written to standard error.
    Denied(&'static str, &'static str),
}

/// The new-connection mail, sent after the commit.
struct Welcome {
    email: String,
    token: String,
    server: String,
    destination: String,
    time: String,
}

/// What the transaction needs from the request and the configuration.
struct Job {
    form: Form,
    grant: Grant,
    now: i64,
    at: OffsetDateTime,
    lifetimes: Lifetimes,
    issuer: String,
    keys: Arc<Keys>,
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
    let form = match read_form(&parts.headers, body, state.config.limits.body_read_seconds).await {
        Ok(Some(form)) => form,
        Ok(None) | Err(ReadError::TooLarge) => return refuse(INVALID_REQUEST),
        Err(ReadError::TimedOut) => return timed_out(),
    };
    let grant = match precheck(&form) {
        Ok(grant) => grant,
        Err(error) => return refuse(error),
    };
    let at = state.clock.now();
    let job = Job {
        form,
        grant,
        now: at.unix_timestamp(),
        at,
        lifetimes: state.config.lifetimes.clone(),
        issuer: state.config.public_url.clone(),
        keys: Arc::clone(&state.keys),
    };
    match state.db.call(move |conn| decide_in(conn, &job)).await {
        Ok(Outcome::Issued { body, welcome }) => {
            if let Some(welcome) = welcome {
                send_welcome(&state, welcome);
            }
            answer(StatusCode::OK, body)
        }
        Ok(Outcome::Refused(error)) => refuse(error),
        Ok(Outcome::Denied(error, reason)) => {
            report::refused("token", reason);
            refuse(error)
        }
        Err(err) => {
            report::failure("token request", &err);
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
/// `Err` when the body is too large or was not sent in time.
async fn read_form(
    headers: &HeaderMap,
    body: Body,
    seconds: u64,
) -> Result<Option<Form>, ReadError> {
    if !is_media_type(headers, FORM_TYPE) {
        return Ok(None);
    }
    let bytes = read(body, BODY_LIMIT, seconds).await?;
    Ok(Form::parse(&bytes))
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
    if job.form.get("client_id") != Some(stored.client_id.as_str()) {
        return Ok(Outcome::Denied(INVALID_GRANT, "the client does not match"));
    }
    if job
        .form
        .get("redirect_uri")
        .is_some_and(|redirect| redirect != stored.redirect_uri)
    {
        return Ok(Outcome::Denied(
            INVALID_GRANT,
            "the redirect address does not match",
        ));
    }
    if !pkce_matches(verifier, &stored.challenge) {
        return Ok(Outcome::Denied(
            INVALID_GRANT,
            "the verifier does not match",
        ));
    }
    if stored.used_at.is_some() {
        return code_replay(tx, job, &stored);
    }
    if job.now >= stored.expires_at {
        return Ok(Outcome::Denied(INVALID_GRANT, "the code has expired"));
    }
    if !resource_ok(tx, job, stored.server_id)? {
        return Ok(Outcome::Denied(
            INVALID_TARGET,
            "the resource does not match",
        ));
    }
    let Some(user) = load_user(tx, stored.user_id)? else {
        return Ok(Outcome::Denied(INVALID_GRANT, "the user no longer exists"));
    };
    if !may_use(
        tx,
        &user,
        stored.auth_epoch,
        stored.user_id,
        stored.server_id,
    )? {
        return Ok(Outcome::Denied(
            INVALID_GRANT,
            "the user may no longer use this server",
        ));
    }
    issue_from_code(tx, job, (code, &code_hash), &stored, user)
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
    Ok(Outcome::Denied(INVALID_GRANT, "the code was already used"))
}

/// Marks the code used, makes its family and pair, and records the connection.
fn issue_from_code(
    tx: &Transaction<'_>,
    job: &Job,
    (code, code_hash): (&str, &str),
    stored: &StoredCode,
    user: UserRow,
) -> rusqlite::Result<Outcome> {
    let held = keys::open_row(
        tx,
        &job.keys,
        stored.user_id,
        Table::AuthCodes,
        code_hash,
        code,
    )?;
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
    carry_key(tx, job, stored.user_id, held.as_ref(), &pair)?;
    keys::clear_row(tx, Table::AuthCodes, code_hash)?;
    let who = Grantee {
        user_id: stored.user_id,
        server_id: stored.server_id,
        client_name: &stored.client_name,
    };
    record(tx, job.now, "client_connected", &who, "")?;
    let welcome = first_connection(tx, job, family_id, stored, user)?;
    Ok(Outcome::Issued {
        body: token_body(&pair, &job.lifetimes),
        welcome,
    })
}

/// Wraps the data key onto the new access token and refresh token; no key, no wraps.
fn carry_key(
    tx: &Transaction<'_>,
    job: &Job,
    user: i64,
    held: Option<&DataKey>,
    pair: &Pair,
) -> rusqlite::Result<()> {
    let Some(key) = held else {
        return Ok(());
    };
    for (table, token) in [
        (Table::AccessTokens, &pair.access_token),
        (Table::RefreshTokens, &pair.refresh_token),
    ] {
        keys::wrap_row(tx, &job.keys, user, table, &token_hash(token), token, key)?;
    }
    Ok(())
}

/// The first redemption of a client for a user makes a disconnect link and asks for the mail.
fn first_connection(
    tx: &Transaction<'_>,
    job: &Job,
    family_id: i64,
    stored: &StoredCode,
    user: UserRow,
) -> rusqlite::Result<Option<Welcome>> {
    let redirect_key = redirect_key_of(&stored.redirect_uri);
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO known_clients (user_id, client_id, redirect_key, first_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![stored.user_id, stored.client_id, redirect_key, job.now],
    )?;
    if inserted == 0 {
        return Ok(None);
    }
    let token = random_token("dw_dl_");
    tx.execute(
        "INSERT INTO disconnect_links (token_hash, family_id, created_at) VALUES (?1, ?2, ?3)",
        params![token_hash(&token), family_id, job.now],
    )?;
    let server = match stored.server_id {
        Some(id) => truncated(&server_name(tx, id)?.unwrap_or_default(), SERVER_LIMIT),
        None => EVERY_SERVER.to_owned(),
    };
    Ok(Some(Welcome {
        email: user.email,
        token,
        server,
        destination: destination_of(&stored.redirect_uri),
        time: utc_text(job.at),
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
        return Ok(Outcome::Denied(
            INVALID_GRANT,
            "the connection no longer exists",
        ));
    };
    families::clear_old_replays_of(
        tx,
        family.id,
        job.now,
        families::replay_window(&job.lifetimes),
    )?;
    if job.form.get("client_id") != Some(family.client_id.as_str()) {
        return Ok(Outcome::Denied(INVALID_GRANT, "the client does not match"));
    }
    if !resource_ok(tx, job, family.server_id)? {
        return Ok(Outcome::Denied(
            INVALID_TARGET,
            "the resource does not match",
        ));
    }
    if let Some(reason) = family_ended(tx, job.now, &family)? {
        return Ok(Outcome::Denied(INVALID_GRANT, reason));
    }
    match row.used_at {
        Some(used_at) => reuse(tx, job, token, &row, &family, used_at),
        None => rotate(tx, job, token, &row, &family),
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
    Ok(Outcome::Denied(
        INVALID_GRANT,
        "the refresh token was already used",
    ))
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
    family: &StoredFamily,
) -> rusqlite::Result<Outcome> {
    if job.now >= row.expires_at {
        return Ok(Outcome::Denied(
            INVALID_GRANT,
            "the refresh token has expired",
        ));
    }
    let held = keys::open_row(
        tx,
        &job.keys,
        family.user_id,
        Table::RefreshTokens,
        &row.token_hash,
        token,
    )?;
    let pair = families::mint_pair(tx, row.family_id, job.now, &job.lifetimes)?;
    carry_key(tx, job, family.user_id, held.as_ref(), &pair)?;
    keys::clear_row(tx, Table::RefreshTokens, &row.token_hash)?;
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

/// The reason the connection cannot be used now: revoked, expired, or its user may not use it.
/// None while it can be used.
fn family_ended(
    conn: &Connection,
    now: i64,
    family: &StoredFamily,
) -> rusqlite::Result<Option<&'static str>> {
    if family.revoked_at.is_some() {
        return Ok(Some("the connection was revoked"));
    }
    if now >= family.expires_at {
        return Ok(Some("the connection has expired"));
    }
    let Some(user) = load_user(conn, family.user_id)? else {
        return Ok(Some("the user no longer exists"));
    };
    let usable = may_use(
        conn,
        &user,
        family.auth_epoch,
        family.user_id,
        family.server_id,
    )?;
    Ok((!usable).then_some("the user may no longer use this server"))
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
        let host = templates::host_and_port(&state.config.public_url);
        let facts = templates::Connection {
            server: &welcome.server,
            destination: &welcome.destination,
            time: &welcome.time,
        };
        let message = templates::new_connection(&link, &facts, host).to(welcome.email);
        // mail::send has already recorded any failure in the activity log.
        let _ = mail::send(&state, "new_connection", message).await;
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

fn server_name(conn: &Connection, server_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT name FROM servers WHERE id = ?1",
        params![server_id],
        |row| row.get(0),
    )
    .optional()
}

/// The host the sign-in was sent to: the redirect address's host, with its port when it has one.
fn destination_of(redirect: &str) -> String {
    match uri::parse(redirect) {
        Some(parsed) => tail(&shown_host(&parsed), DESTINATION_LIMIT),
        None => String::new(),
    }
}

fn truncated(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// The last `limit` characters of `text`.
fn tail(text: &str, limit: usize) -> String {
    let skip = text.chars().count().saturating_sub(limit);
    text.chars().skip(skip).collect()
}

/// The time in UTC as the mail writes it: `21 November 2026, 14:05 UTC`.
fn utc_text(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    format!(
        "{} {} {}, {:02}:{:02} UTC",
        at.day(),
        at.month(),
        at.year(),
        at.hour(),
        at.minute()
    )
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{destination_of, tail, truncated, utc_text};

    #[test]
    fn the_destination_is_named_as_the_consent_page_names_it() {
        assert_eq!(
            destination_of("http://127.0.0.1:53535/callback"),
            "127.0.0.1:53535"
        );
        assert_eq!(destination_of("http://localhost/callback"), "localhost");
        assert_eq!(destination_of("http://[::1]:8000/cb"), "[::1]:8000");
        assert_eq!(
            destination_of("https://app.example.com/api/mcp/auth_callback"),
            "app.example.com"
        );
        assert_eq!(
            destination_of("cursor://anysphere.cursor-mcp/oauth/callback"),
            "cursor:"
        );
    }

    #[test]
    fn a_text_that_does_not_parse_gives_an_empty_destination() {
        assert_eq!(destination_of("not a redirect address"), "");
    }

    #[test]
    fn a_destination_and_a_server_name_are_cut_to_their_limits() {
        let long = format!("https://{}.example.com/cb", "a".repeat(90));
        assert_eq!(
            destination_of(&long),
            format!("{}.example.com", "a".repeat(68))
        );
        assert_eq!(truncated(&"b".repeat(70), 60), "b".repeat(60));
        assert_eq!(truncated("short", 60), "short");
    }

    #[test]
    fn a_destination_of_100_characters_keeps_its_last_80() {
        let host = format!("{}.example.com", "b".repeat(88));
        assert_eq!(host.chars().count(), 100);
        assert_eq!(
            destination_of(&format!("https://{host}/cb")),
            format!("{}.example.com", "b".repeat(68))
        );
        assert_eq!(tail("ééé", 2), "éé");
        assert_eq!(tail("short", 60), "short");
    }

    #[test]
    fn a_destination_of_80_or_fewer_characters_is_unchanged() {
        let exact = format!("{}.example.com", "c".repeat(68));
        assert_eq!(exact.chars().count(), 80);
        assert_eq!(destination_of(&format!("https://{exact}/cb")), exact);
        assert_eq!(
            destination_of("https://app.example.com/cb"),
            "app.example.com"
        );
    }

    #[test]
    fn a_destination_always_ends_with_the_last_label_of_its_host() {
        // uri::parse refuses hosts over 253 characters, so 241 + 12 is the longest host tested.
        for length in [1, 79, 80, 81, 100, 241] {
            let host = format!("{}.example.com", "d".repeat(length));
            let shown = destination_of(&format!("https://{host}/cb"));
            // Brute force: the last 80 characters, taken by reversing twice.
            let reversed: String = host.chars().rev().take(80).collect();
            let expected: String = reversed.chars().rev().collect();
            assert_eq!(shown, expected, "host of {length} d characters");
            let label = host.rsplit('.').next().expect("a host has a last label");
            assert!(
                shown.ends_with(label),
                "the destination must end with the last label {label}, got {shown}"
            );
        }
    }

    #[test]
    fn the_time_is_utc_with_a_day_without_a_zero_and_a_24_hour_clock() {
        // date -u -d @1795269900 gives Sat 21 Nov 2026 02:05:00 PM UTC.
        let at = OffsetDateTime::from_unix_timestamp(1_795_269_900).expect("in range");
        assert_eq!(utc_text(at), "21 November 2026, 14:05 UTC");
        // date -u -d @1772608140 gives Wed 04 Mar 2026 07:09:00 AM UTC.
        let at = OffsetDateTime::from_unix_timestamp(1_772_608_140).expect("in range");
        assert_eq!(utc_text(at), "4 March 2026, 07:09 UTC");
        // date -u -d @1767225600 gives Thu 01 Jan 2026 12:00:00 AM UTC.
        let at = OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("in range");
        assert_eq!(utc_text(at), "1 January 2026, 00:00 UTC");
    }
}
