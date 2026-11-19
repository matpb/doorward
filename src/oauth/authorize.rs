//! `GET /oauth/authorize` and the stored authorization request.

use std::collections::HashSet;

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use form_urlencoded::Serializer;
use maud::html;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{random_token, token_hash};
use crate::servers::valid_slug;
use crate::web::{Viewer, internal_error, page, redirect, throttle_key};

use super::clients::{self, Client};
use super::policy::{self, Verdict};
use super::uri::{self, Redirect};

const REQUEST_PREFIX: &str = "dw_rq_";
const BODY_LEN: usize = 43;
const LIVE_PER_ADDRESS: i64 = 200;
const STATE_LIMIT: usize = 1024;
const HOUR_SECONDS: i64 = 3600;
const CLIENT_TEXT_LIMIT: usize = 100;
const DETAIL_LIMIT: usize = 500;
const INVALID_REQUEST: &str = "invalid_request";
const INVALID_TARGET: &str = "invalid_target";
const INTERACTION_REQUIRED: &str = "interaction_required";

/// Whether `text` is a request id: `dw_rq_` and 43 base64url characters.
pub fn is_request_id(text: &str) -> bool {
    text.strip_prefix(REQUEST_PREFIX)
        .is_some_and(|body| body.len() == BODY_LEN && body.bytes().all(is_base64url))
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// The resource a request names: the combined endpoint, or one server by slug.
#[derive(Debug, PartialEq, Eq)]
pub enum Resource {
    Combined,
    Server(String),
}

/// The resource of `text` when it is exactly the issuer followed by `/mcp` or a valid slug.
pub fn resource_of(text: Option<&str>, issuer: &str) -> Option<Resource> {
    let rest = text?.strip_prefix(issuer)?.strip_prefix('/')?;
    if rest == "mcp" {
        return Some(Resource::Combined);
    }
    valid_slug(rest).then(|| Resource::Server(rest.to_owned()))
}

/// The query parameters of a request, each name at most once.
pub struct Params(Vec<(String, String)>);

impl Params {
    /// None when a name repeats, or when `request` or `request_uri` is present.
    pub fn parse(query: &str) -> Option<Params> {
        let mut names = HashSet::new();
        let mut pairs = Vec::new();
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            if name == "request" || name == "request_uri" || !names.insert(name.to_string()) {
                return None;
            }
            pairs.push((name.into_owned(), value.into_owned()));
        }
        Some(Params(pairs))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The parts of a valid request that are stored.
pub struct Asked {
    pub challenge: String,
    pub target_slug: Option<String>,
}

/// The checks of step 4 in order; the first failure is the error sent back to the client.
pub fn check_request(params: &Params, issuer: &str) -> Result<Asked, &'static str> {
    if params
        .get("state")
        .is_some_and(|state| state.len() > STATE_LIMIT)
    {
        return Err(INVALID_REQUEST);
    }
    if params.get("response_type") != Some("code") {
        return Err(INVALID_REQUEST);
    }
    let challenge = match params.get("code_challenge") {
        Some(challenge) if is_challenge(challenge) => challenge,
        _ => return Err(INVALID_REQUEST),
    };
    if params.get("code_challenge_method") != Some("S256") {
        return Err(INVALID_REQUEST);
    }
    let target_slug = match resource_of(params.get("resource"), issuer) {
        Some(Resource::Combined) => None,
        Some(Resource::Server(slug)) => Some(slug),
        None => return Err(INVALID_TARGET),
    };
    if params.get("prompt") == Some("none") {
        return Err(INTERACTION_REQUIRED);
    }
    Ok(Asked {
        challenge: challenge.to_owned(),
        target_slug,
    })
}

fn is_challenge(text: &str) -> bool {
    text.len() == BODY_LEN && text.bytes().all(is_base64url)
}

/// The redirect address with one pair, the state when one is echoed, and `iss`.
pub fn back_url(
    issuer: &str,
    redirect_uri: &str,
    pair: (&str, &str),
    state: Option<&str>,
) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair(pair.0, pair.1);
    if let Some(state) = state {
        query.append_pair("state", state);
    }
    query.append_pair("iss", issuer);
    format!("{redirect_uri}?{}", query.finish())
}

/// The page for a request that cannot continue; `host` is the redirect host when one is named.
pub fn error_page(host: Option<&str>) -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "error",
        "Sign-in cannot continue",
        html! {
            h1 { "This sign-in cannot continue" }
            @if let Some(host) = host.filter(|text| !text.is_empty()) {
                p { "Doorward will not send you to " (host) "." }
            }
            p { "Start the sign-in again from the app." }
        },
    )
}

/// A stored request, as the consent page and the decision read it.
pub struct Stored {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub target_slug: Option<String>,
    pub session_hash: Option<String>,
    pub client_name: Option<String>,
    pub shown_at: Option<i64>,
    pub expires_at: i64,
}

/// The stored request with this id hash, or None.
pub fn load(conn: &Connection, id_hash: &str) -> rusqlite::Result<Option<Stored>> {
    conn.query_row(
        "SELECT client_id, redirect_uri, state, code_challenge, target_slug, session_hash, \
         client_name, shown_at, expires_at FROM auth_requests WHERE id_hash = ?1",
        params![id_hash],
        |row| {
            Ok(Stored {
                client_id: row.get(0)?,
                redirect_uri: row.get(1)?,
                state: row.get(2)?,
                code_challenge: row.get(3)?,
                target_slug: row.get(4)?,
                session_hash: row.get(5)?,
                client_name: row.get(6)?,
                shown_at: row.get(7)?,
                expires_at: row.get(8)?,
            })
        },
    )
    .optional()
}

/// `GET /oauth/authorize`: a refusal that cannot be sent back gets a page, the rest go to the client.
pub async fn get_authorize(
    State(state): State<AppState>,
    viewer: Viewer,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(params) = Params::parse(raw.as_deref().unwrap_or("")) else {
        return error_page(None);
    };
    let Some(client_id) = params.get("client_id") else {
        return error_page(None);
    };
    let redirect_uri = params.get("redirect_uri").unwrap_or("");
    let issuer = state.config.public_url.clone();
    let now = state.clock.now().unix_timestamp();
    let (client_owned, redirect_owned) = (client_id.to_owned(), redirect_uri.to_owned());
    let checked = state
        .db
        .call(move |conn| check_redirect_in(conn, &client_owned, &redirect_owned, now))
        .await;
    match checked {
        Ok(Checked::Allowed) => {}
        Ok(Checked::Refused(host)) => return error_page(host.as_deref()),
        Err(_) => return internal_error(),
    }
    let asked = match check_request(&params, &issuer) {
        Ok(asked) => asked,
        Err(error) => {
            let echoed = params.get("state").filter(|text| text.len() <= STATE_LIMIT);
            return redirect(&back_url(&issuer, redirect_uri, ("error", error), echoed));
        }
    };
    let signed_in = viewer.user.is_some();
    let session_hash = if signed_in {
        viewer.presented_session().map(token_hash)
    } else {
        None
    };
    let req = random_token(REQUEST_PREFIX);
    let new = NewRequest {
        id_hash: token_hash(&req),
        client_id: client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        state: params.get("state").map(str::to_owned),
        challenge: asked.challenge,
        target_slug: asked.target_slug,
        address: throttle_key(viewer.address),
        session_hash,
    };
    let lifetime = lifetime_seconds(state.config.lifetimes.auth_request_minutes);
    if state
        .db
        .call(move |conn| store_in(conn, &new, now, lifetime))
        .await
        .is_err()
    {
        return internal_error();
    }
    let next = if signed_in {
        format!("/oauth/consent?req={req}")
    } else {
        format!("/login?req={req}")
    };
    redirect(&next)
}

/// What the checks before storing decided.
enum Checked {
    Allowed,
    /// The host to name on the error page, when one is named.
    Refused(Option<String>),
}

fn check_redirect_in(
    conn: &mut Connection,
    client_id: &str,
    redirect_uri: &str,
    now: i64,
) -> rusqlite::Result<Checked> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let checked = check_within(&tx, client_id, redirect_uri, now)?;
    tx.commit()?;
    Ok(checked)
}

fn check_within(
    tx: &Transaction<'_>,
    client_id: &str,
    redirect_uri: &str,
    now: i64,
) -> rusqlite::Result<Checked> {
    let Some(client) = clients::find(tx, client_id)? else {
        return Ok(Checked::Refused(None));
    };
    let host = host_text(redirect_uri);
    // Anything the attacker chose is named only when it is plain host text.
    let Some(parsed) = uri::parse(redirect_uri) else {
        return Ok(Checked::Refused(host));
    };
    if !listed_for(&client, redirect_uri) {
        return Ok(Checked::Refused(host));
    }
    if policy::decide(tx, &parsed)? == Verdict::Blocked {
        record_blocked(tx, &client, &parsed, now)?;
        return Ok(Checked::Refused(host));
    }
    Ok(Checked::Allowed)
}

/// A registered client must have registered the requested address; a document is checked later.
fn listed_for(client: &Client, redirect_uri: &str) -> bool {
    match client {
        Client::Registered { redirect_uris, .. } => redirect_uris
            .iter()
            .any(|registered| uri::matches(registered, redirect_uri)),
        Client::Document { .. } => true,
    }
}

/// Writes one `redirect_blocked` row, unless one with the same address was written in the hour.
fn record_blocked(
    tx: &Transaction<'_>,
    client: &Client,
    parsed: &Redirect<'_>,
    now: i64,
) -> rusqlite::Result<()> {
    let detail = cut(&uri::redirect_key(parsed), DETAIL_LIMIT);
    if recorded_since(tx, &detail, now - HOUR_SECONDS)? {
        return Ok(());
    }
    let client_text = cut(client_label(client), CLIENT_TEXT_LIMIT);
    audit::record(
        tx,
        now,
        &Event {
            kind: "redirect_blocked",
            client: &client_text,
            detail: &detail,
            ..Default::default()
        },
    )
}

fn recorded_since(conn: &Connection, detail: &str, since: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM activity WHERE kind = 'redirect_blocked' \
         AND detail = ?1 AND at > ?2)",
        params![detail, since],
        |row| row.get(0),
    )
}

fn client_label(client: &Client) -> &str {
    match client {
        Client::Registered { client_name, .. } => client_name.as_str(),
        Client::Document { client_id } => client_id.as_str(),
    }
}

/// The authority of an address for the error page: only when it is short and plain, else None.
fn host_text(text: &str) -> Option<String> {
    let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let plain = !authority.is_empty()
        && authority.len() <= CLIENT_TEXT_LIMIT
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    plain.then(|| authority.to_owned())
}

/// The first `limit` characters of `text`.
fn cut(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// A request about to be stored.
struct NewRequest {
    id_hash: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    challenge: String,
    target_slug: Option<String>,
    address: String,
    session_hash: Option<String>,
}

/// Stores a request in one immediate transaction; expired rows go, a full address drops its oldest.
fn store_in(
    conn: &mut Connection,
    new: &NewRequest,
    now: i64,
    lifetime: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM auth_requests WHERE expires_at <= ?1",
        params![now],
    )?;
    evict_oldest(&tx, &new.address)?;
    tx.execute(
        "INSERT INTO auth_requests (id_hash, client_id, redirect_uri, target_slug, state, \
         code_challenge, session_hash, client_name, address, shown_at, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL, ?9, ?10)",
        params![
            new.id_hash,
            new.client_id,
            new.redirect_uri,
            new.target_slug,
            new.state,
            new.challenge,
            new.session_hash,
            new.address,
            now,
            now.saturating_add(lifetime),
        ],
    )?;
    tx.commit()
}

/// When an address already holds 200 live requests, its oldest one is deleted.
fn evict_oldest(tx: &Transaction<'_>, address: &str) -> rusqlite::Result<()> {
    let live: i64 = tx.query_row(
        "SELECT COUNT(*) FROM auth_requests WHERE address = ?1",
        params![address],
        |row| row.get(0),
    )?;
    if live >= LIVE_PER_ADDRESS {
        tx.execute(
            "DELETE FROM auth_requests WHERE rowid = (SELECT rowid FROM auth_requests \
             WHERE address = ?1 ORDER BY created_at, rowid LIMIT 1)",
            params![address],
        )?;
    }
    Ok(())
}

/// Configured minutes as seconds, saturating at the largest value.
fn lifetime_seconds(minutes: u64) -> i64 {
    i64::try_from(minutes.saturating_mul(60)).unwrap_or(i64::MAX)
}
