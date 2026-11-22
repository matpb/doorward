//! The bearer check for `/{slug}` and `/mcp`: one database call, and one refusal for every failure.

use std::net::IpAddr;

use axum::extract::{Path, Request, State};
use axum::http::header::{AUTHORIZATION, RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OptionalExtension, params};

use crate::app::AppState;
use crate::crypto::token_hash;
use crate::mcp;
use crate::proxy;
use crate::rate::{Class, Key, Open};
use crate::report;
use crate::servers::valid_slug;
use crate::web::limit::{hold, now_nanos, peer_of};
use crate::web::{client_address, not_found_bare};

const ACCESS_PREFIX: &str = "dw_at_";
const TOKEN_BODY_LEN: usize = 43;
const BEARER: &str = "Bearer";
/// The label of the combined endpoint in paths and messages.
const COMBINED: &str = "mcp";

/// The path a request is for: one server by its slug, or the combined endpoint.
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    Server(&'a str),
    Combined,
}

/// The caller of a request that passed every check.
pub struct Caller {
    pub user_id: i64,
    pub user_email: String,
    pub family_id: i64,
    pub server_id: Option<i64>,
    pub client_name: String,
    /// The hash the lookup used; never logged or shown.
    pub token_hash: String,
    /// The clock's second when the request passed the bearer check.
    pub admitted: i64,
    /// The user's `values_version` when the request passed the bearer check.
    pub values_version: i64,
}

/// The outcome of a re-check: the caller still passes, has lost access, or the check could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recheck {
    Live,
    Lost,
    Failed,
}

impl std::fmt::Debug for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Caller")
            .field("user_id", &self.user_id)
            .field("family_id", &self.family_id)
            .field("server_id", &self.server_id)
            .finish_non_exhaustive()
    }
}

/// A failed check. An unknown or expired token renders the 401 challenge; a database error renders
/// a 503 with no challenge; a limited request renders the MCP 429.
pub enum Refusal {
    Challenge(String),
    Limited(u64),
    Unavailable,
}

impl Refusal {
    fn new(resource: &str, presented: bool) -> Refusal {
        let mut challenge = format!(r#"{BEARER} resource_metadata="{resource}", scope="mcp""#);
        if presented {
            challenge.push_str(r#", error="invalid_token""#);
        }
        Refusal::Challenge(challenge)
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Refusal::Challenge(challenge) => match HeaderValue::from_str(&challenge) {
                Ok(value) => {
                    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, value)]).into_response()
                }
                // Unreachable: the challenge is built from a validated slug and a configured address.
                Err(_) => StatusCode::UNAUTHORIZED.into_response(),
            },
            Refusal::Limited(wait) => mcp::answer::limited(wait),
            Refusal::Unavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, [(RETRY_AFTER, "1")]).into_response()
            }
        }
    }
}

/// Ok only when every check passes, with the open MCP slot the response must hold.
/// The address is given back only for an admitted request, so an over-budget user still uses it up.
pub async fn check(
    state: &AppState,
    peer: IpAddr,
    headers: &HeaderMap,
    target: Target<'_>,
) -> Result<(Caller, Open), Refusal> {
    let presented = headers.contains_key(AUTHORIZATION);
    let resource = resource_of(state, target);
    let address = Key::address(client_address(peer, headers, &state.config.trusted_proxies));
    let nanos = now_nanos(state.clock.as_ref());
    if let Err(wait) = state.limiter.take(Class::General, address, nanos) {
        return Err(Refusal::Limited(wait));
    }
    let Some(token) = bearer_token(headers) else {
        return Err(Refusal::new(&resource, presented));
    };
    let hash = token_hash(token);
    let now = state.clock.now().unix_timestamp();
    let slug = match target {
        Target::Server(slug) => Some(slug.to_owned()),
        Target::Combined => None,
    };
    match state
        .db
        .call(move |conn| find_caller(conn, &hash, now, slug.as_deref()))
        .await
    {
        Ok(Some(caller)) => {
            let user = Key::User(caller.user_id);
            if let Err(wait) = state.limiter.take(Class::Mcp, user, nanos) {
                return Err(Refusal::Limited(wait));
            }
            match state.limiter.open(caller.user_id) {
                Some(open) => {
                    state.limiter.refund(Class::General, address, nanos);
                    Ok((caller, open))
                }
                None => {
                    state.limiter.refund(Class::Mcp, user, nanos);
                    Err(Refusal::Limited(1))
                }
            }
        }
        Ok(None) => Err(Refusal::new(&resource, presented)),
        Err(err) => {
            report::failure("bearer check", &err);
            Err(Refusal::Unavailable)
        }
    }
}

/// The re-check of `caller` on `/{slug}` with the clock at `at`. The token's expiry and the family's are
/// compared with `at`; revocation, disabling, deletion and assignment are read as they are now.
pub async fn still_valid_at(state: &AppState, caller: &Caller, slug: &str, at: i64) -> Recheck {
    let hash = caller.token_hash.clone();
    let slug = slug.to_owned();
    match state
        .db
        .call(move |conn| find_caller(conn, &hash, at, Some(&slug)))
        .await
    {
        Ok(Some(found))
            if found.family_id == caller.family_id
                && found.values_version == caller.values_version =>
        {
            Recheck::Live
        }
        Ok(_) => Recheck::Lost,
        Err(err) => {
            report::failure("access check", &err);
            Recheck::Failed
        }
    }
}

/// `still_valid_at` with the clock now, for a GET stream, which a reconnect loses nothing by.
pub async fn still_valid(state: &AppState, caller: &Caller, slug: &str) -> Recheck {
    let now = state.clock.now().unix_timestamp();
    still_valid_at(state, caller, slug, now).await
}

/// The re-check of `caller` on `/mcp` with the clock at `at`, and its user still assigned to `server_id`.
pub async fn combined_still_valid_at(
    state: &AppState,
    caller: &Caller,
    server_id: i64,
    at: i64,
) -> Recheck {
    let hash = caller.token_hash.clone();
    match state
        .db
        .call(move |conn| {
            conn.query_row(COMBINED_SQL, params![hash, at, server_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .optional()
        })
        .await
    {
        Ok(Some((family, version)))
            if family == caller.family_id && version == caller.values_version =>
        {
            Recheck::Live
        }
        Ok(_) => Recheck::Lost,
        Err(err) => {
            report::failure("access check", &err);
            Recheck::Failed
        }
    }
}

/// `combined_still_valid_at` with the clock now.
pub async fn combined_still_valid(state: &AppState, caller: &Caller, server_id: i64) -> Recheck {
    let now = state.clock.now().unix_timestamp();
    combined_still_valid_at(state, caller, server_id, now).await
}

/// True when `text` is `prefix` followed by 43 base64url characters.
pub fn is_token_shape(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix)
        .is_some_and(|body| body.len() == TOKEN_BODY_LEN && body.bytes().all(is_base64url))
}

/// `GET`, `POST` and `DELETE` on `/{slug}`. An invalid slug is a plain 404, before the guard.
pub async fn server_path(
    State(state): State<AppState>,
    slug: Option<Path<String>>,
    request: Request,
) -> Response {
    let Some(Path(slug)) = slug else {
        return not_found_bare();
    };
    if !valid_slug(&slug) {
        return not_found_bare();
    }
    let peer = peer_of(request.extensions());
    match check(&state, peer, request.headers(), Target::Server(&slug)).await {
        Ok((caller, open)) => hold(proxy::handle(&state, caller, &slug, request).await, open),
        Err(refusal) => refusal.into_response(),
    }
}

/// `GET`, `POST` and `DELETE` on `/mcp`.
pub async fn combined_path(State(state): State<AppState>, request: Request) -> Response {
    let peer = peer_of(request.extensions());
    match check(&state, peer, request.headers(), Target::Combined).await {
        Ok((caller, open)) => hold(proxy::combined::handle(&state, caller, request).await, open),
        Err(refusal) => refusal.into_response(),
    }
}

/// The metadata address the challenge points at, from the configured public address.
fn resource_of(state: &AppState, target: Target<'_>) -> String {
    let label = match target {
        Target::Server(slug) => slug,
        Target::Combined => COMBINED,
    };
    format!(
        "{}/.well-known/oauth-protected-resource/{label}",
        state.config.public_url
    )
}

/// The token of the only Authorization header, when it is `Bearer <token>` in the exact shape.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value,
        _ => return None,
    };
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case(BEARER) && is_token_shape(token, ACCESS_PREFIX)).then_some(token)
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// The token row, its family and its user, when every check passes for the path.
const CHECK_SQL: &str = "SELECT f.user_id, u.email, f.id, f.server_id, f.client_name, u.values_version \
    FROM access_tokens a \
    JOIN token_families f ON f.id = a.family_id \
    JOIN users u ON u.id = f.user_id \
    WHERE a.token_hash = ?1 AND a.expires_at > ?2 \
    AND f.revoked_at IS NULL AND f.expires_at > ?2 \
    AND u.disabled = 0 AND f.auth_epoch = u.auth_epoch \
    AND ((?3 IS NULL AND f.server_id IS NULL) \
      OR (?3 IS NOT NULL AND f.server_id IN (SELECT id FROM servers WHERE slug = ?3) \
          AND EXISTS (SELECT 1 FROM user_servers us \
                      WHERE us.user_id = f.user_id AND us.server_id = f.server_id)))";

/// The family of the caller's combined token when it passes every check for `/mcp` and the user is
/// assigned to the server in `?3`.
const COMBINED_SQL: &str = "SELECT f.id, u.values_version FROM access_tokens a \
    JOIN token_families f ON f.id = a.family_id \
    JOIN users u ON u.id = f.user_id \
    WHERE a.token_hash = ?1 AND a.expires_at > ?2 \
    AND f.revoked_at IS NULL AND f.expires_at > ?2 \
    AND u.disabled = 0 AND f.auth_epoch = u.auth_epoch \
    AND f.server_id IS NULL \
    AND EXISTS (SELECT 1 FROM user_servers us \
                WHERE us.user_id = f.user_id AND us.server_id = ?3)";

fn find_caller(
    conn: &Connection,
    hash: &str,
    now: i64,
    slug: Option<&str>,
) -> rusqlite::Result<Option<Caller>> {
    conn.query_row(CHECK_SQL, params![hash, now, slug], |row| {
        Ok(Caller {
            user_id: row.get(0)?,
            user_email: row.get(1)?,
            family_id: row.get(2)?,
            server_id: row.get(3)?,
            client_name: row.get(4)?,
            token_hash: hash.to_owned(),
            admitted: now,
            values_version: row.get(5)?,
        })
    })
    .optional()
}
