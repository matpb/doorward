//! The values a user stores for a server's declared custom headers: what the account page shows
//! of them and the post that stores, replaces and removes them.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use time::OffsetDateTime;
use time::format_description;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{Keys, token_hash};
use crate::custom_headers;
use crate::oauth::connected;
use crate::servers::valid_slug;
use crate::vault::keys::{self, Table};
use crate::vault::{ValuePlace, seal_value};
use crate::web::{VerifiedForm, Viewer, internal_error, not_found, redirect};

use super::account::account_page_with;

/// Shown when the browser session holds no key the values could be sealed under.
pub const LOCKED: &str = "Sign in again to store or change credentials.";
const BAD_VALUE: &str = "A credential is 1 to 4096 visible characters with no line break.";
const BOTH: &str = "A credential cannot be saved and removed in the same step.";

/// One declared header of a server as the account page shows it.
pub struct HeaderView {
    pub id: i64,
    pub name: String,
    pub lower: String,
    pub required: bool,
    /// When the user stored a value; never the value.
    pub set_at: Option<i64>,
}

/// One server whose users store values, with the user's state for each declared header.
pub struct ServerView {
    pub slug: String,
    pub name: String,
    pub host: String,
    /// The upstream address is plain http and not on a loopback host.
    pub plain_http: bool,
    pub headers: Vec<HeaderView>,
}

impl ServerView {
    /// True while a required header has no stored value.
    pub fn needs_values(&self) -> bool {
        self.headers
            .iter()
            .any(|header| header.required && header.set_at.is_none())
    }
}

/// A refused post: the server whose form shows the notice, and its words.
pub struct Refusal {
    pub slug: String,
    pub message: &'static str,
}

/// The account page's credentials part: the servers, whether the session can open the key, a refusal,
/// and the name of the server whose credentials were just saved.
#[derive(Default)]
pub struct Part {
    pub servers: Vec<ServerView>,
    pub locked: bool,
    pub refusal: Option<Refusal>,
    pub saved: Option<String>,
    /// Servers whose store switch is off while the user still holds stored values: slug and name.
    pub retired: Vec<(String, String)>,
}

impl ServerView {
    /// The state a server's block shows: a required value missing, else one stored, else none.
    pub fn state(&self) -> ValueState {
        if self.needs_values() {
            ValueState::Needed
        } else if self.headers.iter().any(|header| header.set_at.is_some()) {
            ValueState::Stored
        } else {
            ValueState::Nothing
        }
    }
}

/// What a server's block says about its credentials.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueState {
    Needed,
    Stored,
    Nothing,
}

/// The host of an upstream address, and whether it is plain http on a host that is not loopback.
fn address_facts(address: &str) -> (String, bool) {
    let Ok(url) = Url::parse(address) else {
        return (String::new(), false);
    };
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    let host = url.host_str().unwrap_or_default().to_owned();
    (host, url.scheme() == "http" && !loopback)
}

/// A date as the activity page writes the day, such as `20 Nov 2026`.
pub fn day(at: i64) -> String {
    formatted(at, "[day padding:none] [month repr:short] [year]")
}

/// A date as `YYYY-MM-DD`, for the datetime of a `time` element.
pub fn iso_day(at: i64) -> String {
    formatted(at, "[year]-[month]-[day]")
}

/// The UTC date at `at` in the format `pattern`; empty when the time or the pattern is out of range.
fn formatted(at: i64, pattern: &str) -> String {
    let Ok(format) = format_description::parse_borrowed::<2>(pattern) else {
        return String::new();
    };
    OffsetDateTime::from_unix_timestamp(at)
        .ok()
        .and_then(|when| when.format(&format).ok())
        .unwrap_or_default()
}

/// The servers `user` may store values for, with the state of each header, and whether the
/// browser session `session` opens a key. No value is read.
pub fn part_in(
    conn: &Connection,
    keys: &Keys,
    user: i64,
    session: Option<&str>,
) -> rusqlite::Result<Part> {
    let mut statement = conn.prepare(
        "SELECT s.id, s.slug, s.name, s.upstream_url FROM servers s \
         JOIN user_servers us ON us.server_id = s.id \
         WHERE us.user_id = ?1 AND s.store_headers = 1 \
         AND EXISTS (SELECT 1 FROM server_headers h WHERE h.server_id = s.id) \
         ORDER BY s.name, s.id",
    )?;
    let rows: Vec<(i64, String, String, String)> = statement
        .query_map(params![user], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut servers = Vec::new();
    for (id, slug, name, address) in rows {
        let mut headers = conn.prepare(
            "SELECT h.id, h.name, h.name_lower, h.required, v.set_at FROM server_headers h \
             LEFT JOIN user_header_values v ON v.header_id = h.id AND v.user_id = ?1 \
             WHERE h.server_id = ?2 ORDER BY h.id",
        )?;
        let headers = headers
            .query_map(params![user, id], |row| {
                Ok(HeaderView {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    lower: row.get(2)?,
                    required: row.get(3)?,
                    set_at: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let (host, plain_http) = address_facts(&address);
        servers.push(ServerView {
            slug,
            name,
            host,
            plain_http,
            headers,
        });
    }
    let locked = !servers.is_empty() && !opens_key(conn, keys, user, session)?;
    let mut statement = conn.prepare(
        "SELECT DISTINCT s.slug, s.name FROM user_header_values v \
         JOIN server_headers h ON h.id = v.header_id JOIN servers s ON s.id = h.server_id \
         WHERE v.user_id = ?1 AND s.store_headers = 0 ORDER BY s.name, s.id",
    )?;
    let retired = statement
        .query_map(params![user], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
    Ok(Part {
        servers,
        locked,
        refusal: None,
        saved: None,
        retired,
    })
}

/// The name of the server a query names as saved, when the part holds that server. The query's slug is
/// only compared, never shown.
pub fn saved_name(part: &Part, raw: Option<&str>) -> Option<String> {
    let slug = form_urlencoded::parse(raw.unwrap_or("").as_bytes())
        .find(|(key, _)| key == "server")
        .map(|(_, value)| value.into_owned())?;
    part.servers
        .iter()
        .find(|server| server.slug == slug)
        .map(|server| server.name.clone())
}

/// True when the session cookie `session` carries a wrap that opens.
fn opens_key(
    conn: &Connection,
    keys: &Keys,
    user: i64,
    session: Option<&str>,
) -> rusqlite::Result<bool> {
    let Some(token) = session else {
        return Ok(false);
    };
    let key = keys::open_row(conn, keys, user, Table::Sessions, &token_hash(token), token)?;
    Ok(key.is_some())
}

/// The credentials part for the viewer's page.
pub async fn part_for(state: &AppState, viewer: &Viewer) -> Result<Part, crate::db::DbError> {
    let Some(user) = viewer.user.as_ref() else {
        return Ok(Part::default());
    };
    let (id, keys) = (user.id, state.keys.clone());
    let session = viewer.presented_session().map(str::to_owned);
    state
        .db
        .call(move |conn| part_in(conn, &keys, id, session.as_deref()))
        .await
}

/// The account page again with `refusal` shown on its form.
async fn refused(state: &AppState, viewer: &Viewer, slug: &str, message: &'static str) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    let clients = match connected::list(&state.db, user.id, now).await {
        Ok(clients) => clients,
        Err(err) => return internal_error("connected clients", &err),
    };
    let mut part = match part_for(state, viewer).await {
        Ok(part) => part,
        Err(err) => return internal_error("stored values", &err),
    };
    part.refusal = Some(Refusal {
        slug: slug.to_owned(),
        message,
    });
    account_page_with(viewer, StatusCode::BAD_REQUEST, None, &clients, &part)
}

/// What a post decided.
enum Outcome {
    Saved,
    Missing,
    Refused(&'static str),
}

/// One posted header: what to store and whether to remove.
struct Posted {
    header: i64,
    name: String,
    lower: String,
    value: Zeroizing<String>,
    remove: bool,
}

pub async fn post_values(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(user) = form.viewer.user.clone() else {
        return redirect("/login");
    };
    if !valid_slug(&slug) {
        return not_found();
    }
    let fields = &form.fields;
    let session = form.viewer.presented_session().map(str::to_owned);
    let posted: Vec<(i64, Zeroizing<String>, bool)> = {
        let mut ids: Vec<i64> = fields
            .pairs()
            .filter_map(|(name, _)| {
                name.strip_prefix("value_")
                    .or_else(|| name.strip_prefix("remove_"))
                    .and_then(|id| id.parse::<i64>().ok())
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.into_iter()
            .map(|id| {
                let value = Zeroizing::new(fields.get(&format!("value_{id}")).to_owned());
                let remove = fields.get(&format!("remove_{id}")) == "1";
                (id, value, remove)
            })
            .collect()
    };
    let now = state.clock.now().unix_timestamp();
    if fields.get("forget") == "1" {
        let (user_id, email, lookup) = (user.id, user.email.clone(), slug.clone());
        let forgotten = state
            .db
            .call(move |conn| forget_in(conn, (user_id, &email), &lookup, now))
            .await;
        match forgotten {
            Ok(true) => return redirect("/account"),
            Ok(false) => {}
            Err(err) => return internal_error("stored values", &err),
        }
    }
    let keys = state.keys.clone();
    let (user_id, email, lookup) = (user.id, user.email.clone(), slug.clone());
    let outcome = state
        .db
        .call(move |conn| {
            save_in(
                conn,
                &keys,
                (user_id, &email),
                &lookup,
                session.as_deref(),
                posted,
                now,
            )
        })
        .await;
    match outcome {
        Ok(Outcome::Saved) => redirect(&format!(
            "/account?done=credentials-saved&server={slug}#values-title"
        )),
        Ok(Outcome::Missing) => not_found(),
        Ok(Outcome::Refused(message)) => refused(&state, &form.viewer, &slug, message).await,
        Err(err) => internal_error("stored values", &err),
    }
}

/// Deletes the user's values for a server whose store switch is off, with one `value_removed` row each.
/// False when the switch is on or the user holds none. No key is needed.
fn forget_in(
    conn: &mut Connection,
    (user, email): (i64, &str),
    slug: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let server: Option<i64> = tx
        .query_row(
            "SELECT id FROM servers WHERE slug = ?1 AND store_headers = 0",
            params![slug],
            |row| row.get(0),
        )
        .optional()?;
    let Some(server) = server else {
        return Ok(false);
    };
    let names: Vec<String> = {
        let mut statement = tx.prepare(
            "SELECT h.name FROM user_header_values v JOIN server_headers h ON h.id = v.header_id \
             WHERE v.user_id = ?1 AND h.server_id = ?2 ORDER BY h.id",
        )?;
        statement
            .query_map(params![user, server], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    if names.is_empty() {
        return Ok(false);
    }
    tx.execute(
        "DELETE FROM user_header_values WHERE user_id = ?1 AND header_id IN \
         (SELECT id FROM server_headers WHERE server_id = ?2)",
        params![user, server],
    )?;
    for name in &names {
        let detail = format!("removed header {name}");
        let event = Event {
            kind: "value_removed",
            user_id: Some(user),
            user_email: email,
            server_id: Some(server),
            server_slug: slug,
            detail: &detail,
            ..Default::default()
        };
        audit::record(&tx, now, &event)?;
    }
    tx.execute(
        "UPDATE users SET values_version = values_version + 1 WHERE id = ?1",
        params![user],
    )?;
    tx.execute(
        "DELETE FROM upstream_sessions WHERE server_id = ?1 AND user_id = ?2",
        params![server, user],
    )?;
    tx.commit()?;
    Ok(true)
}

/// One transaction: checks the post, seals each new value under the session's data key and writes it,
/// removes the ticked ones, and ends what ran under the old values.
fn save_in(
    conn: &mut Connection,
    keys: &Keys,
    (user, email): (i64, &str),
    slug: &str,
    session: Option<&str>,
    posted: Vec<(i64, Zeroizing<String>, bool)>,
    now: i64,
) -> rusqlite::Result<Outcome> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let server: Option<(i64, String)> = tx
        .query_row(
            "SELECT s.id, s.upstream_url FROM servers s \
             JOIN user_servers us ON us.server_id = s.id \
             WHERE s.slug = ?1 AND us.user_id = ?2 AND s.store_headers = 1",
            params![slug, user],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((server, address)) = server else {
        return Ok(Outcome::Missing);
    };
    let declared = custom_headers::load(&tx, server)?.declared;
    let mut changes = Vec::new();
    for (id, value, remove) in posted {
        let Some(declared) = declared.iter().find(|declared| declared.id == id) else {
            continue;
        };
        if value.contains(['\r', '\n']) {
            return Ok(Outcome::Refused(BAD_VALUE));
        }
        let trimmed = Zeroizing::new(value.trim_matches([' ', '\t']).to_owned());
        if !trimmed.is_empty() && !custom_headers::valid_value(trimmed.as_bytes()) {
            return Ok(Outcome::Refused(BAD_VALUE));
        }
        if !trimmed.is_empty() && remove {
            return Ok(Outcome::Refused(BOTH));
        }
        if trimmed.is_empty() && !remove {
            continue;
        }
        changes.push(Posted {
            header: id,
            name: declared.name.clone(),
            lower: declared.lower.clone(),
            value: trimmed,
            remove,
        });
    }
    let Some(token) = session else {
        return Ok(Outcome::Refused(LOCKED));
    };
    let Some(key) = keys::open_row(&tx, keys, user, Table::Sessions, &token_hash(token), token)?
    else {
        return Ok(Outcome::Refused(LOCKED));
    };
    let generation: i64 = tx.query_row(
        "SELECT dek_gen FROM users WHERE id = ?1",
        params![user],
        |row| row.get(0),
    )?;
    let mut changed = false;
    for change in &changes {
        let (kind, verb) = if change.remove {
            let removed = tx.execute(
                "DELETE FROM user_header_values WHERE user_id = ?1 AND header_id = ?2",
                params![user, change.header],
            )?;
            if removed == 0 {
                continue;
            }
            ("value_removed", "removed")
        } else {
            let place = ValuePlace {
                user,
                server,
                header: &change.lower,
                generation,
                upstream_url: &address,
            };
            let Ok(sealed) = seal_value(&key, &place, change.value.as_bytes()) else {
                return Ok(Outcome::Refused(LOCKED));
            };
            tx.execute(
                "INSERT INTO user_header_values (user_id, header_id, sealed, set_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (user_id, header_id) \
                 DO UPDATE SET sealed = excluded.sealed, set_at = excluded.set_at",
                params![user, change.header, sealed, now],
            )?;
            ("value_set", "stored")
        };
        changed = true;
        let detail = format!("{verb} header {}", change.name);
        let event = Event {
            kind,
            user_id: Some(user),
            user_email: email,
            server_id: Some(server),
            server_slug: slug,
            detail: &detail,
            ..Default::default()
        };
        audit::record(&tx, now, &event)?;
    }
    if changed {
        tx.execute(
            "UPDATE users SET values_version = values_version + 1 WHERE id = ?1",
            params![user],
        )?;
    }
    if changed {
        tx.execute(
            "DELETE FROM upstream_sessions WHERE server_id = ?1 AND user_id = ?2",
            params![server, user],
        )?;
    }
    tx.commit()?;
    Ok(Outcome::Saved)
}
