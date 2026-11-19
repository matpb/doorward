//! The redirect allowlist page: the entries, the add form, and the last blocked attempts.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::oauth::policy::{self, Entry};
use crate::oauth::uri::{self, Redirect};
use crate::web::{
    SessionUser, VerifiedForm, Viewer, forbidden, form_page, internal_error, not_found, redirect,
};

use super::users::parse_id;

const BLOCKED_LIMIT: i64 = 50;
/// Details are cut to this many characters when stored; a shorter one was not cut.
const DETAIL_LIMIT: usize = 500;
const REFUSED: &str = "The scheme, host and path prefix must form a web address: no http, a plain host name, and a path that is empty only for a private scheme.";

/// One blocked attempt as the page shows it.
struct Blocked {
    client: String,
    detail: String,
}

/// The outcome of an enable or disable, decided inside its transaction.
enum Toggled {
    Done,
    Missing,
}

/// The page with its entries, the add form and the blocked attempts.
pub async fn get_redirects(viewer: Viewer, State(state): State<AppState>) -> Response {
    redirects_page(&state, &viewer, StatusCode::OK, None).await
}

/// Adds an entry, or enables the identical one that exists. A refused address answers 400.
pub async fn post_add(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let scheme = form.fields.get("scheme").to_owned();
    let host = form.fields.get("host").to_owned();
    let path_prefix = form.fields.get("path_prefix").to_owned();
    if !policy::admin_entry_ok(&scheme, &host, &path_prefix) {
        return redirects_page(&state, &form.viewer, StatusCode::BAD_REQUEST, Some(REFUSED)).await;
    }
    let at = state.clock.now().unix_timestamp();
    let written = state
        .db
        .call(move |conn| add_in(conn, &actor, &scheme, &host, &path_prefix, at))
        .await;
    match written {
        Ok(()) => redirect("/admin/redirects"),
        Err(_) => internal_error(),
    }
}

pub async fn post_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    toggle(&state, form, &id, false).await
}

pub async fn post_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    toggle(&state, form, &id, true).await
}

async fn toggle(state: &AppState, form: VerifiedForm, id: &str, enabled: bool) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(id) else {
        return not_found();
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| toggle_in(conn, &actor, id, enabled, at))
        .await
    {
        Ok(Toggled::Done) => redirect("/admin/redirects"),
        Ok(Toggled::Missing) => not_found(),
        Err(_) => internal_error(),
    }
}

/// One transaction: the row is written and the change is recorded.
fn add_in(
    conn: &mut Connection,
    actor: &SessionUser,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    at: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    policy::add(&tx, scheme, host, path_prefix)?;
    let detail = format!("added redirect {}", address_text(scheme, host, path_prefix));
    record(&tx, at, actor, &detail)?;
    tx.commit()
}

/// One transaction: the row must exist; its flag is set and the change is recorded.
fn toggle_in(
    conn: &mut Connection,
    actor: &SessionUser,
    id: i64,
    enabled: bool,
    at: i64,
) -> rusqlite::Result<Toggled> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(row) = policy::entry(&tx, id)? else {
        return Ok(Toggled::Missing);
    };
    policy::set_enabled(&tx, id, enabled)?;
    let verb = if enabled { "enabled" } else { "disabled" };
    let detail = format!(
        "{verb} redirect {}",
        address_text(&row.scheme, &row.host, &row.path_prefix)
    );
    record(&tx, at, actor, &detail)?;
    tx.commit()?;
    Ok(Toggled::Done)
}

/// Writes one admin_change row inside the caller's transaction.
fn record(conn: &Connection, at: i64, actor: &SessionUser, detail: &str) -> rusqlite::Result<()> {
    let change = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        detail,
        ..Default::default()
    };
    audit::record(conn, at, &change)
}

/// The last blocked attempts, newest first.
fn blocked_rows(conn: &Connection) -> rusqlite::Result<Vec<Blocked>> {
    let mut statement = conn.prepare(
        "SELECT client, detail FROM activity WHERE kind = 'redirect_blocked' \
         ORDER BY at DESC, id DESC LIMIT ?1",
    )?;
    let rows = statement.query_map(params![BLOCKED_LIMIT], |row| {
        Ok(Blocked {
            client: row.get(0)?,
            detail: row.get(1)?,
        })
    })?;
    rows.collect()
}

async fn redirects_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    refused: Option<&str>,
) -> Response {
    let loaded = state
        .db
        .call(|conn| Ok((policy::list(conn)?, blocked_rows(conn)?)))
        .await;
    match loaded {
        Ok((entries, blocked)) => form_page(viewer, status, "redirects", "Redirects", |csrf| {
            redirects_body(csrf, &entries, &blocked, refused)
        }),
        Err(_) => internal_error(),
    }
}

fn redirects_body(
    csrf: &str,
    entries: &[Entry],
    blocked: &[Blocked],
    refused: Option<&str>,
) -> Markup {
    html! {
        h1 { "Redirects" }
        p { "Web addresses that clients may send a code to. Loopback addresses are always allowed." }
        @if let Some(message) = refused {
            p.error { (message) }
        }
        h2 { "Allowed addresses" }
        ul.redirects {
            @for entry in entries {
                li data-redirect-id=(entry.id) data-scheme=(entry.scheme) data-host=(entry.host)
                    data-path-prefix=(entry.path_prefix) data-source=(entry.source)
                    data-enabled=(yes_or_no(entry.enabled)) {
                    p { (address_text(&entry.scheme, &entry.host, &entry.path_prefix)) }
                    p { (entry.source) " " (if entry.enabled { "enabled" } else { "disabled" }) }
                    form method="post" action=(toggle_action(entry)) {
                        input type="hidden" name="csrf" value=(csrf);
                        button type="submit" {
                            @if entry.enabled { "Disable" } @else { "Enable" }
                        }
                    }
                }
            }
        }
        h2 { "Add an address" }
        form method="post" action="/admin/redirects" {
            input type="hidden" name="csrf" value=(csrf);
            label for="redirect-scheme" { "Scheme" }
            input id="redirect-scheme" name="scheme" type="text" required;
            label for="redirect-host" { "Host" }
            input id="redirect-host" name="host" type="text" required;
            label for="redirect-path" { "Path prefix (ending in / covers everything under it)" }
            input id="redirect-path" name="path_prefix" type="text";
            button type="submit" { "Add address" }
        }
        h2 { "Blocked attempts" }
        ol.blocked {
            @for row in blocked {
                li data-blocked="yes" {
                    p { "Asked by a client that calls itself " q { (row.client) } }
                    p { (row.detail) }
                    @if let Some(allow) = one_click(&row.detail) {
                        form method="post" action="/admin/redirects" {
                            input type="hidden" name="csrf" value=(csrf);
                            input type="hidden" name="scheme" value=(allow.scheme);
                            input type="hidden" name="host" value=(allow.host);
                            input type="hidden" name="path_prefix" value=(allow.path);
                            button type="submit" { "Allow this address" }
                        }
                    }
                }
            }
        }
    }
}

/// The parts of a blocked attempt that one click may allow.
struct Allow<'a> {
    scheme: &'a str,
    host: &'a str,
    path: &'a str,
}

/// Only for a stored detail that was not cut, that is a web address, and whose path is not a subtree.
fn one_click(detail: &str) -> Option<Allow<'_>> {
    if detail.chars().count() >= DETAIL_LIMIT {
        return None;
    }
    match uri::parse(detail)? {
        Redirect::Web { scheme, host, path } if !path.ends_with('/') => {
            Some(Allow { scheme, host, path })
        }
        _ => None,
    }
}

fn address_text(scheme: &str, host: &str, path_prefix: &str) -> String {
    format!("{scheme}://{host}{path_prefix}")
}

fn toggle_action(entry: &Entry) -> String {
    let verb = if entry.enabled { "disable" } else { "enable" };
    format!("/admin/redirects/{}/{verb}", entry.id)
}

fn yes_or_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}
