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
    MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with, internal_error,
    not_found, redirect, ui,
};

use super::panel_nav;
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
        Err(err) => internal_error("redirect add", &err),
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
        Err(err) => internal_error("redirect change", &err),
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
        Ok((entries, blocked)) => {
            let data = MainData {
                nav: panel_nav(viewer, "/admin/redirects"),
                ..MainData::default()
            };
            form_page_with(viewer, status, "redirects", "Redirects", &data, |csrf| {
                html! {
                    (redirects_body(csrf, &entries, &blocked, refused))
                }
            })
        }
        Err(err) => internal_error("redirects page", &err),
    }
}

fn redirects_body(
    csrf: &str,
    entries: &[Entry],
    blocked: &[Blocked],
    refused: Option<&str>,
) -> Markup {
    html! {
        div.stack {
            h1 { "Redirects" }
            p.lede { "Web addresses that clients may send a code to. Loopback addresses are always allowed." }
            @if let Some(message) = refused {
                p.error { (message) }
            }
            div.split {
                section.card.main {
                    h2 { "Allowed addresses" }
                    ul.redirects.rows {
                        @for entry in entries {
                            li data-redirect-id=(entry.id) data-scheme=(entry.scheme) data-host=(entry.host)
                                data-path-prefix=(entry.path_prefix) data-source=(entry.source)
                                data-enabled=(yes_or_no(entry.enabled)) {
                                div.row-main {
                                    code { (address_text(&entry.scheme, &entry.host, &entry.path_prefix)) }
                                    p.row-meta { (entry.source) }
                                }
                                div.row-actions {
                                    (enabled_pill(entry.enabled))
                                    form method="post" action=(toggle_action(entry)) {
                                        input type="hidden" name="csrf" value=(csrf);
                                        button type="submit" data-kind="secondary" {
                                            @if entry.enabled { "Disable" } @else { "Enable" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                form.card.side method="post" action="/admin/redirects" {
                    h2 { "Add an address" }
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields {
                        div {
                            label for="redirect-scheme" { "Scheme" }
                            input id="redirect-scheme" name="scheme" type="text" required;
                        }
                        div {
                            label for="redirect-host" { "Host" }
                            input id="redirect-host" name="host" type="text" required;
                        }
                        div {
                            label for="redirect-path" { "Path prefix (ending in / covers everything under it)" }
                            input id="redirect-path" name="path_prefix" type="text";
                        }
                    }
                    button type="submit" data-kind="primary" { "Add address" }
                }
            }
            section.card {
                h2 { "Blocked attempts" }
                @if blocked.is_empty() {
                    p.muted { "No blocked attempts." }
                }
                ol.blocked.rows {
                    @for row in blocked {
                        li data-blocked="yes" {
                            div.row-main {
                                p.row-meta { "Asked by a client that calls itself " q { (row.client) } }
                                code { (row.detail) }
                            }
                            @if let Some(allow) = one_click(&row.detail) {
                                div.row-actions {
                                    form method="post" action="/admin/redirects" {
                                        input type="hidden" name="csrf" value=(csrf);
                                        input type="hidden" name="scheme" value=(allow.scheme);
                                        input type="hidden" name="host" value=(allow.host);
                                        input type="hidden" name="path_prefix" value=(allow.path);
                                        button type="submit" data-kind="secondary" { "Allow this address" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Whether an allowed address is enabled, as a pill: Enabled in ok, Disabled in muted.
fn enabled_pill(enabled: bool) -> Markup {
    if enabled {
        ui::pill("ok", "Enabled")
    } else {
        ui::pill("muted", "Disabled")
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
