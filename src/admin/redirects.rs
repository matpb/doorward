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

/// The three parts of a refused add form, shown again as the person posted them.
struct Typed {
    scheme: String,
    host: String,
    path_prefix: String,
}

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
    redirects_page(&state, &viewer, StatusCode::OK, None, None).await
}

/// Adds an entry, or enables the identical one that exists. A refused address answers 400, with the parts shown again.
pub async fn post_add(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let scheme = form.fields.get("scheme").to_owned();
    let host = form.fields.get("host").to_owned();
    let path_prefix = form.fields.get("path_prefix").to_owned();
    if !policy::admin_entry_ok(&scheme, &host, &path_prefix) {
        let typed = Typed {
            scheme: ui::sent_back(&scheme, ui::SENT_BACK_LIMIT),
            host: ui::sent_back(&host, ui::SENT_BACK_LIMIT),
            path_prefix: ui::sent_back(&path_prefix, ui::SENT_BACK_LIMIT),
        };
        return redirects_page(
            &state,
            &form.viewer,
            StatusCode::BAD_REQUEST,
            Some(REFUSED),
            Some(typed),
        )
        .await;
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

/// The redirects page; `typed` is the address of a refused add form, shown again.
async fn redirects_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    refused: Option<&str>,
    typed: Option<Typed>,
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
                    (redirects_body(csrf, &entries, &blocked, refused, typed.as_ref()))
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
    typed: Option<&Typed>,
) -> Markup {
    let scheme = typed.map(|typed| typed.scheme.as_str());
    let host = typed.map(|typed| typed.host.as_str());
    let path = typed.map(|typed| typed.path_prefix.as_str());
    let path_note = ui::note_under(None, Some("Ending in / covers everything under it."));
    let path_described = path_note.describer("redirect-path");
    html! {
        div.page-head {
            h1 { "Redirects" }
            p.lede { "Web addresses that clients may send a code to. Loopback addresses are always allowed." }
            div.head-actions {
                a.button data-kind="secondary" href="#add" { "Add an address" }
            }
        }
        @if let Some(message) = refused {
            (ui::refused(Some("The address was not added."), message, None))
        }
        section aria-labelledby="allowed-title" {
            div.block-head {
                h2 id="allowed-title" { "Allowed addresses" }
            }
            table.list.redirects {
                thead {
                    tr {
                        th scope="col" { "Address" }
                        th scope="col" class="c-source" { "Source" }
                        th scope="col" class="c-state" { "State" }
                        th scope="col" class="c-act" aria-label="Actions" {}
                    }
                }
                tbody {
                    @for entry in entries {
                        (entry_row(csrf, entry))
                    }
                }
            }
        }
        section.block aria-labelledby="blocked-title" {
            div.block-head {
                h2 id="blocked-title" { "Blocked attempts" }
            }
            @if blocked.is_empty() {
                p.muted { "No blocked attempts." }
            } @else {
                table.list.blocked {
                    thead {
                        tr {
                            th scope="col" { "Address" }
                            th scope="col" class="c-client" { "Asked by a client that calls itself" }
                            th scope="col" class="c-act" aria-label="Actions" {}
                        }
                    }
                    tbody {
                        @for row in blocked {
                            (blocked_row(csrf, row))
                        }
                    }
                }
            }
        }
        section.part id="add" aria-labelledby="add-title" {
            div.part-head {
                h2 id="add-title" { "Add an address" }
                p { "A scheme, a host and the start of a path. Clients may be sent to anything that begins with it." }
            }
            div.part-body {
                form.flow method="post" action="/admin/redirects" {
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields data-cols="1-2" {
                        (ui::field(
                            "redirect-scheme",
                            "Scheme",
                            false,
                            html! { input.mono id="redirect-scheme" name="scheme" type="text" required value=[scheme]; },
                            ui::Note::None,
                        ))
                        (ui::field(
                            "redirect-host",
                            "Host",
                            false,
                            html! { input.mono id="redirect-host" name="host" type="text" required value=[host]; },
                            ui::Note::None,
                        ))
                    }
                    div.fields {
                        (ui::field(
                            "redirect-path",
                            "Path prefix",
                            false,
                            html! {
                                input.mono id="redirect-path" name="path_prefix" type="text" value=[path] aria-describedby=[path_described.as_deref()];
                            },
                            path_note,
                        ))
                    }
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Add address" }
                    }
                }
            }
        }
    }
}

/// One allowed address: the address, its source, whether it is enabled, and its enable or disable button.
fn entry_row(csrf: &str, entry: &Entry) -> Markup {
    html! {
        tr data-redirect-id=(entry.id) data-scheme=(entry.scheme) data-host=(entry.host)
            data-path-prefix=(entry.path_prefix) data-source=(entry.source)
            data-enabled=(yes_or_no(entry.enabled)) {
            td.lead {
                code { (ui::breakable(&address_text(&entry.scheme, &entry.host, &entry.path_prefix))) }
            }
            td.half { (entry.source) }
            td.half { (enabled_pill(entry.enabled)) }
            td.act {
                form method="post" action=(toggle_action(entry)) {
                    input type="hidden" name="csrf" value=(csrf);
                    button.row-action type="submit" data-kind="secondary" {
                        @if entry.enabled { "Disable" } @else { "Enable" }
                    }
                }
            }
        }
    }
}

/// One blocked attempt: the address, the client that asked, and the one-click allow or the reason
/// there is none.
fn blocked_row(csrf: &str, row: &Blocked) -> Markup {
    html! {
        tr data-blocked="yes" {
            td.lead {
                code { (ui::breakable(&row.detail)) }
            }
            td {
                span.unit { "asked by a client that calls itself " }
                q { (row.client) }
            }
            @if let Some(allow) = one_click(&row.detail) {
                td.act {
                    form method="post" action="/admin/redirects" {
                        input type="hidden" name="csrf" value=(csrf);
                        input type="hidden" name="scheme" value=(allow.scheme);
                        input type="hidden" name="host" value=(allow.host);
                        input type="hidden" name="path_prefix" value=(allow.path);
                        button.row-action type="submit" data-kind="secondary" { "Allow this address" }
                    }
                }
            } @else {
                td.act.reason {
                    span.sub { (unallowed_reason(&row.detail)) }
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

/// Why a blocked attempt has no one-click allow: plain http is never allowed, every other case
/// is one to add by hand. A detail that `one_click` accepts never reaches this.
fn unallowed_reason(detail: &str) -> &'static str {
    match detail.split_once("://") {
        Some(("http", _)) => "Plain http cannot be allowed.",
        _ => "Add it by hand below.",
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
