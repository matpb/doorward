//! The servers pages: the list, adding, one server, its settings, deleting, and its users.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{CryptoError, Keys};
use crate::db::DbError;
use crate::oauth::families;
use crate::proxy::catalog::{self, RefreshError};
use crate::proxy::upstream::{self, TargetError};
use crate::servers::{
    self, Draft, Refusal, Scope, SecretChange, Server, ServerRef, Settings, UserChoice,
};
use crate::web::{
    FormFields, MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page, form_page_with,
    internal_error, not_found, redirect,
};

use super::panel_nav;
use super::users::parse_id;

/// The outcome of a create, decided inside its transaction.
enum Created {
    Saved(i64),
    Taken,
}

/// The outcome of an update, decided inside its transaction.
enum Changed {
    Saved,
    Taken,
    Missing,
}

enum Deleted {
    Done,
    Missing,
}

/// The outcome of replacing a server's users, decided inside its transaction.
enum Assigned {
    Saved,
    Missing,
    BadValue,
}

pub async fn get_servers(viewer: Viewer, State(state): State<AppState>) -> Response {
    servers_page(&state, &viewer, StatusCode::OK, &Draft::default(), None).await
}

pub async fn post_server(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let draft = draft_from(&form.fields);
    let settings = match servers::check(&draft) {
        Ok(settings) => settings,
        Err(refusal) => {
            return servers_page(
                &state,
                &form.viewer,
                StatusCode::BAD_REQUEST,
                &draft,
                Some(refusal),
            )
            .await;
        }
    };
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let at = state.clock.now().unix_timestamp();
    let keys = Arc::clone(&state.keys);
    match state
        .db
        .call(move |conn| create_in(conn, &keys, &settings, &actor, at))
        .await
    {
        Ok(Ok(Created::Saved(id))) => redirect(&format!("/admin/servers/{id}")),
        Ok(Ok(Created::Taken)) => {
            servers_page(
                &state,
                &form.viewer,
                StatusCode::BAD_REQUEST,
                &draft,
                Some(Refusal::Taken),
            )
            .await
        }
        Ok(Err(err)) => internal_error("server save", &err),
        Err(err) => internal_error("server save", &err),
    }
}

pub async fn get_server(
    viewer: Viewer,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    match load(&state, id).await {
        Ok(Some(server)) => {
            let draft = draft_of(&server);
            server_page(&state, &viewer, StatusCode::OK, &server, &draft, None).await
        }
        Ok(None) => not_found(),
        Err(err) => internal_error("server page", &err),
    }
}

pub async fn post_update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let stored = match load(&state, id).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(),
        Err(err) => return internal_error("server save", &err),
    };
    let draft = draft_from(&form.fields);
    let remove = form.fields.get("remove_secret") == "on";
    let settings = match servers::check(&draft) {
        Ok(settings) => settings,
        Err(refusal) => {
            return server_page(
                &state,
                &form.viewer,
                StatusCode::BAD_REQUEST,
                &stored,
                &draft,
                Some(refusal),
            )
            .await;
        }
    };
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let at = state.clock.now().unix_timestamp();
    let keys = Arc::clone(&state.keys);
    match state
        .db
        .call(move |conn| update_in(conn, &keys, id, &settings, remove, &actor, at))
        .await
    {
        Ok(Ok(Changed::Saved)) => redirect(&format!("/admin/servers/{id}")),
        Ok(Ok(Changed::Taken)) => {
            server_page(
                &state,
                &form.viewer,
                StatusCode::BAD_REQUEST,
                &stored,
                &draft,
                Some(Refusal::Taken),
            )
            .await
        }
        Ok(Ok(Changed::Missing)) => not_found(),
        Ok(Err(err)) => internal_error("server save", &err),
        Err(err) => internal_error("server save", &err),
    }
}

pub async fn post_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| delete_in(conn, id, &actor, at))
        .await
    {
        Ok(Deleted::Done) => redirect("/admin/servers"),
        Ok(Deleted::Missing) => not_found(),
        Err(err) => internal_error("server delete", &err),
    }
}

/// Replaces the server's users with the posted set. An unknown user id is refused with 400.
pub async fn post_users(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let ids = parse_ids(&form.fields.all("user_id"));
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| assign_users_in(conn, id, ids, &actor, at))
        .await
    {
        Ok(Assigned::Saved) => redirect(&format!("/admin/servers/{id}")),
        Ok(Assigned::Missing) => not_found(),
        Ok(Assigned::BadValue) => assignment_refused(&state, &form.viewer, id).await,
        Err(err) => internal_error("server assignment", &err),
    }
}

/// The ids of a repeated field, or None when one of them is not an id.
fn parse_ids(values: &[&str]) -> Option<Vec<i64>> {
    values.iter().map(|value| parse_id(value)).collect()
}

/// The draft a form posted. A missing field is empty and a missing checkbox is off.
fn draft_from(fields: &FormFields) -> Draft {
    Draft {
        name: fields.get("name").to_owned(),
        slug: fields.get("slug").to_owned(),
        upstream_url: fields.get("upstream_url").to_owned(),
        secret_header_name: fields.get("secret_header_name").to_owned(),
        secret_header_value: fields.get("secret_header_value").to_owned(),
        pass_resources: fields.get("pass_resources") == "on",
        pass_prompts: fields.get("pass_prompts") == "on",
    }
}

/// The draft of a stored server. The secret value is never part of a draft.
fn draft_of(server: &Server) -> Draft {
    Draft {
        name: server.name.clone(),
        slug: server.slug.clone(),
        upstream_url: server.upstream_url.clone(),
        secret_header_name: server.secret_header_name.clone(),
        secret_header_value: String::new(),
        pass_resources: server.pass_resources,
        pass_prompts: server.pass_prompts,
    }
}

async fn load(state: &AppState, id: i64) -> Result<Option<Server>, DbError> {
    state.db.call(move |conn| servers::load(conn, id)).await
}

/// One transaction: the path is taken or the server is written with its secret and its row.
fn create_in(
    conn: &mut Connection,
    keys: &Keys,
    settings: &Settings,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Result<Created, CryptoError>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(id) = servers::insert(&tx, settings, at)? else {
        return Ok(Ok(Created::Taken));
    };
    if let Some(secret) = &settings.secret {
        let sealed = match servers::seal(keys, id, &secret.value) {
            Ok(sealed) => sealed,
            Err(err) => return Ok(Err(err)),
        };
        servers::set_secret(&tx, id, &secret.header_name, Some(&sealed))?;
    }
    let detail = format!("added server {}", settings.slug);
    record(&tx, at, actor, Some(id), &settings.slug, &detail)?;
    tx.commit()?;
    Ok(Ok(Created::Saved(id)))
}

/// One transaction: the row, then the secret as the posted values and the address decide it.
fn update_in(
    conn: &mut Connection,
    keys: &Keys,
    id: i64,
    settings: &Settings,
    remove: bool,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Result<Changed, CryptoError>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(stored) = servers::load(&tx, id)? else {
        return Ok(Ok(Changed::Missing));
    };
    let lockdown = if stored.upstream_url == settings.upstream_url {
        stored.lockdown
    } else {
        "unknown".to_owned()
    };
    if !servers::update(&tx, id, settings, &lockdown)? {
        return Ok(Ok(Changed::Taken));
    }
    if stored.slug != settings.slug {
        families::revoke_server(&tx, id, &stored.slug, at)?;
    }
    match servers::secret_change(&stored.upstream_url, settings, remove) {
        SecretChange::Keep => {}
        SecretChange::Drop => servers::set_secret(&tx, id, "", None)?,
        SecretChange::Replace(secret) => {
            let sealed = match servers::seal(keys, id, &secret.value) {
                Ok(sealed) => sealed,
                Err(err) => return Ok(Err(err)),
            };
            servers::set_secret(&tx, id, &secret.header_name, Some(&sealed))?;
        }
    }
    let detail = format!("updated server {}", settings.slug);
    record(&tx, at, actor, Some(id), &settings.slug, &detail)?;
    tx.commit()?;
    Ok(Ok(Changed::Saved))
}

/// One transaction: the row goes, its assignments with it, and the deletion is recorded.
fn delete_in(
    conn: &mut Connection,
    id: i64,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Deleted> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(server) = servers::load(&tx, id)? else {
        return Ok(Deleted::Missing);
    };
    servers::delete(&tx, id)?;
    let detail = format!("deleted server {}", server.slug);
    record(&tx, at, actor, Some(id), &server.slug, &detail)?;
    tx.commit()?;
    Ok(Deleted::Done)
}

/// One transaction: every posted user must exist; the server's users become exactly that set.
fn assign_users_in(
    conn: &mut Connection,
    id: i64,
    ids: Option<Vec<i64>>,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Assigned> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(server) = servers::load(&tx, id)? else {
        return Ok(Assigned::Missing);
    };
    let Some(mut ids) = ids else {
        return Ok(Assigned::BadValue);
    };
    for user_id in &ids {
        if !servers::user_exists(&tx, *user_id)? {
            return Ok(Assigned::BadValue);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    for (user_id, server_id) in servers::set_assignments(&tx, Scope::Server(id), &ids)? {
        families::revoke_pair(&tx, user_id, server_id, at)?;
    }
    let detail = format!("assignments of {} set to {} users", server.slug, ids.len());
    record(&tx, at, actor, Some(id), &server.slug, &detail)?;
    tx.commit()?;
    Ok(Assigned::Saved)
}

/// Writes one admin_change row for a server inside the caller's transaction.
fn record(
    tx: &Transaction<'_>,
    at: i64,
    actor: &SessionUser,
    server_id: Option<i64>,
    slug: &str,
    detail: &str,
) -> rusqlite::Result<()> {
    let change = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        server_id,
        server_slug: slug,
        detail,
        ..Default::default()
    };
    audit::record(tx, at, &change)
}

/// The server page again, with the error, after a refused user choice.
async fn assignment_refused(state: &AppState, viewer: &Viewer, id: i64) -> Response {
    match load(state, id).await {
        Ok(Some(server)) => {
            let draft = draft_of(&server);
            server_page(
                state,
                viewer,
                StatusCode::BAD_REQUEST,
                &server,
                &draft,
                Some(Refusal::UnknownUser),
            )
            .await
        }
        Ok(None) => not_found(),
        Err(err) => internal_error("server page", &err),
    }
}

/// The list page, with the create form filled from `draft`.
async fn servers_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    draft: &Draft,
    refusal: Option<Refusal>,
) -> Response {
    match state.db.call(|conn| servers::list(conn)).await {
        Ok(rows) => {
            let nav = panel_nav(viewer, "/admin/servers");
            form_page(viewer, status, "servers", "Servers", |csrf| {
                html! {
                    (nav)
                    (servers_body(csrf, &rows, draft, refusal))
                }
            })
        }
        Err(err) => internal_error("servers page", &err),
    }
}

/// One server's page: its settings, its users and its delete form.
async fn server_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    server: &Server,
    draft: &Draft,
    refusal: Option<Refusal>,
) -> Response {
    let id = server.id;
    match state
        .db
        .call(move |conn| {
            let users = servers::user_choices(conn, id)?;
            let tools = catalog::names(conn, id)?;
            Ok((users, tools))
        })
        .await
    {
        Ok((users, tools)) => {
            let data = MainData {
                lockdown: Some(&server.lockdown),
                ..MainData::default()
            };
            let nav = panel_nav(viewer, "/admin/servers");
            form_page_with(viewer, status, "server", "Server", &data, |csrf| {
                html! {
                    (nav)
                    (server_body(csrf, server, draft, &users, &tools, refusal))
                }
            })
        }
        Err(err) => internal_error("server page", &err),
    }
}

/// Refreshes the tool list. A failure is recorded and still answers 303 to the server page.
pub async fn post_refresh_tools(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let server = match load(&state, id).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(),
        Err(err) => return internal_error("tool refresh", &err),
    };
    let outcome = match upstream::target(&state, id).await {
        Ok(Some(target)) => catalog::refresh(&state, &target).await.map(|_| ()),
        Ok(None) => return not_found(),
        Err(TargetError::Secret) => catalog::fail(&state, id, RefreshError::Unavailable).await,
        Err(TargetError::Db(err)) => return internal_error("tool refresh", &err),
    };
    let detail = match outcome {
        Ok(()) => "tools refreshed",
        Err(RefreshError::Db) => {
            return internal_error("tool refresh", &"the tool catalog cannot be stored");
        }
        Err(_) => "tool refresh failed",
    };
    match record_change(&state, &actor, id, &server.slug, detail).await {
        Ok(()) => redirect(&format!("/admin/servers/{id}")),
        Err(err) => internal_error("tool refresh record", &err),
    }
}

/// Probes the upstream without the secret, stores the verdict and answers 303 to the server page.
pub async fn post_check_lockdown(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let server = match load(&state, id).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(),
        Err(err) => return internal_error("lockdown check", &err),
    };
    // The probe carries no secret, so the stored secret is not opened for it.
    let probed_url = server.upstream_url;
    let probe = upstream::Target {
        server_id: id,
        slug: server.slug,
        url: probed_url.clone(),
        secret: None,
    };
    let verdict = catalog::lockdown(&state, &probe).await;
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| store_lockdown(conn, id, verdict, &probed_url, &actor, at))
        .await
    {
        Ok(Stored::Missing) => not_found(),
        Ok(_) => redirect(&format!("/admin/servers/{id}")),
        Err(err) => internal_error("lockdown check", &err),
    }
}

/// The outcome of storing a probe result.
pub(super) enum Stored {
    Saved,
    /// The address changed during the probe, so the result belongs to another address.
    Changed,
    Missing,
}

/// One transaction: stores the verdict and its admin_change row while `url` is still the address.
/// Otherwise nothing is written, and a server that is gone is Missing.
pub(super) fn store_lockdown(
    conn: &mut Connection,
    id: i64,
    verdict: &str,
    url: &str,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Stored> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let slug: Option<String> = tx
        .query_row(
            "SELECT slug FROM servers WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(slug) = slug else {
        return Ok(Stored::Missing);
    };
    let updated = tx.execute(
        "UPDATE servers SET lockdown = ?1 WHERE id = ?2 AND upstream_url = ?3",
        params![verdict, id, url],
    )?;
    if updated == 0 {
        return Ok(Stored::Changed);
    }
    let detail = format!("lock-down checked: {verdict}");
    record(&tx, at, actor, Some(id), &slug, &detail)?;
    tx.commit()?;
    Ok(Stored::Saved)
}

/// What the stored lock-down result means, in words.
fn lockdown_note(verdict: &str) -> &'static str {
    match verdict {
        "ok" => "The upstream refused a request without the secret.",
        "open" => {
            "The upstream answered a request without the secret: anyone who can reach its address can use it."
        }
        _ => "Not checked yet, or the upstream did not answer the check.",
    }
}

/// Writes one admin_change row for a server in its own transaction.
async fn record_change(
    state: &AppState,
    actor: &SessionUser,
    server_id: i64,
    slug: &str,
    detail: &str,
) -> Result<(), DbError> {
    let at = state.clock.now().unix_timestamp();
    let actor = actor.clone();
    let slug = slug.to_owned();
    let detail = detail.to_owned();
    state
        .db
        .call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            record(&tx, at, &actor, Some(server_id), &slug, &detail)?;
            tx.commit()
        })
        .await
}

fn servers_body(csrf: &str, rows: &[ServerRef], draft: &Draft, refusal: Option<Refusal>) -> Markup {
    html! {
        h1 { "Servers" }
        @if let Some(refusal) = refusal {
            p.error { (refusal) }
        }
        @if rows.is_empty() {
            p { "No servers yet." }
        }
        ul.servers {
            @for row in rows {
                li data-server-id=(row.id) data-slug=(row.slug) {
                    p { a href=(format!("/admin/servers/{}", row.id)) { (row.name) } }
                    p { (row.slug) }
                }
            }
        }
        h2 { "Add a server" }
        form method="post" action="/admin/servers" {
            input type="hidden" name="csrf" value=(csrf);
            (fields(draft, "Secret header value (optional)"))
            button type="submit" { "Add server" }
        }
    }
}

fn server_body(
    csrf: &str,
    server: &Server,
    draft: &Draft,
    users: &[UserChoice],
    tools: &[String],
    refusal: Option<Refusal>,
) -> Markup {
    let path = format!("/admin/servers/{}", server.id);
    let note = lockdown_note(&server.lockdown);
    html! {
        h1 { (server.name) }
        p { "Path: " (server.slug) }
        p {
            a href=(format!("/admin/activity?server={}", server.id)) data-link="activity" { "Activity" }
        }
        @if let Some(refusal) = refusal {
            p.error { (refusal) }
        }
        @if let Some(message) = &server.catalog_error {
            p.error { (message) }
        }
        form method="post" action=(path) {
            input type="hidden" name="csrf" value=(csrf);
            (fields(draft, "Secret header value (empty keeps the stored one)"))
            @if server.has_secret {
                p { "A secret is stored. Its value is never shown again." }
                label {
                    input type="checkbox" name="remove_secret";
                    " Remove the stored secret"
                }
            }
            button type="submit" { "Save server" }
        }
        h2 { "Tools" }
        @if tools.is_empty() {
            p { "No tools yet. Refresh the list to fetch them from the upstream." }
        }
        ul.catalog {
            @for tool in tools {
                li data-catalog-tool=(tool) { (tool) }
            }
        }
        form method="post" action=(format!("{path}/refresh-tools")) {
            input type="hidden" name="csrf" value=(csrf);
            button type="submit" { "Refresh tools" }
        }
        h2 { "Lock-down" }
        p data-lockdown-note=(note) { (note) }
        form method="post" action=(format!("{path}/check-lockdown")) {
            input type="hidden" name="csrf" value=(csrf);
            button type="submit" { "Check lock-down" }
        }
        h2 { "Users" }
        p {
            "Every user reaches this server under the same identity, so anything the server caches or remembers per caller is shared."
        }
        form method="post" action=(format!("{path}/users")) {
            input type="hidden" name="csrf" value=(csrf);
            @for user in users {
                label {
                    input type="checkbox" name="user_id" value=(user.id) checked[user.assigned];
                    " " (user.email)
                }
            }
            button type="submit" { "Save users" }
        }
        h2 { "Delete" }
        form method="post" action=(format!("{path}/delete")) {
            input type="hidden" name="csrf" value=(csrf);
            button type="submit" { "Delete server" }
        }
    }
}

/// The settings inputs of the create and the edit form. The secret value is never filled in.
fn fields(draft: &Draft, value_hint: &str) -> Markup {
    html! {
        label for="server-name" { "Name" }
        input id="server-name" name="name" type="text" value=(draft.name) required;
        label for="server-slug" { "Path (letters, digits and hyphens, at most 24 characters)" }
        input id="server-slug" name="slug" type="text" value=(draft.slug) required;
        label for="server-url" { "Upstream address (http or https)" }
        input id="server-url" name="upstream_url" type="url" value=(draft.upstream_url) required;
        label for="secret-name" { "Secret header name (optional)" }
        input id="secret-name" name="secret_header_name" type="text" value=(draft.secret_header_name);
        label for="secret-value" { (value_hint) }
        input id="secret-value" name="secret_header_value" type="password" autocomplete="new-password";
        label {
            input type="checkbox" name="pass_resources" checked[draft.pass_resources];
            " Pass resources to the upstream (off: empty list)"
        }
        label {
            input type="checkbox" name="pass_prompts" checked[draft.pass_prompts];
            " Pass prompts to the upstream (off: empty list)"
        }
    }
}
