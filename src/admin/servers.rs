//! The servers pages: the list, adding, one server, its settings, deleting, and its users.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use form_urlencoded::Serializer;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{CryptoError, Keys};
use crate::custom_headers::{self, AddRefusal, Declared, MAX_PER_SERVER, ServerHeaders};
use crate::db::DbError;
use crate::oauth::families;
use crate::proxy::catalog::{self, RefreshError};
use crate::proxy::upstream::{self, TargetError};
use crate::proxy::values::{self, Via};
use crate::servers::{self, Draft, Refusal, Scope, SecretChange, Server, Settings, UserChoice};
use crate::vault::keys;
use crate::web::{
    FormFields, MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with,
    internal_error, not_found, redirect, ui,
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
    /// The secret header name is a declared header of the server.
    SecretDeclared,
    Missing,
}

enum Deleted {
    Done,
    Missing,
}

/// The outcome of a header change, decided inside its transaction.
enum HeaderChange {
    /// The new header's id.
    Saved(i64),
    Refused(AddRefusal),
    Missing,
}

/// The outcome of a removal: the removed header's name as declared.
enum Removed {
    Done(String),
    Missing,
}

/// The outcome of saving the switches: the headers that the save made required.
enum Switched {
    Saved(Vec<i64>),
    Missing,
}

/// A step a redirect says was done, as the query of the server page names it.
#[derive(Debug, PartialEq)]
enum Done {
    /// A header was added: its id.
    HeaderAdded(i64),
    /// A header was removed: its name as declared.
    HeaderRemoved(String),
    /// The headers were saved: the ids of the headers the save made required.
    HeadersSaved(Vec<i64>),
    /// The tool list was refreshed without the admin's stored values, which the session cannot open.
    RefreshedWithoutValues,
}

/// The add-header form as the page shows it: the name as sent back, whether it is required, and its refusal.
#[derive(Default)]
struct HeaderForm {
    name: String,
    required: bool,
    refusal: Option<AddRefusal>,
}

/// Where a step's notice shows: under the page title, or first in the part it reports on.
#[derive(Clone, Copy)]
enum Place {
    Title,
    Headers,
}

/// What a server page shows besides the server: the settings draft, its refusal, the header form,
/// and the notice of a step the redirect says was done, with the place it shows.
struct Shown<'a> {
    draft: &'a Draft,
    refusal: Option<Refusal>,
    secret_sent: bool,
    header: HeaderForm,
    done: Option<(Place, Markup)>,
}

impl<'a> Shown<'a> {
    fn plain(draft: &'a Draft) -> Self {
        Shown {
            draft,
            refusal: None,
            secret_sent: false,
            header: HeaderForm::default(),
            done: None,
        }
    }
}

/// The outcome of replacing a server's users, decided inside its transaction.
enum Assigned {
    Saved,
    Missing,
    BadValue,
}

pub async fn get_servers(viewer: Viewer, State(state): State<AppState>) -> Response {
    servers_page(
        &state,
        &viewer,
        StatusCode::OK,
        &Draft::default(),
        None,
        false,
    )
    .await
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
                &sent_back_draft(&draft),
                Some(refusal),
                secret_sent(&draft),
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
                &sent_back_draft(&draft),
                Some(Refusal::Taken),
                secret_sent(&draft),
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
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    match load(&state, id).await {
        Ok(Some(server)) => {
            let draft = draft_of(&server);
            let done = match done_for(&state, id, raw.as_deref()).await {
                Ok(done) => done,
                Err(err) => return internal_error("server page", &err),
            };
            let shown = Shown {
                done,
                ..Shown::plain(&draft)
            };
            server_page(&state, &viewer, StatusCode::OK, &server, &shown).await
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
            return refused_settings(&state, &form.viewer, &stored, &draft, refusal).await;
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
            refused_settings(&state, &form.viewer, &stored, &draft, Refusal::Taken).await
        }
        Ok(Ok(Changed::SecretDeclared)) => {
            refused_settings(&state, &form.viewer, &stored, &draft, Refusal::SecretName).await
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

/// Declares a custom header. A refused name answers 400 with the page again, the name sent back.
pub async fn post_header(
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
    let name = form.fields.get("name").to_owned();
    let required = form.fields.get("required") == "1";
    let at = state.clock.now().unix_timestamp();
    let posted = name.clone();
    match state
        .db
        .call(move |conn| add_header_in(conn, id, &posted, required, &actor, at))
        .await
    {
        Ok(HeaderChange::Saved(header)) => done_redirect(
            id,
            vec![
                ("done", "header-added".to_owned()),
                ("header", header.to_string()),
            ],
        ),
        Ok(HeaderChange::Refused(refusal)) => {
            let header = HeaderForm {
                name: ui::sent_back(&name, ui::SENT_BACK_LIMIT),
                required,
                refusal: Some(refusal),
            };
            refused_header(&state, &form.viewer, id, header).await
        }
        Ok(HeaderChange::Missing) => not_found(),
        Err(err) => internal_error("header save", &err),
    }
}

/// Removes one declared header of the server; an id that is not one of its headers is not found.
pub async fn post_remove_header(
    State(state): State<AppState>,
    Path((id, header_id)): Path<(String, String)>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let (Some(id), Some(header_id)) = (parse_id(&id), parse_id(&header_id)) else {
        return not_found();
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| remove_header_in(conn, id, header_id, &actor, at))
        .await
    {
        Ok(Removed::Done(name)) => done_redirect(
            id,
            vec![("done", "header-removed".to_owned()), ("name", name)],
        ),
        Ok(Removed::Missing) => not_found(),
        Err(err) => internal_error("header removal", &err),
    }
}

/// The confirm page of a removal: the header's name, the server and how many people stored a credential for it.
pub async fn get_remove_header(
    viewer: Viewer,
    State(state): State<AppState>,
    Path((id, header_id)): Path<(String, String)>,
) -> Response {
    let (Some(id), Some(header_id)) = (parse_id(&id), parse_id(&header_id)) else {
        return not_found();
    };
    let loaded = state
        .db
        .call(move |conn| {
            let Some(server) = servers::load(conn, id)? else {
                return Ok(None);
            };
            let headers = custom_headers::load(conn, id)?;
            let Some(declared) = headers
                .declared
                .into_iter()
                .find(|declared| declared.id == header_id)
            else {
                return Ok(None);
            };
            let stored = stored_for(&stored_counts(conn, id)?, header_id);
            let assigned = assigned_count(conn, id)?;
            Ok(Some((server, declared, stored, assigned)))
        })
        .await;
    match loaded {
        Ok(Some((server, declared, stored, assigned))) => {
            let title = format!("Remove {}?", declared.name);
            form_page_with(
                &viewer,
                StatusCode::OK,
                "remove-header",
                &title,
                &MainData::default(),
                |csrf| remove_body(csrf, &server, &declared, stored, assigned),
            )
        }
        Ok(None) => not_found(),
        Err(err) => internal_error("header removal page", &err),
    }
}

/// The confirm page's card: the title with the header's name, the sentence of who stored one, and the two buttons.
fn remove_body(
    csrf: &str,
    server: &Server,
    declared: &Declared,
    stored: i64,
    assigned: i64,
) -> Markup {
    let path = format!("/admin/servers/{}", server.id);
    html! {
        h1 { "Remove " span.title-name { (ui::breakable(&declared.name)) } "?" }
        p.lede data-stored-by=(stored) {
            @if stored == 0 {
                "No user stored a credential for it on " (server.name) "."
            } @else {
                span.nowrap { (stored) " of " (assigned) " " (if assigned == 1 { "user" } else { "users" }) }
                " stored a credential for it on " (server.name) "."
                @if stored == 1 {
                    " That credential is deleted and cannot be recovered."
                } @else {
                    " Those credentials are deleted and cannot be recovered."
                }
            }
        }
        div.actions {
            form method="post" {
                input type="hidden" name="csrf" value=(csrf);
                button type="submit" data-kind="danger" { "Remove header" }
            }
            a.button data-kind="secondary" href=(format!("{path}#headers-title")) { "Keep header" }
        }
    }
}

/// Saves the server's two header switches and the Required boxes the form lists; a checkbox is on only
/// when posted as "1", and a header is changed only when its `listed_` field arrives.
pub async fn post_header_switches(
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
    let pass = form.fields.get("pass_headers") == "1";
    let store = form.fields.get("store_headers") == "1";
    let mut listed: Vec<i64> = form
        .fields
        .pairs()
        .filter_map(|(name, _)| name.strip_prefix("listed_").and_then(parse_id))
        .collect();
    listed.sort_unstable();
    listed.dedup();
    let required: Vec<(i64, bool)> = listed
        .into_iter()
        .map(|header| {
            (
                header,
                form.fields.get(&format!("required_{header}")) == "1",
            )
        })
        .collect();
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| switches_in(conn, id, pass, store, &required, &actor, at))
        .await
    {
        Ok(Switched::Saved(made_required)) => {
            let mut pairs = vec![("done", "headers-saved".to_owned())];
            pairs.extend(
                made_required
                    .iter()
                    .map(|header| ("required", header.to_string())),
            );
            done_redirect(id, pairs)
        }
        Ok(Switched::Missing) => not_found(),
        Err(err) => internal_error("header switches", &err),
    }
}

/// The server page's address with a query that says which step was done, landing on the headers part.
fn done_redirect(id: i64, pairs: Vec<(&str, String)>) -> Response {
    let query = Serializer::new(String::new()).extend_pairs(pairs).finish();
    redirect(&format!("/admin/servers/{id}?{query}#headers-title"))
}

/// The step a server page's query says was done, with its values as the redirect wrote them. None when
/// the query names none. Only the header ids and the names are read; anything else is ignored.
fn done_of(raw: Option<&str>) -> Option<Done> {
    let mut kind = None;
    let mut header = None;
    let mut name = None;
    let mut required = Vec::new();
    for (key, value) in form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
        match key.as_ref() {
            "done" => kind = Some(value.into_owned()),
            "header" => header = parse_id(&value),
            "name" => name = Some(value.into_owned()),
            "required" if required.len() < MAX_PER_SERVER => {
                required.extend(parse_id(&value));
            }
            _ => {}
        }
    }
    match kind.as_deref() {
        Some("header-added") => header.map(Done::HeaderAdded),
        Some("header-removed") => name
            .filter(|name| custom_headers::valid_name(name))
            .map(Done::HeaderRemoved),
        Some("headers-saved") => Some(Done::HeadersSaved(required)),
        Some("tools-refreshed-without-values") => Some(Done::RefreshedWithoutValues),
        _ => None,
    }
}

/// The notice of a step, from the server's own rows, and the place it shows. A step whose header is gone
/// shows no notice, except a removal, which names the header it was given.
fn done_notice(
    conn: &Connection,
    server: i64,
    done: &Done,
) -> rusqlite::Result<Option<(Place, Markup)>> {
    let declared = custom_headers::load(conn, server)?.declared;
    Ok(match done {
        Done::HeaderAdded(id) => declared
            .iter()
            .find(|header| header.id == *id)
            .map(|header| {
                let notice = ui::notice(
                    "ok",
                    html! { p { code { (ui::breakable(&header.name)) } " added." } },
                );
                (Place::Headers, notice)
            }),
        Done::HeaderRemoved(name) => {
            let notice = ui::notice(
                "ok",
                html! { p { code { (ui::breakable(name)) } " removed." } },
            );
            Some((Place::Headers, notice))
        }
        Done::RefreshedWithoutValues => Some((
            Place::Title,
            ui::notice("warning", html! { p { (REFRESHED_WITHOUT_VALUES) } }),
        )),
        Done::HeadersSaved(ids) => {
            let assigned = assigned_count(conn, server)?;
            let stored = stored_counts(conn, server)?;
            let mut lines = Vec::new();
            for header in declared.iter().filter(|header| ids.contains(&header.id)) {
                if header.required {
                    let unstored = assigned.saturating_sub(stored_for(&stored, header.id));
                    lines.push((header.name.clone(), unstored, assigned));
                }
            }
            let notice = ui::notice(
                "ok",
                html! {
                    p { "Headers saved." }
                    @for (name, unstored, total) in &lines {
                        p.attention {
                            code { (ui::breakable(name)) }
                            " is now required. " (unstored) " of " (total) " users have not stored it."
                        }
                    }
                },
            );
            Some((Place::Headers, notice))
        }
    })
}

/// The notice a server page's query names, with the place it shows, or None.
async fn done_for(
    state: &AppState,
    server: i64,
    raw: Option<&str>,
) -> Result<Option<(Place, Markup)>, DbError> {
    let Some(done) = done_of(raw) else {
        return Ok(None);
    };
    state
        .db
        .call(move |conn| done_notice(conn, server, &done))
        .await
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

/// The draft as a refused form shows it again: plain values through `sent_back`, the secret value dropped.
fn sent_back_draft(draft: &Draft) -> Draft {
    Draft {
        name: ui::sent_back(&draft.name, ui::SENT_BACK_LIMIT),
        slug: ui::sent_back(&draft.slug, ui::SENT_BACK_LIMIT),
        upstream_url: ui::sent_back(&draft.upstream_url, ui::SENT_BACK_LIMIT),
        secret_header_name: ui::sent_back(&draft.secret_header_name, ui::SENT_BACK_LIMIT),
        secret_header_value: String::new(),
        pass_resources: draft.pass_resources,
        pass_prompts: draft.pass_prompts,
    }
}

/// Whether a posted draft carried a secret header value, which a refused form must ask for again.
fn secret_sent(draft: &Draft) -> bool {
    !draft.secret_header_value.is_empty()
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
    if let Some(secret) = &settings.secret
        && custom_headers::declares(&tx, id, &secret.header_name)?
    {
        return Ok(Ok(Changed::SecretDeclared));
    }
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
    if stored.upstream_url != settings.upstream_url {
        keys::release(&tx, id, None, None, at, true)?;
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
        keys::release(&tx, server_id, Some(user_id), None, at, true)?;
    }
    let noun = if ids.len() == 1 { "user" } else { "users" };
    let detail = format!("assignments of {} set to {} {noun}", server.slug, ids.len());
    record(&tx, at, actor, Some(id), &server.slug, &detail)?;
    tx.commit()?;
    Ok(Assigned::Saved)
}

/// One transaction: the header is declared and recorded, or refused and nothing is written.
fn add_header_in(
    conn: &mut Connection,
    id: i64,
    name: &str,
    required: bool,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<HeaderChange> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(server) = servers::load(&tx, id)? else {
        return Ok(HeaderChange::Missing);
    };
    let added = match custom_headers::add(&tx, id, name, required, at)? {
        Ok(header) => header,
        Err(refusal) => return Ok(HeaderChange::Refused(refusal)),
    };
    let detail = format!("declared header {}", name.to_ascii_lowercase());
    record(&tx, at, actor, Some(id), &server.slug, &detail)?;
    tx.commit()?;
    Ok(HeaderChange::Saved(added))
}

/// One transaction: the header goes and its removal is recorded; an id of another server is missing.
fn remove_header_in(
    conn: &mut Connection,
    id: i64,
    header_id: i64,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Removed> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(server) = servers::load(&tx, id)? else {
        return Ok(Removed::Missing);
    };
    let declared = custom_headers::load(&tx, id)?
        .declared
        .into_iter()
        .find(|declared| declared.id == header_id);
    let Some(declared) = declared else {
        return Ok(Removed::Missing);
    };
    keys::release(&tx, id, None, Some(header_id), at, false)?;
    custom_headers::remove(&tx, id, header_id)?;
    let detail = format!("removed header {}", declared.lower);
    record(&tx, at, actor, Some(id), &server.slug, &detail)?;
    tx.commit()?;
    Ok(Removed::Done(declared.name))
}

/// One transaction: the two switches and the listed Required boxes are saved and recorded; each
/// Required change writes its own row. Returns the headers the save made required.
fn switches_in(
    conn: &mut Connection,
    id: i64,
    pass: bool,
    store: bool,
    required: &[(i64, bool)],
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<Switched> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(server) = servers::load(&tx, id)? else {
        return Ok(Switched::Missing);
    };
    let declared = custom_headers::load(&tx, id)?.declared;
    let mut made_required = Vec::new();
    for (header, wanted) in required {
        let Some(declared) = declared.iter().find(|declared| declared.id == *header) else {
            continue;
        };
        if declared.required == *wanted {
            continue;
        }
        custom_headers::set_required(&tx, id, *header, *wanted)?;
        let change = if *wanted {
            "made required"
        } else {
            "made optional"
        };
        let detail = format!("header {} {change}", declared.name);
        record(&tx, at, actor, Some(id), &server.slug, &detail)?;
        if *wanted {
            made_required.push(*header);
        }
    }
    custom_headers::set_switches(&tx, id, pass, store)?;
    let word = |on: bool| if on { "on" } else { "off" };
    let detail = format!(
        "header switches: pass {}, store {}",
        word(pass),
        word(store)
    );
    record(&tx, at, actor, Some(id), &server.slug, &detail)?;
    tx.commit()?;
    Ok(Switched::Saved(made_required))
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
            let shown = Shown {
                refusal: Some(Refusal::UnknownUser),
                ..Shown::plain(&draft)
            };
            server_page(state, viewer, StatusCode::BAD_REQUEST, &server, &shown).await
        }
        Ok(None) => not_found(),
        Err(err) => internal_error("server page", &err),
    }
}

/// The server page again with a refused settings form: the posted values, and the refusal.
async fn refused_settings(
    state: &AppState,
    viewer: &Viewer,
    stored: &Server,
    draft: &Draft,
    refusal: Refusal,
) -> Response {
    let sent = sent_back_draft(draft);
    let shown = Shown {
        draft: &sent,
        refusal: Some(refusal),
        secret_sent: secret_sent(draft),
        header: HeaderForm::default(),
        done: None,
    };
    server_page(state, viewer, StatusCode::BAD_REQUEST, stored, &shown).await
}

/// The server page again with a refused header form, the name sent back in its field.
async fn refused_header(
    state: &AppState,
    viewer: &Viewer,
    id: i64,
    header: HeaderForm,
) -> Response {
    match load(state, id).await {
        Ok(Some(server)) => {
            let draft = draft_of(&server);
            let shown = Shown {
                header,
                ..Shown::plain(&draft)
            };
            server_page(state, viewer, StatusCode::BAD_REQUEST, &server, &shown).await
        }
        Ok(None) => not_found(),
        Err(err) => internal_error("server page", &err),
    }
}

/// The list page, with the create form filled from `draft`. `secret_sent` asks for the secret again.
async fn servers_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    draft: &Draft,
    refusal: Option<Refusal>,
    secret_sent: bool,
) -> Response {
    match state.db.call(|conn| list_in(conn)).await {
        Ok(rows) => {
            let data = MainData {
                nav: panel_nav(viewer, "/admin/servers"),
                ..MainData::default()
            };
            form_page_with(viewer, status, "servers", "Servers", &data, |csrf| {
                html! {
                    (servers_body(csrf, &rows, draft, refusal, secret_sent))
                }
            })
        }
        Err(err) => internal_error("servers page", &err),
    }
}

/// One server's page: its settings, its users and its delete form. `secret_sent` asks for the secret again.
async fn server_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    server: &Server,
    shown: &Shown<'_>,
) -> Response {
    let id = server.id;
    match state
        .db
        .call(move |conn| {
            let users = servers::user_choices(conn, id)?;
            let tools = catalog::names(conn, id)?;
            let headers = custom_headers::load(conn, id)?;
            let stored = stored_counts(conn, id)?;
            Ok((users, tools, headers, stored))
        })
        .await
    {
        Ok((users, tools, headers, stored)) => {
            let lockdown = effective_lockdown(server);
            let data = MainData {
                nav: panel_nav(viewer, "/admin/servers"),
                lockdown: Some(lockdown),
                ..MainData::default()
            };
            form_page_with(viewer, status, "server", "Server", &data, |csrf| {
                html! {
                    (server_body(csrf, server, shown, &users, &tools, (&headers, &stored)))
                }
            })
        }
        Err(err) => internal_error("server page", &err),
    }
}

/// The lock-down state a page shows: an ok result without a stored secret header reads as nosecret.
fn effective_lockdown(server: &Server) -> &str {
    if !server.has_secret && server.lockdown == "ok" {
        "nosecret"
    } else {
        &server.lockdown
    }
}

/// The notice of a refresh sent without the admin's stored values.
const REFRESHED_WITHOUT_VALUES: &str =
    "Tools refreshed without your stored credentials. Sign out and sign in again to send them.";

/// The tool list's notice while the answer memory budget is used up.
const BUSY_NOTICE: &str = "The gateway is busy. Try again in a moment.";

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
    let mut without_values = false;
    let outcome = match upstream::target(&state, id).await {
        Ok(Some(target)) => {
            let session = form.viewer.presented_session().map(str::to_owned);
            let (own, locked) = match own_values(&state, actor.id, id, &target.url, session).await {
                Ok(own) => own,
                Err(err) => return internal_error("tool refresh", &err),
            };
            without_values = locked;
            let limit = upstream::time_limit(&state);
            catalog::refresh_within(&state, &target, limit, None, &own)
                .await
                .map(|_| ())
        }
        Ok(None) => return not_found(),
        Err(TargetError::Secret) => {
            match catalog::fail(&state, id, RefreshError::Unavailable).await {
                Ok(()) => Err(RefreshError::Unavailable),
                Err(err) => Err(err),
            }
        }
        Err(TargetError::Db(err)) => return internal_error("tool refresh", &err),
    };
    let busy = matches!(outcome, Err(RefreshError::Busy));
    let refreshed = outcome.is_ok();
    let detail = match outcome {
        Ok(()) => "tools refreshed",
        Err(RefreshError::Db) => {
            return internal_error("tool refresh", &"the tool catalog cannot be stored");
        }
        Err(_) => "tool refresh failed",
    };
    match record_change(&state, &actor, id, &server.slug, detail).await {
        Ok(()) if busy => busy_page(&state, &form.viewer, id).await,
        Ok(()) if refreshed && without_values => redirect(&format!(
            "/admin/servers/{id}?done=tools-refreshed-without-values"
        )),
        Ok(()) => redirect(&format!("/admin/servers/{id}")),
        Err(err) => internal_error("tool refresh record", &err),
    }
}

/// The pressing admin's own stored values for the server's declared headers, opened for `url` with the
/// admin's browser session, and whether the admin holds values the session cannot open the key for.
async fn own_values(
    state: &AppState,
    user: i64,
    server: i64,
    url: &str,
    session: Option<String>,
) -> Result<(Vec<(HeaderName, HeaderValue)>, bool), DbError> {
    let keys = Arc::clone(&state.keys);
    let url = url.to_owned();
    state
        .db
        .call(move |conn| {
            let config = custom_headers::load(conn, server)?;
            if !config.store || config.declared.is_empty() {
                return Ok((Vec::new(), false));
            }
            let via = session.as_deref().map(Via::Session);
            let opened = values::open_for(conn, &keys, user, server, &url, via, false)?;
            let locked = (opened.locked && !opened.held.is_empty()) || !opened.unopened.is_empty();
            let own = opened
                .stored
                .into_iter()
                .filter_map(|(name, value)| {
                    HeaderName::from_bytes(name.as_bytes())
                        .ok()
                        .map(|name| (name, value))
                })
                .collect();
            Ok((own, locked))
        })
        .await
}

/// The server page again, saying the gateway is busy in the tool list's notice. The notice is not stored.
async fn busy_page(state: &AppState, viewer: &Viewer, id: i64) -> Response {
    match load(state, id).await {
        Ok(Some(mut server)) => {
            server.catalog_error = Some(BUSY_NOTICE.to_owned());
            let draft = draft_of(&server);
            let shown = Shown::plain(&draft);
            server_page(
                state,
                viewer,
                StatusCode::SERVICE_UNAVAILABLE,
                &server,
                &shown,
            )
            .await
        }
        Ok(None) => not_found(),
        Err(err) => internal_error("server page", &err),
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
        "nosecret" => {
            "This server has no secret header, so the gateway has no secret to check the upstream with."
        }
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

/// One server as the list shows it: its path, its lock-down state and its two counts.
struct ServerRow {
    id: i64,
    name: String,
    slug: String,
    lockdown: String,
    tools: i64,
    users: i64,
}

/// Every server with its tool count and its assigned-user count, in one query, oldest first.
fn list_in(conn: &Connection) -> rusqlite::Result<Vec<ServerRow>> {
    let mut statement = conn.prepare(
        "SELECT id, name, slug, \
         CASE WHEN secret_header_value IS NULL AND lockdown = 'ok' THEN 'nosecret' ELSE lockdown END, \
         (SELECT COUNT(*) FROM tool_catalog WHERE tool_catalog.server_id = servers.id), \
         (SELECT COUNT(*) FROM user_servers WHERE user_servers.server_id = servers.id) \
         FROM servers ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(ServerRow {
            id: row.get(0)?,
            name: row.get(1)?,
            slug: row.get(2)?,
            lockdown: row.get(3)?,
            tools: row.get(4)?,
            users: row.get(5)?,
        })
    })?;
    rows.collect()
}

/// The reason a header name was refused, with the name as it was typed set in code.
fn header_refusal(refusal: AddRefusal, name: &str) -> Markup {
    match refusal {
        AddRefusal::Invalid | AddRefusal::SecretName if name.is_empty() => {
            html! { "This header name cannot be used. Choose another name." }
        }
        AddRefusal::Invalid | AddRefusal::SecretName => html! {
            code { (ui::breakable(name)) } " cannot be used as a custom header. Choose another name."
        },
        AddRefusal::Duplicate => html! { "This server already declares that header." },
        AddRefusal::Full => html! { "A server takes at most 8 custom headers." },
    }
}

/// The custom headers part: the declared headers with their Required boxes and switches, then the add form.
fn headers_section(
    csrf: &str,
    server: &Server,
    (headers, stored, assigned): (&ServerHeaders, &[(i64, i64)], usize),
    header: &HeaderForm,
    done: Option<&Markup>,
) -> Markup {
    let path = format!("/admin/servers/{}", server.id);
    let error = header
        .refusal
        .map(|refusal| header_refusal(refusal, &header.name));
    let name_note = match &error {
        Some(message) => ui::Note::Below(
            "header-name-error",
            html! { p.field-error id="header-name-error" { span { (message) } } },
        ),
        None => ui::Note::Hint("For example X-Api-Key. Up to 8 per server."),
    };
    let name_described = name_note.describer("header-name");
    let count = headers.declared.len();
    let required: Vec<&Declared> = headers
        .declared
        .iter()
        .filter(|declared| declared.required)
        .collect();
    html! {
        section.part aria-labelledby="headers-title" {
            div.part-head {
                h2 id="headers-title" { "Custom headers " span.count { (count) " of " (MAX_PER_SERVER) } }
                p { "Headers this server needs from each person, such as an API token." }
            }
            div.part-body.flow {
                @if let Some(done) = done {
                    (done)
                }
                @if headers.declared.is_empty() {
                    p.muted.narrow { "No custom headers. The gateway sends nothing from a client to this server except the MCP protocol headers." }
                } @else {
                    form.flow method="post" action=(format!("{path}/header-switches")) {
                        input type="hidden" name="csrf" value=(csrf);
                        @for declared in &headers.declared {
                            input type="hidden" name=(format!("listed_{}", declared.id)) value="1";
                        }
                        table.list.headers {
                            thead {
                                tr {
                                    th scope="col" { "Header" }
                                    th scope="col" class="c-required" { "Required" }
                                    th scope="col" class="c-stored" { "Stored by" }
                                    th scope="col" class="c-act" aria-label="Actions" {}
                                }
                            }
                            tbody {
                                @for declared in &headers.declared {
                                    (header_row(
                                        &path,
                                        declared,
                                        (headers.store, stored_for(stored, declared.id), assigned),
                                    ))
                                }
                            }
                        }
                        p.muted { "Required: without a value, nothing is sent to this server for that person." }
                        fieldset.flow {
                            legend { "Where the credentials come from" }
                            div.checks data-switches {
                                (ui::check(
                                    "pass-headers",
                                    "pass_headers",
                                    Some("1"),
                                    headers.pass,
                                    "Pass these headers through from the client",
                                    Some("An app that sends one of these headers reaches the server with its own value. Authorization is never passed through."),
                                ))
                                (ui::check(
                                    "store-headers",
                                    "store_headers",
                                    Some("1"),
                                    headers.store,
                                    "Let each person store their own credentials",
                                    Some("Each person saves their credentials on their account page. They are encrypted so that the database and its key cannot open them without that person's password or connected app."),
                                ))
                            }
                        }
                        @if let Some(first) = required.first().filter(|_| !headers.pass && !headers.store) {
                            p data-no-source {
                                span.state data-pill data-tone="warn" {
                                    "No source is on. "
                                    @if required.len() == 1 {
                                        code { (ui::breakable(&first.name)) } " is required, so nothing is sent to this server."
                                    } @else {
                                        (required.len()) " headers are required, so nothing is sent to this server."
                                    }
                                }
                            }
                        }
                        div.form-actions {
                            button type="submit" data-kind="secondary" { "Save headers" }
                        }
                    }
                }
                @if count < MAX_PER_SERVER {
                    form.flow method="post" action=(format!("{path}/headers")) {
                        input type="hidden" name="csrf" value=(csrf);
                        fieldset.flow {
                            legend { "Add a header" }
                            div.fields data-cols="2" {
                                (ui::field(
                                    "header-name",
                                    "Header name",
                                    false,
                                    html! {
                                        input.mono id="header-name" name="name" type="text" value=(header.name)
                                            aria-invalid=[error.as_ref().map(|_| "true")] aria-describedby=[name_described.as_deref()];
                                    },
                                    name_note,
                                ))
                            }
                            div.checks {
                                (ui::check(
                                    "header-required",
                                    "required",
                                    Some("1"),
                                    header.required,
                                    "Required",
                                    Some("Without a value, nothing is sent to this server for that person."),
                                ))
                            }
                        }
                        div.form-actions {
                            button type="submit" data-kind="secondary" { "Add header" }
                        }
                    }
                } @else {
                    p.muted.narrow data-headers-full { "This server has " (count) " of " (MAX_PER_SERVER) " headers. Remove one to add another." }
                }
            }
        }
    }
}

/// One declared header as a row: its name, its Required box, how many people stored a credential, and its Remove link.
fn header_row(
    path: &str,
    declared: &Declared,
    (store, stored, assigned): (bool, i64, usize),
) -> Markup {
    let required = if declared.required { "yes" } else { "no" };
    let word = if declared.required {
        "Required"
    } else {
        "Optional"
    };
    let box_id = format!("required-{}", declared.id);
    let box_label = format!("Required, {}", declared.name);
    html! {
        tr data-header=(declared.lower) data-required=(required) data-stored=(stored) {
            td.lead { code { (ui::breakable(&declared.name)) } }
            td.half.c-required {
                div.check {
                    input type="checkbox" id=(box_id) name=(format!("required_{}", declared.id)) value="1"
                        checked[declared.required] aria-label=(box_label);
                    label for=(box_id) { (word) }
                }
            }
            td.half data-stored-by {
                @if store {
                    span.unit { "Stored by " }
                    span.nowrap { (stored) " of " (assigned) " " (if assigned == 1 { "user" } else { "users" }) }
                } @else {
                    "Storing is off"
                }
            }
            td.act {
                a.button.row-action data-kind="danger" href=(format!("{path}/headers/{}/remove", declared.id))
                    aria-label=(format!("Remove {}", declared.name)) { "Remove" }
            }
        }
    }
}

/// How many users stored a value, per declared header id of the server.
fn stored_counts(conn: &Connection, server: i64) -> rusqlite::Result<Vec<(i64, i64)>> {
    let mut statement = conn.prepare(
        "SELECT h.id, COUNT(v.user_id) FROM server_headers h \
         LEFT JOIN user_header_values v ON v.header_id = h.id \
         WHERE h.server_id = ?1 GROUP BY h.id",
    )?;
    statement
        .query_map(params![server], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

/// How many users are assigned to the server.
fn assigned_count(conn: &Connection, server: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM user_servers WHERE server_id = ?1",
        params![server],
        |row| row.get(0),
    )
}

fn stored_for(counts: &[(i64, i64)], header: i64) -> i64 {
    counts
        .iter()
        .find(|(id, _)| *id == header)
        .map_or(0, |(_, count)| *count)
}

/// The lock-down state as a status: a word with its marker. Answering without the gateway is strong.
fn lockdown_pill(verdict: &str) -> Markup {
    match verdict {
        "ok" => ui::pill("ok", "Locked down"),
        "nosecret" => ui::pill("warn", "No secret header"),
        "open" => {
            html! { span.state.strong data-pill data-tone="bad" { "Answers without the gateway" } }
        }
        _ => ui::pill("warn", "Not checked"),
    }
}

/// The field a refusal is about: its input id and the words the form uses for it.
fn refused_field(refusal: Refusal) -> Option<(&'static str, &'static str)> {
    match refusal {
        Refusal::Name => Some(("server-name", "name")),
        Refusal::Slug | Refusal::Taken => Some(("server-slug", "path")),
        Refusal::UpstreamUrl => Some(("server-url", "upstream address")),
        Refusal::SecretName => Some(("secret-name", "header name")),
        Refusal::SecretValue => Some(("secret-value", "header value")),
        Refusal::UnknownUser => None,
    }
}

fn servers_body(
    csrf: &str,
    rows: &[ServerRow],
    draft: &Draft,
    refusal: Option<Refusal>,
    secret_sent: bool,
) -> Markup {
    html! {
        div.page-head {
            h1 { "Servers" }
            @if !rows.is_empty() {
                div.head-actions {
                    a.button data-kind="secondary" href="#add" { "Add a server" }
                }
            }
        }
        @if let Some(refusal) = refusal {
            (ui::refused(Some("The server was not added."), refusal.to_string().as_str(), refused_field(refusal)))
        }
        @if rows.is_empty() {
            div.empty {
                h2 { "No servers yet." }
                p { "A server is an MCP server that Doorward stands in front of. Add the first one below, then choose who may reach it." }
            }
        } @else {
            table.list.servers {
                thead {
                    tr {
                        th scope="col" { "Name" }
                        th scope="col" class="c-path" { "Path" }
                        th scope="col" class="c-num num" { "Tools" }
                        th scope="col" class="c-num num" { "Users" }
                        th scope="col" class="c-state" { "Lock-down" }
                    }
                }
                tbody {
                    @for row in rows {
                        (server_row(row))
                    }
                }
            }
        }
        section.part id="add" aria-labelledby="add-title" {
            div.part-head {
                h2 id="add-title" { "Add a server" }
                p { "An MCP server that Doorward stands in front of. People reach it only through the gateway." }
            }
            div.part-body {
                form.flow method="post" action="/admin/servers" {
                    input type="hidden" name="csrf" value=(csrf);
                    (settings_fields(draft, refusal, false, secret_sent))
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Add server" }
                    }
                }
            }
        }
    }
}

/// One row of the servers table: the name, the path, the two counts and the lock-down state.
fn server_row(row: &ServerRow) -> Markup {
    html! {
        tr data-server-id=(row.id) data-slug=(row.slug) {
            td.lead {
                a.name href=(format!("/admin/servers/{}", row.id)) { (row.name) }
            }
            td { code { (row.slug) } }
            td.num.half data-tool-count { (ui::count_with_unit(row.tools, "tool", "tools")) }
            td.num.half data-user-count { (ui::count_with_unit(row.users, "user", "users")) }
            td { (lockdown_pill(&row.lockdown)) }
        }
    }
}

fn server_body(
    csrf: &str,
    server: &Server,
    shown: &Shown<'_>,
    users: &[UserChoice],
    tools: &[String],
    (headers, stored): (&ServerHeaders, &[(i64, i64)]),
) -> Markup {
    let path = format!("/admin/servers/{}", server.id);
    let note = lockdown_note(effective_lockdown(server));
    let assigned = users.iter().filter(|user| user.assigned).count();
    let (draft, refusal, secret_sent) = (shown.draft, shown.refusal, shown.secret_sent);
    let headers_done = shown.done.as_ref().and_then(|(place, markup)| match place {
        Place::Headers => Some(markup),
        Place::Title => None,
    });
    html! {
        div.page-head {
            p.crumb { a href="/admin/servers" { "Servers" } }
            h1 { (server.name) }
            p.meta {
                span { "Path " code { (server.slug) } }
                (lockdown_pill(effective_lockdown(server)))
            }
            div.head-actions {
                a.button data-kind="secondary" href=(format!("/admin/activity?server={}", server.id)) data-link="activity" { "Activity" }
            }
        }
        @if let Some(refusal) = refusal {
            (ui::refused(Some("The server was not saved."), refusal.to_string().as_str(), refused_field(refusal)))
        }
        @if let Some(refusal) = shown.header.refusal {
            (ui::refused_markup(
                Some("The header was not added."),
                Some(header_refusal(refusal, &shown.header.name)),
                Some(("header-name", "header name")),
            ))
        }
        @if let Some((Place::Title, done)) = &shown.done {
            (done)
        }
        @if server.lockdown == "open" {
            div.notice data-notice="error" data-lockdown-alert {
                p {
                    strong { "This server answers without the gateway." }
                    " Anyone who can reach its address can use it, with no sign-in and no record. "
                    a href="#lockdown-title" { "Go to lock-down" }
                }
            }
        }
        section.part aria-labelledby="settings-title" {
            div.part-head {
                h2 id="settings-title" { "Settings" }
                p { "Where the server lives and what Doorward sends to it." }
            }
            div.part-body {
                form.flow method="post" action=(path) {
                    input type="hidden" name="csrf" value=(csrf);
                    (settings_fields(draft, refusal, server.has_secret, secret_sent))
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Save server" }
                    }
                }
            }
        }
        (headers_section(csrf, server, (headers, stored, assigned), &shown.header, headers_done))
        section.part aria-labelledby="tools-title" {
            div.part-head {
                h2 id="tools-title" { "Tools " span.count { (tools.len()) } }
                p { "The tools the upstream lists. Rules and the activity log use these names." }
            }
            div.part-body.flow {
                @if let Some(message) = &server.catalog_error {
                    (ui::notice("error", html! { p { (message) } }))
                }
                @if tools.is_empty() {
                    p.muted { "No tools yet. Refresh the list to fetch them from the upstream." }
                } @else {
                    ul.catalog {
                        @for tool in tools {
                            li data-catalog-tool=(tool) { code { (ui::breakable(tool)) } }
                        }
                    }
                }
                form.form-actions method="post" action=(format!("{path}/refresh-tools")) {
                    input type="hidden" name="csrf" value=(csrf);
                    button type="submit" data-kind="secondary" { "Refresh tools" }
                }
            }
        }
        section.part aria-labelledby="lockdown-title" {
            div.part-head {
                h2 id="lockdown-title" { "Lock-down" }
                p { "Checks that the upstream refuses a request that does not carry the secret." }
            }
            div.part-body.flow {
                p { (lockdown_pill(effective_lockdown(server))) }
                p.narrow data-lockdown-note=(note) { (note) }
                @if !headers.declared.is_empty() && !server.has_secret {
                    p.narrow data-direct-warning {
                        "Without a secret header, anyone who reaches the upstream directly bypasses the gateway's rules and its activity log. Add a secret header the server checks, or restrict its network. "
                        a href="#secret-name" { "Go to secret header" }
                    }
                }
                form.form-actions method="post" action=(format!("{path}/check-lockdown")) {
                    input type="hidden" name="csrf" value=(csrf);
                    button type="submit" data-kind="secondary" { "Check lock-down" }
                }
            }
        }
        section.part aria-labelledby="users-title" {
            div.part-head {
                h2 id="users-title" { "Users " span.count { (assigned) " of " (users.len()) } }
                p { "Every user reaches this server under the same identity, so anything the server caches or remembers per caller is shared." }
            }
            div.part-body {
                form.flow method="post" action=(format!("{path}/users")) {
                    input type="hidden" name="csrf" value=(csrf);
                    div.checks {
                        @for user in users {
                            (user_check(user))
                        }
                    }
                    div.form-actions {
                        button type="submit" data-kind="secondary" { "Save users" }
                    }
                }
            }
        }
        section.part aria-labelledby="delete-title" {
            div.part-head {
                h2 id="delete-title" { "Delete" }
                p { "Removes the server from the gateway." }
            }
            div.part-body {
                details.confirm data-confirm {
                    summary {
                        span.confirm-open { "Delete this server " span.chevron aria-hidden="true" {} }
                        " "
                        span.confirm-note { "This cannot be undone." }
                    }
                    div.confirm-body {
                        p { "This cannot be undone. People who use " (server.name) " through Doorward lose it at once." }
                        form method="post" action=(format!("{path}/delete")) {
                            input type="hidden" name="csrf" value=(csrf);
                            button type="submit" data-kind="danger" { "Delete server" }
                        }
                    }
                }
            }
        }
    }
}

/// One user as a checkbox: assigned when the server has the user.
fn user_check(user: &UserChoice) -> Markup {
    let value = user.id.to_string();
    ui::check(
        &format!("user-{}", user.id),
        "user_id",
        Some(&value),
        user.assigned,
        ui::email(&user.email),
        None,
    )
}

/// The settings inputs of the create and the edit form; `stored` lets the edit form remove a secret.
/// `secret_sent` replaces the secret's hint with the request to enter it again.
fn settings_fields(
    draft: &Draft,
    refusal: Option<Refusal>,
    stored: bool,
    secret_sent: bool,
) -> Markup {
    let refused = refusal.and_then(refused_field).map(|(id, _)| id);
    let message = refusal.map(|refusal| refusal.to_string());
    let error_on = |id: &str| message.as_deref().filter(|_| refused == Some(id));

    let name_error = error_on("server-name");
    let name_note = ui::note_under(name_error, None);
    let name_described = name_note.describer("server-name");
    let slug_error = error_on("server-slug");
    let slug_note = ui::note_under(
        slug_error,
        Some("Letters, digits and hyphens, at most 24 characters."),
    );
    let slug_described = slug_note.describer("server-slug");
    let url_error = error_on("server-url");
    let url_note = ui::note_under(url_error, Some("An http or https address."));
    let url_described = url_note.describer("server-url");
    let secret_name_error = error_on("secret-name");
    let secret_name_note = ui::note_under(secret_name_error, None);
    let secret_name_described = secret_name_note.describer("secret-name");
    let value_error = error_on("secret-value");
    let value_note = if stored {
        let remove = ui::check(
            "remove-secret",
            "remove_secret",
            None,
            false,
            "Remove the stored secret",
            None,
        );
        let stored_hint = if secret_sent {
            ui::RE_ENTER_HINT
        } else {
            "Stored, never shown again. Leave empty to keep it. If you change the upstream address, enter it again."
        };
        match value_error {
            Some(text) if secret_sent => ui::Note::Below(
                "secret-value-error secret-value-hint",
                html! {
                    (ui::field_error("secret-value-error", text))
                    (ui::hint("secret-value-hint", stored_hint))
                    (remove)
                },
            ),
            Some(text) => ui::Note::Below(
                "secret-value-error",
                html! { (ui::field_error("secret-value-error", text)) (remove) },
            ),
            None => ui::Note::Below(
                "secret-value-hint",
                html! {
                    (ui::hint("secret-value-hint", stored_hint))
                    (remove)
                },
            ),
        }
    } else if secret_sent {
        match value_error {
            Some(text) => ui::Note::Below(
                "secret-value-error secret-value-hint",
                html! {
                    (ui::field_error("secret-value-error", text))
                    (ui::hint("secret-value-hint", ui::RE_ENTER_HINT))
                },
            ),
            None => ui::Note::Hint(ui::RE_ENTER_HINT),
        }
    } else {
        ui::note_under(value_error, Some("Kept encrypted and never shown again."))
    };
    let value_described = value_note.describer("secret-value");

    html! {
        div.fields {
            (ui::field(
                "server-name",
                "Name",
                false,
                html! {
                    input id="server-name" name="name" type="text" value=(draft.name) required
                        aria-invalid=[ui::invalid(name_error)] aria-describedby=[name_described.as_deref()];
                },
                name_note,
            ))
        }
        div.fields data-cols="2" {
            (ui::field(
                "server-slug",
                "Path",
                false,
                html! {
                    input.mono id="server-slug" name="slug" type="text" value=(draft.slug) required
                        aria-invalid=[ui::invalid(slug_error)] aria-describedby=[slug_described.as_deref()];
                },
                slug_note,
            ))
        }
        div.fields {
            (ui::field(
                "server-url",
                "Upstream address",
                false,
                html! {
                    input id="server-url" name="upstream_url" type="url" value=(draft.upstream_url) required
                        aria-invalid=[ui::invalid(url_error)] aria-describedby=[url_described.as_deref()];
                },
                url_note,
            ))
        }
        fieldset.flow {
            legend { "Secret header" }
            p.muted { "Doorward sends this header with every request, so the upstream can refuse anything that did not come through the gateway." }
            div.fields data-cols="2" {
                (ui::field(
                    "secret-name",
                    "Header name",
                    true,
                    html! {
                        input.mono id="secret-name" name="secret_header_name" type="text" value=(draft.secret_header_name)
                            aria-invalid=[ui::invalid(secret_name_error)] aria-describedby=[secret_name_described.as_deref()];
                    },
                    secret_name_note,
                ))
                (ui::field(
                    "secret-value",
                    "Header value",
                    true,
                    html! {
                        input id="secret-value" name="secret_header_value" type="password" autocomplete="new-password"
                            aria-invalid=[ui::invalid(value_error)] aria-describedby=[value_described.as_deref()];
                    },
                    value_note,
                ))
            }
        }
        div.checks {
            (ui::check(
                "pass-resources",
                "pass_resources",
                None,
                draft.pass_resources,
                "Pass resources to the upstream",
                Some("When off, clients get an empty list."),
            ))
            (ui::check(
                "pass-prompts",
                "pass_prompts",
                None,
                draft.pass_prompts,
                "Pass prompts to the upstream",
                Some("When off, clients get an empty list."),
            ))
        }
    }
}
