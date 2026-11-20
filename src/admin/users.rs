//! The users pages: the list, one user, the role, disable, enable and delete.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::accounts::session;
use crate::app::AppState;
use crate::audit::{self, Event};
use crate::db::DbError;
use crate::oauth::families;
use crate::policy;
use crate::proxy::catalog;
use crate::servers::{self, Scope, ServerChoice};
use crate::web::{
    Role, SessionUser, VerifiedForm, Viewer, forbidden, form_page, internal_error, not_found, page,
    redirect,
};

use super::panel_nav;

const OWNER: &str = "owner";
const OWNER_MESSAGE: &str = "The owner account cannot be changed this way.";
const ROLE_MESSAGE: &str = "Choose the role admin or user.";
const SERVER_MESSAGE: &str = "Choose only servers that exist.";

/// One user as the pages show it.
struct User {
    id: i64,
    email: String,
    role: String,
    disabled: bool,
}

/// One tool of an assigned server, with the verdict and the deciding rule ("" when none).
struct Effective {
    server: String,
    tool: String,
    verdict: &'static str,
    rule: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Disable,
    Enable,
    Delete,
}

/// The decision of a status change, taken inside its transaction.
enum Verdict {
    Missing,
    Owner,
    Forbidden,
    Done,
}

/// The decision of a role change, taken inside its transaction.
enum RoleVerdict {
    Missing,
    Owner,
    BadRole,
    Done,
}

/// The decision of a server assignment, taken inside its transaction.
enum AssignVerdict {
    Missing,
    BadValue,
    Done,
}

pub async fn get_users(viewer: Viewer, State(state): State<AppState>) -> Response {
    match state.db.call(|conn| list_in(conn)).await {
        Ok(rows) => users_page(&viewer, &rows),
        Err(_) => internal_error(),
    }
}

pub async fn get_user(
    viewer: Viewer,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    user_page(&state, &viewer, id, StatusCode::OK, None).await
}

pub async fn post_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    if !form.viewer.is_owner() {
        return forbidden();
    }
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let role = form.fields.get("role").to_owned();
    let now = state.clock.now().unix_timestamp();
    let verdict = state
        .db
        .call(move |conn| set_role_in(conn, id, &role, &actor, now))
        .await;
    match verdict {
        Ok(RoleVerdict::Done) => redirect(&format!("/admin/users/{id}")),
        Ok(RoleVerdict::Missing) => not_found(),
        Ok(RoleVerdict::Owner) => {
            user_page(
                &state,
                &form.viewer,
                id,
                StatusCode::BAD_REQUEST,
                Some(OWNER_MESSAGE),
            )
            .await
        }
        Ok(RoleVerdict::BadRole) => {
            user_page(
                &state,
                &form.viewer,
                id,
                StatusCode::BAD_REQUEST,
                Some(ROLE_MESSAGE),
            )
            .await
        }
        Err(_) => internal_error(),
    }
}

/// Replaces the user's servers with the posted set. An unknown server id is refused with 400.
pub async fn post_servers(
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
    let ids = form
        .fields
        .all("server_id")
        .iter()
        .map(|value| parse_id(value))
        .collect::<Option<Vec<i64>>>();
    let now = state.clock.now().unix_timestamp();
    let verdict = state
        .db
        .call(move |conn| assign_servers_in(conn, id, ids, &actor, now))
        .await;
    match verdict {
        Ok(AssignVerdict::Done) => redirect(&format!("/admin/users/{id}")),
        Ok(AssignVerdict::Missing) => not_found(),
        Ok(AssignVerdict::BadValue) => {
            user_page(
                &state,
                &form.viewer,
                id,
                StatusCode::BAD_REQUEST,
                Some(SERVER_MESSAGE),
            )
            .await
        }
        Err(_) => internal_error(),
    }
}

pub async fn post_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    change(state, &id, form, Action::Disable).await
}

pub async fn post_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    change(state, &id, form, Action::Enable).await
}

pub async fn post_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    change(state, &id, form, Action::Delete).await
}

/// Disable, enable or delete. The owner is never a target; an admin only acts on plain users.
async fn change(state: AppState, id: &str, form: VerifiedForm, action: Action) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(id) else {
        return not_found();
    };
    let now = state.clock.now().unix_timestamp();
    let verdict = state
        .db
        .call(move |conn| change_in(conn, id, action, &actor, now))
        .await;
    match verdict {
        Ok(Verdict::Done) if action == Action::Delete => redirect("/admin/users"),
        Ok(Verdict::Done) => redirect(&format!("/admin/users/{id}")),
        Ok(Verdict::Missing) => not_found(),
        Ok(Verdict::Owner) => {
            user_page(
                &state,
                &form.viewer,
                id,
                StatusCode::BAD_REQUEST,
                Some(OWNER_MESSAGE),
            )
            .await
        }
        Ok(Verdict::Forbidden) => forbidden(),
        Err(_) => internal_error(),
    }
}

/// An id from the path. Anything that is not a number is no user.
pub(super) fn parse_id(text: &str) -> Option<i64> {
    text.parse::<i64>().ok()
}

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let disabled: i64 = row.get(3)?;
    Ok(User {
        id: row.get(0)?,
        email: row.get(1)?,
        role: row.get(2)?,
        disabled: disabled != 0,
    })
}

fn list_in(conn: &Connection) -> rusqlite::Result<Vec<User>> {
    let mut statement = conn.prepare("SELECT id, email, role, disabled FROM users ORDER BY id")?;
    let rows = statement.query_map([], user_from_row)?;
    rows.collect()
}

fn load_in(conn: &Connection, id: i64) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        "SELECT id, email, role, disabled FROM users WHERE id = ?1",
        params![id],
        user_from_row,
    )
    .optional()
}

async fn load(state: &AppState, id: i64) -> Result<Option<User>, DbError> {
    state.db.call(move |conn| load_in(conn, id)).await
}

/// One transaction: the role changes unless the target is the owner or the role is not valid.
fn set_role_in(
    conn: &mut Connection,
    id: i64,
    role: &str,
    actor: &SessionUser,
    now: i64,
) -> rusqlite::Result<RoleVerdict> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(target) = load_in(&tx, id)? else {
        return Ok(RoleVerdict::Missing);
    };
    if target.role == OWNER {
        return Ok(RoleVerdict::Owner);
    }
    if role != "admin" && role != "user" {
        return Ok(RoleVerdict::BadRole);
    }
    tx.execute(
        "UPDATE users SET role = ?1 WHERE id = ?2",
        params![role, id],
    )?;
    let detail = format!("role of {} set to {role}", target.email);
    let changed = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        detail: &detail,
        ..Default::default()
    };
    audit::record(&tx, now, &changed)?;
    tx.commit()?;
    Ok(RoleVerdict::Done)
}

/// One transaction: the target is read, the owner is refused, an admin may act only on plain
/// users, and then the change and its activity row are written together.
fn change_in(
    conn: &mut Connection,
    id: i64,
    action: Action,
    actor: &SessionUser,
    now: i64,
) -> rusqlite::Result<Verdict> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(target) = load_in(&tx, id)? else {
        return Ok(Verdict::Missing);
    };
    if target.role == OWNER {
        return Ok(Verdict::Owner);
    }
    if actor.role != Role::Owner && target.role != "user" {
        return Ok(Verdict::Forbidden);
    }
    let detail = match action {
        Action::Disable => {
            tx.execute("UPDATE users SET disabled = 1 WHERE id = ?1", params![id])?;
            session::revoke_all(&tx, id)?;
            format!("disabled {}", target.email)
        }
        Action::Enable => {
            tx.execute("UPDATE users SET disabled = 0 WHERE id = ?1", params![id])?;
            format!("enabled {}", target.email)
        }
        Action::Delete => {
            session::revoke_all(&tx, id)?;
            tx.execute("DELETE FROM users WHERE id = ?1", params![id])?;
            format!("deleted {}", target.email)
        }
    };
    let changed = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        detail: &detail,
        ..Default::default()
    };
    audit::record(&tx, now, &changed)?;
    tx.commit()?;
    Ok(Verdict::Done)
}

/// One transaction: the user must exist and every posted server must exist; the user's servers
/// become exactly the posted set and the activity row is written with them.
fn assign_servers_in(
    conn: &mut Connection,
    id: i64,
    ids: Option<Vec<i64>>,
    actor: &SessionUser,
    now: i64,
) -> rusqlite::Result<AssignVerdict> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(target) = load_in(&tx, id)? else {
        return Ok(AssignVerdict::Missing);
    };
    let Some(mut ids) = ids else {
        return Ok(AssignVerdict::BadValue);
    };
    for server_id in &ids {
        if !servers::server_exists(&tx, *server_id)? {
            return Ok(AssignVerdict::BadValue);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    for (user_id, server_id) in servers::set_assignments(&tx, Scope::User(id), &ids)? {
        families::revoke_pair(&tx, user_id, server_id, now)?;
    }
    let detail = format!(
        "assignments of {} set to {} servers",
        target.email,
        ids.len()
    );
    let changed = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        detail: &detail,
        ..Default::default()
    };
    audit::record(&tx, now, &changed)?;
    tx.commit()?;
    Ok(AssignVerdict::Done)
}

/// The user page. An error is shown with the status it is answered with.
async fn user_page(
    state: &AppState,
    viewer: &Viewer,
    id: i64,
    status: StatusCode,
    error: Option<&str>,
) -> Response {
    let user = match load(state, id).await {
        Ok(Some(user)) => user,
        Ok(None) => return not_found(),
        Err(_) => return internal_error(),
    };
    let loaded = state
        .db
        .call(move |conn| {
            let choices = servers::server_choices(conn, id)?;
            let tools = effective_in(conn, id, &choices)?;
            Ok((choices, tools))
        })
        .await;
    match loaded {
        Ok((choices, tools)) => {
            let nav = panel_nav(viewer, "/admin/users");
            form_page(viewer, status, "user", "User", |csrf| {
                html! {
                    (nav)
                    (user_body(csrf, viewer, &user, &choices, &tools, error))
                }
            })
        }
        Err(_) => internal_error(),
    }
}

/// The tools of the user's assigned servers, from each cached list, with the verdict of the rules.
fn effective_in(
    conn: &Connection,
    user_id: i64,
    choices: &[ServerChoice],
) -> rusqlite::Result<Vec<Effective>> {
    let mut tools = Vec::new();
    for choice in choices.iter().filter(|choice| choice.assigned) {
        let rules = policy::load(conn, user_id, choice.id)?;
        for name in catalog::names(conn, choice.id)? {
            let verdict = policy::decide(&rules, user_id, choice.id, &name);
            tools.push(Effective {
                server: choice.slug.clone(),
                tool: name,
                verdict: if verdict.allowed { "allow" } else { "deny" },
                rule: verdict.rule.map(|id| id.to_string()).unwrap_or_default(),
            });
        }
    }
    Ok(tools)
}

/// The role form and the action forms appear only where the viewer may use them. The csrf
/// field is always on the page, so every form action can be posted from it.
fn user_body(
    csrf: &str,
    viewer: &Viewer,
    user: &User,
    choices: &[ServerChoice],
    tools: &[Effective],
    error: Option<&str>,
) -> Markup {
    let owner_target = user.role == OWNER;
    let may_set_role = viewer.is_owner() && !owner_target;
    let may_act = !owner_target && (viewer.is_owner() || user.role == "user");
    let status = if user.disabled { "disabled" } else { "active" };
    let path = format!("/admin/users/{}", user.id);
    html! {
        h1 { (user.email) }
        input type="hidden" name="csrf" value=(csrf);
        @if let Some(message) = error {
            p.error { (message) }
        }
        p { "Role: " (user.role) }
        p { "Status: " (status) }
        p {
            a href=(format!("/admin/activity?user={}", user.id)) data-link="activity" { "Activity" }
        }
        h2 { "Servers" }
        form method="post" action=(format!("{path}/servers")) {
            input type="hidden" name="csrf" value=(csrf);
            @for choice in choices {
                label {
                    input type="checkbox" name="server_id" value=(choice.id) checked[choice.assigned];
                    " " (choice.name) " (" (choice.slug) ")"
                }
            }
            button type="submit" { "Save servers" }
        }
        h2 { "Tools" }
        ul.tools {
            @for tool in tools {
                li data-server=(tool.server) data-tool=(tool.tool) data-verdict=(tool.verdict)
                    data-rule=(tool.rule) {
                    (tool.server) " " (tool.tool) ": " (tool.verdict)
                }
            }
        }
        @if may_set_role {
            form method="post" action=(format!("{path}/role")) {
                input type="hidden" name="csrf" value=(csrf);
                label for="user-role" { "Role" }
                select id="user-role" name="role" {
                    option value="admin" selected[user.role == "admin"] { "Admin" }
                    option value="user" selected[user.role == "user"] { "User" }
                }
                button type="submit" { "Save role" }
            }
        }
        @if may_act {
            @if user.disabled {
                form method="post" action=(format!("{path}/enable")) {
                    input type="hidden" name="csrf" value=(csrf);
                    button type="submit" { "Enable account" }
                }
            } @else {
                form method="post" action=(format!("{path}/disable")) {
                    input type="hidden" name="csrf" value=(csrf);
                    button type="submit" { "Disable account" }
                }
            }
            form method="post" action=(format!("{path}/delete")) {
                input type="hidden" name="csrf" value=(csrf);
                button type="submit" { "Delete account" }
            }
        }
    }
}

fn users_page(viewer: &Viewer, rows: &[User]) -> Response {
    page(
        StatusCode::OK,
        "users",
        "Users",
        html! {
            (panel_nav(viewer, "/admin/users"))
            h1 { "Users" }
            ul.users {
                @for user in rows {
                    li data-user-id=(user.id) data-email=(user.email) {
                        p { a href=(format!("/admin/users/{}", user.id)) { (user.email) } }
                        p {
                            (user.role) " "
                            @if user.disabled { "disabled" } @else { "active" }
                        }
                    }
                }
            }
        },
    )
}
