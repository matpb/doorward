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
use crate::vault::keys;
use crate::web::{
    MainData, Role, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with, internal_error,
    not_found, page_with, redirect, ui,
};

use super::panel_nav;

const OWNER: &str = "owner";
const OWNER_MESSAGE: &str = "The owner account cannot be changed this way.";
const ROLE_MESSAGE: &str = "Choose the role admin or user.";
pub(super) const SERVER_MESSAGE: &str = "Choose only servers that exist.";

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
        Err(err) => internal_error("users page", &err),
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
        Err(err) => internal_error("user role", &err),
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
    let ids = server_ids(&form);
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
        Err(err) => internal_error("user servers", &err),
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
        Err(err) => internal_error("user action", &err),
    }
}

/// An id from the path. Anything that is not a number is no user.
pub(super) fn parse_id(text: &str) -> Option<i64> {
    text.parse::<i64>().ok()
}

/// The posted `server_id` values as ids; None when one of them is not a number.
pub(super) fn server_ids(form: &VerifiedForm) -> Option<Vec<i64>> {
    form.fields
        .all("server_id")
        .iter()
        .map(|value| parse_id(value))
        .collect::<Option<Vec<i64>>>()
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

/// A user of the list with the number of servers assigned to them.
struct Listed {
    user: User,
    servers: i64,
}

/// Every user with the count of assigned servers, in one query, oldest first.
fn list_in(conn: &Connection) -> rusqlite::Result<Vec<Listed>> {
    let mut statement = conn.prepare(
        "SELECT id, email, role, disabled, \
         (SELECT COUNT(*) FROM user_servers WHERE user_servers.user_id = users.id) \
         FROM users ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(Listed {
            user: user_from_row(row)?,
            servers: row.get(4)?,
        })
    })?;
    rows.collect()
}

/// How many accounts are disabled: the flag the users list shows as Disabled.
pub(super) fn disabled_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM users WHERE disabled <> 0",
        [],
        |row| row.get(0),
    )
}

/// The account status as a pill: Active in ok, Disabled in muted.
fn status_pill(disabled: bool) -> Markup {
    if disabled {
        ui::pill("muted", "Disabled")
    } else {
        ui::pill("ok", "Active")
    }
}

/// The verdict of a tool as a pill: Allow in ok, Deny in bad.
fn verdict_pill(verdict: &str) -> Markup {
    if verdict == "allow" {
        ui::pill("ok", "Allow")
    } else {
        ui::pill("bad", "Deny")
    }
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

/// Deletes the unused invitations the user made, so that they stop working with the user's access.
fn revoke_invitations(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM invitations WHERE invited_by = ?1", params![id])?;
    Ok(())
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
    if role != "admin" {
        revoke_invitations(&tx, id)?;
    }
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
            revoke_invitations(&tx, id)?;
            format!("disabled {}", target.email)
        }
        Action::Enable => {
            tx.execute("UPDATE users SET disabled = 0 WHERE id = ?1", params![id])?;
            format!("enabled {}", target.email)
        }
        Action::Delete => {
            session::revoke_all(&tx, id)?;
            revoke_invitations(&tx, id)?;
            servers::record_removed_charts(&tx, actor, now, servers::Owner::User, id)?;
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
        keys::release(&tx, server_id, Some(user_id), None, now, true)?;
    }
    let noun = if ids.len() == 1 { "server" } else { "servers" };
    let detail = format!(
        "assignments of {} set to {} {noun}",
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
        Err(err) => return internal_error("user page", &err),
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
            let data = MainData {
                nav: panel_nav(viewer, "/admin/users"),
                ..MainData::default()
            };
            form_page_with(viewer, status, "user", "User", &data, |csrf| {
                html! {
                    (user_body(csrf, viewer, &user, &choices, &tools, error))
                }
            })
        }
        Err(err) => internal_error("user page", &err),
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
    let path = format!("/admin/users/{}", user.id);
    let role_field = error.filter(|message| *message == ROLE_MESSAGE);
    let role_note = ui::note_under(role_field, None);
    let role_described = role_note.describer("user-role");
    let assigned = choices.iter().filter(|choice| choice.assigned).count();
    // The filled button is the submit of the first form: the role form when there is one.
    let servers_kind = if may_set_role { "secondary" } else { "primary" };
    html! {
        div.page-head {
            p.crumb { a href="/admin/users" { "Users" } }
            h1.title-id { (ui::email(&user.email)) }
            p.meta {
                span { "Role " (user.role) }
                (status_pill(user.disabled))
            }
            div.head-actions {
                a.button data-kind="secondary" href=(format!("/admin/activity?user={}", user.id)) data-link="activity" { "Activity" }
            }
        }
        @if let Some(message) = error {
            (ui::refused(None, message, role_field.map(|_| ("user-role", "role"))))
        }
        section.part aria-labelledby="role-title" {
            div.part-head {
                h2 id="role-title" { "Role and status" }
                p { "An admin can change servers, rules and people. A disabled account cannot sign in." }
            }
            div.part-body.flow {
                @if may_set_role {
                    form.flow method="post" action=(format!("{path}/role")) {
                        input type="hidden" name="csrf" value=(csrf);
                        div.fields data-cols="2" {
                            (ui::field(
                                "user-role",
                                "Role",
                                false,
                                html! {
                                    select id="user-role" name="role" aria-invalid=[ui::invalid(role_field)] aria-describedby=[role_described.as_deref()] {
                                        option value="admin" selected[user.role == "admin"] { "Admin" }
                                        option value="user" selected[user.role == "user"] { "User" }
                                    }
                                },
                                role_note,
                            ))
                        }
                        div.form-actions {
                            button type="submit" data-kind="primary" { "Save role" }
                        }
                    }
                }
                dl.facts {
                    dt { "Status" }
                    dd { (status_pill(user.disabled)) }
                }
                @if may_act {
                    form.form-actions method="post" action=(format!("{path}/{}", if user.disabled { "enable" } else { "disable" })) {
                        input type="hidden" name="csrf" value=(csrf);
                        @if user.disabled {
                            button type="submit" data-kind="secondary" { "Enable account" }
                        } @else {
                            button type="submit" data-kind="secondary" { "Disable account" }
                        }
                    }
                }
            }
        }
        section.part aria-labelledby="user-servers-title" {
            div.part-head {
                h2 id="user-servers-title" { "Servers " span.count { (assigned) " of " (choices.len()) } }
                p { "The servers this person may reach." }
            }
            div.part-body {
                form.flow method="post" action=(format!("{path}/servers")) {
                    input type="hidden" name="csrf" value=(csrf);
                    div.checks {
                        @for choice in choices {
                            (server_check(choice))
                        }
                    }
                    div.form-actions {
                        button type="submit" data-kind=(servers_kind) { "Save servers" }
                    }
                }
            }
        }
        section.part aria-labelledby="user-tools-title" {
            div.part-head {
                h2 id="user-tools-title" { "Tools" }
                p { "What the rules decide for this person, tool by tool." }
            }
            div.part-body {
                table.list.tools {
                    thead {
                        tr {
                            th scope="col" class="c-effect" { "Verdict" }
                            th scope="col" { "Tool" }
                            th scope="col" class="c-server" { "Server" }
                        }
                    }
                    tbody {
                        @for tool in tools {
                            (tool_row(tool))
                        }
                    }
                }
            }
        }
        @if may_act {
            section.part aria-labelledby="user-delete-title" {
                div.part-head {
                    h2 id="user-delete-title" { "Delete" }
                    p { "Removes the account from the gateway." }
                }
                div.part-body {
                    details.confirm data-confirm {
                        summary {
                            span.confirm-open { "Delete this account " span.chevron aria-hidden="true" {} }
                            " "
                            span.confirm-note { "This cannot be undone." }
                        }
                        div.confirm-body {
                            p { "This cannot be undone." }
                            form method="post" action=(format!("{path}/delete")) {
                                input type="hidden" name="csrf" value=(csrf);
                                button type="submit" data-kind="danger" { "Delete account" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One server as a checkbox: its name, then its path in code; checked when the user may reach it.
pub(super) fn server_check(choice: &ServerChoice) -> Markup {
    let value = choice.id.to_string();
    let label = html! {
        span.check-name { (choice.name) }
        " "
        code { (choice.slug) }
    };
    ui::check(
        &format!("server-{}", choice.id),
        "server_id",
        Some(&value),
        choice.assigned,
        label,
        None,
    )
}

/// One tool of the user's servers: its verdict, the tool name and the server it is on.
fn tool_row(tool: &Effective) -> Markup {
    html! {
        tr data-server=(tool.server) data-tool=(tool.tool) data-verdict=(tool.verdict) data-rule=(tool.rule) {
            td.half { (verdict_pill(tool.verdict)) }
            td.lead { code { (ui::breakable(&tool.tool)) } }
            td.half { "on " span.whole { code { (tool.server) } } }
        }
    }
}

fn users_page(viewer: &Viewer, rows: &[Listed]) -> Response {
    let data = MainData {
        nav: panel_nav(viewer, "/admin/users"),
        ..MainData::default()
    };
    page_with(StatusCode::OK, "users", "Users", &data, users_body(rows))
}

fn users_body(rows: &[Listed]) -> Markup {
    html! {
        div.page-head {
            h1 { "Users" }
            div.head-actions {
                a.button data-kind="secondary" href="/admin/invitations#add" { "Invite someone" }
            }
        }
        table.list.users {
            thead {
                tr {
                    th scope="col" { "Email" }
                    th scope="col" class="c-role" { "Role" }
                    th scope="col" class="c-num num" { "Servers" }
                    th scope="col" class="c-state" { "Status" }
                }
            }
            tbody {
                @for row in rows {
                    (user_row(row))
                }
            }
        }
    }
}

/// One user of the list: the address, the role, the number of servers and the status.
fn user_row(row: &Listed) -> Markup {
    html! {
        tr data-user-id=(row.user.id) data-email=(row.user.email) {
            td.lead {
                a.name href=(format!("/admin/users/{}", row.user.id)) { (ui::email(&row.user.email)) }
            }
            td.half { (row.user.role) }
            td.num.half data-server-count { (ui::count_with_unit(row.servers, "server", "servers")) }
            td { (status_pill(row.user.disabled)) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_of_a_tool_sits_in_a_whole_span_as_code() {
        let tool = Effective {
            server: "github".to_owned(),
            tool: "create_pull_request".to_owned(),
            verdict: "allow",
            rule: String::new(),
        };
        let markup = tool_row(&tool).into_string();
        assert!(
            markup.contains(
                r#"<td class="half">on <span class="whole"><code>github</code></span></td>"#
            ),
            "the server cell must wrap its code in span.whole: {markup}"
        );
    }
}
