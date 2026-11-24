//! The plan of a pending invitation: the servers and the personal rules its person gets on accept.

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::app::AppState;
use crate::servers::{self, ServerChoice, ServerRef};
use crate::web::{
    MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with, internal_error,
    not_found, redirect, ui,
};

use super::activity::plain_time;
use super::invitations::rfc3339;
use super::panel_nav;
use super::rules::{self, Stored};
use super::users::{SERVER_MESSAGE, parse_id, server_check, server_ids};

const SERVERS_REFUSED: &str = "The servers were not saved.";
const RULE_REFUSED: &str = "The rule was not added.";

/// An open invitation as its plan page shows it.
struct Open {
    id: i64,
    email: String,
    role: String,
    expires: String,
    /// The same instant as the activity page writes it, `D Mon YYYY HH:MM:SS UTC`.
    expires_plain: String,
}

/// What the plan page shows, read in one call.
struct Loaded {
    invitation: Open,
    /// The ids of the servers the plan holds.
    assigned: Vec<i64>,
    servers: Vec<ServerRef>,
    /// The id of the server the rule form picks.
    picked: Option<i64>,
    rules: Vec<Stored>,
    tools: Vec<String>,
}

/// A posted rule as text, before it is checked.
#[derive(Clone)]
struct RuleDraft {
    effect: String,
    scope: String,
    server_id: String,
    tool: String,
}

/// A refused form of the plan page: its message and what was posted, shown again.
enum Refusal<'a> {
    Servers {
        message: &'a str,
        ticked: &'a [i64],
    },
    Rule {
        message: &'a str,
        draft: &'a RuleDraft,
    },
}

/// The outcome of a change to the plan, decided inside its transaction.
enum Verdict {
    Missing,
    Forbidden,
    Refused(&'static str),
    Done,
}

/// The outcome of deleting a rule of the plan.
enum Removed {
    Missing,
    Forbidden,
    Done,
}

/// The plan page of an open invitation. An invitation that is not open is not found.
pub async fn get_plan(
    viewer: Viewer,
    State(state): State<AppState>,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let server = rules::server_param(query.as_deref());
    plan_page(&state, &viewer, id, StatusCode::OK, None, server).await
}

/// Replaces the servers of the plan with the posted set. An unknown server is refused with 400.
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
    let ticked = ids.clone().unwrap_or_default();
    let now = state.clock.now().unix_timestamp();
    let owner = form.viewer.is_owner();
    let verdict = state
        .db
        .call(move |conn| set_servers_in(conn, id, owner, ids, &actor, now))
        .await;
    match verdict {
        Ok(Verdict::Done) => redirect(&plan_path(id)),
        Ok(Verdict::Missing) => not_found(),
        Ok(Verdict::Forbidden) => forbidden(),
        Ok(Verdict::Refused(message)) => {
            let refusal = Refusal::Servers {
                message,
                ticked: &ticked,
            };
            plan_page(
                &state,
                &form.viewer,
                id,
                StatusCode::BAD_REQUEST,
                Some(refusal),
                None,
            )
            .await
        }
        Err(err) => internal_error("invitation servers", &err),
    }
}

/// Adds a rule to the plan. A refused rule answers 400 with the plan page and the draft shown again.
pub async fn post_rule(
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
    let draft = RuleDraft {
        effect: form.fields.get("effect").to_owned(),
        scope: form.fields.get("scope").to_owned(),
        server_id: form.fields.get("server_id").to_owned(),
        tool: form.fields.get("tool").to_owned(),
    };
    let posted = draft.clone();
    let now = state.clock.now().unix_timestamp();
    let owner = form.viewer.is_owner();
    let verdict = state
        .db
        .call(move |conn| add_rule_in(conn, id, owner, &actor, &draft, now))
        .await;
    match verdict {
        Ok(Verdict::Done) => redirect(&plan_path(id)),
        Ok(Verdict::Missing) => not_found(),
        Ok(Verdict::Forbidden) => forbidden(),
        Ok(Verdict::Refused(message)) => {
            let refusal = Refusal::Rule {
                message,
                draft: &posted,
            };
            plan_page(
                &state,
                &form.viewer,
                id,
                StatusCode::BAD_REQUEST,
                Some(refusal),
                None,
            )
            .await
        }
        Err(err) => internal_error("invitation rule add", &err),
    }
}

/// Deletes a rule of the plan. A rule of another invitation is not found.
pub async fn post_rule_delete(
    State(state): State<AppState>,
    Path((id, rule)): Path<(String, String)>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let (Some(id), Some(rule)) = (parse_id(&id), parse_id(&rule)) else {
        return not_found();
    };
    let now = state.clock.now().unix_timestamp();
    let owner = form.viewer.is_owner();
    let removed = state
        .db
        .call(move |conn| delete_rule_in(conn, id, rule, owner, &actor, now))
        .await;
    match removed {
        Ok(Removed::Done) => redirect(&plan_path(id)),
        Ok(Removed::Missing) => not_found(),
        Ok(Removed::Forbidden) => forbidden(),
        Err(err) => internal_error("invitation rule delete", &err),
    }
}

fn plan_path(id: i64) -> String {
    format!("/admin/invitations/{id}")
}

/// An admin may plan only the invitations of plain users; the owner may plan any.
fn may_plan(owner: bool, role: &str) -> bool {
    owner || role == "user"
}

/// The open invitation `id`: one whose expiry is after `now`.
fn open_in(conn: &Connection, id: i64, now: i64) -> rusqlite::Result<Option<Open>> {
    conn.query_row(
        "SELECT id, email, role, expires_at FROM invitations WHERE id = ?1 AND expires_at > ?2",
        params![id, now],
        |row| {
            let expires_at: i64 = row.get(3)?;
            Ok(Open {
                id: row.get(0)?,
                email: row.get(1)?,
                role: row.get(2)?,
                expires: rfc3339(expires_at)?,
                expires_plain: plain_time(expires_at)?,
            })
        },
    )
    .optional()
}

/// What the plan page shows for the open invitation `id`, its rule form picking the server `choice`
/// names; None when the invitation is not open.
fn plan_in(
    conn: &Connection,
    id: i64,
    now: i64,
    choice: Option<&str>,
) -> rusqlite::Result<Option<Loaded>> {
    let Some(invitation) = open_in(conn, id, now)? else {
        return Ok(None);
    };
    let mut statement = conn.prepare(
        "SELECT server_id FROM invitation_servers WHERE invitation_id = ?1 ORDER BY server_id",
    )?;
    let assigned = statement
        .query_map(params![id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<i64>>>()?;
    let servers = servers::list(conn)?;
    let picked = rules::picked_server(&servers, choice);
    Ok(Some(Loaded {
        rules: rules::plan_rules_in(conn, id, &invitation.email, None)?,
        tools: rules::suggested_tools(conn, picked)?,
        picked,
        servers,
        assigned,
        invitation,
    }))
}

/// One transaction: the invitation must be open and the viewer may plan it; the posted servers must
/// all exist, and then the plan's servers become exactly the posted set and the change is recorded.
fn set_servers_in(
    conn: &mut Connection,
    id: i64,
    owner: bool,
    ids: Option<Vec<i64>>,
    actor: &SessionUser,
    now: i64,
) -> rusqlite::Result<Verdict> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(open) = open_in(&tx, id, now)? else {
        return Ok(Verdict::Missing);
    };
    if !may_plan(owner, &open.role) {
        return Ok(Verdict::Forbidden);
    }
    let Some(mut ids) = ids else {
        return Ok(Verdict::Refused(SERVER_MESSAGE));
    };
    for server_id in &ids {
        if !servers::server_exists(&tx, *server_id)? {
            return Ok(Verdict::Refused(SERVER_MESSAGE));
        }
    }
    ids.sort_unstable();
    ids.dedup();
    tx.execute(
        "DELETE FROM invitation_servers WHERE invitation_id = ?1",
        params![id],
    )?;
    for server_id in &ids {
        tx.execute(
            "INSERT INTO invitation_servers (invitation_id, server_id) VALUES (?1, ?2)",
            params![id, server_id],
        )?;
    }
    let noun = if ids.len() == 1 { "server" } else { "servers" };
    let detail = format!(
        "invitation servers of {} set to {} {noun}",
        open.email,
        ids.len()
    );
    rules::record(&tx, now, actor, &detail)?;
    tx.commit()?;
    Ok(Verdict::Done)
}

/// One transaction: the invitation must be open and the viewer may plan it; the draft is checked in
/// the order of the Rules page, the rule is stored and the change is recorded.
fn add_rule_in(
    conn: &mut Connection,
    id: i64,
    owner: bool,
    actor: &SessionUser,
    draft: &RuleDraft,
    now: i64,
) -> rusqlite::Result<Verdict> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(open) = open_in(&tx, id, now)? else {
        return Ok(Verdict::Missing);
    };
    if !may_plan(owner, &open.role) {
        return Ok(Verdict::Forbidden);
    }
    let Some(effect) = rules::effect_of(&draft.effect) else {
        return Ok(Verdict::Refused(rules::EFFECT));
    };
    let Some(scope) = rules::scope_of(&draft.scope) else {
        return Ok(Verdict::Refused(rules::SCOPE));
    };
    let target = match rules::check_target(&tx, scope, &draft.server_id, &draft.tool)? {
        Ok(target) => target,
        Err(message) => return Ok(Verdict::Refused(message)),
    };
    let taken: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM invitation_rules WHERE invitation_id = ?1 \
         AND COALESCE(server_id, 0) = ?2 AND COALESCE(tool, '') = ?3)",
        params![
            id,
            target.server_id.unwrap_or(0),
            target.tool.as_deref().unwrap_or("")
        ],
        |row| row.get(0),
    )?;
    if taken {
        return Ok(Verdict::Refused(rules::DUPLICATE));
    }
    tx.execute(
        "INSERT INTO invitation_rules (invitation_id, effect, server_id, tool, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, effect, target.server_id, target.tool, now],
    )?;
    let rule = tx.last_insert_rowid();
    let stored = rules::plan_rules_in(&tx, id, &open.email, Some(rule))?
        .into_iter()
        .next()
        .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    let detail = format!("added invitation rule {rule}: {}", stored.text());
    rules::record(&tx, now, actor, &detail)?;
    tx.commit()?;
    Ok(Verdict::Done)
}

/// One transaction: the rule must belong to the open invitation and the viewer may plan it.
fn delete_rule_in(
    conn: &mut Connection,
    id: i64,
    rule: i64,
    owner: bool,
    actor: &SessionUser,
    now: i64,
) -> rusqlite::Result<Removed> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(open) = open_in(&tx, id, now)? else {
        return Ok(Removed::Missing);
    };
    if !may_plan(owner, &open.role) {
        return Ok(Removed::Forbidden);
    }
    let Some(stored) = rules::plan_rules_in(&tx, id, &open.email, Some(rule))?
        .into_iter()
        .next()
    else {
        return Ok(Removed::Missing);
    };
    tx.execute(
        "DELETE FROM invitation_rules WHERE id = ?1 AND invitation_id = ?2",
        params![rule, id],
    )?;
    let detail = format!("deleted invitation rule {rule}: {}", stored.text());
    rules::record(&tx, now, actor, &detail)?;
    tx.commit()?;
    Ok(Removed::Done)
}

/// The plan page with the open invitation's servers and rules, a refusal's posted values in place of
/// the stored ones. A refused rule picks the server it posted; otherwise `query` picks the server.
async fn plan_page(
    state: &AppState,
    viewer: &Viewer,
    id: i64,
    status: StatusCode,
    refusal: Option<Refusal<'_>>,
    query: Option<String>,
) -> Response {
    let choice = match refusal.as_ref() {
        Some(Refusal::Rule { draft, .. }) => Some(draft.server_id.clone()),
        _ => query,
    };
    let now = state.clock.now().unix_timestamp();
    let mut loaded = match state
        .db
        .call(move |conn| plan_in(conn, id, now, choice.as_deref()))
        .await
    {
        Ok(Some(loaded)) => loaded,
        Ok(None) => return not_found(),
        Err(err) => return internal_error("invitation plan", &err),
    };
    if !may_plan(viewer.is_owner(), &loaded.invitation.role) {
        return forbidden();
    }
    if let Some(Refusal::Servers { ticked, .. }) = refusal.as_ref() {
        loaded.assigned = ticked.to_vec();
    }
    let data = MainData {
        nav: panel_nav(viewer, "/admin/invitations"),
        ..MainData::default()
    };
    let title = loaded.invitation.email.clone();
    // The layout comes from the page kind: "invitations" is a panel kind, so the plan gets the panel.
    form_page_with(viewer, status, "invitations", &title, &data, |csrf| {
        plan_body(csrf, &loaded, refusal.as_ref())
    })
}

fn plan_body(csrf: &str, plan: &Loaded, refusal: Option<&Refusal<'_>>) -> Markup {
    let invitation = &plan.invitation;
    let path = plan_path(invitation.id);
    let servers_refused = match refusal {
        Some(Refusal::Servers { message, .. }) => Some(*message),
        _ => None,
    };
    let rule_refused = match refusal {
        Some(Refusal::Rule { message, .. }) => Some(*message),
        _ => None,
    };
    let draft = match refusal {
        Some(Refusal::Rule { draft, .. }) => Some(*draft),
        _ => None,
    };
    let effect = draft.map_or("", |draft| draft.effect.as_str());
    let scope = draft.map_or("", |draft| draft.scope.as_str());
    let picked_server = plan
        .servers
        .iter()
        .find(|server| Some(server.id) == plan.picked);
    let tool = draft.map(|draft| ui::sent_back(&draft.tool, ui::SENT_BACK_LIMIT));
    let assigned = plan
        .servers
        .iter()
        .filter(|server| plan.assigned.contains(&server.id))
        .count();
    html! {
        div.page-head {
            p.crumb { a href="/admin/invitations" { "Invitations" } }
            h1.title-id { (ui::email(&invitation.email)) }
            // The separators are no-break spaces before each dot, so a line never starts with one.
            p.meta {
                span {
                    "Pending invitation\u{a0}· Role " (invitation.role) "\u{a0}· Expires "
                    (ui::time_cell(&invitation.expires, &invitation.expires_plain, false))
                    " UTC"
                }
            }
        }
        @if let Some(message) = servers_refused {
            (ui::refused(Some(SERVERS_REFUSED), message, None))
        }
        @if let Some(message) = rule_refused {
            (ui::refused(Some(RULE_REFUSED), message, rules::refused_field(message)))
        }
        section.part aria-labelledby="plan-servers-title" {
            div.part-head {
                h2 id="plan-servers-title" { "Servers " span.count { (assigned) " of " (plan.servers.len()) } }
                p { "The servers this person reaches once they accept." }
            }
            div.part-body {
                form.flow method="post" action=(format!("{path}/servers")) {
                    input type="hidden" name="csrf" value=(csrf);
                    div.checks {
                        @for server in &plan.servers {
                            (server_check(&ServerChoice {
                                id: server.id,
                                name: server.name.clone(),
                                slug: server.slug.clone(),
                                assigned: plan.assigned.contains(&server.id),
                            }))
                        }
                    }
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Save servers" }
                    }
                }
            }
        }
        section.part aria-labelledby="plan-rules-title" {
            div.part-head {
                h2 id="plan-rules-title" { "Rules" }
                p { "Rules that apply to this person from their first sign-in. Rules for everyone already apply to them." }
            }
            div.part-body {
                @if plan.rules.is_empty() {
                    p.muted { "No rules for this person." }
                } @else {
                    table.list.rules {
                        thead {
                            tr {
                                th scope="col" class="c-rule" { "Rule" }
                                th scope="col" class="c-effect" { "Effect" }
                                th scope="col" { "Applies to" }
                                th scope="col" class="c-act" aria-label="Actions" {}
                            }
                        }
                        tbody {
                            @for rule in &plan.rules {
                                (plan_rule_row(csrf, &path, rule))
                            }
                        }
                    }
                }
            }
        }
        section.part id="add-rule" aria-labelledby="add-title" {
            div.part-head {
                h2 id="add-title" { "Add a rule" }
                p { "What the rule covers, and whether it lets the call through." }
            }
            div.part-body {
                (rules::server_picker(&format!("{path}#add-rule"), &plan.servers, plan.picked, rules::field_error(rule_refused, "rule-server")))
                form.flow method="post" action=(format!("{path}/rules")) {
                    input type="hidden" name="csrf" value=(csrf);
                    input type="hidden" name="server_id" value=[picked_server.map(|server| server.id.to_string())];
                    div.fields data-cols="2" {
                        (rules::effect_field(effect, rules::field_error(rule_refused, "rule-effect")))
                        (rules::scope_field(scope))
                    }
                    div.fields data-cols="2" {
                        (rules::chosen_server(picked_server))
                        (rules::tool_field(tool.as_deref(), rules::field_error(rule_refused, "rule-tool"), picked_server.map(|server| server.name.as_str())))
                    }
                    (rules::tool_datalist(picked_server, &plan.tools))
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Add rule" }
                    }
                }
            }
        }
        section.part aria-labelledby="plan-revoke-title" {
            div.part-head {
                h2 id="plan-revoke-title" { "Revoke" }
                p { "Their link stops working and this plan is deleted." }
            }
            div.part-body {
                details.confirm data-confirm {
                    summary {
                        span.confirm-open { "Revoke this invitation " span.chevron aria-hidden="true" {} }
                        " "
                        span.confirm-note { "This cannot be undone." }
                    }
                    div.confirm-body {
                        p { "This cannot be undone." }
                        form method="post" action=(format!("{path}/revoke")) {
                            input type="hidden" name="csrf" value=(csrf);
                            button type="submit" data-kind="danger" { "Revoke invitation" }
                        }
                    }
                }
            }
        }
    }
}

/// One rule of the plan: its number, its effect, what it applies to, and its delete button.
fn plan_rule_row(csrf: &str, path: &str, rule: &Stored) -> Markup {
    html! {
        tr data-rule-id=(rule.id) data-effect=(rule.effect) {
            td.half data-rule-number {
                span.unit { "Rule " }
                code { (rule.id) }
            }
            td.half { (rules::effect_pill(&rule.effect)) }
            td {
                (rules::target_markup(rule))
                @if rule.stale {
                    span.sub.state data-tone="warn" { "The tool is not in the server's tool list." }
                }
            }
            td.act {
                form method="post" action=(format!("{path}/rules/{}/delete", rule.id)) {
                    input type="hidden" name="csrf" value=(csrf);
                    button.row-action type="submit" data-kind="danger" { "Delete rule" }
                }
            }
        }
    }
}
