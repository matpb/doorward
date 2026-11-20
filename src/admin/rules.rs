//! The tool rules page: the rules, the add form, and the delete of one rule.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::proxy::catalog;
use crate::servers::{self, ServerRef};
use crate::web::{
    SessionUser, VerifiedForm, Viewer, forbidden, form_page, internal_error, redirect,
};

use super::panel_nav;
use super::users::parse_id;

const EFFECT: &str = "Choose the effect allow or deny.";
const SCOPE: &str = "Choose the scope all tools, one server or one tool.";
const SUBJECT: &str = "Choose everyone or a user that exists.";
const SERVER: &str = "A server or tool rule needs a server that exists.";
const TOOL: &str = "A tool rule needs the tool name.";
const UNLISTED: &str = "The server's tool list has no tool with that name.";
const DUPLICATE: &str = "A rule for that subject and target already exists.";

/// One stored rule as the page shows it. `server` and `tool` are None when the rule has none.
struct Stored {
    id: i64,
    subject: String,
    effect: String,
    server_id: Option<i64>,
    server: Option<String>,
    tool: Option<String>,
    stale: bool,
}

impl Stored {
    fn scope(&self) -> &'static str {
        if self.tool.is_some() {
            "tool"
        } else if self.server_id.is_some() {
            "server"
        } else {
            "all"
        }
    }

    /// The rule as a sentence: its subject, its effect and its target.
    fn text(&self) -> String {
        let target = match (self.server.as_deref(), self.tool.as_deref()) {
            (Some(server), Some(tool)) => format!("tool {tool} on server {server}"),
            (Some(server), None) => format!("server {server}"),
            _ => "all tools".to_owned(),
        };
        format!("{} {} {target}", self.subject, self.effect)
    }
}

/// The posted add form as text, before it is checked.
struct Draft {
    subject: String,
    effect: String,
    scope: String,
    server_id: String,
    tool: String,
}

/// A draft that passed the checks, ready to store.
struct Checked {
    user_id: Option<i64>,
    effect: &'static str,
    server_id: Option<i64>,
    tool: Option<String>,
}

/// The outcome of an add, decided inside its transaction.
enum Added {
    Done,
    Refused(&'static str),
}

/// The page with its rules, the add form and any refusal.
pub async fn get_rules(viewer: Viewer, State(state): State<AppState>) -> Response {
    rules_page(&state, &viewer, StatusCode::OK, None).await
}

/// Adds a rule. A refused draft answers 400 with the rules page and stores nothing.
pub async fn post_add(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let draft = Draft {
        subject: form.fields.get("subject").to_owned(),
        effect: form.fields.get("effect").to_owned(),
        scope: form.fields.get("scope").to_owned(),
        server_id: form.fields.get("server_id").to_owned(),
        tool: form.fields.get("tool").to_owned(),
    };
    let at = state.clock.now().unix_timestamp();
    let added = state
        .db
        .call(move |conn| add_in(conn, &actor, &draft, at))
        .await;
    match added {
        Ok(Added::Done) => redirect("/admin/rules"),
        Ok(Added::Refused(message)) => {
            rules_page(&state, &form.viewer, StatusCode::BAD_REQUEST, Some(message)).await
        }
        Err(err) => internal_error("rule add", &err),
    }
}

/// Deletes a rule. An unknown id answers the same redirect and changes nothing.
pub async fn post_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return redirect("/admin/rules");
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| delete_in(conn, &actor, id, at))
        .await
    {
        Ok(()) => redirect("/admin/rules"),
        Err(err) => internal_error("rule delete", &err),
    }
}

/// Checks the draft in the order effect, scope, subject, server, tool, tool list, duplicate.
fn check(conn: &Connection, draft: &Draft) -> rusqlite::Result<Result<Checked, &'static str>> {
    let effect = match draft.effect.as_str() {
        "allow" => "allow",
        "deny" => "deny",
        _ => return Ok(Err(EFFECT)),
    };
    if !matches!(draft.scope.as_str(), "all" | "server" | "tool") {
        return Ok(Err(SCOPE));
    }
    let user_id = if draft.subject == "everyone" {
        None
    } else {
        let Some(id) = parse_id(&draft.subject) else {
            return Ok(Err(SUBJECT));
        };
        if !servers::user_exists(conn, id)? {
            return Ok(Err(SUBJECT));
        }
        Some(id)
    };
    let server_id = if draft.scope == "all" {
        None
    } else {
        let Some(id) = parse_id(&draft.server_id) else {
            return Ok(Err(SERVER));
        };
        if !servers::server_exists(conn, id)? {
            return Ok(Err(SERVER));
        }
        Some(id)
    };
    let tool = match draft.scope.as_str() {
        "tool" if draft.tool.is_empty() => return Ok(Err(TOOL)),
        "tool" => Some(draft.tool.clone()),
        _ => None,
    };
    let listed = match (server_id, tool.as_deref()) {
        (Some(server), Some(name)) => catalog::names(conn, server)?
            .iter()
            .any(|known| known == name),
        _ => true,
    };
    if !listed {
        return Ok(Err(UNLISTED));
    }
    let taken: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM rules WHERE COALESCE(user_id, 0) = ?1 \
         AND COALESCE(server_id, 0) = ?2 AND COALESCE(tool, '') = ?3)",
        params![
            user_id.unwrap_or(0),
            server_id.unwrap_or(0),
            tool.as_deref().unwrap_or("")
        ],
        |row| row.get(0),
    )?;
    if taken {
        return Ok(Err(DUPLICATE));
    }
    Ok(Ok(Checked {
        user_id,
        effect,
        server_id,
        tool,
    }))
}

/// One transaction: the draft is checked, the rule is written and the change is recorded.
fn add_in(
    conn: &mut Connection,
    actor: &SessionUser,
    draft: &Draft,
    at: i64,
) -> rusqlite::Result<Added> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let checked = match check(&tx, draft)? {
        Ok(checked) => checked,
        Err(message) => return Ok(Added::Refused(message)),
    };
    tx.execute(
        "INSERT INTO rules (user_id, effect, server_id, tool, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            checked.user_id,
            checked.effect,
            checked.server_id,
            checked.tool,
            at
        ],
    )?;
    let id = tx.last_insert_rowid();
    let stored = rules_in(&tx, Some(id))?
        .into_iter()
        .next()
        .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    record(
        &tx,
        at,
        actor,
        &format!("added rule {id}: {}", stored.text()),
    )?;
    tx.commit()?;
    Ok(Added::Done)
}

/// One transaction: a stored rule is removed and the removal is recorded; an unknown id changes nothing.
fn delete_in(conn: &mut Connection, actor: &SessionUser, id: i64, at: i64) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(stored) = rules_in(&tx, Some(id))?.into_iter().next() else {
        return Ok(());
    };
    tx.execute("DELETE FROM rules WHERE id = ?1", params![id])?;
    record(
        &tx,
        at,
        actor,
        &format!("deleted rule {id}: {}", stored.text()),
    )?;
    tx.commit()
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

/// The stored rules, oldest first; `only` reads just the rule with that id.
fn rules_in(conn: &Connection, only: Option<i64>) -> rusqlite::Result<Vec<Stored>> {
    let mut statement = conn.prepare(
        "SELECT rules.id, COALESCE(users.email, 'everyone'), rules.effect, rules.server_id, \
         servers.slug, rules.tool, \
         rules.tool IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tool_catalog \
         WHERE tool_catalog.server_id = rules.server_id AND tool_catalog.name = rules.tool) \
         FROM rules LEFT JOIN users ON users.id = rules.user_id \
         LEFT JOIN servers ON servers.id = rules.server_id \
         WHERE ?1 IS NULL OR rules.id = ?1 ORDER BY rules.id",
    )?;
    let rows = statement.query_map(params![only], |row| {
        Ok(Stored {
            id: row.get(0)?,
            subject: row.get(1)?,
            effect: row.get(2)?,
            server_id: row.get(3)?,
            server: row.get(4)?,
            tool: row.get(5)?,
            stale: row.get(6)?,
        })
    })?;
    rows.collect()
}

/// Every stored tool with its server's path, by path then name, for the tool name choice.
fn tools_in(conn: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
    let mut statement = conn.prepare(
        "SELECT servers.slug, tool_catalog.name FROM tool_catalog \
         JOIN servers ON servers.id = tool_catalog.server_id \
         ORDER BY servers.slug, tool_catalog.name",
    )?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

/// Every user as an id and an email, for the subject choice.
fn users_in(conn: &Connection) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut statement = conn.prepare("SELECT id, email FROM users ORDER BY id")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

async fn rules_page(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    refused: Option<&str>,
) -> Response {
    let loaded = state
        .db
        .call(|conn| {
            Ok((
                rules_in(conn, None)?,
                users_in(conn)?,
                servers::list(conn)?,
                tools_in(conn)?,
            ))
        })
        .await;
    match loaded {
        Ok((rules, users, server_list, tools)) => {
            let nav = panel_nav(viewer, "/admin/rules");
            form_page(viewer, status, "rules", "Rules", |csrf| {
                html! {
                    (nav)
                    (rules_body(csrf, &rules, &users, &server_list, &tools, refused))
                }
            })
        }
        Err(err) => internal_error("rules page", &err),
    }
}

fn rules_body(
    csrf: &str,
    rules: &[Stored],
    users: &[(i64, String)],
    servers: &[ServerRef],
    tools: &[(String, String)],
    refused: Option<&str>,
) -> Markup {
    html! {
        h1 { "Rules" }
        p { "A deny stands unless an allow is at least as specific in scope and subject, and more specific in one." }
        @if let Some(message) = refused {
            p.error { (message) }
        }
        h2 { "Stored rules" }
        ul.rules {
            @for rule in rules {
                li data-rule-id=(rule.id) data-subject=(rule.subject) data-effect=(rule.effect)
                    data-scope=(rule.scope()) data-server=(rule.server.as_deref().unwrap_or(""))
                    data-tool=(rule.tool.as_deref().unwrap_or(""))
                    data-stale=(yes_or_no(rule.stale)) {
                    p { (rule.text()) }
                    @if rule.stale {
                        p { "The tool is not in the server's tool list." }
                    }
                    form method="post" action=(format!("/admin/rules/{}/delete", rule.id)) {
                        input type="hidden" name="csrf" value=(csrf);
                        button type="submit" { "Delete rule" }
                    }
                }
            }
        }
        h2 { "Add a rule" }
        form method="post" action="/admin/rules" {
            input type="hidden" name="csrf" value=(csrf);
            label for="rule-subject" { "Subject" }
            select id="rule-subject" name="subject" {
                option value="everyone" { "Everyone" }
                @for (id, email) in users {
                    option value=(id) { (email) }
                }
            }
            label for="rule-effect" { "Effect" }
            select id="rule-effect" name="effect" {
                option value="allow" { "Allow" }
                option value="deny" { "Deny" }
            }
            label for="rule-scope" { "Scope" }
            select id="rule-scope" name="scope" {
                option value="all" { "All tools" }
                option value="server" { "One server" }
                option value="tool" { "One tool" }
            }
            label for="rule-server" { "Server (for scope server or tool)" }
            select id="rule-server" name="server_id" {
                @for server in servers {
                    option value=(server.id) { (server.name) " (" (server.slug) ")" }
                }
            }
            label for="rule-tool" { "Tool name (for scope one tool)" }
            input id="rule-tool" name="tool" type="text" list="rule-tools";
            datalist id="rule-tools" {
                @for (slug, tool) in tools {
                    option value=(tool) label=(slug);
                }
            }
            button type="submit" { "Add rule" }
        }
    }
}

fn yes_or_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}
