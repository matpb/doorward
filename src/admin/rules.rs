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
    MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with, internal_error,
    redirect, ui,
};

use super::panel_nav;
use super::users::parse_id;

pub(super) const EFFECT: &str = "Choose the effect allow or deny.";
pub(super) const SCOPE: &str = "Choose the scope all tools, one server or one tool.";
const SUBJECT: &str = "Choose everyone or a user that exists.";
pub(super) const SERVER: &str = "A server or tool rule needs a server that exists.";
pub(super) const TOOL: &str = "A tool rule needs the tool name.";
pub(super) const UNLISTED: &str = "The server's tool list has no tool with that name.";
pub(super) const DUPLICATE: &str = "A rule for that subject and target already exists.";

/// The scope a rule covers: all tools, one server, or one tool of a server.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleScope {
    All,
    Server,
    Tool,
}

/// The scope a posted value names; None for any other value.
pub(super) fn scope_of(text: &str) -> Option<RuleScope> {
    match text {
        "all" => Some(RuleScope::All),
        "server" => Some(RuleScope::Server),
        "tool" => Some(RuleScope::Tool),
        _ => None,
    }
}

/// The effect a posted value names; None for any other value.
pub(super) fn effect_of(text: &str) -> Option<&'static str> {
    match text {
        "allow" => Some("allow"),
        "deny" => Some("deny"),
        _ => None,
    }
}

/// The server and tool a rule covers. Each is None when the scope does not name it.
pub(super) struct Target {
    pub(super) server_id: Option<i64>,
    pub(super) tool: Option<String>,
}

/// Checks a posted target in the order server, tool name, tool list. A refusal is its message.
pub(super) fn check_target(
    conn: &Connection,
    scope: RuleScope,
    server_id: &str,
    tool: &str,
) -> rusqlite::Result<Result<Target, &'static str>> {
    let server_id = if scope == RuleScope::All {
        None
    } else {
        let Some(id) = parse_id(server_id) else {
            return Ok(Err(SERVER));
        };
        if !servers::server_exists(conn, id)? {
            return Ok(Err(SERVER));
        }
        Some(id)
    };
    let tool = match scope {
        RuleScope::Tool if tool.is_empty() => return Ok(Err(TOOL)),
        RuleScope::Tool => Some(tool.to_owned()),
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
    Ok(Ok(Target { server_id, tool }))
}

/// The message of a refused field that the page marks, None when a refusal is about no one field.
pub(super) fn field_error<'a>(message: Option<&'a str>, field: &str) -> Option<&'a str> {
    message.filter(|text| refused_field(text).is_some_and(|(id, _)| id == field))
}

/// One stored rule as the page shows it. `server` and `tool` are None when the rule has none.
pub(super) struct Stored {
    pub(super) id: i64,
    pub(super) subject: String,
    pub(super) effect: String,
    pub(super) server_id: Option<i64>,
    pub(super) server: Option<String>,
    pub(super) tool: Option<String>,
    pub(super) stale: bool,
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
    pub(super) fn text(&self) -> String {
        let target = match (self.server.as_deref(), self.tool.as_deref()) {
            (Some(server), Some(tool)) => format!("tool {tool} on server {server}"),
            (Some(server), None) => format!("server {server}"),
            _ => "all tools".to_owned(),
        };
        format!("{} {} {target}", self.subject, self.effect)
    }
}

/// The posted add form as text, before it is checked.
#[derive(Clone)]
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

/// A refused add form: its refusal and the draft as the person posted it.
struct Refusal<'a> {
    message: &'a str,
    draft: &'a Draft,
}

/// The page with its rules, the add form and any refusal.
pub async fn get_rules(viewer: Viewer, State(state): State<AppState>) -> Response {
    rules_page(&state, &viewer, StatusCode::OK, None).await
}

/// Adds a rule. A refused draft answers 400 with the rules page, the draft shown again, and stores nothing.
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
    let posted = draft.clone();
    let at = state.clock.now().unix_timestamp();
    let added = state
        .db
        .call(move |conn| add_in(conn, &actor, &draft, at))
        .await;
    match added {
        Ok(Added::Done) => redirect("/admin/rules"),
        Ok(Added::Refused(message)) => {
            let refusal = Refusal {
                message,
                draft: &posted,
            };
            rules_page(&state, &form.viewer, StatusCode::BAD_REQUEST, Some(refusal)).await
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
    let Some(effect) = effect_of(&draft.effect) else {
        return Ok(Err(EFFECT));
    };
    let Some(scope) = scope_of(&draft.scope) else {
        return Ok(Err(SCOPE));
    };
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
    let target = match check_target(conn, scope, &draft.server_id, &draft.tool)? {
        Ok(target) => target,
        Err(message) => return Ok(Err(message)),
    };
    let taken: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM rules WHERE COALESCE(user_id, 0) = ?1 \
         AND COALESCE(server_id, 0) = ?2 AND COALESCE(tool, '') = ?3)",
        params![
            user_id.unwrap_or(0),
            target.server_id.unwrap_or(0),
            target.tool.as_deref().unwrap_or("")
        ],
        |row| row.get(0),
    )?;
    if taken {
        return Ok(Err(DUPLICATE));
    }
    Ok(Ok(Checked {
        user_id,
        effect,
        server_id: target.server_id,
        tool: target.tool,
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
pub(super) fn record(
    conn: &Connection,
    at: i64,
    actor: &SessionUser,
    detail: &str,
) -> rusqlite::Result<()> {
    let change = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        detail,
        ..Default::default()
    };
    audit::record(conn, at, &change)
}

/// How many stored rules deny and how many allow.
pub(super) struct EffectCounts {
    pub deny: i64,
    pub allow: i64,
}

/// The rules by effect, in one query.
pub(super) fn effect_counts_in(conn: &Connection) -> rusqlite::Result<EffectCounts> {
    conn.query_row(
        "SELECT COALESCE(SUM(effect = 'deny'), 0), COALESCE(SUM(effect = 'allow'), 0) FROM rules",
        [],
        |row| {
            Ok(EffectCounts {
                deny: row.get(0)?,
                allow: row.get(1)?,
            })
        },
    )
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

/// The rules of an invitation's plan, oldest first, each named after the invited address. `only`
/// reads just the rule with that id.
pub(super) fn plan_rules_in(
    conn: &Connection,
    invitation: i64,
    email: &str,
    only: Option<i64>,
) -> rusqlite::Result<Vec<Stored>> {
    let mut statement = conn.prepare(
        "SELECT invitation_rules.id, invitation_rules.effect, invitation_rules.server_id, \
         servers.slug, invitation_rules.tool, \
         invitation_rules.tool IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tool_catalog \
         WHERE tool_catalog.server_id = invitation_rules.server_id \
         AND tool_catalog.name = invitation_rules.tool) \
         FROM invitation_rules LEFT JOIN servers ON servers.id = invitation_rules.server_id \
         WHERE invitation_rules.invitation_id = ?1 AND (?2 IS NULL OR invitation_rules.id = ?2) \
         ORDER BY invitation_rules.id",
    )?;
    let rows = statement.query_map(params![invitation, only], |row| {
        Ok(Stored {
            id: row.get(0)?,
            subject: email.to_owned(),
            effect: row.get(1)?,
            server_id: row.get(2)?,
            server: row.get(3)?,
            tool: row.get(4)?,
            stale: row.get(5)?,
        })
    })?;
    rows.collect()
}

/// Every stored tool with its server's path, by path then name, for the tool name choice.
pub(super) fn tools_in(conn: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
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
    refusal: Option<Refusal<'_>>,
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
            let data = MainData {
                nav: panel_nav(viewer, "/admin/rules"),
                ..MainData::default()
            };
            form_page_with(viewer, status, "rules", "Rules", &data, |csrf| {
                html! {
                    (rules_body(csrf, &rules, &users, &server_list, &tools, refusal.as_ref()))
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
    refusal: Option<&Refusal<'_>>,
) -> Markup {
    let refused = refusal.map(|refusal| refusal.message);
    let draft = refusal.map(|refusal| refusal.draft);
    let subject = draft.map_or("", |draft| draft.subject.as_str());
    let effect = draft.map_or("", |draft| draft.effect.as_str());
    let scope = draft.map_or("", |draft| draft.scope.as_str());
    let server_choice = draft.map_or("", |draft| draft.server_id.as_str());
    let tool = draft.map(|draft| ui::sent_back(&draft.tool, ui::SENT_BACK_LIMIT));
    let failed = refused.and_then(refused_field);
    let subject_error = field_error(refused, "rule-subject");
    let subject_note = ui::note_under(subject_error, None);
    let subject_described = subject_note.describer("rule-subject");
    html! {
        div.page-head {
            h1 { "Rules" }
            p.lede { "A deny stands unless an allow is at least as specific in scope and subject, and more specific in one." }
            div.head-actions {
                a.button data-kind="secondary" href="#add" { "Add a rule" }
            }
        }
        @if let Some(message) = refused {
            (ui::refused(Some("The rule was not added."), message, failed))
        }
        table.list.rules {
            thead {
                tr {
                    th scope="col" class="c-rule" { "Rule" }
                    th scope="col" class="c-effect" { "Effect" }
                    th scope="col" class="c-subject" { "Subject" }
                    th scope="col" { "Applies to" }
                    th scope="col" class="c-act" aria-label="Actions" {}
                }
            }
            tbody {
                @for rule in rules {
                    (rule_row(csrf, rule))
                }
            }
        }
        section.part id="add" aria-labelledby="add-title" {
            div.part-head {
                h2 id="add-title" { "Add a rule" }
                p { "Who the rule is about, what it covers, and whether it lets the call through." }
            }
            div.part-body {
                form.flow method="post" action="/admin/rules" {
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields data-cols="2" {
                        (ui::field(
                            "rule-subject",
                            "Subject",
                            false,
                            html! {
                                select id="rule-subject" name="subject" aria-invalid=[ui::invalid(subject_error)] aria-describedby=[subject_described.as_deref()] {
                                    option value="everyone" selected[subject == "everyone"] { "Everyone" }
                                    @for (id, email) in users {
                                        option value=(id) selected[subject == id.to_string()] { (email) }
                                    }
                                }
                            },
                            subject_note,
                        ))
                        (effect_field(effect, field_error(refused, "rule-effect")))
                    }
                    div.fields data-cols="2" {
                        (scope_field(scope))
                        (server_field(servers, server_choice, field_error(refused, "rule-server")))
                    }
                    div.fields {
                        (tool_field(tool.as_deref(), field_error(refused, "rule-tool")))
                    }
                    (tool_datalist(tools))
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Add rule" }
                    }
                }
            }
        }
    }
}

/// The effect field of a rule form: allow or deny, with the refusal of the effect when it has one.
pub(super) fn effect_field(effect: &str, error: Option<&str>) -> Markup {
    let note = ui::note_under(error, None);
    let described = note.describer("rule-effect");
    ui::field(
        "rule-effect",
        "Effect",
        false,
        html! {
            select id="rule-effect" name="effect" aria-invalid=[ui::invalid(error)] aria-describedby=[described.as_deref()] {
                option value="allow" selected[effect == "allow"] { "Allow" }
                option value="deny" selected[effect == "deny"] { "Deny" }
            }
        },
        note,
    )
}

/// The scope field of a rule form: all tools, one server or one tool.
pub(super) fn scope_field(scope: &str) -> Markup {
    ui::field(
        "rule-scope",
        "Scope",
        false,
        html! {
            select id="rule-scope" name="scope" {
                option value="all" selected[scope == "all"] { "All tools" }
                option value="server" selected[scope == "server"] { "One server" }
                option value="tool" selected[scope == "tool"] { "One tool" }
            }
        },
        ui::Note::None,
    )
}

/// The server field of a rule form: every server, with the refusal of the server when it has one.
pub(super) fn server_field(servers: &[ServerRef], choice: &str, error: Option<&str>) -> Markup {
    let note = ui::note_under(
        error,
        Some("Used when the scope is one server or one tool."),
    );
    let described = note.describer("rule-server");
    ui::field(
        "rule-server",
        "Server",
        false,
        html! {
            select id="rule-server" name="server_id" aria-invalid=[ui::invalid(error)] aria-describedby=[described.as_deref()] {
                @for server in servers {
                    option value=(server.id) selected[choice == server.id.to_string()] { (server.name) " (" (server.slug) ")" }
                }
            }
        },
        note,
    )
}

/// The tool name field of a rule form, with the refusal of the tool when it has one.
pub(super) fn tool_field(tool: Option<&str>, error: Option<&str>) -> Markup {
    let note = ui::note_under(
        error,
        Some("Used when the scope is one tool. It must be in the server's tool list."),
    );
    let described = note.describer("rule-tool");
    ui::field(
        "rule-tool",
        "Tool name",
        false,
        html! {
            input.mono id="rule-tool" name="tool" type="text" list="rule-tools" value=[tool] aria-invalid=[ui::invalid(error)] aria-describedby=[described.as_deref()];
        },
        note,
    )
}

/// The tools of every server, offered as the choices of the tool name field.
pub(super) fn tool_datalist(tools: &[(String, String)]) -> Markup {
    html! {
        datalist id="rule-tools" {
            @for (slug, tool) in tools {
                option value=(tool) label=(slug);
            }
        }
    }
}

/// The field a refusal of the rule form is about, with the word the notice uses for it. A refusal
/// about the scope or about a duplicate rule is about no one field.
pub(super) fn refused_field(message: &str) -> Option<(&'static str, &'static str)> {
    match message {
        EFFECT => Some(("rule-effect", "effect")),
        SUBJECT => Some(("rule-subject", "subject")),
        SERVER => Some(("rule-server", "server")),
        TOOL | UNLISTED => Some(("rule-tool", "tool name")),
        _ => None,
    }
}

/// One stored rule: its id, its effect, its subject, what it applies to, and its delete button.
fn rule_row(csrf: &str, rule: &Stored) -> Markup {
    html! {
        tr data-rule-id=(rule.id) data-subject=(rule.subject) data-effect=(rule.effect)
            data-scope=(rule.scope()) data-server=(rule.server.as_deref().unwrap_or(""))
            data-tool=(rule.tool.as_deref().unwrap_or(""))
            data-stale=(yes_or_no(rule.stale)) {
            td.half data-rule-number {
                span.unit { "Rule " }
                code { (rule.id) }
            }
            td.half { (effect_pill(&rule.effect)) }
            td.lead { (subject_markup(&rule.subject)) }
            td {
                (target_markup(rule))
                @if rule.stale {
                    span.sub.state data-tone="warn" { "The tool is not in the server's tool list." }
                }
            }
            td.act {
                form method="post" action=(format!("/admin/rules/{}/delete", rule.id)) {
                    input type="hidden" name="csrf" value=(csrf);
                    button.row-action type="submit" data-kind="danger" { "Delete rule" }
                }
            }
        }
    }
}

/// The effect of a rule as a pill: Allow in ok, Deny in bad.
pub(super) fn effect_pill(effect: &str) -> Markup {
    if effect == "allow" {
        ui::pill("ok", "Allow")
    } else {
        ui::pill("bad", "Deny")
    }
}

/// The subject of a rule: "Everyone" in words, or the user's address.
fn subject_markup(subject: &str) -> Markup {
    html! {
        @if subject == "everyone" {
            "Everyone"
        } @else {
            (ui::email(subject))
        }
    }
}

/// What the rule applies to, with the server and tool names in code.
pub(super) fn target_markup(rule: &Stored) -> Markup {
    html! {
        @if let (Some(server), Some(tool)) = (rule.server.as_deref(), rule.tool.as_deref()) {
            "tool " span.whole { code { (ui::breakable(tool)) } } " on server " span.whole { code { (server) } }
        } @else if let Some(server) = rule.server.as_deref() {
            "server " span.whole { code { (server) } }
        } @else {
            "all tools"
        }
    }
}

fn yes_or_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(server: Option<&str>, tool: Option<&str>) -> Stored {
        Stored {
            id: 1,
            subject: "everyone".to_owned(),
            effect: "allow".to_owned(),
            server_id: server.map(|_| 1),
            server: server.map(str::to_owned),
            tool: tool.map(str::to_owned),
            stale: false,
        }
    }

    #[test]
    fn the_applies_to_names_sit_in_whole_spans_as_code() {
        let tool = stored(Some("github"), Some("create_pull_request_review_comment"));
        assert_eq!(
            target_markup(&tool).into_string(),
            r#"tool <span class="whole"><code>create_<wbr>pull_<wbr>request_<wbr>review_<wbr>comment</code></span> on server <span class="whole"><code>github</code></span>"#
        );
        let server = stored(Some("demo"), None);
        assert_eq!(
            target_markup(&server).into_string(),
            r#"server <span class="whole"><code>demo</code></span>"#
        );
        let all = stored(None, None);
        assert_eq!(target_markup(&all).into_string(), "all tools");
    }
}
