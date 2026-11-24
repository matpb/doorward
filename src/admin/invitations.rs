//! The invitations page: open invitations, creating one, and revoking one.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::accounts::input::{normalize_email, valid_new_email};
use crate::accounts::invite::{INVITE_PREFIX, lifetime_seconds};
use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{random_token, token_hash};
use crate::db::{Db, DbError};
use crate::mail::templates;
use crate::mail::{self, NOT_SET_UP};
use crate::servers::{self, ServerChoice, ServerRef};
use crate::web::{
    MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with, internal_error,
    page_with, redirect, ui,
};

use super::activity::plain_time;
use super::panel_nav;
use super::users::{SERVER_MESSAGE, server_ids};

const EMAIL_MESSAGE: &str = "Enter a valid email address.";
const ROLE_MESSAGE: &str = "Choose the role user or admin.";
const TAKEN_MESSAGE: &str = "An account already has that email address.";

/// One open invitation as the page shows it.
struct Row {
    id: i64,
    email: String,
    role: String,
    expires: String,
    /// The same instant as the activity page writes it, `D Mon YYYY HH:MM:SS UTC`.
    expires_plain: String,
    /// The email of the admin who made it; None when that account no longer exists.
    inviter: Option<String>,
    /// How many servers the plan of the invitation reaches on accept.
    servers: i64,
}

/// What creating an invitation writes: its servers, sorted and without repeats.
struct NewInvitation {
    actor: SessionUser,
    owner: bool,
    email: String,
    role: String,
    hash: String,
    servers: Vec<i64>,
    now: i64,
    lifetime: i64,
}

/// A rule of an open invitation that a new invitation for the same address keeps.
struct CarriedRule {
    effect: String,
    server_id: Option<i64>,
    tool: Option<String>,
    created_at: i64,
}

enum Stored {
    Written,
    Taken,
    UnknownServer,
    Forbidden,
}

/// What revoking an invitation did.
enum Revoked {
    Done,
    Forbidden,
}

pub async fn get_invitations(viewer: Viewer, State(state): State<AppState>) -> Response {
    let now = state.clock.now().unix_timestamp();
    match load_open(&state.db, now).await {
        Ok((rows, servers)) => {
            let choices = server_choices(servers, &[]);
            invitations_page(&viewer, StatusCode::OK, &rows, &choices, None, None)
        }
        Err(err) => internal_error("invitations page", &err),
    }
}

/// Stores the invitation and mails the link. A failed send shows the link once instead.
pub async fn post_invitation(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let email = normalize_email(form.fields.get("email"));
    if !valid_new_email(&email) {
        return refuse(&state, &form, EMAIL_MESSAGE).await;
    }
    let role = form.fields.get("role").to_owned();
    if role != "admin" && role != "user" {
        return refuse(&state, &form, ROLE_MESSAGE).await;
    }
    if role == "admin" && !form.viewer.is_owner() {
        return forbidden();
    }
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(mut servers) = server_ids(&form) else {
        return refuse(&state, &form, SERVER_MESSAGE).await;
    };
    servers.sort_unstable();
    servers.dedup();
    let token = random_token(INVITE_PREFIX);
    let new = NewInvitation {
        actor,
        owner: form.viewer.is_owner(),
        email: email.clone(),
        role: role.clone(),
        hash: token_hash(&token),
        servers,
        now: state.clock.now().unix_timestamp(),
        lifetime: lifetime_seconds(state.config.lifetimes.invitation_days),
    };
    match state.db.call(move |conn| store_in(conn, &new)).await {
        Ok(Stored::Written) => {}
        Ok(Stored::Taken) => return refuse(&state, &form, TAKEN_MESSAGE).await,
        Ok(Stored::UnknownServer) => return refuse(&state, &form, SERVER_MESSAGE).await,
        Ok(Stored::Forbidden) => return forbidden(),
        Err(err) => return internal_error("invitation", &err),
    }
    let link = format!("{}/invite/{token}", state.config.public_url);
    let host = templates::host_and_port(&state.config.public_url);
    let message = templates::invitation(&link, host).to(email);
    match mail::send(&state, "invitation", message).await {
        Ok(()) => redirect("/admin/invitations"),
        Err(error) => invitation_created(&form.viewer, &error.0, &link),
    }
}

pub async fn post_revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Ok(id) = id.parse::<i64>() else {
        return redirect("/admin/invitations");
    };
    let owner = form.viewer.is_owner();
    let now = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| revoke_in(conn, id, &actor, owner, now))
        .await
    {
        Ok(Revoked::Done) => redirect("/admin/invitations"),
        Ok(Revoked::Forbidden) => forbidden(),
        Err(err) => internal_error("invitation revoke", &err),
    }
}

/// The open invitations, oldest id first, and the servers a plan can reach.
async fn load_open(db: &Db, now: i64) -> Result<(Vec<Row>, Vec<ServerRef>), DbError> {
    db.call(move |conn| Ok((open_rows_in(conn, now)?, servers::list(conn)?)))
        .await
}

/// Every server as a checkbox choice; ticked when its id is in `ticked`.
fn server_choices(servers: Vec<ServerRef>, ticked: &[i64]) -> Vec<ServerChoice> {
    servers
        .into_iter()
        .map(|server| ServerChoice {
            assigned: ticked.contains(&server.id),
            id: server.id,
            name: server.name,
            slug: server.slug,
        })
        .collect()
}

fn open_rows_in(conn: &Connection, now: i64) -> rusqlite::Result<Vec<Row>> {
    let mut statement = conn.prepare(
        "SELECT i.id, i.email, i.role, i.expires_at, u.email, \
         (SELECT COUNT(*) FROM invitation_servers WHERE invitation_servers.invitation_id = i.id) \
         FROM invitations i LEFT JOIN users u ON u.id = i.invited_by \
         WHERE i.expires_at > ?1 ORDER BY i.id",
    )?;
    let rows = statement.query_map(params![now], |row| {
        let expires_at: i64 = row.get(3)?;
        Ok(Row {
            id: row.get(0)?,
            email: row.get(1)?,
            role: row.get(2)?,
            expires: rfc3339(expires_at)?,
            expires_plain: plain_time(expires_at)?,
            inviter: row.get(4)?,
            servers: row.get(5)?,
        })
    })?;
    rows.collect()
}

/// The earliest expiry among the open invitations, the same ones `open_rows_in` lists.
pub(super) fn earliest_open_expiry(conn: &Connection, now: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MIN(expires_at) FROM invitations WHERE expires_at > ?1",
        params![now],
        |row| row.get(0),
    )
}

/// The UTC time of a unix timestamp as RFC 3339.
pub(super) fn rfc3339(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    when.format(&Rfc3339).map_err(invalid_time)
}

fn invalid_time<E>(err: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

/// The rules of the open invitation for `email` with the role `role`, in the order they were added.
/// A rule made for another role is not carried.
fn carried_rules(
    conn: &Connection,
    email: &str,
    role: &str,
    now: i64,
) -> rusqlite::Result<Vec<CarriedRule>> {
    let mut statement = conn.prepare(
        "SELECT invitation_rules.effect, invitation_rules.server_id, invitation_rules.tool, \
         invitation_rules.created_at FROM invitation_rules \
         JOIN invitations ON invitations.id = invitation_rules.invitation_id \
         WHERE invitations.email = ?1 AND invitations.role = ?2 AND invitations.expires_at > ?3 \
         ORDER BY invitation_rules.id",
    )?;
    let rows = statement.query_map(params![email, role, now], |row| {
        Ok(CarriedRule {
            effect: row.get(0)?,
            server_id: row.get(1)?,
            tool: row.get(2)?,
            created_at: row.get(3)?,
        })
    })?;
    rows.collect()
}

/// One transaction. An open invitation for the address is replaced, keeping its rules when the
/// role is unchanged; only the owner replaces an open admin invitation.
fn store_in(conn: &mut Connection, new: &NewInvitation) -> rusqlite::Result<Stored> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let taken: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1)",
        params![new.email],
        |row| row.get(0),
    )?;
    if taken {
        return Ok(Stored::Taken);
    }
    if !new.owner {
        let open_admin: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM invitations WHERE email = ?1 AND role = 'admin' \
             AND expires_at > ?2)",
            params![new.email, new.now],
            |row| row.get(0),
        )?;
        if open_admin {
            return Ok(Stored::Forbidden);
        }
    }
    for server in &new.servers {
        if !servers::server_exists(&tx, *server)? {
            return Ok(Stored::UnknownServer);
        }
    }
    let carried = carried_rules(&tx, &new.email, &new.role, new.now)?;
    tx.execute(
        "DELETE FROM invitations WHERE email = ?1",
        params![new.email],
    )?;
    tx.execute(
        "INSERT INTO invitations (email, role, token_hash, invited_by, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            new.email,
            new.role,
            new.hash,
            new.actor.id,
            new.now,
            new.now.saturating_add(new.lifetime)
        ],
    )?;
    let invitation = tx.last_insert_rowid();
    for server in &new.servers {
        tx.execute(
            "INSERT INTO invitation_servers (invitation_id, server_id) VALUES (?1, ?2)",
            params![invitation, server],
        )?;
    }
    for rule in &carried {
        tx.execute(
            "INSERT INTO invitation_rules (invitation_id, effect, server_id, tool, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                invitation,
                rule.effect,
                rule.server_id,
                rule.tool,
                rule.created_at
            ],
        )?;
    }
    if !new.servers.is_empty() {
        let noun = if new.servers.len() == 1 {
            "server"
        } else {
            "servers"
        };
        let detail = format!(
            "invitation servers of {} set to {} {noun}",
            new.email,
            new.servers.len()
        );
        let set = Event {
            kind: "admin_change",
            user_id: Some(new.actor.id),
            user_email: &new.actor.email,
            detail: &detail,
            ..Default::default()
        };
        audit::record(&tx, new.now, &set)?;
    }
    let detail = format!("invited {} as {}", new.email, new.role);
    let invited = Event {
        kind: "invitation",
        user_id: Some(new.actor.id),
        user_email: &new.actor.email,
        detail: &detail,
        ..Default::default()
    };
    audit::record(&tx, new.now, &invited)?;
    tx.commit()?;
    Ok(Stored::Written)
}

/// Deletes the invitation and records it. An id that matches no row changes nothing.
/// Only the owner revokes an admin invitation.
fn revoke_in(
    conn: &mut Connection,
    id: i64,
    actor: &SessionUser,
    owner: bool,
    now: i64,
) -> rusqlite::Result<Revoked> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found: Option<(String, String)> = tx
        .query_row(
            "SELECT email, role FROM invitations WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if matches!(&found, Some((_, role)) if role == "admin" && !owner) {
        return Ok(Revoked::Forbidden);
    }
    if let Some((email, _)) = found {
        tx.execute("DELETE FROM invitations WHERE id = ?1", params![id])?;
        let detail = format!("revoked {email}");
        let revoked = Event {
            kind: "invitation",
            user_id: Some(actor.id),
            user_email: &actor.email,
            detail: &detail,
            ..Default::default()
        };
        audit::record(&tx, now, &revoked)?;
    }
    tx.commit()?;
    Ok(Revoked::Done)
}

/// The page again, with the error and the email, role and servers as posted, for a refused form.
async fn refuse(state: &AppState, form: &VerifiedForm, message: &str) -> Response {
    let now = state.clock.now().unix_timestamp();
    let email = ui::sent_back(form.fields.get("email"), ui::EMAIL_SENT_BACK_LIMIT);
    let role = ui::sent_back(form.fields.get("role"), ui::SENT_BACK_LIMIT);
    let ticked = server_ids(form).unwrap_or_default();
    match load_open(&state.db, now).await {
        Ok((rows, servers)) => invitations_page(
            &form.viewer,
            StatusCode::BAD_REQUEST,
            &rows,
            &server_choices(servers, &ticked),
            Some((&email, &role)),
            Some(message),
        ),
        Err(err) => internal_error("invitations page", &err),
    }
}

/// The invitations page; `posted` is the email and role of a refused form, shown again.
fn invitations_page(
    viewer: &Viewer,
    status: StatusCode,
    rows: &[Row],
    choices: &[ServerChoice],
    posted: Option<(&str, &str)>,
    error: Option<&str>,
) -> Response {
    let data = MainData {
        nav: panel_nav(viewer, "/admin/invitations"),
        ..MainData::default()
    };
    form_page_with(
        viewer,
        status,
        "invitations",
        "Invitations",
        &data,
        |csrf| {
            html! {
                (invitations_body(csrf, viewer.is_owner(), rows, choices, posted, error))
            }
        },
    )
}

/// The field a refusal of the invitation form is about, with the word the notice uses for it.
fn refused_field(message: &str) -> Option<(&'static str, &'static str)> {
    match message {
        EMAIL_MESSAGE | TAKEN_MESSAGE => Some(("invite-email", "email")),
        ROLE_MESSAGE => Some(("invite-role", "role")),
        _ => None,
    }
}

fn invitations_body(
    csrf: &str,
    owner: bool,
    rows: &[Row],
    choices: &[ServerChoice],
    posted: Option<(&str, &str)>,
    error: Option<&str>,
) -> Markup {
    let posted_email = posted.map(|(email, _)| email);
    let posted_role = posted.map(|(_, role)| role);
    let failed = error.and_then(refused_field);
    let email_error = error.filter(|_| failed.is_some_and(|(id, _)| id == "invite-email"));
    let role_error = error.filter(|_| failed.is_some_and(|(id, _)| id == "invite-role"));
    let email_note = ui::note_under(email_error, None);
    let email_described = email_note.describer("invite-email");
    let role_note = ui::note_under(role_error, None);
    let role_described = role_note.describer("invite-role");
    html! {
        div.page-head {
            h1 { "Invitations" }
            div.head-actions {
                a.button data-kind="secondary" href="#add" { "Invite someone" }
            }
        }
        @if let Some(message) = error {
            (ui::refused(Some("The invitation was not sent."), message, failed))
        }
        @if rows.is_empty() {
            p.muted { "No open invitations." }
        } @else {
            table.list.invitations {
                thead {
                    tr {
                        th scope="col" { "Email" }
                        th scope="col" class="c-role" { "Role" }
                        th scope="col" class="c-num num" { "Servers" }
                        th scope="col" class="c-when" { "Expires (UTC)" }
                        th scope="col" class="c-by" { "Invited by" }
                        th scope="col" class="c-act" aria-label="Actions" {}
                    }
                }
                tbody {
                    @for row in rows {
                        (invitation_row(csrf, owner, row))
                    }
                }
            }
        }
        section.part id="add" aria-labelledby="add-title" {
            div.part-head {
                h2 id="add-title" { "Invite someone" }
                p { "They get a link by email and choose their own password." }
            }
            div.part-body {
                form.flow method="post" action="/admin/invitations" {
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields {
                        (ui::field(
                            "invite-email",
                            "Email",
                            false,
                            html! {
                                input id="invite-email" name="email" type="email" required value=[posted_email]
                                    aria-invalid=[ui::invalid(email_error)] aria-describedby=[email_described.as_deref()];
                            },
                            email_note,
                        ))
                    }
                    div.fields data-cols="2" {
                        (ui::field(
                            "invite-role",
                            "Role",
                            false,
                            html! {
                                select id="invite-role" name="role" aria-invalid=[ui::invalid(role_error)] aria-describedby=[role_described.as_deref()] {
                                    option value="user" selected[posted_role != Some("admin")] { "User" }
                                    @if owner {
                                        option value="admin" selected[posted_role == Some("admin")] { "Admin" }
                                    }
                                }
                            },
                            role_note,
                        ))
                    }
                    div.fields {
                        div.field role="group" aria-labelledby="invite-servers-label" {
                            span.label id="invite-servers-label" { "Servers" }
                            (ui::hint("invite-servers-hint", "What they can reach as soon as they accept. To restrict tools first, send the invitation with no servers, then set rules and servers on its page."))
                            div.checks {
                                @for choice in choices {
                                    (invite_server_check(choice))
                                }
                            }
                        }
                    }
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Send invitation" }
                    }
                }
            }
        }
    }
}

/// One server of the invite form as a checkbox, described by the hint of the servers group.
fn invite_server_check(choice: &ServerChoice) -> Markup {
    let id = format!("invite-server-{}", choice.id);
    html! {
        div.check {
            input type="checkbox" id=(id) name="server_id" value=(choice.id) checked[choice.assigned] aria-describedby="invite-servers-hint";
            label for=(id) {
                span.check-name { (choice.name) }
                " "
                code { (choice.slug) }
            }
        }
    }
}

/// One open invitation: its address, which links to its plan, role, servers, expiry, inviter, and
/// the revoke button.
fn invitation_row(csrf: &str, owner: bool, row: &Row) -> Markup {
    // An admin invitation has no plan page for anyone but the owner, so its address is not a link.
    let plain = row.role == "admin" && !owner;
    html! {
        tr data-invitation-id=(row.id) data-email=(row.email) {
            td.lead.strong {
                @if plain {
                    (ui::email(&row.email))
                } @else {
                    a.name href=(format!("/admin/invitations/{}", row.id)) { (ui::email(&row.email)) }
                }
            }
            td.half { span.unit { "as " } (row.role) }
            td.num.half data-server-count {
                @if row.servers == 0 {
                    span.no-servers { "No servers" }
                } @else {
                    (ui::count_with_unit(row.servers, "server", "servers"))
                }
            }
            td {
                span.unit { "expires " }
                (ui::time_cell(&row.expires, &row.expires_plain, true))
            }
            td {
                span data-invited-by {
                    span.unit { "invited by " }
                    @if let Some(inviter) = &row.inviter {
                        (ui::email(inviter))
                    } @else {
                        "a removed account"
                    }
                }
            }
            td.act {
                form method="post" action=(format!("/admin/invitations/{}/revoke", row.id)) {
                    input type="hidden" name="csrf" value=(csrf);
                    button.row-action type="submit" data-kind="danger" { "Revoke" }
                }
            }
        }
    }
}

/// The warning of a stored invitation whose mail did not leave. The owner, who alone opens the mail
/// page, is linked to it when no mail is set up.
fn mail_warning(error: &str, owner: bool) -> Markup {
    html! {
        p {
            (error)
            @if owner && error == NOT_SET_UP {
                " "
                a href="/admin/mail" data-link="mail" { "Set up mail" }
            }
        }
    }
}

/// The link cut once before the first `/` after its host: the origin, and the path from that `/` on.
/// None when the link is not `scheme://host/...` shaped.
fn split_link(link: &str) -> Option<(&str, &str)> {
    let scheme_end = link.find("://")?;
    let scheme = &link[..scheme_end];
    let scheme_ok = !scheme.is_empty()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    if !scheme_ok {
        return None;
    }
    let host_start = scheme_end + 3;
    let host_len = link[host_start..]
        .find('/')
        .unwrap_or(link.len() - host_start);
    if host_len == 0 {
        return None;
    }
    let origin_end = host_start + host_len;
    Some((&link[..origin_end], &link[origin_end..]))
}

/// The link as a code element, copied by hand: the origin and the path in two spans, with one wbr
/// between them and no white space inside.
fn invite_link_code(link: &str) -> Markup {
    let parts = split_link(link);
    html! {
        code.copy data-invite-link=(link) {
            @match parts {
                Some((origin, "")) => span { (ui::breakable(origin)) },
                Some((origin, path)) => {
                    span { (ui::breakable(origin)) }
                    wbr;
                    span { (path) }
                }
                None => span { (ui::breakable(link)) },
            }
        }
    }
}

/// The invitation link as a labelled field, the one thing the person copies by hand.
fn invite_link_field(link: &str) -> Markup {
    html! {
        div.fields.narrow {
            div.field role="group" aria-labelledby="invite-link-label" {
                span.label id="invite-link-label" { "Invitation link" }
                (invite_link_code(link))
            }
        }
    }
}

/// The answer when the mail did not leave: the error, and the link once for copying by hand.
fn invitation_created(viewer: &Viewer, error: &str, link: &str) -> Response {
    let owner = viewer.is_owner();
    let data = MainData {
        nav: panel_nav(viewer, "/admin/invitations"),
        ..MainData::default()
    };
    page_with(
        StatusCode::OK,
        "invitation-created",
        "Invitation created",
        &data,
        html! {
            div.page-head {
                p.crumb { a href="/admin/invitations" { "Invitations" } }
                h1 { "The invitation is stored but the email was not sent" }
            }
            (ui::notice("warning", mail_warning(error, owner)))
            section.part aria-labelledby="link-title" {
                div.part-head {
                    h2 id="link-title" { "Send it by hand" }
                    p { "Copy this link and send it to the person you invited." }
                }
                div.part-body.flow {
                    (invite_link_field(link))
                    div.form-actions {
                        a.button data-kind="secondary" href="/admin/invitations" { "Back to invitations" }
                    }
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_warning_other_than_not_set_up_has_no_mail_link() {
        assert_eq!(
            mail_warning("any other error", true).into_string(),
            "<p>any other error</p>"
        );
    }

    #[test]
    fn a_link_is_cut_before_the_first_slash_after_its_host() {
        assert_eq!(
            split_link("https://example.com/invite/abc"),
            Some(("https://example.com", "/invite/abc"))
        );
        assert_eq!(
            split_link("https://example.com:8443/a/b"),
            Some(("https://example.com:8443", "/a/b"))
        );
        assert_eq!(
            split_link("https://example.com"),
            Some(("https://example.com", ""))
        );
    }

    #[test]
    fn a_link_that_is_not_scheme_host_shaped_is_not_cut() {
        assert_eq!(split_link("example.com/invite/abc"), None);
        assert_eq!(split_link("https:///invite/abc"), None);
        assert_eq!(split_link("a b://example.com/x"), None);
        assert_eq!(split_link("://example.com/x"), None);
    }

    #[test]
    fn the_link_code_holds_origin_and_path_in_two_spans_with_one_wbr() {
        assert_eq!(
            invite_link_code("https://example.com/invite/abc").into_string(),
            r#"<code class="copy" data-invite-link="https://example.com/invite/abc"><span>https://<wbr>example<wbr>.com</span><wbr><span>/invite/abc</span></code>"#
        );
    }

    #[test]
    fn a_link_without_a_path_has_one_span_and_no_wbr_between() {
        assert_eq!(
            invite_link_code("https://example.com").into_string(),
            r#"<code class="copy" data-invite-link="https://example.com"><span>https://<wbr>example<wbr>.com</span></code>"#
        );
    }

    #[test]
    fn a_link_that_is_not_shaped_is_one_span_with_no_path_span() {
        assert_eq!(
            invite_link_code("example.com/invite/abc").into_string(),
            r#"<code class="copy" data-invite-link="example.com/invite/abc"><span>example<wbr>.com/<wbr>invite/<wbr>abc</span></code>"#
        );
    }

    #[test]
    fn the_invitation_link_is_a_labelled_field_of_one_narrow_row() {
        assert_eq!(
            invite_link_field("https://example.com/invite/abc").into_string(),
            r#"<div class="fields narrow"><div class="field" role="group" aria-labelledby="invite-link-label"><span class="label" id="invite-link-label">Invitation link</span><code class="copy" data-invite-link="https://example.com/invite/abc"><span>https://<wbr>example<wbr>.com</span><wbr><span>/invite/abc</span></code></div></div>"#
        );
    }

    #[test]
    fn the_owner_gets_the_mail_link_only_for_not_set_up() {
        assert_eq!(
            mail_warning(NOT_SET_UP, true).into_string(),
            r#"<p>Mail is not set up. <a href="/admin/mail" data-link="mail">Set up mail</a></p>"#
        );
        assert_eq!(
            mail_warning(NOT_SET_UP, false).into_string(),
            "<p>Mail is not set up.</p>"
        );
    }
}
