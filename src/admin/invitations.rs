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
use crate::web::{
    MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with, internal_error,
    page_with, redirect, ui,
};

use super::activity::plain_time;
use super::panel_nav;

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
}

/// What creating an invitation writes.
struct NewInvitation {
    actor: SessionUser,
    email: String,
    role: String,
    hash: String,
    now: i64,
    lifetime: i64,
}

enum Stored {
    Written,
    Taken,
}

pub async fn get_invitations(viewer: Viewer, State(state): State<AppState>) -> Response {
    let now = state.clock.now().unix_timestamp();
    match load_open(&state.db, now).await {
        Ok(rows) => invitations_page(&viewer, StatusCode::OK, &rows, None, None),
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
    let token = random_token(INVITE_PREFIX);
    let new = NewInvitation {
        actor,
        email: email.clone(),
        role: role.clone(),
        hash: token_hash(&token),
        now: state.clock.now().unix_timestamp(),
        lifetime: lifetime_seconds(state.config.lifetimes.invitation_days),
    };
    match state.db.call(move |conn| store_in(conn, &new)).await {
        Ok(Stored::Written) => {}
        Ok(Stored::Taken) => return refuse(&state, &form, TAKEN_MESSAGE).await,
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
    let now = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| revoke_in(conn, id, &actor, now))
        .await
    {
        Ok(()) => redirect("/admin/invitations"),
        Err(err) => internal_error("invitation revoke", &err),
    }
}

/// The open invitations, oldest id first.
async fn load_open(db: &Db, now: i64) -> Result<Vec<Row>, DbError> {
    db.call(move |conn| open_rows_in(conn, now)).await
}

fn open_rows_in(conn: &Connection, now: i64) -> rusqlite::Result<Vec<Row>> {
    let mut statement = conn.prepare(
        "SELECT i.id, i.email, i.role, i.expires_at, u.email FROM invitations i \
         LEFT JOIN users u ON u.id = i.invited_by \
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
fn rfc3339(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    when.format(&Rfc3339).map_err(invalid_time)
}

fn invalid_time<E>(err: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

/// One transaction: an address with an account gets no invitation; otherwise any open invitation
/// for the address is replaced and the activity row is written.
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
fn revoke_in(
    conn: &mut Connection,
    id: i64,
    actor: &SessionUser,
    now: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let email: Option<String> = tx
        .query_row(
            "SELECT email FROM invitations WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(email) = email {
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
    tx.commit()
}

/// The page again, with the error and the email and role as posted, for a refused form.
async fn refuse(state: &AppState, form: &VerifiedForm, message: &str) -> Response {
    let now = state.clock.now().unix_timestamp();
    let email = ui::sent_back(form.fields.get("email"), ui::EMAIL_SENT_BACK_LIMIT);
    let role = ui::sent_back(form.fields.get("role"), ui::SENT_BACK_LIMIT);
    match load_open(&state.db, now).await {
        Ok(rows) => invitations_page(
            &form.viewer,
            StatusCode::BAD_REQUEST,
            &rows,
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
                (invitations_body(csrf, viewer.is_owner(), rows, posted, error))
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
                        th scope="col" class="c-when" { "Expires (UTC)" }
                        th scope="col" class="c-by" { "Invited by" }
                        th scope="col" class="c-act" aria-label="Actions" {}
                    }
                }
                tbody {
                    @for row in rows {
                        (invitation_row(csrf, row))
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
                    div.form-actions {
                        button type="submit" data-kind="primary" { "Send invitation" }
                    }
                }
            }
        }
    }
}

/// One open invitation: its address, role, expiry, inviter, and the revoke button.
fn invitation_row(csrf: &str, row: &Row) -> Markup {
    html! {
        tr data-invitation-id=(row.id) data-email=(row.email) {
            td.lead.strong { (ui::email(&row.email)) }
            td.half { span.unit { "as " } (row.role) }
            td.half { (ui::time_cell(&row.expires, &row.expires_plain, true)) }
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
