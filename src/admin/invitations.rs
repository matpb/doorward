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
use crate::mail;
use crate::mail::templates;
use crate::web::{
    SessionUser, VerifiedForm, Viewer, forbidden, form_page, internal_error, page, redirect,
};

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
        Ok(rows) => invitations_page(&viewer, StatusCode::OK, &rows, None),
        Err(err) => internal_error("invitations page", &err),
    }
}

/// Stores the invitation and mails the link. A failed send shows the link once instead.
pub async fn post_invitation(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let email = normalize_email(form.fields.get("email"));
    if !valid_new_email(&email) {
        return refuse(&state, &form.viewer, EMAIL_MESSAGE).await;
    }
    let role = form.fields.get("role").to_owned();
    if role != "admin" && role != "user" {
        return refuse(&state, &form.viewer, ROLE_MESSAGE).await;
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
        Ok(Stored::Taken) => return refuse(&state, &form.viewer, TAKEN_MESSAGE).await,
        Err(err) => return internal_error("invitation", &err),
    }
    let link = format!("{}/invite/{token}", state.config.public_url);
    let message = templates::invitation(&link).to(email);
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
            inviter: row.get(4)?,
        })
    })?;
    rows.collect()
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

/// The page again, with the error, for a refused form.
async fn refuse(state: &AppState, viewer: &Viewer, message: &str) -> Response {
    let now = state.clock.now().unix_timestamp();
    match load_open(&state.db, now).await {
        Ok(rows) => invitations_page(viewer, StatusCode::BAD_REQUEST, &rows, Some(message)),
        Err(err) => internal_error("invitations page", &err),
    }
}

fn invitations_page(
    viewer: &Viewer,
    status: StatusCode,
    rows: &[Row],
    error: Option<&str>,
) -> Response {
    let nav = panel_nav(viewer, "/admin/invitations");
    form_page(viewer, status, "invitations", "Invitations", |csrf| {
        html! {
            (nav)
            (invitations_body(csrf, viewer.is_owner(), rows, error))
        }
    })
}

fn invitations_body(csrf: &str, owner: bool, rows: &[Row], error: Option<&str>) -> Markup {
    html! {
        div.stack {
            h1 { "Invitations" }
            @if let Some(message) = error {
                p.error { (message) }
            }
            div.split {
                section.card.main {
                    @if rows.is_empty() {
                        p { "No open invitations." }
                    }
                    ul.invitations.rows {
                        @for row in rows {
                            li data-invitation-id=(row.id) data-email=(row.email) {
                                div.row-main {
                                    span.row-title { (row.email) }
                                    p.row-meta {
                                        "as " (row.role) " · Expires " (row.expires)
                                    }
                                    p.row-meta {
                                        @if let Some(inviter) = &row.inviter {
                                            span data-invited-by { "invited by " (inviter) }
                                        } @else {
                                            span data-invited-by { "invited by a removed account" }
                                        }
                                    }
                                }
                                div.row-actions {
                                    form method="post" action=(format!("/admin/invitations/{}/revoke", row.id)) {
                                        input type="hidden" name="csrf" value=(csrf);
                                        button type="submit" data-kind="danger" { "Revoke" }
                                    }
                                }
                            }
                        }
                    }
                }
                form.card.side method="post" action="/admin/invitations" {
                    h2 { "Invite someone" }
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields {
                        div {
                            label for="invite-email" { "Email" }
                            input id="invite-email" name="email" type="email" required;
                        }
                        div {
                            label for="invite-role" { "Role" }
                            select id="invite-role" name="role" {
                                option value="user" selected { "User" }
                                @if owner {
                                    option value="admin" { "Admin" }
                                }
                            }
                        }
                    }
                    button type="submit" data-kind="primary" { "Send invitation" }
                }
            }
        }
    }
}

/// The answer when the mail did not leave: the error, and the link once for copying by hand.
fn invitation_created(viewer: &Viewer, error: &str, link: &str) -> Response {
    page(
        StatusCode::OK,
        "invitation-created",
        "Invitation created",
        html! {
            (panel_nav(viewer, "/admin/invitations"))
            div.stack {
                h1 { "The invitation is stored but the email was not sent" }
                p.error { (error) }
                p { "Copy this link and send it by hand:" }
                p { code.copy data-invite-link=(link) { (link) } }
                p { a href="/admin/invitations" { "Back to invitations" } }
            }
        },
    )
}
