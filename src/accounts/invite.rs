//! Accepting an invitation: the link page, the password, and the one transaction that makes the account.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::token_hash;
use crate::web::{
    VerifiedForm, Viewer, busy, form_page, internal_error, not_found_link, redirect,
    session_cookie, with_cookie,
};

use super::input::{to_i64, valid_password};
use super::password::PASSWORD_MESSAGE;
use super::session;

pub const INVITE_PREFIX: &str = "dw_iv_";
const DAY_SECONDS: i64 = 86_400;
const TITLE: &str = "Accept your invitation";

/// An invitation whose link can still be used.
pub struct Invitation {
    pub id: i64,
    pub email: String,
    pub role: String,
}

/// What accepting writes: the link's hash, the new password hash, the time, the session length
/// and the session cookie the browser came with.
struct Accept {
    hash: String,
    phc: String,
    now: i64,
    lifetime: i64,
    presented: Option<String>,
}

/// The lifetime of an invitation link in seconds.
pub fn lifetime_seconds(days: u64) -> i64 {
    to_i64(days).saturating_mul(DAY_SECONDS)
}

/// The invitation of a token hash, when its row exists and has not expired.
pub(crate) fn usable_in(
    conn: &Connection,
    hash: &str,
    now: i64,
) -> rusqlite::Result<Option<Invitation>> {
    conn.query_row(
        "SELECT id, email, role FROM invitations WHERE token_hash = ?1 AND expires_at > ?2",
        params![hash, now],
        |row| {
            Ok(Invitation {
                id: row.get(0)?,
                email: row.get(1)?,
                role: row.get(2)?,
            })
        },
    )
    .optional()
}

/// Never changes anything: it only shows the form when the link is usable.
pub async fn get_invite(
    viewer: Viewer,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    match state.db.call(move |conn| usable_in(conn, &hash, now)).await {
        Ok(Some(invitation)) => form_page(&viewer, StatusCode::OK, "invite", TITLE, |csrf| {
            invite_body(csrf, &invitation.email, None)
        }),
        Ok(None) => not_found_link(),
        Err(_) => internal_error(),
    }
}

pub async fn post_invite(
    State(state): State<AppState>,
    Path(token): Path<String>,
    form: VerifiedForm,
) -> Response {
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    let lookup = hash.clone();
    let invitation = match state
        .db
        .call(move |conn| usable_in(conn, &lookup, now))
        .await
    {
        Ok(Some(invitation)) => invitation,
        Ok(None) => return not_found_link(),
        Err(_) => return internal_error(),
    };
    let password = form.fields.get("password").to_owned();
    if !valid_password(&password) {
        return invite_page(&form, &invitation.email, Some(PASSWORD_MESSAGE));
    }
    let Some(slot) = state.hasher.try_slot() else {
        return busy();
    };
    let phc = match state.hasher.hash(slot, password).await {
        Ok(phc) => phc,
        Err(_) => return internal_error(),
    };
    let accept = Accept {
        hash,
        phc,
        now,
        lifetime: session::lifetime_seconds(state.config.lifetimes.session_hours),
        presented: form.viewer.presented_session().map(str::to_owned),
    };
    match state.db.call(move |conn| accept_in(conn, &accept)).await {
        Ok(Some(token)) => with_cookie(redirect("/account"), &session_cookie(&token)),
        Ok(None) => not_found_link(),
        Err(_) => internal_error(),
    }
}

/// One transaction: the link is checked again, the address must be free, then the account,
/// the session and the activity row are written. None when the link can no longer be used.
fn accept_in(conn: &mut Connection, accept: &Accept) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(invitation) = usable_in(&tx, &accept.hash, accept.now)? else {
        return Ok(None);
    };
    let taken: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1)",
        params![invitation.email],
        |row| row.get(0),
    )?;
    if taken {
        return Ok(None);
    }
    tx.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![invitation.email, accept.phc, invitation.role, accept.now],
    )?;
    let user_id = tx.last_insert_rowid();
    tx.execute(
        "DELETE FROM invitations WHERE id = ?1",
        params![invitation.id],
    )?;
    if let Some(previous) = &accept.presented {
        session::delete(&tx, previous)?;
    }
    let token = session::insert(&tx, user_id, accept.now, accept.lifetime)?;
    let accepted = Event {
        kind: "invitation",
        user_id: Some(user_id),
        user_email: &invitation.email,
        detail: "accepted",
        ..Default::default()
    };
    audit::record(&tx, accept.now, &accepted)?;
    tx.commit()?;
    Ok(Some(token))
}

fn invite_page(form: &VerifiedForm, email: &str, error: Option<&str>) -> Response {
    form_page(
        &form.viewer,
        StatusCode::BAD_REQUEST,
        "invite",
        TITLE,
        |csrf| invite_body(csrf, email, error),
    )
}

/// The form posts to the address it was loaded from, so the token never appears in the page.
fn invite_body(csrf: &str, email: &str, error: Option<&str>) -> Markup {
    html! {
        h1 { "Accept your invitation" }
        p { "Invited address: " (email) }
        @if let Some(message) = error {
            p.error { (message) }
        }
        form method="post" {
            input type="hidden" name="csrf" value=(csrf);
            label for="password" { "Choose a password (12 to 256 characters)" }
            input id="password" name="password" type="password" autocomplete="new-password" required;
            button type="submit" { "Set password" }
        }
    }
}
