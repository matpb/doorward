//! Changing the password while signed in. Shares the sign-in throttle for the wrong current password.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::token_hash;
use crate::oauth::connected;
use crate::web::limit;
use crate::web::{
    VerifiedForm, Viewer, busy, internal_error, redirect, session_cookie, throttle_key, with_cookie,
};

use super::account::account_page;
use super::input::valid_password;
use super::login;
use super::session;
use super::throttle::{self, Attempt};

pub const PASSWORD_MESSAGE: &str = "The password must be 12 to 256 characters.";
const WRONG_CURRENT: &str = "The current password is wrong.";
const BLOCKED: &str = "Too many sign-in attempts. Try again later.";

/// What the change writes: the signed-in user, the client address, the verified old hash and its
/// epoch, the presented session cookie value and the new hash.
pub(super) struct Change {
    pub(super) user_id: i64,
    pub(super) email: String,
    pub(super) account: String,
    pub(super) address: String,
    pub(super) old_phc: String,
    pub(super) epoch: i64,
    pub(super) session: Option<String>,
    pub(super) new_phc: String,
    pub(super) now: i64,
    pub(super) lifetime: i64,
}

/// The account page for a refused change, with the viewer's connected clients.
async fn refused(state: &AppState, viewer: &Viewer, status: StatusCode, message: &str) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    match connected::list(&state.db, user.id, now).await {
        Ok(clients) => account_page(viewer, status, Some(message), &clients),
        Err(err) => internal_error("connected clients", &err),
    }
}

pub async fn post_password(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(user) = form.viewer.user.clone() else {
        return redirect("/login");
    };
    let new_password = form.fields.get("new_password").to_owned();
    if !valid_password(&new_password) {
        return refused(
            &state,
            &form.viewer,
            StatusCode::BAD_REQUEST,
            PASSWORD_MESSAGE,
        )
        .await;
    }
    let Some(first) = state.hasher.try_slot() else {
        return busy();
    };
    let Some(second) = state.hasher.try_slot() else {
        return busy();
    };
    let now = state.clock.now().unix_timestamp();
    let reserve = login::reservation(&state, &user.email, form.viewer.address, now);
    let attempt = match throttle::reserve(&state.db, reserve).await {
        Ok(attempt) => attempt,
        Err(err) => return internal_error("password change", &err),
    };
    let Attempt::Counted {
        user_id,
        phc,
        epoch,
    } = attempt
    else {
        let wait = limit::window_seconds(state.config.limits.block_minutes);
        let refusal = refused(&state, &form.viewer, StatusCode::TOO_MANY_REQUESTS, BLOCKED).await;
        return limit::retry_after(refusal, wait);
    };
    let current = form.fields.get("current_password").to_owned();
    let verified = phc.clone();
    let matched = state.hasher.verify(first, current, phc).await;
    let (true, Some(user_id), Some(epoch), Some(old_phc)) = (matched, user_id, epoch, verified)
    else {
        login::record_failed(&state, user_id, &user.email).await;
        return refused(&state, &form.viewer, StatusCode::BAD_REQUEST, WRONG_CURRENT).await;
    };
    let new_phc = match state.hasher.hash(second, new_password).await {
        Ok(phc) => phc,
        Err(err) => return internal_error("password change", &err),
    };
    let change = Change {
        user_id,
        account: token_hash(&user.email),
        email: user.email,
        address: throttle_key(form.viewer.address),
        old_phc,
        epoch,
        session: form.viewer.presented_session().map(str::to_owned),
        new_phc,
        now,
        lifetime: session::lifetime_seconds(state.config.lifetimes.session_hours),
    };
    match state.db.call(move |conn| change_in(conn, &change)).await {
        Ok(Some(token)) => with_cookie(redirect("/account"), &session_cookie(&token)),
        Ok(None) => redirect("/login"),
        Err(err) => internal_error("password change", &err),
    }
}

/// One transaction: None, with nothing changed, unless the session exists and the verified hash
/// and epoch still match an enabled user.
pub(super) fn change_in(
    conn: &mut Connection,
    change: &Change,
) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !presented_session_exists(&tx, change.session.as_deref())? {
        return Ok(None);
    }
    throttle::clear_attempt(&tx, &change.account, &change.address)?;
    let updated = tx.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2 AND password_hash = ?3 \
         AND auth_epoch = ?4 AND disabled = 0",
        params![change.new_phc, change.user_id, change.old_phc, change.epoch],
    )?;
    if updated == 0 {
        return Ok(None);
    }
    session::revoke_all(&tx, change.user_id)?;
    let token = session::insert(&tx, change.user_id, change.now, change.lifetime)?;
    let changed = Event {
        kind: "password_change",
        user_id: Some(change.user_id),
        user_email: &change.email,
        detail: "password changed",
        ..Default::default()
    };
    audit::record(&tx, change.now, &changed)?;
    tx.commit()?;
    Ok(Some(token))
}

/// True when the presented cookie has a session row. Without a cookie there is none.
fn presented_session_exists(conn: &Connection, cookie: Option<&str>) -> rusqlite::Result<bool> {
    match cookie {
        Some(token) => session::exists(conn, token),
        None => Ok(false),
    }
}
