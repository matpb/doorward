//! Changing the password while signed in. Shares the sign-in throttle for the wrong current password.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::token_hash;
use crate::web::{VerifiedForm, busy, internal_error, redirect, session_cookie, with_cookie};

use super::account::account_page;
use super::input::valid_password;
use super::login;
use super::session;
use super::throttle::{self, Attempt};

pub const PASSWORD_MESSAGE: &str = "The password must be 12 to 256 characters.";
const WRONG_CURRENT: &str = "The current password is wrong.";
const BLOCKED: &str = "Too many sign-in attempts. Try again later.";

/// What the change writes: the signed-in user, the reserved failure and the new password hash.
struct Change {
    user_id: i64,
    email: String,
    account: String,
    failure_id: i64,
    phc: String,
    now: i64,
    lifetime: i64,
}

pub async fn post_password(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(user) = form.viewer.user.clone() else {
        return redirect("/login");
    };
    let new_password = form.fields.get("new_password").to_owned();
    if !valid_password(&new_password) {
        return account_page(
            &form.viewer,
            StatusCode::BAD_REQUEST,
            Some(PASSWORD_MESSAGE),
        );
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
        Err(_) => return internal_error(),
    };
    let Attempt::Counted {
        failure_id,
        user_id,
        phc,
    } = attempt
    else {
        return account_page(&form.viewer, StatusCode::TOO_MANY_REQUESTS, Some(BLOCKED));
    };
    let current = form.fields.get("current_password").to_owned();
    let matched = state.hasher.verify(first, current, phc).await;
    let (true, Some(user_id)) = (matched, user_id) else {
        login::record_failed(&state, user_id, &user.email).await;
        return account_page(&form.viewer, StatusCode::BAD_REQUEST, Some(WRONG_CURRENT));
    };
    let phc = match state.hasher.hash(second, new_password).await {
        Ok(phc) => phc,
        Err(_) => return internal_error(),
    };
    let change = Change {
        user_id,
        account: token_hash(&user.email),
        email: user.email,
        failure_id,
        phc,
        now,
        lifetime: session::lifetime_seconds(state.config.lifetimes.session_hours),
    };
    match state.db.call(move |conn| change_in(conn, &change)).await {
        Ok(Some(token)) => with_cookie(redirect("/account"), &session_cookie(&token)),
        Ok(None) => internal_error(),
        Err(_) => internal_error(),
    }
}

/// One transaction: the sign-in clean-up, the new hash, every session ended, a new session and
/// the activity row. None when the user row is gone.
fn change_in(conn: &mut Connection, change: &Change) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    throttle::clear_attempt(&tx, &change.account, change.failure_id)?;
    let updated = tx.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![change.phc, change.user_id],
    )?;
    if updated == 0 {
        return Ok(None);
    }
    session::revoke_all(&tx, change.user_id)?;
    let token = session::insert(&tx, change.user_id, change.now, change.lifetime)?;
    let changed = Event {
        kind: "reset",
        user_id: Some(change.user_id),
        user_email: &change.email,
        detail: "password changed",
        ..Default::default()
    };
    audit::record(&tx, change.now, &changed)?;
    tx.commit()?;
    Ok(Some(token))
}
