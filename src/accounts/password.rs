//! Changing the password while signed in. Shares the sign-in throttle for the wrong current password.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{Keys, token_hash};
use crate::oauth::connected;
use crate::vault::Unlock;
use crate::vault::keys::{self, Table};
use crate::web::limit;
use crate::web::{
    VerifiedForm, Viewer, busy, internal_error, redirect, session_cookie, throttle_key, with_cookie,
};

use super::account::account_page_with;
use super::input::valid_password;
use super::login;
use super::session;
use super::throttle::{self, Attempt};
use super::values;

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
    pub(super) vault: Option<ChangeVault>,
}

/// The vault side of a change: the unlock of the old password (None when it could not be made)
/// and of the new one.
pub(super) struct ChangeVault {
    pub(super) keys: Arc<Keys>,
    pub(super) old: Option<Unlock>,
    pub(super) new: Unlock,
}

/// The account page for a refused change, with the viewer's connected clients and credentials part.
async fn refused(state: &AppState, viewer: &Viewer, status: StatusCode, message: &str) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    let clients = match connected::list(&state.db, user.id, now).await {
        Ok(clients) => clients,
        Err(err) => return internal_error("connected clients", &err),
    };
    match values::part_for(state, viewer).await {
        Ok(part) => account_page_with(viewer, status, Some(message), &clients, &part),
        Err(err) => internal_error("stored values", &err),
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
        salt,
    } = attempt
    else {
        let wait = limit::window_seconds(state.config.limits.block_minutes);
        let refusal = refused(&state, &form.viewer, StatusCode::TOO_MANY_REQUESTS, BLOCKED).await;
        return limit::retry_after(refusal, wait);
    };
    let current = form.fields.get("current_password").to_owned();
    let verified = phc.clone();
    let fallback = user_id.map_or([0; 16], |id| state.keys.vault_salt(id));
    let (matched, old_unlock) = state
        .hasher
        .verify_unlock(first, current, phc, salt, fallback)
        .await;
    let (true, Some(user_id), Some(epoch), Some(old_phc)) = (matched, user_id, epoch, verified)
    else {
        login::record_failed(&state, user_id, &user.email).await;
        return refused(&state, &form.viewer, StatusCode::BAD_REQUEST, WRONG_CURRENT).await;
    };
    let (new_phc, new_unlock) = match state.hasher.hash_unlock(second, new_password).await {
        Ok(hashed) => hashed,
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
        vault: Some(ChangeVault {
            keys: Arc::clone(&state.keys),
            old: old_unlock,
            new: new_unlock,
        }),
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
    let new_key = match &change.vault {
        Some(vault) => {
            let old = match &vault.old {
                Some(unlock) => keys::open_password(&tx, &vault.keys, change.user_id, unlock)?,
                None => None,
            };
            let rekeyed = keys::rekey(
                &tx,
                &vault.keys,
                change.user_id,
                old.as_ref(),
                &vault.new,
                &change.email,
                change.now,
            )?;
            Some((rekeyed, &vault.keys))
        }
        None => None,
    };
    session::revoke_all(&tx, change.user_id)?;
    let token = session::insert(&tx, change.user_id, change.now, change.lifetime)?;
    if let Some((key, server_keys)) = &new_key {
        let row = token_hash(&token);
        keys::wrap_row(
            &tx,
            server_keys,
            change.user_id,
            Table::Sessions,
            &row,
            &token,
            key,
        )?;
    }
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
