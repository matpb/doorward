use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::constant_time_eq;
use crate::db::{Db, DbError};
use crate::web::{
    VerifiedForm, Viewer, busy, forbidden, form_page, internal_error, not_found, redirect,
    session_cookie, with_cookie,
};

use super::input::{normalize_email, valid_new_email, valid_password};
use super::session;

const SETUP_CODE_FIELD: &str = "setup_code";
const EMAIL_MESSAGE: &str = "Enter a valid email address.";
const PASSWORD_MESSAGE: &str = "The password must be 12 to 256 characters.";

/// True when some user has the owner role.
pub async fn owner_exists(db: &Db) -> Result<bool, DbError> {
    db.call(|conn| {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')",
            [],
            |row| row.get(0),
        )
    })
    .await
}

pub async fn get_setup(viewer: Viewer, State(state): State<AppState>) -> Response {
    match setup_open(&state).await {
        Ok(true) => form_page(
            &viewer,
            StatusCode::OK,
            "setup",
            "Set up Doorward",
            |csrf| setup_form(csrf, None),
        ),
        Ok(false) => not_found(),
        Err(err) => internal_error("setup page", &err),
    }
}

pub async fn post_setup(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(code) = state.setup_code.as_deref() else {
        return not_found();
    };
    match setup_open(&state).await {
        Ok(true) => {}
        Ok(false) => return not_found(),
        Err(err) => return internal_error("setup", &err),
    }
    let submitted = form.fields.get(SETUP_CODE_FIELD);
    if !constant_time_eq(submitted.as_bytes(), code.as_bytes()) {
        return forbidden();
    }
    let email = normalize_email(form.fields.get("email"));
    let password = form.fields.get("password");
    if !valid_new_email(&email) {
        return setup_error(&form, EMAIL_MESSAGE);
    }
    if !valid_password(password) {
        return setup_error(&form, PASSWORD_MESSAGE);
    }
    let Some(slot) = state.hasher.try_slot() else {
        return busy();
    };
    let phc = match state.hasher.hash(slot, password.to_owned()).await {
        Ok(phc) => phc,
        Err(err) => return internal_error("setup", &err),
    };
    let now = state.clock.now().unix_timestamp();
    let lifetime = session::lifetime_seconds(state.config.lifetimes.session_hours);
    let previous = form.viewer.presented_session().map(str::to_owned);
    let created = state
        .db
        .call(move |conn| create_owner_in(conn, &email, &phc, now, lifetime, previous.as_deref()))
        .await;
    match created {
        Ok(Some(token)) => with_cookie(redirect("/admin"), &session_cookie(&token)),
        Ok(None) => not_found(),
        Err(err) => internal_error("setup", &err),
    }
}

/// Open while the instance started with a setup code and no owner exists.
async fn setup_open(state: &AppState) -> Result<bool, DbError> {
    if state.setup_code.is_none() {
        return Ok(false);
    }
    Ok(!owner_exists(&state.db).await?)
}

/// One transaction: the "no owner yet" check and the insert. None when an owner already exists.
fn create_owner_in(
    conn: &mut Connection,
    email: &str,
    phc: &str,
    now: i64,
    lifetime: i64,
    previous: Option<&str>,
) -> rusqlite::Result<Option<String>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let owners: i64 = tx.query_row(
        "SELECT COUNT(*) FROM users WHERE role = 'owner'",
        [],
        |row| row.get(0),
    )?;
    if owners > 0 {
        return Ok(None);
    }
    let inserted = tx.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, ?2, 'owner', ?3)",
        params![email, phc, now],
    );
    match inserted {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == ErrorCode::ConstraintViolation =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    let user_id = tx.last_insert_rowid();
    let created = Event {
        kind: "owner_created",
        user_id: Some(user_id),
        user_email: email,
        ..Default::default()
    };
    audit::record(&tx, now, &created)?;
    if let Some(previous) = previous {
        session::delete(&tx, previous)?;
    }
    let token = session::insert(&tx, user_id, now, lifetime)?;
    tx.commit()?;
    Ok(Some(token))
}

fn setup_error(form: &VerifiedForm, message: &str) -> Response {
    form_page(
        &form.viewer,
        StatusCode::BAD_REQUEST,
        "setup",
        "Set up Doorward",
        |csrf| setup_form(csrf, Some(message)),
    )
}

fn setup_form(csrf: &str, error: Option<&str>) -> Markup {
    html! {
        h1 { "Set up Doorward" }
        p { "Enter the setup code printed when the gateway started, then the owner's email and a password of 12 to 256 characters." }
        @if let Some(message) = error {
            p.error { (message) }
        }
        form method="post" action="/setup" {
            input type="hidden" name="csrf" value=(csrf);
            label for="setup_code" { "Setup code" }
            input id="setup_code" name="setup_code" type="text" autocomplete="off" required;
            label for="email" { "Owner email" }
            input id="email" name="email" type="email" autocomplete="username" required;
            label for="password" { "Password" }
            input id="password" name="password" type="password" autocomplete="new-password" required;
            button type="submit" { "Create owner" }
        }
    }
}
