use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::constant_time_eq;
use crate::db::{Db, DbError};
use crate::vault::Unlocked;
use crate::vault::keys;
use crate::web::ui::{self, Note};
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
            |csrf| setup_form(csrf, None, None),
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
    let (phc, unlock) = match state.hasher.hash_unlock(slot, password.to_owned()).await {
        Ok(hashed) => hashed,
        Err(err) => return internal_error("setup", &err),
    };
    let vault = unlock.map(|unlock| Unlocked {
        keys: Arc::clone(&state.keys),
        unlock,
    });
    let now = state.clock.now().unix_timestamp();
    let lifetime = session::lifetime_seconds(state.config.lifetimes.session_hours);
    let previous = form.viewer.presented_session().map(str::to_owned);
    let created = state
        .db
        .call(move |conn| {
            create_owner_in(
                conn,
                &email,
                &phc,
                now,
                lifetime,
                previous.as_deref(),
                vault.as_ref(),
            )
        })
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
pub(super) fn create_owner_in(
    conn: &mut Connection,
    email: &str,
    phc: &str,
    now: i64,
    lifetime: i64,
    previous: Option<&str>,
    vault: Option<&Unlocked>,
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
    if let Some(vault) = vault {
        keys::sign_in(&tx, vault, user_id, &token)?;
    }
    tx.commit()?;
    Ok(Some(token))
}

/// The setup page again with the refusal. The email comes back; the password and the code never do.
fn setup_error(form: &VerifiedForm, message: &str) -> Response {
    let email = ui::sent_back(form.fields.get("email"), ui::EMAIL_SENT_BACK_LIMIT);
    form_page(
        &form.viewer,
        StatusCode::BAD_REQUEST,
        "setup",
        "Set up Doorward",
        |csrf| setup_form(csrf, Some(&email), Some(message)),
    )
}

/// The setup form; `email` is the address to show again, when a refused post sent one.
fn setup_form(csrf: &str, email: Option<&str>, error: Option<&str>) -> Markup {
    let password_note = Note::Hint("12 to 256 characters.");
    let password_described = password_note.describer("password");
    html! {
        h1 { "Set up Doorward" }
        p.lede { "Enter the setup code printed when the gateway started, then the owner's email and a password." }
        @if let Some(message) = error {
            (ui::refused(None, message, None))
        }
        form.flow method="post" action="/setup" {
            input type="hidden" name="csrf" value=(csrf);
            div.fields {
                (ui::field(
                    "setup_code",
                    "Setup code",
                    false,
                    html! { input class="mono" id="setup_code" name="setup_code" type="text" autocomplete="off" required; },
                    Note::None,
                ))
            }
            div.fields {
                (ui::field(
                    "email",
                    "Owner email",
                    false,
                    html! { input id="email" name="email" type="email" autocomplete="username" required value=[email]; },
                    Note::None,
                ))
            }
            div.fields {
                (ui::field(
                    "password",
                    "Password",
                    false,
                    html! {
                        input id="password" name="password" type="password" autocomplete="new-password" required
                            aria-describedby=[password_described.as_deref()];
                    },
                    password_note,
                ))
            }
            button type="submit" data-kind="primary" { "Create owner" }
        }
    }
}

#[cfg(test)]
mod tests {
    use scraper::{Html, Selector};

    use super::*;

    /// How many elements of `doc` match `css`.
    fn count(doc: &Html, css: &str) -> usize {
        doc.select(&Selector::parse(css).expect("selector")).count()
    }

    #[test]
    fn the_setup_page_has_a_lede_under_its_heading_and_one_primary_button() {
        let doc = Html::parse_fragment(&setup_form("token", None, None).into_string());
        assert_eq!(count(&doc, "h1"), 1);
        assert_eq!(
            count(&doc, "h1 + p.lede"),
            1,
            "the sentence under the heading must be a lede"
        );
        assert_eq!(count(&doc, r#"form > button[data-kind="primary"]"#), 1);
        assert_eq!(count(&doc, "div.notice"), 0);
        assert_eq!(
            count(
                &doc,
                "div.field > label[for=password] + input#password[aria-describedby=password-hint] + p.hint#password-hint"
            ),
            1,
            "the password field must carry its hint, not a bracket in its label"
        );
    }
}
