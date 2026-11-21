//! Password reset: the public request, the background mail task and the link page.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{random_token, token_hash};
use crate::mail;
use crate::mail::templates;
use crate::report;
use crate::web::ui::{self, Note};
use crate::web::{
    VerifiedForm, Viewer, busy, form_page, internal_error, not_found_link, page, redirect,
};

use super::input::{normalize_email, to_i64, valid_password};
use super::password::PASSWORD_MESSAGE;
use super::session;
use super::throttle;

const RESET_PREFIX: &str = "dw_rs_";
const MINUTE_SECONDS: i64 = 60;
/// At most one reset mail per account inside this many seconds.
pub const REQUEST_GAP_SECONDS: i64 = 300;

/// A reset link that can still be used: its user and that user's address.
struct Reset {
    user_id: i64,
    email: String,
}

/// What completing a reset writes: the link's hash, the new password hash and the time.
struct Complete {
    hash: String,
    phc: String,
    now: i64,
}

/// The reset row of a token hash, when it has not expired and its user is enabled.
fn usable_in(conn: &Connection, hash: &str, now: i64) -> rusqlite::Result<Option<Reset>> {
    conn.query_row(
        "SELECT r.user_id, u.email FROM password_resets r JOIN users u ON u.id = r.user_id \
         WHERE r.token_hash = ?1 AND r.expires_at > ?2 AND u.disabled = 0",
        params![hash, now],
        |row| {
            Ok(Reset {
                user_id: row.get(0)?,
                email: row.get(1)?,
            })
        },
    )
    .optional()
}

pub async fn get_forgot(viewer: Viewer) -> Response {
    form_page(
        &viewer,
        StatusCode::OK,
        "forgot",
        "Forgot your password",
        forgot_body,
    )
}

/// Answers the same for every address. The work happens in a task, and only when a permit is free.
pub async fn post_forgot(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let email = normalize_email(form.fields.get("email"));
    if let Ok(permit) = Arc::clone(&state.reset_requests).try_acquire_owned() {
        tokio::spawn(async move {
            let _permit = permit;
            send_reset_mail(&state, email).await;
        });
    }
    forgot_sent()
}

/// The background half of `POST /forgot`. Failures are logged by the mail module or dropped here.
async fn send_reset_mail(state: &AppState, email: String) {
    let token = random_token(RESET_PREFIX);
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    let lifetime = to_i64(state.config.lifetimes.reset_minutes).saturating_mul(MINUTE_SECONDS);
    let recipient = email.clone();
    let stored = state
        .db
        .call(move |conn| store_reset_in(conn, &email, &hash, now, lifetime))
        .await;
    match stored {
        Ok(true) => {}
        Ok(false) => return,
        Err(err) => {
            report::failure("password reset", &err);
            return;
        }
    }
    let link = format!("{}/reset/{token}", state.config.public_url);
    let message = templates::reset(&link).to(recipient);
    // mail::send has already recorded any failure in the activity log.
    let _ = mail::send(state, "reset", message).await;
}

/// One transaction: the user must exist and be enabled, and no reset may have been stored in the
/// last five minutes. Returns true when a new reset row was written.
fn store_reset_in(
    conn: &mut Connection,
    email: &str,
    hash: &str,
    now: i64,
    lifetime: i64,
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let user: Option<(i64, i64)> = tx
        .query_row(
            "SELECT id, disabled FROM users WHERE email = ?1",
            params![email],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((user_id, disabled)) = user else {
        return Ok(false);
    };
    if disabled != 0 {
        return Ok(false);
    }
    let recent: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM password_resets WHERE user_id = ?1 AND created_at > ?2)",
        params![user_id, now.saturating_sub(REQUEST_GAP_SECONDS)],
        |row| row.get(0),
    )?;
    if recent {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(user_id) DO UPDATE SET token_hash = excluded.token_hash, \
         created_at = excluded.created_at, expires_at = excluded.expires_at",
        params![user_id, hash, now, now.saturating_add(lifetime)],
    )?;
    let requested = Event {
        kind: "reset",
        user_id: Some(user_id),
        user_email: email,
        detail: "requested",
        ..Default::default()
    };
    audit::record(&tx, now, &requested)?;
    tx.commit()?;
    Ok(true)
}

pub async fn get_reset(
    viewer: Viewer,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    match state.db.call(move |conn| usable_in(conn, &hash, now)).await {
        Ok(Some(_)) => form_page(
            &viewer,
            StatusCode::OK,
            "reset",
            "Choose a new password",
            reset_body,
        ),
        Ok(None) => not_found_link(),
        Err(err) => internal_error("reset page", &err),
    }
}

pub async fn post_reset(
    State(state): State<AppState>,
    Path(token): Path<String>,
    form: VerifiedForm,
) -> Response {
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    let lookup = hash.clone();
    match state
        .db
        .call(move |conn| usable_in(conn, &lookup, now))
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return not_found_link(),
        Err(err) => return internal_error("reset link", &err),
    }
    let password = form.fields.get("password").to_owned();
    if !valid_password(&password) {
        return form_page(
            &form.viewer,
            StatusCode::BAD_REQUEST,
            "reset",
            "Choose a new password",
            |csrf| reset_form(csrf, Some(PASSWORD_MESSAGE)),
        );
    }
    let Some(slot) = state.hasher.try_slot() else {
        return busy();
    };
    let phc = match state.hasher.hash(slot, password).await {
        Ok(phc) => phc,
        Err(err) => return internal_error("password reset", &err),
    };
    let complete = Complete { hash, phc, now };
    match state
        .db
        .call(move |conn| complete_in(conn, &complete))
        .await
    {
        Ok(true) => redirect("/login"),
        Ok(false) => not_found_link(),
        Err(err) => internal_error("password reset", &err),
    }
}

/// One transaction: the link is read again, the password changes, every session ends, the link
/// is spent and the account's sign-in block is lifted. False when the link is no longer usable.
fn complete_in(conn: &mut Connection, complete: &Complete) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(reset) = usable_in(&tx, &complete.hash, complete.now)? else {
        return Ok(false);
    };
    tx.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![complete.phc, reset.user_id],
    )?;
    session::revoke_all(&tx, reset.user_id)?;
    tx.execute(
        "DELETE FROM password_resets WHERE user_id = ?1",
        params![reset.user_id],
    )?;
    throttle::lift_block(&tx, &reset.email)?;
    let completed = Event {
        kind: "reset",
        user_id: Some(reset.user_id),
        user_email: &reset.email,
        detail: "completed",
        ..Default::default()
    };
    audit::record(&tx, complete.now, &completed)?;
    tx.commit()?;
    Ok(true)
}

fn forgot_sent() -> Response {
    page(
        StatusCode::OK,
        "forgot-sent",
        "Check your email",
        html! {
            h1 { "Check your email" }
            p.lede { "If an account exists for that address, a link to reset its password is on its way." }
        },
    )
}

fn forgot_body(csrf: &str) -> Markup {
    html! {
        h1 { "Forgot your password?" }
        p.lede { "Enter your email address. If an account exists for it, a reset link is sent." }
        form.flow method="post" action="/forgot" {
            input type="hidden" name="csrf" value=(csrf);
            div.fields {
                (ui::field(
                    "email",
                    "Email",
                    false,
                    html! { input id="email" name="email" type="email" autocomplete="username" required; },
                    Note::None,
                ))
            }
            button type="submit" data-kind="primary" { "Send reset link" }
        }
        p.back { a href="/login" { "Back to sign in" } }
    }
}

fn reset_body(csrf: &str) -> Markup {
    reset_form(csrf, None)
}

/// The form posts to the address it was loaded from, so the token never appears in the page.
/// A refused password is named in a notice and marked under its field.
fn reset_form(csrf: &str, error: Option<&str>) -> Markup {
    let note = ui::note_under(error, Some("12 to 256 characters."));
    let described = note.describer("password");
    html! {
        h1 { "Choose a new password" }
        @if error.is_some() {
            (ui::refused(Some("The password was not changed."), None, None))
        }
        form.flow method="post" {
            input type="hidden" name="csrf" value=(csrf);
            div.fields {
                (ui::field(
                    "password",
                    "New password",
                    false,
                    html! {
                        input id="password" name="password" type="password" autocomplete="new-password" required
                            aria-invalid=[ui::invalid(error)] aria-describedby=[described.as_deref()];
                    },
                    note,
                ))
            }
            button type="submit" data-kind="primary" { "Set password" }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use scraper::{Html, Selector};

    use super::*;

    /// How many elements of `doc` match `css`.
    fn count(doc: &Html, css: &str) -> usize {
        doc.select(&Selector::parse(css).expect("selector")).count()
    }

    #[test]
    fn the_forgot_page_has_a_lede_and_one_primary_button() {
        let doc = Html::parse_fragment(&forgot_body("token").into_string());
        assert_eq!(count(&doc, "h1 + p.lede"), 1);
        assert_eq!(count(&doc, r#"form > button[data-kind="primary"]"#), 1);
        assert_eq!(
            count(
                &doc,
                "div.field > label[for=email] + input#email[name=email]"
            ),
            1
        );
    }

    #[test]
    fn the_forgot_page_links_back_to_sign_in_after_its_form() {
        assert_eq!(
            forgot_body("token")
                .into_string()
                .rsplit_once("</form>")
                .map(|(_, tail)| tail),
            Some(r#"<p class="back"><a href="/login">Back to sign in</a></p>"#)
        );
    }

    #[test]
    fn the_choose_password_page_has_one_primary_button_and_its_field() {
        let doc = Html::parse_fragment(&reset_form("token", None).into_string());
        assert_eq!(count(&doc, "h1"), 1);
        assert_eq!(count(&doc, r#"form > button[data-kind="primary"]"#), 1);
        assert_eq!(
            count(
                &doc,
                "div.field > label[for=password] + input#password + p.hint"
            ),
            1,
            "the password hint must sit under its field, out of the label"
        );
        assert_eq!(count(&doc, "div.notice"), 0);
    }

    #[test]
    fn a_refused_password_names_the_refusal_and_marks_its_field() {
        let doc = Html::parse_fragment(
            &reset_form("token", Some("The password must be 12 to 256 characters.")).into_string(),
        );
        assert_eq!(
            count(
                &doc,
                r#"div.notice[data-notice="error"][role="alert"] > p > strong"#
            ),
            1
        );
        assert_eq!(
            count(
                &doc,
                r#"input#password[aria-invalid="true"][aria-describedby="password-error"]"#
            ),
            1
        );
        assert_eq!(count(&doc, "div.field > p.field-error#password-error"), 1);
    }

    #[test]
    fn a_refused_password_notice_is_exactly_its_lead_in() {
        let markup =
            reset_form("token", Some("The password must be 12 to 256 characters.")).into_string();
        assert!(
            markup.contains(r#"<div class="notice" data-notice="error" role="alert"><p><strong>The password was not changed.</strong></p></div>"#),
            "the refused reset notice must be exactly its lead-in markup: {markup}"
        );
    }

    #[tokio::test]
    async fn the_check_email_page_has_its_sentence_as_a_lede() {
        let bytes = to_bytes(forgot_sent().into_body(), usize::MAX)
            .await
            .expect("body");
        let doc = Html::parse_document(std::str::from_utf8(&bytes).expect("utf-8"));
        assert_eq!(count(&doc, "h1 + p.lede"), 1);
    }
}
