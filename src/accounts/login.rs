use std::net::IpAddr;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use serde::Deserialize;

use crate::app::AppState;
use crate::audit::{self, OwnedEvent};
use crate::crypto::token_hash;
use crate::oauth::authorize::is_request_id;
use crate::report;
use crate::web::limit;
use crate::web::ui::{self, Note};
use crate::web::{
    SESSION_COOKIE, VerifiedForm, Viewer, busy, clear_cookie, form_page, internal_error, redirect,
    session_cookie, throttle_key, with_cookie,
};

use super::input::{normalize_email, to_i64};
use super::session;
use super::throttle::{self, Attempt, Reserve, Success};

const WRONG_CREDENTIALS: &str = "Wrong email or password.";
const BLOCKED: &str = "Too many sign-in attempts. Try again later.";
const UNKNOWN_ADDRESS: &str = "unknown address";

#[derive(Deserialize)]
pub struct LoginQuery {
    req: Option<String>,
}

pub async fn get_login(viewer: Viewer, Query(query): Query<LoginQuery>) -> Response {
    let req = query.req.unwrap_or_default();
    form_page(&viewer, StatusCode::OK, "login", "Sign in", |csrf| {
        login_form(csrf, &req, None)
    })
}

/// The steps of the throttling section, in order.
pub async fn post_login(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let email = normalize_email(form.fields.get("email"));
    let password = form.fields.get("password").to_owned();
    let req = form.fields.get("req").to_owned();
    let account = token_hash(&email);
    let Some(slot) = state.hasher.try_slot() else {
        return busy();
    };
    let now = state.clock.now().unix_timestamp();
    let reserve = reservation(&state, &email, form.viewer.address, now);
    let attempt = match throttle::reserve(&state.db, reserve).await {
        Ok(attempt) => attempt,
        Err(err) => return internal_error("sign-in", &err),
    };
    let Attempt::Counted {
        user_id,
        phc,
        epoch,
    } = attempt
    else {
        let wait = limit::window_seconds(state.config.limits.block_minutes);
        return limit::retry_after(
            login_page(&form, StatusCode::TOO_MANY_REQUESTS, BLOCKED, &req),
            wait,
        );
    };
    let verified = phc.clone();
    let matched = state.hasher.verify(slot, password, phc).await;
    let (true, Some(user_id), Some(epoch), Some(phc)) = (matched, user_id, epoch, verified) else {
        record_failed(&state, user_id, &email).await;
        return login_page(&form, StatusCode::UNAUTHORIZED, WRONG_CREDENTIALS, &req);
    };
    let success = Success {
        account,
        address: throttle_key(form.viewer.address),
        user_id,
        email: email.clone(),
        previous: form.viewer.presented_session().map(str::to_owned),
        now,
        lifetime: session::lifetime_seconds(state.config.lifetimes.session_hours),
        phc,
        epoch,
    };
    match throttle::succeed(&state.db, success).await {
        Ok(Some(token)) => with_cookie(redirect(&after_sign_in(&req)), &session_cookie(&token)),
        Ok(None) => {
            record_failed(&state, Some(user_id), &email).await;
            login_page(&form, StatusCode::UNAUTHORIZED, WRONG_CREDENTIALS, &req)
        }
        Err(err) => internal_error("sign-in", &err),
    }
}

/// The page after a sign-in: consent for a request id of the exact shape, else the account page.
pub fn after_sign_in(req: &str) -> String {
    if is_request_id(req) {
        format!("/oauth/consent?req={req}")
    } else {
        "/account".to_owned()
    }
}

/// The reservation of one attempt: `email` is normalised, `address` is the client address.
pub(super) fn reservation(state: &AppState, email: &str, address: IpAddr, now: i64) -> Reserve {
    let limits = &state.config.limits;
    Reserve {
        account: token_hash(email),
        address: throttle_key(address),
        email: email.to_owned(),
        now,
        block_seconds: to_i64(limits.block_minutes).saturating_mul(60),
        account_failures: to_i64(limits.account_failures),
        account_ceiling: to_i64(limits.account_ceiling),
        address_failures: to_i64(limits.address_failures),
    }
}

/// Writes the `login_failed` row. A failed write is reported and never changes the answer.
pub(super) async fn record_failed(state: &AppState, user_id: Option<i64>, email: &str) {
    let event = match user_id {
        Some(id) => OwnedEvent {
            kind: "login_failed".to_owned(),
            user_id: Some(id),
            user_email: email.to_owned(),
            ..Default::default()
        },
        None => OwnedEvent {
            kind: "login_failed".to_owned(),
            detail: UNKNOWN_ADDRESS.to_owned(),
            ..Default::default()
        },
    };
    if let Err(err) = audit::record_now(state, event).await {
        report::failure("sign-in record", &err);
    }
}

pub async fn post_logout(State(state): State<AppState>, form: VerifiedForm) -> Response {
    if let Some(token) = form.viewer.presented_session().map(str::to_owned) {
        let deleted = state
            .db
            .call(move |conn| session::delete(conn, &token))
            .await;
        if let Err(err) = deleted {
            return internal_error("sign-out", &err);
        }
    }
    with_cookie(redirect("/login"), &clear_cookie(SESSION_COOKIE))
}

fn login_page(form: &VerifiedForm, status: StatusCode, message: &str, req: &str) -> Response {
    form_page(&form.viewer, status, "login", "Sign in", |csrf| {
        login_form(csrf, req, Some(message))
    })
}

fn login_form(csrf: &str, req: &str, error: Option<&str>) -> Markup {
    html! {
        h1 { "Sign in" }
        @if let Some(message) = error {
            (ui::refused(None, message, None))
        }
        form.flow method="post" action="/login" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="req" value=(req);
            div.fields {
                (ui::field(
                    "email",
                    "Email",
                    false,
                    html! { input id="email" name="email" type="email" autocomplete="username" required; },
                    Note::None,
                ))
            }
            div.fields {
                div.field {
                    label for="password" { "Password" }
                    input id="password" name="password" type="password" autocomplete="current-password" required;
                    a.field-link href="/forgot" { "Forgot your password?" }
                }
            }
            button type="submit" data-kind="primary" { "Sign in" }
        }
    }
}

#[cfg(test)]
mod tests {
    use scraper::{Html, Selector};

    use super::*;

    /// The sign-in body as a fragment, with the error line when one is given.
    fn body(error: Option<&str>) -> Html {
        Html::parse_fragment(&login_form("token", "", error).into_string())
    }

    /// How many elements of `doc` match `css`.
    fn count(doc: &Html, css: &str) -> usize {
        doc.select(&Selector::parse(css).expect("selector")).count()
    }

    #[test]
    fn the_sign_in_form_has_one_primary_button_and_keeps_its_fields() {
        let doc = body(None);
        assert_eq!(count(&doc, "h1"), 1);
        assert_eq!(count(&doc, r#"form > button[data-kind="primary"]"#), 1);
        assert_eq!(count(&doc, "form > input[name=csrf][type=hidden]"), 1);
        assert_eq!(
            count(
                &doc,
                r#"div.field > label[for="email"] + input#email[name=email]"#
            ),
            1
        );
        assert_eq!(
            count(
                &doc,
                r#"div.field > label[for="password"] + input#password[name=password]"#
            ),
            1
        );
        assert_eq!(count(&doc, "div.notice"), 0);
    }

    #[test]
    fn the_forgot_link_is_the_password_fields_last_child() {
        let doc = body(None);
        let link = Selector::parse("div.field > a.field-link").expect("selector");
        let links: Vec<String> = doc
            .select(&link)
            .map(|element| element.text().collect())
            .collect();
        assert_eq!(links, vec!["Forgot your password?".to_owned()]);
        assert_eq!(count(&doc, r#"a.field-link[href="/forgot"]"#), 1);
    }

    #[test]
    fn a_refused_sign_in_shows_its_message_in_an_error_notice() {
        let doc = body(Some(WRONG_CREDENTIALS));
        let selector = Selector::parse(r#"div.notice[data-notice="error"][role="alert"] > p"#)
            .expect("selector");
        let errors: Vec<String> = doc
            .select(&selector)
            .map(|element| element.text().collect())
            .collect();
        assert_eq!(errors, vec!["Wrong email or password.".to_owned()]);
    }
}
