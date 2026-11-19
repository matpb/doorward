use std::net::IpAddr;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use serde::Deserialize;

use crate::app::AppState;
use crate::audit::{self, OwnedEvent};
use crate::crypto::token_hash;
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
        Err(_) => return internal_error(),
    };
    let Attempt::Counted {
        failure_id,
        user_id,
        phc,
    } = attempt
    else {
        return login_page(&form, StatusCode::TOO_MANY_REQUESTS, BLOCKED, &req);
    };
    let matched = state.hasher.verify(slot, password, phc).await;
    let (true, Some(user_id)) = (matched, user_id) else {
        record_failed(&state, user_id, &email).await;
        return login_page(&form, StatusCode::UNAUTHORIZED, WRONG_CREDENTIALS, &req);
    };
    let success = Success {
        account,
        failure_id,
        user_id,
        email,
        previous: form.viewer.presented_session().map(str::to_owned),
        now,
        lifetime: session::lifetime_seconds(state.config.lifetimes.session_hours),
    };
    match throttle::succeed(&state.db, success).await {
        Ok(token) => with_cookie(redirect("/account"), &session_cookie(&token)),
        Err(_) => internal_error(),
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
        eprintln!("doorward: cannot record a failed sign-in: {err}");
    }
}

pub async fn post_logout(State(state): State<AppState>, form: VerifiedForm) -> Response {
    if let Some(token) = form.viewer.presented_session().map(str::to_owned) {
        let deleted = state
            .db
            .call(move |conn| session::delete(conn, &token))
            .await;
        if deleted.is_err() {
            return internal_error();
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
            p.error { (message) }
        }
        form method="post" action="/login" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="req" value=(req);
            label for="email" { "Email" }
            input id="email" name="email" type="email" autocomplete="username" required;
            label for="password" { "Password" }
            input id="password" name="password" type="password" autocomplete="current-password" required;
            button type="submit" { "Sign in" }
        }
    }
}
