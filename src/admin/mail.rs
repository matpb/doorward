use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::accounts::input::{normalize_email, valid_new_email};
use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::{CryptoError, Keys};
use crate::db::{self, Db, DbError};
use crate::mail::{self, Message};
use crate::web::{
    FormFields, SessionUser, VerifiedForm, Viewer, forbidden, form_page, internal_error, redirect,
};

use super::panel_nav;

const PLAIN_KEYS: [&str; 9] = [
    "mail.provider",
    "mail.from",
    "mail.smtp_host",
    "mail.smtp_port",
    "mail.smtp_username",
    "mail.smtp_tls",
    "mail.resend_base_url",
    "mail.mailgun_domain",
    "mail.mailgun_base_url",
];
const CONTROL_MESSAGE: &str = "A field contains a control character.";
const PROVIDER_MESSAGE: &str = "Choose a provider: smtp, resend or mailgun.";
const PORT_MESSAGE: &str = "The SMTP port must be a number from 1 to 65535.";
const TLS_MESSAGE: &str = "Choose a TLS mode: off, starttls or implicit.";
const TEST_TO_MESSAGE: &str = "Enter a valid email address.";
const TEST_SENT: &str = "Test email sent.";
const TEST_SUBJECT: &str = "Doorward test email";
const TEST_TEXT: &str = "This is a test email from Doorward.";
const TEST_HTML: &str = "<p>This is a test email from Doorward.</p>";

/// The plain settings as stored. Secrets are never loaded for display.
type View = BTreeMap<String, String>;

/// What one save writes: the plain values, the sealed secret when one was posted, and the connection fields.
pub struct Plan {
    plain: Vec<(&'static str, String)>,
    secret_key: &'static str,
    sealed: Option<String>,
    connection: Vec<(&'static str, String)>,
}

/// A refused post answers 400; a failed seal answers 500.
enum PlanError {
    Invalid(&'static str),
    Seal(CryptoError),
}

/// A save the page refuses: the provider whose form was posted when its name is one of the three,
/// and the reason. Without a provider the reason sits at the top of the page.
#[derive(Clone, Copy)]
struct Refused {
    provider: Option<&'static str>,
    reason: &'static str,
}

/// The providers, in the order of their disclosures.
const PROVIDERS: [&str; 3] = ["smtp", "resend", "mailgun"];

/// The provider of a name, when the name is one of the three.
fn provider_named(name: &str) -> Option<&'static str> {
    PROVIDERS.into_iter().find(|known| *known == name)
}

pub async fn get_mail(viewer: Viewer, State(state): State<AppState>) -> Response {
    match load_view(&state.db).await {
        Ok(view) => mail_page(&viewer, StatusCode::OK, &view, None, None, None),
        Err(err) => internal_error("mail page", &err),
    }
}

pub async fn post_mail(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let plan = match plan_from(&form.fields, &state.keys) {
        Ok(plan) => plan,
        Err(PlanError::Invalid(reason)) => {
            let refused = Refused {
                provider: provider_named(form.fields.get("provider")),
                reason,
            };
            return match load_view(&state.db).await {
                Ok(view) => mail_page(
                    &form.viewer,
                    StatusCode::BAD_REQUEST,
                    &view,
                    Some(refused),
                    None,
                    None,
                ),
                Err(err) => internal_error("mail page", &err),
            };
        }
        Err(PlanError::Seal(err)) => return internal_error("mail settings", &err),
    };
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let at = state.clock.now().unix_timestamp();
    let saved = state
        .db
        .call(move |conn| save_in(conn, &plan, &actor, at))
        .await;
    match saved {
        Ok(()) => redirect("/admin/mail"),
        Err(err) => internal_error("mail settings", &err),
    }
}

/// Sends the owner's test email. A bad address answers 400; a send answers 200 with its outcome.
pub async fn post_test(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let to = normalize_email(form.fields.get("to"));
    if !valid_new_email(&to) {
        return test_answer(
            &state,
            &form.viewer,
            StatusCode::BAD_REQUEST,
            None,
            Some(TEST_TO_MESSAGE),
        )
        .await;
    }
    let message = Message {
        to,
        subject: TEST_SUBJECT.to_owned(),
        text: TEST_TEXT.to_owned(),
        html: TEST_HTML.to_owned(),
    };
    match mail::send(&state, "test", message).await {
        Ok(()) => test_answer(&state, &form.viewer, StatusCode::OK, Some(TEST_SENT), None).await,
        Err(error) => {
            test_answer(
                &state,
                &form.viewer,
                StatusCode::OK,
                None,
                Some(error.0.as_str()),
            )
            .await
        }
    }
}

/// The mail page carrying the outcome of a test send.
async fn test_answer(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    notice: Option<&str>,
    error: Option<&str>,
) -> Response {
    match load_view(&state.db).await {
        Ok(view) => mail_page(viewer, status, &view, None, notice, error),
        Err(err) => internal_error("mail page", &err),
    }
}

async fn load_view(db: &Db) -> Result<View, DbError> {
    db.call(|conn| {
        let mut view = View::new();
        for key in PLAIN_KEYS {
            if let Some(value) = db::setting_text(conn, key)? {
                view.insert(key.to_owned(), value);
            }
        }
        Ok(view)
    })
    .await
}

/// Validates the post and builds the plan for the posted provider only. Seals the secret here.
fn plan_from(fields: &FormFields, keys: &Keys) -> Result<Plan, PlanError> {
    if fields
        .pairs()
        .any(|(name, value)| has_control(name) || has_control(value))
    {
        return Err(PlanError::Invalid(CONTROL_MESSAGE));
    }
    let from = fields.get("from").to_owned();
    match fields.get("provider") {
        "smtp" => smtp_plan(fields, keys, from),
        "resend" => resend_plan(fields, keys, from),
        "mailgun" => mailgun_plan(fields, keys, from),
        _ => Err(PlanError::Invalid(PROVIDER_MESSAGE)),
    }
}

/// The sealed secret, or None when the posted secret field is empty.
fn seal_secret(keys: &Keys, secret_key: &str, secret: &str) -> Result<Option<String>, PlanError> {
    if secret.is_empty() {
        return Ok(None);
    }
    let context = format!("settings.value:{secret_key}");
    keys.seal(&context, secret.as_bytes())
        .map(Some)
        .map_err(PlanError::Seal)
}

fn smtp_plan(fields: &FormFields, keys: &Keys, from: String) -> Result<Plan, PlanError> {
    let port = port_text(fields.get("smtp_port"))?;
    let tls = fields.get("smtp_tls");
    if !matches!(tls, "off" | "starttls" | "implicit") {
        return Err(PlanError::Invalid(TLS_MESSAGE));
    }
    let host = fields.get("smtp_host").to_owned();
    let username = fields.get("smtp_username").to_owned();
    let connection = vec![
        ("mail.smtp_host", host.clone()),
        ("mail.smtp_port", port.clone()),
        ("mail.smtp_username", username.clone()),
        ("mail.smtp_tls", tls.to_owned()),
    ];
    let plain = vec![
        ("mail.provider", "smtp".to_owned()),
        ("mail.from", from),
        ("mail.smtp_host", host),
        ("mail.smtp_port", port),
        ("mail.smtp_username", username),
        ("mail.smtp_tls", tls.to_owned()),
    ];
    Ok(Plan {
        plain,
        secret_key: "mail.smtp_password",
        sealed: seal_secret(keys, "mail.smtp_password", fields.get("smtp_password"))?,
        connection,
    })
}

fn resend_plan(fields: &FormFields, keys: &Keys, from: String) -> Result<Plan, PlanError> {
    let base_url = fields.get("resend_base_url").to_owned();
    Ok(Plan {
        plain: vec![
            ("mail.provider", "resend".to_owned()),
            ("mail.from", from),
            ("mail.resend_base_url", base_url.clone()),
        ],
        secret_key: "mail.resend_api_key",
        sealed: seal_secret(keys, "mail.resend_api_key", fields.get("resend_api_key"))?,
        connection: vec![("mail.resend_base_url", base_url)],
    })
}

fn mailgun_plan(fields: &FormFields, keys: &Keys, from: String) -> Result<Plan, PlanError> {
    let domain = fields.get("mailgun_domain").to_owned();
    let base_url = fields.get("mailgun_base_url").to_owned();
    Ok(Plan {
        plain: vec![
            ("mail.provider", "mailgun".to_owned()),
            ("mail.from", from),
            ("mail.mailgun_domain", domain.clone()),
            ("mail.mailgun_base_url", base_url.clone()),
        ],
        secret_key: "mail.mailgun_api_key",
        sealed: seal_secret(keys, "mail.mailgun_api_key", fields.get("mailgun_api_key"))?,
        connection: vec![
            ("mail.mailgun_domain", domain),
            ("mail.mailgun_base_url", base_url),
        ],
    })
}

/// Digits only, 1 to 65535, stored in canonical form.
fn port_text(text: &str) -> Result<String, PlanError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PlanError::Invalid(PORT_MESSAGE));
    }
    match text.parse::<u16>() {
        Ok(port) if port >= 1 => Ok(port.to_string()),
        _ => Err(PlanError::Invalid(PORT_MESSAGE)),
    }
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// One transaction: the settings, the `admin_change` row, and the rule for an empty secret.
/// A secret left empty is kept only when every connection field is unchanged.
fn save_in(
    conn: &mut Connection,
    plan: &Plan,
    actor: &SessionUser,
    at: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let keep_secret = plan.sealed.is_none() && connection_unchanged(&tx, &plan.connection)?;
    for (key, value) in &plan.plain {
        upsert(&tx, key, value)?;
    }
    if let Some(sealed) = &plan.sealed {
        upsert(&tx, plan.secret_key, sealed)?;
    } else if !keep_secret {
        tx.execute(
            "DELETE FROM settings WHERE key = ?1",
            params![plan.secret_key],
        )?;
    }
    let change = Event {
        kind: "admin_change",
        user_id: Some(actor.id),
        user_email: &actor.email,
        detail: "mail settings",
        ..Default::default()
    };
    audit::record(&tx, at, &change)?;
    tx.commit()
}

fn connection_unchanged(
    conn: &Connection,
    connection: &[(&str, String)],
) -> rusqlite::Result<bool> {
    for (key, posted) in connection {
        if db::setting_text(conn, key)?.as_deref() != Some(posted.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn upsert(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value.as_bytes()],
    )
}

fn mail_page(
    viewer: &Viewer,
    status: StatusCode,
    view: &View,
    refused: Option<Refused>,
    notice: Option<&str>,
    error: Option<&str>,
) -> Response {
    let nav = panel_nav(viewer, "/admin/mail");
    form_page(viewer, status, "mail", "Mail settings", |csrf| {
        html! {
            (nav)
            (mail_forms(csrf, view, refused, notice, error))
        }
    })
}

fn shown<'a>(view: &'a View, key: &str) -> &'a str {
    view.get(key).map_or("", String::as_str)
}

/// The stack of the page: the provider in use, one disclosure per provider, and the test email.
fn mail_forms(
    csrf: &str,
    view: &View,
    refused: Option<Refused>,
    notice: Option<&str>,
    error: Option<&str>,
) -> Markup {
    let provider = shown(view, "mail.provider");
    let in_use = provider_named(provider);
    let refusal_of = |name: &str| {
        refused.and_then(|refusal| (refusal.provider == Some(name)).then_some(refusal.reason))
    };
    let unplaced = refused.and_then(|refusal| refusal.provider.is_none().then_some(refusal.reason));
    html! {
        div.stack {
            h1 { "Mail settings" }
            p { "Current provider: " (if provider.is_empty() { "none" } else { provider }) }
            @if in_use.is_none() {
                p { "No provider is in use." }
            }
            @if let Some(message) = unplaced {
                p.error { (message) }
            }
            div.providers {
                (provider_disclosure("smtp", "Raw SMTP", in_use == Some("smtp"), refusal_of("smtp"), smtp_form(csrf, view)))
                (provider_disclosure("resend", "Resend", in_use == Some("resend"), refusal_of("resend"), resend_form(csrf, view)))
                (provider_disclosure("mailgun", "Mailgun", in_use == Some("mailgun"), refusal_of("mailgun"), mailgun_form(csrf, view)))
            }
            section.card {
                h2 { "Test email" }
                @if let Some(message) = notice {
                    p.notice data-notice="ok" { (message) }
                }
                @if let Some(message) = error {
                    p.error { (message) }
                }
                form method="post" action="/admin/mail/test" {
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields {
                        div {
                            label for="test-to" { "Send the test email to" }
                            input id="test-to" name="to" type="email" required;
                        }
                    }
                    button type="submit" data-kind="secondary" { "Send test email" }
                }
            }
        }
    }
}

/// One provider's disclosure. It is open when it is in use or its save was refused, and it is
/// marked as in use when it is the provider in use.
fn provider_disclosure(
    name: &str,
    title: &str,
    in_use: bool,
    reason: Option<&str>,
    form: Markup,
) -> Markup {
    let is_open = in_use || reason.is_some();
    html! {
        details class=(if in_use { "provider card in-use" } else { "provider card" }) data-provider=(name) open[is_open] {
            summary {
                span { (title) }
                span class="provider-state" data-in-use[in_use] {
                    (if in_use { "In use" } else { "Not in use" })
                }
            }
            @if let Some(message) = reason {
                p.error { (message) }
            }
            (form)
        }
    }
}

fn smtp_form(csrf: &str, view: &View) -> Markup {
    let tls = shown(view, "mail.smtp_tls");
    html! {
        form method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="smtp";
            div.fields {
                div {
                    label for="smtp-from" { "From address" }
                    input id="smtp-from" name="from" type="text" value=(shown(view, "mail.from"));
                }
                div {
                    label for="smtp-host" { "Server" }
                    input id="smtp-host" name="smtp_host" type="text" value=(shown(view, "mail.smtp_host"));
                }
                div {
                    label for="smtp-port" { "Port" }
                    input id="smtp-port" name="smtp_port" type="text" inputmode="numeric" value=(shown(view, "mail.smtp_port"));
                }
                div {
                    label for="smtp-username" { "Username" }
                    input id="smtp-username" name="smtp_username" type="text" value=(shown(view, "mail.smtp_username"));
                }
                div {
                    label for="smtp-password" { "Password (empty keeps the stored one)" }
                    input id="smtp-password" name="smtp_password" type="password" autocomplete="new-password";
                }
                div {
                    label for="smtp-tls" { "TLS" }
                    select id="smtp-tls" name="smtp_tls" {
                        option value="off" selected[tls == "off"] { "Off (password and mail are sent unencrypted)" }
                        option value="starttls" selected[tls == "starttls"] { "STARTTLS" }
                        option value="implicit" selected[tls == "implicit"] { "Implicit TLS" }
                    }
                }
            }
            button type="submit" data-kind="primary" { "Save SMTP settings" }
        }
    }
}

fn resend_form(csrf: &str, view: &View) -> Markup {
    html! {
        form method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="resend";
            div.fields {
                div {
                    label for="resend-from" { "From address" }
                    input id="resend-from" name="from" type="text" value=(shown(view, "mail.from"));
                }
                div {
                    label for="resend-key" { "API key (empty keeps the stored one)" }
                    input id="resend-key" name="resend_api_key" type="password" autocomplete="new-password";
                }
                div {
                    label for="resend-base" { "Base address (empty means the provider's own)" }
                    input id="resend-base" name="resend_base_url" type="text" value=(shown(view, "mail.resend_base_url"));
                }
            }
            button type="submit" data-kind="primary" { "Save Resend settings" }
        }
    }
}

fn mailgun_form(csrf: &str, view: &View) -> Markup {
    html! {
        form method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="mailgun";
            div.fields {
                div {
                    label for="mailgun-from" { "From address" }
                    input id="mailgun-from" name="from" type="text" value=(shown(view, "mail.from"));
                }
                div {
                    label for="mailgun-key" { "API key (empty keeps the stored one)" }
                    input id="mailgun-key" name="mailgun_api_key" type="password" autocomplete="new-password";
                }
                div {
                    label for="mailgun-domain" { "Domain" }
                    input id="mailgun-domain" name="mailgun_domain" type="text" value=(shown(view, "mail.mailgun_domain"));
                }
                div {
                    label for="mailgun-base" { "Base address (empty means the provider's own)" }
                    input id="mailgun-base" name="mailgun_base_url" type="text" value=(shown(view, "mail.mailgun_base_url"));
                }
            }
            button type="submit" data-kind="primary" { "Save Mailgun settings" }
        }
    }
}
