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
use crate::web::ui::{self, Note};
use crate::web::{
    FormFields, MainData, SessionUser, VerifiedForm, Viewer, forbidden, form_page_with,
    internal_error, redirect,
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
const TLS_MESSAGE: &str = "Choose a TLS setting: off, starttls or implicit.";
const TEST_TO_MESSAGE: &str = "Enter a valid email address.";
const TEST_SENT: &str = "Test email sent.";
const TEST_SUBJECT: &str = "Doorward test email";
const TEST_TEXT: &str = "This is a test email from Doorward.";
const TEST_HTML: &str = "<p>This is a test email from Doorward.</p>";

/// The sentence of a control character in a field of a provider's form: provider, posted name, sentence.
const CONTROL_SENTENCES: [(&str, &str, &str); 13] = [
    (
        "smtp",
        "from",
        "The from address contains a control character.",
    ),
    (
        "smtp",
        "smtp_host",
        "The server contains a control character.",
    ),
    (
        "smtp",
        "smtp_port",
        "The port contains a control character.",
    ),
    (
        "smtp",
        "smtp_username",
        "The username contains a control character.",
    ),
    (
        "smtp",
        "smtp_password",
        "The password contains a control character.",
    ),
    (
        "smtp",
        "smtp_tls",
        "The TLS setting contains a control character.",
    ),
    (
        "resend",
        "from",
        "The from address contains a control character.",
    ),
    (
        "resend",
        "resend_api_key",
        "The API key contains a control character.",
    ),
    (
        "resend",
        "resend_base_url",
        "The base address contains a control character.",
    ),
    (
        "mailgun",
        "from",
        "The from address contains a control character.",
    ),
    (
        "mailgun",
        "mailgun_api_key",
        "The API key contains a control character.",
    ),
    (
        "mailgun",
        "mailgun_domain",
        "The domain contains a control character.",
    ),
    (
        "mailgun",
        "mailgun_base_url",
        "The base address contains a control character.",
    ),
];

/// The plain settings as stored. Secrets are never loaded for display.
type View = BTreeMap<String, String>;

/// The plain settings a provider form posts, as (setting key, posted field name).
const POSTED_SETTINGS: [(&str, &str); 8] = [
    ("mail.from", "from"),
    ("mail.smtp_host", "smtp_host"),
    ("mail.smtp_port", "smtp_port"),
    ("mail.smtp_username", "smtp_username"),
    ("mail.smtp_tls", "smtp_tls"),
    ("mail.resend_base_url", "resend_base_url"),
    ("mail.mailgun_domain", "mailgun_domain"),
    ("mail.mailgun_base_url", "mailgun_base_url"),
];

/// What a refused post held, shown again: the plain settings it posted and the test address it typed.
struct Typed {
    settings: View,
    to: Option<String>,
}

/// What one save writes: the plain values, the sealed secret when one was posted, and the connection fields.
pub struct Plan {
    plain: Vec<(&'static str, String)>,
    secret_key: &'static str,
    sealed: Option<String>,
    pub(super) connection: Vec<(&'static str, String)>,
}

/// The hints of the secret fields: a change of the named fields drops a stored secret not re-entered.
pub(super) const SMTP_SECRET_HINT: &str = "Leave empty to keep the stored one. If you change the server, the port, the username or the TLS setting, enter it again.";
pub(super) const RESEND_SECRET_HINT: &str =
    "Leave empty to keep the stored one. If you change the base address, enter it again.";
pub(super) const MAILGUN_SECRET_HINT: &str = "Leave empty to keep the stored one. If you change the domain or the base address, enter it again.";

/// A refused post answers 400; a failed seal answers 500. A refusal names the posted field it is about.
pub(super) enum PlanError {
    Invalid {
        reason: &'static str,
        field: Option<&'static str>,
    },
    Seal(CryptoError),
}

/// A save the page refuses: the provider whose form was posted when its name is one of the three,
/// the reason, and the posted field it is about. Without a provider the reason sits at the top of the page.
#[derive(Clone, Copy)]
struct Refused {
    provider: Option<&'static str>,
    reason: &'static str,
    field: Option<&'static str>,
}

/// The providers, in the order of their disclosures.
const PROVIDERS: [&str; 3] = ["smtp", "resend", "mailgun"];

/// The provider of a name, when the name is one of the three.
fn provider_named(name: &str) -> Option<&'static str> {
    PROVIDERS.into_iter().find(|known| *known == name)
}

pub async fn get_mail(viewer: Viewer, State(state): State<AppState>) -> Response {
    match load_view(&state.db).await {
        Ok(view) => mail_page(&viewer, StatusCode::OK, &view, None, None, None, None),
        Err(err) => internal_error("mail page", &err),
    }
}

pub async fn post_mail(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let plan = match plan_from(&form.fields, &state.keys) {
        Ok(plan) => plan,
        Err(PlanError::Invalid { reason, field }) => {
            let refused = Refused {
                provider: provider_named(form.fields.get("provider")),
                reason,
                field,
            };
            let typed = Typed {
                settings: posted_settings(&form.fields),
                to: None,
            };
            return match load_view(&state.db).await {
                Ok(view) => mail_page(
                    &form.viewer,
                    StatusCode::BAD_REQUEST,
                    &view,
                    Some(&typed),
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

/// The plain settings a refused post sent, as its form shows them again.
fn posted_settings(fields: &FormFields) -> View {
    POSTED_SETTINGS
        .iter()
        .map(|(key, field)| {
            (
                (*key).to_owned(),
                ui::sent_back(fields.get(field), ui::SENT_BACK_LIMIT),
            )
        })
        .collect()
}

/// Sends the owner's test email. A bad address answers 400 with the address shown again; a send answers 200.
pub async fn post_test(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let to = normalize_email(form.fields.get("to"));
    if !valid_new_email(&to) {
        let typed = Typed {
            settings: View::new(),
            to: Some(ui::sent_back(
                form.fields.get("to"),
                ui::EMAIL_SENT_BACK_LIMIT,
            )),
        };
        return test_answer(
            &state,
            &form.viewer,
            StatusCode::BAD_REQUEST,
            None,
            Some(TEST_TO_MESSAGE),
            Some(&typed),
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
        Ok(()) => {
            test_answer(
                &state,
                &form.viewer,
                StatusCode::OK,
                Some(TEST_SENT),
                None,
                None,
            )
            .await
        }
        Err(error) => {
            test_answer(
                &state,
                &form.viewer,
                StatusCode::OK,
                None,
                Some(error.0.as_str()),
                None,
            )
            .await
        }
    }
}

/// The mail page carrying the outcome of a test send, with what a refused post held.
async fn test_answer(
    state: &AppState,
    viewer: &Viewer,
    status: StatusCode,
    notice: Option<&str>,
    error: Option<&str>,
    typed: Option<&Typed>,
) -> Response {
    match load_view(&state.db).await {
        Ok(view) => mail_page(viewer, status, &view, typed, None, notice, error),
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
    let provider = fields.get("provider");
    if let Some((name, _)) = fields
        .pairs()
        .find(|(name, value)| has_control(name) || has_control(value))
    {
        return Err(control_refusal(provider, name));
    }
    let posted = |name: &str| fields.get(name).to_owned();
    let from = posted("from");
    match provider {
        "smtp" => smtp_plan(posted, keys, from),
        "resend" => resend_plan(posted, keys, from),
        "mailgun" => mailgun_plan(posted, keys, from),
        _ => Err(PlanError::Invalid {
            reason: PROVIDER_MESSAGE,
            field: None,
        }),
    }
}

/// The refusal of a control character in the posted field `name`: it names the field when the
/// posted provider's form holds that field, else it keeps the general sentence.
fn control_refusal(provider: &str, name: &str) -> PlanError {
    match CONTROL_SENTENCES
        .iter()
        .find(|(known, field, _)| *known == provider && *field == name)
    {
        Some((_, field, reason)) => PlanError::Invalid {
            reason,
            field: Some(*field),
        },
        None => PlanError::Invalid {
            reason: CONTROL_MESSAGE,
            field: None,
        },
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

/// The plan of a raw SMTP post. `posted` returns a field's value; a missing field is "".
pub(super) fn smtp_plan(
    posted: impl Fn(&str) -> String,
    keys: &Keys,
    from: String,
) -> Result<Plan, PlanError> {
    let port = port_text(&posted("smtp_port"))?;
    let tls = posted("smtp_tls");
    if !matches!(tls.as_str(), "off" | "starttls" | "implicit") {
        return Err(PlanError::Invalid {
            reason: TLS_MESSAGE,
            field: Some("smtp_tls"),
        });
    }
    let host = posted("smtp_host");
    let username = posted("smtp_username");
    let connection = vec![
        ("mail.smtp_host", host.clone()),
        ("mail.smtp_port", port.clone()),
        ("mail.smtp_username", username.clone()),
        ("mail.smtp_tls", tls.clone()),
    ];
    let plain = vec![
        ("mail.provider", "smtp".to_owned()),
        ("mail.from", from),
        ("mail.smtp_host", host),
        ("mail.smtp_port", port),
        ("mail.smtp_username", username),
        ("mail.smtp_tls", tls),
    ];
    Ok(Plan {
        plain,
        secret_key: "mail.smtp_password",
        sealed: seal_secret(keys, "mail.smtp_password", &posted("smtp_password"))?,
        connection,
    })
}

/// The plan of a Resend post. `posted` returns a field's value; a missing field is "".
pub(super) fn resend_plan(
    posted: impl Fn(&str) -> String,
    keys: &Keys,
    from: String,
) -> Result<Plan, PlanError> {
    let base_url = posted("resend_base_url");
    Ok(Plan {
        plain: vec![
            ("mail.provider", "resend".to_owned()),
            ("mail.from", from),
            ("mail.resend_base_url", base_url.clone()),
        ],
        secret_key: "mail.resend_api_key",
        sealed: seal_secret(keys, "mail.resend_api_key", &posted("resend_api_key"))?,
        connection: vec![("mail.resend_base_url", base_url)],
    })
}

/// The plan of a Mailgun post. `posted` returns a field's value; a missing field is "".
pub(super) fn mailgun_plan(
    posted: impl Fn(&str) -> String,
    keys: &Keys,
    from: String,
) -> Result<Plan, PlanError> {
    let domain = posted("mailgun_domain");
    let base_url = posted("mailgun_base_url");
    Ok(Plan {
        plain: vec![
            ("mail.provider", "mailgun".to_owned()),
            ("mail.from", from),
            ("mail.mailgun_domain", domain.clone()),
            ("mail.mailgun_base_url", base_url.clone()),
        ],
        secret_key: "mail.mailgun_api_key",
        sealed: seal_secret(keys, "mail.mailgun_api_key", &posted("mailgun_api_key"))?,
        connection: vec![
            ("mail.mailgun_domain", domain),
            ("mail.mailgun_base_url", base_url),
        ],
    })
}

/// Digits only, 1 to 65535, stored in canonical form.
fn port_text(text: &str) -> Result<String, PlanError> {
    let refused = PlanError::Invalid {
        reason: PORT_MESSAGE,
        field: Some("smtp_port"),
    };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused);
    }
    match text.parse::<u16>() {
        Ok(port) if port >= 1 => Ok(port.to_string()),
        _ => Err(refused),
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
    typed: Option<&Typed>,
    refused: Option<Refused>,
    notice: Option<&str>,
    error: Option<&str>,
) -> Response {
    let data = MainData {
        nav: panel_nav(viewer, "/admin/mail"),
        ..MainData::default()
    };
    form_page_with(viewer, status, "mail", "Mail settings", &data, |csrf| {
        html! {
            (mail_forms(csrf, view, typed, refused, notice, error))
        }
    })
}

fn shown<'a>(view: &'a View, key: &str) -> &'a str {
    view.get(key).map_or("", String::as_str)
}

/// The sentence of a refusal about `field` of this form, or None when the refusal is about another field.
fn error_on(refusal: Option<Refused>, field: &str) -> Option<&'static str> {
    refusal.and_then(|refusal| (refusal.field == Some(field)).then_some(refusal.reason))
}

/// The ids a control names in aria-describedby: its refusal, then its hint, each when there is one.
fn described_by(id: &str, error: Option<&str>, hint: Option<&str>) -> Option<String> {
    let mut ids = Vec::new();
    if error.is_some() {
        ids.push(format!("{id}-error"));
    }
    if hint.is_some() {
        ids.push(format!("{id}-hint"));
    }
    (!ids.is_empty()).then(|| ids.join(" "))
}

/// The note under a field: its refusal and its hint, both under their own ids when both are there.
fn field_note<'a>(
    id: &str,
    error: Option<&'a str>,
    hint: Option<&'a str>,
    described: Option<&'a str>,
) -> Note<'a> {
    match (error, hint, described) {
        (Some(text), Some(hint), Some(ids)) => Note::Below(
            ids,
            html! {
                (ui::field_error(&format!("{id}-error"), text))
                (ui::hint(&format!("{id}-hint"), hint))
            },
        ),
        _ => ui::note_under(error, hint),
    }
}

/// The stack of the page: the provider in use, one disclosure per provider, and the test email.
fn mail_forms(
    csrf: &str,
    view: &View,
    typed: Option<&Typed>,
    refused: Option<Refused>,
    notice: Option<&str>,
    error: Option<&str>,
) -> Markup {
    let provider = shown(view, "mail.provider");
    let in_use = provider_named(provider);
    let open = open_provider(in_use, refused.and_then(|refusal| refusal.provider));
    let refusal_of = |name: &str| refused.filter(|refusal| refusal.provider == Some(name));
    // The refused provider's form shows what was posted; the other two show what is stored.
    let shown_in = |name: &str| match (typed, refusal_of(name)) {
        (Some(typed), Some(_)) => &typed.settings,
        _ => view,
    };
    let to = typed.and_then(|typed| typed.to.as_deref());
    let unplaced = refused.and_then(|refusal| refusal.provider.is_none().then_some(refusal.reason));
    let current = in_use.and_then(title_of).unwrap_or("none");
    html! {
        div.page-head {
            h1 { "Mail settings" }
            p.lede { "Doorward sends invitations and password reset links by email. Current provider: " (current) "." }
        }
        @if let Some(message) = unplaced {
            (ui::refused(None, message, None))
        }
        div.providers {
            (provider_disclosure("smtp", "Raw SMTP", in_use == Some("smtp"), open == Some("smtp"), smtp_form(csrf, shown_in("smtp"), refusal_of("smtp"))))
            (provider_disclosure("resend", "Resend", in_use == Some("resend"), open == Some("resend"), resend_form(csrf, shown_in("resend"), refusal_of("resend"))))
            (provider_disclosure("mailgun", "Mailgun", in_use == Some("mailgun"), open == Some("mailgun"), mailgun_form(csrf, shown_in("mailgun"), refusal_of("mailgun"))))
        }
        section.part aria-labelledby="test-title" {
            div.part-head {
                h2 id="test-title" { "Test email" }
                p { "Sends one message through the provider in use." }
            }
            div.part-body {
                form.flow method="post" action="/admin/mail/test" {
                    input type="hidden" name="csrf" value=(csrf);
                    @if let Some(message) = notice {
                        (ui::notice("ok", html! { p { (message) } }))
                    }
                    @if let Some(message) = error {
                        (ui::refused(None, message, None))
                    }
                    div.fields {
                        (ui::field(
                            "test-to",
                            "Send the test email to",
                            false,
                            html! { input id="test-to" name="to" type="email" required value=[to]; },
                            Note::None,
                        ))
                    }
                    div.form-actions {
                        button type="submit" data-kind="secondary" { "Send test email" }
                    }
                }
            }
        }
    }
}

/// The name the lead line and the provider's row give a provider, or None for an unknown one.
fn title_of(name: &str) -> Option<&'static str> {
    match name {
        "smtp" => Some("Raw SMTP"),
        "resend" => Some("Resend"),
        "mailgun" => Some("Mailgun"),
        _ => None,
    }
}

/// The one provider whose disclosure is open: the provider a refusal names, else the one in use.
pub(super) fn open_provider(
    in_use: Option<&'static str>,
    refused: Option<&'static str>,
) -> Option<&'static str> {
    refused.or(in_use)
}

/// One provider's disclosure, open when `is_open` is set. It is marked as in use when it is in use.
fn provider_disclosure(
    name: &str,
    title: &str,
    in_use: bool,
    is_open: bool,
    form: Markup,
) -> Markup {
    html! {
        details.provider name="provider" data-provider=(name) open[is_open] {
            summary {
                span.provider-name { (title) }
                @if in_use {
                    span.state data-tone="ok" data-in-use { "In use" }
                } @else {
                    span.state data-tone="muted" { "Not in use" }
                }
                span.chevron aria-hidden="true" {}
            }
            (form)
        }
    }
}

/// The notice of a refused save sits first in its form, when that form was posted.
fn smtp_form(csrf: &str, view: &View, refusal: Option<Refused>) -> Markup {
    let tls = shown(view, "mail.smtp_tls");
    let from_error = error_on(refusal, "from");
    let from_described = described_by("smtp-from", from_error, None);
    let host_error = error_on(refusal, "smtp_host");
    let host_described = described_by("smtp-host", host_error, None);
    let port_error = error_on(refusal, "smtp_port");
    let port_described = described_by("smtp-port", port_error, None);
    let username_error = error_on(refusal, "smtp_username");
    let username_described = described_by("smtp-username", username_error, None);
    let password_error = error_on(refusal, "smtp_password");
    let password_hint = Some(SMTP_SECRET_HINT);
    let password_described = described_by("smtp-password", password_error, password_hint);
    let tls_error = error_on(refusal, "smtp_tls");
    let tls_hint = Some("Off sends the password and the mail unencrypted.");
    let tls_described = described_by("smtp-tls", tls_error, tls_hint);
    html! {
        form.flow method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="smtp";
            @if let Some(refusal) = refusal {
                (ui::refused(None, refusal.reason, None))
            }
            div.fields {
                (ui::field(
                    "smtp-from",
                    "From address",
                    false,
                    html! {
                        input id="smtp-from" name="from" type="text" value=(shown(view, "mail.from"))
                            aria-invalid=[ui::invalid(from_error)] aria-describedby=[from_described.as_deref()];
                    },
                    field_note("smtp-from", from_error, None, from_described.as_deref()),
                ))
            }
            div.fields data-cols="2-1" {
                (ui::field(
                    "smtp-host",
                    "Server",
                    false,
                    html! {
                        input class="mono" id="smtp-host" name="smtp_host" type="text" value=(shown(view, "mail.smtp_host"))
                            aria-invalid=[ui::invalid(host_error)] aria-describedby=[host_described.as_deref()];
                    },
                    field_note("smtp-host", host_error, None, host_described.as_deref()),
                ))
                (ui::field(
                    "smtp-port",
                    "Port",
                    false,
                    html! {
                        input class="mono" id="smtp-port" name="smtp_port" type="text" inputmode="numeric" value=(shown(view, "mail.smtp_port"))
                            aria-invalid=[ui::invalid(port_error)] aria-describedby=[port_described.as_deref()];
                    },
                    field_note("smtp-port", port_error, None, port_described.as_deref()),
                ))
            }
            div.fields data-cols="2" {
                (ui::field(
                    "smtp-username",
                    "Username",
                    false,
                    html! {
                        input id="smtp-username" name="smtp_username" type="text" value=(shown(view, "mail.smtp_username"))
                            aria-invalid=[ui::invalid(username_error)] aria-describedby=[username_described.as_deref()];
                    },
                    field_note("smtp-username", username_error, None, username_described.as_deref()),
                ))
                (ui::field(
                    "smtp-password",
                    "Password",
                    false,
                    html! {
                        input id="smtp-password" name="smtp_password" type="password" autocomplete="new-password"
                            aria-invalid=[ui::invalid(password_error)] aria-describedby=[password_described.as_deref()];
                    },
                    field_note("smtp-password", password_error, password_hint, password_described.as_deref()),
                ))
            }
            div.fields data-cols="2" {
                (ui::field(
                    "smtp-tls",
                    "TLS",
                    false,
                    html! {
                        select id="smtp-tls" name="smtp_tls" aria-invalid=[ui::invalid(tls_error)] aria-describedby=[tls_described.as_deref()] {
                            option value="off" selected[tls == "off"] { "Off" }
                            option value="starttls" selected[tls == "starttls"] { "STARTTLS" }
                            option value="implicit" selected[tls == "implicit"] { "Implicit TLS" }
                        }
                    },
                    field_note("smtp-tls", tls_error, tls_hint, tls_described.as_deref()),
                ))
            }
            div.form-actions {
                button type="submit" data-kind="primary" { "Save SMTP settings" }
            }
        }
    }
}

fn resend_form(csrf: &str, view: &View, refusal: Option<Refused>) -> Markup {
    let from_error = error_on(refusal, "from");
    let from_described = described_by("resend-from", from_error, None);
    let key_error = error_on(refusal, "resend_api_key");
    let key_hint = Some(RESEND_SECRET_HINT);
    let key_described = described_by("resend-key", key_error, key_hint);
    let base_error = error_on(refusal, "resend_base_url");
    let base_hint = Some("Empty means the provider's own address.");
    let base_described = described_by("resend-base", base_error, base_hint);
    html! {
        form.flow method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="resend";
            @if let Some(refusal) = refusal {
                (ui::refused(None, refusal.reason, None))
            }
            div.fields {
                (ui::field(
                    "resend-from",
                    "From address",
                    false,
                    html! {
                        input id="resend-from" name="from" type="text" value=(shown(view, "mail.from"))
                            aria-invalid=[ui::invalid(from_error)] aria-describedby=[from_described.as_deref()];
                    },
                    field_note("resend-from", from_error, None, from_described.as_deref()),
                ))
            }
            div.fields {
                (ui::field(
                    "resend-key",
                    "API key",
                    false,
                    html! {
                        input id="resend-key" name="resend_api_key" type="password" autocomplete="new-password"
                            aria-invalid=[ui::invalid(key_error)] aria-describedby=[key_described.as_deref()];
                    },
                    field_note("resend-key", key_error, key_hint, key_described.as_deref()),
                ))
            }
            div.fields {
                (ui::field(
                    "resend-base",
                    "Base address",
                    true,
                    html! {
                        input class="mono" id="resend-base" name="resend_base_url" type="text"
                            value=(shown(view, "mail.resend_base_url"))
                            aria-invalid=[ui::invalid(base_error)] aria-describedby=[base_described.as_deref()];
                    },
                    field_note("resend-base", base_error, base_hint, base_described.as_deref()),
                ))
            }
            div.form-actions {
                button type="submit" data-kind="primary" { "Save Resend settings" }
            }
        }
    }
}

fn mailgun_form(csrf: &str, view: &View, refusal: Option<Refused>) -> Markup {
    let from_error = error_on(refusal, "from");
    let from_described = described_by("mailgun-from", from_error, None);
    let key_error = error_on(refusal, "mailgun_api_key");
    let key_hint = Some(MAILGUN_SECRET_HINT);
    let key_described = described_by("mailgun-key", key_error, key_hint);
    let domain_error = error_on(refusal, "mailgun_domain");
    let domain_described = described_by("mailgun-domain", domain_error, None);
    let base_error = error_on(refusal, "mailgun_base_url");
    let base_hint = Some("Empty means the provider's own address.");
    let base_described = described_by("mailgun-base", base_error, base_hint);
    html! {
        form.flow method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="mailgun";
            @if let Some(refusal) = refusal {
                (ui::refused(None, refusal.reason, None))
            }
            div.fields {
                (ui::field(
                    "mailgun-from",
                    "From address",
                    false,
                    html! {
                        input id="mailgun-from" name="from" type="text" value=(shown(view, "mail.from"))
                            aria-invalid=[ui::invalid(from_error)] aria-describedby=[from_described.as_deref()];
                    },
                    field_note("mailgun-from", from_error, None, from_described.as_deref()),
                ))
            }
            div.fields data-cols="2" {
                (ui::field(
                    "mailgun-key",
                    "API key",
                    false,
                    html! {
                        input id="mailgun-key" name="mailgun_api_key" type="password" autocomplete="new-password"
                            aria-invalid=[ui::invalid(key_error)] aria-describedby=[key_described.as_deref()];
                    },
                    field_note("mailgun-key", key_error, key_hint, key_described.as_deref()),
                ))
                (ui::field(
                    "mailgun-domain",
                    "Domain",
                    false,
                    html! {
                        input class="mono" id="mailgun-domain" name="mailgun_domain" type="text" value=(shown(view, "mail.mailgun_domain"))
                            aria-invalid=[ui::invalid(domain_error)] aria-describedby=[domain_described.as_deref()];
                    },
                    field_note("mailgun-domain", domain_error, None, domain_described.as_deref()),
                ))
            }
            div.fields {
                (ui::field(
                    "mailgun-base",
                    "Base address",
                    true,
                    html! {
                        input class="mono" id="mailgun-base" name="mailgun_base_url" type="text"
                            value=(shown(view, "mail.mailgun_base_url"))
                            aria-invalid=[ui::invalid(base_error)] aria-describedby=[base_described.as_deref()];
                    },
                    field_note("mailgun-base", base_error, base_hint, base_described.as_deref()),
                ))
            }
            div.form-actions {
                button type="submit" data-kind="primary" { "Save Mailgun settings" }
            }
        }
    }
}
