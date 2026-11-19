use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::app::AppState;
use crate::crypto::Keys;
use crate::db::{Db, DbError};
use crate::web::{FormFields, VerifiedForm, Viewer, form_page, internal_error, redirect};

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
    Seal,
}

pub async fn get_mail(viewer: Viewer, State(state): State<AppState>) -> Response {
    match load_view(&state.db).await {
        Ok(view) => mail_page(&viewer, StatusCode::OK, &view, None),
        Err(_) => internal_error(),
    }
}

pub async fn post_mail(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let plan = match plan_from(&form.fields, &state.keys) {
        Ok(plan) => plan,
        Err(PlanError::Invalid(message)) => {
            return match load_view(&state.db).await {
                Ok(view) => mail_page(&form.viewer, StatusCode::BAD_REQUEST, &view, Some(message)),
                Err(_) => internal_error(),
            };
        }
        Err(PlanError::Seal) => return internal_error(),
    };
    let saved = state.db.call(move |conn| save_in(conn, &plan)).await;
    match saved {
        Ok(()) => redirect("/admin/mail"),
        Err(_) => internal_error(),
    }
}

async fn load_view(db: &Db) -> Result<View, DbError> {
    db.call(|conn| {
        let mut view = View::new();
        for key in PLAIN_KEYS {
            if let Some(value) = stored_text(conn, key)? {
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
        .map_err(|_| PlanError::Seal)
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

/// One transaction. A secret left empty is kept only when every connection field is unchanged.
fn save_in(conn: &mut Connection, plan: &Plan) -> rusqlite::Result<()> {
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
    tx.commit()
}

fn connection_unchanged(
    conn: &Connection,
    connection: &[(&str, String)],
) -> rusqlite::Result<bool> {
    for (key, posted) in connection {
        if stored_text(conn, key)?.as_deref() != Some(posted.as_str()) {
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

fn stored_text(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(err),
                )
            })
        })
        .transpose()
}

fn mail_page(viewer: &Viewer, status: StatusCode, view: &View, error: Option<&str>) -> Response {
    form_page(viewer, status, "mail", "Mail settings", |csrf| {
        mail_forms(csrf, view, error)
    })
}

fn shown<'a>(view: &'a View, key: &str) -> &'a str {
    view.get(key).map_or("", String::as_str)
}

fn mail_forms(csrf: &str, view: &View, error: Option<&str>) -> Markup {
    let provider = shown(view, "mail.provider");
    let tls = shown(view, "mail.smtp_tls");
    html! {
        h1 { "Mail settings" }
        p { "Current provider: " (if provider.is_empty() { "none" } else { provider }) }
        @if let Some(message) = error {
            p.error { (message) }
        }
        h2 { "Raw SMTP" }
        form method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="smtp";
            label for="smtp-from" { "From address" }
            input id="smtp-from" name="from" type="text" value=(shown(view, "mail.from"));
            label for="smtp-host" { "Server" }
            input id="smtp-host" name="smtp_host" type="text" value=(shown(view, "mail.smtp_host"));
            label for="smtp-port" { "Port" }
            input id="smtp-port" name="smtp_port" type="text" inputmode="numeric" value=(shown(view, "mail.smtp_port"));
            label for="smtp-username" { "Username" }
            input id="smtp-username" name="smtp_username" type="text" value=(shown(view, "mail.smtp_username"));
            label for="smtp-password" { "Password (empty keeps the stored one)" }
            input id="smtp-password" name="smtp_password" type="password" autocomplete="new-password";
            label for="smtp-tls" { "TLS" }
            select id="smtp-tls" name="smtp_tls" {
                option value="off" selected[tls == "off"] { "Off" }
                option value="starttls" selected[tls == "starttls"] { "STARTTLS" }
                option value="implicit" selected[tls == "implicit"] { "Implicit TLS" }
            }
            button type="submit" { "Save SMTP settings" }
        }
        h2 { "Resend" }
        form method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="resend";
            label for="resend-from" { "From address" }
            input id="resend-from" name="from" type="text" value=(shown(view, "mail.from"));
            label for="resend-key" { "API key (empty keeps the stored one)" }
            input id="resend-key" name="resend_api_key" type="password" autocomplete="new-password";
            label for="resend-base" { "Base address (empty means the provider's own)" }
            input id="resend-base" name="resend_base_url" type="text" value=(shown(view, "mail.resend_base_url"));
            button type="submit" { "Save Resend settings" }
        }
        h2 { "Mailgun" }
        form method="post" action="/admin/mail" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="provider" value="mailgun";
            label for="mailgun-from" { "From address" }
            input id="mailgun-from" name="from" type="text" value=(shown(view, "mail.from"));
            label for="mailgun-key" { "API key (empty keeps the stored one)" }
            input id="mailgun-key" name="mailgun_api_key" type="password" autocomplete="new-password";
            label for="mailgun-domain" { "Domain" }
            input id="mailgun-domain" name="mailgun_domain" type="text" value=(shown(view, "mail.mailgun_domain"));
            label for="mailgun-base" { "Base address (empty means the provider's own)" }
            input id="mailgun-base" name="mailgun_base_url" type="text" value=(shown(view, "mail.mailgun_base_url"));
            button type="submit" { "Save Mailgun settings" }
        }
    }
}
