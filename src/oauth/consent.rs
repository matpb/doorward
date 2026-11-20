//! `GET` and `POST /oauth/consent`: the approval page, and the one decision a shown request allows.

use std::time::Duration;

use axum::extract::{RawQuery, State};
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::app::AppState;
use crate::cimd::{CimdFetcher, ClientMetadata};
use crate::crypto::{constant_time_eq, random_token, token_hash};
use crate::report;
use crate::web::{
    MainData, VerifiedForm, Viewer, content_security_policy, form_page_with, internal_error, page,
    redirect,
};

use super::authorize::{self, Stored, back_url, error_page, is_request_id};
use super::clients::{self, Client};
use super::policy::{self, Verdict};
use super::register::is_plain_text;
use super::uri::{self, Redirect};

const FETCH_LIMIT: Duration = Duration::from_secs(5);
const NAME_LIMIT: usize = 100;
const CODE_PREFIX: &str = "dw_ac_";
const ALL_SERVERS: &str = "all servers";

/// Where a request points for one user.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// The combined endpoint, which needs no assignment.
    Combined,
    /// A server the user is assigned to.
    Server(i64),
    /// No such server, or the user is not assigned to it.
    NoAccess,
}

/// The target of a request: the combined endpoint, or a server the user holds by its slug.
fn target_for(conn: &Connection, user_id: i64, slug: Option<&str>) -> rusqlite::Result<Target> {
    let Some(slug) = slug else {
        return Ok(Target::Combined);
    };
    let server: Option<i64> = conn
        .query_row(
            "SELECT s.id FROM servers s JOIN user_servers us ON us.server_id = s.id \
             WHERE s.slug = ?1 AND us.user_id = ?2",
            params![slug, user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(server.map_or(Target::NoAccess, Target::Server))
}

/// A request the page may show: its binding and its target passed.
struct Pending {
    stored: Stored,
    client: Client,
}

/// The read of the page, decided in one transaction.
enum Opened {
    Refused,
    NoAccess,
    Ready(Box<Pending>),
}

/// The client as the page names it.
struct Shown {
    name: String,
    verified: bool,
    client_host: Option<String>,
}

/// Everything the consent page prints.
struct ConsentPage {
    redirect_host: String,
    origin: String,
    loopback: bool,
    client: Shown,
    server: String,
    email: String,
}

/// The one `req` of a query string; a missing or repeated one is None.
fn single_req(raw: Option<&str>) -> Option<String> {
    let mut values: Vec<String> = form_urlencoded::parse(raw.unwrap_or("").as_bytes())
        .filter(|(name, _)| name == "req")
        .map(|(_, value)| value.into_owned())
        .collect();
    if values.len() == 1 {
        values.pop()
    } else {
        None
    }
}

/// `GET /oauth/consent?req=`: the page for the browser that owns the request.
pub async fn get_consent(
    State(state): State<AppState>,
    viewer: Viewer,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(req) = single_req(raw.as_deref()) else {
        return error_page(None);
    };
    if !is_request_id(&req) {
        return error_page(None);
    }
    let (Some(user), Some(session)) = (viewer.user.as_ref(), viewer.presented_session()) else {
        return redirect(&format!("/login?req={req}"));
    };
    let user_id = user.id;
    let email = user.email.clone();
    let id_hash = token_hash(&req);
    let session_hash = token_hash(session);
    let now = state.clock.now().unix_timestamp();
    let (bind_id, bind_session) = (id_hash.clone(), session_hash.clone());
    let opened = state
        .db
        .call(move |conn| open_in(conn, &bind_id, &bind_session, user_id, now))
        .await;
    let pending = match opened {
        Ok(Opened::Ready(pending)) => pending,
        Ok(Opened::Refused) => return error_page(None),
        Ok(Opened::NoAccess) => return no_access(),
        Err(err) => return internal_error("consent page", &err),
    };
    let Some(redirect_address) = uri::parse(&pending.stored.redirect_uri) else {
        return error_page(None);
    };
    let Some(client) = client_display(&state, &pending.client, &pending.stored.redirect_uri).await
    else {
        return error_page(None);
    };
    let server = pending
        .stored
        .target_slug
        .clone()
        .unwrap_or_else(|| ALL_SERVERS.to_owned());
    let name = client.name.clone();
    let shown = state
        .db
        .call(move |conn| mark_shown_in(conn, &id_hash, &session_hash, &name, now))
        .await;
    match shown {
        Ok(true) => {}
        Ok(false) => return error_page(None),
        Err(err) => return internal_error("consent page", &err),
    }
    let consent = ConsentPage {
        redirect_host: shown_host(&redirect_address),
        origin: origin_of(&redirect_address),
        loopback: matches!(redirect_address, Redirect::Loopback { .. }),
        client,
        server,
        email,
    };
    render(&viewer, &req, &consent)
}

/// The binding and target of the read: a request started signed out takes this session.
fn open_in(
    conn: &mut Connection,
    id_hash: &str,
    session_hash: &str,
    user_id: i64,
    now: i64,
) -> rusqlite::Result<Opened> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let opened = open_within(&tx, id_hash, session_hash, user_id, now)?;
    tx.commit()?;
    Ok(opened)
}

fn open_within(
    tx: &Transaction<'_>,
    id_hash: &str,
    session_hash: &str,
    user_id: i64,
    now: i64,
) -> rusqlite::Result<Opened> {
    let Some(stored) = authorize::load(tx, id_hash)? else {
        return Ok(Opened::Refused);
    };
    if now >= stored.expires_at {
        return Ok(Opened::Refused);
    }
    match stored.session_hash.as_deref() {
        None => {
            tx.execute(
                "UPDATE auth_requests SET session_hash = ?1 WHERE id_hash = ?2",
                params![session_hash, id_hash],
            )?;
        }
        Some(owner) if constant_time_eq(owner.as_bytes(), session_hash.as_bytes()) => {}
        Some(_) => return Ok(Opened::Refused),
    }
    if target_for(tx, user_id, stored.target_slug.as_deref())? == Target::NoAccess {
        return Ok(Opened::NoAccess);
    }
    let Some(client) = clients::find(tx, &stored.client_id)? else {
        return Ok(Opened::Refused);
    };
    Ok(Opened::Ready(Box::new(Pending { stored, client })))
}

/// The name, verification and host the page shows. A document is fetched outside any transaction.
async fn client_display(state: &AppState, client: &Client, redirect_uri: &str) -> Option<Shown> {
    match client {
        Client::Registered { client_name, .. } => Some(Shown {
            name: client_name.clone(),
            verified: false,
            client_host: None,
        }),
        Client::Document { client_id } => {
            let metadata = fetch_within(state.cimd.as_ref(), client_id, FETCH_LIMIT).await?;
            if !document_fits(&metadata, client_id, redirect_uri) {
                return None;
            }
            let host = host_of(client_id)?;
            Some(Shown {
                name: document_name(metadata.client_name.as_deref(), &host),
                verified: true,
                client_host: Some(host),
            })
        }
    }
}

/// The metadata document, or None on an error or when `limit` runs out first. Each failure is
/// written to standard error under the host of the address.
pub(super) async fn fetch_within(
    fetcher: &dyn CimdFetcher,
    client_id: &str,
    limit: Duration,
) -> Option<ClientMetadata> {
    let label = format!("client metadata for {}", host_of(client_id)?);
    match tokio::time::timeout(limit, fetcher.fetch(client_id)).await {
        Ok(Ok(metadata)) => Some(metadata),
        Ok(Err(err)) => {
            report::failure(&label, &err);
            None
        }
        Err(_) => {
            let waited = format!("no answer within {} seconds", limit.as_secs());
            report::failure(&label, &waited);
            None
        }
    }
}

/// The document names this client, lists the requested address, and asks for no secret.
fn document_fits(metadata: &ClientMetadata, client_id: &str, redirect_uri: &str) -> bool {
    metadata.client_id == client_id
        && metadata
            .token_endpoint_auth_method
            .as_deref()
            .is_none_or(|method| method == "none")
        && metadata
            .redirect_uris
            .iter()
            .any(|listed| uri::matches(listed, redirect_uri))
}

/// The host of a metadata address, which is a web address.
fn host_of(client_id: &str) -> Option<String> {
    match uri::parse(client_id) {
        Some(Redirect::Web { host, .. }) => Some(host.to_owned()),
        _ => None,
    }
}

/// The name a document client is shown under: its trimmed name cut to 100 characters, or the host
/// when the name is absent or empty, or holds a control, invisible or direction character.
pub fn document_name(client_name: Option<&str>, host: &str) -> String {
    let name: String = client_name
        .unwrap_or("")
        .trim()
        .chars()
        .take(NAME_LIMIT)
        .collect();
    if name.is_empty() || !is_plain_text(&name) {
        host.to_owned()
    } else {
        name
    }
}

/// Marks the request shown with the name, if it is still this session's and not expired.
fn mark_shown_in(
    conn: &mut Connection,
    id_hash: &str,
    session_hash: &str,
    name: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE auth_requests SET shown_at = ?1, client_name = ?2 \
         WHERE id_hash = ?3 AND session_hash = ?4 AND expires_at > ?1",
        params![now, name, id_hash, session_hash],
    )?;
    tx.commit()?;
    Ok(changed == 1)
}

/// The redirect host as the page names it: host or host:port, or the scheme and a colon.
fn shown_host(redirect: &Redirect<'_>) -> String {
    match redirect {
        Redirect::Loopback {
            host,
            port: Some(port),
            ..
        } => format!("{host}:{port}"),
        Redirect::Loopback {
            host, port: None, ..
        } => (*host).to_owned(),
        Redirect::Web {
            scheme: "https",
            host,
            ..
        } => (*host).to_owned(),
        Redirect::Web { scheme, .. } => format!("{scheme}:"),
    }
}

/// The origin a form may post to: scheme://host[:port] for http and https, scheme: otherwise.
fn origin_of(redirect: &Redirect<'_>) -> String {
    match redirect {
        Redirect::Loopback {
            host,
            port: Some(port),
            ..
        } => format!("http://{host}:{port}"),
        Redirect::Loopback {
            host, port: None, ..
        } => format!("http://{host}"),
        Redirect::Web {
            scheme: "https",
            host,
            ..
        } => format!("https://{host}"),
        Redirect::Web { scheme, .. } => format!("{scheme}:"),
    }
}

/// The page, with its policy: the standard one, and the redirect origin as a form target.
fn render(viewer: &Viewer, req: &str, consent: &ConsentPage) -> Response {
    let data = MainData {
        redirect_host: Some(consent.redirect_host.as_str()),
        client_name: Some(consent.client.name.as_str()),
        client_verified: Some(if consent.client.verified { "yes" } else { "no" }),
        client_host: consent.client.client_host.as_deref(),
        server: Some(consent.server.as_str()),
        user: Some(consent.email.as_str()),
        ..MainData::default()
    };
    let response = form_page_with(
        viewer,
        StatusCode::OK,
        "consent",
        "Approve sign-in",
        &data,
        |csrf| consent_body(csrf, req, consent),
    );
    with_policy(response, &consent.origin)
}

/// The body: what the client asks for, who signs in, then the two decisions.
fn consent_body(csrf: &str, req: &str, consent: &ConsentPage) -> Markup {
    html! {
        h1 { "You will be sent to " (consent.redirect_host) }
        (client_line(&consent.client, consent.loopback))
        p { "Server: " (consent.server) }
        p { "Signed in as " (consent.email) }
        @if consent.loopback {
            p.local-app { "The sign-in will be handed to whatever program is listening on this computer." }
        }
        p.notice data-consent-notice { "Approve only if you started this sign-in yourself." }
        form method="post" action="/oauth/consent" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="req" value=(req);
            input type="hidden" name="decision" value="approve";
            button type="submit" { "Approve" }
        }
        form method="post" action="/oauth/consent" {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="req" value=(req);
            input type="hidden" name="decision" value="deny";
            button type="submit" { "Deny" }
        }
    }
}

/// The client line: a claim for a registered client, a publisher for a web document, and a claim
/// from a host for a document on a loopback redirect.
fn client_line(client: &Shown, loopback: bool) -> Markup {
    match client.client_host.as_deref() {
        None => html! {
            p data-client="registered" {
                "An app that calls itself " q.client-name { (client.name) } ". Doorward cannot check this name."
            }
        },
        Some(host) if loopback => html! {
            p data-client="document-loopback" {
                "Says it is " q.client-name { (client.name) } " from " span.client-host { (host) }
                ". Any program on this computer can use that description."
            }
        },
        Some(host) => html! {
            p data-client="document" {
                q.client-name { (client.name) } ", published by " span.client-host { (host) } "."
            }
        },
    }
}

/// Sets this page's policy: the standard one, with the redirect origin allowed as a form target.
fn with_policy(mut response: Response, origin: &str) -> Response {
    match HeaderValue::from_str(&content_security_policy(Some(origin))) {
        Ok(value) => {
            response
                .headers_mut()
                .insert(CONTENT_SECURITY_POLICY, value);
            response
        }
        Err(err) => internal_error("consent page", &err),
    }
}

/// The page for a user who holds no access to the requested server. The same for every cause.
fn no_access() -> Response {
    page(
        StatusCode::FORBIDDEN,
        "no-access",
        "No access",
        html! {
            h1 { "You do not have access to this server" }
            p { "Ask an administrator to give you access, then start the sign-in again." }
        },
    )
}

/// The inputs of a decision.
struct Decision {
    id_hash: String,
    session_hash: String,
    user_id: i64,
    approve: bool,
    now: i64,
    code_lifetime: i64,
    issuer: String,
}

/// What the decision answers.
enum Answer {
    Refused,
    NoAccess,
    Redirect(String),
}

/// `POST /oauth/consent`: the one decision a shown request allows.
pub async fn post_consent(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let (Some(user), Some(session)) = (form.viewer.user.as_ref(), form.viewer.presented_session())
    else {
        return redirect("/login");
    };
    let req = match form.fields.all("req").as_slice() {
        [only] => *only,
        _ => return error_page(None),
    };
    if !is_request_id(req) {
        return error_page(None);
    }
    let decision = Decision {
        id_hash: token_hash(req),
        session_hash: token_hash(session),
        user_id: user.id,
        approve: form.fields.all("decision") == ["approve"],
        now: state.clock.now().unix_timestamp(),
        code_lifetime: i64::try_from(state.config.lifetimes.auth_code_seconds).unwrap_or(i64::MAX),
        issuer: state.config.public_url.clone(),
    };
    match state.db.call(move |conn| decide_in(conn, &decision)).await {
        Ok(Answer::Redirect(url)) => redirect(&url),
        Ok(Answer::Refused) => error_page(None),
        Ok(Answer::NoAccess) => no_access(),
        Err(err) => internal_error("consent decision", &err),
    }
}

/// The decision in one immediate transaction. Every outcome, refusals included, is committed.
fn decide_in(conn: &mut Connection, decision: &Decision) -> rusqlite::Result<Answer> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let answer = decide_within(&tx, decision)?;
    tx.commit()?;
    Ok(answer)
}

fn decide_within(tx: &Transaction<'_>, decision: &Decision) -> rusqlite::Result<Answer> {
    let Some(stored) = authorize::load(tx, &decision.id_hash)? else {
        return Ok(Answer::Refused);
    };
    if decision.now >= stored.expires_at || !bound_and_shown(&stored, &decision.session_hash) {
        return Ok(Answer::Refused);
    }
    let consumed = tx.execute(
        "DELETE FROM auth_requests WHERE id_hash = ?1",
        params![decision.id_hash],
    )?;
    if consumed != 1 {
        return Ok(Answer::Refused);
    }
    if !decision.approve {
        let url = back_url(
            &decision.issuer,
            &stored.redirect_uri,
            ("error", "access_denied"),
            stored.state.as_deref(),
        );
        return Ok(Answer::Redirect(url));
    }
    approve_within(tx, decision, &stored)
}

/// The request belongs to this session, and its page was rendered.
fn bound_and_shown(stored: &Stored, session_hash: &str) -> bool {
    let bound = stored
        .session_hash
        .as_deref()
        .is_some_and(|owner| constant_time_eq(owner.as_bytes(), session_hash.as_bytes()));
    bound && stored.shown_at.is_some()
}

/// The approval checks, then the code. Every refusal comes before the first write of the approval.
fn approve_within(
    tx: &Transaction<'_>,
    decision: &Decision,
    stored: &Stored,
) -> rusqlite::Result<Answer> {
    let target = target_for(tx, decision.user_id, stored.target_slug.as_deref())?;
    if target == Target::NoAccess {
        return Ok(Answer::NoAccess);
    }
    let Some(redirect) = uri::parse(&stored.redirect_uri) else {
        return Ok(Answer::Refused);
    };
    if policy::decide(tx, &redirect)? == Verdict::Blocked {
        return Ok(Answer::Refused);
    }
    let Some(client) = clients::find(tx, &stored.client_id)? else {
        return Ok(Answer::Refused);
    };
    let Some(auth_epoch) = session_epoch(tx, &decision.session_hash)? else {
        return Ok(Answer::Refused);
    };
    let Some(client_name) = stored.client_name.as_deref() else {
        return Ok(Answer::Refused);
    };
    let code = random_token(CODE_PREFIX);
    let binding = CodeBinding {
        client_id: &stored.client_id,
        redirect_uri: &stored.redirect_uri,
        user_id: decision.user_id,
        server_id: server_id(&target),
        client_name,
        challenge: &stored.code_challenge,
        auth_epoch,
    };
    insert_code(
        tx,
        &token_hash(&code),
        &binding,
        decision.now,
        decision.code_lifetime,
    )?;
    if matches!(client, Client::Registered { .. }) {
        tx.execute(
            "UPDATE oauth_clients SET used_at = ?1 WHERE client_id = ?2",
            params![decision.now, stored.client_id],
        )?;
    }
    let url = back_url(
        &decision.issuer,
        &stored.redirect_uri,
        ("code", &code),
        stored.state.as_deref(),
    );
    Ok(Answer::Redirect(url))
}

/// The server a code is bound to; None for the combined endpoint.
fn server_id(target: &Target) -> Option<i64> {
    match target {
        Target::Server(id) => Some(*id),
        Target::Combined | Target::NoAccess => None,
    }
}

/// The `auth_epoch` of this session's row, or None when there is no such row.
fn session_epoch(conn: &Connection, session_hash: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT auth_epoch FROM sessions WHERE id_hash = ?1",
        params![session_hash],
        |row| row.get(0),
    )
    .optional()
}

/// What an authorization code is bound to.
struct CodeBinding<'a> {
    client_id: &'a str,
    redirect_uri: &'a str,
    user_id: i64,
    server_id: Option<i64>,
    client_name: &'a str,
    challenge: &'a str,
    auth_epoch: i64,
}

fn insert_code(
    tx: &Transaction<'_>,
    code_hash: &str,
    binding: &CodeBinding<'_>,
    now: i64,
    lifetime: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, user_id, server_id, combined, \
         client_name, code_challenge, auth_epoch, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            code_hash,
            binding.client_id,
            binding.redirect_uri,
            binding.user_id,
            binding.server_id,
            binding.server_id.is_none(),
            binding.client_name,
            binding.challenge,
            binding.auth_epoch,
            now,
            now.saturating_add(lifetime),
        ],
    )?;
    Ok(())
}
