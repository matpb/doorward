//! Connected clients: the account list, disconnect from the account page, and the mailed link.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::crypto::token_hash;
use crate::db::{Db, DbError};
use crate::web::{
    MainData, VerifiedForm, Viewer, form_page_with, internal_error, not_found, not_found_link,
    page, redirect,
};

use super::families;
use super::guard::is_token_shape;

const LINK_PREFIX: &str = "dw_dl_";
const ALL_SERVERS: &str = "all servers";
const CLIENT_DISCONNECTED: &str = "client_disconnected";

/// One connected client as the account page lists it.
pub struct Connected {
    pub public_id: String,
    pub client_name: String,
    /// The server's slug, or "all servers" for the combined endpoint.
    pub server: String,
}

/// A family as a disconnect reads it: its owner, its server, its client name and whether it is revoked.
struct Family {
    id: i64,
    user_id: i64,
    user_email: String,
    server_id: Option<i64>,
    server_slug: Option<String>,
    client_name: String,
    revoked: bool,
}

/// What a disconnect of the viewer's own family found.
enum Own {
    Missing,
    Ended,
    Disconnected,
}

impl Family {
    fn server_label(&self) -> &str {
        self.server_slug.as_deref().unwrap_or(ALL_SERVERS)
    }
}

/// The families of `user_id` that are not revoked, not expired and of the user's current epoch.
pub async fn list(db: &Db, user_id: i64, now: i64) -> Result<Vec<Connected>, DbError> {
    db.call(move |conn| list_in(conn, user_id, now)).await
}

fn list_in(conn: &Connection, user_id: i64, now: i64) -> rusqlite::Result<Vec<Connected>> {
    let mut statement = conn.prepare(
        "SELECT f.public_id, f.client_name, s.slug FROM token_families f \
         JOIN users u ON u.id = f.user_id LEFT JOIN servers s ON s.id = f.server_id \
         WHERE f.user_id = ?1 AND f.revoked_at IS NULL AND f.expires_at > ?2 \
         AND f.auth_epoch = u.auth_epoch ORDER BY f.id",
    )?;
    let rows = statement.query_map(params![user_id, now], |row| {
        let slug: Option<String> = row.get(2)?;
        Ok(Connected {
            public_id: row.get(0)?,
            client_name: row.get(1)?,
            server: slug.unwrap_or_else(|| ALL_SERVERS.to_owned()),
        })
    })?;
    rows.collect()
}

/// Revokes the viewer's own family, then `303 /account`. Another user's family is a plain 404.
pub async fn post_client_disconnect(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(user) = form.viewer.user.as_ref() else {
        return redirect("/login");
    };
    let user_id = user.id;
    let now = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| disconnect_own_in(conn, user_id, &public_id, now))
        .await
    {
        Ok(Own::Missing) => not_found(),
        Ok(Own::Ended | Own::Disconnected) => redirect("/account"),
        Err(err) => internal_error("client disconnect", &err),
    }
}

/// `GET /account/disconnect/{token}`: the page of a usable mailed link. Changes nothing.
pub async fn get_disconnect_link(
    State(state): State<AppState>,
    token: Option<Path<String>>,
    request: Request,
) -> Response {
    let Some(Path(token)) = token else {
        return not_found_link();
    };
    if !is_token_shape(&token, LINK_PREFIX) {
        return not_found_link();
    }
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    let found = state
        .db
        .call(move |conn| usable_by_link(conn, &hash, now))
        .await;
    let family = match found {
        Ok(Some(family)) => family,
        Ok(None) => return not_found_link(),
        Err(err) => return internal_error("disconnect link", &err),
    };
    let (parts, _body) = request.into_parts();
    let viewer = Viewer::resolve(&parts, &state).await;
    link_page(&viewer, &family)
}

/// `POST /account/disconnect/{token}`: the mailed link disconnects its family, once.
pub async fn post_disconnect_link(
    State(state): State<AppState>,
    token: Option<Path<String>>,
    _form: VerifiedForm,
) -> Response {
    let Some(Path(token)) = token else {
        return not_found_link();
    };
    if !is_token_shape(&token, LINK_PREFIX) {
        return not_found_link();
    }
    let hash = token_hash(&token);
    let now = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| disconnect_link_in(conn, &hash, now))
        .await
    {
        Ok(Some(family)) => disconnected_page(&family),
        Ok(None) => not_found_link(),
        Err(err) => internal_error("disconnect link", &err),
    }
}

/// Revokes the family `public_id` when `user_id` owns it and it is not revoked yet.
fn disconnect_own_in(
    conn: &mut Connection,
    user_id: i64,
    public_id: &str,
    now: i64,
) -> rusqlite::Result<Own> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = match family_of(&tx, user_id, public_id)? {
        None => Own::Missing,
        Some(family) if family.revoked => Own::Ended,
        Some(family) => {
            disconnect(&tx, &family, now)?;
            Own::Disconnected
        }
    };
    tx.commit()?;
    Ok(outcome)
}

/// Revokes a usable link's family and deletes the link. None when the link is not usable.
fn disconnect_link_in(
    conn: &mut Connection,
    hash: &str,
    now: i64,
) -> rusqlite::Result<Option<Family>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found = usable_by_link(&tx, hash, now)?;
    if let Some(family) = &found {
        tx.execute(
            "DELETE FROM disconnect_links WHERE token_hash = ?1",
            params![hash],
        )?;
        disconnect(&tx, family, now)?;
    }
    tx.commit()?;
    Ok(found)
}

/// Ends the family and records the disconnect, inside the caller's transaction.
fn disconnect(tx: &Transaction<'_>, family: &Family, now: i64) -> rusqlite::Result<()> {
    families::revoke(tx, family.id, now)?;
    audit::record(
        tx,
        now,
        &Event {
            kind: CLIENT_DISCONNECTED,
            user_id: Some(family.user_id),
            user_email: &family.user_email,
            server_id: family.server_id,
            server_slug: family.server_slug.as_deref().unwrap_or(""),
            client: &family.client_name,
            ..Default::default()
        },
    )
}

fn family_of(conn: &Connection, user_id: i64, public_id: &str) -> rusqlite::Result<Option<Family>> {
    conn.query_row(
        "SELECT f.id, f.user_id, u.email, f.server_id, s.slug, f.client_name, f.revoked_at IS NOT NULL \
         FROM token_families f JOIN users u ON u.id = f.user_id \
         LEFT JOIN servers s ON s.id = f.server_id \
         WHERE f.public_id = ?1 AND f.user_id = ?2",
        params![public_id, user_id],
        family_from_row,
    )
    .optional()
}

/// The family of a link whose family is not revoked, not expired and of its user's epoch.
fn usable_by_link(conn: &Connection, hash: &str, now: i64) -> rusqlite::Result<Option<Family>> {
    conn.query_row(
        "SELECT f.id, f.user_id, u.email, f.server_id, s.slug, f.client_name, f.revoked_at IS NOT NULL \
         FROM disconnect_links d \
         JOIN token_families f ON f.id = d.family_id \
         JOIN users u ON u.id = f.user_id \
         LEFT JOIN servers s ON s.id = f.server_id \
         WHERE d.token_hash = ?1 AND f.revoked_at IS NULL AND f.expires_at > ?2 \
         AND f.auth_epoch = u.auth_epoch",
        params![hash, now],
        family_from_row,
    )
    .optional()
}

fn family_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Family> {
    Ok(Family {
        id: row.get(0)?,
        user_id: row.get(1)?,
        user_email: row.get(2)?,
        server_id: row.get(3)?,
        server_slug: row.get(4)?,
        client_name: row.get(5)?,
        revoked: row.get(6)?,
    })
}

fn link_page(viewer: &Viewer, family: &Family) -> Response {
    let data = MainData {
        client_name: Some(family.client_name.as_str()),
        server: Some(family.server_label()),
        ..MainData::default()
    };
    form_page_with(
        viewer,
        StatusCode::OK,
        "disconnect",
        "Disconnect an app",
        &data,
        |csrf| link_body(csrf, family),
    )
}

/// The one form has no action: it posts back to the link, so the token stays out of the markup.
fn link_body(csrf: &str, family: &Family) -> Markup {
    html! {
        h1 { "Disconnect this app?" }
        p.lede {
            (family.client_name) " on " (family.server_label())
            " will no longer be able to use your account."
        }
        form method="post" {
            input type="hidden" name="csrf" value=(csrf);
            button type="submit" data-kind="danger" { "Disconnect" }
        }
    }
}

fn disconnected_page(family: &Family) -> Response {
    page(
        StatusCode::OK,
        "disconnected",
        "App disconnected",
        html! {
            h1 { "The app is disconnected" }
            p.lede {
                (family.client_name) " on " (family.server_label())
                " can no longer use your account."
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use scraper::{Html, Selector};

    use super::*;

    fn family() -> Family {
        Family {
            id: 1,
            user_id: 2,
            user_email: "bob@example.com".to_owned(),
            server_id: Some(3),
            server_slug: Some("demo".to_owned()),
            client_name: "Claude Code".to_owned(),
            revoked: false,
        }
    }

    /// How many elements of `doc` match `css`.
    fn count(doc: &Html, css: &str) -> usize {
        doc.select(&Selector::parse(css).expect("selector")).count()
    }

    #[test]
    fn the_disconnect_question_has_a_lede_and_one_danger_button() {
        let doc = Html::parse_fragment(&link_body("token", &family()).into_string());
        assert_eq!(count(&doc, "h1 + p.lede"), 1);
        assert_eq!(count(&doc, r#"form > button[data-kind="danger"]"#), 1);
        assert_eq!(count(&doc, "button[data-kind=secondary]"), 0);
    }

    #[tokio::test]
    async fn the_disconnected_page_has_its_sentence_as_a_lede() {
        let bytes = to_bytes(disconnected_page(&family()).into_body(), usize::MAX)
            .await
            .expect("body");
        let doc = Html::parse_document(std::str::from_utf8(&bytes).expect("utf-8"));
        assert_eq!(count(&doc, "h1 + p.lede"), 1);
    }
}
