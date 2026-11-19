//! Registered clients and the client lookup that authorize and token use.

use rusqlite::{Connection, OptionalExtension, params};

use super::uri::{self, Redirect};

const REGISTERED_PREFIX: &str = "dcr_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Client {
    /// Registered here. `redirect_uris` as stored.
    Registered {
        client_id: String,
        client_name: String,
        redirect_uris: Vec<String>,
    },
    /// A metadata document address. Nothing is known about it until it is fetched.
    Document { client_id: String },
}

/// `dcr_` ids are looked up; an id that `is_document_id` is a Document; anything else is None.
pub fn find(conn: &Connection, client_id: &str) -> rusqlite::Result<Option<Client>> {
    if client_id.starts_with(REGISTERED_PREFIX) {
        return registered(conn, client_id);
    }
    if is_document_id(client_id) {
        return Ok(Some(Client::Document {
            client_id: client_id.to_owned(),
        }));
    }
    Ok(None)
}

/// `https://host/path` by the web grammar: scheme exactly https, and a path that is not `/`.
pub fn is_document_id(client_id: &str) -> bool {
    matches!(
        uri::parse(client_id),
        Some(Redirect::Web { scheme: "https", path, .. }) if path != "/"
    )
}

fn registered(conn: &Connection, client_id: &str) -> rusqlite::Result<Option<Client>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
            params![client_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((client_name, stored_uris)) = row else {
        return Ok(None);
    };
    let redirect_uris: Vec<String> = serde_json::from_str(&stored_uris).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(err))
    })?;
    Ok(Some(Client::Registered {
        client_id: client_id.to_owned(),
        client_name,
        redirect_uris,
    }))
}
