//! The values a user stored for a server's custom headers, opened for the length of one request.

use axum::http::{HeaderMap, HeaderValue};
use rusqlite::{Connection, OptionalExtension, params};

use crate::app::AppState;
use crate::crypto::{Keys, token_hash};
use crate::custom_headers::{self, Resolved, ServerHeaders};
use crate::db::DbError;
use crate::oauth::guard::{Caller, bearer_token};
use crate::servers;
use crate::vault::keys::{self, Table};
use crate::vault::{ValuePlace, open_value};

/// What proves the data key: the raw secret of a row that carries a wrap of it.
#[derive(Clone, Copy)]
pub enum Via<'a> {
    Access(&'a str),
    Session(&'a str),
}

/// A user's stored values for one server, opened.
pub struct Opened {
    /// Lower-cased header name and value, marked sensitive.
    pub stored: Vec<(String, HeaderValue)>,
    /// The lower-cased names that have a stored row, opened or not.
    pub held: Vec<String>,
    /// The key could not be opened although a value is held or needed.
    pub locked: bool,
}

/// Opens `user`'s stored values for `server`, bound to the address `url`. The key is worked only when a
/// value is held or `need_key` is true; a row that does not open counts as absent.
pub fn open_for(
    conn: &Connection,
    keys: &Keys,
    user: i64,
    server: i64,
    url: &str,
    via: Option<Via<'_>>,
    need_key: bool,
) -> rusqlite::Result<Opened> {
    let rows: Vec<(String, String)> = {
        let mut statement = conn.prepare(
            "SELECT h.name_lower, v.sealed FROM user_header_values v \
             JOIN server_headers h ON h.id = v.header_id \
             WHERE v.user_id = ?1 AND h.server_id = ?2 ORDER BY h.id",
        )?;
        statement
            .query_map(params![user, server], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let held: Vec<String> = rows.iter().map(|(name, _)| name.clone()).collect();
    if rows.is_empty() && !need_key {
        return Ok(Opened {
            stored: Vec::new(),
            held,
            locked: false,
        });
    }
    let key = match via {
        Some(Via::Access(token)) => keys::open_row(
            conn,
            keys,
            user,
            Table::AccessTokens,
            &token_hash(token),
            token,
        )?,
        Some(Via::Session(token)) => {
            keys::open_row(conn, keys, user, Table::Sessions, &token_hash(token), token)?
        }
        None => None,
    };
    let Some(key) = key else {
        return Ok(Opened {
            stored: Vec::new(),
            held,
            locked: true,
        });
    };
    let generation: i64 = conn
        .query_row(
            "SELECT dek_gen FROM users WHERE id = ?1",
            params![user],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let mut stored = Vec::new();
    for (name, sealed) in &rows {
        let place = ValuePlace {
            user,
            server,
            header: name,
            generation,
            upstream_url: url,
        };
        let Ok(plain) = open_value(&key, &place, sealed) else {
            continue;
        };
        if let Ok(mut value) = HeaderValue::from_bytes(&plain) {
            value.set_sensitive(true);
            stored.push((name.clone(), value));
        }
    }
    Ok(Opened {
        stored,
        held,
        locked: false,
    })
}

/// A server's custom headers resolved for one caller, with what the sender must check.
pub struct Reached {
    pub resolved: Resolved,
    /// The server's name; None when no server has the id.
    pub name: Option<String>,
    /// Whether the server lets users store values.
    pub store: bool,
    /// The upstream address the values were opened for; the request must go to exactly this address.
    pub url: String,
}

/// The headers `caller`'s request carries to `server`: the client's passed values, else the stored ones.
/// `bound` is the address the request will be sent to; without it the server's stored address is used.
pub async fn resolve(
    state: &AppState,
    caller: &Caller,
    client: &HeaderMap,
    server: i64,
    bound: Option<&str>,
) -> Result<Reached, DbError> {
    let keys = state.keys.clone();
    let user = caller.user_id;
    let token = bearer_token(client).map(str::to_owned);
    let client = client.clone();
    let bound = bound.map(str::to_owned);
    state
        .db
        .call(move |conn| {
            let config = custom_headers::load(conn, server)?;
            let Some(row) = servers::load(conn, server)? else {
                return Ok(Reached {
                    resolved: custom_headers::resolve(&config, &client, &[]),
                    name: None,
                    store: config.store,
                    url: String::new(),
                });
            };
            let url = bound.unwrap_or(row.upstream_url);
            let reached = |resolved| Reached {
                resolved,
                name: Some(row.name.clone()),
                store: config.store,
                url: url.clone(),
            };
            if !config.store || config.declared.is_empty() {
                return Ok(reached(custom_headers::resolve(&config, &client, &[])));
            }
            let need_key = config.declared.iter().any(|declared| declared.required);
            let via = token.as_deref().map(Via::Access);
            let opened = open_for(conn, &keys, user, server, &url, via, need_key)?;
            let resolved = custom_headers::resolve(&config, &client, &opened.stored);
            Ok(reached(lock_check(&config, &client, &opened, resolved)))
        })
        .await
}

/// A held value that cannot be opened makes the connection locked, unless the client supplies that header itself.
fn lock_check(
    config: &ServerHeaders,
    client: &HeaderMap,
    opened: &Opened,
    resolved: Resolved,
) -> Resolved {
    if !opened.locked {
        return resolved;
    }
    let supplied = |name: &str| config.pass && name != "authorization" && client.contains_key(name);
    let uncovered = opened.held.iter().any(|name| !supplied(name));
    match resolved {
        Resolved::Missing { .. } => Resolved::Locked,
        Resolved::Ready(_) if uncovered => Resolved::Locked,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    use super::*;
    use crate::db::Db;
    use crate::vault::keys::wrap_row;
    use crate::vault::testing::keys as server_keys;
    use crate::vault::{DataKey, seal_value};

    const URL: &str = "https://example.com/mcp";
    const SESSION: &str = "dw_ss_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "dw_ss_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    /// A user with a session that wraps a data key, a server with one header, and one value sealed for `sealed_url`.
    fn fixture(sealed_url: &str) -> (tempfile::TempDir, Connection, Keys) {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("database");
        let conn = Connection::open(&path).expect("connection");
        conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES ('bob@example.com', 'h', 'user', 0)",
            [],
        )
        .expect("user");
        conn.execute(
            "INSERT INTO sessions (id_hash, user_id, auth_epoch, created_at, expires_at) VALUES (?1, 1, 0, 0, 100)",
            params![token_hash(SESSION)],
        )
        .expect("session");
        conn.execute(
            "INSERT INTO servers (name, slug, upstream_url, created_at) VALUES ('demo', 'demo', ?1, 0)",
            params![URL],
        )
        .expect("server");
        conn.execute(
            "INSERT INTO server_headers (server_id, name, name_lower, created_at) VALUES (1, 'X-Key', 'x-key', 0)",
            [],
        )
        .expect("header");
        let keys = server_keys();
        let key = DataKey::random();
        wrap_row(
            &conn,
            &keys,
            1,
            Table::Sessions,
            &token_hash(SESSION),
            SESSION,
            &key,
        )
        .expect("wrap");
        let place = ValuePlace {
            user: 1,
            server: 1,
            header: "x-key",
            generation: 0,
            upstream_url: sealed_url,
        };
        let sealed = seal_value(&key, &place, b"canary").expect("seal");
        conn.execute(
            "INSERT INTO user_header_values (user_id, header_id, sealed, set_at) VALUES (1, 1, ?1, 0)",
            params![sealed],
        )
        .expect("value");
        (dir, conn, keys)
    }

    #[test]
    fn an_opened_value_is_marked_sensitive() {
        let (_dir, conn, keys) = fixture(URL);
        let opened =
            open_for(&conn, &keys, 1, 1, URL, Some(Via::Session(SESSION)), false).expect("opens");
        assert!(!opened.locked);
        assert_eq!(opened.stored.len(), 1);
        assert_eq!(opened.stored[0].0, "x-key");
        assert_eq!(opened.stored[0].1.as_bytes(), b"canary");
        assert!(opened.stored[0].1.is_sensitive());
    }

    #[test]
    fn a_secret_that_opens_no_wrap_locks_a_held_value() {
        let (_dir, conn, keys) = fixture(URL);
        for via in [Some(Via::Session(OTHER)), None] {
            let opened = open_for(&conn, &keys, 1, 1, URL, via, false).expect("reads");
            assert!(opened.locked, "a held value needs the key");
            assert!(opened.stored.is_empty());
            assert_eq!(opened.held, ["x-key"]);
        }
    }

    #[test]
    fn a_value_sealed_for_another_address_is_absent() {
        let (_dir, conn, keys) = fixture("https://other.example.com/mcp");
        let opened =
            open_for(&conn, &keys, 1, 1, URL, Some(Via::Session(SESSION)), false).expect("reads");
        assert!(!opened.locked);
        assert!(
            opened.stored.is_empty(),
            "a row that does not open is absent"
        );
    }

    #[test]
    fn no_held_value_and_no_need_means_no_key_work() {
        let (_dir, conn, keys) = fixture(URL);
        conn.execute("DELETE FROM user_header_values", [])
            .expect("delete");
        let opened = open_for(&conn, &keys, 1, 1, URL, None, false).expect("reads");
        assert!(
            !opened.locked,
            "nothing held and nothing needed is not locked"
        );
        let needed = open_for(&conn, &keys, 1, 1, URL, None, true).expect("reads");
        assert!(needed.locked, "a needed key that cannot open is locked");
    }
}
