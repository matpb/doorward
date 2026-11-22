//! Helpers the tests of the vault and of the flows that use it share.

use std::path::PathBuf;

use rusqlite::{Connection, params};

use super::keys::{Table, Unlock};
use super::{DataKey, password_key};
use crate::config::Config;
use crate::crypto::Keys;

const MASTER: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// The server keys every test of the flows uses.
pub(crate) fn keys() -> Keys {
    let config = Config {
        public_url: "https://example.com".to_owned(),
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 8717)),
        database: PathBuf::from("unused.db"),
        key_file: None,
        trusted_proxies: Vec::new(),
        shared_client_address: false,
        allowed_origins: Vec::new(),
        lifetimes: Default::default(),
        limits: Default::default(),
        mail: Default::default(),
    };
    Keys::from_sources(Some(MASTER.to_owned()), &config, None).expect("keys")
}

/// The unlock of `password` under `salt`; `fresh` as the hasher would set it.
pub(crate) fn unlock(password: &str, salt: [u8; 16], fresh: bool) -> Unlock {
    Unlock {
        salt,
        key: password_key(password, &salt).expect("password key"),
        fresh,
    }
}

/// The data key that `token` opens from the row `row_hash` of `table`, as bytes.
pub(crate) fn key_of(
    conn: &Connection,
    user: i64,
    table: Table,
    row_hash: &str,
    token: &str,
) -> Option<[u8; 32]> {
    super::keys::open_row(conn, &keys(), user, table, row_hash, token)
        .expect("the row reads")
        .map(|key| *key.bytes())
}

/// The data key of the user's password wrap, as bytes.
pub(crate) fn key_of_password(conn: &Connection, user: i64, unlock: &Unlock) -> Option<[u8; 32]> {
    super::keys::open_password(conn, &keys(), user, unlock)
        .expect("the user reads")
        .map(|key: DataKey| *key.bytes())
}

/// How many rows of `table` carry a wrap.
pub(crate) fn wrapped_rows(conn: &Connection, table: &str) -> i64 {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE dek_wrap IS NOT NULL"),
        params![],
        |row| row.get(0),
    )
    .expect("count")
}
