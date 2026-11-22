use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use doorward::crypto::{CryptoError, Keys, token_hash};
use doorward::vault::{self, DataKey, Place, ValuePlace};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::client::{Page, TestClient};
use super::world::World;

/// A stored value that appears nowhere else in a test.
pub const CANARY: &str = "canary-7f3a9c51e2d44b06";
const RESET_SUBJECT: &str = "Reset your Doorward password";

/// The anti-forgery value of the account page.
pub async fn account_csrf(browser: &TestClient) -> String {
    browser
        .get("/account")
        .await
        .csrf()
        .expect("the account page carries a csrf field")
}

/// Posts `value` for the declared header `header_id` of the server `slug`.
pub async fn store_value(browser: &TestClient, slug: &str, header_id: &str, value: &str) -> Page {
    let csrf = account_csrf(browser).await;
    let field = format!("value_{header_id}");
    browser
        .post(
            &format!("/account/values/{slug}"),
            &[("csrf", csrf.as_str()), (field.as_str(), value)],
        )
        .await
}

/// Ticks the remove box of the header `header_id` on the values form of `slug` and posts it.
pub async fn remove_value(browser: &TestClient, slug: &str, header_id: &str) -> Page {
    let csrf = account_csrf(browser).await;
    let field = format!("remove_{header_id}");
    browser
        .post(
            &format!("/account/values/{slug}"),
            &[("csrf", csrf.as_str()), (field.as_str(), "1")],
        )
        .await
}

/// The state shown for the header `header` (lower-cased) of `slug` on the account page.
pub async fn value_state(browser: &TestClient, slug: &str, header: &str) -> Option<String> {
    browser.get("/account").await.attr(
        &format!(
            r#"section[data-values-server="{slug}"] [data-value-state][data-header="{header}"]"#
        ),
        "data-value-state",
    )
}

/// The needs-values flag of the account page's section for `slug`.
pub async fn needs_values(browser: &TestClient, slug: &str) -> Option<String> {
    browser.get("/account").await.attr(
        &format!(r#"section[data-values-server="{slug}"]"#),
        "data-needs-values",
    )
}

/// A connection to the gateway's own database file.
pub fn live_db(w: &World) -> Connection {
    Connection::open(w.gw.db_path()).expect("the gateway database opens")
}

/// Copies the database, its write-ahead log and the key file to a new folder, then loads the
/// key from the copy the way the gateway does. The folder lives as long as the first value.
pub fn copy_store(w: &World) -> (TempDir, Connection, Keys) {
    let live = w.gw.db_path();
    let dir = tempfile::tempdir().expect("a temporary folder");
    let db = dir
        .path()
        .join(live.file_name().expect("the database has a file name"));
    copy(&live, &db);
    let wal = with_suffix(&live, "-wal");
    if wal.exists() {
        copy(&wal, &with_suffix(&db, "-wal"));
    }
    copy(&with_suffix(&live, ".key"), &with_suffix(&db, ".key"));
    let conn = Connection::open(&db).expect("the copied database opens");
    let mut config = w.gw.config().clone();
    config.database = db;
    let keys = Keys::load(&config, stored_key_id(&conn).as_deref())
        .expect("the copied key opens the copied database");
    (dir, conn, keys)
}

/// The paths of every file in the copy folder.
pub fn copied_files(dir: &TempDir) -> Vec<PathBuf> {
    fs::read_dir(dir.path())
        .expect("the copy folder reads")
        .map(|entry| entry.expect("a directory entry").path())
        .collect()
}

/// Whether the file at `path` holds `needle` anywhere.
pub fn file_contains(path: &Path, needle: &[u8]) -> bool {
    let bytes =
        fs::read(path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// A token-bound wrap of the data key, with the row it sits on and the user and generation it names.
pub struct Wrap {
    pub table: &'static str,
    pub row: String,
    pub user: i64,
    pub generation: i64,
    pub wrap: String,
}

/// Every wrap on a code, session or token row of the copy, with the user and generation of its row.
pub fn token_wraps(conn: &Connection) -> Vec<Wrap> {
    let queries: [(&'static str, &str); 4] = [
        (
            "sessions",
            "SELECT r.id_hash, r.user_id, u.dek_gen, r.dek_wrap FROM sessions r \
             JOIN users u ON u.id = r.user_id WHERE r.dek_wrap IS NOT NULL",
        ),
        (
            "auth_codes",
            "SELECT r.code_hash, r.user_id, u.dek_gen, r.dek_wrap FROM auth_codes r \
             JOIN users u ON u.id = r.user_id WHERE r.dek_wrap IS NOT NULL",
        ),
        (
            "access_tokens",
            "SELECT r.token_hash, f.user_id, u.dek_gen, r.dek_wrap FROM access_tokens r \
             JOIN token_families f ON f.id = r.family_id \
             JOIN users u ON u.id = f.user_id WHERE r.dek_wrap IS NOT NULL",
        ),
        (
            "refresh_tokens",
            "SELECT r.token_hash, f.user_id, u.dek_gen, r.dek_wrap FROM refresh_tokens r \
             JOIN token_families f ON f.id = r.family_id \
             JOIN users u ON u.id = f.user_id WHERE r.dek_wrap IS NOT NULL",
        ),
    ];
    let mut found = Vec::new();
    for (table, sql) in queries {
        let mut statement = conn.prepare(sql).expect("the wrap query prepares");
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .expect("the wrap query runs");
        for row in rows {
            let (row_hash, user, generation, wrap) = row.expect("a wrap row reads");
            found.push(Wrap {
                table,
                row: row_hash,
                user,
                generation,
                wrap,
            });
        }
    }
    found
}

/// Whether `token` opens the wrap `wrap`, with the place the wrap's row names.
fn opens(keys: &Keys, wrap: &Wrap, token: &str) -> bool {
    let place = Place {
        user: wrap.user,
        generation: wrap.generation,
        table: wrap.table,
        row: wrap.row.as_str(),
    };
    vault::unwrap_with_token(keys, &place, token, &wrap.wrap).is_ok()
}

/// Opens the wrap that sits on the row of `token` in `table`; the error when the copy holds none.
pub fn token_data_key(
    conn: &Connection,
    keys: &Keys,
    table: &str,
    token: &str,
) -> Result<DataKey, CryptoError> {
    let hash = token_hash(token);
    let wrap = token_wraps(conn)
        .into_iter()
        .find(|wrap| wrap.table == table && wrap.row == hash)
        .ok_or(CryptoError::Open)?;
    let place = Place {
        user: wrap.user,
        generation: wrap.generation,
        table: wrap.table,
        row: wrap.row.as_str(),
    };
    vault::unwrap_with_token(keys, &place, token, &wrap.wrap)
}

/// Whether `token` opens any of the `wraps`.
pub fn any_wrap_opens(keys: &Keys, wraps: &[Wrap], token: &str) -> bool {
    wraps.iter().any(|wrap| opens(keys, wrap, token))
}

/// Whether `token` opens any wrap in the copy.
pub fn opens_any_row(conn: &Connection, keys: &Keys, token: &str) -> bool {
    any_wrap_opens(keys, &token_wraps(conn), token)
}

/// A stored value in the copy, with the place it is bound to.
pub struct Sealed {
    pub user: i64,
    pub header_id: i64,
    pub server: i64,
    pub header: String,
    pub upstream_url: String,
    pub generation: i64,
    pub sealed: String,
}

/// Every stored value of the copy.
pub fn sealed_values(conn: &Connection) -> Vec<Sealed> {
    let mut statement = conn
        .prepare(
            "SELECT v.user_id, v.header_id, s.id, h.name_lower, s.upstream_url, u.dek_gen, v.sealed \
             FROM user_header_values v JOIN server_headers h ON h.id = v.header_id \
             JOIN servers s ON s.id = h.server_id JOIN users u ON u.id = v.user_id",
        )
        .expect("the value query prepares");
    let rows = statement
        .query_map([], |row| {
            Ok(Sealed {
                user: row.get(0)?,
                header_id: row.get(1)?,
                server: row.get(2)?,
                header: row.get(3)?,
                upstream_url: row.get(4)?,
                generation: row.get(5)?,
                sealed: row.get(6)?,
            })
        })
        .expect("the value query runs");
    rows.map(|row| row.expect("a value row reads")).collect()
}

/// The stored value of `user` for the declared header `header_id` in the copy.
pub fn sealed_of(conn: &Connection, user: i64, header_id: i64) -> Sealed {
    sealed_values(conn)
        .into_iter()
        .find(|sealed| sealed.user == user && sealed.header_id == header_id)
        .expect("the user has a stored value for the header")
}

/// Opens a stored value with `key`, the error when the place or the key does not match.
pub fn open_sealed(key: &DataKey, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let place = ValuePlace {
        user: sealed.user,
        server: sealed.server,
        header: sealed.header.as_str(),
        generation: sealed.generation,
        upstream_url: sealed.upstream_url.as_str(),
    };
    vault::open_value(key, &place, &sealed.sealed)
}

/// The generation, password wrap and salt of a user's data key, when the copy holds them.
pub fn password_wrap(conn: &Connection, user: i64) -> Option<(i64, String, [u8; 16])> {
    let (generation, wrap, salt): (i64, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT dek_gen, dek_wrap, dek_salt FROM users WHERE id = ?1",
            [user],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the users row reads");
    let wrap = wrap?;
    let salt_bytes = URL_SAFE_NO_PAD
        .decode(salt?)
        .expect("the salt is base64url text");
    let salt: [u8; 16] = salt_bytes.try_into().expect("the salt is 16 bytes");
    Some((generation, wrap, salt))
}

/// Opens the password wrap of `user` with `password`; the error when the copy holds no wrap.
pub fn password_opens(
    keys: &Keys,
    conn: &Connection,
    user: i64,
    password: &str,
) -> Result<DataKey, CryptoError> {
    let (generation, wrap, salt) = password_wrap(conn, user).ok_or(CryptoError::Open)?;
    let key = vault::password_key(password, &salt)?;
    let row = user.to_string();
    let place = Place {
        user,
        generation,
        table: "users",
        row: row.as_str(),
    };
    vault::unwrap_with_password(keys, &place, &key, &wrap)
}

/// Every text value stored anywhere in the copy, each once.
pub fn stored_strings(conn: &Connection) -> Vec<String> {
    let mut names = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .expect("the table list prepares");
    let tables: Vec<String> = names
        .query_map([], |row| row.get(0))
        .expect("the table list runs")
        .map(|name| name.expect("a table name reads"))
        .collect();
    let mut found = BTreeSet::new();
    for table in tables {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .expect("the table reads");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("the table queries");
        while let Some(row) = rows.next().expect("a row reads") {
            for index in 0..columns {
                if let ValueRef::Text(bytes) = row.get_ref(index).expect("a cell reads") {
                    found.insert(String::from_utf8_lossy(bytes).into_owned());
                }
            }
        }
    }
    found.into_iter().collect()
}

/// Asks for a reset link for `email`; the answer is the forgot page's.
pub async fn request_reset(browser: &TestClient, email: &str) -> Page {
    let csrf = browser
        .get("/forgot")
        .await
        .csrf()
        .expect("the forgot page carries a csrf field");
    browser
        .post("/forgot", &[("csrf", csrf.as_str()), ("email", email)])
        .await
}

/// The link of the newest reset mail to `email`, waiting up to 5 seconds for it.
pub async fn reset_link(w: &World, email: &str) -> String {
    let prefix = format!("{}/reset/", w.base());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = w
            .mail
            .to(email)
            .into_iter()
            .rev()
            .find(|message| message.subject == RESET_SUBJECT);
        if let Some(message) = found {
            return super::mail::link_with_prefix(&message.text, &prefix)
                .expect("the reset mail has a link");
        }
        assert!(
            Instant::now() < deadline,
            "no reset mail reached {email} within 5 seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn stored_key_id(conn: &Connection) -> Option<String> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = 'crypto.key_id'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("the settings table reads");
    bytes.map(|bytes| String::from_utf8(bytes).expect("the key id is text"))
}

fn copy(from: &Path, to: &Path) {
    fs::copy(from, to).unwrap_or_else(|err| panic!("cannot copy {}: {err}", from.display()));
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
