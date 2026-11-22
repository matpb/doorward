use rusqlite::{Connection, params};

use super::keys::{self, Table};
use super::testing::{key_of, key_of_password, keys as server_keys, unlock, wrapped_rows};
use super::{DataKey, ValuePlace, open_value, seal_value};
use crate::crypto::token_hash;
use crate::db::Db;

const SALT: [u8; 16] = [1; 16];
const PASSWORD: &str = "a long enough password";
const TOKEN: &str = "dw_ss_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER: &str = "dw_ss_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const URL: &str = "https://example.com/mcp";

fn open() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("doorward.db");
    Db::open(&path).expect("database");
    let conn = Connection::open(&path).expect("connection");
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .expect("pragma");
    (dir, conn)
}

fn add_user(conn: &Connection, email: &str) -> i64 {
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, 'hash', 'user', 0)",
        params![email],
    )
    .expect("user");
    conn.last_insert_rowid()
}

fn add_session(conn: &Connection, user: i64, token: &str) {
    conn.execute(
        "INSERT INTO sessions (id_hash, user_id, auth_epoch, created_at, expires_at) \
         VALUES (?1, ?2, 0, 0, 100)",
        params![token_hash(token), user],
    )
    .expect("session");
}

/// A server with one declared header; returns the server id and the header id.
fn add_header(conn: &Connection) -> (i64, i64) {
    conn.execute(
        "INSERT INTO servers (name, slug, upstream_url, created_at) VALUES ('demo', 'demo', ?1, 0)",
        params![URL],
    )
    .expect("server");
    let server = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO server_headers (server_id, name, name_lower, created_at) \
         VALUES (?1, 'X-Key', 'x-key', 0)",
        params![server],
    )
    .expect("header");
    (server, conn.last_insert_rowid())
}

fn store_value(conn: &Connection, key: &DataKey, user: i64, ids: (i64, i64), generation: i64) {
    let place = ValuePlace {
        user,
        server: ids.0,
        header: "x-key",
        generation,
        upstream_url: URL,
    };
    let sealed = seal_value(key, &place, b"canary").expect("seal");
    conn.execute(
        "INSERT INTO user_header_values (user_id, header_id, sealed, set_at) VALUES (?1, ?2, ?3, 0)",
        params![user, ids.1, sealed],
    )
    .expect("value");
}

fn stored_value(conn: &Connection, key: &DataKey, user: i64, ids: (i64, i64)) -> Option<Vec<u8>> {
    let generation: i64 = conn
        .query_row(
            "SELECT dek_gen FROM users WHERE id = ?1",
            params![user],
            |row| row.get(0),
        )
        .expect("generation");
    let sealed: String = conn
        .query_row(
            "SELECT sealed FROM user_header_values WHERE user_id = ?1 AND header_id = ?2",
            params![user, ids.1],
            |row| row.get(0),
        )
        .ok()?;
    let place = ValuePlace {
        user,
        server: ids.0,
        header: "x-key",
        generation,
        upstream_url: URL,
    };
    open_value(key, &place, &sealed)
        .ok()
        .map(|plain| plain.to_vec())
}

#[test]
fn the_first_unlock_makes_a_key_and_a_later_one_opens_the_same_key() {
    let (_dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    let keys = server_keys();
    let first = keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, SALT, true))
        .expect("create")
        .expect("a key");
    let again = keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, SALT, false))
        .expect("open")
        .expect("a key");
    assert_eq!(first.bytes(), again.bytes());
    assert_eq!(
        key_of_password(&conn, user, &unlock(PASSWORD, SALT, false)),
        Some(*first.bytes())
    );
}

#[test]
fn an_unlock_with_another_salt_or_a_damaged_wrap_gets_no_key_and_changes_nothing() {
    let (_dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    let keys = server_keys();
    keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, SALT, true)).expect("create");
    let before: (String, String) = conn
        .query_row(
            "SELECT dek_wrap, dek_salt FROM users WHERE id = ?1",
            params![user],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("row");
    let racing = keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, [2; 16], true));
    assert!(racing.expect("no error").is_none());
    let wrong = keys::open_or_create(
        &conn,
        &keys,
        user,
        &unlock("another password!", SALT, false),
    );
    assert!(wrong.expect("no error").is_none());
    conn.execute(
        "UPDATE users SET dek_wrap = 'garbage' WHERE id = ?1",
        params![user],
    )
    .expect("damage");
    let damaged = keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, SALT, false));
    assert!(damaged.expect("no error").is_none());
    let after: String = conn
        .query_row(
            "SELECT dek_wrap FROM users WHERE id = ?1",
            params![user],
            |r| r.get(0),
        )
        .expect("row");
    assert_eq!(after, "garbage", "a damaged wrap is left as it is");
    assert_ne!(before.0, after);
}

#[test]
fn a_row_wrap_opens_with_its_token_only_and_a_clear_removes_it() {
    let (_dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    add_session(&conn, user, TOKEN);
    let keys = server_keys();
    let key = DataKey::random();
    let hash = token_hash(TOKEN);
    keys::wrap_row(&conn, &keys, user, Table::Sessions, &hash, TOKEN, &key).expect("wrap");
    assert_eq!(
        key_of(&conn, user, Table::Sessions, &hash, TOKEN),
        Some(*key.bytes())
    );
    assert_eq!(key_of(&conn, user, Table::Sessions, &hash, OTHER), None);
    assert_eq!(key_of(&conn, user + 1, Table::Sessions, &hash, TOKEN), None);
    keys::clear_row(&conn, Table::Sessions, &hash).expect("clear");
    assert_eq!(wrapped_rows(&conn, "sessions"), 0);
}

#[test]
fn rekey_moves_every_value_to_the_new_key_and_the_next_generation() {
    let (_dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    let keys = server_keys();
    let old = keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, SALT, true))
        .expect("create")
        .expect("a key");
    let ids = add_header(&conn);
    store_value(&conn, &old, user, ids, 0);
    let new_unlock = unlock("a brand new password", [9; 16], true);
    let new = keys::rekey(
        &conn,
        &keys,
        user,
        Some(&old),
        &new_unlock,
        "bob@example.com",
        5,
    )
    .expect("rekey");
    assert_ne!(new.bytes(), old.bytes());
    assert_eq!(
        stored_value(&conn, &new, user, ids).as_deref(),
        Some(&b"canary"[..])
    );
    assert_eq!(stored_value(&conn, &old, user, ids), None);
    let generation: i64 = conn
        .query_row(
            "SELECT dek_gen FROM users WHERE id = ?1",
            params![user],
            |r| r.get(0),
        )
        .expect("generation");
    assert_eq!(generation, 1);
    assert_eq!(
        key_of_password(&conn, user, &new_unlock),
        Some(*new.bytes())
    );
    assert_eq!(
        key_of_password(&conn, user, &unlock(PASSWORD, SALT, false)),
        None
    );
    let dropped: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(dropped, 0);
}

#[test]
fn rekey_without_the_old_key_deletes_the_values_and_writes_one_activity_row() {
    let (_dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    let keys = server_keys();
    let old = DataKey::random();
    let ids = add_header(&conn);
    store_value(&conn, &old, user, ids, 0);
    let new_unlock = unlock("a brand new password", [9; 16], true);
    let new =
        keys::rekey(&conn, &keys, user, None, &new_unlock, "bob@example.com", 5).expect("rekey");
    assert_eq!(stored_value(&conn, &new, user, ids), None);
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM user_header_values", [], |r| r.get(0))
        .expect("count");
    assert_eq!(rows, 0);
    let (email, detail): (String, String) = conn
        .query_row(
            "SELECT user_email, detail FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("one row");
    assert_eq!(email, "bob@example.com");
    assert!(!detail.contains("canary"));
    assert_eq!(
        key_of_password(&conn, user, &new_unlock),
        Some(*new.bytes()),
        "the new key is still made"
    );
}

#[test]
fn forget_deletes_the_values_and_the_password_wrap_and_moves_the_generation() {
    let (_dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    let keys = server_keys();
    let key = keys::open_or_create(&conn, &keys, user, &unlock(PASSWORD, SALT, true))
        .expect("create")
        .expect("a key");
    let ids = add_header(&conn);
    store_value(&conn, &key, user, ids, 0);
    assert_eq!(keys::forget(&conn, user).expect("forget"), 1);
    let (generation, wrap, salt): (i64, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT dek_gen, dek_wrap, dek_salt FROM users WHERE id = ?1",
            params![user],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("row");
    assert_eq!((generation, wrap, salt), (1, None, None));
    assert_eq!(keys::forget(&conn, user).expect("again"), 0);
}

#[test]
fn clear_user_tokens_nulls_codes_and_both_token_tables_of_that_user_only() {
    let (_dir, conn) = open();
    let bob = add_user(&conn, "bob@example.com");
    let eve = add_user(&conn, "eve@example.com");
    for (user, name) in [(bob, "b"), (eve, "e")] {
        conn.execute(
            "INSERT INTO token_families (public_id, user_id, client_id, client_name, auth_epoch, \
             created_at, expires_at) VALUES (?1, ?2, 'c', 'C', 0, 0, 100)",
            params![format!("fam_{name}"), user],
        )
        .expect("family");
        let family = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO access_tokens (token_hash, family_id, expires_at, dek_wrap) VALUES (?1, ?2, 100, 'w')",
            params![format!("a{name}"), family],
        )
        .expect("access");
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at, dek_wrap) \
             VALUES (?1, ?2, 0, 100, 'w')",
            params![format!("r{name}"), family],
        )
        .expect("refresh");
        conn.execute(
            "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, user_id, combined, client_name, \
             code_challenge, auth_epoch, created_at, expires_at, dek_wrap) \
             VALUES (?1, 'c', 'http://127.0.0.1/cb', ?2, 1, 'C', 'x', 0, 0, 100, 'w')",
            params![format!("c{name}"), user],
        )
        .expect("code");
    }
    keys::clear_user_tokens(&conn, bob).expect("clear");
    for table in ["access_tokens", "refresh_tokens", "auth_codes"] {
        assert_eq!(
            wrapped_rows(&conn, table),
            1,
            "{table} keeps only eve's wrap"
        );
    }
}

fn unlocked(password: &str, salt: [u8; 16], fresh: bool) -> keys::Unlocked {
    keys::Unlocked {
        keys: std::sync::Arc::new(server_keys()),
        unlock: unlock(password, salt, fresh),
    }
}

fn generation_of(conn: &Connection, user: i64) -> i64 {
    conn.query_row(
        "SELECT dek_gen FROM users WHERE id = ?1",
        params![user],
        |row| row.get(0),
    )
    .expect("generation")
}

fn value_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM user_header_values", [], |row| {
        row.get(0)
    })
    .expect("count")
}

/// A user with a key, a second session that opens it, one stored value and a third, new session.
fn healing_setup() -> (tempfile::TempDir, Connection, i64, [u8; 32]) {
    let (dir, conn) = open();
    let user = add_user(&conn, "bob@example.com");
    let ks = server_keys();
    let key = keys::open_or_create(&conn, &ks, user, &unlock(PASSWORD, SALT, true))
        .expect("reads")
        .expect("a key");
    add_session(&conn, user, OTHER);
    keys::wrap_row(
        &conn,
        &ks,
        user,
        Table::Sessions,
        &token_hash(OTHER),
        OTHER,
        &key,
    )
    .expect("wrap");
    let ids = add_header(&conn);
    store_value(&conn, &key, user, ids, 0);
    add_session(&conn, user, TOKEN);
    (dir, conn, user, *key.bytes())
}

const EMAIL: &str = "bob@example.com";

#[test]
fn a_heal_changes_nothing_while_the_password_wrap_opens() {
    let (_dir, mut conn, user, _old) = healing_setup();
    keys::heal(
        &mut conn,
        &unlocked(PASSWORD, SALT, false),
        (user, EMAIL),
        TOKEN,
        5,
    )
    .expect("heal");
    assert_eq!((generation_of(&conn, user), value_count(&conn)), (0, 1));
}

#[test]
fn a_heal_changes_nothing_when_the_salt_differs() {
    let (_dir, mut conn, user, _old) = healing_setup();
    for fresh in [false, true] {
        keys::heal(
            &mut conn,
            &unlocked(PASSWORD, [2; 16], fresh),
            (user, EMAIL),
            TOKEN,
            5,
        )
        .expect("heal");
        assert_eq!((generation_of(&conn, user), value_count(&conn)), (0, 1));
    }
}

#[test]
fn a_heal_changes_nothing_without_a_wrap_or_without_a_salt() {
    let (_dir, mut conn, user, _old) = healing_setup();
    conn.execute("UPDATE users SET dek_wrap = NULL", [])
        .expect("clear");
    keys::heal(
        &mut conn,
        &unlocked(PASSWORD, SALT, false),
        (user, EMAIL),
        TOKEN,
        5,
    )
    .expect("heal");
    assert_eq!((generation_of(&conn, user), value_count(&conn)), (0, 1));
    conn.execute("UPDATE users SET dek_wrap = 'garbage', dek_salt = NULL", [])
        .expect("damage");
    keys::heal(
        &mut conn,
        &unlocked(PASSWORD, SALT, false),
        (user, EMAIL),
        TOKEN,
        5,
    )
    .expect("heal");
    assert_eq!((generation_of(&conn, user), value_count(&conn)), (0, 1));
}

#[test]
fn a_heal_leaves_one_wrapped_session_and_the_other_wraps_cleared() {
    let (_dir, mut conn, user, old) = healing_setup();
    assert_eq!(
        key_of(&conn, user, Table::Sessions, &token_hash(OTHER), OTHER),
        Some(old),
        "the other session opens the old key before the heal"
    );
    conn.execute("UPDATE users SET dek_wrap = 'garbage'", [])
        .expect("damage");
    keys::heal(
        &mut conn,
        &unlocked(PASSWORD, SALT, false),
        (user, EMAIL),
        TOKEN,
        5,
    )
    .expect("heal");
    assert_eq!((generation_of(&conn, user), value_count(&conn)), (1, 0));
    assert_eq!(
        key_of(&conn, user, Table::Sessions, &token_hash(OTHER), OTHER),
        None
    );
    let fresh = key_of(&conn, user, Table::Sessions, &token_hash(TOKEN), TOKEN)
        .expect("the new session opens the new key");
    assert_ne!(fresh, old);
    assert_eq!(
        wrapped_rows(&conn, "sessions"),
        1,
        "exactly one session holds a wrap"
    );
    assert_eq!(
        key_of_password(&conn, user, &unlock(PASSWORD, SALT, false)),
        Some(fresh)
    );
}

#[test]
fn a_heal_also_fires_when_the_wrap_is_under_an_older_password_with_the_same_salt() {
    let (_dir, mut conn, user, _old) = healing_setup();
    keys::heal(
        &mut conn,
        &unlocked("another accepted password", SALT, false),
        (user, EMAIL),
        TOKEN,
        5,
    )
    .expect("heal");
    assert_eq!((generation_of(&conn, user), value_count(&conn)), (1, 0));
}
