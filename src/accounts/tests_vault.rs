//! The data key through sign-in, setup, invitation, password change, reset, sign-out and
//! revocation: each step's wraps open with the right secret to the same key, and damage never
//! changes whether the step succeeds.

use std::sync::Arc;

use rusqlite::{Connection, params};

use crate::crypto::{Keys, token_hash};
use crate::db::Db;
use crate::vault::keys::{Table, Unlock, Unlocked};
use crate::vault::testing::{key_of, key_of_password, keys as server_keys, unlock, wrapped_rows};
use crate::vault::{DataKey, ValuePlace, open_value, seal_value};

use super::invite::{Accept, accept_in};
use super::password::{Change, ChangeVault, change_in};
use super::reset::{Complete, complete_in};
use super::session;
use super::setup::create_owner_in;
use super::throttle::{Success, succeed_in};

const NOW: i64 = 1_000;
const LIFETIME: i64 = 3_600;
const EMAIL: &str = "bob@example.com";
const PASSWORD: &str = "a long enough password";
const NEW_PASSWORD: &str = "a brand new password!";
const SALT: [u8; 16] = [1; 16];
const NEW_SALT: [u8; 16] = [2; 16];
const URL: &str = "https://example.com/mcp";
const OLD_PHC: &str = "old-hash";

fn open() -> (tempfile::TempDir, Db) {
    let dir = tempfile::tempdir().expect("dir");
    let db = Db::open(&dir.path().join("doorward.db")).expect("open");
    (dir, db)
}

fn arc_keys() -> Arc<Keys> {
    Arc::new(server_keys())
}

fn unlocked(password: &str, salt: [u8; 16], fresh: bool) -> Unlocked {
    Unlocked {
        keys: arc_keys(),
        unlock: unlock(password, salt, fresh),
    }
}

fn add_user(conn: &Connection) -> i64 {
    conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, ?2, 'user', 0)",
        params![EMAIL, OLD_PHC],
    )
    .expect("user");
    conn.last_insert_rowid()
}

fn epoch_of(conn: &Connection, user: i64) -> i64 {
    conn.query_row(
        "SELECT auth_epoch FROM users WHERE id = ?1",
        params![user],
        |r| r.get(0),
    )
    .expect("epoch")
}

fn success(user: i64, vault: Option<Unlocked>) -> Success {
    Success {
        account: token_hash(EMAIL),
        address: "127.0.0.1".to_owned(),
        user_id: user,
        email: EMAIL.to_owned(),
        previous: None,
        now: NOW,
        lifetime: LIFETIME,
        phc: OLD_PHC.to_owned(),
        epoch: 0,
        vault,
    }
}

fn session_key(conn: &Connection, user: i64, token: &str) -> Option<[u8; 32]> {
    key_of(conn, user, Table::Sessions, &token_hash(token), token)
}

fn sign_in(conn: &mut Connection, user: i64, vault: Option<Unlocked>) -> String {
    succeed_in(conn, &success(user, vault))
        .expect("sign-in runs")
        .expect("sign-in succeeds")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_sign_in_makes_the_key_and_every_later_one_wraps_the_same_key() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let first = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        let password_key = key_of_password(conn, user, &unlock(PASSWORD, SALT, false))
            .expect("the password wrap opens");
        assert_eq!(session_key(conn, user, &first), Some(password_key));
        let second = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, false)));
        assert_eq!(session_key(conn, user, &second), Some(password_key));
        assert_ne!(first, second);
        let signed_in_without = sign_in(conn, user, None);
        assert_eq!(session_key(conn, user, &signed_in_without), None);
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_first_sign_ins_made_with_the_same_first_salt_share_one_key() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let salt = server_keys().vault_salt(user);
        let first = sign_in(conn, user, Some(unlocked(PASSWORD, salt, true)));
        let second = sign_in(conn, user, Some(unlocked(PASSWORD, salt, true)));
        let one = session_key(conn, user, &first).expect("first key");
        assert_eq!(session_key(conn, user, &second), Some(one));
        assert_ne!(
            server_keys().vault_salt(user),
            server_keys().vault_salt(user + 1)
        );
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_or_foreign_password_wrap_still_signs_in_without_a_session_wrap() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        let foreign = sign_in(conn, user, Some(unlocked(PASSWORD, NEW_SALT, true)));
        assert_eq!(
            session_key(conn, user, &foreign),
            None,
            "another salt: no key"
        );
        conn.execute(
            "UPDATE users SET dek_wrap = 'garbage' WHERE id = ?1",
            params![user],
        )?;
        let damaged = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, false)));
        assert_eq!(session_key(conn, user, &damaged), None);
        let stored: String = conn.query_row(
            "SELECT dek_wrap FROM users WHERE id = ?1",
            params![user],
            |r| r.get(0),
        )?;
        assert_eq!(stored, "garbage");
        assert_eq!(
            wrapped_rows(conn, "sessions"),
            1,
            "only the first sign-in's wrap"
        );
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_and_an_invitation_make_the_key_and_wrap_the_new_session() {
    let (_dir, db) = open();
    db.call(|conn| {
        let token = create_owner_in(
            conn,
            "owner@example.com",
            "phc",
            NOW,
            LIFETIME,
            None,
            Some(&unlocked(PASSWORD, SALT, true)),
        )?
        .expect("the owner is created");
        let owner: i64 = conn.query_row("SELECT id FROM users", [], |r| r.get(0))?;
        let key = key_of_password(conn, owner, &unlock(PASSWORD, SALT, false))
            .expect("the password wrap opens");
        assert_eq!(session_key(conn, owner, &token), Some(key));

        conn.execute(
            "INSERT INTO invitations (email, role, token_hash, created_at, expires_at) \
             VALUES (?1, 'user', 'link', 0, 5000)",
            params![EMAIL],
        )?;
        let accept = Accept {
            hash: "link".to_owned(),
            phc: "phc".to_owned(),
            now: NOW,
            lifetime: LIFETIME,
            presented: None,
            vault: Some(unlocked(NEW_PASSWORD, NEW_SALT, true)),
        };
        let invited_token = accept_in(conn, &accept)?.expect("the invitation is accepted");
        let invited: i64 = conn.query_row(
            "SELECT id FROM users WHERE email = ?1",
            params![EMAIL],
            |r| r.get(0),
        )?;
        let invited_key = key_of_password(conn, invited, &unlock(NEW_PASSWORD, NEW_SALT, false))
            .expect("the invited user's wrap opens");
        assert_eq!(
            session_key(conn, invited, &invited_token),
            Some(invited_key)
        );
        assert_ne!(invited_key, key);
        Ok(())
    })
    .await
    .expect("run");
}

/// A server with one declared header and a value of `user` sealed under `key`.
fn seed_value(conn: &Connection, user: i64, key: &DataKey, generation: i64) -> (i64, i64) {
    conn.execute(
        "INSERT INTO servers (name, slug, upstream_url, created_at) VALUES ('demo', 'demo', ?1, 0)",
        params![URL],
    )
    .expect("server");
    let server = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO server_headers (server_id, name, name_lower, created_at) VALUES (?1, 'X-Key', 'x-key', 0)",
        params![server],
    )
    .expect("header");
    let header = conn.last_insert_rowid();
    let place = ValuePlace {
        user,
        server,
        header: "x-key",
        generation,
        upstream_url: URL,
    };
    let sealed = seal_value(key, &place, b"canary").expect("seal");
    conn.execute(
        "INSERT INTO user_header_values (user_id, header_id, sealed, set_at) VALUES (?1, ?2, ?3, 0)",
        params![user, header, sealed],
    )
    .expect("value");
    (server, header)
}

fn value_opens(conn: &Connection, user: i64, key: &[u8; 32], server: i64) -> bool {
    let generation: i64 = conn
        .query_row(
            "SELECT dek_gen FROM users WHERE id = ?1",
            params![user],
            |r| r.get(0),
        )
        .expect("generation");
    let sealed: Option<String> = conn
        .query_row(
            "SELECT sealed FROM user_header_values WHERE user_id = ?1",
            params![user],
            |r| r.get(0),
        )
        .ok();
    let Some(sealed) = sealed else {
        return false;
    };
    let place = ValuePlace {
        user,
        server,
        header: "x-key",
        generation,
        upstream_url: URL,
    };
    open_value(&DataKey::from_test_bytes(*key), &place, &sealed)
        .is_ok_and(|plain| plain.as_slice() == b"canary")
}

fn change_with(user: i64, session: String, old: Option<Unlock>, new: Unlock) -> Change {
    Change {
        user_id: user,
        email: EMAIL.to_owned(),
        account: token_hash(EMAIL),
        address: "127.0.0.1".to_owned(),
        old_phc: OLD_PHC.to_owned(),
        epoch: 0,
        session: Some(session),
        new_phc: "new-hash".to_owned(),
        now: NOW,
        lifetime: LIFETIME,
        vault: Some(ChangeVault {
            keys: arc_keys(),
            old,
            new,
        }),
    }
}

/// Wrapped rows on a code, an access token and a refresh token of `user`.
fn seed_token_wraps(conn: &Connection, user: i64) {
    conn.execute(
        "INSERT INTO token_families (public_id, user_id, client_id, client_name, auth_epoch, created_at, \
         expires_at) VALUES ('fam_x', ?1, 'c', 'C', 0, 0, 99999)",
        params![user],
    )
    .expect("family");
    let family = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO access_tokens (token_hash, family_id, expires_at, dek_wrap) VALUES ('a', ?1, 99999, 'w')",
        params![family],
    )
    .expect("access");
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, family_id, created_at, expires_at, dek_wrap) \
         VALUES ('r', ?1, 0, 99999, 'w')",
        params![family],
    )
    .expect("refresh");
    conn.execute(
        "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, user_id, combined, client_name, \
         code_challenge, auth_epoch, created_at, expires_at, dek_wrap) \
         VALUES ('c', 'c', 'http://127.0.0.1/cb', ?1, 1, 'C', 'x', 0, 0, 99999, 'w')",
        params![user],
    )
    .expect("code");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_reseals_the_values_under_a_new_key_and_clears_every_old_wrap() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let old_session = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        let old_key = session_key(conn, user, &old_session).expect("old key");
        let (server, _) = seed_value(conn, user, &DataKey::from_test_bytes(old_key), 0);
        seed_token_wraps(conn, user);
        let epoch = epoch_of(conn, user);
        let mut change = change_with(
            user,
            old_session.clone(),
            Some(unlock(PASSWORD, SALT, false)),
            unlock(NEW_PASSWORD, NEW_SALT, true),
        );
        change.epoch = epoch;
        let new_session = change_in(conn, &change)?.expect("the password changes");
        let new_key = key_of_password(conn, user, &unlock(NEW_PASSWORD, NEW_SALT, false))
            .expect("the new password wrap opens");
        assert_ne!(new_key, old_key);
        assert_eq!(session_key(conn, user, &new_session), Some(new_key));
        assert!(
            value_opens(conn, user, &new_key, server),
            "the value moved to the new key"
        );
        assert!(!value_opens(conn, user, &old_key, server));
        assert_eq!(
            key_of_password(conn, user, &unlock(PASSWORD, SALT, false)),
            None
        );
        for table in ["auth_codes", "access_tokens", "refresh_tokens"] {
            assert_eq!(wrapped_rows(conn, table), 0, "{table} keeps no wrap");
        }
        assert_eq!(
            wrapped_rows(conn, "sessions"),
            1,
            "only the fresh session carries one"
        );
        let dropped: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(dropped, 0);
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_with_a_damaged_old_wrap_still_changes_drops_the_values_and_writes_a_row()
{
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let old_session = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        let old_key = session_key(conn, user, &old_session).expect("old key");
        seed_value(conn, user, &DataKey::from_test_bytes(old_key), 0);
        conn.execute(
            "UPDATE users SET dek_wrap = 'garbage' WHERE id = ?1",
            params![user],
        )?;
        let change = change_with(
            user,
            old_session,
            Some(unlock(PASSWORD, SALT, false)),
            unlock(NEW_PASSWORD, NEW_SALT, true),
        );
        let new_session = change_in(conn, &change)?.expect("the change still goes through");
        let rows: i64 =
            conn.query_row("SELECT COUNT(*) FROM user_header_values", [], |r| r.get(0))?;
        assert_eq!(rows, 0);
        let (who, count): (String, i64) = conn.query_row(
            "SELECT user_email, COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!((who.as_str(), count), (EMAIL, 1));
        let new_key = key_of_password(conn, user, &unlock(NEW_PASSWORD, NEW_SALT, false))
            .expect("a new key is made");
        assert_eq!(session_key(conn, user, &new_session), Some(new_key));
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_for_a_user_with_no_key_makes_one_and_writes_no_row() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let old_session = session::insert(conn, user, NOW, LIFETIME)?;
        let change = change_with(
            user,
            old_session,
            Some(unlock(PASSWORD, SALT, true)),
            unlock(NEW_PASSWORD, NEW_SALT, true),
        );
        let token = change_in(conn, &change)?.expect("the change goes through");
        let key = key_of_password(conn, user, &unlock(NEW_PASSWORD, NEW_SALT, false)).expect("key");
        assert_eq!(session_key(conn, user, &token), Some(key));
        let dropped: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(dropped, 0);
        Ok(())
    })
    .await
    .expect("run");
}

fn reset_row(conn: &Connection, user: i64) {
    conn.execute(
        "INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) VALUES (?1, 'link', 0, 5000)",
        params![user],
    )
    .expect("reset");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_deletes_the_values_and_the_wraps_moves_the_generation_and_writes_a_row() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let session = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        let key = session_key(conn, user, &session).expect("key");
        seed_value(conn, user, &DataKey::from_test_bytes(key), 0);
        seed_token_wraps(conn, user);
        reset_row(conn, user);
        let complete = Complete {
            hash: "link".to_owned(),
            phc: "new-hash".to_owned(),
            now: NOW,
        };
        assert!(complete_in(conn, &complete)?);
        let rows: i64 =
            conn.query_row("SELECT COUNT(*) FROM user_header_values", [], |r| r.get(0))?;
        assert_eq!(rows, 0);
        let (generation, wrap, salt): (i64, Option<String>, Option<String>) = conn.query_row(
            "SELECT dek_gen, dek_wrap, dek_salt FROM users WHERE id = ?1",
            params![user],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        assert_eq!((generation, wrap, salt), (1, None, None));
        for table in ["sessions", "auth_codes", "access_tokens", "refresh_tokens"] {
            assert_eq!(wrapped_rows(conn, table), 0, "{table} keeps no wrap");
        }
        let (who, count): (String, i64) = conn.query_row(
            "SELECT user_email, COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!((who.as_str(), count), (EMAIL, 1));
        let mut again = success(user, Some(unlocked(NEW_PASSWORD, NEW_SALT, true)));
        again.phc = "new-hash".to_owned();
        again.epoch = epoch_of(conn, user);
        let next = succeed_in(conn, &again)?.expect("the next sign-in succeeds");
        assert!(
            session_key(conn, user, &next).is_some(),
            "the next sign-in makes a new key"
        );
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_with_no_values_writes_no_activity_row() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        reset_row(conn, user);
        let complete = Complete {
            hash: "link".to_owned(),
            phc: "new-hash".to_owned(),
            now: NOW,
        };
        assert!(complete_in(conn, &complete)?);
        let dropped: i64 = conn.query_row(
            "SELECT COUNT(*) FROM activity WHERE kind = 'values_dropped'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(dropped, 0);
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_all_nulls_the_token_wraps_of_that_user_and_leaves_the_password_wrap() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        seed_token_wraps(conn, user);
        session::revoke_all(conn, user)?;
        for table in ["sessions", "auth_codes", "access_tokens", "refresh_tokens"] {
            assert_eq!(wrapped_rows(conn, table), 0, "{table} keeps no wrap");
        }
        assert!(key_of_password(conn, user, &unlock(PASSWORD, SALT, false)).is_some());
        Ok(())
    })
    .await
    .expect("run");
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_out_takes_the_session_wrap_with_the_row() {
    let (_dir, db) = open();
    db.call(|conn| {
        let user = add_user(conn);
        let token = sign_in(conn, user, Some(unlocked(PASSWORD, SALT, true)));
        assert_eq!(wrapped_rows(conn, "sessions"), 1);
        session::delete(conn, &token)?;
        assert_eq!(wrapped_rows(conn, "sessions"), 0);
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        assert_eq!(rows, 0);
        Ok(())
    })
    .await
    .expect("run");
}
