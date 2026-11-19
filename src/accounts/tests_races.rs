//! Flows in flight while a reset, a password change or a disable lands: sign-in, password change
//! and the reset link that a change or a disable must end.

use rusqlite::params;
use tempfile::TempDir;

use crate::crypto::token_hash;
use crate::db::Db;

use super::password::{Change, change_in};
use super::session;
use super::throttle::{self, Attempt, Reserve, Success};

const NOW: i64 = 1_000;
const LIFETIME: i64 = 3_600;
const BLOCK_SECONDS: i64 = 900;
const EMAIL: &str = "bob@example.com";
const OLD_PHC: &str = "old-hash";
const OTHER_PHC: &str = "other-hash";
const NEW_PHC: &str = "new-hash";

/// A migrated database with one enabled user holding OLD_PHC. The TempDir keeps the file alive.
async fn seeded_db() -> (TempDir, Db, i64) {
    let dir = tempfile::tempdir().expect("dir");
    let db = Db::open(&dir.path().join("doorward.db")).expect("open");
    let user_id = db
        .call(|conn| {
            conn.execute(
                "INSERT INTO users (email, password_hash, role, created_at) VALUES (?1, ?2, 'user', 0)",
                params![EMAIL, OLD_PHC],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .expect("seed");
    (dir, db, user_id)
}

/// Reserves one attempt for EMAIL and returns its failure id, the stored hash and its epoch.
async fn reserve_counted(db: &Db) -> (i64, String, i64) {
    let input = Reserve {
        account: token_hash(EMAIL),
        address: "127.0.0.1".to_owned(),
        email: EMAIL.to_owned(),
        now: NOW,
        block_seconds: BLOCK_SECONDS,
        account_failures: 5,
        address_failures: 5,
    };
    match throttle::reserve(db, input).await.expect("reserve") {
        Attempt::Counted {
            failure_id,
            user_id: Some(_),
            phc: Some(phc),
            epoch: Some(epoch),
        } => (failure_id, phc, epoch),
        _ => panic!("the reservation must count an enabled account"),
    }
}

fn success_for(failure_id: i64, user_id: i64, phc: String, epoch: i64) -> Success {
    Success {
        account: token_hash(EMAIL),
        failure_id,
        user_id,
        email: EMAIL.to_owned(),
        previous: None,
        now: NOW,
        lifetime: LIFETIME,
        phc,
        epoch,
    }
}

fn change_for(failure_id: i64, user_id: i64, epoch: i64, session: Option<String>) -> Change {
    Change {
        user_id,
        email: EMAIL.to_owned(),
        account: token_hash(EMAIL),
        failure_id,
        old_phc: OLD_PHC.to_owned(),
        epoch,
        session,
        new_phc: NEW_PHC.to_owned(),
        now: NOW,
        lifetime: LIFETIME,
    }
}

/// Runs one statement that takes the user id as its only parameter.
async fn exec_for_user(db: &Db, user_id: i64, sql: &'static str) {
    db.call(move |conn| conn.execute(sql, params![user_id]).map(|_| ()))
        .await
        .expect("statement");
}

/// Sets the stored hash and ends every session, as a reset does.
async fn reset_password_elsewhere(db: &Db, user_id: i64) {
    db.call(move |conn| {
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![OTHER_PHC, user_id],
        )?;
        session::revoke_all(conn, user_id)
    })
    .await
    .expect("reset");
}

async fn seed_session(db: &Db, user_id: i64) -> String {
    db.call(move |conn| session::insert(conn, user_id, NOW, LIFETIME))
        .await
        .expect("session")
}

async fn session_count(db: &Db, user_id: i64) -> i64 {
    db.call(move |conn| {
        conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
    })
    .await
    .expect("count")
}

async fn stored_hash(db: &Db, user_id: i64) -> String {
    db.call(move |conn| {
        conn.query_row(
            "SELECT password_hash FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
    })
    .await
    .expect("hash")
}

async fn seed_reset(db: &Db, user_id: i64) {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO password_resets (user_id, token_hash, created_at, expires_at) \
             VALUES (?1, 'reset-hash', ?2, ?3)",
            params![user_id, NOW, NOW + LIFETIME],
        )
        .map(|_| ())
    })
    .await
    .expect("reset row");
}

/// Sets the stored hash and nothing else.
async fn set_password_hash(db: &Db, user_id: i64, phc: &'static str) {
    db.call(move |conn| {
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![phc, user_id],
        )
        .map(|_| ())
    })
    .await
    .expect("hash");
}

async fn reset_count(db: &Db, user_id: i64) -> i64 {
    db.call(move |conn| {
        conn.query_row(
            "SELECT COUNT(*) FROM password_resets WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
    })
    .await
    .expect("count")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_with_nothing_in_between_signs_in() {
    let (_dir, db, user_id) = seeded_db().await;
    let (failure_id, phc, epoch) = reserve_counted(&db).await;
    let outcome = throttle::succeed(&db, success_for(failure_id, user_id, phc, epoch))
        .await
        .expect("succeed");
    let token = outcome.expect("a token when nothing changed");
    assert!(
        session::find(&db, &token, NOW)
            .await
            .expect("find")
            .is_some(),
        "the new session must resolve"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_in_flight_is_refused_after_a_reset_revokes_sessions() {
    let (_dir, db, user_id) = seeded_db().await;
    let (failure_id, phc, epoch) = reserve_counted(&db).await;
    reset_password_elsewhere(&db, user_id).await;
    let outcome = throttle::succeed(&db, success_for(failure_id, user_id, phc, epoch))
        .await
        .expect("succeed");
    assert!(
        outcome.is_none(),
        "a reset in flight must refuse the sign-in"
    );
    assert_eq!(session_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_in_flight_is_refused_after_the_account_is_disabled() {
    let (_dir, db, user_id) = seeded_db().await;
    let (failure_id, phc, epoch) = reserve_counted(&db).await;
    exec_for_user(&db, user_id, "UPDATE users SET disabled = 1 WHERE id = ?1").await;
    let outcome = throttle::succeed(&db, success_for(failure_id, user_id, phc, epoch))
        .await
        .expect("succeed");
    assert!(
        outcome.is_none(),
        "a disable in flight must refuse the sign-in"
    );
    assert_eq!(session_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_in_flight_is_refused_after_a_disable_and_an_enable() {
    let (_dir, db, user_id) = seeded_db().await;
    let (failure_id, phc, epoch) = reserve_counted(&db).await;
    exec_for_user(&db, user_id, "UPDATE users SET disabled = 1 WHERE id = ?1").await;
    db.call(move |conn| session::revoke_all(conn, user_id))
        .await
        .expect("revoke");
    exec_for_user(&db, user_id, "UPDATE users SET disabled = 0 WHERE id = ?1").await;
    let outcome = throttle::succeed(&db, success_for(failure_id, user_id, phc, epoch))
        .await
        .expect("succeed");
    assert!(outcome.is_none(), "an epoch change must refuse the sign-in");
    assert_eq!(session_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_in_flight_does_not_overwrite_a_reset() {
    let (_dir, db, user_id) = seeded_db().await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    reset_password_elsewhere(&db, user_id).await;
    let change = change_for(failure_id, user_id, epoch, Some(cookie));
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    assert!(
        outcome.is_none(),
        "a reset in flight must refuse the change"
    );
    assert_eq!(stored_hash(&db, user_id).await, OTHER_PHC);
    assert_eq!(session_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_in_flight_is_refused_after_the_account_is_disabled() {
    let (_dir, db, user_id) = seeded_db().await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    exec_for_user(&db, user_id, "UPDATE users SET disabled = 1 WHERE id = ?1").await;
    let change = change_for(failure_id, user_id, epoch, Some(cookie));
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    assert!(
        outcome.is_none(),
        "a disable in flight must refuse the change"
    );
    assert_eq!(stored_hash(&db, user_id).await, OLD_PHC);
    assert_eq!(session_count(&db, user_id).await, 1, "nothing may change");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_with_nothing_in_between_ends_the_old_sessions() {
    let (_dir, db, user_id) = seeded_db().await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    let change = change_for(failure_id, user_id, epoch, Some(cookie.clone()));
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    let token = outcome.expect("a token when nothing changed");
    assert_eq!(stored_hash(&db, user_id).await, NEW_PHC);
    assert!(
        session::find(&db, &cookie, NOW)
            .await
            .expect("find")
            .is_none(),
        "the old session must end"
    );
    assert!(
        session::find(&db, &token, NOW)
            .await
            .expect("find")
            .is_some(),
        "the new session must resolve"
    );
    assert_eq!(session_count(&db, user_id).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_ends_the_unused_reset_link() {
    let (_dir, db, user_id) = seeded_db().await;
    seed_reset(&db, user_id).await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    assert_eq!(reset_count(&db, user_id).await, 1);
    let change = change_for(failure_id, user_id, epoch, Some(cookie));
    db.call(move |conn| change_in(conn, &change))
        .await
        .expect("change")
        .expect("a token when nothing changed");
    assert_eq!(reset_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disable_ends_the_unused_reset_link_and_enabling_does_not_bring_it_back() {
    let (_dir, db, user_id) = seeded_db().await;
    seed_reset(&db, user_id).await;
    assert_eq!(reset_count(&db, user_id).await, 1);
    // The admin disable path (admin/users.rs change_in) sets disabled and then calls revoke_all.
    exec_for_user(&db, user_id, "UPDATE users SET disabled = 1 WHERE id = ?1").await;
    db.call(move |conn| session::revoke_all(conn, user_id))
        .await
        .expect("revoke");
    assert_eq!(reset_count(&db, user_id).await, 0);
    exec_for_user(&db, user_id, "UPDATE users SET disabled = 0 WHERE id = ?1").await;
    assert_eq!(reset_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_in_flight_is_refused_after_the_hash_alone_changes() {
    let (_dir, db, user_id) = seeded_db().await;
    let (failure_id, phc, epoch) = reserve_counted(&db).await;
    set_password_hash(&db, user_id, OTHER_PHC).await;
    let outcome = throttle::succeed(&db, success_for(failure_id, user_id, phc, epoch))
        .await
        .expect("succeed");
    assert!(
        outcome.is_none(),
        "a changed hash alone must refuse the sign-in"
    );
    assert_eq!(session_count(&db, user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_is_refused_after_the_hash_alone_changes() {
    let (_dir, db, user_id) = seeded_db().await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    set_password_hash(&db, user_id, OTHER_PHC).await;
    let change = change_for(failure_id, user_id, epoch, Some(cookie));
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    assert!(
        outcome.is_none(),
        "a changed hash alone must refuse the change"
    );
    assert_eq!(stored_hash(&db, user_id).await, OTHER_PHC);
    assert_eq!(
        session_count(&db, user_id).await,
        1,
        "the session must stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_is_refused_after_the_epoch_alone_changes() {
    let (_dir, db, user_id) = seeded_db().await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    exec_for_user(
        &db,
        user_id,
        "UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?1",
    )
    .await;
    let change = change_for(failure_id, user_id, epoch, Some(cookie));
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    assert!(
        outcome.is_none(),
        "a changed epoch alone must refuse the change"
    );
    assert_eq!(stored_hash(&db, user_id).await, OLD_PHC);
    assert_eq!(
        session_count(&db, user_id).await,
        1,
        "the session must stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_is_refused_when_only_the_presented_session_row_is_gone() {
    let (_dir, db, user_id) = seeded_db().await;
    let cookie = seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    exec_for_user(&db, user_id, "DELETE FROM sessions WHERE user_id = ?1").await;
    assert_eq!(session_count(&db, user_id).await, 0);
    let change = change_for(failure_id, user_id, epoch, Some(cookie));
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    assert!(
        outcome.is_none(),
        "a missing session row must refuse the change"
    );
    assert_eq!(stored_hash(&db, user_id).await, OLD_PHC);
    assert_eq!(
        session_count(&db, user_id).await,
        0,
        "nothing may be inserted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_is_refused_without_a_presented_session() {
    let (_dir, db, user_id) = seeded_db().await;
    seed_session(&db, user_id).await;
    let (failure_id, _phc, epoch) = reserve_counted(&db).await;
    let change = change_for(failure_id, user_id, epoch, None);
    let outcome = db
        .call(move |conn| change_in(conn, &change))
        .await
        .expect("change");
    assert!(
        outcome.is_none(),
        "no presented session must refuse the change"
    );
    assert_eq!(stored_hash(&db, user_id).await, OLD_PHC);
    assert_eq!(
        session_count(&db, user_id).await,
        1,
        "the session must stay"
    );
}
