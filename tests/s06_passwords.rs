mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::ManualClock;
use common::cimd::FakeCimd;
use common::client::{Page, TestClient};
use common::mail::link_with_prefix;
use common::world::{OWNER_EMAIL, PASSWORD, World};
use doorward::{Config, Deps, build};
use futures_util::future::join_all;

const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const WRONG: &str = "definitely wrong";
const SESSION: &str = "__Host-doorward_session";

/// True when `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Asserts that a browser is sent to the sign-in page.
fn assert_sent_to_login(page: &Page, what: &str) {
    assert_eq!(page.status, 303, "{what} must redirect");
    assert_eq!(
        page.location().as_deref(),
        Some("/login"),
        "{what} must go to /login"
    );
}

/// Signs in from `browser` with one X-Forwarded-For header and returns the answer.
async fn login_from(browser: &TestClient, email: &str, password: &str, forwarded: &str) -> Page {
    let form = browser.get("/login").await;
    let csrf = form.csrf().expect("the login form carries a csrf token");
    browser
        .post_with(
            "/login",
            &[
                ("csrf", csrf.as_str()),
                ("email", email),
                ("password", password),
            ],
            &[("X-Forwarded-For", forwarded)],
        )
        .await
}

/// Asks for a password reset for `email` and returns the reset link from the mail.
async fn reset_link(w: &World, email: &str) -> String {
    w.mail.clear();
    let page = w
        .client()
        .submit("/forgot", "/forgot", &[("email", email)])
        .await;
    assert_eq!(page.status, 200, "the reset request must answer 200");
    let message = w
        .mail
        .wait_to(email, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| panic!("no reset mail to {email} arrived within 5 seconds"));
    let prefix = format!("{}/reset/", w.base());
    link_with_prefix(&message.text, &prefix)
        .unwrap_or_else(|| panic!("the reset mail has no link, text: {:?}", message.text))
}

/// The key file of a database: the database path with `.key` appended to its file name.
fn key_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".key");
    PathBuf::from(name)
}

/// The permission bits of a file.
fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|err| panic!("cannot stat {}: {err}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// A config whose database is in `dir` and whose key file is `key`.
fn config_with_key(dir: &Path, key: PathBuf) -> Config {
    Config {
        public_url: "http://127.0.0.1:8717".to_owned(),
        listen: SocketAddr::from(([127, 0, 0, 1], 8717)),
        database: dir.join("doorward.db"),
        key_file: Some(key),
        trusted_proxies: Vec::new(),
        lifetimes: Default::default(),
        limits: Default::default(),
        mail: Default::default(),
    }
}

/// A clock and a client metadata fetcher for a gateway built without the harness.
fn deps() -> Deps {
    Deps {
        clock: ManualClock::new(time::OffsetDateTime::UNIX_EPOCH),
        cimd: FakeCimd::new(),
    }
}

/// Writes a key file of 64 hexadecimal characters in `dir` with the given mode.
fn key_file(dir: &Path, mode: u32) -> PathBuf {
    let path = dir.join("doorward.key");
    std::fs::write(&path, "ab".repeat(32)).expect("write the key file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("set the key file mode");
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn password_is_stored_as_argon2id_only() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let stored = w.stored_bytes();
    assert!(
        contains(&stored, "$argon2id$"),
        "the stored data must hold an Argon2id hash"
    );
    assert!(
        !contains(&stored, PASSWORD),
        "the stored data must not hold the password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn twelve_character_minimum_on_every_form() {
    let w = World::start().await;
    let link = w.invite_link(CAROL, "user").await;
    let invitee = w.client();
    let short = invitee.accept_invite(&link, &"x".repeat(11)).await;
    assert_eq!(
        short.status, 400,
        "an 11 character invitation password must answer 400"
    );
    let long = invitee.accept_invite(&link, &"x".repeat(12)).await;
    assert_eq!(
        long.status, 303,
        "a 12 character invitation password must be accepted"
    );

    let bob = w.user(BOB).await;
    let short = bob.change_password(PASSWORD, &"y".repeat(11)).await;
    assert_eq!(
        short.status, 400,
        "an 11 character new password must answer 400"
    );
    let long = bob.change_password(PASSWORD, &"y".repeat(12)).await;
    assert_eq!(
        long.status, 303,
        "a 12 character new password must be accepted"
    );

    let link = reset_link(&w, BOB).await;
    let anon = w.client();
    let short = anon.reset_password(&link, &"z".repeat(11)).await;
    assert_eq!(
        short.status, 400,
        "an 11 character reset password must answer 400"
    );
    let long = anon.reset_password(&link, &"z".repeat(12)).await;
    assert_eq!(
        long.status, 303,
        "a 12 character reset password must be accepted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn longer_than_256_characters_is_refused() {
    let w = World::start().await;
    let link = w.invite_link(BOB, "user").await;
    let invitee = w.client();
    let too_long = invitee.accept_invite(&link, &"x".repeat(257)).await;
    assert_eq!(
        too_long.status, 400,
        "a 257 character password must be refused"
    );
    let longest = invitee.accept_invite(&link, &"x".repeat(256)).await;
    assert_eq!(
        longest.status, 303,
        "a 256 character password must be accepted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn account_blocks_after_five_wrong_guesses() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let anon = w.client();
    for attempt in 1..=5 {
        let page = anon.login(BOB, WRONG).await;
        assert_eq!(page.status, 401, "wrong guess {attempt} must answer 401");
    }
    let blocked = anon.login(BOB, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the right password must be refused while the account is blocked"
    );
    w.gw.clock
        .advance(time::Duration::minutes(15) + time::Duration::seconds(1));
    let after = anon.login(BOB, PASSWORD).await;
    assert_eq!(
        after.status, 303,
        "the right password must work 15 minutes and 1 second after the last failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_login_resets_the_count() {
    let w = World::start().await;
    let _bob = w.user(BOB).await;
    let anon = w.client();
    for round in 1..=2 {
        for attempt in 1..=4 {
            let page = anon.login(BOB, WRONG).await;
            assert_eq!(
                page.status, 401,
                "round {round}, wrong guess {attempt} must answer 401"
            );
        }
        let right = anon.login(BOB, PASSWORD).await;
        assert_eq!(
            right.status, 303,
            "round {round}, the right password must sign in"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn address_blocks_across_accounts() {
    let w = World::start_with(|c| c.limits.address_failures = 6).await;
    for n in 1..=7 {
        let page = w
            .client()
            .login(&format!("nobody{n}@example.com"), WRONG)
            .await;
        assert_eq!(page.status, 401, "wrong guess {n} must answer 401");
    }
    let blocked = w.client().login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        blocked.status, 429,
        "the owner's right password from a blocked address must be refused"
    );
    w.gw.clock
        .advance(time::Duration::minutes(15) + time::Duration::seconds(1));
    let after = w.client().login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        after.status, 303,
        "the owner's right password must work 15 minutes and 1 second later"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_for_is_ignored_without_a_trusted_proxy() {
    let w = World::start_with(|c| c.limits.address_failures = 6).await;
    for n in 1..=7 {
        let forwarded = format!("203.0.113.{}", 10 + n);
        let page = login_from(
            &w.client(),
            &format!("nobody{n}@example.com"),
            WRONG,
            &forwarded,
        )
        .await;
        assert_eq!(
            page.status, 401,
            "wrong guess {n} must answer 401 while the address is at most 6 failures"
        );
    }
    let blocked = login_from(&w.client(), OWNER_EMAIL, PASSWORD, "203.0.113.50").await;
    assert_eq!(
        blocked.status, 429,
        "a new X-Forwarded-For must not lift the block when no proxy is trusted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_for_counts_behind_a_trusted_proxy() {
    let w = World::start_with(|c| {
        c.trusted_proxies = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        c.limits.address_failures = 6;
    })
    .await;
    for n in 1..=7 {
        let page = login_from(
            &w.client(),
            &format!("nobody{n}@example.com"),
            WRONG,
            "203.0.113.5",
        )
        .await;
        assert_eq!(
            page.status, 401,
            "wrong guess {n} must answer 401 while the address is at most 6 failures"
        );
    }
    let blocked = login_from(&w.client(), OWNER_EMAIL, PASSWORD, "203.0.113.5").await;
    assert_eq!(
        blocked.status, 429,
        "the right password from the blocked client address must be refused"
    );
    let other = login_from(&w.client(), OWNER_EMAIL, PASSWORD, "203.0.113.6").await;
    assert_eq!(
        other.status, 303,
        "the right password from another client address must sign in"
    );
    let chain = login_from(
        &w.client(),
        OWNER_EMAIL,
        PASSWORD,
        "203.0.113.6, 203.0.113.5",
    )
    .await;
    assert_eq!(
        chain.status, 429,
        "the last X-Forwarded-For entry must decide the address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_address_looks_like_a_wrong_password() {
    let w = World::start().await;
    let anon = w.client();
    let unknown = anon.login("nobody@example.com", WRONG).await;
    let wrong = anon.login(OWNER_EMAIL, WRONG).await;
    assert_eq!(unknown.status, 401, "an unknown address must answer 401");
    assert_eq!(wrong.status, 401, "a wrong password must answer 401");
    assert_eq!(
        unknown.error().as_deref(),
        Some("Wrong email or password."),
        "an unknown address must show the wrong-password text"
    );
    assert_eq!(
        wrong.error(),
        unknown.error(),
        "an unknown address and a wrong password must show the same text"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_logins_do_not_starve_the_gateway() {
    let w = World::start_with(|c| c.limits.address_failures = 1000).await;
    let attempts = (0..16).map(|n| {
        let browser = w.client();
        let email = format!("nobody{n}@example.com");
        async move { browser.login(&email, WRONG).await.status }
    });
    let health = w.gw.http.get(w.gw.url("/healthz")).send();
    let (health, statuses) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(1), health),
        join_all(attempts)
    );
    let health = health
        .expect("GET /healthz must answer within 1 second while logins are in flight")
        .expect("the healthz request must succeed");
    assert_eq!(
        health.status().as_u16(),
        200,
        "GET /healthz must answer 200 while logins are in flight"
    );
    assert_eq!(statuses.len(), 16, "all sixteen logins must finish");
    for (n, status) in statuses.iter().enumerate() {
        assert_eq!(
            *status, 401,
            "login {n} for an unknown address must answer 401"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn login_issues_a_new_session_id() {
    let w = World::start().await;
    let browser = w.client();
    browser.set_cookie(SESSION, "attacker-chosen");
    let login = browser.login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(login.status, 303, "the owner must be able to sign in");
    let issued = browser
        .cookie(SESSION)
        .expect("a successful sign-in must set the session cookie");
    assert_ne!(
        issued, "attacker-chosen",
        "a sign-in must replace a session id planted by the browser"
    );
    let other = w.client();
    other.set_cookie(SESSION, "attacker-chosen");
    assert_sent_to_login(
        &other.get("/account").await,
        "a browser holding the planted session id",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_cookie_is_host_only_and_protected() {
    let w = World::start().await;
    let attributes = w
        .owner
        .cookie_attributes(SESSION)
        .expect("the owner's session cookie must carry attributes");
    let parts: Vec<&str> = attributes.split(';').map(str::trim).collect();
    for wanted in ["secure", "httponly", "samesite=lax", "path=/"] {
        assert!(
            parts.contains(&wanted),
            "the session cookie must carry {wanted}, got {attributes}"
        );
    }
    assert!(
        !parts.iter().any(|part| part.starts_with("domain")),
        "the session cookie must be host-only, got {attributes}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_ends_after_twelve_hours() {
    let w = World::start().await;
    assert_eq!(
        w.owner.get("/account").await.status,
        200,
        "the owner must be signed in before the 12 hours pass"
    );
    w.gw.clock
        .advance(time::Duration::hours(12) + time::Duration::seconds(1));
    assert_sent_to_login(
        &w.owner.get("/account").await,
        "the owner's session after 12 hours and 1 second",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn login_needs_csrf_and_origin() {
    let w = World::start().await;
    let anon = w.client();
    let fields = [("email", OWNER_EMAIL), ("password", PASSWORD)];

    let no_csrf = anon.post("/login", &fields).await;
    assert_eq!(no_csrf.status, 403, "a login without csrf must answer 403");
    assert_eq!(
        no_csrf.kind().as_deref(),
        Some("forbidden"),
        "a login without csrf must show the forbidden page"
    );

    let csrf = anon
        .get("/login")
        .await
        .csrf()
        .expect("the login form carries a csrf token");
    let with_csrf = [
        ("csrf", csrf.as_str()),
        ("email", OWNER_EMAIL),
        ("password", PASSWORD),
    ];
    let foreign = anon
        .post_with(
            "/login",
            &with_csrf,
            &[("Origin", "https://evil.example.com")],
        )
        .await;
    assert_eq!(foreign.status, 403, "a foreign origin must answer 403");
    assert_eq!(
        foreign.kind().as_deref(),
        Some("forbidden"),
        "a foreign origin must show the forbidden page"
    );

    let no_origin = anon
        .post_with("/login", &with_csrf, &[("Origin", "")])
        .await;
    assert_eq!(no_origin.status, 403, "a missing origin must answer 403");
    assert_eq!(
        no_origin.kind().as_deref(),
        Some("forbidden"),
        "a missing origin must show the forbidden page"
    );

    assert!(
        anon.cookie(SESSION).is_none(),
        "a refused login must not set a session cookie"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_ends_the_session() {
    let w = World::start().await;
    let browser = w.client();
    assert_eq!(
        browser.login(OWNER_EMAIL, PASSWORD).await.status,
        303,
        "the owner must be able to sign in"
    );
    let old = browser
        .cookie(SESSION)
        .expect("a successful sign-in must set the session cookie");
    let replay = w.client();
    replay.set_cookie(SESSION, &old);
    assert_eq!(
        replay.get("/account").await.status,
        200,
        "the captured session cookie must be live before the logout"
    );
    assert_sent_to_login(&browser.logout().await, "logout");
    assert_sent_to_login(
        &replay.get("/account").await,
        "a browser replaying the session cookie after logout",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn database_and_key_files_are_private() {
    let w = World::start().await;
    let database = w.gw.db_path();
    let key = key_path(&database);
    assert!(
        database.exists(),
        "the database file must exist at {}",
        database.display()
    );
    assert!(key.exists(), "the key file must exist at {}", key.display());
    assert_eq!(
        mode_of(&database),
        0o600,
        "the database file must have mode 0600"
    );
    assert_eq!(mode_of(&key), 0o600, "the key file must have mode 0600");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_readable_key_file_refuses_the_start() {
    let refused_dir = tempfile::tempdir().expect("temp dir");
    let readable = key_file(refused_dir.path(), 0o644);
    let refused = build(config_with_key(refused_dir.path(), readable), deps()).await;
    assert!(
        refused.is_err(),
        "a key file that others can read must refuse the start"
    );

    let private_dir = tempfile::tempdir().expect("temp dir");
    let private = key_file(private_dir.path(), 0o600);
    let started = build(config_with_key(private_dir.path(), private), deps()).await;
    assert!(
        started.is_ok(),
        "a key file only the owner can read must let the gateway start"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_id_is_not_stored() {
    let w = World::start().await;
    let value = w
        .owner
        .cookie(SESSION)
        .expect("the owner must hold a session cookie");
    assert!(!value.is_empty(), "the session cookie must have a value");
    assert!(
        !contains(&w.stored_bytes(), &value),
        "the session cookie value must not be stored"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_guesses_cannot_outrun_the_block() {
    let w = World::start_with(|c| c.limits.address_failures = 1000).await;
    let guesses = (0..20).map(|_| {
        let browser = w.client();
        async move { browser.login(OWNER_EMAIL, WRONG).await.status }
    });
    let statuses = join_all(guesses).await;
    assert_eq!(
        statuses.len(),
        20,
        "all twenty parallel guesses must finish"
    );
    for (n, status) in statuses.iter().enumerate() {
        assert!(
            *status == 401 || *status == 429,
            "parallel guess {n} must answer 401 or 429, got {status}"
        );
    }
    let unauthorized = statuses.iter().filter(|status| **status == 401).count();
    let blocked = statuses.iter().filter(|status| **status == 429).count();
    assert_eq!(
        unauthorized, 5,
        "exactly five parallel guesses must answer 401, statuses were {statuses:?}"
    );
    assert_eq!(
        blocked, 15,
        "exactly fifteen parallel guesses must answer 429, statuses were {statuses:?}"
    );
    let right = w.client().login(OWNER_EMAIL, PASSWORD).await;
    assert_eq!(
        right.status, 429,
        "the owner's right password must be refused once the account is blocked"
    );
}
