//! Statement 51: a failure inside the gateway writes one line to standard error, with no secret.
//! The tests run the real binary; the database fails by a held write lock or a renamed table.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::admin::{self, ServerSpec};
use common::binary::{Run, free_port, write_file};
use common::client::{OAuthApp, TestClient, pkce};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, Generation, Mode, UpstreamOptions};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct horse battery staple";
const SESSION_COOKIE: &str = "__Host-doorward_session";
const CLIENT_NAME: &str = "Probe Client";
const LOOPBACK_CALLBACK: &str = "http://127.0.0.1:8765/callback";
/// A metadata address on the reserved .invalid domain: its fetch fails without any network.
const METADATA_ID: &str = "https://client.example.invalid/dw-probe/metadata.json";
/// The busy timeout the gateway waits for a lock (`src/db.rs`).
const BUSY: Duration = Duration::from_secs(5);

/// The real binary on a free loopback port, with its database in a temp dir.
struct Spawned {
    run: Run,
    base: String,
    db: PathBuf,
    _dir: TempDir,
}

impl Spawned {
    /// Starts the binary and waits until it answers on `/healthz`.
    fn start() -> Spawned {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let db = dir.path().join("doorward.db");
        let text = format!(
            "public_url = \"http://127.0.0.1:{port}\"\nlisten = \"127.0.0.1:{port}\"\ndatabase = '{}'\n",
            db.display()
        );
        let config = write_file(dir.path(), "doorward.toml", &text);
        let config = config.display().to_string();
        let mut run = Run::spawn(&["--config", config.as_str()], &[]);
        run.wait_until_healthy(port);
        Spawned {
            run,
            base: format!("http://127.0.0.1:{port}"),
            db,
            _dir: dir,
        }
    }

    /// Every line written to standard error so far.
    fn lines(&self) -> Vec<String> {
        self.run.stderr().lines().map(str::to_owned).collect()
    }

    /// The lines written after the first `before` lines.
    fn lines_since(&self, before: usize) -> Vec<String> {
        self.lines().into_iter().skip(before).collect()
    }

    /// Sets up the owner with the setup code the binary printed; returns the owner's browser.
    async fn owner(&self) -> TestClient {
        let code = self
            .lines()
            .iter()
            .find_map(|line| line.strip_prefix("doorward setup code: "))
            .map(str::to_owned)
            .expect("the binary prints a setup code while no owner exists");
        let browser = TestClient::new(&self.base);
        let page = browser.setup_owner(&code, EMAIL, PASSWORD).await;
        assert_eq!(
            page.status, 303,
            "setup must make the owner and sign them in"
        );
        browser
    }
}

/// A write lock on the database, held in BEGIN EXCLUSIVE until `release`. Writers wait out the
/// gateway's busy timeout and fail. In WAL mode readers are not stopped by it.
struct WriteLock(Connection);

impl WriteLock {
    fn take(db: &Path) -> WriteLock {
        let conn = Connection::open(db).expect("open the database");
        conn.busy_timeout(BUSY).expect("set the busy timeout");
        conn.execute_batch("BEGIN EXCLUSIVE;")
            .expect("take the write lock");
        WriteLock(conn)
    }

    /// Rolls the lock back; the connection closes with the value.
    fn release(self) {
        self.0
            .execute_batch("ROLLBACK")
            .expect("roll back the lock");
    }
}

/// Renames `table` out of its name, so that a read of it fails with "no such table". A lock
/// does not stop readers in WAL mode, so the failing read is made by the schema instead.
fn hide_table(db: &Path, table: &str) {
    rename_table(db, table, &format!("{table}_hidden"));
}

/// Renames `table` back, undoing `hide_table`.
fn show_table(db: &Path, table: &str) {
    rename_table(db, &format!("{table}_hidden"), table);
}

fn rename_table(db: &Path, from: &str, to: &str) {
    let conn = Connection::open(db).expect("open the database");
    conn.busy_timeout(BUSY).expect("set the busy timeout");
    conn.execute_batch(&format!("ALTER TABLE {from} RENAME TO {to};"))
        .expect("rename the table");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_sign_in_writes_one_line() {
    let gateway = Spawned::start();
    gateway.owner().await;
    let browser = TestClient::new(&gateway.base);
    let form = browser.get("/login").await;
    let csrf = form.csrf().expect("the sign-in form carries a csrf field");
    let before = gateway.lines().len();
    let lock = WriteLock::take(&gateway.db);
    let page = browser
        .post(
            "/login",
            &[
                ("csrf", csrf.as_str()),
                ("req", ""),
                ("email", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    lock.release();
    assert_eq!(
        page.status, 500,
        "a locked database must answer a sign-in with 500"
    );
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a failed sign-in must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: sign-in failed: "),
        "the line must start with the failure label; line: {}",
        added[0]
    );
    assert!(
        !added[0].contains(PASSWORD) && !added[0].contains(EMAIL),
        "the line must not name the password or the email; line: {}",
        added[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_session_lookup_writes_one_line() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let token = owner
        .cookie(SESSION_COOKIE)
        .expect("setup signs the owner in");
    let before = gateway.lines().len();
    hide_table(&gateway.db, "sessions");
    let page = owner.get("/account").await;
    show_table(&gateway.db, "sessions");
    assert_eq!(
        page.status, 303,
        "a failed session lookup makes the request anonymous, so /account goes to sign-in"
    );
    assert_eq!(page.location().as_deref(), Some("/login"));
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a failed session lookup must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: session lookup failed: "),
        "the line must start with the failure label; line: {}",
        added[0]
    );
    assert!(
        !added[0].contains(&token),
        "the line must not carry the session token; line: {}",
        added[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_error_in_the_bearer_check_answers_503() {
    let gateway = Spawned::start();
    let browser = TestClient::new(&gateway.base);
    let token = format!("dw_at_{}", pkce().challenge);
    let bearer = format!("Bearer {token}");
    let before = gateway.lines().len();
    hide_table(&gateway.db, "access_tokens");
    let page = browser
        .post_with("/demo", &[], &[("authorization", bearer.as_str())])
        .await;
    show_table(&gateway.db, "access_tokens");
    assert_eq!(
        page.status, 503,
        "a database error in the bearer check must answer 503, not 401"
    );
    assert_eq!(page.header("retry-after").as_deref(), Some("1"));
    assert!(
        page.headers_all("www-authenticate").is_empty(),
        "a 503 must carry no WWW-Authenticate header"
    );
    assert!(page.body.is_empty(), "a 503 must have an empty body");
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a bearer check that cannot read must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: bearer check failed: "),
        "the line must start with the failure label; line: {}",
        added[0]
    );
    assert!(
        !added[0].contains(&token),
        "the line must not carry the token; line: {}",
        added[0]
    );
    let again = browser
        .post_with("/demo", &[], &[("authorization", bearer.as_str())])
        .await;
    assert_eq!(
        again.status, 401,
        "once the database answers, an unknown token is 401 again"
    );
    assert!(!again.headers_all("www-authenticate").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_metadata_fetch_writes_one_line() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let app = OAuthApp {
        client_id: METADATA_ID.to_owned(),
        redirect_uri: LOOPBACK_CALLBACK.to_owned(),
    };
    let authorized = owner
        .authorize(
            &app,
            &format!("{}/mcp", gateway.base),
            &pkce(),
            "probe-state",
        )
        .await;
    assert_eq!(
        authorized.status, 303,
        "the authorize step must go on to consent"
    );
    let before = gateway.lines().len();
    let consent = owner.follow(&authorized).await;
    assert_eq!(
        (consent.status, consent.kind().as_deref()),
        (400, Some("error")),
        "a metadata document that cannot be fetched shows the error page"
    );
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a failed metadata fetch must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: client metadata for client.example.invalid failed: "),
        "the line must name the host of the address and nothing after it; line: {}",
        added[0]
    );
    assert!(
        !added[0].contains("dw-probe") && !added[0].contains('?'),
        "the line must not carry the path or the query; line: {}",
        added[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_code_writes_one_line_and_an_unknown_code_writes_none() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let resource = format!("{}/mcp", gateway.base);
    let registered = owner.register(CLIENT_NAME, &[LOOPBACK_CALLBACK]).await;
    assert_eq!(registered.status, 201, "the probe client must register");
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: LOOPBACK_CALLBACK.to_owned(),
    };
    let real = pkce();
    let authorized = owner.authorize(&app, &resource, &real, "probe-state").await;
    let req = authorized
        .query("req")
        .expect("a signed-in owner goes to consent with a request id");
    let granted = owner.consent(&req, "approve").await;
    let code = granted.query("code").expect("approval answers with a code");
    let wrong = pkce().verifier;

    let before = gateway.lines().len();
    let refused = owner.token_code(&app, &code, &wrong, Some(&resource)).await;
    assert_eq!(refused.status, 400, "a wrong verifier is refused");
    assert_eq!(
        refused.json().expect("a JSON answer")["error"],
        "invalid_grant",
        "a wrong verifier is an invalid_grant"
    );
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a refused code must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    let prefix = "doorward: token refused: ";
    assert!(
        added[0].starts_with(prefix) && added[0].len() > prefix.len(),
        "the line must start with the refusal label and name a reason; line: {}",
        added[0]
    );
    for secret in [code.as_str(), wrong.as_str(), real.verifier.as_str()] {
        assert!(
            !added[0].contains(secret),
            "the line must not carry the code or a verifier; line: {}",
            added[0]
        );
    }

    let before = gateway.lines().len();
    let stranger = format!("dw_ac_{}", pkce().challenge);
    let unknown = owner
        .token_code(&app, &stranger, &real.verifier, Some(&resource))
        .await;
    assert_eq!(unknown.status, 400, "an unknown code is refused");
    assert_eq!(
        unknown.json().expect("a JSON answer")["error"],
        "invalid_grant",
        "an unknown code is an invalid_grant"
    );
    assert!(
        gateway.lines_since(before).is_empty(),
        "a code that matches no row must write nothing; stderr:\n{:?}",
        gateway.lines()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_upstream_writes_one_line() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let mut upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let page = admin::refresh_tools(&owner, &id).await;
    assert_eq!(
        page.status, 303,
        "the tool list of demo must be fetched while its upstream runs"
    );
    let owner_id = admin::user_id(&owner, EMAIL)
        .await
        .expect("the owner must be listed on the users page");
    let page = admin::assign(&owner, &owner_id, &[id.as_str()]).await;
    assert_eq!(page.status, 303, "the owner must be assigned to demo");
    upstream.shutdown().await;

    let registered = owner.register(CLIENT_NAME, &[LOOPBACK_CALLBACK]).await;
    assert_eq!(registered.status, 201, "the probe client must register");
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: LOOPBACK_CALLBACK.to_owned(),
    };
    let resource = format!("{}/demo", gateway.base);
    let tokens = owner.connect(&app, &resource).await;
    let mcp = McpClient::stateless(&resource, Some(&tokens.access_token));

    let before = gateway.lines().len();
    let reply = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(reply.status, 502, "an unreachable upstream must answer 502");
    assert_eq!(
        gateway.lines_since(before),
        vec!["doorward: upstream demo failed: no connection".to_string()],
        "one tool call to an unreachable upstream must write exactly that one line"
    );
}

/// The phrase of a server whose stored secret no key opens.
const SECRET_PHRASE: &str = "the stored secret cannot be opened";

/// Replaces the stored secret of server `id` by text that no key opens, as a restored database with
/// a lost key file would hold.
fn break_secret(db: &Path, id: i64) {
    let conn = Connection::open(db).expect("open the database");
    conn.busy_timeout(BUSY).expect("set the busy timeout");
    conn.execute(
        "UPDATE servers SET secret_header_value = 'not a sealed value' WHERE id = ?1",
        [id],
    )
    .expect("replace the stored secret");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_secret_writes_one_line_and_blames_no_upstream() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let secret = "s3cret-value";
    let upstream = FakeUpstream::start(UpstreamOptions {
        require_header: Some(("x-upstream-secret".to_owned(), secret.to_owned())),
        ..UpstreamOptions::default()
    })
    .await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: Some(("x-upstream-secret", secret)),
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let page = admin::refresh_tools(&owner, &id).await;
    assert_eq!(
        page.status, 303,
        "the tool list of demo must be fetched while its secret is intact"
    );
    let owner_id = admin::user_id(&owner, EMAIL)
        .await
        .expect("the owner must be listed on the users page");
    let page = admin::assign(&owner, &owner_id, &[id.as_str()]).await;
    assert_eq!(page.status, 303, "the owner must be assigned to demo");
    let server_id: i64 = id.parse().expect("a numeric server id");
    break_secret(&gateway.db, server_id);

    let registered = owner.register(CLIENT_NAME, &[LOOPBACK_CALLBACK]).await;
    assert_eq!(registered.status, 201, "the probe client must register");
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: LOOPBACK_CALLBACK.to_owned(),
    };
    let slug_resource = format!("{}/demo", gateway.base);
    let combined_resource = format!("{}/mcp", gateway.base);
    let slug_tokens = owner.connect(&app, &slug_resource).await;
    let combined_tokens = owner.connect(&app, &combined_resource).await;
    let line = format!("doorward: server demo failed: {SECRET_PHRASE}");

    let before = gateway.lines().len();
    let slug = McpClient::stateless(&slug_resource, Some(&slug_tokens.access_token));
    let reply = slug.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(
        reply.status, 502,
        "an unreadable secret must answer 502 on /demo"
    );
    assert_eq!(
        gateway.lines_since(before),
        vec![line.clone()],
        "a tool call on /demo with an unreadable secret must write exactly that one line"
    );
    let rows = admin::activity_with_details(&owner, None, None).await;
    let calls: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call" && row.server == "demo" && row.tool == "echo")
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "a tool call on /demo with an unreadable secret must leave one activity row, rows were {rows:?}"
    );
    assert_eq!(
        calls[0].0.outcome, "unavailable",
        "the row of that call must be unavailable"
    );
    assert_eq!(
        calls[0].1, SECRET_PHRASE,
        "the row of that call must carry the phrase of the cause as its detail"
    );

    let before = gateway.lines().len();
    let combined = McpClient::stateless(&combined_resource, Some(&combined_tokens.access_token));
    let reply = combined
        .call_tool("demo__echo", json!({"text": "hi"}))
        .await;
    assert_eq!(
        reply.status, 502,
        "an unreadable secret must answer 502 on /mcp"
    );
    assert_eq!(
        gateway.lines_since(before),
        vec![line],
        "a tool call on /mcp with an unreadable secret must write exactly that one line"
    );

    let conn = Connection::open(&gateway.db).expect("open the database");
    let refresh_error: Option<String> = conn
        .query_row(
            "SELECT catalog_error FROM servers WHERE id = ?1",
            [server_id],
            |row| row.get(0),
        )
        .expect("read the stored refresh error");
    assert!(
        !refresh_error.unwrap_or_default().contains("did not answer"),
        "a cause on the gateway's side must not be stored as the upstream did not answer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_stored_hash_writes_one_line() {
    let gateway = Spawned::start();
    gateway.owner().await;
    let conn = Connection::open(&gateway.db).expect("open the database");
    conn.execute(
        "UPDATE users SET password_hash = 'not a hash' WHERE email = ?1",
        [EMAIL],
    )
    .expect("replace the stored hash");
    let browser = TestClient::new(&gateway.base);
    let form = browser.get("/login").await;
    let csrf = form.csrf().expect("the sign-in form carries a csrf field");
    let before = gateway.lines().len();
    let page = browser
        .post(
            "/login",
            &[
                ("csrf", csrf.as_str()),
                ("req", ""),
                ("email", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(
        page.status, 401,
        "a stored hash that cannot be read must refuse the sign-in as a wrong password"
    );
    assert_eq!(
        page.error().as_deref(),
        Some("Wrong email or password."),
        "the sign-in answer must be the usual refusal"
    );
    assert_eq!(
        gateway.lines_since(before),
        vec!["doorward: password check failed: the stored hash cannot be read".to_string()],
        "a stored hash that cannot be read must write exactly that one line, without the email"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mail_settings_read_failure_writes_one_line() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let csrf = owner
        .get("/admin/invitations")
        .await
        .csrf()
        .expect("the invitations page carries a csrf token");
    let before = gateway.lines().len();
    hide_table(&gateway.db, "settings");
    let page = owner
        .post(
            "/admin/invitations",
            &[
                ("csrf", csrf.as_str()),
                ("email", "recipient@example.com"),
                ("role", "user"),
            ],
        )
        .await;
    show_table(&gateway.db, "settings");
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a mail settings read that fails must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: mail settings failed: "),
        "the line must name the mail settings; line: {}",
        added[0]
    );
    assert_eq!(
        page.status, 200,
        "the invitation that could not be mailed answers with the link page, as before"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mail_failure_record_that_cannot_be_written_writes_one_line() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let closed = free_port();
    let page = admin::mail_smtp(
        &owner,
        "gateway@example.com",
        "127.0.0.1",
        closed,
        "mailer",
        "mail-password",
        "off",
    )
    .await;
    assert_eq!(page.status, 303, "the mail settings must be saved");
    let csrf = owner
        .get("/admin/mail")
        .await
        .csrf()
        .expect("the mail page carries a csrf token");
    let before = gateway.lines().len();
    hide_table(&gateway.db, "activity");
    let page = owner
        .post(
            "/admin/mail/test",
            &[("csrf", csrf.as_str()), ("to", "recipient@example.com")],
        )
        .await;
    show_table(&gateway.db, "activity");
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a failed mail whose failure record cannot be written must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: mail failure record failed: "),
        "the line must name the failure record; line: {}",
        added[0]
    );
    assert_eq!(
        page.status, 200,
        "the test send answers with the mail page, as before"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_error_on_the_combined_endpoint_writes_one_line() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let upstream = FakeUpstream::start(UpstreamOptions {
        generation: Generation::Session,
        ..UpstreamOptions::default()
    })
    .await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let page = admin::refresh_tools(&owner, &id).await;
    assert_eq!(page.status, 303, "the tool list of demo must be fetched");
    let owner_id = admin::user_id(&owner, EMAIL)
        .await
        .expect("the owner must be listed on the users page");
    let page = admin::assign(&owner, &owner_id, &[id.as_str()]).await;
    assert_eq!(page.status, 303, "the owner must be assigned to demo");
    let registered = owner.register(CLIENT_NAME, &[LOOPBACK_CALLBACK]).await;
    assert_eq!(registered.status, 201, "the probe client must register");
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: LOOPBACK_CALLBACK.to_owned(),
    };
    let resource = format!("{}/mcp", gateway.base);
    let tokens = owner.connect(&app, &resource).await;
    let mcp = McpClient::session(&resource, Some(&tokens.access_token));
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "the session must start before the table is hidden"
    );

    let before = gateway.lines().len();
    hide_table(&gateway.db, "upstream_sessions");
    let reply = mcp.call_tool("demo__echo", json!({"text": "hi"})).await;
    show_table(&gateway.db, "upstream_sessions");
    let added = gateway.lines_since(before);
    assert_eq!(
        added.len(),
        1,
        "a database error on /mcp must write exactly one line; stderr:\n{:?}",
        gateway.lines()
    );
    assert!(
        added[0].starts_with("doorward: upstream sessions failed: "),
        "the line must be the database one; line: {}",
        added[0]
    );
    assert!(
        !added[0].contains("no connection"),
        "a database error must not be reported as no connection; line: {}",
        added[0]
    );
    assert_ne!(
        reply.status, 0,
        "the caller must get an answer while the database fails"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_database_error_during_the_access_check_writes_one_line_and_ends_unavailable() {
    let gateway = Spawned::start();
    let owner = gateway.owner().await;
    let upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let page = admin::refresh_tools(&owner, &id).await;
    assert_eq!(
        page.status, 303,
        "the tool list of demo must be fetched before the call"
    );
    let owner_id = admin::user_id(&owner, EMAIL)
        .await
        .expect("the owner must be listed on the users page");
    let page = admin::assign(&owner, &owner_id, &[id.as_str()]).await;
    assert_eq!(page.status, 303, "the owner must be assigned to demo");
    upstream.set_mode(Mode::Delayed { millis: 1500 });

    let registered = owner.register(CLIENT_NAME, &[LOOPBACK_CALLBACK]).await;
    assert_eq!(registered.status, 201, "the probe client must register");
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: LOOPBACK_CALLBACK.to_owned(),
    };
    let resource = format!("{}/demo", gateway.base);
    let tokens = owner.connect(&app, &resource).await;
    let mcp = McpClient::stateless(&resource, Some(&tokens.access_token));

    let before = gateway.lines().len();
    let call = mcp.call_tool("echo", json!({"text": "hi"}));
    let hide = async {
        // The bearer check has passed by now; the table goes before the answer, so the re-check fails.
        tokio::time::sleep(Duration::from_millis(500)).await;
        hide_table(&gateway.db, "access_tokens");
    };
    let (reply, ()) = tokio::join!(call, hide);
    show_table(&gateway.db, "access_tokens");
    assert_eq!(
        reply.status, 502,
        "a call whose access check cannot be made must be unavailable"
    );
    assert_eq!(
        gateway.lines_since(before),
        vec![
            "doorward: access check failed: database error: no such table: access_tokens"
                .to_string()
        ],
        "a database error during the access check must write exactly that one line"
    );
    let rows = admin::activity_with_details(&owner, None, None).await;
    let calls: Vec<_> = rows
        .iter()
        .filter(|(row, _)| row.kind == "tool_call" && row.tool == "echo")
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "the call must write exactly one activity row"
    );
    let (row, detail) = calls[0];
    assert_eq!(
        (row.decision.as_str(), row.outcome.as_str(), detail.as_str()),
        ("allow", "unavailable", "the access check could not be done"),
        "the row must say the access check could not be done, not that access was lost"
    );
}
