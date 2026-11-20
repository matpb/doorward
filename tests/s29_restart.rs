mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use common::TestGateway;
use common::admin::{self, ServerSpec};
use common::binary::{Run, free_port, write_file};
use common::client::{OAuthApp, TestClient};
use common::mcp::McpClient;
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use serde_json::json;
use tempfile::TempDir;
use tokio::task::JoinHandle;

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct horse battery staple";
const CLIENT_NAME: &str = "Stop Probe";
const LOOPBACK_CALLBACK: &str = "http://127.0.0.1:8765/callback";
/// The line written by the first stop signal.
const STOPPING: &str = "doorward: stopping, waiting up to 10 seconds for open requests";
/// The line written when requests are still open at the end of the wait.
const STILL_OPEN: &str = "doorward: stopped with requests still open";
/// One progress event a second for 100 seconds: a stream that stays open through every wait here.
const STREAM_STEPS: u32 = 100;
const STREAM_INTERVAL_MS: u64 = 1000;

/// A config file in `dir` that names `database` and, when given, `key_file`; returns its path.
fn config_naming(dir: &Path, name: &str, database: &Path, key_file: Option<&Path>) -> String {
    let key_line = key_file
        .map(|key| format!("key_file = '{}'\n", key.display()))
        .unwrap_or_default();
    let text = format!(
        "public_url = \"http://127.0.0.1:8717\"\ndatabase = '{}'\n{key_line}",
        database.display()
    );
    write_file(dir, name, &text).display().to_string()
}

fn migration_rows(path: &Path) -> Vec<(i64, String)> {
    let conn = rusqlite::Connection::open(path).expect("open database");
    let mut stmt = conn
        .prepare("SELECT version, applied_at FROM schema_migrations ORDER BY version")
        .expect("prepare");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

#[tokio::test(flavor = "multi_thread")]
async fn s29_restart_keeps_data() {
    let mut gateway = TestGateway::start().await;
    {
        let conn = rusqlite::Connection::open(gateway.db_path()).expect("open database");
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)",
            rusqlite::params!["probe", b"kept".as_slice()],
        )
        .expect("insert");
    }
    gateway.restart().await;
    let response = gateway
        .http
        .get(gateway.url("/healthz"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let conn = rusqlite::Connection::open(gateway.db_path()).expect("open database");
    let value: Vec<u8> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            ["probe"],
            |row| row.get(0),
        )
        .expect("row survives restart");
    assert_eq!(value, b"kept");
}

#[test]
fn a_start_up_failure_names_the_file_and_the_cause() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();

    let absent = root.join("absent.toml");
    let absent_text = absent.display().to_string();
    let outcome = Run::spawn(&["--config", absent_text.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a missing config file must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot read the config file {absent_text}: No such file or directory (os error 2)\n"
        ),
        "the line must name the config file and the cause"
    );

    let missing = root.join("missing");
    let database = missing.join("doorward.db");
    let config = config_naming(root, "database.toml", &database, None);
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a database in a missing directory must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot open the database {}: No such file or directory (os error 2)\n",
            database.display()
        ),
        "the line must name the database and the cause"
    );
    assert!(
        !missing.exists(),
        "the missing directory must not be created"
    );

    let key = missing.join("doorward.key");
    let database = root.join("keyed.db");
    let config = config_naming(root, "key-missing.toml", &database, Some(&key));
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a key file that cannot be created must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot create the key file {}: No such file or directory (os error 2)\n",
            key.display()
        ),
        "the line must name the key file and the cause"
    );
    assert!(!key.exists(), "no key file may be created");

    let keydir = root.join("keydir");
    std::fs::create_dir(&keydir).expect("create the directory used as a key file");
    std::fs::set_permissions(&keydir, std::fs::Permissions::from_mode(0o700))
        .expect("make the directory private");
    let database = root.join("dir-key.db");
    let config = config_naming(root, "key-dir.toml", &database, Some(&keydir));
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "a key file that cannot be read must exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "doorward: cannot read the key file {}: Is a directory (os error 21)\n",
            keydir.display()
        ),
        "the line must name the key file and the cause"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s29_migrations_apply_once() {
    let mut gateway = TestGateway::start().await;
    let after_start = migration_rows(&gateway.db_path());
    assert!(
        !after_start.is_empty(),
        "a first start must apply migrations"
    );
    for (index, row) in after_start.iter().enumerate() {
        assert_eq!(row.0, index as i64 + 1, "versions must run from 1 upward");
    }
    gateway.restart().await;
    let after_restart = migration_rows(&gateway.db_path());
    assert_eq!(after_restart, after_start);
}

/// The real binary on a free loopback port, with its database in a temp dir.
struct Spawned {
    run: Run,
    base: String,
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
            _dir: dir,
        }
    }

    /// Sets up the owner with the setup code the binary printed; returns the owner's browser.
    async fn owner(&self) -> TestClient {
        let code = self
            .run
            .stderr()
            .lines()
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

/// The lines of standard error that the stop writes, in order.
fn stop_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.starts_with("doorward: stop"))
        .collect()
}

/// A gateway with a server `demo` whose owner-held tool call is streamed by the upstream until it
/// is cut. Returns once the upstream has received the call; the call task is still running.
async fn gateway_with_open_stream() -> (Spawned, FakeUpstream, JoinHandle<()>) {
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
    upstream.set_mode(Mode::Progress {
        steps: STREAM_STEPS,
        interval_ms: STREAM_INTERVAL_MS,
    });
    let mcp = McpClient::stateless(&resource, Some(&tokens.access_token));
    mcp.set_timeout(Duration::from_secs(120));
    let call = tokio::spawn(async move {
        let _ = mcp.call_tool("echo", json!({"text": "held"})).await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.rpc_count("tools/call") < 1 {
        assert!(
            Instant::now() < deadline,
            "the call did not reach the upstream within 10 seconds; stderr:\n{}",
            gateway.run.stderr()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (gateway, upstream, call)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_signal_ends_the_gateway_while_a_stream_is_open() {
    let (mut gateway, _upstream, call) = gateway_with_open_stream().await;
    assert!(
        !call.is_finished(),
        "the stream must still be open when the stop is sent"
    );
    gateway.run.signal("TERM");
    assert!(
        gateway.run.exit_within(Duration::from_secs(5)).is_none(),
        "the gateway exited within 5 seconds of SIGTERM while a stream was open; stderr:\n{}",
        gateway.run.stderr()
    );
    let outcome = gateway
        .run
        .exit_within(Duration::from_secs(9))
        .unwrap_or_else(|| {
            panic!(
                "the gateway was still running 14 seconds after SIGTERM; stderr:\n{}",
                gateway.run.stderr()
            )
        });
    assert_eq!(
        outcome.code,
        Some(0),
        "a stop with requests still open must exit with 0; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        stop_lines(&outcome.stderr),
        [STOPPING, STILL_OPEN],
        "the stop must write the stopping line, then the still-open line; stderr:\n{}",
        outcome.stderr
    );
    call.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_signal_ends_the_wait() {
    let (mut gateway, _upstream, call) = gateway_with_open_stream().await;
    gateway.run.signal("TERM");
    assert!(
        gateway.run.exit_within(Duration::from_secs(2)).is_none(),
        "the gateway exited 2 seconds after SIGTERM while a stream was open; stderr:\n{}",
        gateway.run.stderr()
    );
    gateway.run.signal("TERM");
    let outcome = gateway
        .run
        .exit_within(Duration::from_secs(3))
        .unwrap_or_else(|| {
            panic!(
                "a second SIGTERM did not end the wait within 3 seconds; stderr:\n{}",
                gateway.run.stderr()
            )
        });
    assert_eq!(
        outcome.code,
        Some(0),
        "a second signal must exit with 0; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        stop_lines(&outcome.stderr),
        [STOPPING, STILL_OPEN],
        "a second signal must write the still-open line; stderr:\n{}",
        outcome.stderr
    );
    call.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_with_nothing_open_is_immediate() {
    let mut gateway = Spawned::start();
    gateway.run.signal("TERM");
    let outcome = gateway
        .run
        .exit_within(Duration::from_secs(3))
        .unwrap_or_else(|| {
            panic!(
                "the gateway with nothing open did not exit within 3 seconds of SIGTERM; stderr:\n{}",
                gateway.run.stderr()
            )
        });
    assert_eq!(
        outcome.code,
        Some(0),
        "a stop with nothing open must exit with 0; stderr:\n{}",
        outcome.stderr
    );
    assert_eq!(
        stop_lines(&outcome.stderr),
        [STOPPING],
        "a stop with nothing open must write the stopping line and no still-open line; stderr:\n{}",
        outcome.stderr
    );
}
