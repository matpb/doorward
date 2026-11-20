//! Helpers for the tests that run the real `doorward` binary and read its settings.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use doorward::Config;
use serde_json::Value;
use tempfile::TempDir;

/// The longest any start, refusal, exit or answer may take.
pub const DEADLINE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);

/// A port that was free a moment ago: bound on loopback, then released.
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a free port");
    listener.local_addr().expect("local address").port()
}

/// Writes `text` to `dir/name` and returns the path.
pub fn write_file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write file");
    path
}

/// The variables that make a valid gateway configuration on their own.
pub fn required_vars() -> Vec<(String, String)> {
    vec![
        (
            "DOORWARD_PUBLIC_URL".to_owned(),
            "https://doorward.example.com".to_owned(),
        ),
        (
            "DOORWARD_DATABASE".to_owned(),
            "/var/lib/doorward/doorward.db".to_owned(),
        ),
    ]
}

/// The exit code and the printed output of a finished doorward process.
pub struct Outcome {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// A doorward process. Its output goes to a temp dir of its own; it is killed on drop.
pub struct Run {
    child: Child,
    logs: TempDir,
}

impl Run {
    /// Starts the binary with `args`, and `vars` as its whole environment.
    pub fn spawn(args: &[&str], vars: &[(&str, &str)]) -> Run {
        let logs = tempfile::tempdir().expect("temp dir for the output");
        let stdout = File::create(logs.path().join("stdout.txt")).expect("stdout file");
        let stderr = File::create(logs.path().join("stderr.txt")).expect("stderr file");
        let child = Command::new(env!("CARGO_BIN_EXE_doorward"))
            .args(args)
            .env_clear()
            .envs(vars.iter().copied())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .expect("start the doorward binary");
        Run { child, logs }
    }

    /// Everything the process has written to stderr so far.
    pub fn stderr(&self) -> String {
        read_log(&self.logs.path().join("stderr.txt"))
    }

    /// Waits up to 5 seconds for the process to exit, then returns its code and output.
    pub fn wait_for_exit(&mut self) -> Outcome {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll doorward") {
                return Outcome {
                    code: status.code(),
                    stdout: read_log(&self.logs.path().join("stdout.txt")),
                    stderr: self.stderr(),
                };
            }
            if Instant::now() >= deadline {
                panic!(
                    "doorward was still running after 5 seconds; stderr so far:\n{}",
                    self.stderr()
                );
            }
            std::thread::sleep(POLL);
        }
    }

    /// Waits up to 5 seconds until `GET /healthz` on `port` answers 200.
    pub fn wait_until_healthy(&mut self, port: u16) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll doorward") {
                panic!(
                    "doorward exited ({status}) instead of starting; stderr:\n{}",
                    self.stderr()
                );
            }
            if matches!(
                try_http(port, "GET", "/healthz", &[], &[]),
                Ok(reply) if reply.status == 200
            ) {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "doorward did not answer 200 on /healthz port {port} within 5 seconds; stderr:\n{}",
                    self.stderr()
                );
            }
            std::thread::sleep(POLL);
        }
    }

    /// Kills the process and waits until it is gone.
    pub fn stop(&mut self) {
        self.child.kill().expect("kill doorward");
        self.child.wait().expect("reap doorward");
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        // An exited process makes the kill fail; the wait then returns at once.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read the output file")
}

/// One HTTP/1.1 answer: the status, the head (status line and headers) and the body.
pub struct Reply {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl Reply {
    /// The value of every header named `name`; the name is matched without case.
    pub fn header(&self, name: &str) -> Vec<String> {
        self.head
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
            .collect()
    }
}

/// Sends one request on a new connection and reads the answer until the server closes it.
pub fn try_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<Reply> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(DEADLINE))?;
    let mut lines = vec![
        format!("{method} {path} HTTP/1.1"),
        "Host: localhost".to_owned(),
        "Connection: close".to_owned(),
        format!("Content-Length: {}", body.len()),
    ];
    lines.extend(
        headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}")),
    );
    let mut request = lines.join("\r\n").into_bytes();
    request.extend_from_slice(b"\r\n\r\n");
    request.extend_from_slice(body);
    stream.write_all(&request)?;
    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        // A server that refuses before reading the whole body resets the socket after its answer.
        Err(err) if err.kind() == ErrorKind::ConnectionReset && !raw.is_empty() => {}
        Err(err) => return Err(err),
    }
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("the answer has no head"))?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("the answer has no status code"))?;
    Ok(Reply {
        status,
        head,
        body: String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    })
}

/// `try_http` for a request that must be answered.
pub fn http(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    try_http(port, method, path, headers, body).expect("the request was answered")
}

/// The lines of `text` that contain `needle`.
pub fn lines_containing<'a>(text: &'a str, needle: &str) -> Vec<&'a str> {
    text.lines().filter(|line| line.contains(needle)).collect()
}

/// Every leaf of a serialised `config`, keyed by its dotted path as `SETTINGS` names it.
pub fn settings_of(config: &Config) -> BTreeMap<String, Value> {
    let value = serde_json::to_value(config).expect("serialise the config");
    let mut leaves = BTreeMap::new();
    flatten("", &value, &mut leaves);
    leaves
}

fn flatten(prefix: &str, value: &Value, leaves: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(fields) => {
            for (name, inner) in fields {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                flatten(&path, inner, leaves);
            }
        }
        other => {
            leaves.insert(prefix.to_owned(), other.clone());
        }
    }
}
