mod common;

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use common::binary::{Run, free_port, http, lines_containing, write_file};

const SHARED_WARNING: &str = "doorward: shared_client_address is set: every visitor shares one address for sign-in throttling and rate limits";
const PROXY_WARNING: &str = "a trusted proxy sent no X-Forwarded-For";
const PRIVATE_WARNING: &str = "the client address is private";

/// Writes `doorward.toml` in `dir` for a gateway on `port`, then the `extra` lines.
fn config_file(dir: &Path, port: u16, public_url: &str, extra: &str) -> PathBuf {
    let text = format!(
        "public_url = \"{public_url}\"\nlisten = \"127.0.0.1:{port}\"\ndatabase = '{}'\n{extra}",
        dir.join("doorward.db").display()
    );
    write_file(dir, "doorward.toml", &text)
}

#[test]
fn https_without_a_trusted_proxy_refuses() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = config_file(dir.path(), free_port(), "https://doorward.example.com", "");
    let config = config.display().to_string();
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "https with no trusted proxy must refuse the start with exit 2; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("trusted_proxies")
            && outcome.stderr.contains("shared_client_address"),
        "the refusal must name trusted_proxies and shared_client_address; stderr:\n{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains("trusted_proxies = [\"127.0.0.1\", \"::1\"]"),
        "the refusal must show the loopback entry for a proxy on the same host; stderr:\n{}",
        outcome.stderr
    );
}

#[test]
fn the_opt_out_starts_with_a_warning() {
    let dir = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    let config = config_file(
        dir.path(),
        port,
        "https://doorward.example.com",
        "shared_client_address = true\n",
    );
    let config = config.display().to_string();
    let mut run = Run::spawn(&["--config", config.as_str()], &[]);
    run.wait_until_healthy(port);
    let stderr = run.stderr();
    assert_eq!(
        lines_containing(&stderr, "every visitor shares one address"),
        [SHARED_WARNING],
        "the opt-out must start and log exactly one warning that every visitor shares one address; stderr:\n{stderr}"
    );
}

#[test]
fn a_trusted_proxy_starts_quietly() {
    let dir = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    let config = config_file(
        dir.path(),
        port,
        "https://doorward.example.com",
        "trusted_proxies = [\"127.0.0.1\"]\n",
    );
    let config = config.display().to_string();
    let mut run = Run::spawn(&["--config", config.as_str()], &[]);
    run.wait_until_healthy(port);
    let stderr = run.stderr();
    assert!(
        lines_containing(&stderr, "every visitor shares one address").is_empty(),
        "a trusted proxy must start without the shared address warning; stderr:\n{stderr}"
    );
}

#[test]
fn http_on_loopback_is_exempt() {
    for host in ["127.0.0.1", "localhost"] {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let public_url = format!("http://{host}:{port}");
        let config = config_file(dir.path(), port, &public_url, "");
        let config = config.display().to_string();
        let mut run = Run::spawn(&["--config", config.as_str()], &[]);
        run.wait_until_healthy(port);
        let stderr = run.stderr();
        assert!(
            lines_containing(&stderr, "every visitor shares one address").is_empty(),
            "{public_url} must start without the https warning; stderr:\n{stderr}"
        );
    }
}

#[test]
fn http_on_a_public_name_follows_the_https_rule() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = config_file(dir.path(), free_port(), "http://doorward.example.com", "");
    let config = config.display().to_string();
    let outcome = Run::spawn(&["--config", config.as_str()], &[]).wait_for_exit();
    assert_eq!(
        outcome.code,
        Some(2),
        "http on a public name with no trusted proxy must refuse the start with exit 2; stderr:\n{}",
        outcome.stderr
    );
}

#[test]
fn a_trusted_proxy_that_sends_no_address_is_logged_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    let public_url = format!("http://127.0.0.1:{port}");
    let config = config_file(
        dir.path(),
        port,
        &public_url,
        "trusted_proxies = [\"127.0.0.1\"]\n",
    );
    let config = config.display().to_string();
    let mut run = Run::spawn(&["--config", config.as_str()], &[]);
    run.wait_until_healthy(port);
    for _ in 0..3 {
        let reply = http(port, "GET", "/login", &[], &[]);
        assert_eq!(
            reply.status, 200,
            "the login page must answer while the proxy sends no address"
        );
    }
    let stderr = run.stderr();
    assert_eq!(
        lines_containing(&stderr, PROXY_WARNING).len(),
        1,
        "three requests without X-Forwarded-For from a trusted proxy must log exactly one line saying so; stderr:\n{stderr}"
    );
}

#[test]
fn a_private_client_address_on_a_public_install_is_logged_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    let config = config_file(
        dir.path(),
        port,
        "https://doorward.example.com",
        "trusted_proxies = [\"127.0.0.1\"]\n",
    );
    let config = config.display().to_string();
    let mut run = Run::spawn(&["--config", config.as_str()], &[]);
    run.wait_until_healthy(port);
    let private = Ipv4Addr::new(10, 0, 0, 7).to_string();
    for _ in 0..3 {
        let reply = http(
            port,
            "GET",
            "/login",
            &[("X-Forwarded-For", private.as_str())],
            &[],
        );
        assert_eq!(
            reply.status, 200,
            "the login page must answer a forwarded private address"
        );
    }
    let stderr = run.stderr();
    let warnings = lines_containing(&stderr, PRIVATE_WARNING);
    assert_eq!(
        warnings.len(),
        1,
        "a private client address must log exactly one line saying so; stderr:\n{stderr}"
    );
    assert!(
        warnings[0].contains("rootless Docker"),
        "the line must name the usual causes; line: {}",
        warnings[0]
    );
    for _ in 0..2 {
        let reply = http(
            port,
            "GET",
            "/login",
            &[("X-Forwarded-For", "203.0.113.9")],
            &[],
        );
        assert_eq!(
            reply.status, 200,
            "the login page must answer a forwarded public address"
        );
    }
    let stderr = run.stderr();
    assert_eq!(
        lines_containing(&stderr, PRIVATE_WARNING).len(),
        1,
        "requests from a public client address must add no line; stderr:\n{stderr}"
    );
}
