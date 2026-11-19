use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use doorward::config::{Lifetimes, Limits};
use doorward::{Config, ConfigError};

fn config_with_url(url: &str) -> Config {
    Config {
        public_url: url.to_owned(),
        listen: SocketAddr::from(([127, 0, 0, 1], 8717)),
        database: "doorward.db".into(),
        key_file: None,
        trusted_proxies: Vec::new(),
        lifetimes: Default::default(),
        limits: Default::default(),
        mail: Default::default(),
    }
}

fn accepted(url: &str, stored: &str) {
    let mut config = config_with_url(url);
    config.validate().expect("public_url accepted");
    assert_eq!(config.public_url, stored);
}

fn refused(url: &str) {
    let mut config = config_with_url(url);
    let err = config.validate().expect_err("public_url refused");
    assert!(
        matches!(err, ConfigError::PublicUrl(_)),
        "wrong error for {url}: {err:?}"
    );
}

fn write_config(dir: &tempfile::TempDir, text: &str) -> std::path::PathBuf {
    let path = dir.path().join("doorward.toml");
    std::fs::write(&path, text).expect("write config");
    path
}

#[test]
fn https_origin_is_accepted() {
    accepted("https://gateway.example.com", "https://gateway.example.com");
}

#[test]
fn trailing_slash_is_stripped() {
    accepted(
        "https://gateway.example.com/",
        "https://gateway.example.com",
    );
}

#[test]
fn https_with_port_is_accepted() {
    accepted(
        "https://gateway.example.com:8443",
        "https://gateway.example.com:8443",
    );
}

#[test]
fn http_ipv4_loopback_is_accepted() {
    accepted("http://127.0.0.1:8717", "http://127.0.0.1:8717");
}

#[test]
fn http_localhost_is_accepted() {
    accepted("http://localhost:8717", "http://localhost:8717");
}

#[test]
fn http_ipv6_loopback_is_accepted() {
    accepted("http://[::1]:8717", "http://[::1]:8717");
}

#[test]
fn http_on_remote_host_is_refused() {
    refused("http://gateway.example.com");
}

#[test]
fn path_is_refused() {
    refused("https://gateway.example.com/base");
}

#[test]
fn query_is_refused() {
    refused("https://gateway.example.com?x=1");
}

#[test]
fn fragment_is_refused() {
    refused("https://gateway.example.com#f");
}

#[test]
fn userinfo_is_refused() {
    refused("https://user@gateway.example.com");
}

#[test]
fn non_http_scheme_is_refused() {
    refused("ftp://gateway.example.com");
}

#[test]
fn missing_scheme_is_refused() {
    refused("gateway.example.com");
}

#[test]
fn unknown_key_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = write_config(
        &dir,
        "public_url = \"https://gateway.example.com\"\ndatabase = \"doorward.db\"\nextra = 1\n",
    );
    let err = Config::load(&path).expect_err("unknown key refused");
    assert!(matches!(err, ConfigError::Parse(_)), "wrong error: {err:?}");
}

#[test]
fn defaults_apply() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = write_config(
        &dir,
        "public_url = \"https://gateway.example.com\"\ndatabase = \"doorward.db\"\n",
    );
    let config = Config::load(&path).expect("config loads");
    assert_eq!(config.listen, SocketAddr::from(([127, 0, 0, 1], 8717)));
    assert_eq!(config.key_file, None);
    assert_eq!(config.trusted_proxies, Vec::<IpAddr>::new());
}

#[test]
fn missing_file_is_read_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let err = Config::load(&dir.path().join("absent.toml")).expect_err("missing file refused");
    assert!(
        matches!(err, ConfigError::Read(_, _)),
        "wrong error: {err:?}"
    );
}

const BASE: &str = "public_url = \"https://gateway.example.com\"\ndatabase = \"doorward.db\"\n";

fn load_text(text: &str) -> Result<Config, ConfigError> {
    let dir = tempfile::tempdir().expect("temp dir");
    Config::load(&write_config(&dir, text))
}

fn refused_with(err: ConfigError, message: &str) {
    assert!(
        matches!(&err, ConfigError::Invalid(found) if found == message),
        "wrong error: {err:?}"
    );
    assert_eq!(err.to_string(), format!("invalid config: {message}"));
}

#[test]
fn sections_default_when_absent() {
    let config = load_text(BASE).expect("config loads");
    assert_eq!(
        config.lifetimes,
        Lifetimes {
            invitation_days: 7,
            reset_minutes: 60,
            session_hours: 12,
            auth_request_minutes: 10,
            auth_code_seconds: 60,
            access_token_minutes: 60,
            refresh_token_days: 30,
            family_days: 90,
            refresh_replay_seconds: 30,
        }
    );
    assert_eq!(
        config.limits,
        Limits {
            body_bytes: 1_048_576,
            tools_list_bytes: 4_194_304,
            upstream_timeout_seconds: 300,
            account_failures: 5,
            address_failures: 30,
            block_minutes: 15,
            dcr_per_hour: 20,
        }
    );
    assert_eq!(config.mail.smtp_ca_file, None);
}

#[test]
fn replay_window_zero_is_valid() {
    let config = load_text(&format!("{BASE}[lifetimes]\nrefresh_replay_seconds = 0\n"))
        .expect("zero replay window is valid");
    assert_eq!(
        config.lifetimes,
        Lifetimes {
            refresh_replay_seconds: 0,
            ..Lifetimes::default()
        }
    );
}

#[test]
fn replay_window_300_is_valid() {
    let config = load_text(&format!(
        "{BASE}[lifetimes]\nrefresh_replay_seconds = 300\n"
    ))
    .expect("replay window of 300 is valid");
    assert_eq!(config.lifetimes.refresh_replay_seconds, 300);
}

#[test]
fn zero_lifetime_is_rejected() {
    let err = load_text(&format!("{BASE}[lifetimes]\nauth_code_seconds = 0\n"))
        .expect_err("zero lifetime refused");
    refused_with(err, "lifetimes.auth_code_seconds must be at least 1");
}

#[test]
fn zero_limit_is_rejected() {
    let err =
        load_text(&format!("{BASE}[limits]\nbody_bytes = 0\n")).expect_err("zero limit refused");
    refused_with(err, "limits.body_bytes must be at least 1");
}

#[test]
fn replay_window_over_300_is_rejected() {
    let err = load_text(&format!(
        "{BASE}[lifetimes]\nrefresh_replay_seconds = 301\n"
    ))
    .expect_err("replay window over 300 refused");
    refused_with(err, "lifetimes.refresh_replay_seconds must be at most 300");
}

#[test]
fn unknown_section_key_is_parse_error() {
    let err =
        load_text(&format!("{BASE}[limits]\nunknown = 1\n")).expect_err("unknown key refused");
    assert!(matches!(err, ConfigError::Parse(_)), "wrong error: {err:?}");
}

#[test]
fn mail_ca_file_is_read() {
    let config =
        load_text(&format!("{BASE}[mail]\nsmtp_ca_file = \"roots.pem\"\n")).expect("config loads");
    assert_eq!(config.mail.smtp_ca_file, Some(PathBuf::from("roots.pem")));
}
