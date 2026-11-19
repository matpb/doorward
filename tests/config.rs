use std::net::{IpAddr, SocketAddr};

use doorward::{Config, ConfigError};

fn config_with_url(url: &str) -> Config {
    Config {
        public_url: url.to_owned(),
        listen: SocketAddr::from(([127, 0, 0, 1], 8717)),
        database: "doorward.db".into(),
        key_file: None,
        trusted_proxies: Vec::new(),
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
