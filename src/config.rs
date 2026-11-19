use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use url::{Host, Url};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Public origin of the gateway: scheme, host and optional port only.
    pub public_url: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub database: PathBuf,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    #[serde(default)]
    pub lifetimes: Lifetimes,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub mail: MailConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Lifetimes {
    pub invitation_days: u64,
    pub reset_minutes: u64,
    pub session_hours: u64,
    pub auth_request_minutes: u64,
    pub auth_code_seconds: u64,
    pub access_token_minutes: u64,
    pub refresh_token_days: u64,
    pub family_days: u64,
    /// 0 disables the replay window.
    pub refresh_replay_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub body_bytes: u64,
    pub tools_list_bytes: u64,
    pub upstream_timeout_seconds: u64,
    pub account_failures: u64,
    pub address_failures: u64,
    pub block_minutes: u64,
    pub dcr_per_hour: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MailConfig {
    pub smtp_ca_file: Option<PathBuf>,
}

impl Default for Lifetimes {
    fn default() -> Self {
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
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            body_bytes: 1_048_576,
            tools_list_bytes: 4_194_304,
            upstream_timeout_seconds: 300,
            account_failures: 5,
            address_failures: 30,
            block_minutes: 15,
            dcr_per_hour: 20,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {}: {}", .0.display(), .1)]
    Read(PathBuf, #[source] std::io::Error),
    #[error("invalid config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid public_url: {0}")]
    PublicUrl(String),
    #[error("invalid config: {0}")]
    Invalid(String),
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8717))
}

impl Config {
    /// Reads, parses and validates the config file at `path`.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| ConfigError::Read(path.to_path_buf(), err))?;
        let mut config: Config = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks `public_url` and stores it without a trailing slash.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let url = Url::parse(&self.public_url)
            .map_err(|err| ConfigError::PublicUrl(format!("not an absolute URL: {err}")))?;
        check_public_url(&url).map_err(ConfigError::PublicUrl)?;
        let normalised = url.as_str();
        self.public_url = normalised
            .strip_suffix('/')
            .unwrap_or(normalised)
            .to_owned();
        self.lifetimes.validate()?;
        self.limits.validate()?;
        Ok(())
    }
}

impl Lifetimes {
    fn validate(&self) -> Result<(), ConfigError> {
        require_at_least_one(
            "lifetimes",
            &[
                ("invitation_days", self.invitation_days),
                ("reset_minutes", self.reset_minutes),
                ("session_hours", self.session_hours),
                ("auth_request_minutes", self.auth_request_minutes),
                ("auth_code_seconds", self.auth_code_seconds),
                ("access_token_minutes", self.access_token_minutes),
                ("refresh_token_days", self.refresh_token_days),
                ("family_days", self.family_days),
            ],
        )?;
        if self.refresh_replay_seconds > 300 {
            return Err(ConfigError::Invalid(
                "lifetimes.refresh_replay_seconds must be at most 300".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Limits {
    fn validate(&self) -> Result<(), ConfigError> {
        require_at_least_one(
            "limits",
            &[
                ("body_bytes", self.body_bytes),
                ("tools_list_bytes", self.tools_list_bytes),
                ("upstream_timeout_seconds", self.upstream_timeout_seconds),
                ("account_failures", self.account_failures),
                ("address_failures", self.address_failures),
                ("block_minutes", self.block_minutes),
                ("dcr_per_hour", self.dcr_per_hour),
            ],
        )
    }
}

/// Fails with the first of `fields` that is 0.
fn require_at_least_one(section: &str, fields: &[(&str, u64)]) -> Result<(), ConfigError> {
    match fields.iter().find(|(_, value)| *value == 0) {
        Some((name, _)) => Err(ConfigError::Invalid(format!(
            "{section}.{name} must be at least 1"
        ))),
        None => Ok(()),
    }
}

fn check_public_url(url: &Url) -> Result<(), String> {
    let loopback = match url.host() {
        Some(Host::Domain(name)) => name == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => return Err("http is allowed only for a loopback address".to_owned()),
        _ => return Err("scheme must be https".to_owned()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain user information".to_owned());
    }
    if url.query().is_some() {
        return Err("must not contain a query".to_owned());
    }
    if url.fragment().is_some() {
        return Err("must not contain a fragment".to_owned());
    }
    if url.path() != "/" {
        return Err("must not contain a path".to_owned());
    }
    Ok(())
}
