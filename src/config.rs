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
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {}: {}", .0.display(), .1)]
    Read(PathBuf, #[source] std::io::Error),
    #[error("invalid config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid public_url: {0}")]
    PublicUrl(String),
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
        Ok(())
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
