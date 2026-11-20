use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use toml::{Table, Value};
use url::{Host, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Listen,
    Path,
    Ranges,
    Bool,
    Whole,
    Origins,
}

const ORIGINS_MAX_ENTRIES: usize = 32;
const ORIGIN_MAX_BYTES: usize = 256;
/// Characters of an entry shown in a refusal.
const SHOWN_CHARS: usize = 200;

pub struct Setting {
    pub variable: &'static str,
    pub path: &'static str,
    pub kind: Kind,
}

/// One row per setting of `Config`, in the order of the file.
pub const SETTINGS: &[Setting] = &[
    Setting {
        variable: "DOORWARD_PUBLIC_URL",
        path: "public_url",
        kind: Kind::Text,
    },
    Setting {
        variable: "DOORWARD_LISTEN",
        path: "listen",
        kind: Kind::Listen,
    },
    Setting {
        variable: "DOORWARD_DATABASE",
        path: "database",
        kind: Kind::Path,
    },
    Setting {
        variable: "DOORWARD_KEY_FILE",
        path: "key_file",
        kind: Kind::Path,
    },
    Setting {
        variable: "DOORWARD_TRUSTED_PROXIES",
        path: "trusted_proxies",
        kind: Kind::Ranges,
    },
    Setting {
        variable: "DOORWARD_SHARED_CLIENT_ADDRESS",
        path: "shared_client_address",
        kind: Kind::Bool,
    },
    Setting {
        variable: "DOORWARD_ALLOWED_ORIGINS",
        path: "allowed_origins",
        kind: Kind::Origins,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_INVITATION_DAYS",
        path: "lifetimes.invitation_days",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_RESET_MINUTES",
        path: "lifetimes.reset_minutes",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_SESSION_HOURS",
        path: "lifetimes.session_hours",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_AUTH_REQUEST_MINUTES",
        path: "lifetimes.auth_request_minutes",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_AUTH_CODE_SECONDS",
        path: "lifetimes.auth_code_seconds",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_ACCESS_TOKEN_MINUTES",
        path: "lifetimes.access_token_minutes",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_REFRESH_TOKEN_DAYS",
        path: "lifetimes.refresh_token_days",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_FAMILY_DAYS",
        path: "lifetimes.family_days",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIFETIMES_REFRESH_REPLAY_SECONDS",
        path: "lifetimes.refresh_replay_seconds",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_BODY_BYTES",
        path: "limits.body_bytes",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_TOOLS_LIST_BYTES",
        path: "limits.tools_list_bytes",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_UPSTREAM_TIMEOUT_SECONDS",
        path: "limits.upstream_timeout_seconds",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_ACCOUNT_FAILURES",
        path: "limits.account_failures",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_ACCOUNT_CEILING",
        path: "limits.account_ceiling",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_ADDRESS_FAILURES",
        path: "limits.address_failures",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_BLOCK_MINUTES",
        path: "limits.block_minutes",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_DCR_PER_HOUR",
        path: "limits.dcr_per_hour",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_GENERAL_BURST",
        path: "limits.general_burst",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_GENERAL_PER_MINUTE",
        path: "limits.general_per_minute",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_OAUTH_BURST",
        path: "limits.oauth_burst",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_OAUTH_PER_MINUTE",
        path: "limits.oauth_per_minute",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_CREDENTIALS_BURST",
        path: "limits.credentials_burst",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_CREDENTIALS_PER_MINUTE",
        path: "limits.credentials_per_minute",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_MCP_BURST",
        path: "limits.mcp_burst",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_MCP_PER_MINUTE",
        path: "limits.mcp_per_minute",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_MCP_OPEN",
        path: "limits.mcp_open",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_RATE_TABLE_KEYS",
        path: "limits.rate_table_keys",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_AUTH_REQUESTS_MAX",
        path: "limits.auth_requests_max",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_DCR_TOTAL_PER_HOUR",
        path: "limits.dcr_total_per_hour",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_LIMITS_ACTIVITY_DAYS",
        path: "limits.activity_days",
        kind: Kind::Whole,
    },
    Setting {
        variable: "DOORWARD_MAIL_SMTP_CA_FILE",
        path: "mail.smtp_ca_file",
        kind: Kind::Path,
    },
];

/// The line logged at start when `shared_client_address` is the only proxy answer.
const SHARED_LINE: &str = "doorward: shared_client_address is set: every visitor shares one address for sign-in throttling and rate limits";

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub trusted_proxies: Vec<Range>,
    #[serde(default)]
    pub shared_client_address: bool,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub lifetimes: Lifetimes,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub mail: MailConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub body_bytes: u64,
    pub tools_list_bytes: u64,
    pub upstream_timeout_seconds: u64,
    pub account_failures: u64,
    pub account_ceiling: u64,
    pub address_failures: u64,
    pub block_minutes: u64,
    pub dcr_per_hour: u64,
    pub general_burst: u64,
    pub general_per_minute: u64,
    pub oauth_burst: u64,
    pub oauth_per_minute: u64,
    pub credentials_burst: u64,
    pub credentials_per_minute: u64,
    pub mcp_burst: u64,
    pub mcp_per_minute: u64,
    pub mcp_open: u64,
    pub rate_table_keys: u64,
    pub auth_requests_max: u64,
    pub dcr_total_per_hour: u64,
    pub activity_days: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
            account_ceiling: 50,
            address_failures: 30,
            block_minutes: 15,
            dcr_per_hour: 60,
            general_burst: 240,
            general_per_minute: 600,
            oauth_burst: 60,
            oauth_per_minute: 120,
            credentials_burst: 20,
            credentials_per_minute: 20,
            mcp_burst: 240,
            mcp_per_minute: 600,
            mcp_open: 64,
            rate_table_keys: 100_000,
            auth_requests_max: 10_000,
            dcr_total_per_hour: 600,
            activity_days: 90,
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
    #[error("unknown setting {0}: see docs/DOCKER.md for the list")]
    UnknownVariable(String),
    #[error("{variable} must be {expected}")]
    BadValue {
        variable: String,
        expected: &'static str,
    },
    #[error("{0} is required: set it in the config file or as {variable}", variable = variable_for(.0))]
    Missing(&'static str),
    #[error(
        "public_url is https and trusted_proxies is empty: when a proxy or tunnel is in front of doorward, list its address (for a tunnel on this host):\ntrusted_proxies = [\"127.0.0.1\", \"::1\"]\nor set shared_client_address = true to accept that every visitor shares one address"
    )]
    ProxyRequired,
}

/// The variable that sets the setting at `path`; the path itself when no row has it.
fn variable_for(path: &str) -> &str {
    SETTINGS
        .iter()
        .find(|setting| setting.path == path)
        .map_or(path, |setting| setting.variable)
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8717))
}

/// An address or a CIDR range: `127.0.0.1`, `203.0.113.0/24`, `2001:db8::/32`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    network: IpAddr,
    prefix: u8,
}

impl Range {
    /// True when `address` lies in the range. An IPv4-mapped IPv6 address counts as IPv4.
    pub fn contains(&self, address: IpAddr) -> bool {
        let (network, width) = bits(self.network);
        let (address, address_width) = bits(address.to_canonical());
        if width != address_width {
            return false;
        }
        let mask = u128::MAX
            .checked_shl(width - u32::from(self.prefix))
            .unwrap_or(0);
        network & mask == address & mask
    }
}

/// The address as 128 bits, and the width of its family in bits.
fn bits(address: IpAddr) -> (u128, u32) {
    match address {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    }
}

impl FromStr for Range {
    type Err = String;

    fn from_str(text: &str) -> Result<Range, String> {
        let (address_text, prefix_text) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let parsed: IpAddr = address_text
            .parse()
            .map_err(|_| "not an address or a range".to_owned())?;
        let width: u32 = if parsed.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => width,
            Some(digits) => u32::from(
                digits
                    .parse::<u8>()
                    .map_err(|_| "the prefix length is not a number".to_owned())?,
            ),
        };
        if prefix > width {
            return Err("the prefix is longer than the address".to_owned());
        }
        let (network, prefix) = match parsed {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
                _ => (parsed, prefix),
            },
            IpAddr::V4(_) => (parsed, prefix),
        };
        let prefix = u8::try_from(prefix).map_err(|_| "the prefix is too long".to_owned())?;
        Ok(Range { network, prefix })
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = if self.network.is_ipv4() { 32 } else { 128 };
        if self.prefix == full {
            write!(f, "{}", self.network)
        } else {
            write!(f, "{}/{}", self.network, self.prefix)
        }
    }
}

impl Serialize for Range {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Range, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl From<IpAddr> for Range {
    fn from(address: IpAddr) -> Range {
        let network = address.to_canonical();
        let prefix = if network.is_ipv4() { 32 } else { 128 };
        Range { network, prefix }
    }
}

/// Every `DOORWARD_*` name must be a setting, DOORWARD_KEY, DOORWARD_CONFIG or an ignored name.
fn check_names(vars: &[(String, String)]) -> Result<(), ConfigError> {
    for (name, _) in vars {
        if !name.starts_with("DOORWARD_") || accepted_name(name) {
            continue;
        }
        return Err(ConfigError::UnknownVariable(name.clone()));
    }
    Ok(())
}

fn accepted_name(name: &str) -> bool {
    let setting = SETTINGS.iter().any(|setting| setting.variable == name);
    let ignored = name == "DOORWARD_PORT"
        || name.starts_with("DOORWARD_PORT_")
        || name.starts_with("DOORWARD_SERVICE_");
    setting || ignored || name == "DOORWARD_KEY" || name == "DOORWARD_CONFIG"
}

/// The value of `name`, or None when it is absent or empty.
fn variable<'a>(vars: &'a [(String, String)], name: &str) -> Option<&'a str> {
    vars.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
}

fn file_path(file: Option<&Path>, vars: &[(String, String)]) -> Option<PathBuf> {
    match file {
        Some(path) => Some(path.to_path_buf()),
        None => variable(vars, "DOORWARD_CONFIG").map(PathBuf::from),
    }
}

fn read_table(path: &Path) -> Result<Table, ConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|err| ConfigError::Read(path.to_path_buf(), err))?;
    Ok(toml::from_str(&text)?)
}

/// Checks one variable's text against its kind and returns the TOML value it stands for.
fn parse_value(setting: &Setting, text: &str) -> Result<Value, ConfigError> {
    let refuse = |expected: &'static str| ConfigError::BadValue {
        variable: setting.variable.to_owned(),
        expected,
    };
    match setting.kind {
        Kind::Text => {
            Url::parse(text).map_err(|_| refuse("a URL"))?;
            Ok(Value::String(text.to_owned()))
        }
        Kind::Listen => {
            text.parse::<SocketAddr>()
                .map_err(|_| refuse("an address and a port"))?;
            Ok(Value::String(text.to_owned()))
        }
        Kind::Path => {
            if text.contains('\0') {
                return Err(refuse("a path"));
            }
            Ok(Value::String(text.to_owned()))
        }
        Kind::Ranges => {
            let mut entries = Vec::new();
            for entry in text.split(',').map(str::trim) {
                entry
                    .parse::<Range>()
                    .map_err(|_| refuse("a comma separated list of addresses or ranges"))?;
                entries.push(Value::String(entry.to_owned()));
            }
            Ok(Value::Array(entries))
        }
        Kind::Bool => match text {
            "true" => Ok(Value::Boolean(true)),
            "false" => Ok(Value::Boolean(false)),
            _ => Err(refuse("true or false")),
        },
        Kind::Whole => {
            let number: u64 = text.parse().map_err(|_| refuse("a whole number"))?;
            let number = i64::try_from(number).map_err(|_| {
                ConfigError::Invalid(format!("{} must be at most {}", setting.variable, i64::MAX))
            })?;
            Ok(Value::Integer(number))
        }
        Kind::Origins => {
            if text.contains('\0') {
                return Err(refuse("a comma separated list of origins"));
            }
            Ok(Value::Array(
                text.split(',')
                    .map(|entry| Value::String(entry.to_owned()))
                    .collect(),
            ))
        }
    }
}

/// Stores `value` at the dotted `path` of `table`, creating the sections on the way.
fn set_path(table: &mut Table, path: &str, value: Value) -> Result<(), ConfigError> {
    match path.split_once('.') {
        None => {
            table.insert(path.to_owned(), value);
            Ok(())
        }
        Some((section, rest)) => {
            let inner = table
                .entry(section.to_owned())
                .or_insert_with(|| Value::Table(Table::new()));
            match inner.as_table_mut() {
                Some(inner) => set_path(inner, rest, value),
                None => Err(ConfigError::Invalid(format!("{section} must be a table"))),
            }
        }
    }
}

fn loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => name == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

impl Config {
    /// The file (when given, else the one named by DOORWARD_CONFIG, else none), then the
    /// variables on top, then `validate`. `vars` may hold any names; only DOORWARD_* count.
    pub fn from_sources(
        file: Option<&Path>,
        vars: &[(String, String)],
    ) -> Result<Config, ConfigError> {
        check_names(vars)?;
        let mut table = match file_path(file, vars) {
            Some(path) => read_table(&path)?,
            None => Table::new(),
        };
        for setting in SETTINGS {
            if let Some(text) = variable(vars, setting.variable) {
                let value = parse_value(setting, text)?;
                set_path(&mut table, setting.path, value)?;
            }
        }
        for required in ["public_url", "database"] {
            if !table.contains_key(required) {
                return Err(ConfigError::Missing(required));
            }
        }
        let mut config: Config = table.try_into()?;
        config.validate()?;
        Ok(config)
    }

    /// Statement 42. `Err` refuses the start; `Ok(Some(line))` starts and logs `line` once.
    pub fn start_check(&self) -> Result<Option<String>, ConfigError> {
        if !self.trusted_proxies.is_empty() {
            return Ok(None);
        }
        if self.shared_client_address {
            return Ok(Some(SHARED_LINE.to_owned()));
        }
        if self.public_url.starts_with("https://") {
            return Err(ConfigError::ProxyRequired);
        }
        Ok(None)
    }

    /// True when `public_url` is https and its host is not loopback.
    pub fn https_public(&self) -> bool {
        Url::parse(&self.public_url)
            .is_ok_and(|url| url.scheme() == "https" && !loopback_host(&url))
    }

    /// Reads, parses and validates the config file at `path`.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        Config::from_sources(Some(path), &[])
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
        check_allowed_origins(&self.allowed_origins)?;
        Ok(())
    }
}

/// Refuses an `allowed_origins` list that breaks statement 48.
fn check_allowed_origins(entries: &[String]) -> Result<(), ConfigError> {
    if entries.len() > ORIGINS_MAX_ENTRIES {
        return Err(ConfigError::Invalid(format!(
            "allowed_origins has {} entries, at most {ORIGINS_MAX_ENTRIES} are allowed",
            entries.len()
        )));
    }
    for entry in entries {
        check_origin(entry).map_err(ConfigError::Invalid)?;
    }
    Ok(())
}

/// The first rule `entry` breaks, worded for the refusal. An origin is `scheme://host[:port]`.
fn check_origin(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("allowed_origins has an empty entry".to_owned());
    }
    let shown = shown_entry(entry);
    let refuse = |reason: &str| Err(format!("allowed_origins entry \"{shown}\" {reason}"));
    if entry.len() > ORIGIN_MAX_BYTES {
        return refuse(&format!("is over {ORIGIN_MAX_BYTES} bytes"));
    }
    if !entry.bytes().all(|byte| byte.is_ascii_graphic()) {
        return refuse("has a character outside visible ASCII");
    }
    if entry == "*" {
        return refuse("is a wildcard, not an origin");
    }
    if entry == "null" {
        return refuse("is not an origin");
    }
    let Some((scheme, rest)) = entry.split_once("://") else {
        return refuse("must be scheme://host[:port]");
    };
    if scheme.is_empty() || rest.is_empty() {
        return refuse("must be scheme://host[:port]");
    }
    if rest.contains(['/', '?', '#']) {
        return refuse("has a path, query, fragment or trailing slash");
    }
    Ok(())
}

/// The entry as a refusal shows it: its first 200 characters, each byte outside visible ASCII as `?`.
fn shown_entry(entry: &str) -> String {
    entry
        .chars()
        .take(SHOWN_CHARS)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
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
                ("account_ceiling", self.account_ceiling),
                ("address_failures", self.address_failures),
                ("block_minutes", self.block_minutes),
                ("dcr_per_hour", self.dcr_per_hour),
                ("general_burst", self.general_burst),
                ("general_per_minute", self.general_per_minute),
                ("oauth_burst", self.oauth_burst),
                ("oauth_per_minute", self.oauth_per_minute),
                ("credentials_burst", self.credentials_burst),
                ("credentials_per_minute", self.credentials_per_minute),
                ("mcp_burst", self.mcp_burst),
                ("mcp_per_minute", self.mcp_per_minute),
                ("mcp_open", self.mcp_open),
                ("rate_table_keys", self.rate_table_keys),
                ("auth_requests_max", self.auth_requests_max),
                ("dcr_total_per_hour", self.dcr_total_per_hour),
                ("activity_days", self.activity_days),
            ],
        )?;
        if self.account_ceiling < self.account_failures {
            return Err(ConfigError::Invalid(
                "limits.account_ceiling must be at least limits.account_failures".to_owned(),
            ));
        }
        Ok(())
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
    let loopback = loopback_host(url);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    const REQUIRED: [(&str, &str); 2] = [
        ("DOORWARD_PUBLIC_URL", "https://doorward.example.com"),
        ("DOORWARD_DATABASE", "/var/lib/doorward/doorward.db"),
    ];

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn range(text: &str) -> Range {
        text.parse().expect("range")
    }

    /// The required variables, with `extra` replacing or adding variables.
    fn with(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut vars: Vec<(String, String)> = REQUIRED
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        for (name, value) in extra {
            vars.retain(|(existing, _)| existing.as_str() != *name);
            vars.push((name.to_string(), value.to_string()));
        }
        vars
    }

    /// The refusal message of a load with `extra` variables.
    fn refusal(extra: &[(&str, &str)]) -> String {
        Config::from_sources(None, &with(extra))
            .expect_err("the load must be refused")
            .to_string()
    }

    #[test]
    fn an_address_range_contains_only_itself() {
        let r = range("127.0.0.1");
        assert!(r.contains(ip("127.0.0.1")));
        assert!(!r.contains(ip("203.0.113.9")));
    }

    #[test]
    fn an_ipv4_cidr_range_contains_its_block() {
        let r = range(&format!("{}/8", Ipv4Addr::new(10, 0, 0, 0)));
        assert!(r.contains(ip(&Ipv4Addr::new(10, 1, 2, 3).to_string())));
        assert!(!r.contains(ip(&Ipv4Addr::new(11, 0, 0, 0).to_string())));
    }

    #[test]
    fn an_ipv6_cidr_range_contains_its_block() {
        let r = range("2001:db8::/32");
        assert!(r.contains(ip("2001:db8:1::5")));
        assert!(!r.contains(ip("2001:db9::1")));
        assert!(range("fd00::/8").contains(ip("fd12::1")));
        assert!(!range("fd00::/8").contains(ip("fe80::1")));
    }

    #[test]
    fn a_zero_prefix_contains_its_family_only() {
        assert!(range("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(!range("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(range("::/0").contains(ip("2001:db8::1")));
        assert!(!range("::/0").contains(ip("203.0.113.9")));
    }

    #[test]
    fn a_full_prefix_is_one_address() {
        assert!(range("203.0.113.9/32").contains(ip("203.0.113.9")));
        assert!(!range("203.0.113.9/32").contains(ip("203.0.113.10")));
        assert!(range("2001:db8::1/128").contains(ip("2001:db8::1")));
        assert!(!range("2001:db8::1/128").contains(ip("2001:db8::2")));
    }

    #[test]
    fn a_prefix_longer_than_the_family_is_refused() {
        assert!("203.0.113.0/33".parse::<Range>().is_err());
        assert!("2001:db8::/129".parse::<Range>().is_err());
    }

    #[test]
    fn garbage_is_refused() {
        for text in ["not-an-address", "203.0.113.0/", "203.0.113.0/x", ""] {
            assert!(text.parse::<Range>().is_err(), "{text:?} must be refused");
        }
    }

    #[test]
    fn a_mapped_address_matches_its_ipv4_range() {
        assert!(range("127.0.0.1").contains(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn a_plain_address_converts_to_a_full_range() {
        let r = Range::from(ip("203.0.113.9"));
        assert!(r.contains(ip("203.0.113.9")));
        assert!(!r.contains(ip("203.0.113.10")));
    }

    #[test]
    fn a_range_prints_as_it_was_written() {
        assert_eq!(range("203.0.113.0/24").to_string(), "203.0.113.0/24");
        assert_eq!(range("2001:db8::1").to_string(), "2001:db8::1");
    }

    #[test]
    fn a_whole_number_must_be_whole() {
        for value in ["a lot", "-1", "1.5"] {
            assert_eq!(
                refusal(&[("DOORWARD_LIMITS_BODY_BYTES", value)]),
                "DOORWARD_LIMITS_BODY_BYTES must be a whole number"
            );
        }
    }

    #[test]
    fn a_flag_must_be_true_or_false() {
        for value in ["yes", "True", "1"] {
            assert_eq!(
                refusal(&[("DOORWARD_SHARED_CLIENT_ADDRESS", value)]),
                "DOORWARD_SHARED_CLIENT_ADDRESS must be true or false"
            );
        }
    }

    #[test]
    fn a_listen_address_needs_an_address_and_a_port() {
        for value in ["127.0.0.1", "not-an-address"] {
            assert_eq!(
                refusal(&[("DOORWARD_LISTEN", value)]),
                "DOORWARD_LISTEN must be an address and a port"
            );
        }
    }

    #[test]
    fn a_list_must_hold_addresses_or_ranges() {
        for value in ["127.0.0.1, not-an-address", "127.0.0.1,"] {
            assert_eq!(
                refusal(&[("DOORWARD_TRUSTED_PROXIES", value)]),
                "DOORWARD_TRUSTED_PROXIES must be a comma separated list of addresses or ranges"
            );
        }
    }

    #[test]
    fn a_path_must_not_hold_a_nul_byte() {
        assert_eq!(
            refusal(&[("DOORWARD_DATABASE", "/var/lib/a\u{0}b")]),
            "DOORWARD_DATABASE must be a path"
        );
    }

    #[test]
    fn a_public_url_must_be_absolute() {
        assert_eq!(
            refusal(&[("DOORWARD_PUBLIC_URL", "gateway.example.com")]),
            "DOORWARD_PUBLIC_URL must be a URL"
        );
    }

    #[test]
    fn a_public_url_that_breaks_the_rules_keeps_its_message() {
        assert_eq!(
            refusal(&[("DOORWARD_PUBLIC_URL", "http://doorward.example.com")]),
            "invalid public_url: http is allowed only for a loopback address"
        );
    }

    #[test]
    fn orchestrator_names_are_ignored() {
        let vars = with(&[
            ("DOORWARD_PORT", "arbitrary text"),
            ("DOORWARD_PORT_8717_TCP", "arbitrary text"),
            ("DOORWARD_SERVICE_HOST", "arbitrary text"),
        ]);
        Config::from_sources(None, &vars).expect("orchestrator names must not refuse the start");
    }

    #[test]
    fn an_unknown_name_is_refused_before_any_value_is_read() {
        assert_eq!(
            refusal(&[
                ("DOORWARD_LIMIT_BODY_BYTES", "1"),
                ("DOORWARD_LISTEN", "not-an-address"),
            ]),
            "unknown setting DOORWARD_LIMIT_BODY_BYTES: see docs/DOCKER.md for the list"
        );
    }

    #[test]
    fn the_key_and_the_config_path_are_accepted_names() {
        let key = "0123456789abcdef".repeat(4);
        Config::from_sources(
            None,
            &with(&[("DOORWARD_KEY", key.as_str()), ("DOORWARD_CONFIG", "")]),
        )
        .expect("DOORWARD_KEY and DOORWARD_CONFIG are not settings but are accepted");
    }

    #[test]
    fn an_empty_variable_is_unset() {
        let config = Config::from_sources(
            None,
            &with(&[
                ("DOORWARD_LIMITS_BODY_BYTES", ""),
                ("DOORWARD_TRUSTED_PROXIES", ""),
                ("DOORWARD_KEY_FILE", ""),
            ]),
        )
        .expect("empty values are unset");
        assert_eq!(config.limits.body_bytes, 1_048_576);
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.key_file, None);
    }

    #[test]
    fn an_empty_variable_leaves_the_file_value() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("doorward.toml");
        std::fs::write(&path, "listen = \"127.0.0.1:8719\"\n").expect("write config");
        let config = Config::from_sources(Some(&path), &with(&[("DOORWARD_LISTEN", "")]))
            .expect("the file's listen applies");
        assert_eq!(config.listen, SocketAddr::from(([127, 0, 0, 1], 8719)));
    }

    #[test]
    fn a_variable_beats_the_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("doorward.toml");
        std::fs::write(&path, "listen = \"127.0.0.1:8719\"\n").expect("write config");
        let config =
            Config::from_sources(Some(&path), &with(&[("DOORWARD_LISTEN", "127.0.0.1:8720")]))
                .expect("the variable applies");
        assert_eq!(config.listen, SocketAddr::from(([127, 0, 0, 1], 8720)));
    }

    #[test]
    fn a_missing_public_url_is_named() {
        let vars: Vec<(String, String)> = vec![(
            "DOORWARD_DATABASE".to_owned(),
            "/var/lib/doorward/doorward.db".to_owned(),
        )];
        let err = Config::from_sources(None, &vars).expect_err("public_url is required");
        assert_eq!(
            err.to_string(),
            "public_url is required: set it in the config file or as DOORWARD_PUBLIC_URL"
        );
    }

    #[test]
    fn the_file_may_hold_the_required_settings() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("doorward.toml");
        std::fs::write(&path, "database = \"/var/lib/doorward/doorward.db\"\n")
            .expect("write config");
        let vars = vec![(
            "DOORWARD_PUBLIC_URL".to_owned(),
            "https://doorward.example.com".to_owned(),
        )];
        Config::from_sources(Some(&path), &vars).expect("the file and the variables together load");
    }

    #[test]
    fn a_list_holds_its_entries_trimmed() {
        let config = Config::from_sources(
            None,
            &with(&[("DOORWARD_TRUSTED_PROXIES", "127.0.0.1 , 2001:db8::/32")]),
        )
        .expect("the list loads");
        assert_eq!(
            config.trusted_proxies,
            vec![range("127.0.0.1"), range("2001:db8::/32")]
        );
    }

    #[test]
    fn a_true_flag_is_read() {
        let config =
            Config::from_sources(None, &with(&[("DOORWARD_SHARED_CLIENT_ADDRESS", "true")]))
                .expect("the flag loads");
        assert!(config.shared_client_address);
    }

    #[test]
    fn the_ceiling_and_activity_defaults_apply() {
        let config = Config::from_sources(None, &with(&[])).expect("the defaults load");
        assert_eq!(config.limits.account_ceiling, 50);
        assert_eq!(config.limits.activity_days, 90);
        assert_eq!(Limits::default().account_ceiling, 50);
        assert_eq!(Limits::default().activity_days, 90);
    }

    #[test]
    fn a_ceiling_below_the_failures_is_refused() {
        assert_eq!(
            refusal(&[("DOORWARD_LIMITS_ACCOUNT_CEILING", "4")]),
            "invalid config: limits.account_ceiling must be at least limits.account_failures"
        );
    }

    #[test]
    fn a_ceiling_equal_to_the_failures_is_valid() {
        let config = Config::from_sources(None, &with(&[("DOORWARD_LIMITS_ACCOUNT_CEILING", "5")]))
            .expect("a ceiling equal to the failures loads");
        assert_eq!(config.limits.account_ceiling, 5);
    }

    #[test]
    fn an_activity_period_of_zero_is_refused() {
        assert_eq!(
            refusal(&[("DOORWARD_LIMITS_ACTIVITY_DAYS", "0")]),
            "invalid config: limits.activity_days must be at least 1"
        );
    }

    #[test]
    fn an_activity_period_is_read() {
        let config = Config::from_sources(None, &with(&[("DOORWARD_LIMITS_ACTIVITY_DAYS", "7")]))
            .expect("the period loads");
        assert_eq!(config.limits.activity_days, 7);
    }

    fn started(public_url: &str, extra: &[(&str, &str)]) -> Config {
        let mut vars = with(extra);
        vars.retain(|(name, _)| name != "DOORWARD_PUBLIC_URL");
        vars.push(("DOORWARD_PUBLIC_URL".to_owned(), public_url.to_owned()));
        Config::from_sources(None, &vars).expect("the configuration loads")
    }

    #[test]
    fn https_without_a_proxy_refuses_with_the_fix() {
        let config = started("https://doorward.example.com", &[]);
        let err = config.start_check().expect_err("the start must be refused");
        assert!(matches!(err, ConfigError::ProxyRequired));
        let text = err.to_string();
        assert!(text.contains("trusted_proxies"), "{text}");
        assert!(text.contains("shared_client_address"), "{text}");
        assert!(
            text.lines()
                .any(|line| line == "trusted_proxies = [\"127.0.0.1\", \"::1\"]"),
            "the fix must be a line of its own: {text}"
        );
    }

    #[test]
    fn the_opt_out_logs_its_line() {
        let config = started(
            "https://doorward.example.com",
            &[("DOORWARD_SHARED_CLIENT_ADDRESS", "true")],
        );
        assert_eq!(
            config.start_check().expect("the opt-out starts"),
            Some("doorward: shared_client_address is set: every visitor shares one address for sign-in throttling and rate limits".to_owned())
        );
    }

    #[test]
    fn a_proxy_needs_no_check() {
        let proxied = started(
            "https://doorward.example.com",
            &[("DOORWARD_TRUSTED_PROXIES", "127.0.0.1")],
        );
        assert_eq!(proxied.start_check().expect("starts"), None);
        let both = started(
            "https://doorward.example.com",
            &[
                ("DOORWARD_TRUSTED_PROXIES", "127.0.0.1"),
                ("DOORWARD_SHARED_CLIENT_ADDRESS", "true"),
            ],
        );
        assert_eq!(both.start_check().expect("starts"), None);
    }

    #[test]
    fn loopback_http_needs_no_check() {
        let config = started("http://127.0.0.1:8717", &[]);
        assert_eq!(config.start_check().expect("starts"), None);
    }

    #[test]
    fn a_loopback_https_address_is_not_a_public_install() {
        assert!(!started("https://localhost", &[]).https_public());
        assert!(!started("https://127.0.0.1:8717", &[]).https_public());
        assert!(started("https://doorward.example.com", &[]).https_public());
        assert!(!started("http://127.0.0.1:8717", &[]).https_public());
    }

    /// The `allowed_origins` of a load with `value` as the variable.
    fn origins_of(value: &str) -> Vec<String> {
        Config::from_sources(None, &with(&[("DOORWARD_ALLOWED_ORIGINS", value)]))
            .expect("the list loads")
            .allowed_origins
    }

    /// The refusal of a load with `entries` joined by commas as the variable.
    fn origins_refusal(entries: &[String]) -> String {
        let joined = entries.join(",");
        refusal(&[("DOORWARD_ALLOWED_ORIGINS", joined.as_str())])
    }

    /// The refusal of a config file whose `allowed_origins` is the TOML array `list`.
    fn file_origins_refusal(list: &str) -> String {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("doorward.toml");
        std::fs::write(&path, format!("allowed_origins = {list}\n")).expect("write config");
        Config::from_sources(Some(&path), &with(&[]))
            .expect_err("the list must be refused")
            .to_string()
    }

    #[test]
    fn origins_are_read_from_the_variable_in_order() {
        assert_eq!(
            origins_of("chrome-extension://abcdefghijklmnop,https://gw.example.com:8443"),
            vec![
                "chrome-extension://abcdefghijklmnop".to_owned(),
                "https://gw.example.com:8443".to_owned(),
            ]
        );
    }

    #[test]
    fn an_empty_variable_means_no_origins() {
        assert!(origins_of("").is_empty());
    }

    #[test]
    fn any_scheme_with_a_host_and_port_is_accepted() {
        let list = origins_of("http://127.0.0.1:8717,moz-extension://abcdefghijklmnop");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn a_file_list_loads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("doorward.toml");
        std::fs::write(
            &path,
            "allowed_origins = [\"chrome-extension://abcdefghijklmnop\"]\n",
        )
        .expect("write config");
        let config = Config::from_sources(Some(&path), &with(&[])).expect("the list loads");
        assert_eq!(
            config.allowed_origins,
            vec!["chrome-extension://abcdefghijklmnop".to_owned()]
        );
    }

    #[test]
    fn a_nul_byte_is_refused_as_not_text() {
        assert_eq!(
            refusal(&[("DOORWARD_ALLOWED_ORIGINS", "a\u{0}b")]),
            "DOORWARD_ALLOWED_ORIGINS must be a comma separated list of origins"
        );
    }

    #[test]
    fn a_wildcard_and_null_are_refused() {
        assert_eq!(
            origins_refusal(&["*".to_owned()]),
            r#"invalid config: allowed_origins entry "*" is a wildcard, not an origin"#
        );
        assert_eq!(
            origins_refusal(&["null".to_owned()]),
            r#"invalid config: allowed_origins entry "null" is not an origin"#
        );
    }

    #[test]
    fn an_empty_entry_is_refused() {
        assert_eq!(
            origins_refusal(&["https://a.example.com".to_owned(), String::new()]),
            "invalid config: allowed_origins has an empty entry"
        );
        assert_eq!(
            file_origins_refusal("[\"\"]"),
            "invalid config: allowed_origins has an empty entry"
        );
    }

    #[test]
    fn an_entry_must_be_a_scheme_and_a_host() {
        for entry in ["example.com", "://gw.example.com", "https://"] {
            assert_eq!(
                origins_refusal(&[entry.to_owned()]),
                format!(
                    r#"invalid config: allowed_origins entry "{entry}" must be scheme://host[:port]"#
                ),
                "{entry} must be refused"
            );
        }
    }

    #[test]
    fn a_path_query_fragment_or_trailing_slash_is_refused() {
        for entry in [
            "https://gw.example.com/",
            "https://gw.example.com/x",
            "https://gw.example.com?x=1",
            "https://gw.example.com#x",
        ] {
            assert_eq!(
                origins_refusal(&[entry.to_owned()]),
                format!(
                    r#"invalid config: allowed_origins entry "{entry}" has a path, query, fragment or trailing slash"#
                ),
                "{entry} must be refused"
            );
        }
    }

    #[test]
    fn bytes_outside_visible_ascii_are_refused_and_shown_as_question_marks() {
        assert_eq!(
            origins_refusal(&["https://gw.example.com ".to_owned()]),
            r#"invalid config: allowed_origins entry "https://gw.example.com?" has a character outside visible ASCII"#
        );
        assert_eq!(
            origins_refusal(&["https://ex\u{e9}mple.example.com".to_owned()]),
            r#"invalid config: allowed_origins entry "https://ex?mple.example.com" has a character outside visible ASCII"#
        );
    }

    #[test]
    fn an_entry_of_256_bytes_loads_and_one_of_257_is_refused_cut_to_200_characters() {
        let at_limit = format!("https://{}", "a".repeat(248));
        assert_eq!(at_limit.len(), 256);
        assert_eq!(origins_of(&at_limit), vec![at_limit.clone()]);
        let over = format!("https://{}", "a".repeat(249));
        assert_eq!(
            origins_refusal(&[over]),
            format!(
                r#"invalid config: allowed_origins entry "https://{}" is over 256 bytes"#,
                "a".repeat(192)
            )
        );
    }

    #[test]
    fn at_most_32_origins_are_allowed() {
        let list: Vec<String> = (0..32)
            .map(|index| format!("https://h{index}.example.com"))
            .collect();
        assert_eq!(origins_of(&list.join(",")).len(), 32);
        let mut more = list.clone();
        more.push("https://h32.example.com".to_owned());
        assert_eq!(
            origins_refusal(&more),
            "invalid config: allowed_origins has 33 entries, at most 32 are allowed"
        );
    }

    #[test]
    fn a_file_list_is_checked_like_the_variable() {
        assert_eq!(
            file_origins_refusal(r#"["https://gw.example.com", "*"]"#),
            r#"invalid config: allowed_origins entry "*" is a wildcard, not an origin"#
        );
    }
}
