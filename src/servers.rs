//! Upstream servers and who may use them: the rules, and the storage. No HTTP in this module.

use std::collections::HashSet;
use std::fmt;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use url::Url;

use crate::audit::{self, Event};
use crate::crypto::{CryptoError, Keys};
use crate::web::SessionUser;

/// Paths the gateway needs for itself; no server may take one.
pub const RESERVED: [&str; 18] = [
    "-",
    ".well-known",
    "oauth",
    "login",
    "logout",
    "setup",
    "invite",
    "forgot",
    "reset",
    "account",
    "admin",
    "assets",
    "healthz",
    "mcp",
    "signup",
    "register",
    "favicon.ico",
    "robots.txt",
];

/// Header names the gateway never adds upstream, compared in lower case.
const REFUSED_HEADERS: [&str; 13] = [
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "accept",
    "cookie",
    "user-agent",
];

/// Token characters of RFC 9110 besides ASCII letters and digits.
const TOKEN_MARKS: &[u8] = b"!#$%&'*+-.^_`|~";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("The name must be 1 to 100 characters with no control characters.")]
    Name,
    #[error(
        "The path must be 1 to 24 lower-case letters, digits or hyphens, starting with a letter or digit, and not a reserved word."
    )]
    Slug,
    #[error(
        "The upstream address must be an http or https address with a host, and no user name, password or fragment."
    )]
    UpstreamUrl,
    #[error(
        "The secret header name must be a header name of at most 64 characters that the gateway may send; a secret value needs one."
    )]
    SecretName,
    #[error("The secret header value must be visible ASCII or spaces, at most 4096 characters.")]
    SecretValue,
    #[error("Another server already uses that path.")]
    Taken,
    #[error("Choose only users that exist.")]
    UnknownUser,
}

/// The posted form as text. A missing field is empty and a missing checkbox is off.
#[derive(Default, Clone)]
pub struct Draft {
    pub name: String,
    pub slug: String,
    pub upstream_url: String,
    pub secret_header_name: String,
    pub secret_header_value: String,
    pub pass_resources: bool,
    pub pass_prompts: bool,
}

/// Prints every field but the secret value, which prints as `[redacted]`.
impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("name", &self.name)
            .field("slug", &self.slug)
            .field("upstream_url", &self.upstream_url)
            .field("secret_header_name", &self.secret_header_name)
            .field("secret_header_value", &redacted(&self.secret_header_value))
            .field("pass_resources", &self.pass_resources)
            .field("pass_prompts", &self.pass_prompts)
            .finish()
    }
}

/// A secret header to store: the name in lower case, the value not yet sealed.
#[derive(PartialEq, Eq)]
pub struct Secret {
    pub header_name: String,
    pub value: String,
}

/// Prints the value as `[redacted]`, or as empty when there is none.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("header_name", &self.header_name)
            .field("value", &redacted(&self.value))
            .finish()
    }
}

/// What a secret value prints as: `[redacted]`, or empty when the value is empty.
fn redacted(value: &str) -> &'static str {
    if value.is_empty() { "" } else { "[redacted]" }
}

/// A draft that passed the rules.
#[derive(Debug)]
pub struct Settings {
    pub name: String,
    pub slug: String,
    pub upstream_url: String,
    pub pass_resources: bool,
    pub pass_prompts: bool,
    /// None when no secret value was posted.
    pub secret: Option<Secret>,
}

/// What an update does to the stored secret.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretChange<'a> {
    Keep,
    Drop,
    Replace(&'a Secret),
}

/// `[a-z0-9][a-z0-9-]{0,23}` and not a reserved word.
pub fn valid_slug(slug: &str) -> bool {
    let Some((&first, rest)) = slug.as_bytes().split_first() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && rest.len() <= 23
        && rest
            .iter()
            .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !RESERVED.contains(&slug)
}

/// The canonical text of an upstream address, or None. Whitespace, control characters and
/// backslashes are refused before parsing; the result is what `url` serializes.
pub fn upstream_url(text: &str) -> Option<String> {
    if text
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return None;
    }
    let url = Url::parse(text).ok()?;
    let plain = matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none();
    plain.then(|| url.as_str().to_owned())
}

/// True when `text` is an upstream address that `upstream_url` accepts.
pub fn valid_upstream_url(text: &str) -> bool {
    upstream_url(text).is_some()
}

/// A header name the gateway may add for an upstream: an HTTP token, at most 64 characters,
/// and none of the refused names below.
pub fn valid_secret_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || TOKEN_MARKS.contains(&byte))
        && !REFUSED_HEADERS.contains(&lower.as_str())
        && !lower.starts_with("proxy-")
        && !lower.starts_with("mcp-")
}

/// Visible ASCII and spaces only (no control characters), at most 4096 characters.
pub fn valid_secret_header_value(value: &str) -> bool {
    value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

/// The trimmed name when it is 1 to 100 characters with no control characters.
pub fn clean_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let count = trimmed.chars().count();
    let fits = (1..=100).contains(&count);
    if fits && !trimmed.chars().any(char::is_control) {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

/// Checks a draft in the order name, slug, upstream address, secret pair.
pub fn check(draft: &Draft) -> Result<Settings, Refusal> {
    let name = clean_name(&draft.name).ok_or(Refusal::Name)?;
    if !valid_slug(&draft.slug) {
        return Err(Refusal::Slug);
    }
    let upstream_url = upstream_url(&draft.upstream_url).ok_or(Refusal::UpstreamUrl)?;
    let secret = secret_of(draft)?;
    Ok(Settings {
        name,
        slug: draft.slug.clone(),
        upstream_url,
        pass_resources: draft.pass_resources,
        pass_prompts: draft.pass_prompts,
        secret,
    })
}

/// No secret when the value is empty, whatever the name says; a value needs a valid name.
fn secret_of(draft: &Draft) -> Result<Option<Secret>, Refusal> {
    if draft.secret_header_value.is_empty() {
        return Ok(None);
    }
    if !valid_secret_header_name(&draft.secret_header_name) {
        return Err(Refusal::SecretName);
    }
    if !valid_secret_header_value(&draft.secret_header_value) {
        return Err(Refusal::SecretValue);
    }
    Ok(Some(Secret {
        header_name: draft.secret_header_name.to_ascii_lowercase(),
        value: draft.secret_header_value.clone(),
    }))
}

/// What an update does to the stored secret: a posted value replaces it, a removal drops it,
/// and an address change without a value drops it; otherwise it is kept.
pub fn secret_change<'a>(
    stored_url: &str,
    settings: &'a Settings,
    remove: bool,
) -> SecretChange<'a> {
    match &settings.secret {
        _ if remove => SecretChange::Drop,
        Some(secret) => SecretChange::Replace(secret),
        None if stored_url == settings.upstream_url => SecretChange::Keep,
        None => SecretChange::Drop,
    }
}

/// Which assignments a call replaces: every user of one server, or every server of one user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Server(i64),
    User(i64),
}

/// The (user id, server id) pairs that a replacement removed.
pub type Removed = Vec<(i64, i64)>;

/// A stored server as the settings page reads it. The secret value is never loaded.
#[derive(Debug)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub upstream_url: String,
    pub secret_header_name: String,
    pub has_secret: bool,
    pub pass_resources: bool,
    pub pass_prompts: bool,
    pub lockdown: String,
    /// The fixed message of the last failed tool refresh, until a refresh succeeds.
    pub catalog_error: Option<String>,
}

/// A server's id, name and path, for lists.
#[derive(Debug)]
pub struct ServerRef {
    pub id: i64,
    pub name: String,
    pub slug: String,
}

/// A server with whether one user is assigned to it.
#[derive(Debug)]
pub struct ServerChoice {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub assigned: bool,
}

/// A user with whether it is assigned to one server.
#[derive(Debug)]
pub struct UserChoice {
    pub id: i64,
    pub email: String,
    pub assigned: bool,
}

/// The context a secret value is sealed under, bound to its row id.
fn secret_context(id: i64) -> String {
    format!("servers.secret_header_value:{id}")
}

/// The sealed text of a secret value, bound to its row id.
pub fn seal(keys: &Keys, id: i64, value: &str) -> Result<String, CryptoError> {
    keys.seal(&secret_context(id), value.as_bytes())
}

/// The secret value of a sealed text, bound to its row id (the context `seal` uses).
pub fn open_secret(keys: &Keys, id: i64, sealed: &str) -> Result<String, CryptoError> {
    let bytes = keys.open(&secret_context(id), sealed)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::Open)
}

/// What the proxy needs of one server; the sealed secret is opened only by `open_secret`.
pub struct Upstream {
    pub slug: String,
    pub upstream_url: String,
    pub secret_header_name: String,
    pub sealed_secret: Option<String>,
}

/// The proxy's view of one server, or None when no row has the id.
pub fn load_upstream(conn: &Connection, id: i64) -> rusqlite::Result<Option<Upstream>> {
    conn.query_row(
        "SELECT slug, upstream_url, secret_header_name, secret_header_value \
         FROM servers WHERE id = ?1",
        params![id],
        |row| {
            Ok(Upstream {
                slug: row.get(0)?,
                upstream_url: row.get(1)?,
                secret_header_name: row.get(2)?,
                sealed_secret: row.get(3)?,
            })
        },
    )
    .optional()
}

/// True when a user with this id exists.
pub fn user_exists(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1)",
        [id],
        |row| row.get(0),
    )
}

/// True when a server with this id exists.
pub fn server_exists(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM servers WHERE id = ?1)",
        [id],
        |row| row.get(0),
    )
}

/// Every server by id, oldest first.
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<ServerRef>> {
    let mut statement = conn.prepare("SELECT id, name, slug FROM servers ORDER BY id")?;
    let rows = statement.query_map([], |row| {
        Ok(ServerRef {
            id: row.get(0)?,
            name: row.get(1)?,
            slug: row.get(2)?,
        })
    })?;
    rows.collect()
}

/// A server whose last lock-down check found it open: its id and its name.
#[derive(Debug)]
pub struct OpenServer {
    pub id: i64,
    pub name: String,
}

/// Every server whose lock-down state is open, by name.
pub fn open_servers(conn: &Connection) -> rusqlite::Result<Vec<OpenServer>> {
    let mut statement =
        conn.prepare("SELECT id, name FROM servers WHERE lockdown = 'open' ORDER BY name, id")?;
    let rows = statement.query_map([], |row| {
        Ok(OpenServer {
            id: row.get(0)?,
            name: row.get(1)?,
        })
    })?;
    rows.collect()
}

/// How many servers are not checked: every state but open and ok, and an ok without a secret header (nosecret).
pub fn unchecked_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM servers WHERE lockdown NOT IN ('open', 'ok') \
         OR (lockdown = 'ok' AND secret_header_value IS NULL)",
        [],
        |row| row.get(0),
    )
}

/// One server, or None when no row has the id.
pub fn load(conn: &Connection, id: i64) -> rusqlite::Result<Option<Server>> {
    conn.query_row(
        "SELECT id, name, slug, upstream_url, secret_header_name, \
         secret_header_value IS NOT NULL, pass_resources, pass_prompts, lockdown, catalog_error \
         FROM servers WHERE id = ?1",
        params![id],
        |row| {
            Ok(Server {
                id: row.get(0)?,
                name: row.get(1)?,
                slug: row.get(2)?,
                upstream_url: row.get(3)?,
                secret_header_name: row.get(4)?,
                has_secret: row.get(5)?,
                pass_resources: row.get(6)?,
                pass_prompts: row.get(7)?,
                lockdown: row.get(8)?,
                catalog_error: row.get(9)?,
            })
        },
    )
    .optional()
}

/// Every server with whether the user is assigned to it.
pub fn server_choices(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<ServerChoice>> {
    let mut statement = conn.prepare(
        "SELECT id, name, slug, EXISTS (SELECT 1 FROM user_servers \
         WHERE user_servers.server_id = servers.id AND user_servers.user_id = ?1) \
         FROM servers ORDER BY id",
    )?;
    let rows = statement.query_map(params![user_id], |row| {
        Ok(ServerChoice {
            id: row.get(0)?,
            name: row.get(1)?,
            slug: row.get(2)?,
            assigned: row.get(3)?,
        })
    })?;
    rows.collect()
}

/// Every user with whether it is assigned to the server.
pub fn user_choices(conn: &Connection, server_id: i64) -> rusqlite::Result<Vec<UserChoice>> {
    let mut statement = conn.prepare(
        "SELECT id, email, EXISTS (SELECT 1 FROM user_servers \
         WHERE user_servers.user_id = users.id AND user_servers.server_id = ?1) \
         FROM users ORDER BY id",
    )?;
    let rows = statement.query_map(params![server_id], |row| {
        Ok(UserChoice {
            id: row.get(0)?,
            email: row.get(1)?,
            assigned: row.get(2)?,
        })
    })?;
    rows.collect()
}

/// Inserts the row without a secret and returns its id, or None when the path is taken.
pub fn insert(
    tx: &Transaction<'_>,
    settings: &Settings,
    created_at: i64,
) -> rusqlite::Result<Option<i64>> {
    let result = tx.execute(
        "INSERT INTO servers (name, slug, upstream_url, pass_resources, pass_prompts, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            settings.name,
            settings.slug,
            settings.upstream_url,
            settings.pass_resources,
            settings.pass_prompts,
            created_at
        ],
    );
    match result {
        Ok(_) => Ok(Some(tx.last_insert_rowid())),
        Err(err) if is_taken(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Writes the settings and the lock-down state; false when the path is taken.
pub fn update(
    tx: &Transaction<'_>,
    id: i64,
    settings: &Settings,
    lockdown: &str,
) -> rusqlite::Result<bool> {
    let result = tx.execute(
        "UPDATE servers SET name = ?1, slug = ?2, upstream_url = ?3, pass_resources = ?4, \
         pass_prompts = ?5, lockdown = ?6 WHERE id = ?7",
        params![
            settings.name,
            settings.slug,
            settings.upstream_url,
            settings.pass_resources,
            settings.pass_prompts,
            lockdown,
            id
        ],
    );
    match result {
        Ok(_) => Ok(true),
        Err(err) if is_taken(&err) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Stores the secret header name and its sealed value; None removes the value.
pub fn set_secret(
    tx: &Transaction<'_>,
    id: i64,
    header_name: &str,
    sealed: Option<&str>,
) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE servers SET secret_header_name = ?1, secret_header_value = ?2 WHERE id = ?3",
        params![header_name, sealed, id],
    )?;
    Ok(())
}

/// The row a dashboard chart points at, which takes the chart with it when it is deleted.
#[derive(Clone, Copy)]
pub enum Owner {
    Server,
    User,
}

/// Deletes the row, and first records one admin_change row per dashboard chart that goes with it.
/// Its assignments go with it.
pub fn delete(tx: &Transaction<'_>, id: i64, actor: &SessionUser, at: i64) -> rusqlite::Result<()> {
    record_removed_charts(tx, actor, at, Owner::Server, id)?;
    tx.execute("DELETE FROM servers WHERE id = ?1", params![id])?;
    Ok(())
}

/// Writes one admin_change row per dashboard chart that deleting `owner` `id` removes, as the actor
/// at the application clock. Call it before the delete.
pub fn record_removed_charts(
    tx: &Transaction<'_>,
    actor: &SessionUser,
    at: i64,
    owner: Owner,
    id: i64,
) -> rusqlite::Result<()> {
    let (sql, reason) = match owner {
        Owner::Server => (
            "SELECT charts.title, dashboards.name FROM charts \
             JOIN dashboards ON dashboards.id = charts.dashboard_id \
             WHERE charts.server_id = ?1 ORDER BY charts.id",
            "its server was deleted",
        ),
        Owner::User => (
            "SELECT charts.title, dashboards.name FROM charts \
             JOIN dashboards ON dashboards.id = charts.dashboard_id \
             WHERE charts.user_id = ?1 ORDER BY charts.id",
            "its user was deleted",
        ),
    };
    let charts: Vec<(String, String)> = {
        let mut statement = tx.prepare(sql)?;
        let rows = statement.query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for (title, dashboard) in charts {
        let detail = format!("deleted chart {title} from dashboard {dashboard}: {reason}");
        let change = Event {
            kind: "admin_change",
            user_id: Some(actor.id),
            user_email: &actor.email,
            detail: &detail,
            ..Default::default()
        };
        audit::record(tx, at, &change)?;
    }
    Ok(())
}

/// Makes `ids` the whole set for `scope` and returns the pairs it removed, in key order.
/// The caller's transaction must be open; every write of the replacement happens in it.
pub fn set_assignments(
    tx: &Transaction<'_>,
    scope: Scope,
    ids: &[i64],
) -> rusqlite::Result<Removed> {
    let wanted: HashSet<(i64, i64)> = ids.iter().map(|&other| pair(scope, other)).collect();
    let mut removed = Vec::new();
    for (user, server) in assigned_pairs(tx, scope)? {
        if !wanted.contains(&(user, server)) {
            tx.execute(
                "DELETE FROM user_servers WHERE user_id = ?1 AND server_id = ?2",
                params![user, server],
            )?;
            removed.push((user, server));
        }
    }
    for (user, server) in wanted {
        tx.execute(
            "INSERT OR IGNORE INTO user_servers (user_id, server_id) VALUES (?1, ?2)",
            params![user, server],
        )?;
    }
    Ok(removed)
}

/// The (user, server) pair that the other id makes with the scope's id.
fn pair(scope: Scope, other: i64) -> (i64, i64) {
    match scope {
        Scope::Server(server) => (other, server),
        Scope::User(user) => (user, other),
    }
}

/// The current pairs of the scope, in key order.
fn assigned_pairs(conn: &Connection, scope: Scope) -> rusqlite::Result<Vec<(i64, i64)>> {
    let (sql, key) = match scope {
        Scope::Server(id) => (
            "SELECT user_id, server_id FROM user_servers WHERE server_id = ?1 ORDER BY user_id",
            id,
        ),
        Scope::User(id) => (
            "SELECT user_id, server_id FROM user_servers WHERE user_id = ?1 ORDER BY server_id",
            id,
        ),
    };
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map(params![key], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

/// The UNIQUE constraint of a path, the only uniqueness a server write can meet.
fn is_taken(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(code, _)
            if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Draft {
        Draft {
            name: "Demo".into(),
            slug: "demo".into(),
            upstream_url: "https://mcp.example.com/mcp".into(),
            ..Draft::default()
        }
    }

    #[test]
    fn a_draft_debug_prints_its_secret_as_redacted() {
        let draft = Draft {
            secret_header_name: "x-upstream-secret".into(),
            secret_header_value: "draft-secret-text".into(),
            ..draft()
        };
        let shown = format!("{draft:?}");
        assert!(
            !shown.contains("draft-secret-text"),
            "the secret must not print: {shown}"
        );
        assert!(
            shown.contains("[redacted]"),
            "the secret must print as [redacted]: {shown}"
        );
        assert!(
            shown.contains("x-upstream-secret"),
            "the header name stays visible: {shown}"
        );
    }

    #[test]
    fn a_draft_without_a_secret_prints_the_value_as_empty() {
        let shown = format!("{:?}", draft());
        assert!(
            shown.contains(r#"secret_header_value: """#),
            "an absent secret must print as empty: {shown}"
        );
    }

    #[test]
    fn a_secret_debug_prints_its_value_as_redacted() {
        let secret = Secret {
            header_name: "x-upstream-secret".into(),
            value: "secret-value-text".into(),
        };
        let shown = format!("{secret:?}");
        assert!(
            !shown.contains("secret-value-text"),
            "the value must not print: {shown}"
        );
        assert!(
            shown.contains("[redacted]"),
            "the value must print as [redacted]: {shown}"
        );
    }

    #[test]
    fn a_secret_without_a_value_prints_the_value_as_empty() {
        let secret = Secret {
            header_name: "x-upstream-secret".into(),
            value: String::new(),
        };
        assert!(
            format!("{secret:?}").contains(r#"value: """#),
            "an empty value must print as empty"
        );
    }

    #[test]
    fn valid_slug_refuses_every_reserved_word() {
        for word in RESERVED {
            assert!(!valid_slug(word), "{word:?} is reserved");
        }
    }

    #[test]
    fn valid_slug_refuses_bad_shapes() {
        let long = "a".repeat(25);
        for slug in ["Bad", "a_b", long.as_str(), "", "-a", "a/b", "a.b"] {
            assert!(!valid_slug(slug), "{slug:?} is not a slug");
        }
    }

    #[test]
    fn valid_slug_accepts_the_edges() {
        let longest = "a".repeat(24);
        for slug in ["a", "0", "a-b-1", longest.as_str()] {
            assert!(valid_slug(slug), "{slug:?} is a slug");
        }
    }

    #[test]
    fn an_upstream_address_is_stored_as_its_canonical_text() {
        assert_eq!(
            upstream_url("http://@example.com/").as_deref(),
            Some("http://example.com/")
        );
        assert_eq!(
            upstream_url("https://MCP.Example.com").as_deref(),
            Some("https://mcp.example.com/")
        );
        assert_eq!(
            upstream_url("http://127.0.0.1:9000/mcp").as_deref(),
            Some("http://127.0.0.1:9000/mcp")
        );
        assert_eq!(
            upstream_url("https://mcp.example.com/mcp").as_deref(),
            Some("https://mcp.example.com/mcp")
        );
    }

    #[test]
    fn an_upstream_address_with_whitespace_control_or_backslash_is_refused() {
        for text in [
            "http://exa\tmple.com/",
            " http://example.com/",
            "http://example.com/ ",
            "http:\\\\example.com\\mcp",
            "http://example.com/a b",
            "http://example.com/\n",
        ] {
            assert_eq!(upstream_url(text), None, "{text:?} is refused");
            assert!(!valid_upstream_url(text), "{text:?} is refused");
        }
    }

    #[test]
    fn a_checked_draft_stores_the_canonical_address() {
        let mut upper = draft();
        upper.upstream_url = "https://MCP.Example.com/mcp".into();
        let settings = check(&upper).expect("valid");
        assert_eq!(settings.upstream_url, "https://mcp.example.com/mcp");
    }

    #[test]
    fn upstream_urls_must_be_plain_http_or_https() {
        for text in [
            "file:///etc/passwd",
            "ftp://example.com/",
            "javascript:alert(1)",
            "not a url",
            "http://user:pass@example.com/mcp",
            "http://user@example.com/mcp",
            "https://example.com/mcp#x",
        ] {
            assert!(!valid_upstream_url(text), "{text:?} is refused");
        }
        for text in ["http://127.0.0.1:9000/mcp", "https://mcp.example.com/mcp"] {
            assert!(valid_upstream_url(text), "{text:?} is accepted");
        }
    }

    #[test]
    fn refused_header_names_are_refused_in_any_case() {
        for name in REFUSED_HEADERS {
            assert!(!valid_secret_header_name(name), "{name} is refused");
            assert!(
                !valid_secret_header_name(&name.to_uppercase()),
                "{name} is refused"
            );
        }
        for name in ["Proxy-Auth", "proxy-x", "MCP-Method", "mcp-name"] {
            assert!(!valid_secret_header_name(name), "{name} is refused");
        }
    }

    #[test]
    fn bad_header_names_are_refused() {
        let long = "x".repeat(65);
        for name in ["x y", "", "a:b", long.as_str()] {
            assert!(!valid_secret_header_name(name), "{name:?} is refused");
        }
        let longest = "x".repeat(64);
        assert!(valid_secret_header_name(&longest));
    }

    #[test]
    fn upstream_header_names_are_accepted() {
        for name in ["x-upstream-secret", "Authorization"] {
            assert!(valid_secret_header_name(name), "{name} is accepted");
        }
    }

    #[test]
    fn secret_values_are_visible_ascii_and_spaces_up_to_4096() {
        assert!(valid_secret_header_value("s3cret value~"));
        let longest = "v".repeat(4096);
        assert!(valid_secret_header_value(&longest));
        let longer = "v".repeat(4097);
        for value in ["tab\there", "line\nbreak", "nul\u{0}", "ü", longer.as_str()] {
            assert!(!valid_secret_header_value(value), "{value:?} is refused");
        }
    }

    #[test]
    fn names_are_trimmed_and_limited_to_100_characters() {
        assert_eq!(clean_name("  Demo  ").as_deref(), Some("Demo"));
        assert_eq!(clean_name("   "), None);
        assert_eq!(clean_name("").map(|name| name.len()), None);
        assert_eq!(
            clean_name(&"n".repeat(100)).map(|name| name.len()),
            Some(100)
        );
        assert_eq!(clean_name(&"n".repeat(101)), None);
        assert_eq!(
            clean_name(&"é".repeat(100)).map(|name| name.chars().count()),
            Some(100)
        );
        assert_eq!(clean_name("a\tb"), None);
    }

    #[test]
    fn a_draft_without_a_secret_value_has_no_secret() {
        let mut named = draft();
        named.secret_header_name = "x y".into();
        let settings = check(&named).expect("valid without a value");
        assert!(settings.secret.is_none());
        assert_eq!(settings.name, "Demo");
    }

    #[test]
    fn each_refusal_names_its_field() {
        let mut bad = draft();
        bad.name = " ".into();
        assert_eq!(check(&bad).err(), Some(Refusal::Name));

        let mut bad = draft();
        bad.slug = "Bad".into();
        assert_eq!(check(&bad).err(), Some(Refusal::Slug));

        let mut bad = draft();
        bad.upstream_url = "ftp://example.com/".into();
        assert_eq!(check(&bad).err(), Some(Refusal::UpstreamUrl));

        let mut bad = draft();
        bad.secret_header_value = "s3cret".into();
        assert_eq!(check(&bad).err(), Some(Refusal::SecretName));

        let mut bad = draft();
        bad.secret_header_name = "x:y".into();
        bad.secret_header_value = "s3cret".into();
        assert_eq!(check(&bad).err(), Some(Refusal::SecretName));

        let mut bad = draft();
        bad.secret_header_name = "x-key".into();
        bad.secret_header_value = "s3cret\u{1}".into();
        assert_eq!(check(&bad).err(), Some(Refusal::SecretValue));
    }

    #[test]
    fn a_secret_name_is_stored_in_lower_case_and_a_zero_value_is_a_secret() {
        let mut keyed = draft();
        keyed.secret_header_name = "Authorization".into();
        keyed.secret_header_value = "0".into();
        let settings = check(&keyed).expect("valid");
        assert_eq!(
            settings.secret,
            Some(Secret {
                header_name: "authorization".into(),
                value: "0".into(),
            })
        );
    }

    #[test]
    fn an_update_decides_the_secret_by_the_address_and_the_post() {
        let plain = check(&draft()).expect("valid");
        let mut keyed = draft();
        keyed.secret_header_name = "x-key".into();
        keyed.secret_header_value = "v1".into();
        let keyed = check(&keyed).expect("valid");
        let stored = "https://mcp.example.com/mcp";
        let moved = "https://other.example.com/mcp";
        assert_eq!(secret_change(stored, &plain, false), SecretChange::Keep);
        assert_eq!(secret_change(moved, &plain, false), SecretChange::Drop);
        assert_eq!(secret_change(stored, &plain, true), SecretChange::Drop);
        assert!(matches!(
            secret_change(moved, &keyed, false),
            SecretChange::Replace(_)
        ));
        assert!(matches!(
            secret_change(stored, &keyed, false),
            SecretChange::Replace(_)
        ));
        assert_eq!(secret_change(stored, &keyed, true), SecretChange::Drop);
    }

    #[tokio::test]
    async fn the_open_servers_are_the_open_ones_by_name() {
        let dir = tempfile::tempdir().expect("dir");
        let db = crate::db::Db::open(&dir.path().join("doorward.db")).expect("open");
        db.call(|conn| {
            for (name, slug, state) in [
                ("Zeta", "zeta", "open"),
                ("Alpha", "alpha", "open"),
                ("Mid", "mid", "ok"),
                ("Beta", "beta", "unknown"),
                ("Gamma", "gamma", "open"),
            ] {
                conn.execute(
                    "INSERT INTO servers (name, slug, upstream_url, lockdown, created_at) \
                     VALUES (?1, ?2, 'https://example.com/mcp', ?3, 0)",
                    params![name, slug, state],
                )?;
            }
            Ok(())
        })
        .await
        .expect("seed");
        let found = db.call(|conn| open_servers(conn)).await.expect("query");
        let pairs: Vec<(i64, &str)> = found.iter().map(|s| (s.id, s.name.as_str())).collect();
        assert_eq!(pairs, [(2, "Alpha"), (5, "Gamma"), (1, "Zeta")]);
        db.call(|conn| {
            conn.execute("UPDATE servers SET lockdown = 'ok'", [])?;
            Ok(())
        })
        .await
        .expect("update");
        let none = db.call(|conn| open_servers(conn)).await.expect("query");
        assert!(none.is_empty(), "no open server must give no rows");
    }
}
