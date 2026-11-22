//! A server's custom headers: their names and values, their storage, and what a request carries.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::servers;

/// The most custom headers one server declares.
pub const MAX_PER_SERVER: usize = 8;
/// The longest value a declared header may carry, in bytes.
const VALUE_LIMIT: usize = 4096;
/// Names refused beyond the secret rules, compared in lower case.
const REFUSED: [&str; 6] = [
    "origin",
    "referer",
    "last-event-id",
    "forwarded",
    "via",
    "x-real-ip",
];

/// One header a server declares: its row id, its name as typed, the name in lower case, and whether it is required.
pub struct Declared {
    pub id: i64,
    pub name: String,
    pub lower: String,
    pub required: bool,
}

/// A server's declared headers, in declaration order, and its two switches.
pub struct ServerHeaders {
    pub declared: Vec<Declared>,
    pub pass: bool,
    pub store: bool,
}

/// Why a header cannot be declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRefusal {
    Invalid,
    Duplicate,
    Full,
    SecretName,
}

/// What a request to one server carries for one caller.
#[derive(Debug)]
pub enum Resolved {
    Ready(Vec<(HeaderName, HeaderValue)>),
    /// A declared header the client sent twice or with a bad value: HTTP 400.
    Bad,
    /// A required header has no value: nothing is sent to the server.
    Missing {
        header: String,
    },
    /// The caller's connection holds no openable key and a value is held or needed: nothing is sent.
    Locked,
}

/// A header name a server may declare: a valid secret header name, not one the gateway refuses.
pub fn valid_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    servers::valid_secret_header_name(name)
        && !REFUSED.contains(&lower.as_str())
        && !lower.starts_with("x-forwarded-")
}

/// 1 to 4096 bytes, each visible ASCII; a space or a tab is allowed only inside the value.
pub fn valid_value(value: &[u8]) -> bool {
    let len = value.len();
    (1..=VALUE_LIMIT).contains(&len)
        && value.iter().enumerate().all(|(index, &byte)| {
            let inner_blank = matches!(byte, b' ' | b'\t') && index != 0 && index + 1 != len;
            (0x21..=0x7e).contains(&byte) || inner_blank
        })
}

/// The server's declared headers and switches; a missing server has none and both off.
pub fn load(conn: &Connection, server_id: i64) -> rusqlite::Result<ServerHeaders> {
    let switches: Option<(bool, bool)> = conn
        .query_row(
            "SELECT pass_headers, store_headers FROM servers WHERE id = ?1",
            params![server_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (pass, store) = switches.unwrap_or((false, false));
    let mut statement = conn.prepare(
        "SELECT id, name, name_lower, required FROM server_headers \
         WHERE server_id = ?1 ORDER BY id",
    )?;
    let declared = statement
        .query_map(params![server_id], |row| {
            Ok(Declared {
                id: row.get(0)?,
                name: row.get(1)?,
                lower: row.get(2)?,
                required: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<Declared>>>()?;
    Ok(ServerHeaders {
        declared,
        pass,
        store,
    })
}

/// Declares a header inside the caller's transaction; the id, or the refusal.
pub fn add(
    tx: &Transaction<'_>,
    server_id: i64,
    name: &str,
    required: bool,
    now: i64,
) -> rusqlite::Result<Result<i64, AddRefusal>> {
    if !valid_name(name) {
        return Ok(Err(AddRefusal::Invalid));
    }
    let lower = name.to_ascii_lowercase();
    let secret: String = tx.query_row(
        "SELECT secret_header_name FROM servers WHERE id = ?1",
        params![server_id],
        |row| row.get(0),
    )?;
    if secret.eq_ignore_ascii_case(name) {
        return Ok(Err(AddRefusal::SecretName));
    }
    let taken: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM server_headers WHERE server_id = ?1 AND name_lower = ?2)",
        params![server_id, lower],
        |row| row.get(0),
    )?;
    if taken {
        return Ok(Err(AddRefusal::Duplicate));
    }
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM server_headers WHERE server_id = ?1",
        params![server_id],
        |row| row.get(0),
    )?;
    if count >= i64::try_from(MAX_PER_SERVER).unwrap_or(i64::MAX) {
        return Ok(Err(AddRefusal::Full));
    }
    tx.execute(
        "INSERT INTO server_headers (server_id, name, name_lower, required, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![server_id, name, lower, required, now],
    )?;
    Ok(Ok(tx.last_insert_rowid()))
}

/// Removes one declared header of the server; false when no header of that server has the id.
pub fn remove(tx: &Transaction<'_>, server_id: i64, header_id: i64) -> rusqlite::Result<bool> {
    let removed = tx.execute(
        "DELETE FROM server_headers WHERE server_id = ?1 AND id = ?2",
        params![server_id, header_id],
    )?;
    Ok(removed > 0)
}

/// True when the server declares a header whose lower-cased name is `lower`.
pub fn declares(conn: &Connection, server_id: i64, lower: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM server_headers WHERE server_id = ?1 AND name_lower = ?2)",
        params![server_id, lower],
        |row| row.get(0),
    )
}

/// Sets whether a declared header of the server is required; false when no header of that server has the id.
pub fn set_required(
    tx: &Transaction<'_>,
    server_id: i64,
    header_id: i64,
    required: bool,
) -> rusqlite::Result<bool> {
    let updated = tx.execute(
        "UPDATE server_headers SET required = ?1 WHERE server_id = ?2 AND id = ?3",
        params![required, server_id, header_id],
    )?;
    Ok(updated > 0)
}

/// Saves the two switches of the server.
pub fn set_switches(
    tx: &Transaction<'_>,
    server_id: i64,
    pass: bool,
    store: bool,
) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE servers SET pass_headers = ?1, store_headers = ?2 WHERE id = ?3",
        params![pass, store, server_id],
    )?;
    Ok(())
}

/// The headers one request carries: the client's declared values under pass-through, else the stored ones.
pub fn resolve(
    config: &ServerHeaders,
    client: &HeaderMap,
    stored: &[(String, HeaderValue)],
) -> Resolved {
    let mut out = Vec::new();
    for declared in &config.declared {
        // A stored name was validated when declared, so this fails only on a damaged row: fail closed.
        let Ok(header) = HeaderName::from_bytes(declared.lower.as_bytes()) else {
            return Resolved::Bad;
        };
        let sent: Vec<&HeaderValue> = client.get_all(&header).iter().collect();
        if config.pass && declared.lower != "authorization" && !sent.is_empty() {
            match sent.as_slice() {
                [value] if valid_value(value.as_bytes()) => {
                    out.push((header, sensitive((*value).clone())));
                }
                _ => return Resolved::Bad,
            }
        } else if let Some((_, value)) = stored.iter().find(|(name, _)| *name == declared.lower) {
            out.push((header, sensitive(value.clone())));
        } else if declared.required {
            return Resolved::Missing {
                header: declared.name.clone(),
            };
        }
    }
    Resolved::Ready(out)
}

/// The value marked sensitive, so its bytes stay out of debug output.
fn sensitive(mut value: HeaderValue) -> HeaderValue {
    value.set_sensitive(true);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn declared(id: i64, name: &str, required: bool) -> Declared {
        Declared {
            id,
            name: name.to_owned(),
            lower: name.to_ascii_lowercase(),
            required,
        }
    }

    fn config(declared: Vec<Declared>, pass: bool) -> ServerHeaders {
        ServerHeaders {
            declared,
            pass,
            store: false,
        }
    }

    fn client(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    #[test]
    fn a_name_is_refused_by_the_secret_rules_and_the_extra_list() {
        for name in [
            "Host",
            "Cookie",
            "User-Agent",
            "Origin",
            "Referer",
            "Last-Event-ID",
            "Forwarded",
            "Via",
            "X-Real-IP",
            "X-Forwarded-For",
            "X-FORWARDED-host",
            "Mcp-Session-Id",
            "Proxy-Authorization",
            "X Trace",
            "",
        ] {
            assert!(!valid_name(name), "{name:?} is refused");
        }
        let longest = format!("x-{}", "a".repeat(62));
        assert!(valid_name(&longest), "a 64 character name is accepted");
        assert!(
            !valid_name(&format!("{longest}a")),
            "65 characters are refused"
        );
    }

    #[test]
    fn authorization_and_an_ordinary_name_are_accepted() {
        assert!(valid_name("Authorization"));
        assert!(valid_name("X-Trace-Id"));
    }

    #[test]
    fn a_value_is_one_to_4096_visible_bytes_with_inner_blanks() {
        assert!(valid_value(b"a"));
        assert!(valid_value(b"a b\tc"));
        assert!(valid_value(&vec![b'v'; 4096]));
        assert!(!valid_value(b""));
        assert!(!valid_value(&vec![b'v'; 4097]));
        assert!(!valid_value(b" a"), "a leading space is refused");
        assert!(!valid_value(b"a "), "a trailing space is refused");
        assert!(!valid_value(b"\t"), "a lone tab is refused");
        assert!(!valid_value("caf\u{e9}".as_bytes()));
        assert!(!valid_value(&[0x80]));
        assert!(!valid_value(b"a\x7f"));
    }

    #[test]
    fn a_declared_header_the_client_sent_once_is_passed_with_its_value() {
        let config = config(vec![declared(1, "X-Trace-Id", false)], true);
        let sent = client(&[("x-trace-id", "abc")]);
        let Resolved::Ready(headers) = resolve(&config, &sent, &[]) else {
            panic!("the header must resolve");
        };
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "x-trace-id");
        assert_eq!(headers[0].1.to_str().ok(), Some("abc"));
        assert!(headers[0].1.is_sensitive(), "the value is marked sensitive");
    }

    #[test]
    fn a_header_sent_twice_or_with_a_bad_value_is_bad_only_when_passed() {
        let on = config(vec![declared(1, "X-Trace-Id", false)], true);
        let twice = client(&[("x-trace-id", "a"), ("x-trace-id", "b")]);
        assert!(matches!(resolve(&on, &twice, &[]), Resolved::Bad));
        let empty = client(&[("x-trace-id", "")]);
        assert!(matches!(resolve(&on, &empty, &[]), Resolved::Bad));
        let off = config(vec![declared(1, "X-Trace-Id", false)], false);
        let Resolved::Ready(headers) = resolve(&off, &twice, &[]) else {
            panic!("with pass-through off the client's header is ignored");
        };
        assert!(headers.is_empty());
    }

    #[test]
    fn a_required_header_without_a_value_is_missing_under_its_declared_name() {
        let config = config(vec![declared(1, "X-Trace-Id", true)], true);
        let Resolved::Missing { header } = resolve(&config, &client(&[]), &[]) else {
            panic!("a required header with no value is missing");
        };
        assert_eq!(header, "X-Trace-Id");
    }

    #[test]
    fn an_optional_header_without_a_value_changes_nothing() {
        let config = config(vec![declared(1, "X-Trace-Id", false)], true);
        let Resolved::Ready(headers) = resolve(&config, &client(&[]), &[]) else {
            panic!("an optional header may be missing");
        };
        assert!(headers.is_empty());
    }

    #[test]
    fn authorization_and_undeclared_headers_are_never_passed_from_the_client() {
        let config = config(vec![declared(1, "Authorization", false)], true);
        let sent = client(&[("authorization", "Bearer x"), ("x-other", "1")]);
        let Resolved::Ready(headers) = resolve(&config, &sent, &[]) else {
            panic!("authorization is ignored from the client");
        };
        assert!(headers.is_empty());
    }

    #[test]
    fn a_stored_value_is_used_when_the_client_sends_none() {
        let config = config(vec![declared(1, "X-Api-Key", true)], false);
        let stored = [("x-api-key".to_owned(), HeaderValue::from_static("k1"))];
        let Resolved::Ready(headers) = resolve(&config, &client(&[]), &stored) else {
            panic!("the stored value must resolve");
        };
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].1.to_str().ok(), Some("k1"));
        assert!(headers[0].1.is_sensitive());
    }

    #[test]
    fn a_header_that_is_not_declared_is_ignored_and_order_follows_declaration() {
        let config = config(
            vec![declared(1, "X-B", false), declared(2, "X-A", false)],
            true,
        );
        let sent = client(&[("x-a", "1"), ("x-b", "2"), ("x-c", "3")]);
        let Resolved::Ready(headers) = resolve(&config, &sent, &[]) else {
            panic!("both resolve");
        };
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["x-b", "x-a"]);
    }

    #[tokio::test]
    async fn add_refuses_bad_secret_duplicate_and_full_declarations() {
        let dir = tempfile::tempdir().expect("dir");
        let db = Db::open(&dir.path().join("doorward.db")).expect("open");
        let id: i64 = db
            .call(|conn| {
                conn.execute(
                    "INSERT INTO servers (name, slug, upstream_url, secret_header_name, created_at) \
                     VALUES ('Demo', 'demo', 'https://example.com/mcp', 'X-Upstream-Secret', 0)",
                    [],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
            .expect("seed");
        let outcomes = db
            .call(move |conn| {
                let mut seen = Vec::new();
                let tx = conn.transaction()?;
                for name in ["Cookie", "x-upstream-secret", "X-Trace-Id", "x-trace-id"] {
                    seen.push(add(&tx, id, name, false, 0)?);
                }
                for index in 1..MAX_PER_SERVER {
                    seen.push(add(&tx, id, &format!("X-Custom-{index}"), true, 0)?);
                }
                seen.push(add(&tx, id, "X-Custom-9", false, 0)?);
                tx.commit()?;
                Ok(seen)
            })
            .await
            .expect("adds");
        assert_eq!(
            &outcomes[..4],
            &[
                Err(AddRefusal::Invalid),
                Err(AddRefusal::SecretName),
                Ok(1),
                Err(AddRefusal::Duplicate),
            ]
        );
        assert_eq!(
            outcomes.last(),
            Some(&Err(AddRefusal::Full)),
            "a ninth header is full"
        );
        let loaded = db.call(move |conn| load(conn, id)).await.expect("load");
        assert_eq!(loaded.declared.len(), MAX_PER_SERVER);
        assert_eq!(
            loaded.declared[0].lower, "x-trace-id",
            "the first row is kept first"
        );
        assert!(!loaded.pass && !loaded.store, "both switches start off");
    }

    #[tokio::test]
    async fn remove_and_switches_change_only_their_own_rows() {
        let dir = tempfile::tempdir().expect("dir");
        let db = Db::open(&dir.path().join("doorward.db")).expect("open");
        let id: i64 = db
            .call(|conn| {
                conn.execute(
                    "INSERT INTO servers (name, slug, upstream_url, created_at) \
                     VALUES ('Demo', 'demo', 'https://example.com/mcp', 0)",
                    [],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
            .expect("seed");
        let header_id = db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let added = add(&tx, id, "X-Trace-Id", false, 0)?.expect("added");
                set_switches(&tx, id, true, false)?;
                assert!(
                    !remove(&tx, id + 1, added)?,
                    "another server's id removes nothing"
                );
                tx.commit()?;
                Ok(added)
            })
            .await
            .expect("add and switch");
        let loaded = db.call(move |conn| load(conn, id)).await.expect("load");
        assert!(loaded.pass && !loaded.store);
        assert_eq!(loaded.declared.len(), 1);
        let removed = db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let removed = remove(&tx, id, header_id)?;
                tx.commit()?;
                Ok(removed)
            })
            .await
            .expect("remove");
        assert!(removed);
        let loaded = db.call(move |conn| load(conn, id)).await.expect("load");
        assert!(loaded.declared.is_empty());
    }
}
