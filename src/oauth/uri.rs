//! The redirect address grammar. Pure: no URL library, so the text checked is the text used.

const MAX_LENGTH: usize = 2000;
const MAX_HOST_LENGTH: usize = 253;
const MAX_SCHEME_LENGTH: usize = 32;
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];
/// Schemes a browser handles itself; never a place to send a code.
const REFUSED_SCHEMES: [&str; 8] = [
    "javascript",
    "data",
    "vbscript",
    "file",
    "blob",
    "about",
    "filesystem",
    "view-source",
];

/// A redirect address in normal form. Borrows from the text it was parsed from.
#[derive(Debug, PartialEq, Eq)]
pub enum Redirect<'a> {
    /// http://127.0.0.1 | localhost | [::1], any port, a path
    Loopback {
        host: &'a str,
        port: Option<&'a str>,
        path: &'a str,
    },
    /// scheme://host/path with no port. `path` may be empty for a private scheme.
    Web {
        scheme: &'a str,
        host: &'a str,
        path: &'a str,
    },
}

/// None unless the WHOLE string matches the grammar.
pub fn parse(text: &str) -> Option<Redirect<'_>> {
    if text.len() > MAX_LENGTH || !text.is_ascii() {
        return None;
    }
    let (scheme, rest) = text.split_once("://")?;
    if !valid_scheme(scheme) || REFUSED_SCHEMES.contains(&scheme) {
        return None;
    }
    let split = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    if !valid_path(path) {
        return None;
    }
    let needs_path = scheme == "http" || scheme == "https";
    if path.is_empty() && needs_path {
        return None;
    }
    if scheme == "http" {
        let (host, port) = loopback_authority(authority)?;
        return Some(Redirect::Loopback { host, port, path });
    }
    if !valid_host(authority) {
        return None;
    }
    Some(Redirect::Web {
        scheme,
        host: authority,
        path,
    })
}

/// True when `requested` may be used by a client that registered `registered`.
/// Web: byte equality. Loopback: same host text and same path; the port is ignored.
pub fn matches(registered: &str, requested: &str) -> bool {
    match (parse(registered), parse(requested)) {
        (
            Some(Redirect::Loopback {
                host: registered_host,
                path: registered_path,
                ..
            }),
            Some(Redirect::Loopback {
                host: requested_host,
                path: requested_path,
                ..
            }),
        ) => registered_host == requested_host && registered_path == requested_path,
        (Some(Redirect::Web { .. }), Some(Redirect::Web { .. })) => registered == requested,
        _ => false,
    }
}

/// The address with a loopback port removed; a web address unchanged.
pub fn redirect_key(redirect: &Redirect<'_>) -> String {
    match redirect {
        Redirect::Loopback { host, path, .. } => format!("http://{host}{path}"),
        Redirect::Web { scheme, host, path } => format!("{scheme}://{host}{path}"),
    }
}

/// `[a-z][a-z0-9+.-]{0,31}`.
fn valid_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    bytes.len() <= MAX_SCHEME_LENGTH
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|&b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
}

/// Empty, or `/` then `[A-Za-z0-9._~-]` and `/`, with no `//` and no `.` or `..` segment.
fn valid_path(path: &str) -> bool {
    let Some(body) = path.strip_prefix('/') else {
        return path.is_empty();
    };
    !path.contains("//")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'/'))
        && body
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

/// The loopback host of an authority, and its port when one is written.
fn loopback_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    LOOPBACK_HOSTS.iter().find_map(|&host| {
        let rest = authority.strip_prefix(host)?;
        if rest.is_empty() {
            return Some((host, None));
        }
        let port = rest.strip_prefix(':')?;
        valid_port(port).then_some((host, Some(port)))
    })
}

/// 1 to 5 digits, no leading zero, value 1 to 65535.
fn valid_port(port: &str) -> bool {
    port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.as_bytes().first().is_some_and(|&b| b != b'0')
        && port.parse::<u16>().is_ok()
}

/// Labels of `[a-z0-9]([a-z0-9-]*[a-z0-9])?` joined by dots; no punycode label; the last
/// label is neither all digits nor `0x` plus hexadecimal digits.
fn valid_host(host: &str) -> bool {
    if host.len() > MAX_HOST_LENGTH {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let Some((last, _)) = labels.split_last() else {
        return false;
    };
    labels
        .iter()
        .all(|label| valid_label(label) && !label.starts_with("xn--"))
        && !reads_as_ipv4(last)
}

fn valid_label(label: &str) -> bool {
    let is_edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match (label.as_bytes().first(), label.as_bytes().last()) {
        (Some(first), Some(last)) => {
            is_edge(first)
                && is_edge(last)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }
        _ => false,
    }
}

/// Browsers read an all-digit last label, or `0x` and hex digits, as an IPv4 address.
fn reads_as_ipv4(last: &str) -> bool {
    let all_digits = last.bytes().all(|b| b.is_ascii_digit());
    let hex = last
        .strip_prefix("0x")
        .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
    all_digits || hex
}
