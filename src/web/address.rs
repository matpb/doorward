use std::net::{IpAddr, Ipv6Addr};

use axum::http::HeaderMap;

/// The client address: the peer, or the right-most untrusted X-Forwarded-For entry behind a trusted proxy.
pub fn client_address(peer: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    let peer = peer.to_canonical();
    if !is_trusted(peer, trusted) {
        return peer;
    }
    let mut entries: Vec<&str> = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(text) = value.to_str() else {
            return peer;
        };
        entries.extend(text.split(',').map(str::trim));
    }
    for entry in entries.iter().rev() {
        match entry.parse::<IpAddr>() {
            Ok(ip) if is_trusted(ip.to_canonical(), trusted) => continue,
            Ok(ip) => return ip.to_canonical(),
            Err(_) => return peer,
        }
    }
    peer
}

/// The login throttle key: the address for IPv4, the address with its low 64 bits zeroed for IPv6.
pub fn throttle_key(address: IpAddr) -> String {
    const LOW_64: u128 = u64::MAX as u128;
    match address.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => Ipv6Addr::from(u128::from(v6) & !LOW_64).to_string(),
    }
}

fn is_trusted(ip: IpAddr, trusted: &[IpAddr]) -> bool {
    trusted.iter().any(|proxy| proxy.to_canonical() == ip)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                "x-forwarded-for",
                HeaderValue::from_str(value).expect("header value"),
            );
        }
        headers
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    #[test]
    fn an_untrusted_peer_is_the_client() {
        let headers = forwarded(&["198.51.100.1"]);
        assert_eq!(
            client_address(ip("203.0.113.9"), &headers, &[]),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn the_right_most_untrusted_entry_is_the_client() {
        let headers = forwarded(&["203.0.113.6, 203.0.113.5"]);
        let trusted = [ip("127.0.0.1")];
        assert_eq!(
            client_address(ip("127.0.0.1"), &headers, &trusted),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn trusted_entries_are_skipped() {
        let headers = forwarded(&["203.0.113.5", "127.0.0.1"]);
        let trusted = [ip("127.0.0.1")];
        assert_eq!(
            client_address(ip("127.0.0.1"), &headers, &trusted),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn an_unparseable_entry_is_only_read_when_it_is_the_right_most() {
        let headers = forwarded(&["garbage, 203.0.113.5"]);
        let trusted = [ip("127.0.0.1")];
        assert_eq!(
            client_address(ip("127.0.0.1"), &headers, &trusted),
            ip("203.0.113.5")
        );
        let headers = forwarded(&["203.0.113.5, garbage"]);
        assert_eq!(
            client_address(ip("127.0.0.1"), &headers, &trusted),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn a_mapped_trusted_peer_is_matched_as_ipv4() {
        let headers = forwarded(&["203.0.113.5"]);
        let trusted = [ip("127.0.0.1")];
        assert_eq!(
            client_address(ip("::ffff:127.0.0.1"), &headers, &trusted),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn ipv6_throttle_key_drops_the_low_64_bits() {
        assert_eq!(throttle_key(ip("2001:db8:1:2:3:4:5:6")), "2001:db8:1:2::");
        assert_eq!(
            throttle_key(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            "2001:db8:1:2::"
        );
    }

    #[test]
    fn ipv4_and_mapped_throttle_keys_are_the_plain_address() {
        assert_eq!(throttle_key(ip("203.0.113.7")), "203.0.113.7");
        assert_eq!(throttle_key(ip("::ffff:203.0.113.7")), "203.0.113.7");
    }
}
