use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::HeaderMap;

use crate::config::Range;

const NO_FORWARDED_FOR: &str = "doorward: a trusted proxy sent no X-Forwarded-For: its own address is used as the client address";
const PRIVATE_CLIENT: &str = "doorward: the client address is private: the proxy may not pass the real address (rootless Docker, Docker Desktop, a wrong trusted_proxies entry)";

/// The two warnings about the address, each due at most once per `Warned`.
#[derive(Default)]
pub struct Warned {
    no_forwarded_for: AtomicBool,
    private_client: AtomicBool,
}

static WARNED: Warned = Warned {
    no_forwarded_for: AtomicBool::new(false),
    private_client: AtomicBool::new(false),
};

impl Warned {
    /// The warnings this request is due; each is returned by the first request that earns it.
    pub fn due(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
        trusted: &[Range],
        public_https: bool,
        client: IpAddr,
    ) -> Vec<&'static str> {
        let mut lines = Vec::new();
        let forwarded = headers.contains_key("x-forwarded-for");
        if is_trusted(peer.to_canonical(), trusted)
            && !forwarded
            && !self.no_forwarded_for.swap(true, Ordering::Relaxed)
        {
            lines.push(NO_FORWARDED_FOR);
        }
        if public_https && is_private(client) && !self.private_client.swap(true, Ordering::Relaxed)
        {
            lines.push(PRIVATE_CLIENT);
        }
        lines
    }
}

/// Logs the address warnings this request is due, on stderr, once per process.
pub fn log_warnings(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[Range],
    public_https: bool,
    client: IpAddr,
) {
    for line in WARNED.due(peer, headers, trusted, public_https, client) {
        eprintln!("{line}");
    }
}

/// Private, loopback, link-local or unique-local: the addresses of a proxy on this host or a LAN.
fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00
        }
    }
}

/// The client address: the peer, or the right-most untrusted X-Forwarded-For entry behind a trusted proxy.
pub fn client_address(peer: IpAddr, headers: &HeaderMap, trusted: &[Range]) -> IpAddr {
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

fn is_trusted(ip: IpAddr, trusted: &[Range]) -> bool {
    trusted.iter().any(|range| range.contains(ip))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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
        let trusted = [Range::from(ip("127.0.0.1"))];
        assert_eq!(
            client_address(ip("127.0.0.1"), &headers, &trusted),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn trusted_entries_are_skipped() {
        let headers = forwarded(&["203.0.113.5", "127.0.0.1"]);
        let trusted = [Range::from(ip("127.0.0.1"))];
        assert_eq!(
            client_address(ip("127.0.0.1"), &headers, &trusted),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn an_unparseable_entry_is_only_read_when_it_is_the_right_most() {
        let headers = forwarded(&["garbage, 203.0.113.5"]);
        let trusted = [Range::from(ip("127.0.0.1"))];
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
        let trusted = [Range::from(ip("127.0.0.1"))];
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

    #[test]
    fn a_trusted_range_is_matched_by_containment() {
        let range: Range = format!("{}/8", Ipv4Addr::new(10, 0, 0, 0))
            .parse()
            .expect("range");
        let headers = forwarded(&["203.0.113.5"]);
        let inside = ip(&Ipv4Addr::new(10, 1, 2, 3).to_string());
        assert_eq!(
            client_address(inside, &headers, std::slice::from_ref(&range)),
            ip("203.0.113.5")
        );
        assert_eq!(
            client_address(ip("203.0.113.9"), &headers, &[range]),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn a_trusted_proxy_without_a_forwarded_header_is_warned_once() {
        let warned = Warned::default();
        let trusted = [Range::from(ip("127.0.0.1"))];
        let peer = ip("127.0.0.1");
        assert_eq!(
            warned.due(peer, &HeaderMap::new(), &trusted, false, peer),
            [NO_FORWARDED_FOR]
        );
        assert!(
            warned
                .due(peer, &HeaderMap::new(), &trusted, false, peer)
                .is_empty()
        );
    }

    #[test]
    fn a_forwarded_header_or_an_untrusted_peer_is_not_warned() {
        let warned = Warned::default();
        let trusted = [Range::from(ip("127.0.0.1"))];
        let peer = ip("127.0.0.1");
        let headers = forwarded(&["203.0.113.5"]);
        assert!(
            warned
                .due(peer, &headers, &trusted, false, ip("203.0.113.5"))
                .is_empty()
        );
        let stranger = ip("203.0.113.9");
        assert!(
            warned
                .due(stranger, &HeaderMap::new(), &trusted, false, stranger)
                .is_empty()
        );
    }

    #[test]
    fn a_private_client_on_a_public_install_is_warned_once() {
        let warned = Warned::default();
        let trusted = [Range::from(ip("127.0.0.1"))];
        let private = ip(&Ipv4Addr::new(10, 0, 0, 7).to_string());
        let private_text = private.to_string();
        let headers = forwarded(&[private_text.as_str()]);
        assert_eq!(
            warned.due(ip("127.0.0.1"), &headers, &trusted, true, private),
            [PRIVATE_CLIENT]
        );
        assert!(
            warned
                .due(ip("127.0.0.1"), &headers, &trusted, true, private)
                .is_empty()
        );
    }

    #[test]
    fn a_public_client_or_a_loopback_install_is_not_warned_about_privacy() {
        let warned = Warned::default();
        let trusted = [Range::from(ip("127.0.0.1"))];
        let headers = forwarded(&["203.0.113.9"]);
        assert!(
            warned
                .due(ip("127.0.0.1"), &headers, &trusted, true, ip("203.0.113.9"))
                .is_empty()
        );
        let private = ip(&Ipv4Addr::new(10, 0, 0, 7).to_string());
        assert!(
            warned
                .due(ip("127.0.0.1"), &headers, &trusted, false, private)
                .is_empty()
        );
    }

    #[test]
    fn link_local_and_unique_local_clients_are_private() {
        let trusted = [Range::from(ip("127.0.0.1"))];
        let link_local_v4 = ip(&Ipv4Addr::new(169, 254, 1, 1).to_string());
        for client in [ip("fe80::1"), ip("fd00::1"), link_local_v4] {
            let warned = Warned::default();
            assert_eq!(
                warned.due(
                    ip("127.0.0.1"),
                    &forwarded(&["203.0.113.9"]),
                    &trusted,
                    true,
                    client
                ),
                [PRIVATE_CLIENT],
                "{client} must count as private"
            );
        }
    }

    #[test]
    fn loopback_clients_are_private() {
        let trusted = [Range::from(ip("127.0.0.1"))];
        for client in [ip("127.0.0.1"), ip("::1")] {
            let warned = Warned::default();
            assert_eq!(
                warned.due(
                    ip("127.0.0.1"),
                    &forwarded(&["203.0.113.9"]),
                    &trusted,
                    true,
                    client
                ),
                [PRIVATE_CLIENT],
                "{client} is a loopback client and must earn the private-address warning"
            );
        }
    }
}
