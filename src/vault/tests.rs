use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;
use crate::config::Config;

const MASTER: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const OTHER_MASTER: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const TOKEN: &str = "dw_ss_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_TOKEN: &str = "dw_ss_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const SALT: [u8; 16] = [7; 16];

fn keys_for(master: &str) -> Keys {
    let config = Config {
        public_url: "https://example.com".to_owned(),
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 8717)),
        database: PathBuf::from("unused.db"),
        key_file: None,
        trusted_proxies: Vec::new(),
        shared_client_address: false,
        allowed_origins: Vec::new(),
        lifetimes: Default::default(),
        limits: Default::default(),
        mail: Default::default(),
    };
    Keys::from_sources(Some(master.to_owned()), &config, None).expect("keys")
}

fn place() -> Place<'static> {
    Place {
        user: 3,
        generation: 2,
        table: "sessions",
        row: "abc",
    }
}

fn value_place() -> ValuePlace<'static> {
    ValuePlace {
        user: 3,
        server: 5,
        header: "x-api-key",
        generation: 2,
        upstream_url: "https://example.com/mcp",
    }
}

/// Flips one bit of the last base64url part of a dotted text.
fn flipped(text: &str) -> String {
    let (head, tail) = text.rsplit_once('.').expect("a dotted text");
    let mut bytes = URL_SAFE_NO_PAD.decode(tail).expect("base64url tail");
    bytes[0] ^= 1;
    format!("{head}.{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn is_open_error<T>(result: Result<T, CryptoError>) -> bool {
    matches!(result, Err(CryptoError::Open))
}

#[test]
fn a_wrap_round_trips_with_a_token() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let wrap = wrap_with_token(&keys, &place(), TOKEN, &key).expect("wrap");
    let opened = unwrap_with_token(&keys, &place(), TOKEN, &wrap).expect("unwrap");
    assert_eq!(opened.bytes(), key.bytes());
}

#[test]
fn a_wrap_round_trips_with_a_password() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let password = password_key("correct horse battery", &SALT).expect("key");
    let wrap = wrap_with_password(&keys, &place(), &password, &key).expect("wrap");
    let opened = unwrap_with_password(&keys, &place(), &password, &wrap).expect("unwrap");
    assert_eq!(opened.bytes(), key.bytes());
}

#[test]
fn a_token_wrap_opens_nothing_when_one_part_differs() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let wrap = wrap_with_token(&keys, &place(), TOKEN, &key).expect("wrap");
    let cases = [
        ("token", place(), OTHER_TOKEN, keys_for(MASTER)),
        (
            "table",
            Place {
                table: "auth_codes",
                ..place()
            },
            TOKEN,
            keys_for(MASTER),
        ),
        (
            "row",
            Place {
                row: "abd",
                ..place()
            },
            TOKEN,
            keys_for(MASTER),
        ),
        (
            "user",
            Place { user: 4, ..place() },
            TOKEN,
            keys_for(MASTER),
        ),
        (
            "generation",
            Place {
                generation: 3,
                ..place()
            },
            TOKEN,
            keys_for(MASTER),
        ),
        ("server key", place(), TOKEN, keys_for(OTHER_MASTER)),
    ];
    for (what, at, token, keys) in cases {
        assert!(
            is_open_error(unwrap_with_token(&keys, &at, token, &wrap)),
            "a wrap must not open with a different {what}"
        );
    }
    assert!(is_open_error(unwrap_with_token(
        &keys,
        &place(),
        TOKEN,
        &flipped(&wrap)
    )));
}

#[test]
fn a_password_wrap_opens_nothing_when_one_part_differs() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let password = password_key("correct horse battery", &SALT).expect("key");
    let wrap = wrap_with_password(&keys, &place(), &password, &key).expect("wrap");
    let wrong_password = password_key("correct horse batterz", &SALT).expect("key");
    let wrong_salt = password_key("correct horse battery", &[8; 16]).expect("key");
    assert!(is_open_error(unwrap_with_password(
        &keys,
        &place(),
        &wrong_password,
        &wrap
    )));
    assert!(is_open_error(unwrap_with_password(
        &keys,
        &place(),
        &wrong_salt,
        &wrap
    )));
    let moved = Place {
        generation: 3,
        ..place()
    };
    assert!(is_open_error(unwrap_with_password(
        &keys, &moved, &password, &wrap
    )));
    assert!(is_open_error(unwrap_with_password(
        &keys_for(OTHER_MASTER),
        &place(),
        &password,
        &wrap
    )));
    assert!(is_open_error(unwrap_with_password(
        &keys,
        &place(),
        &password,
        &flipped(&wrap)
    )));
}

#[test]
fn a_password_wrap_does_not_open_as_a_token_wrap_and_back() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let password = password_key("correct horse battery", &SALT).expect("key");
    let wrap = wrap_with_password(&keys, &place(), &password, &key).expect("wrap");
    assert!(is_open_error(unwrap_with_token(
        &keys,
        &place(),
        TOKEN,
        &wrap
    )));
}

#[test]
fn two_wraps_of_one_key_differ() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let first = wrap_with_token(&keys, &place(), TOKEN, &key).expect("wrap");
    let second = wrap_with_token(&keys, &place(), TOKEN, &key).expect("wrap");
    assert_ne!(first, second);
    assert!(first.starts_with("w1."));
}

#[test]
fn a_string_that_is_not_a_sealing_token_never_wraps_or_opens() {
    let keys = keys_for(MASTER);
    let key = DataKey::random();
    let good = wrap_with_token(&keys, &place(), TOKEN, &key).expect("wrap");
    for text in [
        "",
        "dw_ss_short",
        "dw_ss_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "Dw_ss_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "hunter2",
        "dw_ss_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
    ] {
        assert!(is_open_error(wrap_with_token(&keys, &place(), text, &key)));
        assert!(is_open_error(unwrap_with_token(
            &keys,
            &place(),
            text,
            &good
        )));
    }
}

#[test]
fn a_value_round_trips() {
    let key = DataKey::random();
    let sealed = seal_value(&key, &value_place(), b"secret-value").expect("seal");
    let opened = open_value(&key, &value_place(), &sealed).expect("open");
    assert_eq!(opened.as_slice(), b"secret-value");
    assert!(!sealed.contains("secret-value"));
}

#[test]
fn a_value_opens_nothing_when_one_part_differs() {
    let key = DataKey::random();
    let sealed = seal_value(&key, &value_place(), b"secret-value").expect("seal");
    let cases = [
        (
            "user",
            ValuePlace {
                user: 4,
                ..value_place()
            },
        ),
        (
            "server",
            ValuePlace {
                server: 6,
                ..value_place()
            },
        ),
        (
            "header",
            ValuePlace {
                header: "x-other",
                ..value_place()
            },
        ),
        (
            "generation",
            ValuePlace {
                generation: 3,
                ..value_place()
            },
        ),
        (
            "upstream url",
            ValuePlace {
                upstream_url: "https://example.org/mcp",
                ..value_place()
            },
        ),
    ];
    for (what, at) in cases {
        assert!(
            is_open_error(open_value(&key, &at, &sealed)),
            "a value must not open with a different {what}"
        );
    }
    assert!(is_open_error(open_value(
        &DataKey::random(),
        &value_place(),
        &sealed
    )));
    assert!(is_open_error(open_value(
        &key,
        &value_place(),
        &flipped(&sealed)
    )));
    assert!(is_open_error(open_value(&key, &value_place(), "s1.x")));
}

#[test]
fn two_seals_of_one_value_differ() {
    let key = DataKey::random();
    let first = seal_value(&key, &value_place(), b"v").expect("seal");
    let second = seal_value(&key, &value_place(), b"v").expect("seal");
    assert_ne!(first, second);
}
