//! Stored header values: the envelope API. Every open refuses and every key is zero until the feature lands.

use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Keys};

/// A user's data key: it seals that user's stored header values.
#[allow(dead_code)]
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    pub fn random() -> DataKey {
        DataKey(Zeroizing::new([0; 32]))
    }
}

/// The row a wrap of the data key sits on.
pub struct Place<'a> {
    pub user: i64,
    pub generation: i64,
    pub table: &'a str,
    pub row: &'a str,
}

/// A key from Argon2id over the password and the user's own salt.
#[allow(dead_code)]
pub struct PasswordKey(Zeroizing<[u8; 32]>);

pub fn password_key(_password: &str, _salt: &[u8; 16]) -> Result<PasswordKey, CryptoError> {
    Err(CryptoError::Open)
}

pub fn wrap_with_token(
    _keys: &Keys,
    _place: &Place,
    _token: &str,
    _key: &DataKey,
) -> Result<String, CryptoError> {
    Err(CryptoError::Open)
}

pub fn unwrap_with_token(
    _keys: &Keys,
    _place: &Place,
    _token: &str,
    _wrap: &str,
) -> Result<DataKey, CryptoError> {
    Err(CryptoError::Open)
}

pub fn wrap_with_password(
    _keys: &Keys,
    _place: &Place,
    _password: &PasswordKey,
    _key: &DataKey,
) -> Result<String, CryptoError> {
    Err(CryptoError::Open)
}

pub fn unwrap_with_password(
    _keys: &Keys,
    _place: &Place,
    _password: &PasswordKey,
    _wrap: &str,
) -> Result<DataKey, CryptoError> {
    Err(CryptoError::Open)
}

/// What a sealed value is bound to.
pub struct ValuePlace<'a> {
    pub user: i64,
    pub server: i64,
    pub header: &'a str,
    pub generation: i64,
    pub upstream_url: &'a str,
}

pub fn seal_value(
    _key: &DataKey,
    _place: &ValuePlace,
    _value: &[u8],
) -> Result<String, CryptoError> {
    Err(CryptoError::Open)
}

pub fn open_value(
    _key: &DataKey,
    _place: &ValuePlace,
    _sealed: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    Err(CryptoError::Open)
}
