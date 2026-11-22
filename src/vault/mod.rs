//! Stored header values: the envelope API. A wrap opens only with the server key, the holder's
//! secret and the same place; every failure is `CryptoError::Open`.

pub mod keys;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Keys, argon_key, fill_random, vault_token_key};

pub use keys::{Unlock, Unlocked};

const WRAP_VERSION: &str = "w1";
const VALUE_VERSION: &str = "s1";
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// A user's data key: it seals that user's stored header values.
pub struct DataKey(Zeroizing<[u8; KEY_LEN]>);

impl DataKey {
    pub fn random() -> DataKey {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(&mut bytes[..]);
        DataKey(bytes)
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; KEY_LEN]) -> DataKey {
        DataKey(Zeroizing::new(bytes))
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
pub struct PasswordKey(Zeroizing<[u8; KEY_LEN]>);

impl PasswordKey {
    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> PasswordKey {
        PasswordKey(bytes)
    }
}

pub fn password_key(password: &str, salt: &[u8; 16]) -> Result<PasswordKey, CryptoError> {
    argon_key(password, salt)
        .map(PasswordKey)
        .map_err(|_| CryptoError::Open)
}

pub fn wrap_with_token(
    keys: &Keys,
    place: &Place,
    token: &str,
    key: &DataKey,
) -> Result<String, CryptoError> {
    let holder = vault_token_key(token).ok_or(CryptoError::Open)?;
    wrap(keys, place, &holder, key)
}

pub fn unwrap_with_token(
    keys: &Keys,
    place: &Place,
    token: &str,
    wrap_text: &str,
) -> Result<DataKey, CryptoError> {
    let holder = vault_token_key(token).ok_or(CryptoError::Open)?;
    unwrap(keys, place, &holder, wrap_text)
}

pub fn wrap_with_password(
    keys: &Keys,
    place: &Place,
    password: &PasswordKey,
    key: &DataKey,
) -> Result<String, CryptoError> {
    wrap(keys, place, &password.0, key)
}

pub fn unwrap_with_password(
    keys: &Keys,
    place: &Place,
    password: &PasswordKey,
    wrap_text: &str,
) -> Result<DataKey, CryptoError> {
    unwrap(keys, place, &password.0, wrap_text)
}

/// The associated data of a wrap: version-free fields joined by NUL bytes.
fn wrap_context(place: &Place) -> String {
    format!(
        "vault.wrap\0{}\0{}\0{}\0{}",
        place.table, place.row, place.user, place.generation
    )
}

/// "w1." plus `Keys::seal` of nonce and AEAD body of the key bytes under the holder key.
fn wrap(
    keys: &Keys,
    place: &Place,
    holder: &[u8; KEY_LEN],
    key: &DataKey,
) -> Result<String, CryptoError> {
    let context = wrap_context(place);
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);
    let cipher = XChaCha20Poly1305::new(&(*holder).into());
    let body = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &key.0[..],
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    let mut inner = Vec::with_capacity(NONCE_LEN + body.len());
    inner.extend_from_slice(&nonce);
    inner.extend_from_slice(&body);
    let sealed = keys.seal(&context, &inner).map_err(|_| CryptoError::Open)?;
    Ok(format!("{WRAP_VERSION}.{sealed}"))
}

fn unwrap(
    keys: &Keys,
    place: &Place,
    holder: &[u8; KEY_LEN],
    wrap_text: &str,
) -> Result<DataKey, CryptoError> {
    let context = wrap_context(place);
    let sealed = wrap_text
        .strip_prefix(WRAP_VERSION)
        .and_then(|rest| rest.strip_prefix('.'))
        .ok_or(CryptoError::Open)?;
    let inner = Zeroizing::new(keys.open(&context, sealed)?);
    if inner.len() != NONCE_LEN + KEY_LEN + TAG_LEN {
        return Err(CryptoError::Open);
    }
    let (nonce, body) = inner.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::Open)?;
    let cipher = XChaCha20Poly1305::new(&(*holder).into());
    let opened = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: body,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| CryptoError::Open)?,
    );
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    if opened.len() != KEY_LEN {
        return Err(CryptoError::Open);
    }
    bytes.copy_from_slice(&opened);
    Ok(DataKey(bytes))
}

/// What a sealed value is bound to.
pub struct ValuePlace<'a> {
    pub user: i64,
    pub server: i64,
    pub header: &'a str,
    pub generation: i64,
    pub upstream_url: &'a str,
}

fn value_context(place: &ValuePlace) -> String {
    format!(
        "vault.value\0{}\0{}\0{}\0{}\0{}",
        place.user, place.server, place.header, place.generation, place.upstream_url
    )
}

/// "s1.<nonce>.<body>", both base64url without padding; the place is the associated data.
pub fn seal_value(key: &DataKey, place: &ValuePlace, value: &[u8]) -> Result<String, CryptoError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let context = value_context(place);
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);
    let cipher = XChaCha20Poly1305::new(&(*key.0).into());
    let body = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: value,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    Ok(format!(
        "{VALUE_VERSION}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(body)
    ))
}

pub fn open_value(
    key: &DataKey,
    place: &ValuePlace,
    sealed: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = sealed.split('.').collect();
    let [version, nonce_text, body_text] = parts.as_slice() else {
        return Err(CryptoError::Open);
    };
    if *version != VALUE_VERSION {
        return Err(CryptoError::Open);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(nonce_text)
        .map_err(|_| CryptoError::Open)?;
    let nonce = XNonce::try_from(nonce.as_slice()).map_err(|_| CryptoError::Open)?;
    let body = URL_SAFE_NO_PAD
        .decode(body_text)
        .map_err(|_| CryptoError::Open)?;
    let context = value_context(place);
    let cipher = XChaCha20Poly1305::new(&(*key.0).into());
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &body,
                aad: context.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Open)
}

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_keys;
