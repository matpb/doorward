//! Keys, sealed values, tokens and password hashing. Reviewed line by line.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::config::Config;

const KEY_ENV: &str = "DOORWARD_KEY";
const SEAL_INFO: &[u8] = b"doorward seal v1";
const CSRF_INFO: &[u8] = b"doorward csrf v1";
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const TOKEN_BYTES: usize = 32;
const QUEUE_PERMITS: usize = 64;
const ARGON2_MEMORY_KIB: u32 = 19456;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_LANES: u32 = 1;
const DUMMY_PASSWORD: &str = "doorward dummy password";

/// What a request used to prove itself: a session cookie value or a pre-session cookie value.
pub enum CsrfBinding {
    Session(String),
    Anonymous(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("the key file is readable by other users: make it mode 0600")]
    Mode,
    #[error("the key is not 64 hexadecimal characters")]
    Malformed,
    #[error("cannot read or create the key file")]
    Io(#[source] std::io::Error),
    #[error(
        "the database was encrypted with a key that is not present: supply the original key in DOORWARD_KEY or in the key file"
    )]
    Missing,
    #[error(
        "the key does not match the key that encrypted the database: supply the original key in DOORWARD_KEY or in the key file"
    )]
    Mismatch,
    #[error("key derivation failed")]
    Derive,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("the sealed value cannot be opened")]
    Open,
    #[error("the value cannot be sealed")]
    Seal,
    #[error("password hashing failed")]
    Hash,
    #[error("the password task failed")]
    Task,
}

/// The subkeys and the key id. Holds no master key and prints nothing.
pub struct Keys {
    seal: Zeroizing<[u8; 32]>,
    csrf: Zeroizing<[u8; 32]>,
    key_id: String,
}

impl Keys {
    /// Reads the environment variable DOORWARD_KEY and calls `from_sources`.
    pub fn load(config: &Config, stored_key_id: Option<&str>) -> Result<Keys, KeyError> {
        let env_key = match std::env::var(KEY_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => return Err(KeyError::Malformed),
        };
        Keys::from_sources(env_key, config, stored_key_id)
    }

    /// Pure: unit tests call this and never touch the process environment.
    fn from_sources(
        env_key: Option<String>,
        config: &Config,
        stored_key_id: Option<&str>,
    ) -> Result<Keys, KeyError> {
        let text = match env_key.filter(|value| !value.is_empty()) {
            Some(value) => Zeroizing::new(value),
            None => read_key_file(&key_file_path(config), stored_key_id)?,
        };
        let master = parse_master_key(&text)?;
        let seal = derive(&master, SEAL_INFO)?;
        let csrf = derive(&master, CSRF_INFO)?;
        let key_id = key_id_of(&seal);
        if stored_key_id.is_some_and(|stored| stored != key_id) {
            return Err(KeyError::Mismatch);
        }
        Ok(Keys { seal, csrf, key_id })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Output text: "v1.<key id>.<nonce>.<ciphertext>", both base64url without padding.
    pub fn seal(&self, context: &str, plaintext: &[u8]) -> Result<String, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce);
        let cipher = XChaCha20Poly1305::new(&(*self.seal).into());
        let aad = associated_data(&self.key_id, context);
        let body = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Seal)?;
        Ok(format!(
            "v1.{}.{}.{}",
            self.key_id,
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(body)
        ))
    }

    pub fn open(&self, context: &str, sealed: &str) -> Result<Vec<u8>, CryptoError> {
        let parts: Vec<&str> = sealed.split('.').collect();
        let [version, key_id, nonce_text, body_text] = parts.as_slice() else {
            return Err(CryptoError::Open);
        };
        if *version != "v1" || *key_id != self.key_id {
            return Err(CryptoError::Open);
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(nonce_text)
            .map_err(|_| CryptoError::Open)?;
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::Open);
        }
        let body = URL_SAFE_NO_PAD
            .decode(body_text)
            .map_err(|_| CryptoError::Open)?;
        let nonce = XNonce::try_from(nonce.as_slice()).map_err(|_| CryptoError::Open)?;
        let cipher = XChaCha20Poly1305::new(&(*self.seal).into());
        let aad = associated_data(&self.key_id, context);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &body,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Open)
    }

    /// Base64url HMAC-SHA256 of the binding, under the csrf subkey.
    pub fn csrf_token(&self, binding: &CsrfBinding) -> String {
        let (label, value) = match binding {
            CsrfBinding::Session(value) => ("session", value),
            CsrfBinding::Anonymous(value) => ("anon", value),
        };
        // HMAC zero-pads a short key to the block size, so this equals HMAC under the 32 byte key.
        let mut key_block = Zeroizing::new([0u8; 64]);
        key_block[..32].copy_from_slice(&self.csrf[..]);
        let mut mac = Hmac::<Sha256>::new(&(*key_block).into());
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

/// `prefix` followed by 43 base64url characters (32 bytes from the operating system).
pub fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    fill_random(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// 32 lower-case hexadecimal characters from 16 random bytes.
pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    hex::encode(bytes)
}

/// Lower-case hex SHA-256 of the token text. The only form in which tokens are stored.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// An owned permit of the waiting queue; dropped only when its hashing has finished.
pub struct HashSlot(#[allow(dead_code)] OwnedSemaphorePermit);

pub struct PasswordHasher {
    queue: Arc<Semaphore>,
    run: Arc<Semaphore>,
    dummy: String,
}

impl PasswordHasher {
    /// Computes the dummy hash once, through the same code path as `hash`.
    pub async fn new() -> Result<PasswordHasher, CryptoError> {
        let parallelism = std::thread::available_parallelism().map_or(1, |n| n.get());
        let mut hasher = PasswordHasher {
            queue: Arc::new(Semaphore::new(QUEUE_PERMITS)),
            run: Arc::new(Semaphore::new(parallelism.max(2))),
            dummy: String::new(),
        };
        let slot = hasher.try_slot().ok_or(CryptoError::Hash)?;
        let dummy = hasher.hash(slot, DUMMY_PASSWORD.to_owned()).await?;
        hasher.dummy = dummy;
        Ok(hasher)
    }

    /// None when 64 requests already wait or run. The caller then answers 503.
    pub fn try_slot(&self) -> Option<HashSlot> {
        Arc::clone(&self.queue)
            .try_acquire_owned()
            .ok()
            .map(HashSlot)
    }

    /// Argon2id, 19456 KiB, 2 iterations, parallelism 1, random 16 byte salt, PHC string.
    pub async fn hash(&self, slot: HashSlot, password: String) -> Result<String, CryptoError> {
        self.run_blocking(slot, move || hash_now(&password)).await?
    }

    /// With `None`, verifies against the dummy hash and returns false, so an unknown
    /// account costs the same time as a wrong password. Any internal error is false.
    pub async fn verify(&self, slot: HashSlot, password: String, phc: Option<String>) -> bool {
        let known = phc.is_some();
        let stored = phc.unwrap_or_else(|| self.dummy.clone());
        let outcome = self
            .run_blocking(slot, move || check_password(&password, &stored) && known)
            .await;
        matches!(outcome, Ok(true))
    }

    /// Runs `work` on a blocking thread. The run permit and the slot move into that thread,
    /// so both are released only when the work has really finished.
    async fn run_blocking<T, F>(&self, slot: HashSlot, work: F) -> Result<T, CryptoError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let run = Arc::clone(&self.run)
            .acquire_owned()
            .await
            .map_err(|_| CryptoError::Task)?;
        tokio::task::spawn_blocking(move || {
            let _held = (run, slot);
            work()
        })
        .await
        .map_err(|_| CryptoError::Task)
    }
}

/// Reads the key text from the key file, or creates the file when no key was ever stored.
fn read_key_file(path: &Path, stored_key_id: Option<&str>) -> Result<Zeroizing<String>, KeyError> {
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            let mode = file.metadata().map_err(KeyError::Io)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(KeyError::Mode);
            }
            let mut text = Zeroizing::new(String::new());
            file.read_to_string(&mut text).map_err(KeyError::Io)?;
            Ok(text)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if stored_key_id.is_some() {
                return Err(KeyError::Missing);
            }
            create_key_file(path)
        }
        Err(err) => Err(KeyError::Io(err)),
    }
}

/// Writes a new random key to `path` with mode 0600 in one open.
fn create_key_file(path: &Path) -> Result<Zeroizing<String>, KeyError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill_random(&mut bytes[..]);
    let text = Zeroizing::new(hex::encode(&bytes[..]));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(KeyError::Io)?;
    file.write_all(text.as_bytes()).map_err(KeyError::Io)?;
    file.write_all(b"\n").map_err(KeyError::Io)?;
    file.sync_all().map_err(KeyError::Io)?;
    Ok(text)
}

fn key_file_path(config: &Config) -> PathBuf {
    match &config.key_file {
        Some(path) => path.clone(),
        None => {
            let mut name = config.database.as_os_str().to_owned();
            name.push(".key");
            PathBuf::from(name)
        }
    }
}

/// Trims trailing whitespace, then requires exactly 64 hexadecimal characters.
fn parse_master_key(text: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let trimmed = text.trim_end();
    if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeyError::Malformed);
    }
    let mut master = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(trimmed, &mut master[..]).map_err(|_| KeyError::Malformed)?;
    Ok(master)
}

/// HKDF-SHA256 with no salt, 32 bytes out.
fn derive(master: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, &mut out[..])
        .map_err(|_| KeyError::Derive)?;
    Ok(out)
}

/// The first 8 hexadecimal characters of SHA-256 over the seal subkey.
fn key_id_of(seal: &[u8; 32]) -> String {
    let full = hex::encode(Sha256::digest(seal));
    full[..8].to_owned()
}

/// The associated data: "v1.<key id>", one NUL byte, then the context.
fn associated_data(key_id: &str, context: &str) -> Vec<u8> {
    let mut aad = format!("v1.{key_id}").into_bytes();
    aad.push(0);
    aad.extend_from_slice(context.as_bytes());
    aad
}

/// The only caller of the operating system generator in `src/`.
fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("os rng");
}

fn hashing_context() -> Result<Argon2<'static>, CryptoError> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, None)
        .map_err(|_| CryptoError::Hash)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_now(password: &str) -> Result<String, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt);
    let phc = hashing_context()?
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|_| CryptoError::Hash)?;
    Ok(phc.to_string())
}

/// True only when `stored` is a valid PHC string that matches `password`.
fn check_password(password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    const MASTER: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const CONTEXT: &str = "settings.value:mail.smtp_password";
    const SEALED_MAIL: &str =
        "v1.6f0dc451.AAECAwQFBgcICQoLDA0ODxAREhMUFRYX.5uI6Ewt1Hj24xxMBHByJgFL0aSi9mVR18YXWeWA";

    fn config_in(database: PathBuf, key_file: Option<PathBuf>) -> Config {
        Config {
            public_url: "https://example.com".to_owned(),
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 8717)),
            database,
            key_file,
            trusted_proxies: Vec::new(),
            lifetimes: Default::default(),
            limits: Default::default(),
            mail: Default::default(),
        }
    }

    fn keys_for(hex_key: &str) -> Keys {
        let config = config_in(PathBuf::from("unused.db"), None);
        Keys::from_sources(Some(hex_key.to_owned()), &config, None).expect("keys")
    }

    #[test]
    fn known_answers() {
        let keys = keys_for(MASTER);
        assert_eq!(keys.key_id(), "6f0dc451");
        assert_eq!(
            keys.csrf_token(&CsrfBinding::Session("dw_ss_example".into())),
            "4HoRqx5gui-p_XyuAJw943oeYxANMZu7CgwOtegFXvU"
        );
        assert_eq!(
            keys.csrf_token(&CsrfBinding::Anonymous("dw_cs_example".into())),
            "b4YrnqkOdQo2_puzG5b8KFO4fJt2_A9mYg8ofLZtvJY"
        );
        assert_eq!(
            keys.open(CONTEXT, SEALED_MAIL).expect("open"),
            b"mail-password"
        );
    }

    #[test]
    fn stored_key_id_that_matches_is_accepted() {
        let config = config_in(PathBuf::from("unused.db"), None);
        let keys = Keys::from_sources(Some(MASTER.to_owned()), &config, Some("6f0dc451"));
        assert!(keys.is_ok());
    }

    #[test]
    fn seal_then_open_round_trips() {
        let keys = keys_for(MASTER);
        let sealed = keys.seal(CONTEXT, b"hello").expect("seal");
        assert_eq!(keys.open(CONTEXT, &sealed).expect("open"), b"hello");
    }

    #[test]
    fn two_seals_of_the_same_text_differ() {
        let keys = keys_for(MASTER);
        assert_ne!(
            keys.seal(CONTEXT, b"hello").expect("seal"),
            keys.seal(CONTEXT, b"hello").expect("seal")
        );
    }

    #[test]
    fn open_refuses_every_wrong_input() {
        let keys = keys_for(MASTER);
        let sealed = keys.seal(CONTEXT, b"hello").expect("seal");
        assert!(matches!(
            keys.open("settings.value:mail.resend_api_key", &sealed),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            keys_for(&"ab".repeat(32)).open(CONTEXT, &sealed),
            Err(CryptoError::Open)
        ));
        let parts: Vec<&str> = sealed.split('.').collect();
        let mut body = URL_SAFE_NO_PAD.decode(parts[3]).expect("body");
        body[0] ^= 1;
        let flipped = format!(
            "{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            URL_SAFE_NO_PAD.encode(&body)
        );
        assert!(matches!(
            keys.open(CONTEXT, &flipped),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            keys.open(CONTEXT, "v1.6f0dc451.AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            keys.open(CONTEXT, &format!("{sealed}.extra")),
            Err(CryptoError::Open)
        ));
        let short_nonce = URL_SAFE_NO_PAD.encode([0u8; 23]);
        assert!(matches!(
            keys.open(CONTEXT, &format!("v1.6f0dc451.{short_nonce}.{}", parts[3])),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            keys.open(CONTEXT, &SEALED_MAIL.replacen("v1.", "v2.", 1)),
            Err(CryptoError::Open)
        ));
    }

    #[test]
    fn random_tokens_have_the_shape_and_differ() {
        let first = random_token("dw_ss_");
        let second = random_token("dw_ss_");
        assert_ne!(first, second);
        let body = first.strip_prefix("dw_ss_").expect("prefix");
        assert_eq!(body.len(), 43);
        assert!(
            body.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
    }

    #[test]
    fn random_ids_are_32_lower_case_hex_and_differ() {
        let first = random_id();
        let second = random_id();
        assert_ne!(first, second);
        for id in [&first, &second] {
            assert_eq!(id.len(), 32);
            assert!(
                id.bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            );
        }
    }

    #[test]
    fn token_hash_is_sha256_hex() {
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hash_then_verify() {
        let hasher = PasswordHasher::new().await.expect("hasher");
        let slot = hasher.try_slot().expect("slot");
        let phc = hasher
            .hash(slot, "correct horse battery".to_owned())
            .await
            .expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        let slot = hasher.try_slot().expect("slot");
        assert!(
            hasher
                .verify(slot, "correct horse battery".to_owned(), Some(phc.clone()))
                .await
        );
        let slot = hasher.try_slot().expect("slot");
        assert!(
            !hasher
                .verify(slot, "wrong password".to_owned(), Some(phc))
                .await
        );
        let slot = hasher.try_slot().expect("slot");
        assert!(
            !hasher
                .verify(slot, "correct horse battery".to_owned(), None)
                .await
        );
        let slot = hasher.try_slot().expect("slot");
        assert!(
            !hasher
                .verify(
                    slot,
                    "correct horse battery".to_owned(),
                    Some("not a phc".into())
                )
                .await
        );
    }

    fn key_file_config(dir: &Path, name: &str) -> Config {
        config_in(dir.join("doorward.db"), Some(dir.join(name)))
    }

    fn write_key(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).expect("write key");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
    }

    #[test]
    fn a_new_key_file_is_created_private() {
        let dir = tempfile::tempdir().expect("dir");
        let config = key_file_config(dir.path(), "k");
        let path = dir.path().join("k");
        assert!(Keys::from_sources(None, &config, None).is_ok());
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text.len(), 65);
        assert!(text.ends_with('\n'));
        assert!(text[..64].bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn a_key_file_readable_by_others_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let config = key_file_config(dir.path(), "k");
        write_key(&dir.path().join("k"), &"ab".repeat(32), 0o644);
        assert!(matches!(
            Keys::from_sources(None, &config, None),
            Err(KeyError::Mode)
        ));
    }

    #[test]
    fn a_malformed_key_file_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let config = key_file_config(dir.path(), "k");
        write_key(&dir.path().join("k"), &"ab".repeat(31), 0o600);
        assert!(matches!(
            Keys::from_sources(None, &config, None),
            Err(KeyError::Malformed)
        ));
    }

    #[test]
    fn a_missing_key_file_with_a_stored_id_is_refused_and_not_created() {
        let dir = tempfile::tempdir().expect("dir");
        let config = key_file_config(dir.path(), "k");
        assert!(matches!(
            Keys::from_sources(None, &config, Some("6f0dc451")),
            Err(KeyError::Missing)
        ));
        assert!(!dir.path().join("k").exists());
    }

    #[test]
    fn a_key_with_another_id_than_the_stored_one_is_refused() {
        let config = config_in(PathBuf::from("unused.db"), None);
        assert!(matches!(
            Keys::from_sources(Some(MASTER.to_owned()), &config, Some("00000000")),
            Err(KeyError::Mismatch)
        ));
    }

    #[test]
    fn a_trailing_newline_in_the_key_file_is_accepted() {
        let dir = tempfile::tempdir().expect("dir");
        let config = key_file_config(dir.path(), "k");
        write_key(
            &dir.path().join("k"),
            &format!("{}\n", "ab".repeat(32)),
            0o600,
        );
        let keys = Keys::from_sources(None, &config, None).expect("keys");
        assert_eq!(keys.key_id(), keys_for(&"ab".repeat(32)).key_id());
    }

    #[test]
    fn an_empty_environment_key_falls_back_to_the_file() {
        let dir = tempfile::tempdir().expect("dir");
        let config = key_file_config(dir.path(), "k");
        assert!(Keys::from_sources(Some(String::new()), &config, None).is_ok());
        assert!(dir.path().join("k").exists());
    }

    /// Starts `count` calls of `run_blocking`; each records the running count.
    fn spawn_batch(
        hasher: &Arc<PasswordHasher>,
        running: &Arc<AtomicUsize>,
        maximum: &Arc<AtomicUsize>,
        count: usize,
    ) -> Vec<tokio::task::JoinHandle<Result<(), CryptoError>>> {
        (0..count)
            .map(|_| {
                let hasher = Arc::clone(hasher);
                let running = Arc::clone(running);
                let maximum = Arc::clone(maximum);
                tokio::spawn(async move {
                    let slot = hasher.try_slot().expect("slot");
                    hasher
                        .run_blocking(slot, move || {
                            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                            maximum.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(50));
                            running.fetch_sub(1, Ordering::SeqCst);
                        })
                        .await
                })
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_hashing_keeps_its_permit() {
        const PERMITS: usize = 2;
        let hasher = Arc::new(PasswordHasher {
            queue: Arc::new(Semaphore::new(QUEUE_PERMITS)),
            run: Arc::new(Semaphore::new(PERMITS)),
            dummy: String::new(),
        });
        let running = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let first = spawn_batch(&hasher, &running, &maximum, 8 * PERMITS);
        tokio::time::sleep(Duration::from_millis(10)).await;
        for task in &first {
            task.abort();
        }
        // Started at once, while the first batch's threads are still sleeping.
        let second = spawn_batch(&hasher, &running, &maximum, 8 * PERMITS);
        for task in second {
            task.await
                .expect("second batch task")
                .expect("second batch hashing");
        }
        let seen = maximum.load(Ordering::SeqCst);
        assert!(seen >= 1, "no hashing ran");
        assert!(
            seen <= PERMITS,
            "at most {PERMITS} hashing calls may run at once, saw {seen}"
        );
    }
}
