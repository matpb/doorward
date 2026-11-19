use std::collections::HashMap;
use std::future::ready;
use std::sync::{Arc, Mutex, MutexGuard};

use doorward::cimd::CimdFuture;
use doorward::{CimdError, CimdFetcher, ClientMetadata};

#[derive(Default)]
struct State {
    documents: HashMap<String, ClientMetadata>,
    failures: HashMap<String, CimdError>,
    fetches: HashMap<String, usize>,
}

/// In-memory client metadata fetcher for tests.
pub struct FakeCimd {
    state: Mutex<State>,
}

impl FakeCimd {
    pub fn new() -> Arc<FakeCimd> {
        Arc::new(FakeCimd {
            state: Mutex::new(State::default()),
        })
    }

    /// Registers a document with `client_name` set and `token_endpoint_auth_method` "none".
    pub fn put(&self, client_id: &str, name: &str, redirect_uris: &[&str]) {
        self.put_metadata(
            client_id,
            ClientMetadata {
                client_id: client_id.to_owned(),
                client_name: Some(name.to_owned()),
                redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
                token_endpoint_auth_method: Some("none".to_owned()),
            },
        );
    }

    /// Registers a document, clearing any failure set for this id.
    pub fn put_metadata(&self, client_id: &str, metadata: ClientMetadata) {
        let mut state = self.lock();
        state.failures.remove(client_id);
        state.documents.insert(client_id.to_owned(), metadata);
    }

    /// Makes fetches of this id fail with `error` until `put` is called for it again.
    pub fn fail(&self, client_id: &str, error: CimdError) {
        self.lock().failures.insert(client_id.to_owned(), error);
    }

    /// How many times this id was fetched, failures included.
    pub fn fetches(&self, client_id: &str) -> usize {
        self.lock().fetches.get(client_id).copied().unwrap_or(0)
    }

    fn lookup(&self, client_id: &str) -> Result<ClientMetadata, CimdError> {
        let mut state = self.lock();
        *state.fetches.entry(client_id.to_owned()).or_insert(0) += 1;
        if let Some(error) = state.failures.get(client_id) {
            return Err(error.clone());
        }
        match state.documents.get(client_id) {
            Some(metadata) => Ok(metadata.clone()),
            None => Err(CimdError::Fetch("not found".into())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("fake cimd state")
    }
}

impl CimdFetcher for FakeCimd {
    fn fetch<'a>(&'a self, client_id: &'a str) -> CimdFuture<'a> {
        Box::pin(ready(self.lookup(client_id)))
    }
}
