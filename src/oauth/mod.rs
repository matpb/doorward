//! The OAuth authorization server: redirect grammar and allowlist, clients, registration, metadata.

pub mod clients;
pub mod metadata;
pub mod policy;
pub mod register;
pub mod uri;

#[cfg(test)]
mod tests;
