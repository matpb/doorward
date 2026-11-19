//! The OAuth authorization server: redirect grammar and allowlist, clients, registration, metadata.

pub mod authorize;
pub mod clients;
pub mod connected;
pub mod consent;
pub mod families;
pub mod guard;
pub mod metadata;
pub mod policy;
pub mod register;
pub mod token;
pub mod uri;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_consent;
#[cfg(test)]
mod tests_guard;
#[cfg(test)]
mod tests_token;
