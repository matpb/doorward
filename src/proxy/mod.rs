//! The proxy's upstream side: the HTTP client to a server's upstream, and its tool catalog.

pub mod catalog;
#[cfg(test)]
pub(crate) mod tests;
pub mod upstream;
