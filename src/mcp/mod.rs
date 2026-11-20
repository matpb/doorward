//! Strict JSON parsing, message classification and the method rules of the MCP paths, without I/O.

pub mod answer;
pub mod headers;
pub mod json;
pub mod message;

#[cfg(test)]
mod tests;
