//! The one writer of failure lines on standard error.

use std::fmt::Display;

/// Writes `doorward: <what> failed: <err>` as one line; a newline in `err` becomes a space.
pub fn failure(what: &str, err: &dyn Display) {
    eprintln!("doorward: {what} failed: {}", one_line(&err.to_string()));
}

/// Writes `doorward: <what> refused: <reason>` as one line, for a refusal of a token that exists.
pub fn refused(what: &str, reason: &str) {
    eprintln!("doorward: {what} refused: {}", one_line(reason));
}

fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::one_line;

    #[test]
    fn a_line_break_inside_an_error_becomes_a_space() {
        assert_eq!(one_line("first\nsecond\r\nthird"), "first second  third");
    }
}
