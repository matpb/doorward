//! The one writer of failure lines on standard error.

use std::fmt::Display;

/// Writes `doorward: <what> failed: <err>` as one line; a control character in `err` becomes a space.
pub fn failure(what: &str, err: &dyn Display) {
    eprintln!("doorward: {what} failed: {}", one_line(&err.to_string()));
}

/// Writes `doorward: <what> refused: <reason>` as one line, for a refusal of a token that exists.
pub fn refused(what: &str, reason: &str) {
    eprintln!("doorward: {what} refused: {}", one_line(reason));
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::one_line;

    #[test]
    fn a_line_break_inside_an_error_becomes_a_space() {
        assert_eq!(one_line("first\nsecond\r\nthird"), "first second  third");
    }

    #[test]
    fn every_control_character_becomes_a_space() {
        let controls: String = (0x00..=0x1f_u32)
            .chain(0x7f..=0x9f)
            .filter_map(char::from_u32)
            .collect();
        assert_eq!(one_line(&controls), " ".repeat(controls.chars().count()));
    }

    #[test]
    fn text_that_is_not_a_control_character_is_kept() {
        assert_eq!(
            one_line("caf\u{e9} \u{1b}[31mred\u{0}end"),
            "caf\u{e9}  [31mred end"
        );
    }
}
