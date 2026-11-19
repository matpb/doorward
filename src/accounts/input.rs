/// Trims, then lower-cases ASCII letters. Feeds storage, lookup and the throttle key.
pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Characters that address syntax gives a meaning: a mailbox parser reads them as structure.
const ADDRESS_SYNTAX: [char; 11] = ['<', '>', ',', ';', ':', '"', '(', ')', '[', ']', '\\'];

/// 3 to 254 characters, exactly one `@` with text on both sides, no whitespace, control characters
/// or address-syntax characters.
pub fn valid_new_email(email: &str) -> bool {
    let length = email.chars().count();
    if !(3..=254).contains(&length) {
        return false;
    }
    if email
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || ADDRESS_SYNTAX.contains(&c))
    {
        return false;
    }
    match email.split_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && !domain.contains('@'),
        None => false,
    }
}

/// 12 to 256 characters, counted as Unicode scalar values.
pub fn valid_password(password: &str) -> bool {
    (12..=256).contains(&password.chars().count())
}

/// Clamps a configured count or duration to the signed range used in the database.
pub fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_then_lower_cases_ascii() {
        assert_eq!(normalize_email("  Bob@example.com \n"), "bob@example.com");
    }

    #[test]
    fn a_new_email_needs_one_at_with_text_on_both_sides() {
        assert!(valid_new_email("a@b"));
        assert!(!valid_new_email("ab"));
        assert!(!valid_new_email("a@@b"));
        assert!(!valid_new_email("@bc"));
        assert!(!valid_new_email("ab@"));
    }

    #[test]
    fn a_new_email_has_no_whitespace_or_control_characters() {
        assert!(!valid_new_email("a b@c"));
        assert!(!valid_new_email("a\tb@c"));
        assert!(!valid_new_email("a\u{7}b@c"));
    }

    #[test]
    fn a_new_email_refuses_address_syntax_characters() {
        for email in [
            "x<y@example.com>",
            "\"x\"<y@example.com>",
            "<a@example.com>",
            "a,b@example.com",
            "a;b@example.com",
            "a:b@example.com",
            "a(c)@example.com",
            "a@[127.0.0.1]",
            "a\\b@example.com",
        ] {
            assert!(!valid_new_email(email), "{email} must be refused");
        }
        for c in ['<', '>', ',', ';', ':', '"', '(', ')', '[', ']', '\\'] {
            let email = format!("a{c}b@example.com");
            assert!(!valid_new_email(&email), "{email} must be refused");
        }
    }

    #[test]
    fn a_new_email_keeps_ordinary_addresses() {
        for email in [
            "bob@example.com",
            "first.last+tag@sub.example.com",
            "o'neil@example.com",
        ] {
            assert!(valid_new_email(email), "{email} must be accepted");
        }
    }

    #[test]
    fn a_new_email_is_3_to_254_characters() {
        let at_limit = format!("{}@example.com", "a".repeat(242));
        assert_eq!(at_limit.chars().count(), 254);
        assert!(valid_new_email(&at_limit));
        let over = format!("{}@example.com", "a".repeat(243));
        assert!(!valid_new_email(&over));
    }

    #[test]
    fn a_password_is_12_to_256_characters() {
        assert!(!valid_password(&"x".repeat(11)));
        assert!(valid_password(&"x".repeat(12)));
        assert!(valid_password(&"x".repeat(256)));
        assert!(!valid_password(&"x".repeat(257)));
    }

    #[test]
    fn a_password_is_counted_in_characters_not_bytes() {
        assert!(valid_password(&"é".repeat(12)));
        assert!(!valid_password(&"é".repeat(11)));
    }

    #[test]
    fn counts_are_clamped_into_the_signed_range() {
        assert_eq!(to_i64(5), 5);
        assert_eq!(to_i64(u64::MAX), i64::MAX);
    }
}
