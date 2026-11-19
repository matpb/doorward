//! The text and HTML parts of the invitation and reset mails. The link is the only content.

use maud::html;

use crate::mail::Message;

/// The parts of a mail; the recipient is added when it is sent.
pub struct Parts {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl Parts {
    pub fn to(self, to: String) -> Message {
        Message {
            to,
            subject: self.subject,
            text: self.text,
            html: self.html,
        }
    }
}

pub fn invitation(link: &str) -> Parts {
    Parts {
        subject: "You are invited to Doorward".to_owned(),
        text: format!(
            "You are invited to Doorward.\n\nSet your password at this link. It works once:\n\n{link}\n"
        ),
        html: html! {
            p { "You are invited to Doorward." }
            p { "Set your password at this link. It works once:" }
            p { a href=(link) { (link) } }
        }
        .into_string(),
    }
}

pub fn reset(link: &str) -> Parts {
    Parts {
        subject: "Reset your Doorward password".to_owned(),
        text: format!(
            "Someone asked to reset the password of your Doorward account.\n\nSet a new password at this link. It works once:\n\n{link}\n"
        ),
        html: html! {
            p { "Someone asked to reset the password of your Doorward account." }
            p { "Set a new password at this link. It works once:" }
            p { a href=(link) { (link) } }
        }
        .into_string(),
    }
}

/// Sent when a client connects to the account for the first time; the link disconnects it.
pub fn new_connection(link: &str) -> Parts {
    Parts {
        subject: "A new app was connected to your Doorward account".to_owned(),
        text: format!(
            "A new app was connected to your Doorward account.\n\nIf you did not connect it, disconnect it at this link:\n\n{link}\n"
        ),
        html: html! {
            p { "A new app was connected to your Doorward account." }
            p { "If you did not connect it, disconnect it at this link:" }
            p { a href=(link) { (link) } }
        }
        .into_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_connection_mail_carries_its_link_in_both_parts() {
        let link = "http://127.0.0.1:8717/account/disconnect/dw_dl_example";
        let parts = new_connection(link);
        assert_eq!(
            parts.subject,
            "A new app was connected to your Doorward account"
        );
        assert!(parts.text.contains(link));
        assert!(parts.html.contains(link));
    }

    #[test]
    fn the_new_connection_html_escapes_its_link() {
        let parts = new_connection("http://127.0.0.1:8717/account/disconnect/\"<x>");
        assert!(!parts.html.contains("\"<x>"));
        assert!(parts.html.contains("&quot;&lt;x&gt;"));
    }

    #[test]
    fn the_link_is_in_both_parts() {
        let link = "http://127.0.0.1:8717/invite/dw_iv_example";
        let parts = invitation(link);
        assert_eq!(parts.subject, "You are invited to Doorward");
        assert!(parts.text.contains(link));
        assert!(parts.html.contains(link));
    }

    #[test]
    fn the_html_part_escapes_the_link() {
        let parts = reset("http://127.0.0.1:8717/reset/\"<x>");
        assert_eq!(parts.subject, "Reset your Doorward password");
        assert!(!parts.html.contains("\"<x>"));
        assert!(parts.html.contains("&quot;&lt;x&gt;"));
    }
}
