//! What an alert becomes: a short plain-text message.

use serde::Deserialize;

/// The most characters of the webhook's `message` that are sent.
pub const MAX_CONTENT_CHARS: usize = 1000;
const MAX_TITLE_CHARS: usize = 64;

/// One alert, as an LXMF title and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub title: String,
    pub content: String,
}

/// The two fields of the website's generic webhook body the bridge uses; the rest is ignored.
#[derive(Deserialize)]
struct Body {
    event: String,
    message: String,
}

/// Why a body is not an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAnAlert;

impl Alert {
    /// Reads the generic webhook body: `event` is the title and `message` the text, cut to
    /// [`MAX_CONTENT_CHARS`] characters.
    pub fn parse(body: &[u8]) -> Result<Self, NotAnAlert> {
        let Body { event, message } = serde_json::from_slice(body).map_err(|_| NotAnAlert)?;
        let word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ');
        if event.is_empty() || event.chars().count() > MAX_TITLE_CHARS || !event.chars().all(word) {
            return Err(NotAnAlert);
        }
        // Line breaks stay; other control characters (escape sequences) do not.
        let message: String = message.chars().filter(|c| *c == '\n' || !c.is_control()).collect();
        let content = truncate(message.trim(), MAX_CONTENT_CHARS);
        if content.is_empty() {
            return Err(NotAnAlert);
        }
        Ok(Self { title: event, content })
    }
}

/// `text` cut to `max` characters, the last of them an ellipsis when something was cut off.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(event: &str, message: &str) -> Vec<u8> {
        serde_json::json!({"event": event, "host": "a:1", "name": null, "message": message, "durationSeconds": 3}).to_string().into_bytes()
    }

    #[test]
    fn the_event_is_the_title_and_the_message_the_text() {
        let alert = Alert::parse(&body("down", "Front (front:4242) is down since 12:03 UTC.")).unwrap();
        assert_eq!(alert, Alert { title: "down".into(), content: "Front (front:4242) is down since 12:03 UTC.".into() });
    }

    #[test]
    fn a_long_message_is_cut_to_a_thousand_characters() {
        let alert = Alert::parse(&body("down", &"x".repeat(5000))).unwrap();
        assert_eq!(alert.content.chars().count(), 1000);
        assert!(alert.content.ends_with('…'));
        let exact = Alert::parse(&body("down", &"x".repeat(1000))).unwrap();
        assert_eq!(exact.content, "x".repeat(1000));
        // Characters, not bytes: this does not cut one in two.
        let wide = Alert::parse(&body("down", &"é".repeat(1500))).unwrap();
        assert_eq!(wide.content.chars().count(), 1000);
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("abcd", 3), "ab…");
        assert_eq!(truncate("abc", 0), "…");
    }

    #[test]
    fn control_characters_are_dropped_but_line_breaks_stay() {
        let alert = Alert::parse(&body("recovered", "  one\n\u{1b}[31mtwo\u{7}  ")).unwrap();
        assert_eq!(alert.content, "one\n[31mtwo");
    }

    #[test]
    fn what_is_not_an_alert_is_refused() {
        let long_title = "e".repeat(65);
        for bad in [
            &b""[..],
            b"null",
            b"[]",
            b"{}",
            b"not json",
            br#"{"event":"down"}"#,
            br#"{"event":1,"message":"x"}"#,
            br#"{"event":"down","message":null}"#,
            &body("", "x"),
            &body("two\nlines", "x"),
            &body(&long_title, "x"),
            &body("down", ""),
            &body("down", " \n\u{7} "),
        ] {
            assert_eq!(Alert::parse(bad), Err(NotAnAlert), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn deeply_nested_input_is_an_error_not_a_crash() {
        let nested = format!("{}1{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(Alert::parse(nested.as_bytes()), Err(NotAnAlert));
    }
}
