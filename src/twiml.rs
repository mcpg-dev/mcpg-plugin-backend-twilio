//! TwiML rendering from a structured, ordered list of verbs.
//!
//! Twilio drives a call/SMS reply by returning a TwiML document — an XML
//! `<Response>` whose child elements are verbs (`<Say>`, `<Play>`, `<Gather>`,
//! …). The agent (or the operator config) authors an ordered [`Vec<TwimlVerb>`]
//! and this module renders it to a wire string. Every text node and attribute
//! value is XML-escaped (via `quick-xml`), so caller-supplied content can never
//! break out of the document or inject markup.

use quick_xml::escape::escape;
use serde::{Deserialize, Serialize};

/// XML prologue + opening tag every TwiML document carries.
const TWIML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

/// One TwiML verb. The `verb` tag selects the variant; unknown tags are a
/// deserialise error (so a typo'd verb fails closed at config/argument parse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum TwimlVerb {
    /// Text-to-speech.
    Say {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        voice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
    },
    /// Play an audio file from a URL.
    Play { url: String },
    /// Collect DTMF digits / speech, then POST to `action`. May nest verbs
    /// (typically a `Say`/`Play` prompt) inside the `<Gather>`.
    Gather {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        num_digits: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        speech_timeout: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u32>,
        #[serde(default)]
        nested: Vec<TwimlVerb>,
    },
    /// Record the caller.
    Record {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_length: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        play_beep: Option<bool>,
    },
    /// Dial a destination — exactly one of number / sip / client / conference.
    Dial {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sip: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conference: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_id: Option<String>,
    },
    /// Reject the inbound call.
    Reject {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Hang up.
    Hangup,
    /// Pause for `length` seconds.
    Pause {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<u32>,
    },
    /// Transfer control to another TwiML URL.
    Redirect { url: String },
    /// Send an SMS reply (inside an SMS webhook response).
    Message {
        body: String,
        #[serde(default)]
        media_url: Vec<String>,
    },
}

/// Render an empty `<Response/>` — the safe no-op reply (acknowledge, do
/// nothing).
pub fn empty_response() -> String {
    format!("{TWIML_HEADER}<Response></Response>")
}

/// Render a `<Reject/>`-only response — the safe-default for an unhandled
/// inbound voice call.
pub fn reject_response() -> String {
    render(&[TwimlVerb::Reject { reason: None }])
}

/// Render an ordered list of verbs into a complete TwiML document.
pub fn render(verbs: &[TwimlVerb]) -> String {
    let mut body = String::new();
    for verb in verbs {
        render_verb(verb, &mut body);
    }
    format!("{TWIML_HEADER}<Response>{body}</Response>")
}

/// XML-escape a text node / attribute value. All five predefined entities are
/// escaped so neither markup nor attribute-quote breakout is possible.
fn esc(s: &str) -> String {
    escape(s).into_owned()
}

/// Append `attr="value"` (escaped) when `value` is `Some`.
fn opt_attr(out: &mut String, name: &str, value: Option<&str>) {
    if let Some(v) = value {
        out.push_str(&format!(" {name}=\"{}\"", esc(v)));
    }
}

fn opt_attr_num<T: std::fmt::Display>(out: &mut String, name: &str, value: Option<T>) {
    if let Some(v) = value {
        out.push_str(&format!(" {name}=\"{v}\""));
    }
}

fn render_verb(verb: &TwimlVerb, out: &mut String) {
    match verb {
        TwimlVerb::Say {
            text,
            voice,
            language,
        } => {
            out.push_str("<Say");
            opt_attr(out, "voice", voice.as_deref());
            opt_attr(out, "language", language.as_deref());
            out.push('>');
            out.push_str(&esc(text));
            out.push_str("</Say>");
        }
        TwimlVerb::Play { url } => {
            out.push_str(&format!("<Play>{}</Play>", esc(url)));
        }
        TwimlVerb::Gather {
            input,
            action,
            num_digits,
            speech_timeout,
            timeout,
            nested,
        } => {
            out.push_str("<Gather");
            opt_attr(out, "input", input.as_deref());
            opt_attr(out, "action", action.as_deref());
            opt_attr_num(out, "numDigits", *num_digits);
            opt_attr(out, "speechTimeout", speech_timeout.as_deref());
            opt_attr_num(out, "timeout", *timeout);
            out.push('>');
            for child in nested {
                render_verb(child, out);
            }
            out.push_str("</Gather>");
        }
        TwimlVerb::Record {
            action,
            max_length,
            play_beep,
        } => {
            out.push_str("<Record");
            opt_attr(out, "action", action.as_deref());
            opt_attr_num(out, "maxLength", *max_length);
            opt_attr_num(out, "playBeep", *play_beep);
            out.push_str("/>");
        }
        TwimlVerb::Dial {
            number,
            sip,
            client,
            conference,
            caller_id,
        } => {
            out.push_str("<Dial");
            opt_attr(out, "callerId", caller_id.as_deref());
            out.push('>');
            // Exactly one destination noun is expected; render whichever is set.
            if let Some(n) = number {
                out.push_str(&esc(n));
            } else if let Some(s) = sip {
                out.push_str(&format!("<Sip>{}</Sip>", esc(s)));
            } else if let Some(c) = client {
                out.push_str(&format!("<Client>{}</Client>", esc(c)));
            } else if let Some(conf) = conference {
                out.push_str(&format!("<Conference>{}</Conference>", esc(conf)));
            }
            out.push_str("</Dial>");
        }
        TwimlVerb::Reject { reason } => {
            out.push_str("<Reject");
            opt_attr(out, "reason", reason.as_deref());
            out.push_str("/>");
        }
        TwimlVerb::Hangup => out.push_str("<Hangup/>"),
        TwimlVerb::Pause { length } => {
            out.push_str("<Pause");
            opt_attr_num(out, "length", *length);
            out.push_str("/>");
        }
        TwimlVerb::Redirect { url } => {
            out.push_str(&format!("<Redirect>{}</Redirect>", esc(url)));
        }
        TwimlVerb::Message { body, media_url } => {
            out.push_str("<Message>");
            out.push_str(&format!("<Body>{}</Body>", esc(body)));
            for url in media_url {
                out.push_str(&format!("<Media>{}</Media>", esc(url)));
            }
            out.push_str("</Message>");
        }
    }
}

/// JSON Schema fragment for a `twiml_verbs` array (reused by op input schemas).
pub fn verbs_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "array",
        "description": "Ordered list of TwiML verbs. Each item has a `verb` discriminator (say/play/gather/record/dial/reject/hangup/pause/redirect/message) plus verb-specific fields.",
        "items": { "type": "object", "required": ["verb"] }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response_is_minimal() {
        assert_eq!(
            empty_response(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response></Response>"
        );
    }

    #[test]
    fn say_and_gather_golden() {
        let verbs = vec![
            TwimlVerb::Say {
                text: "Welcome".into(),
                voice: Some("alice".into()),
                language: None,
            },
            TwimlVerb::Gather {
                input: Some("dtmf".into()),
                action: Some("/hooks/gather/CA123".into()),
                num_digits: Some(1),
                speech_timeout: None,
                timeout: Some(5),
                nested: vec![TwimlVerb::Say {
                    text: "Press one".into(),
                    voice: None,
                    language: None,
                }],
            },
        ];
        let xml = render(&verbs);
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>\
             <Say voice=\"alice\">Welcome</Say>\
             <Gather input=\"dtmf\" action=\"/hooks/gather/CA123\" numDigits=\"1\" timeout=\"5\">\
             <Say>Press one</Say></Gather></Response>"
        );
    }

    #[test]
    fn play_golden() {
        let xml = render(&[TwimlVerb::Play {
            url: "https://cdn.example.com/a.mp3".into(),
        }]);
        assert!(xml.contains("<Play>https://cdn.example.com/a.mp3</Play>"));
    }

    #[test]
    fn dial_number_golden() {
        let xml = render(&[TwimlVerb::Dial {
            number: Some("+15551234567".into()),
            sip: None,
            client: None,
            conference: None,
            caller_id: Some("+15557654321".into()),
        }]);
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>\
             <Dial callerId=\"+15557654321\">+15551234567</Dial></Response>"
        );
    }

    #[test]
    fn reject_golden() {
        assert_eq!(
            reject_response(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Reject/></Response>"
        );
    }

    #[test]
    fn sms_auto_reply_golden() {
        let xml = render(&[TwimlVerb::Message {
            body: "Thanks, we got your message".into(),
            media_url: vec![],
        }]);
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>\
             <Message><Body>Thanks, we got your message</Body></Message></Response>"
        );
    }

    #[test]
    fn text_is_xml_escaped() {
        // A caller-supplied body with markup chars must not break the document.
        let xml = render(&[TwimlVerb::Say {
            text: "a < b & c > \"d\"".into(),
            voice: None,
            language: None,
        }]);
        assert!(xml.contains("a &lt; b &amp; c &gt; &quot;d&quot;"));
        assert!(!xml.contains("a < b"));
    }

    #[test]
    fn unknown_verb_fails_to_deserialize() {
        let r: Result<TwimlVerb, _> =
            serde_json::from_value(serde_json::json!({ "verb": "teleport" }));
        assert!(r.is_err());
    }

    #[test]
    fn say_verb_round_trips_from_json() {
        let v: TwimlVerb = serde_json::from_value(serde_json::json!({
            "verb": "say", "text": "hi", "voice": "man"
        }))
        .unwrap();
        assert_eq!(
            v,
            TwimlVerb::Say {
                text: "hi".into(),
                voice: Some("man".into()),
                language: None
            }
        );
    }
}
