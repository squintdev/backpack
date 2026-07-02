//! Client-side NIP-01 relay frames.
//!
//! Outgoing: `["EVENT", <event>]`, `["REQ", <sub>, <filter>]`, `["CLOSE", <sub>]`.
//! Incoming: `["EVENT", <sub>, <event>]`, `["EOSE", <sub>]`, `["OK", <id>, <bool>, <msg>]`,
//! `["NOTICE", <msg>]`.

use serde::Serialize;
use serde_json::{json, Value};

use crate::event::Event;

/// A subscription filter (the subset the CLI uses).
#[derive(Debug, Default, Serialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `["EVENT", …]` frame to publish an event.
pub fn publish_frame(ev: &Event) -> String {
    json!(["EVENT", ev]).to_string()
}

/// `["REQ", …]` frame opening a subscription.
pub fn req_frame(sub_id: &str, filter: &Filter) -> String {
    json!(["REQ", sub_id, filter]).to_string()
}

/// `["CLOSE", …]` frame ending a subscription.
pub fn close_frame(sub_id: &str) -> String {
    json!(["CLOSE", sub_id]).to_string()
}

/// A parsed message from the relay.
#[derive(Debug)]
pub enum RelayMsg {
    Event(Box<Event>),
    /// End of stored events for our subscription.
    Eose,
    /// `OK` result for a published event: (event id, accepted, message).
    Ok(String, bool, String),
    Notice(String),
    /// Anything unrecognized (ignored by callers).
    Other,
}

/// Parse one incoming relay frame.
pub fn parse(text: &str) -> RelayMsg {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return RelayMsg::Other;
    };
    let Some(arr) = v.as_array() else {
        return RelayMsg::Other;
    };
    match arr.first().and_then(Value::as_str) {
        Some("EVENT") if arr.len() >= 3 => {
            match serde_json::from_value::<Event>(arr[2].clone()) {
                Ok(ev) => RelayMsg::Event(Box::new(ev)),
                Err(_) => RelayMsg::Other,
            }
        }
        Some("EOSE") => RelayMsg::Eose,
        Some("OK") if arr.len() >= 3 => RelayMsg::Ok(
            arr[1].as_str().unwrap_or_default().to_string(),
            arr[2].as_bool().unwrap_or(false),
            arr.get(3).and_then(Value::as_str).unwrap_or_default().to_string(),
        ),
        Some("NOTICE") => RelayMsg::Notice(
            arr.get(1).and_then(Value::as_str).unwrap_or_default().to_string(),
        ),
        _ => RelayMsg::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sign_event;

    #[test]
    fn frames_are_wellformed() {
        let ev = sign_event(&[7u8; 32], 1, 1, vec![], "hi".into()).unwrap();
        let pf = publish_frame(&ev);
        assert!(pf.starts_with(r#"["EVENT",{"#));

        let f = Filter {
            authors: Some(vec!["ab".into()]),
            kinds: Some(vec![1]),
            limit: Some(10),
        };
        let rf = req_frame("sub1", &f);
        assert!(rf.contains(r#""authors":["ab"]"#) && rf.contains(r#""limit":10"#));
        // Unset fields stay off the wire (some relays reject nulls).
        assert!(!req_frame("s", &Filter::default()).contains("null"));

        assert_eq!(close_frame("sub1"), r#"["CLOSE","sub1"]"#);
    }

    #[test]
    fn parses_relay_messages() {
        let ev = sign_event(&[7u8; 32], 1, 1, vec![], "hi".into()).unwrap();
        let frame = format!(r#"["EVENT","sub1",{}]"#, serde_json::to_string(&ev).unwrap());
        assert!(matches!(parse(&frame), RelayMsg::Event(e) if e.content == "hi"));

        assert!(matches!(parse(r#"["EOSE","sub1"]"#), RelayMsg::Eose));
        assert!(matches!(
            parse(r#"["OK","abc",true,""]"#),
            RelayMsg::Ok(id, true, _) if id == "abc"
        ));
        assert!(matches!(parse(r#"["NOTICE","slow down"]"#), RelayMsg::Notice(m) if m == "slow down"));
        assert!(matches!(parse("not json"), RelayMsg::Other));
        assert!(matches!(parse(r#"{"obj":1}"#), RelayMsg::Other));
    }
}
