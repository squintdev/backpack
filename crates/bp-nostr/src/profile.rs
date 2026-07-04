//! Kind-0 profile metadata (NIP-01 "set_metadata").
//!
//! A profile is a replaceable event whose `content` is a JSON object
//! (`name`, `about`, `picture`, `nip05`, …). Other clients may have written
//! fields this module doesn't know about (banner, lud16, website), so edits
//! operate on the **raw JSON map** — change only the requested keys, keep
//! everything else — and republish the merged object. A typed struct would
//! silently drop unknown fields.

use serde_json::{Map, Value};

use crate::event::Event;

/// Kind for profile metadata.
pub const KIND_METADATA: u32 = 0;

/// The fields backpack knows how to display and edit. Everything else is
/// preserved verbatim through [`merged_content`].
pub const KNOWN_FIELDS: &[&str] = &["name", "about", "picture", "nip05"];

/// Parse a kind-0 event's content into its JSON map. Malformed content yields
/// an empty map (some relays carry junk kind-0s).
pub fn parse_profile(ev: &Event) -> Map<String, Value> {
    serde_json::from_str::<Value>(&ev.content)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// A displayable string field from a profile map.
pub fn field(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Merge `updates` into an existing profile map and serialize the result.
///
/// An update with a non-empty value sets the key; an empty value removes it;
/// keys absent from `updates` — including ones backpack doesn't model — are
/// preserved untouched.
pub fn merged_content(mut current: Map<String, Value>, updates: &[(&str, String)]) -> String {
    for (key, value) in updates {
        if value.trim().is_empty() {
            current.remove(*key);
        } else {
            current.insert(key.to_string(), Value::String(value.trim().to_string()));
        }
    }
    Value::Object(current).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sign_event;

    fn ev(content: &str) -> Event {
        sign_event(&[7u8; 32], 1, KIND_METADATA, vec![], content.to_string()).unwrap()
    }

    #[test]
    fn parse_and_field() {
        let map = parse_profile(&ev(r#"{"name":"fj","about":"","lud16":"x@y.z"}"#));
        assert_eq!(field(&map, "name").as_deref(), Some("fj"));
        assert_eq!(field(&map, "about"), None); // empty -> None
        assert_eq!(field(&map, "lud16").as_deref(), Some("x@y.z"));
        assert!(parse_profile(&ev("not json")).is_empty());
    }

    #[test]
    fn merge_preserves_unknown_fields() {
        let current = parse_profile(&ev(
            r#"{"name":"old","banner":"https://b","lud16":"x@y.z"}"#,
        ));
        let out = merged_content(current, &[("name", "new".into()), ("about", "hi".into())]);
        let back: Map<String, Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(field(&back, "name").as_deref(), Some("new"));
        assert_eq!(field(&back, "about").as_deref(), Some("hi"));
        // Fields backpack doesn't model survive the round-trip.
        assert_eq!(field(&back, "banner").as_deref(), Some("https://b"));
        assert_eq!(field(&back, "lud16").as_deref(), Some("x@y.z"));
    }

    #[test]
    fn empty_update_removes_field() {
        let current = parse_profile(&ev(r#"{"name":"old","about":"bye"}"#));
        let out = merged_content(current, &[("about", "".into())]);
        let back: Map<String, Value> = serde_json::from_str(&out).unwrap();
        assert!(field(&back, "about").is_none());
        assert_eq!(field(&back, "name").as_deref(), Some("old"));
    }
}
