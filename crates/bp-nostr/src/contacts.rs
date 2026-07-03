//! NIP-02 contact lists (kind-3 events).
//!
//! A contact list is a *replaceable* event: relays keep only the newest kind-3
//! per author, and publishing one replaces the whole list. Every mutation here
//! therefore works on a full parsed list (fetch → merge → publish), never a
//! blind write.

use crate::event::Event;

/// Kind for a contact list (NIP-02).
pub const KIND_CONTACTS: u32 = 3;

/// One followed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// x-only public key, lowercase hex.
    pub pubkey: String,
    /// Optional local nickname (NIP-02 petname).
    pub petname: Option<String>,
}

/// Parse the follows out of a kind-3 event's `p` tags.
pub fn parse_contacts(ev: &Event) -> Vec<Contact> {
    ev.tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p" && t[1].len() == 64)
        .map(|t| Contact {
            pubkey: t[1].to_ascii_lowercase(),
            petname: t.get(3).filter(|s| !s.is_empty()).cloned(),
        })
        .collect()
}

/// Build the tags for a kind-3 event from a contact list.
///
/// The relay-hint slot (index 2) is left empty; petnames go in slot 3 as per
/// NIP-02.
pub fn contact_tags(contacts: &[Contact]) -> Vec<Vec<String>> {
    contacts
        .iter()
        .map(|c| match &c.petname {
            Some(name) => vec![
                "p".to_string(),
                c.pubkey.clone(),
                String::new(),
                name.clone(),
            ],
            None => vec!["p".to_string(), c.pubkey.clone()],
        })
        .collect()
}

/// Add (or rename) a follow. Returns the updated list; idempotent for an
/// existing pubkey with the same petname.
pub fn with_contact(mut contacts: Vec<Contact>, pubkey: &str, petname: Option<String>) -> Vec<Contact> {
    let pubkey = pubkey.to_ascii_lowercase();
    match contacts.iter_mut().find(|c| c.pubkey == pubkey) {
        Some(existing) => {
            if petname.is_some() {
                existing.petname = petname;
            }
        }
        None => contacts.push(Contact { pubkey, petname }),
    }
    contacts
}

/// Remove a follow. Returns the updated list and whether anything was removed.
pub fn without_contact(mut contacts: Vec<Contact>, pubkey: &str) -> (Vec<Contact>, bool) {
    let pubkey = pubkey.to_ascii_lowercase();
    let before = contacts.len();
    contacts.retain(|c| c.pubkey != pubkey);
    let removed = contacts.len() != before;
    (contacts, removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::sign_event;

    const A: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const B: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";

    fn ev_with(contacts: &[Contact]) -> Event {
        sign_event(&[7u8; 32], 1, KIND_CONTACTS, contact_tags(contacts), String::new()).unwrap()
    }

    #[test]
    fn tags_roundtrip_with_petnames() {
        let list = vec![
            Contact { pubkey: A.into(), petname: Some("fiatjaf".into()) },
            Contact { pubkey: B.into(), petname: None },
        ];
        let ev = ev_with(&list);
        assert_eq!(parse_contacts(&ev), list);
    }

    #[test]
    fn parse_skips_malformed_tags() {
        let mut ev = ev_with(&[Contact { pubkey: A.into(), petname: None }]);
        ev.tags.push(vec!["e".into(), B.into()]); // event tag, not a follow
        ev.tags.push(vec!["p".into(), "tooshort".into()]);
        ev.tags.push(vec!["p".into()]); // missing key
        assert_eq!(parse_contacts(&ev).len(), 1);
    }

    #[test]
    fn with_contact_adds_renames_and_is_idempotent() {
        let list = with_contact(Vec::new(), A, None);
        assert_eq!(list.len(), 1);
        let list = with_contact(list, A, Some("fj".into())); // rename
        assert_eq!(list[0].petname.as_deref(), Some("fj"));
        let list = with_contact(list, A, None); // no-op, keeps petname
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].petname.as_deref(), Some("fj"));
        let list = with_contact(list, &B.to_ascii_uppercase(), None); // case-folds
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].pubkey, B);
    }

    #[test]
    fn without_contact_removes_and_reports() {
        let list = vec![
            Contact { pubkey: A.into(), petname: None },
            Contact { pubkey: B.into(), petname: None },
        ];
        let (list, removed) = without_contact(list, A);
        assert!(removed);
        assert_eq!(list.len(), 1);
        let (list, removed) = without_contact(list, A);
        assert!(!removed);
        assert_eq!(list.len(), 1);
    }
}
