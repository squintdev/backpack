//! Live network tests — read-only, against public relays.
//!
//! Ignored by default (network-dependent, non-deterministic); run explicitly:
//! `cargo test -p bp-nostr --test live -- --ignored`

use bp_nostr::client::{fetch_timeline, latest_contacts, resolve_relays};
use bp_nostr::contacts::parse_contacts;

/// fiatjaf — Nostr's author; a stable, heavily-followed account.
const FIATJAF: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

#[test]
#[ignore = "hits public relays"]
fn fetch_real_contact_list_and_timeline() {
    let relays = resolve_relays(&[]);

    let ev = latest_contacts(&relays, FIATJAF)
        .expect("relays reachable")
        .expect("fiatjaf has a contact list");
    let contacts = parse_contacts(&ev);
    assert!(!contacts.is_empty(), "expected a non-empty follow list");

    // Timeline over a slice of his follows: merged, deduped, newest-first.
    let authors: Vec<String> = contacts.iter().take(20).map(|c| c.pubkey.clone()).collect();
    let events = fetch_timeline(&relays, authors, 15).expect("timeline fetch");
    assert!(!events.is_empty(), "expected some notes");
    assert!(events.windows(2).all(|w| w[0].created_at >= w[1].created_at));
    let mut ids: Vec<&String> = events.iter().map(|e| &e.id).collect();
    ids.dedup();
    assert_eq!(ids.len(), events.len(), "no duplicate events");
}
