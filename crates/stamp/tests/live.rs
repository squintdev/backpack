//! Live network tests — hit real calendar servers and Esplora.
//! Run explicitly: `cargo test -p stamp -- --ignored`

use stamp::calendar::{DEFAULT_CALENDARS, DEFAULT_ESPLORA};
use stamp::{Attestation, Check, Op, Proof, Timestamp};

/// The official hello-world example proof from the opentimestamps-client
/// repo: sha256("Hello World!\n"), anchored in Bitcoin block 358391.
/// Reference client's own test vector — full interop check.
#[test]
#[ignore]
fn verifies_reference_hello_world_proof() {
    let body = ureq::get(
        "https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples/hello-world.txt.ots",
    )
    .call()
    .expect("fetch example proof");
    let mut bytes = Vec::new();
    use std::io::Read;
    body.into_reader().read_to_end(&mut bytes).unwrap();

    let proof = Proof::deserialize(&bytes).expect("parse reference proof");
    let digest = {
        let mut r: &[u8] = b"Hello World!\n";
        stamp::digest_reader(&mut r).unwrap()
    };
    let checks = stamp::verify(&proof, digest, Some(DEFAULT_ESPLORA)).expect("verify");
    assert!(
        checks
            .iter()
            .any(|c| matches!(c, Check::BitcoinVerified { height: 358391, .. })),
        "{checks:?}"
    );
}

/// Round-trip against a real calendar: submit a commitment, get a pending
/// timestamp back, and confirm every path ends in a pending attestation.
#[test]
#[ignore]
fn calendar_accepts_submission() {
    let digest = [0x42u8; 32];
    let (proof, outcomes) = stamp::stamp(digest, &DEFAULT_CALENDARS[..1]);
    assert!(outcomes.iter().any(|(_, r)| r.is_ok()), "{outcomes:?}");
    let proof = proof.unwrap();
    let atts = proof.timestamp.walk(&digest).unwrap();
    assert!(!atts.is_empty());
    assert!(atts
        .iter()
        .all(|(_, a)| matches!(a, Attestation::Pending { .. })));
    // And the written form parses back byte-identically.
    let bytes = proof.serialize().unwrap();
    assert_eq!(Proof::deserialize(&bytes).unwrap(), proof);
}

/// Esplora merkle-root lookup returns the internal byte order we compare
/// against: block 358391's root must match the reference proof's commitment.
#[test]
#[ignore]
fn esplora_block_lookup() {
    let (root, time) = stamp::calendar::block_merkle_root(DEFAULT_ESPLORA, 358391).unwrap();
    assert_eq!(
        hex::encode(root),
        "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a"
    );
    assert_eq!(time, 1432827678);
    let _ = Op::Sha256; // keep imports honest
    let _ = Timestamp::default();
}
