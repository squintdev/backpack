//! NIP-01 events: canonical id computation, BIP340 signing, verification.

use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Kind for a short text note.
pub const KIND_TEXT_NOTE: u32 = 1;

/// A Nostr event as it travels over the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// The x-only public key (hex) for a secret key.
pub fn pubkey_hex(secret: &[u8; 32]) -> Result<String> {
    let sk = SigningKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    Ok(hex::encode(sk.verifying_key().to_bytes()))
}

/// Compute the canonical NIP-01 event id: the SHA-256 of
/// `[0, pubkey, created_at, kind, tags, content]` serialized as compact JSON.
pub fn event_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32]> {
    let canonical = serde_json::to_string(&(
        0u8,
        pubkey,
        created_at,
        kind,
        tags,
        content,
    ))
    .map_err(|_| Error::Serialize)?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Build and sign an event with the given secp256k1 secret key.
pub fn sign_event(
    secret: &[u8; 32],
    created_at: u64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
) -> Result<Event> {
    let sk = SigningKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    let id = event_id(&pubkey, created_at, kind, &tags, &content)?;

    // BIP340 with fresh auxiliary randomness.
    let mut aux = [0u8; 32];
    OsRng.fill_bytes(&mut aux);
    let sig = sk
        .sign_raw(&id, &aux)
        .map_err(|_| Error::BadSignature)?;

    Ok(Event {
        id: hex::encode(id),
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: hex::encode(sig.to_bytes()),
    })
}

/// Verify an event: its id must match its contents, and its signature must
/// verify over the id under its pubkey.
pub fn verify_event(ev: &Event) -> Result<()> {
    let id = event_id(&ev.pubkey, ev.created_at, ev.kind, &ev.tags, &ev.content)?;
    if hex::encode(id) != ev.id {
        return Err(Error::BadSignature);
    }

    let pk_bytes = hex::decode(&ev.pubkey).map_err(|_| Error::BadPubkey)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| Error::BadPubkey)?;
    let sig_bytes = hex::decode(&ev.sig).map_err(|_| Error::BadSignature)?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| Error::BadSignature)?;
    vk.verify_prehash(&id, &sig).map_err(|_| Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: [u8; 32] = [7u8; 32];

    #[test]
    fn sign_then_verify() {
        let ev = sign_event(&SK, 1700000000, KIND_TEXT_NOTE, vec![], "hello".into()).unwrap();
        verify_event(&ev).unwrap();
    }

    #[test]
    fn id_is_deterministic_and_signature_randomized() {
        let a = sign_event(&SK, 1700000000, 1, vec![], "x".into()).unwrap();
        let b = sign_event(&SK, 1700000000, 1, vec![], "x".into()).unwrap();
        assert_eq!(a.id, b.id); // same canonical content -> same id
        assert_ne!(a.sig, b.sig); // fresh aux randomness -> different sigs
        verify_event(&a).unwrap();
        verify_event(&b).unwrap();
    }

    #[test]
    fn tampered_content_rejected() {
        let mut ev = sign_event(&SK, 1700000000, 1, vec![], "original".into()).unwrap();
        ev.content = "forged".into();
        assert!(verify_event(&ev).is_err());
    }

    #[test]
    fn tampered_id_rejected() {
        let mut ev = sign_event(&SK, 1700000000, 1, vec![], "note".into()).unwrap();
        // Recompute a valid-looking id for different content, keep old sig.
        ev.content = "forged".into();
        let id = event_id(&ev.pubkey, ev.created_at, ev.kind, &ev.tags, &ev.content).unwrap();
        ev.id = hex::encode(id);
        assert!(verify_event(&ev).is_err());
    }

    #[test]
    fn tags_are_part_of_the_id() {
        let a = sign_event(&SK, 1, 1, vec![], "x".into()).unwrap();
        let b = sign_event(&SK, 1, 1, vec![vec!["t".into(), "topic".into()]], "x".into()).unwrap();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn escaping_matches_json() {
        // Content with quotes, backslashes, and newlines still round-trips.
        let content = "line1\nline2 \"quoted\" back\\slash";
        let ev = sign_event(&SK, 1, 1, vec![], content.into()).unwrap();
        verify_event(&ev).unwrap();
    }
}
