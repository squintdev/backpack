//! `bp-nostr` — a minimal Nostr (NIP-01) implementation for the backpack suite.
//!
//! Covers exactly what the CLI needs, with no async runtime:
//!
//! * [`event`] — build, id, sign (BIP340 Schnorr over secp256k1), and verify
//!   Nostr events.
//! * [`nip19`] — bech32 `npub` encoding/decoding of public keys.
//! * [`relay`] — the client-side JSON frames (`EVENT`, `REQ`, `CLOSE`) and
//!   parsing of relay responses.
//! * [`contacts`] — NIP-02 kind-3 contact lists (follows, petnames).
//!
//! Identity keys come from the suite's `keyring` (each identity carries a
//! secp256k1 key alongside its Ed25519/X25519 pair).

pub mod client;
pub mod contacts;
pub mod event;
pub mod nip04;
pub mod nip19;
pub mod profile;
pub mod relay;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid secret key")]
    BadKey,
    #[error("invalid public key")]
    BadPubkey,
    #[error("malformed npub: {0}")]
    BadNpub(&'static str),
    #[error("event serialization failed")]
    Serialize,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed {0}")]
    BadFormat(&'static str),
    #[error("decryption failed (wrong key or corrupted message)")]
    Decrypt,
}

pub type Result<T> = std::result::Result<T, Error>;
