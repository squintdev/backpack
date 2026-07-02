//! `bp-core` — shared crypto primitives for the backpack tool suite.
//!
//! Every tool in the suite depends on this crate so that one audited layer of
//! AEAD, KDF, and stream framing is reused everywhere instead of duplicated.
//!
//! # Example
//! ```
//! use bp_core::{seal, open};
//!
//! let plaintext = b"attack at dawn";
//! let mut ciphertext = Vec::new();
//! seal(&mut &plaintext[..], &mut ciphertext, b"correct horse").unwrap();
//!
//! let mut recovered = Vec::new();
//! open(&mut &ciphertext[..], &mut recovered, b"correct horse").unwrap();
//! assert_eq!(recovered, plaintext);
//! ```

pub mod error;
pub mod kdf;
pub mod pubkey;
pub mod stream;

pub use error::{Error, Result};
pub use pubkey::{open_as_recipient, seal_to_recipient};
pub use stream::{open, open_with_key, seal, seal_with_key, MAGIC};
