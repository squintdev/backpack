//! `cph-core` — shared crypto primitives for the cipherpunk tool suite.
//!
//! Every tool in the suite depends on this crate so that one audited layer of
//! AEAD, KDF, and stream framing is reused everywhere instead of duplicated.
//!
//! # Example
//! ```
//! use cph_core::{seal, open};
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
pub mod stream;

pub use error::{Error, Result};
pub use stream::{open, seal, MAGIC};
