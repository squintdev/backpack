//! Public-key file encryption (anonymous sender / sealed-box style).
//!
//! Encrypts to a recipient's X25519 public key so no shared passphrase is
//! needed. A fresh ephemeral keypair is generated per message; the shared
//! secret is `X25519(ephemeral_sk, recipient_pk)`, run through HKDF-SHA256 to a
//! 32-byte key, which then drives the [`stream`](crate::stream) chunk cipher.
//!
//! On-disk layout:
//! ```text
//! MAGIC "VEILX1\n" (7) || ephemeral_pubkey (32) || stream body
//! ```
//! The recipient recomputes the same shared secret from
//! `X25519(recipient_sk, ephemeral_pk)`.

use rand_core::{OsRng, RngCore};
use std::io::{Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::stream;

/// Stream format magic + version for public-key mode.
pub const MAGIC: &[u8; 7] = b"VEILX1\n";

/// Derive the 32-byte content key from a shared secret and both public keys.
fn derive(shared: &[u8; 32], ephemeral_pk: &[u8; 32], recipient_pk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = [0u8; 64];
    info[..32].copy_from_slice(ephemeral_pk);
    info[32..].copy_from_slice(recipient_pk);

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut_slice()).map_err(|_| Error::Kdf)?;
    Ok(key)
}

/// Encrypt `reader` into `writer` for the holder of `recipient_pk` (an X25519
/// public key).
pub fn seal_to_recipient<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    recipient_pk: &[u8; 32],
) -> Result<()> {
    let mut eph_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(eph_bytes.as_mut_slice());
    let eph_sk = StaticSecret::from(*eph_bytes);
    let eph_pk = PublicKey::from(&eph_sk).to_bytes();

    let shared = eph_sk.diffie_hellman(&PublicKey::from(*recipient_pk));
    if !shared.was_contributory() {
        // Recipient key is a low-order point; the shared secret is all-zero.
        return Err(Error::Encrypt);
    }
    let key = derive(shared.as_bytes(), &eph_pk, recipient_pk)?;

    writer.write_all(MAGIC)?;
    writer.write_all(&eph_pk)?;
    stream::seal_with_key(reader, writer, &key)
}

/// Decrypt `reader` (produced by [`seal_to_recipient`]) into `writer` using the
/// recipient's X25519 secret key.
pub fn open_as_recipient<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    recipient_sk: &[u8; 32],
) -> Result<()> {
    let mut magic = [0u8; MAGIC.len()];
    reader.read_exact(&mut magic).map_err(|_| Error::BadHeader)?;
    if &magic != MAGIC {
        return Err(Error::BadHeader);
    }
    let mut eph_pk = [0u8; 32];
    reader.read_exact(&mut eph_pk).map_err(|_| Error::BadHeader)?;

    let sk = StaticSecret::from(*recipient_sk);
    let recipient_pk = PublicKey::from(&sk).to_bytes();
    let shared = sk.diffie_hellman(&PublicKey::from(eph_pk));
    if !shared.was_contributory() {
        return Err(Error::Decrypt);
    }
    let key = derive(shared.as_bytes(), &eph_pk, &recipient_pk)?;

    stream::open_with_key(reader, writer, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        let sk = StaticSecret::from(sk_bytes);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk_bytes, pk)
    }

    #[test]
    fn roundtrip() {
        let (sk, pk) = keypair();
        let data = b"meet at the safehouse";
        let mut ct = Vec::new();
        seal_to_recipient(&mut &data[..], &mut ct, &pk).unwrap();
        assert!(ct.starts_with(MAGIC));

        let mut pt = Vec::new();
        open_as_recipient(&mut &ct[..], &mut pt, &sk).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn wrong_recipient_fails() {
        let (_sk_a, pk_a) = keypair();
        let (sk_b, _pk_b) = keypair();
        let mut ct = Vec::new();
        seal_to_recipient(&mut &b"secret"[..], &mut ct, &pk_a).unwrap();
        // Decrypting with a different secret key must fail authentication.
        let mut pt = Vec::new();
        assert!(open_as_recipient(&mut &ct[..], &mut pt, &sk_b).is_err());
    }

    #[test]
    fn different_ciphertexts_each_time() {
        let (_sk, pk) = keypair();
        let mut a = Vec::new();
        let mut b = Vec::new();
        seal_to_recipient(&mut &b"x"[..], &mut a, &pk).unwrap();
        seal_to_recipient(&mut &b"x"[..], &mut b, &pk).unwrap();
        assert_ne!(a, b); // fresh ephemeral key per message
    }

    #[test]
    fn low_order_recipient_rejected() {
        // All-zero point is low order; sealing to it must error.
        let mut ct = Vec::new();
        assert!(seal_to_recipient(&mut &b"x"[..], &mut ct, &[0u8; 32]).is_err());
    }
}
