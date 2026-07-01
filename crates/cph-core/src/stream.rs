//! Chunked authenticated streaming encryption (STREAM construction).
//!
//! The plaintext is split into fixed-size chunks. Each chunk is sealed with
//! ChaCha20-Poly1305 under a per-chunk nonce built from a random prefix, a
//! monotonic counter, and a final-chunk flag:
//!
//! ```text
//! nonce (12 bytes) = prefix (7) || counter_be_u32 (4) || last_flag (1)
//! ```
//!
//! The counter binds chunk order (reordering breaks authentication) and the
//! final flag binds the end of stream (truncation breaks authentication).
//!
//! On-disk layout:
//! ```text
//! MAGIC (6) || salt (16) || prefix (7) || chunk_0 || chunk_1 || ... || chunk_n
//! ```
//! where each `chunk_i` is `ciphertext || tag(16)`.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};
use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::kdf::{self, SALT_LEN};

/// Stream format magic + version.
pub const MAGIC: &[u8; 6] = b"VEIL1\n";
/// Random nonce prefix length, in bytes.
const PREFIX_LEN: usize = 7;
/// Poly1305 authentication tag length, in bytes.
const TAG_LEN: usize = 16;
/// Plaintext bytes per chunk (64 KiB).
const CHUNK: usize = 64 * 1024;
/// Ciphertext bytes per full chunk.
const ENC_CHUNK: usize = CHUNK + TAG_LEN;

fn nonce_for(prefix: &[u8; PREFIX_LEN], counter: u32, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    *Nonce::from_slice(&n)
}

/// Read into `buf` until it is full or EOF. Returns bytes read.
fn fill<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match reader.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Encrypt `reader` into `writer` using a passphrase.
///
/// A fresh random salt and nonce prefix are generated per call, so encrypting
/// the same input twice yields different ciphertext.
pub fn seal<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    passphrase: &[u8],
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; PREFIX_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut prefix);

    let key = kdf::derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&prefix)?;

    // Read-ahead by one chunk so we can flag the final chunk correctly, even
    // when the plaintext length is an exact multiple of CHUNK.
    let mut counter: u32 = 0;
    let mut cur = vec![0u8; CHUNK];
    let mut cur_len = fill(reader, &mut cur)?;
    loop {
        let mut next = vec![0u8; CHUNK];
        let next_len = fill(reader, &mut next)?;
        let last = next_len == 0;

        let nonce = nonce_for(&prefix, counter, last);
        let ct = cipher
            .encrypt(&nonce, &cur[..cur_len])
            .map_err(|_| Error::Encrypt)?;
        writer.write_all(&ct)?;

        if last {
            break;
        }
        counter = counter.checked_add(1).ok_or(Error::TooLong)?;
        cur = next;
        cur_len = next_len;
    }
    writer.flush()?;
    Ok(())
}

/// Decrypt `reader` into `writer` using a passphrase.
///
/// Fails with [`Error::Decrypt`] on a wrong passphrase or any tampering,
/// including truncation or reordering of chunks.
pub fn open<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    passphrase: &[u8],
) -> Result<()> {
    let mut magic = [0u8; MAGIC.len()];
    reader.read_exact(&mut magic).map_err(|_| Error::BadHeader)?;
    if &magic != MAGIC {
        return Err(Error::BadHeader);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; PREFIX_LEN];
    reader.read_exact(&mut salt).map_err(|_| Error::BadHeader)?;
    reader
        .read_exact(&mut prefix)
        .map_err(|_| Error::BadHeader)?;

    let key = kdf::derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));

    // Read-ahead by one ciphertext chunk to identify the final chunk by the
    // absence of following bytes, not by its size.
    let mut counter: u32 = 0;
    let mut cur = vec![0u8; ENC_CHUNK];
    let mut cur_len = fill(reader, &mut cur)?;
    loop {
        let mut next = vec![0u8; ENC_CHUNK];
        let next_len = fill(reader, &mut next)?;
        let last = next_len == 0;

        if cur_len < TAG_LEN {
            // A valid chunk is at least a tag; anything shorter is corrupt.
            return Err(Error::Decrypt);
        }
        let nonce = nonce_for(&prefix, counter, last);
        let pt = cipher
            .decrypt(&nonce, &cur[..cur_len])
            .map_err(|_| Error::Decrypt)?;
        writer.write_all(&pt)?;

        if last {
            break;
        }
        counter = counter.checked_add(1).ok_or(Error::TooLong)?;
        cur = next;
        cur_len = next_len;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8], pass: &[u8]) -> Vec<u8> {
        let mut ct = Vec::new();
        seal(&mut &data[..], &mut ct, pass).unwrap();
        let mut pt = Vec::new();
        open(&mut &ct[..], &mut pt, pass).unwrap();
        pt
    }

    #[test]
    fn roundtrip_empty() {
        assert_eq!(roundtrip(b"", b"pw"), b"");
    }

    #[test]
    fn roundtrip_small() {
        assert_eq!(roundtrip(b"hello cipherpunk", b"pw"), b"hello cipherpunk");
    }

    #[test]
    fn roundtrip_exact_chunk_boundary() {
        let data = vec![7u8; CHUNK];
        assert_eq!(roundtrip(&data, b"pw"), data);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let data = vec![9u8; CHUNK * 3 + 123];
        assert_eq!(roundtrip(&data, b"pw"), data);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let mut ct = Vec::new();
        seal(&mut &b"secret"[..], &mut ct, b"right").unwrap();
        let mut pt = Vec::new();
        assert!(matches!(
            open(&mut &ct[..], &mut pt, b"wrong"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn truncation_fails() {
        let data = vec![1u8; CHUNK * 2];
        let mut ct = Vec::new();
        seal(&mut &data[..], &mut ct, b"pw").unwrap();
        // Drop the final chunk entirely.
        ct.truncate(MAGIC.len() + SALT_LEN + PREFIX_LEN + ENC_CHUNK);
        let mut pt = Vec::new();
        assert!(open(&mut &ct[..], &mut pt, b"pw").is_err());
    }

    #[test]
    fn tamper_fails() {
        let mut ct = Vec::new();
        seal(&mut &b"tamper me"[..], &mut ct, b"pw").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let mut pt = Vec::new();
        assert!(matches!(
            open(&mut &ct[..], &mut pt, b"pw"),
            Err(Error::Decrypt)
        ));
    }
}
