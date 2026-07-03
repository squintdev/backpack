//! NIP-44 v2 encryption — the current Nostr encrypted-payload scheme, used by
//! NIP-46 remote signing and modern DMs.
//!
//! secp256k1 ECDH → the conversation key is `HKDF-Extract(salt="nip44-v2",
//! ikm=shared_x)`. Per message: a 32-byte nonce expands (HKDF-Expand) to a
//! ChaCha20 key+nonce and an HMAC key; the plaintext is length-prefixed and
//! padded, ChaCha20-encrypted, then MAC'd with HMAC-SHA256 over `nonce ‖
//! ciphertext`. Payload = `base64(0x02 ‖ nonce ‖ ciphertext ‖ mac)`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;
const VERSION: u8 = 2;

/// The per-pair conversation key: `HKDF-Extract(salt="nip44-v2", shared_x)`.
fn conversation_key(sk: &[u8; 32], their_xonly: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let shared = crate::nip04::shared_x(sk, their_xonly)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared[..]);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    Ok(out)
}

/// Expand the conversation key + nonce into ChaCha20 key (32), ChaCha20 nonce
/// (12), and HMAC key (32).
fn message_keys(conv: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hk = Hkdf::<Sha256>::from_prk(conv).expect("32-byte prk");
    let mut okm = [0u8; 76];
    hk.expand(nonce, &mut okm).expect("76 <= 255*32");
    let mut ck = [0u8; 32];
    let mut cn = [0u8; 12];
    let mut hmk = [0u8; 32];
    ck.copy_from_slice(&okm[0..32]);
    cn.copy_from_slice(&okm[32..44]);
    hmk.copy_from_slice(&okm[44..76]);
    (ck, cn, hmk)
}

/// NIP-44 padded length for `unpadded` plaintext bytes.
fn calc_padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    // 1 << (floor(log2(len-1)) + 1) — the bit length of (len-1) as a u32.
    let bits = u32::BITS - ((unpadded - 1) as u32).leading_zeros();
    let next_power = 1usize << bits;
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((unpadded - 1) / chunk + 1)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let len = plaintext.len();
    if !(1..=65535).contains(&len) {
        return Err(Error::BadFormat("nip44 length"));
    }
    let padded_len = calc_padded_len(len);
    let mut out = Vec::with_capacity(2 + padded_len);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(2 + padded_len, 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<String> {
    if padded.len() < 2 {
        return Err(Error::BadFormat("nip44 padded"));
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len == 0 || 2 + len > padded.len() || padded.len() != 2 + calc_padded_len(len) {
        return Err(Error::BadFormat("nip44 padding"));
    }
    String::from_utf8(padded[2..2 + len].to_vec()).map_err(|_| Error::BadFormat("nip44 utf8"))
}

fn hmac_with_aad(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(aad);
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Encrypt `plaintext` for `their_xonly`, returning the base64 payload.
pub fn encrypt(sk: &[u8; 32], their_xonly: &[u8; 32], plaintext: &str) -> Result<String> {
    let conv = conversation_key(sk, their_xonly)?;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let (ck, cn, hmk) = message_keys(&conv, &nonce);

    let mut buf = pad(plaintext.as_bytes())?;
    ChaCha20::new(&ck.into(), &cn.into()).apply_keystream(&mut buf);
    let mac = hmac_with_aad(&hmk, &nonce, &buf);

    let mut payload = Vec::with_capacity(1 + 32 + buf.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&buf);
    payload.extend_from_slice(&mac);
    Ok(B64.encode(payload))
}

/// Decrypt a base64 NIP-44 payload from `their_xonly`.
pub fn decrypt(sk: &[u8; 32], their_xonly: &[u8; 32], payload: &str) -> Result<String> {
    let data = B64
        .decode(payload.trim())
        .map_err(|_| Error::BadFormat("nip44 base64"))?;
    if data.len() < 1 + 32 + 32 || data[0] != VERSION {
        return Err(Error::BadFormat("nip44 payload"));
    }
    let nonce: [u8; 32] = data[1..33].try_into().unwrap();
    let ct = &data[33..data.len() - 32];
    let mac = &data[data.len() - 32..];

    let conv = conversation_key(sk, their_xonly)?;
    let (ck, cn, hmk) = message_keys(&conv, &nonce);

    // Constant-time MAC check before touching the ciphertext.
    let mut verifier = HmacSha256::new_from_slice(&hmk).expect("hmac key");
    verifier.update(&nonce);
    verifier.update(ct);
    verifier.verify_slice(mac).map_err(|_| Error::Decrypt)?;

    let mut buf = ct.to_vec();
    ChaCha20::new(&ck.into(), &cn.into()).apply_keystream(&mut buf);
    unpad(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::pubkey_hex;

    fn xonly(sk: &[u8; 32]) -> [u8; 32] {
        hex::decode(pubkey_hex(sk).unwrap()).unwrap().try_into().unwrap()
    }

    #[test]
    fn padded_len_matches_spec() {
        assert_eq!(calc_padded_len(1), 32);
        assert_eq!(calc_padded_len(32), 32);
        assert_eq!(calc_padded_len(33), 64);
        assert_eq!(calc_padded_len(65), 96);
        assert_eq!(calc_padded_len(100), 128);
        assert_eq!(calc_padded_len(256), 256);
        assert_eq!(calc_padded_len(512), 512);
    }

    #[test]
    fn roundtrip_and_symmetry() {
        let (alice, bob) = ([1u8; 32], [2u8; 32]);
        let (a_pub, b_pub) = (xonly(&alice), xonly(&bob));
        let msg = "connect: sign this, key stays on the deck ✍";
        let ct = encrypt(&alice, &b_pub, msg).unwrap();
        // Both directions derive the same conversation key.
        assert_eq!(decrypt(&bob, &a_pub, &ct).unwrap(), msg);
    }

    #[test]
    fn official_conversation_key_vector() {
        // NIP-44 test vector: sec1 = 1, sec2 = 2.
        let mut sec1 = [0u8; 32];
        sec1[31] = 1;
        let mut sec2 = [0u8; 32];
        sec2[31] = 2;
        let ck = conversation_key(&sec1, &xonly(&sec2)).unwrap();
        assert_eq!(
            hex::encode(*ck),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );
    }

    #[test]
    fn conversation_key_is_symmetric() {
        let (alice, bob) = ([5u8; 32], [9u8; 32]);
        let ka = conversation_key(&alice, &xonly(&bob)).unwrap();
        let kb = conversation_key(&bob, &xonly(&alice)).unwrap();
        assert_eq!(*ka, *kb);
    }

    #[test]
    fn tamper_and_wrong_key_rejected() {
        let (alice, bob) = ([1u8; 32], [2u8; 32]);
        let (a_pub, b_pub) = (xonly(&alice), xonly(&bob));
        let ct = encrypt(&alice, &b_pub, "secret").unwrap();
        // Flip a payload byte -> MAC fails.
        let mut raw = B64.decode(&ct).unwrap();
        let n = raw.len() - 40;
        raw[n] ^= 1;
        let bad = B64.encode(raw);
        assert!(decrypt(&bob, &a_pub, &bad).is_err());
        // Third party can't read it.
        let eve = [3u8; 32];
        assert!(decrypt(&eve, &a_pub, &ct).is_err());
    }

    #[test]
    fn distinct_ciphertexts_per_message() {
        let b_pub = xonly(&[2u8; 32]);
        let a = encrypt(&[1u8; 32], &b_pub, "x").unwrap();
        let b = encrypt(&[1u8; 32], &b_pub, "x").unwrap();
        assert_ne!(a, b);
    }
}
