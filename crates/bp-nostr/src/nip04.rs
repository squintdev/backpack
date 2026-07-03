//! NIP-04 encrypted direct messages (kind-4).
//!
//! The widely-deployed legacy DM scheme: ECDH over secp256k1, then
//! AES-256-CBC with the shared point's **unhashed x-coordinate** as the key
//! (a NIP-04 quirk — standard ECDH would hash it), content encoded as
//! `base64(ciphertext)?iv=base64(iv)`.
//!
//! Interop is why this exists; privacy is why it's deprecated upstream:
//! the ciphertext hides the text, but sender, recipient, timing, and
//! approximate length are public relay data. NIP-17 gift wraps fix that and
//! can be added alongside later.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Kind for a NIP-04 encrypted direct message.
pub const KIND_DM: u32 = 4;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The NIP-04 shared key: x-coordinate of `sk * P(their_xonly)`.
///
/// The x-only pubkey lifts to the even-Y point, per BIP340 convention.
fn shared_x(sk: &[u8; 32], their_xonly: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    // Lift x-only key to a full point (0x02 prefix = even Y).
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(their_xonly);
    let point = EncodedPoint::from_bytes(sec1).map_err(|_| Error::BadPubkey)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&point))
        .ok_or(Error::BadPubkey)?;

    let scalar = Option::<Scalar>::from(Scalar::from_repr((*sk).into())).ok_or(Error::BadKey)?;
    if scalar == Scalar::ZERO {
        return Err(Error::BadKey);
    }
    let shared = (ProjectivePoint::from(affine) * scalar).to_affine();
    let encoded = shared.to_encoded_point(false);
    let x = encoded.x().ok_or(Error::BadPubkey)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(x);
    Ok(out)
}

/// Encrypt `plaintext` for the holder of `their_xonly`.
pub fn encrypt(sk: &[u8; 32], their_xonly: &[u8; 32], plaintext: &str) -> Result<String> {
    let key = shared_x(sk, their_xonly)?;
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let ct = Aes256CbcEnc::new(key.as_ref().into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    Ok(format!("{}?iv={}", B64.encode(ct), B64.encode(iv)))
}

/// Decrypt a NIP-04 `content` string from the holder of `their_xonly`.
pub fn decrypt(sk: &[u8; 32], their_xonly: &[u8; 32], content: &str) -> Result<String> {
    let (ct_b64, iv_b64) = content
        .split_once("?iv=")
        .ok_or(Error::BadFormat("nip04 content"))?;
    let ct = B64
        .decode(ct_b64.trim())
        .map_err(|_| Error::BadFormat("nip04 ciphertext"))?;
    let iv: [u8; 16] = B64
        .decode(iv_b64.trim())
        .map_err(|_| Error::BadFormat("nip04 iv"))?
        .try_into()
        .map_err(|_| Error::BadFormat("nip04 iv"))?;

    let key = shared_x(sk, their_xonly)?;
    let pt = Aes256CbcDec::new(key.as_ref().into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| Error::Decrypt)?;
    String::from_utf8(pt).map_err(|_| Error::BadFormat("nip04 plaintext"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::pubkey_hex;

    const ALICE: [u8; 32] = [7u8; 32];
    const BOB: [u8; 32] = [11u8; 32];

    fn xonly(sk: &[u8; 32]) -> [u8; 32] {
        hex::decode(pubkey_hex(sk).unwrap()).unwrap().try_into().unwrap()
    }

    #[test]
    fn roundtrip_and_cross_key_symmetry() {
        let (a_pub, b_pub) = (xonly(&ALICE), xonly(&BOB));
        let msg = "verification code: 424242 — reply STOP to unsubscribe";
        // Alice encrypts to Bob; Bob decrypts using Alice's pubkey.
        let content = encrypt(&ALICE, &b_pub, msg).unwrap();
        assert!(content.contains("?iv="));
        assert_eq!(decrypt(&BOB, &a_pub, &content).unwrap(), msg);
    }

    #[test]
    fn wrong_key_fails() {
        let (a_pub, b_pub) = (xonly(&ALICE), xonly(&BOB));
        let content = encrypt(&ALICE, &b_pub, "secret").unwrap();
        let eve = [13u8; 32];
        // Eve holds neither key: padding check rejects.
        assert!(decrypt(&eve, &a_pub, &content).is_err());
    }

    #[test]
    fn distinct_ciphertexts_per_message() {
        let b_pub = xonly(&BOB);
        let c1 = encrypt(&ALICE, &b_pub, "x").unwrap();
        let c2 = encrypt(&ALICE, &b_pub, "x").unwrap();
        assert_ne!(c1, c2); // fresh IV each time
    }

    #[test]
    fn malformed_content_rejected() {
        let a_pub = xonly(&ALICE);
        assert!(decrypt(&BOB, &a_pub, "no-iv-separator").is_err());
        assert!(decrypt(&BOB, &a_pub, "!!!?iv=!!!").is_err());
        assert!(decrypt(&BOB, &a_pub, "AAAA?iv=AAAA").is_err()); // bad iv length
    }
}
