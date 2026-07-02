//! NIP-19 bech32 encoding for public keys (`npub`).

use bech32::{Bech32, Hrp};

use crate::{Error, Result};

/// Encode a 32-byte x-only public key as an `npub1…` string.
pub fn npub_encode(pubkey: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").expect("static hrp");
    bech32::encode::<Bech32>(hrp, pubkey).expect("32 bytes always encode")
}

/// Decode an `npub1…` string to the 32-byte public key.
pub fn npub_decode(s: &str) -> Result<[u8; 32]> {
    let (hrp, data) = bech32::decode(s.trim()).map_err(|_| Error::BadNpub("not bech32"))?;
    if hrp.as_str() != "npub" {
        return Err(Error::BadNpub("wrong prefix (expected npub)"));
    }
    data.try_into().map_err(|_| Error::BadNpub("wrong length"))
}

/// Accept either an `npub1…` or 64-char hex form of a public key; return hex.
pub fn pubkey_to_hex(s: &str) -> Result<String> {
    let s = s.trim();
    if s.starts_with("npub1") {
        return Ok(hex::encode(npub_decode(s)?));
    }
    let bytes = hex::decode(s).map_err(|_| Error::BadNpub("neither npub nor hex"))?;
    if bytes.len() != 32 {
        return Err(Error::BadNpub("wrong length"));
    }
    Ok(s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from NIP-19.
    const HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    #[test]
    fn nip19_vector() {
        let pk: [u8; 32] = hex::decode(HEX).unwrap().try_into().unwrap();
        assert_eq!(npub_encode(&pk), NPUB);
        assert_eq!(npub_decode(NPUB).unwrap(), pk);
    }

    #[test]
    fn roundtrip_random() {
        let pk = [0xABu8; 32];
        assert_eq!(npub_decode(&npub_encode(&pk)).unwrap(), pk);
    }

    #[test]
    fn pubkey_to_hex_accepts_both() {
        assert_eq!(pubkey_to_hex(NPUB).unwrap(), HEX);
        assert_eq!(pubkey_to_hex(HEX).unwrap(), HEX);
        assert!(pubkey_to_hex("nsec1notapub").is_err());
        assert!(pubkey_to_hex("zzzz").is_err());
    }
}
