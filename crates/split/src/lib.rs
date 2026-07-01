//! `split` — Shamir secret sharing with integrity detection.
//!
//! A secret is split into `n` shares such that any `k` reconstruct it and any
//! `k - 1` reveal nothing. Plain Shamir silently returns garbage when given
//! wrong or too-few shares, so this layer adds detection:
//!
//! * A 4-byte digest of the secret is split *together with* the secret, so the
//!   digest is only recoverable with `k` valid shares (it is never exposed in
//!   an individual share). On recovery a mismatch means the shares are wrong or
//!   insufficient — reported as an error instead of returning garbage.
//! * Each share string carries a 2-byte checksum that catches transcription
//!   typos before reconstruction is attempted.
//!
//! Share string format (one line, copy-pasteable):
//! ```text
//! SPLIT1-<k>-<index>-<hex share bytes>-<hex checksum>
//! ```

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use thiserror::Error;

/// Bytes of secret digest mixed into the shared payload for recovery
/// verification.
const DIGEST_LEN: usize = 4;
/// Share string prefix / version tag.
const TAG: &str = "SPLIT1";
/// Public prefix callers can use to recognize share lines.
pub const TAG_PREFIX: &str = TAG;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("threshold k must be at least 2")]
    Threshold,
    #[error("share count n must be >= k")]
    ShareCount,
    #[error("no shares provided")]
    NoShares,
    #[error("shares specify different thresholds")]
    Mismatch,
    #[error("need {need} shares, got {got}")]
    NotEnough { need: u8, got: usize },
    #[error("malformed share string")]
    Format,
    #[error("share failed its checksum (corrupted or mistyped)")]
    Checksum,
    #[error("shares do not reconstruct a valid secret (wrong or corrupted shares)")]
    WrongShares,
}

/// Split `secret` into `n` shares with recovery threshold `k`.
///
/// Returns `n` share strings. Requires `2 <= k <= n <= 255`.
pub fn deal(secret: &[u8], k: u8, n: u8) -> Result<Vec<String>, Error> {
    if k < 2 {
        return Err(Error::Threshold);
    }
    if n < k {
        return Err(Error::ShareCount);
    }

    let mut payload = secret.to_vec();
    payload.extend_from_slice(&digest(secret));

    let sharks = Sharks(k);
    let shares: Vec<Share> = sharks.dealer(&payload).take(n as usize).collect();

    Ok(shares.iter().map(|s| encode_share(s, k)).collect())
}

/// Reconstruct the secret from a set of share strings.
///
/// Deduplicates by share index, verifies each checksum, and confirms the
/// recovered secret against its embedded digest.
pub fn combine(share_strs: &[String]) -> Result<Vec<u8>, Error> {
    if share_strs.is_empty() {
        return Err(Error::NoShares);
    }

    let mut threshold: Option<u8> = None;
    let mut by_index: BTreeMap<u8, Share> = BTreeMap::new();

    for s in share_strs {
        let (k, bytes) = parse_share(s)?;
        match threshold {
            None => threshold = Some(k),
            Some(k0) if k0 != k => return Err(Error::Mismatch),
            _ => {}
        }
        let index = bytes[0];
        let share = Share::try_from(bytes.as_slice()).map_err(|_| Error::Format)?;
        by_index.insert(index, share);
    }

    let k = threshold.expect("non-empty checked above");
    if by_index.len() < k as usize {
        return Err(Error::NotEnough {
            need: k,
            got: by_index.len(),
        });
    }

    let shares: Vec<Share> = by_index.into_values().collect();
    let payload = Sharks(k)
        .recover(shares.as_slice())
        .map_err(|_| Error::WrongShares)?;

    if payload.len() < DIGEST_LEN {
        return Err(Error::WrongShares);
    }
    let (secret, tag) = payload.split_at(payload.len() - DIGEST_LEN);
    if digest(secret) != tag {
        return Err(Error::WrongShares);
    }
    Ok(secret.to_vec())
}

fn encode_share(share: &Share, k: u8) -> String {
    let bytes: Vec<u8> = Vec::from(share);
    let index = bytes[0];
    // Embed the threshold so `combine` knows how many shares are required
    // without the user passing an extra flag.
    let chk = checksum(k, &bytes);
    format!(
        "{TAG}-{k}-{index}-{}-{}",
        hex::encode(&bytes),
        hex::encode(chk)
    )
}

fn parse_share(s: &str) -> Result<(u8, Vec<u8>), Error> {
    let parts: Vec<&str> = s.trim().split('-').collect();
    if parts.len() != 5 || parts[0] != TAG {
        return Err(Error::Format);
    }
    let k: u8 = parts[1].parse().map_err(|_| Error::Format)?;
    let index: u8 = parts[2].parse().map_err(|_| Error::Format)?;
    let bytes = hex::decode(parts[3]).map_err(|_| Error::Format)?;
    let chk = hex::decode(parts[4]).map_err(|_| Error::Format)?;

    if bytes.is_empty() || bytes[0] != index {
        return Err(Error::Checksum);
    }
    if checksum(k, &bytes).as_slice() != chk.as_slice() {
        return Err(Error::Checksum);
    }
    Ok((k, bytes))
}

fn digest(secret: &[u8]) -> [u8; DIGEST_LEN] {
    let hash = Sha256::digest(secret);
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&hash[..DIGEST_LEN]);
    out
}

fn checksum(k: u8, share: &[u8]) -> [u8; 2] {
    let mut h = Sha256::new();
    h.update(TAG.as_bytes());
    h.update([k]);
    h.update(share);
    let out = h.finalize();
    [out[0], out[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"correct horse battery staple";

    #[test]
    fn roundtrip_any_k_of_n() {
        let shares = deal(SECRET, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        // Every 3-subset must recover the same secret.
        for combo in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let subset: Vec<String> = combo.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(combine(&subset).unwrap(), SECRET);
        }
    }

    #[test]
    fn more_than_k_shares_ok() {
        let shares = deal(SECRET, 2, 4).unwrap();
        assert_eq!(combine(&shares).unwrap(), SECRET);
    }

    #[test]
    fn fewer_than_k_fails() {
        let shares = deal(SECRET, 3, 5).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        assert_eq!(
            combine(&subset),
            Err(Error::NotEnough { need: 3, got: 2 })
        );
    }

    #[test]
    fn wrong_shares_detected() {
        // k shares, but from two different secrets -> digest mismatch.
        let a = deal(SECRET, 2, 3).unwrap();
        let b = deal(b"a different secret", 2, 3).unwrap();
        let mixed = vec![a[0].clone(), b[1].clone()];
        assert_eq!(combine(&mixed), Err(Error::WrongShares));
    }

    #[test]
    fn corrupted_share_fails_checksum() {
        let mut shares = deal(SECRET, 2, 3).unwrap();
        // Flip a hex digit in the share body.
        let s = &mut shares[0];
        let pos = s.rfind('-').unwrap() - 1; // inside the share-bytes field
        let ch = if s.as_bytes()[pos] == b'a' { 'b' } else { 'a' };
        s.replace_range(pos..pos + 1, &ch.to_string());
        assert_eq!(combine(&[shares[0].clone()]), Err(Error::Checksum));
    }

    #[test]
    fn duplicate_shares_do_not_count_twice() {
        let shares = deal(SECRET, 3, 5).unwrap();
        let dupes = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert_eq!(combine(&dupes), Err(Error::NotEnough { need: 3, got: 2 }));
    }

    #[test]
    fn bad_params_rejected() {
        assert_eq!(deal(SECRET, 1, 5), Err(Error::Threshold));
        assert_eq!(deal(SECRET, 4, 3), Err(Error::ShareCount));
    }

    #[test]
    fn binary_secret_roundtrip() {
        let secret: Vec<u8> = (0..=255u8).cycle().take(600).collect();
        let shares = deal(&secret, 2, 2).unwrap();
        assert_eq!(combine(&shares).unwrap(), secret);
    }
}
