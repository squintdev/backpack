//! `stamp` — timestamp proofs: prove a file existed at a point in time
//! without revealing its contents.
//!
//! OpenTimestamps-compatible. `stamp` hashes the file (SHA-256), blinds the
//! digest with a random nonce (calendars never see the raw file hash), and
//! submits the commitment to public calendar servers, which aggregate
//! commitments into a Bitcoin transaction. The `.ots` proof file this
//! produces — and the ones it verifies — interoperate with the reference
//! `ots` clients.
//!
//! Lifecycle: [`stamp`] writes a *pending* proof immediately; hours later
//! (after Bitcoin confirmation) [`upgrade`] replaces the pending attestation
//! with a permanent Bitcoin one; [`verify`] then needs only the file, the
//! proof, and any way to look up a block's merkle root.

pub mod calendar;
pub mod ots;
pub mod ser;

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use ots::{Attestation, Op, Proof, Timestamp};

#[derive(Debug, Error)]
pub enum Error {
    #[error("malformed proof: {0}")]
    BadFormat(&'static str),
    #[error("unsupported operation 0x{0:02x} in proof")]
    UnsupportedOp(u8),
    #[error("calendar: {0}")]
    Calendar(String),
    #[error("no calendar accepted the commitment")]
    NoCalendar,
}

pub type Result<T> = std::result::Result<T, Error>;

/// SHA-256 of a reader (the file being stamped/verified).
pub fn digest_reader<R: std::io::Read + ?Sized>(r: &mut R) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    std::io::copy(r, &mut hasher)?;
    Ok(hasher.finalize().into())
}

/// Stamp a digest: blind it with a fresh 16-byte nonce, submit the
/// commitment to every calendar, and assemble the pending proof.
/// Succeeds if at least one calendar accepts; per-calendar failures are
/// reported in the returned list as `Err`.
pub fn stamp(digest: [u8; 32], calendars: &[&str]) -> (Result<Proof>, Vec<(String, Result<()>)>) {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    // commitment = sha256(digest ‖ nonce)
    let append = Op::Append(nonce.to_vec());
    let blinded = append.apply(&digest).expect("digest fits");
    let commitment = Op::Sha256.apply(&blinded).expect("hash");

    let mut at_commitment = Timestamp::default();
    let mut outcomes = Vec::new();
    for cal in calendars {
        match calendar::submit(cal, &commitment) {
            Ok(ts) => {
                at_commitment.merge(ts);
                outcomes.push((cal.to_string(), Ok(())));
            }
            Err(e) => outcomes.push((cal.to_string(), Err(e))),
        }
    }
    if at_commitment.is_empty() {
        return (Err(Error::NoCalendar), outcomes);
    }

    let timestamp = Timestamp {
        attestations: vec![],
        ops: vec![(
            append,
            Timestamp {
                attestations: vec![],
                ops: vec![(Op::Sha256, at_commitment)],
            },
        )],
    };
    (Ok(Proof { digest, timestamp }), outcomes)
}

/// Try to replace pending attestations with Bitcoin ones by asking each
/// pending calendar for its upgraded timestamp. Returns how many pending
/// attestations were upgraded; the proof keeps its pending entries for any
/// calendar that hasn't anchored yet.
pub fn upgrade(proof: &mut Proof) -> Result<(usize, usize)> {
    let pending = proof.timestamp.walk(&proof.digest)?;
    let mut upgraded = 0;
    let mut remaining = 0;
    for (msg, att) in pending {
        let Attestation::Pending { uri } = att else {
            continue;
        };
        match calendar::upgrade(&uri, &msg)? {
            Some(ts) => {
                merge_at(&mut proof.timestamp, &proof.digest, &msg, ts)?;
                remove_pending(&mut proof.timestamp, &proof.digest, &msg, &uri)?;
                upgraded += 1;
            }
            None => remaining += 1,
        }
    }
    Ok((upgraded, remaining))
}

/// The result of checking one attestation during verification.
#[derive(Clone, Debug)]
pub enum Check {
    /// Bitcoin attestation whose commitment matches block `height`'s merkle
    /// root; `block_time` is that block's timestamp.
    BitcoinVerified { height: u64, block_time: u64 },
    /// Bitcoin attestation that does NOT match the block's merkle root.
    BitcoinMismatch { height: u64 },
    /// Bitcoin attestation present but not checked (offline).
    BitcoinUnchecked { height: u64 },
    /// Still waiting on a calendar (run `stamp upgrade`).
    Pending { uri: String },
    /// Attestation type this tool doesn't know.
    Unknown,
}

/// Verify `proof` against a file digest. Walks every op path and checks each
/// Bitcoin attestation's commitment against the block merkle root via
/// Esplora (`esplora = None` skips the network and reports `Unchecked`).
pub fn verify(proof: &Proof, digest: [u8; 32], esplora: Option<&str>) -> Result<Vec<Check>> {
    if proof.digest != digest {
        return Err(Error::BadFormat("digest does not match the file"));
    }
    let mut checks = Vec::new();
    for (msg, att) in proof.timestamp.walk(&digest)? {
        checks.push(match att {
            Attestation::Bitcoin { height } => match esplora {
                Some(api) => {
                    let (root, block_time) = calendar::block_merkle_root(api, height)?;
                    if msg == root {
                        Check::BitcoinVerified { height, block_time }
                    } else {
                        Check::BitcoinMismatch { height }
                    }
                }
                None => Check::BitcoinUnchecked { height },
            },
            Attestation::Pending { uri } => Check::Pending { uri },
            Attestation::Unknown { .. } => Check::Unknown,
        });
    }
    Ok(checks)
}

/// Graft `ts` onto the node whose message is `target`.
fn merge_at(root: &mut Timestamp, msg: &[u8], target: &[u8], ts: Timestamp) -> Result<()> {
    if msg == target {
        root.merge(ts);
        return Ok(());
    }
    for (op, sub) in &mut root.ops {
        merge_at(sub, &op.apply(msg)?, target, ts.clone())?;
    }
    Ok(())
}

/// Drop the pending attestation for `uri` at the node whose message is
/// `target` (after that calendar's Bitcoin attestation replaced it).
fn remove_pending(root: &mut Timestamp, msg: &[u8], target: &[u8], uri: &str) -> Result<()> {
    if msg == target {
        root.attestations
            .retain(|a| !matches!(a, Attestation::Pending { uri: u } if u == uri));
        return Ok(());
    }
    for (op, sub) in &mut root.ops {
        remove_pending(sub, &op.apply(msg)?, target, uri)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_with(att: Attestation) -> (Proof, Vec<u8>) {
        let digest = [3u8; 32];
        let nonce_op = Op::Append(vec![5; 16]);
        let blinded = nonce_op.apply(&digest).unwrap();
        let commitment = Op::Sha256.apply(&blinded).unwrap();
        let at_commit = Timestamp {
            attestations: vec![att],
            ops: vec![],
        };
        let proof = Proof {
            digest,
            timestamp: Timestamp {
                attestations: vec![],
                ops: vec![(
                    nonce_op,
                    Timestamp {
                        attestations: vec![],
                        ops: vec![(Op::Sha256, at_commit)],
                    },
                )],
            },
        };
        (proof, commitment)
    }

    #[test]
    fn verify_rejects_wrong_digest() {
        let (proof, _) = proof_with(Attestation::Bitcoin { height: 1 });
        assert!(verify(&proof, [9u8; 32], None).is_err());
    }

    #[test]
    fn verify_offline_reports_unchecked_and_pending() {
        let (proof, _) = proof_with(Attestation::Bitcoin { height: 800_000 });
        let checks = verify(&proof, proof.digest, None).unwrap();
        assert!(matches!(
            checks[..],
            [Check::BitcoinUnchecked { height: 800_000 }]
        ));

        let (proof, _) = proof_with(Attestation::Pending {
            uri: "https://x".into(),
        });
        let checks = verify(&proof, proof.digest, None).unwrap();
        assert!(matches!(checks[..], [Check::Pending { .. }]));
    }

    #[test]
    fn merge_at_grafts_bitcoin_and_remove_pending_cleans_up() {
        let (mut proof, commitment) = proof_with(Attestation::Pending {
            uri: "https://cal".into(),
        });
        let upgraded = Timestamp {
            attestations: vec![],
            ops: vec![(
                Op::Prepend(vec![1; 32]),
                Timestamp {
                    attestations: vec![Attestation::Bitcoin { height: 42 }],
                    ops: vec![],
                },
            )],
        };
        let digest = proof.digest;
        merge_at(&mut proof.timestamp, &digest, &commitment, upgraded).unwrap();
        remove_pending(&mut proof.timestamp, &digest, &commitment, "https://cal").unwrap();

        let atts: Vec<Attestation> = proof
            .timestamp
            .walk(&digest)
            .unwrap()
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        assert_eq!(atts, vec![Attestation::Bitcoin { height: 42 }]);
        // Still serializes cleanly after surgery.
        let bytes = proof.serialize().unwrap();
        assert_eq!(Proof::deserialize(&bytes).unwrap(), proof);
    }
}
