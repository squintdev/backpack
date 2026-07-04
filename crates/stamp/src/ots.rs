//! The OpenTimestamps proof structure: a tree of commitment operations from
//! a file digest down to attestations, byte-compatible with the reference
//! `ots` clients.
//!
//! A timestamp for message `m` is a set of attestations about `m` plus edges
//! `(op, timestamp-for-op(m))`. Serialization interleaves them with `\xff`
//! continuation markers; `\x00` introduces an attestation.

use sha2::{Digest, Sha256};

use crate::ser::{write_varbytes, write_varuint, Reader, MAX_BYTES};
use crate::{Error, Result};

/// `\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94`
pub const HEADER_MAGIC: &[u8] = &[
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];
pub const VERSION: u64 = 1;

const TAG_ATTESTATION: u8 = 0x00;
const TAG_FORK: u8 = 0xff;
const TAG_APPEND: u8 = 0xf0;
const TAG_PREPEND: u8 = 0xf1;
const TAG_SHA1: u8 = 0x02;
const TAG_RIPEMD160: u8 = 0x03;
pub const TAG_SHA256: u8 = 0x08;

const ATTESTATION_TAG_LEN: usize = 8;
const PENDING_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Nesting cap for deserialization — real proofs are a few levels deep.
const MAX_DEPTH: u32 = 256;

// ---------------------------------------------------------------- ops

/// A commitment operation mapping one message to the next.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    /// SHA-256 of the message.
    Sha256,
    /// SHA-1 (legacy proofs only).
    Sha1,
    /// RIPEMD-160 (used in Bitcoin transaction paths of older proofs).
    Ripemd160,
    /// message ‖ arg
    Append(Vec<u8>),
    /// arg ‖ message
    Prepend(Vec<u8>),
}

impl Op {
    pub fn apply(&self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() > MAX_BYTES {
            return Err(Error::BadFormat("message too long"));
        }
        Ok(match self {
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Sha1 => {
                use sha1::Sha1;
                Sha1::digest(msg).to_vec()
            }
            Op::Ripemd160 => {
                use ripemd::Ripemd160;
                Ripemd160::digest(msg).to_vec()
            }
            Op::Append(a) => {
                let mut v = msg.to_vec();
                v.extend_from_slice(a);
                v
            }
            Op::Prepend(a) => {
                let mut v = a.clone();
                v.extend_from_slice(msg);
                v
            }
        })
    }

    fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            Op::Sha256 => out.push(TAG_SHA256),
            Op::Sha1 => out.push(TAG_SHA1),
            Op::Ripemd160 => out.push(TAG_RIPEMD160),
            Op::Append(a) => {
                out.push(TAG_APPEND);
                write_varbytes(out, a);
            }
            Op::Prepend(a) => {
                out.push(TAG_PREPEND);
                write_varbytes(out, a);
            }
        }
    }

    fn deserialize(tag: u8, r: &mut Reader) -> Result<Op> {
        Ok(match tag {
            TAG_SHA256 => Op::Sha256,
            TAG_SHA1 => Op::Sha1,
            TAG_RIPEMD160 => Op::Ripemd160,
            TAG_APPEND => Op::Append(r.read_varbytes(MAX_BYTES)?.to_vec()),
            TAG_PREPEND => Op::Prepend(r.read_varbytes(MAX_BYTES)?.to_vec()),
            _ => return Err(Error::UnsupportedOp(tag)),
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Op::Sha256 => "sha256".into(),
            Op::Sha1 => "sha1".into(),
            Op::Ripemd160 => "ripemd160".into(),
            Op::Append(a) => format!("append {}", hex::encode(a)),
            Op::Prepend(a) => format!("prepend {}", hex::encode(a)),
        }
    }
}

// ---------------------------------------------------------------- attestations

/// A claim that some external system observed the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attestation {
    /// A calendar server has the commitment and will anchor it; `uri` is
    /// where to fetch the upgrade.
    Pending { uri: String },
    /// The commitment is the merkle root of Bitcoin block `height`.
    Bitcoin { height: u64 },
    /// Unrecognized attestation type, preserved byte-exactly.
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

impl Attestation {
    fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            Attestation::Pending { uri } => {
                out.extend_from_slice(&PENDING_TAG);
                let mut payload = Vec::new();
                write_varbytes(&mut payload, uri.as_bytes());
                write_varbytes(out, &payload);
            }
            Attestation::Bitcoin { height } => {
                out.extend_from_slice(&BITCOIN_TAG);
                let mut payload = Vec::new();
                write_varuint(&mut payload, *height);
                write_varbytes(out, &payload);
            }
            Attestation::Unknown { tag, payload } => {
                out.extend_from_slice(tag);
                write_varbytes(out, payload);
            }
        }
    }

    fn deserialize(r: &mut Reader) -> Result<Attestation> {
        let tag: [u8; 8] = r
            .read_bytes(ATTESTATION_TAG_LEN)?
            .try_into()
            .expect("fixed length");
        let payload = r.read_varbytes(MAX_BYTES)?;
        let mut pr = Reader::new(payload);
        Ok(match tag {
            PENDING_TAG => {
                let uri = String::from_utf8(pr.read_varbytes(1000)?.to_vec())
                    .map_err(|_| Error::BadFormat("calendar uri utf8"))?;
                Attestation::Pending { uri }
            }
            BITCOIN_TAG => Attestation::Bitcoin {
                height: pr.read_varuint()?,
            },
            _ => Attestation::Unknown {
                tag,
                payload: payload.to_vec(),
            },
        })
    }

    /// Canonical sort key — the reference client orders attestations by
    /// their serialized bytes.
    fn sort_key(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.serialize(&mut v);
        v
    }
}

// ---------------------------------------------------------------- timestamp

/// Attestations and onward operations for one message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Op, Timestamp)>,
}

impl Timestamp {
    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty() && self.ops.is_empty()
    }

    /// Merge another timestamp for the same message into this one.
    pub fn merge(&mut self, other: Timestamp) {
        for a in other.attestations {
            if !self.attestations.contains(&a) {
                self.attestations.push(a);
            }
        }
        for (op, sub) in other.ops {
            if let Some((_, existing)) = self.ops.iter_mut().find(|(o, _)| *o == op) {
                existing.merge(sub);
            } else {
                self.ops.push((op, sub));
            }
        }
    }

    /// All attestations in the tree, with the message each one attests to.
    pub fn walk(&self, msg: &[u8]) -> Result<Vec<(Vec<u8>, Attestation)>> {
        let mut out = Vec::new();
        for a in &self.attestations {
            out.push((msg.to_vec(), a.clone()));
        }
        for (op, sub) in &self.ops {
            out.extend(sub.walk(&op.apply(msg)?)?);
        }
        Ok(out)
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.is_empty() {
            return Err(Error::BadFormat("empty timestamp"));
        }
        let mut attestations = self.attestations.clone();
        attestations.sort_by_key(Attestation::sort_key);
        let mut ops: Vec<&(Op, Timestamp)> = self.ops.iter().collect();
        ops.sort_by(|a, b| a.0.cmp(&b.0));

        if attestations.len() > 1 {
            for a in &attestations[..attestations.len() - 1] {
                out.push(TAG_FORK);
                out.push(TAG_ATTESTATION);
                a.serialize(out);
            }
        }
        if ops.is_empty() {
            out.push(TAG_ATTESTATION);
            attestations.last().expect("non-empty").serialize(out);
            return Ok(());
        }
        if let Some(last) = attestations.last() {
            out.push(TAG_FORK);
            out.push(TAG_ATTESTATION);
            last.serialize(out);
        }
        for (op, sub) in &ops[..ops.len() - 1] {
            out.push(TAG_FORK);
            op.serialize(out);
            sub.serialize(out)?;
        }
        let (op, sub) = ops.last().expect("non-empty");
        op.serialize(out);
        sub.serialize(out)
    }

    pub fn deserialize(r: &mut Reader) -> Result<Timestamp> {
        Self::deserialize_inner(r, 0)
    }

    fn deserialize_inner(r: &mut Reader, depth: u32) -> Result<Timestamp> {
        if depth > MAX_DEPTH {
            return Err(Error::BadFormat("proof nests too deep"));
        }
        let mut ts = Timestamp::default();
        loop {
            let tag = r.read_byte()?;
            let (entry_tag, last) = if tag == TAG_FORK {
                (r.read_byte()?, false)
            } else {
                (tag, true)
            };
            if entry_tag == TAG_ATTESTATION {
                ts.attestations.push(Attestation::deserialize(r)?);
            } else {
                let op = Op::deserialize(entry_tag, r)?;
                ts.ops.push((op, Self::deserialize_inner(r, depth + 1)?));
            }
            if last {
                return Ok(ts);
            }
        }
    }
}

// ---------------------------------------------------------------- proof file

/// A detached `.ots` proof: the file's SHA-256 digest plus its timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub digest: [u8; 32],
    pub timestamp: Timestamp,
}

impl Proof {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(HEADER_MAGIC);
        write_varuint(&mut out, VERSION);
        out.push(TAG_SHA256);
        out.extend_from_slice(&self.digest);
        self.timestamp.serialize(&mut out)?;
        Ok(out)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Proof> {
        let mut r = Reader::new(buf);
        if r.read_bytes(HEADER_MAGIC.len()).ok() != Some(HEADER_MAGIC) {
            return Err(Error::BadFormat("not an OpenTimestamps proof"));
        }
        if r.read_varuint()? != VERSION {
            return Err(Error::BadFormat("unsupported proof version"));
        }
        if r.read_byte()? != TAG_SHA256 {
            return Err(Error::BadFormat("unsupported file hash op"));
        }
        let digest: [u8; 32] = r.read_bytes(32)?.try_into().expect("fixed length");
        let timestamp = Timestamp::deserialize(&mut r)?;
        if !r.is_empty() {
            return Err(Error::BadFormat("trailing bytes after proof"));
        }
        Ok(Proof { digest, timestamp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Proof {
        let digest = [7u8; 32];
        let mut pending = Timestamp::default();
        pending.attestations.push(Attestation::Pending {
            uri: "https://alice.btc.calendar.opentimestamps.org".into(),
        });
        let mut bitcoin = Timestamp::default();
        bitcoin
            .attestations
            .push(Attestation::Bitcoin { height: 900_000 });
        let mut after_sha = Timestamp::default();
        after_sha.ops.push((Op::Prepend(vec![0xaa; 32]), bitcoin));
        after_sha.attestations.push(Attestation::Pending {
            uri: "https://bob.btc.calendar.opentimestamps.org".into(),
        });
        let mut root = Timestamp::default();
        root.ops.push((
            Op::Append(vec![1, 2, 3, 4]),
            Timestamp {
                attestations: vec![],
                ops: vec![(Op::Sha256, after_sha)],
            },
        ));
        root.merge(pending);
        Proof {
            digest,
            timestamp: root,
        }
    }

    #[test]
    fn proof_roundtrips_byte_exactly() {
        let p = sample();
        let bytes = p.serialize().unwrap();
        let q = Proof::deserialize(&bytes).unwrap();
        assert_eq!(q.serialize().unwrap(), bytes);
        assert_eq!(q.digest, p.digest);
    }

    #[test]
    fn ops_apply_correctly() {
        assert_eq!(Op::Append(vec![3, 4]).apply(&[1, 2]).unwrap(), [1, 2, 3, 4]);
        assert_eq!(Op::Prepend(vec![0]).apply(&[1]).unwrap(), [0, 1]);
        assert_eq!(
            Op::Sha256.apply(b"hello").unwrap(),
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap()
        );
    }

    #[test]
    fn walk_reaches_all_attestations_with_correct_messages() {
        let p = sample();
        let found = p.timestamp.walk(&p.digest).unwrap();
        assert_eq!(found.len(), 3);
        // The bitcoin attestation's message: prepend(aa*32, sha256(digest ‖ 01020304)).
        let inner = Op::Sha256
            .apply(&Op::Append(vec![1, 2, 3, 4]).apply(&p.digest).unwrap())
            .unwrap();
        let expected = Op::Prepend(vec![0xaa; 32]).apply(&inner).unwrap();
        let btc = found
            .iter()
            .find(|(_, a)| matches!(a, Attestation::Bitcoin { .. }))
            .unwrap();
        assert_eq!(btc.0, expected);
    }

    #[test]
    fn merge_deduplicates_and_deepens() {
        let mut a = Timestamp::default();
        a.attestations.push(Attestation::Bitcoin { height: 1 });
        let mut b = Timestamp::default();
        b.attestations.push(Attestation::Bitcoin { height: 1 });
        b.ops.push((Op::Sha256, {
            let mut t = Timestamp::default();
            t.attestations.push(Attestation::Bitcoin { height: 2 });
            t
        }));
        a.merge(b);
        assert_eq!(a.attestations.len(), 1);
        assert_eq!(a.ops.len(), 1);
    }

    #[test]
    fn unknown_attestations_survive_roundtrip() {
        let mut ts = Timestamp::default();
        ts.attestations.push(Attestation::Unknown {
            tag: [9; 8],
            payload: vec![1, 2, 3],
        });
        let p = Proof {
            digest: [0; 32],
            timestamp: ts,
        };
        let bytes = p.serialize().unwrap();
        assert_eq!(
            Proof::deserialize(&bytes).unwrap().serialize().unwrap(),
            bytes
        );
    }

    #[test]
    fn garbage_rejected() {
        assert!(Proof::deserialize(b"not a proof").is_err());
        let mut bytes = sample().serialize().unwrap();
        bytes.push(0x00); // trailing byte
        assert!(Proof::deserialize(&bytes).is_err());
    }
}
