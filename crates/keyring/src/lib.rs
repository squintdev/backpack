//! `keyring` — manage signing/encryption identities for the backpack suite.
//!
//! Each identity holds an Ed25519 signing keypair and an X25519 key-agreement
//! keypair. Private keys live in a [`KeyStore`] that is encrypted at rest with
//! the suite's own crypto core (`bp-core`): the whole store is sealed under a
//! passphrase, so the on-disk file is a `VEIL1` ciphertext.
//!
//! Public identities and signatures are single-line, copy-pasteable text:
//! ```text
//! BPKEY1 <name> <ed25519 pubkey hex> <x25519 pubkey hex>
//! BPSIG1 <ed25519 signature hex>
//! ```

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

const KEY_TAG: &str = "BPKEY1";
const SIG_TAG: &str = "BPSIG1";
const STORE_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] bp_core::Error),
    #[error("keystore is corrupt: {0}")]
    Corrupt(String),
    #[error("no identity named {0:?}")]
    NotFound(String),
    #[error("an identity named {0:?} already exists")]
    Duplicate(String),
    #[error("invalid identity name: {0}")]
    BadName(&'static str),
    #[error("malformed {0} string")]
    BadFormat(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A full identity: a name plus Ed25519 (signing) and X25519 (agreement) secret
/// keys. Secret material is zeroized on drop.
pub struct KeyPair {
    name: String,
    ed_sk: Zeroizing<[u8; 32]>,
    x_sk: Zeroizing<[u8; 32]>,
}

impl KeyPair {
    /// Generate a fresh identity with random keys.
    pub fn generate(name: &str) -> Result<Self> {
        validate_name(name)?;
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut x = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(ed.as_mut_slice());
        OsRng.fill_bytes(x.as_mut_slice());
        Ok(KeyPair {
            name: name.to_string(),
            ed_sk: ed,
            x_sk: x,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed_sk)
    }

    fn ed_public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    fn x_public(&self) -> [u8; 32] {
        let secret = StaticSecret::from(*self.x_sk);
        XPublicKey::from(&secret).to_bytes()
    }

    /// The public half of this identity, safe to share.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            name: self.name.clone(),
            ed: self.ed_public(),
            x: self.x_public(),
        }
    }

    /// Sign a message with the Ed25519 key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key().sign(msg).to_bytes()
    }

    /// The raw X25519 secret key, for public-key decryption (`veil` recipient
    /// mode). Zeroized on drop.
    pub fn x_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.x_sk)
    }
}

/// The shareable public half of an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub name: String,
    pub ed: [u8; 32],
    pub x: [u8; 32],
}

impl PublicIdentity {
    /// Short human-comparable fingerprint of the signing key.
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.ed);
        let hex = hex::encode(&hash[..8]);
        // Group as xxxx-xxxx-xxxx-xxxx for readability.
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Serialize to the one-line `BPKEY1 …` wire format.
    pub fn to_line(&self) -> String {
        format!(
            "{KEY_TAG} {} {} {}",
            self.name,
            hex::encode(self.ed),
            hex::encode(self.x)
        )
    }

    /// Parse a `BPKEY1 …` line. Extra whitespace and surrounding blank lines are
    /// tolerated; the name must be a single whitespace-free token.
    pub fn parse(s: &str) -> Result<Self> {
        let line = s
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(KEY_TAG))
            .ok_or(Error::BadFormat("public identity"))?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            return Err(Error::BadFormat("public identity"));
        }
        Ok(PublicIdentity {
            name: parts[1].to_string(),
            ed: decode_key(parts[2])?,
            x: decode_key(parts[3])?,
        })
    }

    /// Verify an Ed25519 signature over `msg` against this identity.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.ed) else {
            return false;
        };
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
    }
}

/// Serialize a signature to the `BPSIG1 …` wire format.
pub fn format_signature(sig: &[u8; 64]) -> String {
    format!("{SIG_TAG} {}", hex::encode(sig))
}

/// Parse a `BPSIG1 …` line into a 64-byte signature.
pub fn parse_signature(s: &str) -> Result<[u8; 64]> {
    let line = s
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(SIG_TAG))
        .ok_or(Error::BadFormat("signature"))?;
    let hexpart = line
        .split_whitespace()
        .nth(1)
        .ok_or(Error::BadFormat("signature"))?;
    let bytes = hex::decode(hexpart).map_err(|_| Error::BadFormat("signature"))?;
    bytes
        .try_into()
        .map_err(|_| Error::BadFormat("signature"))
}

// --- on-disk (JSON, then sealed by bp-core) -------------------------------

#[derive(Serialize, Deserialize)]
struct StoredEntry {
    name: String,
    ed25519_sk: String,
    x25519_sk: String,
}

#[derive(Serialize, Deserialize)]
struct StoredFile {
    version: u8,
    entries: Vec<StoredEntry>,
}

/// A passphrase-encrypted collection of [`KeyPair`]s backed by a file.
pub struct KeyStore {
    path: PathBuf,
    entries: Vec<KeyPair>,
}

impl KeyStore {
    /// Open the store at `path`, decrypting with `passphrase`. A missing file
    /// yields an empty store (created on first [`save`](KeyStore::save)).
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        if !path.exists() {
            return Ok(KeyStore {
                path: path.to_path_buf(),
                entries: Vec::new(),
            });
        }
        let sealed = std::fs::read(path)?;
        let mut json = Vec::new();
        bp_core::open(&mut &sealed[..], &mut json, passphrase)?;
        let file: StoredFile =
            serde_json::from_slice(&json).map_err(|e| Error::Corrupt(e.to_string()))?;
        if file.version != STORE_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported store version {}",
                file.version
            )));
        }
        let mut entries = Vec::with_capacity(file.entries.len());
        for e in file.entries {
            entries.push(KeyPair {
                name: e.name,
                ed_sk: Zeroizing::new(decode_key(&e.ed25519_sk)?),
                x_sk: Zeroizing::new(decode_key(&e.x25519_sk)?),
            });
        }
        Ok(KeyStore {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Encrypt and write the store to its file, atomically.
    pub fn save(&self, passphrase: &[u8]) -> Result<()> {
        let file = StoredFile {
            version: STORE_VERSION,
            entries: self
                .entries
                .iter()
                .map(|k| StoredEntry {
                    name: k.name.clone(),
                    ed25519_sk: hex::encode(*k.ed_sk),
                    x25519_sk: hex::encode(*k.x_sk),
                })
                .collect(),
        };
        let json = serde_json::to_vec(&file).map_err(|e| Error::Corrupt(e.to_string()))?;
        let mut sealed = Vec::new();
        bp_core::seal(&mut &json[..], &mut sealed, passphrase)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &sealed)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Generate a new identity and add it. Errors if the name is taken.
    pub fn generate(&mut self, name: &str) -> Result<&KeyPair> {
        validate_name(name)?;
        if self.get(name).is_some() {
            return Err(Error::Duplicate(name.to_string()));
        }
        self.entries.push(KeyPair::generate(name)?);
        Ok(self.entries.last().unwrap())
    }

    pub fn get(&self, name: &str) -> Option<&KeyPair> {
        self.entries.iter().find(|k| k.name == name)
    }

    /// Remove an identity by name, returning whether it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|k| k.name != name);
        self.entries.len() != before
    }

    /// Public identities of every stored key.
    pub fn identities(&self) -> Vec<PublicIdentity> {
        self.entries.iter().map(KeyPair::public).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Environment variable overriding the keystore path.
pub const PATH_ENV: &str = "BACKPACK_KEYRING";

/// Default keystore path: `$BACKPACK_KEYRING`, else the per-user config dir.
///
/// Returns `None` only if neither the env var is set nor a config directory can
/// be determined. Shared so other suite tools (e.g. `veil` recipient mode) look
/// in the same place.
pub fn default_keystore_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(PATH_ENV) {
        return Some(PathBuf::from(p));
    }
    directories::ProjectDirs::from("", "", "backpack")
        .map(|d| d.config_dir().join("keyring.veil"))
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::BadName("must not be empty"));
    }
    if name.len() > 64 {
        return Err(Error::BadName("must be at most 64 characters"));
    }
    if name.chars().any(|c| c.is_whitespace()) {
        return Err(Error::BadName("must not contain whitespace"));
    }
    Ok(())
}

fn decode_key(hexstr: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hexstr).map_err(|_| Error::BadFormat("key hex"))?;
    bytes.try_into().map_err(|_| Error::BadFormat("key length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("keyring-test-{}-{n}.veil", std::process::id()))
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::generate("alice").unwrap();
        let msg = b"transfer 10 to bob";
        let sig = kp.sign(msg);
        assert!(kp.public().verify(msg, &sig));
        assert!(!kp.public().verify(b"transfer 100 to bob", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!kp.public().verify(msg, &bad));
    }

    #[test]
    fn identity_line_roundtrip() {
        let id = KeyPair::generate("bob").unwrap().public();
        let parsed = PublicIdentity::parse(&id.to_line()).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn signature_line_roundtrip() {
        let kp = KeyPair::generate("carol").unwrap();
        let sig = kp.sign(b"hi");
        assert_eq!(parse_signature(&format_signature(&sig)).unwrap(), sig);
    }

    #[test]
    fn bad_names_rejected() {
        assert!(KeyPair::generate("").is_err());
        assert!(KeyPair::generate("has space").is_err());
    }

    #[test]
    fn store_persists_and_reopens() {
        let path = temp_path();
        let pass = b"open sesame";
        {
            let mut store = KeyStore::open(&path, pass).unwrap();
            assert!(store.is_empty());
            store.generate("alice").unwrap();
            store.generate("bob").unwrap();
            assert!(store.generate("alice").is_err()); // duplicate
            store.save(pass).unwrap();
        }
        let reopened = KeyStore::open(&path, pass).unwrap();
        let names: Vec<String> = reopened.identities().into_iter().map(|i| i.name).collect();
        assert_eq!(names, vec!["alice".to_string(), "bob".to_string()]);

        // A signature made after reload verifies against the stored key.
        let alice = reopened.get("alice").unwrap();
        let sig = alice.sign(b"msg");
        assert!(alice.public().verify(b"msg", &sig));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let path = temp_path();
        {
            let mut store = KeyStore::open(&path, b"right").unwrap();
            store.generate("alice").unwrap();
            store.save(b"right").unwrap();
        }
        assert!(KeyStore::open(&path, b"wrong").is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn stored_key_is_stable_across_reload() {
        let path = temp_path();
        let pass = b"pw";
        let line;
        {
            let mut store = KeyStore::open(&path, pass).unwrap();
            store.generate("alice").unwrap();
            line = store.get("alice").unwrap().public().to_line();
            store.save(pass).unwrap();
        }
        let reopened = KeyStore::open(&path, pass).unwrap();
        assert_eq!(reopened.get("alice").unwrap().public().to_line(), line);
        std::fs::remove_file(&path).ok();
    }
}
