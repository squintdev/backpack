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
    #[error("an identity named {0:?} exists with a DIFFERENT key — rename one first")]
    Conflict(String),
    #[error("invalid identity name: {0}")]
    BadName(&'static str),
    #[error("malformed {0} string")]
    BadFormat(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A full identity: a name plus Ed25519 (signing), X25519 (agreement), and
/// secp256k1 (Nostr, BIP340 Schnorr) secret keys. Nostr uses a different curve
/// than the other two, so it is a distinct key, optional on identities created
/// before Nostr support. Secret material is zeroized on drop.
pub struct KeyPair {
    name: String,
    ed_sk: Zeroizing<[u8; 32]>,
    x_sk: Zeroizing<[u8; 32]>,
    nostr_sk: Option<Zeroizing<[u8; 32]>>,
    btc_seed: Option<Zeroizing<[u8; 32]>>,
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
            nostr_sk: Some(gen_nostr_key()),
            btc_seed: Some(gen_seed()),
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

    /// The raw secp256k1 secret key for Nostr (BIP340), if this identity has
    /// one. Identities created before Nostr support return `None` until
    /// upgraded with [`KeyStore::nostr_init`]. Zeroized on drop.
    pub fn nostr_secret(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.nostr_sk.as_ref().map(|k| Zeroizing::new(**k))
    }

    /// The raw 32-byte BIP32 master seed for Bitcoin (`sats`), if this
    /// identity has one. Identities created before Bitcoin support return
    /// `None` until upgraded with [`KeyStore::btc_init`]. Zeroized on drop.
    pub fn btc_seed(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.btc_seed.as_ref().map(|k| Zeroizing::new(**k))
    }
}

/// Generate a random 32-byte BIP32 master seed.
fn gen_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut_slice());
    seed
}

/// Generate a valid secp256k1 secret key.
fn gen_nostr_key() -> Zeroizing<[u8; 32]> {
    let sk = k256::schnorr::SigningKey::random(&mut OsRng);
    Zeroizing::new(sk.to_bytes().into())
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
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig))
            .is_ok()
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
    bytes.try_into().map_err(|_| Error::BadFormat("signature"))
}

// --- on-disk (JSON, then sealed by bp-core) -------------------------------

#[derive(Serialize, Deserialize)]
struct StoredEntry {
    name: String,
    ed25519_sk: String,
    x25519_sk: String,
    /// Absent on stores written before Nostr support; loads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nostr_sk: Option<String>,
    /// Absent on stores written before Bitcoin support; loads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    btc_seed: Option<String>,
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
            let nostr_sk = match &e.nostr_sk {
                Some(hexstr) => Some(Zeroizing::new(decode_key(hexstr)?)),
                None => None,
            };
            let btc_seed = match &e.btc_seed {
                Some(hexstr) => Some(Zeroizing::new(decode_key(hexstr)?)),
                None => None,
            };
            entries.push(KeyPair {
                name: e.name,
                ed_sk: Zeroizing::new(decode_key(&e.ed25519_sk)?),
                x_sk: Zeroizing::new(decode_key(&e.x25519_sk)?),
                nostr_sk,
                btc_seed,
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
                    nostr_sk: k.nostr_sk.as_ref().map(|s| hex::encode(**s)),
                    btc_seed: k.btc_seed.as_ref().map(|s| hex::encode(**s)),
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
        // fsync before rename: on FAT (USB drives) a yank right after rename
        // must not leave a truncated store.
        std::fs::File::open(&tmp)?.sync_all()?;
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

    /// Give an existing identity a Nostr key if it lacks one (identities
    /// created before Nostr support). Returns whether a key was added.
    pub fn nostr_init(&mut self, name: &str) -> Result<bool> {
        let kp = self
            .entries
            .iter_mut()
            .find(|k| k.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        if kp.nostr_sk.is_some() {
            return Ok(false);
        }
        kp.nostr_sk = Some(gen_nostr_key());
        Ok(true)
    }

    /// Give an existing identity a Bitcoin seed if it lacks one (identities
    /// created before Bitcoin support). Returns whether a seed was added.
    pub fn btc_init(&mut self, name: &str) -> Result<bool> {
        let kp = self
            .entries
            .iter_mut()
            .find(|k| k.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        if kp.btc_seed.is_some() {
            return Ok(false);
        }
        kp.btc_seed = Some(gen_seed());
        Ok(true)
    }

    /// Copy an identity from another store into this one.
    ///
    /// Rules: an identity with the same name and the same signing key is a
    /// no-op (`Ok(false)`); the same name with a DIFFERENT key is refused —
    /// silently overwriting keys is how coins and identities get lost.
    pub fn adopt(&mut self, from: &KeyPair) -> Result<bool> {
        if let Some(existing) = self.get(from.name()) {
            if existing.public().ed == from.public().ed {
                return Ok(false);
            }
            return Err(Error::Conflict(from.name().to_string()));
        }
        self.entries.push(KeyPair {
            name: from.name.clone(),
            ed_sk: Zeroizing::new(*from.ed_sk),
            x_sk: Zeroizing::new(*from.x_sk),
            nostr_sk: from.nostr_sk.as_ref().map(|k| Zeroizing::new(**k)),
            btc_seed: from.btc_seed.as_ref().map(|k| Zeroizing::new(**k)),
        });
        Ok(true)
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
    directories::ProjectDirs::from("", "", "backpack").map(|d| d.config_dir().join("keyring.veil"))
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
    fn nostr_key_persists_and_old_stores_upgrade() {
        let path = temp_path();
        let pass = b"pw";
        {
            let mut store = KeyStore::open(&path, pass).unwrap();
            store.generate("alice").unwrap();
            assert!(store.get("alice").unwrap().nostr_secret().is_some());
            store.save(pass).unwrap();
        }
        // Key is stable across reload.
        let reopened = KeyStore::open(&path, pass).unwrap();
        assert!(reopened.get("alice").unwrap().nostr_secret().is_some());

        // A pre-Nostr entry (no nostr_sk field in the JSON) loads as None and
        // nostr_init adds a key exactly once.
        let legacy = StoredFile {
            version: STORE_VERSION,
            entries: vec![StoredEntry {
                name: "old".to_string(),
                ed25519_sk: hex::encode([1u8; 32]),
                x25519_sk: hex::encode([2u8; 32]),
                nostr_sk: None,
                btc_seed: None,
            }],
        };
        let json = serde_json::to_vec(&legacy).unwrap();
        assert!(!String::from_utf8_lossy(&json).contains("nostr_sk"));
        let mut sealed = Vec::new();
        bp_core::seal(&mut &json[..], &mut sealed, pass).unwrap();
        std::fs::write(&path, &sealed).unwrap();

        let mut store = KeyStore::open(&path, pass).unwrap();
        assert!(store.get("old").unwrap().nostr_secret().is_none());
        assert!(store.nostr_init("old").unwrap());
        assert!(!store.nostr_init("old").unwrap()); // idempotent
        assert!(store.get("old").unwrap().nostr_secret().is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn btc_seed_persists_and_old_stores_upgrade() {
        let path = temp_path();
        let pass = b"pw";
        {
            let mut store = KeyStore::open(&path, pass).unwrap();
            store.generate("alice").unwrap();
            assert!(store.get("alice").unwrap().btc_seed().is_some());
            store.save(pass).unwrap();
        }
        let reopened = KeyStore::open(&path, pass).unwrap();
        let seed = reopened.get("alice").unwrap().btc_seed().unwrap();
        assert_ne!(*seed, [0u8; 32]);

        // Pre-Bitcoin entry upgrades exactly once.
        let legacy = StoredFile {
            version: STORE_VERSION,
            entries: vec![StoredEntry {
                name: "old".to_string(),
                ed25519_sk: hex::encode([1u8; 32]),
                x25519_sk: hex::encode([2u8; 32]),
                nostr_sk: None,
                btc_seed: None,
            }],
        };
        let json = serde_json::to_vec(&legacy).unwrap();
        let mut sealed = Vec::new();
        bp_core::seal(&mut &json[..], &mut sealed, pass).unwrap();
        std::fs::write(&path, &sealed).unwrap();
        let mut store = KeyStore::open(&path, pass).unwrap();
        assert!(store.get("old").unwrap().btc_seed().is_none());
        assert!(store.btc_init("old").unwrap());
        assert!(!store.btc_init("old").unwrap());
        assert!(store.get("old").unwrap().btc_seed().is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn adopt_copies_and_enforces_collision_rules() {
        let (src_path, dst_path) = (temp_path(), temp_path());
        let mut src = KeyStore::open(&src_path, b"srcpw").unwrap();
        src.generate("alice").unwrap();
        let alice_fp = src.get("alice").unwrap().public().fingerprint();

        // Copy into a fresh store under a different passphrase.
        let mut dst = KeyStore::open(&dst_path, b"usbpw").unwrap();
        assert!(dst.adopt(src.get("alice").unwrap()).unwrap());
        dst.save(b"usbpw").unwrap();

        // Full identity travelled: signing key, nostr, bitcoin seed.
        let reopened = KeyStore::open(&dst_path, b"usbpw").unwrap();
        let copy = reopened.get("alice").unwrap();
        assert_eq!(copy.public().fingerprint(), alice_fp);
        assert_eq!(
            copy.nostr_secret().unwrap(),
            src.get("alice").unwrap().nostr_secret().unwrap()
        );
        assert_eq!(
            copy.btc_seed().unwrap(),
            src.get("alice").unwrap().btc_seed().unwrap()
        );

        // Same identity again: no-op, not an error.
        let mut dst = KeyStore::open(&dst_path, b"usbpw").unwrap();
        assert!(!dst.adopt(src.get("alice").unwrap()).unwrap());

        // Same name, different key: refused.
        let impostor = KeyPair::generate("alice").unwrap();
        assert!(matches!(dst.adopt(&impostor), Err(Error::Conflict(_))));

        std::fs::remove_file(&src_path).ok();
        std::fs::remove_file(&dst_path).ok();
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
