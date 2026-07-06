//! The unlocked keystore session shared by every screen.
//!
//! The keystore is unlocked once, in-TUI, when the launcher starts; the
//! passphrase is retained (zeroized on drop) so mutations can re-seal the
//! store without prompting again.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use keyring::{KeyStore, PublicIdentity};
use zeroize::Zeroizing;

pub struct Session {
    pub store: KeyStore,
    pub path: PathBuf,
    pass: Zeroizing<String>,
}

impl Session {
    /// Resolve the keystore path (`$BACKPACK_KEYRING` or the config dir).
    pub fn keystore_path() -> Result<PathBuf> {
        keyring::default_keystore_path()
            .ok_or_else(|| anyhow!("cannot determine keystore path; set {}", keyring::PATH_ENV))
    }

    /// True if no keystore exists yet (first run: set a passphrase).
    pub fn is_new() -> bool {
        Self::keystore_path().map(|p| !p.exists()).unwrap_or(true)
    }

    /// Unlock (or create) the keystore with `pass`.
    pub fn unlock(pass: &str) -> Result<Self> {
        let path = Self::keystore_path()?;
        let store = KeyStore::open(&path, pass.as_bytes())?;
        Ok(Session {
            store,
            path,
            pass: Zeroizing::new(pass.to_string()),
        })
    }

    /// Re-seal the store to disk after a mutation.
    pub fn save(&self) -> Result<()> {
        self.store.save(self.pass.as_bytes())?;
        Ok(())
    }

    /// Change the keystore passphrase: verify `current`, re-seal the store
    /// under `new`, and hold `new` for the rest of the session. The write is
    /// atomic — a failure leaves the store sealed under the old passphrase.
    pub fn rekey(&mut self, current: &str, new: &str) -> Result<()> {
        if current != self.pass.as_str() {
            return Err(anyhow!("current passphrase is wrong"));
        }
        if new.is_empty() {
            return Err(anyhow!("new passphrase must not be empty"));
        }
        self.store.save(new.as_bytes())?;
        self.pass = Zeroizing::new(new.to_string());
        Ok(())
    }

    pub fn identities(&self) -> Vec<PublicIdentity> {
        self.store.identities()
    }

    /// Name of the first identity, as a convenient default for forms.
    pub fn first_identity(&self) -> Option<String> {
        self.identities().first().map(|i| i.name.clone())
    }

    /// The Nostr secret key for an identity, with a helpful error if the
    /// identity is missing or predates Nostr support.
    pub fn nostr_key(&self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        let kp = self
            .store
            .get(name)
            .ok_or_else(|| anyhow!("no identity named {name:?}"))?;
        kp.nostr_secret().ok_or_else(|| {
            anyhow!("{name} has no Nostr key yet (press n on IDENTITIES to add one)")
        })
    }
}
