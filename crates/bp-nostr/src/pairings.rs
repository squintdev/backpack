//! Persisted NIP-46 pairings: which client pubkeys have authorized with the
//! bunker secret, per identity.
//!
//! NIP-46 clients send `connect` once, at pairing time; on later sessions
//! they sign straight away and expect the signer to remember them. Pairings
//! survive signer restarts via a plain text file (client pubkeys are public
//! information — nothing secret lives here):
//!
//! ```text
//! <identity> <client pubkey hex>
//! ```
//!
//! Revoke a client by deleting its line (or the whole file) and restarting
//! the signer.

use std::path::{Path, PathBuf};

/// `~/.config/backpack/bunker-pairings.txt` (or `$BACKPACK_PAIRINGS`).
pub fn default_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BACKPACK_PAIRINGS") {
        return Some(PathBuf::from(p));
    }
    directories::ProjectDirs::from("", "", "backpack")
        .map(|d| d.config_dir().join("bunker-pairings.txt"))
}

/// Client pubkeys previously paired with `identity`. Missing file = none.
pub fn load(path: &Path, identity: &str) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(id), Some(pk)) if id == identity && pk.len() == 64 => Some(pk.to_string()),
                _ => None,
            }
        })
        .collect()
}

/// Record a pairing (idempotent).
pub fn add(path: &Path, identity: &str, client_pubkey: &str) -> std::io::Result<()> {
    if load(path, identity).iter().any(|p| p == client_pubkey) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = std::fs::read_to_string(path).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{identity} {client_pubkey}\n"));
    std::fs::write(path, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pairings-test-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn add_load_roundtrip_and_isolation() {
        let p = temp();
        let pk_a = "a".repeat(64);
        let pk_b = "b".repeat(64);
        assert!(load(&p, "alice").is_empty());
        add(&p, "alice", &pk_a).unwrap();
        add(&p, "alice", &pk_a).unwrap(); // idempotent
        add(&p, "bob", &pk_b).unwrap();
        assert_eq!(load(&p, "alice"), vec![pk_a]);
        assert_eq!(load(&p, "bob"), vec![pk_b]);
        // Garbage lines are ignored.
        std::fs::write(&p, "junk\nalice tooshort\n").unwrap();
        assert!(load(&p, "alice").is_empty());
        std::fs::remove_file(&p).ok();
    }
}
