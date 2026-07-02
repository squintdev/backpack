//! `veil` — file encryption for the backpack suite.
//!
//! Library layer over [`bp_core`]: key-mode selection, output naming, and
//! atomic file writes. The `veil` CLI and the `backpack` launcher both build
//! on this so behavior stays identical.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Extension appended to encrypted files.
pub const EXT: &str = "veil";

/// How to derive the encryption key.
pub enum EncKey<'a> {
    Passphrase(&'a [u8]),
    /// Recipient's X25519 public key (from a keyring `BPKEY1` line).
    Recipient([u8; 32]),
}

/// How to derive the decryption key.
pub enum DecKey<'a> {
    Passphrase(&'a [u8]),
    /// Recipient's X25519 secret key (from the keyring).
    IdentitySecret(&'a [u8; 32]),
}

/// Encrypt any reader into any writer.
pub fn encrypt_stream<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    key: &EncKey,
) -> Result<()> {
    match key {
        EncKey::Passphrase(p) => bp_core::seal(reader, writer, p)?,
        EncKey::Recipient(pk) => bp_core::seal_to_recipient(reader, writer, pk)?,
    }
    Ok(())
}

/// Decrypt any reader into any writer.
pub fn decrypt_stream<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    key: &DecKey,
) -> Result<()> {
    match key {
        DecKey::Passphrase(p) => bp_core::open(reader, writer, p)?,
        DecKey::IdentitySecret(sk) => bp_core::open_as_recipient(reader, writer, sk)?,
    }
    Ok(())
}

/// Default encrypted name: `<input>.veil`.
pub fn enc_output_for(input: &Path) -> PathBuf {
    PathBuf::from(format!("{}.{EXT}", input.display()))
}

/// Default decrypted name: strip the `.veil` suffix; error if it isn't there.
pub fn dec_output_for(input: &Path) -> Result<PathBuf> {
    if input.extension().map(|e| e == EXT).unwrap_or(false) {
        Ok(input.with_extension(""))
    } else {
        bail!("cannot infer output name for {}; choose one", input.display())
    }
}

/// Encrypt `input` to `output`, written atomically (temp sibling + rename), so
/// a failure never leaves a truncated destination.
pub fn encrypt_path(input: &Path, output: &Path, key: &EncKey) -> Result<()> {
    file_op(input, output, |r, w| encrypt_stream(r, w, key))
}

/// Decrypt `input` to `output`, written atomically. A wrong key or tampered
/// input leaves no partial output file.
pub fn decrypt_path(input: &Path, output: &Path, key: &DecKey) -> Result<()> {
    file_op(input, output, |r, w| decrypt_stream(r, w, key))
}

fn file_op<F>(input: &Path, output: &Path, op: F) -> Result<()>
where
    F: FnOnce(&mut dyn Read, &mut dyn Write) -> Result<()>,
{
    let mut reader = BufReader::new(
        File::open(input).with_context(|| format!("opening {}", input.display()))?,
    );
    let tmp = tmp_path(output);
    let file = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let mut w = BufWriter::new(file);
    match op(&mut reader, &mut w).and_then(|_| Ok(w.flush()?)) {
        Ok(()) => {
            fs::rename(&tmp, output).with_context(|| format!("finalizing {}", output.display()))?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_file(content: &[u8]) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("veil-lib-{}-{n}", std::process::id()));
        fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn path_roundtrip_passphrase() {
        let input = temp_file(b"deck secrets");
        let enc = enc_output_for(&input);
        encrypt_path(&input, &enc, &EncKey::Passphrase(b"pw")).unwrap();
        let dec = input.with_extension("out");
        decrypt_path(&enc, &dec, &DecKey::Passphrase(b"pw")).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), b"deck secrets");
        for p in [&input, &enc, &dec] {
            fs::remove_file(p).ok();
        }
    }

    #[test]
    fn wrong_passphrase_leaves_no_output() {
        let input = temp_file(b"data");
        let enc = enc_output_for(&input);
        encrypt_path(&input, &enc, &EncKey::Passphrase(b"right")).unwrap();
        let dec = input.with_extension("out");
        assert!(decrypt_path(&enc, &dec, &DecKey::Passphrase(b"wrong")).is_err());
        assert!(!dec.exists(), "failed decrypt must not leave a file");
        for p in [&input, &enc] {
            fs::remove_file(p).ok();
        }
    }

    #[test]
    fn output_naming() {
        assert_eq!(enc_output_for(Path::new("a.pdf")), Path::new("a.pdf.veil"));
        assert_eq!(
            dec_output_for(Path::new("a.pdf.veil")).unwrap(),
            Path::new("a.pdf")
        );
        assert!(dec_output_for(Path::new("noext")).is_err());
    }
}
