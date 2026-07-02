//! `veil` CLI — thin wrapper over the veil library.
//!
//! ```text
//! veil enc secret.pdf                     # passphrase -> secret.pdf.veil
//! veil dec secret.pdf.veil                # passphrase
//! veil enc -r alice.pub secret.pdf        # to alice's public key
//! veil dec --identity alice secret.pdf.veil   # with alice's stored key
//! ```

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};

use veil::{DecKey, EncKey, EXT};

#[derive(Parser)]
#[command(
    name = "veil",
    version,
    about = "File encryptor (passphrase or public key)",
    long_about = "Encrypt and decrypt files with a passphrase or a recipient's public key.\n\n\
        Passphrase mode uses Argon2id key derivation; public-key mode uses X25519 \
        key agreement to a keyring identity. Both drive chunked ChaCha20-Poly1305 \
        authenticated encryption: tampering, truncation, or the wrong key are \
        detected and rejected. File output is written atomically, so a failed run \
        never leaves a partial destination file.",
    after_help = "EXAMPLES:\n  \
        veil enc secret.pdf              Passphrase-encrypt to secret.pdf.veil\n  \
        veil dec secret.pdf.veil         Passphrase-decrypt\n  \
        veil enc -r alice.pub secret.pdf     Encrypt to alice's public key\n  \
        veil dec --identity alice f.veil     Decrypt with alice's stored key\n  \
        tar c dir | veil enc > d.veil    Encrypt a stream\n\n\
        ENVIRONMENT:\n  \
        VEIL_PASSPHRASE        Passphrase for passphrase mode (scripts/CI).\n  \
        BACKPACK_PASSPHRASE    Keystore passphrase for --identity.\n  \
        BACKPACK_KEYRING       Keystore path for --identity.\n\n\
        SECURITY: v0.1, unaudited."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt a file (or stdin). Prompts for a passphrase twice.
    Enc(Io),
    /// Decrypt a file (or stdin). Prompts for the passphrase once.
    Dec(Io),
}

#[derive(clap::Args)]
struct Io {
    /// Input file. Omit or use "-" to read stdin.
    input: Option<PathBuf>,
    /// Output file. Omit to derive from input, or "-" for stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// (enc) Encrypt to this recipient public-identity file instead of a
    /// passphrase (a `keyring export` line).
    #[arg(short = 'r', long)]
    recipient: Option<PathBuf>,
    /// (dec) Decrypt using this stored keyring identity instead of a passphrase.
    #[arg(long)]
    identity: Option<String>,
    /// (dec) Keystore path for --identity (overrides the default and
    /// $BACKPACK_KEYRING).
    #[arg(long)]
    keyring: Option<PathBuf>,
}

/// Environment variable used to supply the passphrase non-interactively
/// (scripting / CI). When set, prompting and confirmation are skipped.
const PASS_ENV: &str = "VEIL_PASSPHRASE";
/// Keystore passphrase environment variable (shared with `keyring`).
const KEYSTORE_PASS_ENV: &str = "BACKPACK_PASSPHRASE";

fn main() {
    if let Err(e) = run() {
        eprintln!("veil: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Enc(io) => encrypt(io),
        Cmd::Dec(io) => decrypt(io),
    }
}

fn encrypt(io: Io) -> Result<()> {
    let out = default_enc_output(&io);
    if let Some(rp) = &io.recipient {
        let txt = fs::read_to_string(rp).with_context(|| format!("reading {}", rp.display()))?;
        let key = EncKey::Recipient(keyring::PublicIdentity::parse(&txt)?.x);
        return with_streams(&io.input, &out, |r, w| veil::encrypt_stream(r, w, &key));
    }
    let pass = prompt_new_passphrase()?;
    let key = EncKey::Passphrase(pass.as_bytes());
    with_streams(&io.input, &out, |r, w| veil::encrypt_stream(r, w, &key))
}

fn decrypt(io: Io) -> Result<()> {
    let out = default_dec_output(&io)?;

    if let Some(name) = &io.identity {
        let path = io
            .keyring
            .clone()
            .or_else(keyring::default_keystore_path)
            .ok_or_else(|| anyhow!("cannot locate keystore; set BACKPACK_KEYRING or --keyring"))?;
        let pass = keystore_passphrase()?;
        let store = keyring::KeyStore::open(&path, pass.as_bytes())?;
        let sk = store
            .get(name)
            .ok_or_else(|| anyhow!("no identity named {name:?} in keystore"))?
            .x_secret();
        return with_streams(&io.input, &out, |r, w| {
            veil::decrypt_stream(r, w, &DecKey::IdentitySecret(&sk))
        });
    }

    let pass = match std::env::var(PASS_ENV) {
        Ok(p) => p,
        Err(_) => rpassword::prompt_password("Passphrase: ").context("reading passphrase")?,
    };
    with_streams(&io.input, &out, |r, w| {
        veil::decrypt_stream(r, w, &DecKey::Passphrase(pass.as_bytes()))
    })
}

fn keystore_passphrase() -> Result<String> {
    match std::env::var(KEYSTORE_PASS_ENV) {
        Ok(p) => Ok(p),
        Err(_) => {
            rpassword::prompt_password("Keystore passphrase: ").context("reading passphrase")
        }
    }
}

fn prompt_new_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var(PASS_ENV) {
        if p.is_empty() {
            bail!("{PASS_ENV} must not be empty");
        }
        return Ok(p);
    }
    let p1 = rpassword::prompt_password("Passphrase: ").context("reading passphrase")?;
    if p1.is_empty() {
        bail!("passphrase must not be empty");
    }
    let p2 = rpassword::prompt_password("Confirm passphrase: ").context("reading passphrase")?;
    if p1 != p2 {
        bail!("passphrases do not match");
    }
    Ok(p1)
}

fn is_stdio(p: &Option<PathBuf>) -> bool {
    match p {
        None => true,
        Some(p) => p.as_os_str() == "-",
    }
}

/// Encrypted output path: explicit `-o`, else `<input>.veil`, else stdout.
fn default_enc_output(io: &Io) -> Option<PathBuf> {
    if let Some(o) = &io.output {
        return non_stdio(o);
    }
    match &io.input {
        Some(p) if p.as_os_str() != "-" => Some(veil::enc_output_for(p)),
        _ => None,
    }
}

/// Decrypted output path: explicit `-o`, else strip `.veil`, else require `-o`.
fn default_dec_output(io: &Io) -> Result<Option<PathBuf>> {
    if let Some(o) = &io.output {
        return Ok(non_stdio(o));
    }
    match &io.input {
        Some(p) if p.extension().map(|e| e == EXT).unwrap_or(false) => {
            Ok(Some(veil::dec_output_for(p)?))
        }
        Some(p) if p.as_os_str() != "-" => {
            bail!("cannot infer output name for {}; pass -o", p.display())
        }
        _ => Ok(None), // stdin -> stdout
    }
}

fn non_stdio(p: &Path) -> Option<PathBuf> {
    if p.as_os_str() == "-" {
        None
    } else {
        Some(p.to_path_buf())
    }
}

/// Stream plumbing for the CLI's stdin/stdout modes; file output is atomic
/// (temp sibling + rename) like the library's path helpers.
fn with_streams<F>(input: &Option<PathBuf>, output: &Option<PathBuf>, op: F) -> Result<()>
where
    F: FnOnce(&mut dyn Read, &mut dyn Write) -> Result<()>,
{
    let mut reader: BufReader<Box<dyn Read>> = BufReader::new(if is_stdio(input) {
        Box::new(io::stdin().lock())
    } else {
        let p = input.as_ref().unwrap();
        Box::new(File::open(p).with_context(|| format!("opening {}", p.display()))?)
    });

    match output {
        None => {
            let stdout = io::stdout();
            let mut w = BufWriter::new(stdout.lock());
            op(&mut reader, &mut w)?;
            w.flush()?;
            Ok(())
        }
        Some(path) => {
            let tmp = {
                let mut name = path.file_name().unwrap_or_default().to_os_string();
                name.push(".tmp");
                path.with_file_name(name)
            };
            let file =
                File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            let mut w = BufWriter::new(file);
            match op(&mut reader, &mut w).and_then(|_| Ok(w.flush()?)) {
                Ok(()) => {
                    fs::rename(&tmp, path)
                        .with_context(|| format!("finalizing {}", path.display()))?;
                    Ok(())
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    Err(e)
                }
            }
        }
    }
}
