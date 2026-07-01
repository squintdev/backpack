//! `veil` — encrypt and decrypt files with a passphrase.
//!
//! ```text
//! veil enc secret.pdf            # -> secret.pdf.veil
//! veil dec secret.pdf.veil       # -> secret.pdf
//! cat data | veil enc > data.veil
//! ```

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

/// Extension appended to encrypted files.
const EXT: &str = "veil";

#[derive(Parser)]
#[command(
    name = "veil",
    version,
    about = "Passphrase file encryptor",
    long_about = "Encrypt and decrypt files with a passphrase.\n\n\
        Uses Argon2id key derivation and chunked ChaCha20-Poly1305 authenticated \
        encryption. Tampering, truncation, or a wrong passphrase are detected and \
        rejected. File output is written atomically, so a failed run never leaves \
        a partial destination file.",
    after_help = "EXAMPLES:\n  \
        veil enc secret.pdf              Encrypt to secret.pdf.veil\n  \
        veil dec secret.pdf.veil         Decrypt back to secret.pdf\n  \
        veil enc notes.txt -o n.bin      Encrypt to a chosen name\n  \
        tar c dir | veil enc > d.veil    Encrypt a stream\n  \
        veil dec d.veil | tar x          Decrypt a stream\n\n\
        ENVIRONMENT:\n  \
        VEIL_PASSPHRASE   If set, used instead of prompting (for scripts/CI).\n\n\
        SECURITY: v0.1, unaudited. Passphrase strength determines security."
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
}

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
    let pass = prompt_new_passphrase()?;
    let out = default_enc_output(&io);
    with_streams(&io.input, &out, |r, w| {
        cph_core::seal(r, w, pass.as_bytes()).map_err(Into::into)
    })
}

/// Environment variable used to supply the passphrase non-interactively
/// (scripting / CI). When set, prompting and confirmation are skipped.
const PASS_ENV: &str = "VEIL_PASSPHRASE";

fn decrypt(io: Io) -> Result<()> {
    let pass = match std::env::var(PASS_ENV) {
        Ok(p) => p,
        Err(_) => rpassword::prompt_password("Passphrase: ").context("reading passphrase")?,
    };
    let out = default_dec_output(&io)?;
    with_streams(&io.input, &out, |r, w| {
        cph_core::open(r, w, pass.as_bytes()).map_err(Into::into)
    })
}

/// Obtain a passphrase for encryption: from `VEIL_PASSPHRASE` if set,
/// otherwise prompt twice and confirm the two entries match.
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
        Some(p) if p.as_os_str() != "-" => {
            Some(PathBuf::from(format!("{}.{EXT}", p.display())))
        }
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
            Ok(Some(p.with_extension("")))
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

/// Open input/output streams and run `op`. File output is written to a
/// temporary sibling and atomically renamed on success, so a failure or wrong
/// passphrase never leaves a truncated destination file.
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
            let tmp = tmp_path(path);
            let file = File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
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

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}
