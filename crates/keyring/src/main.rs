//! `keyring` — manage signing/encryption identities.
//!
//! ```text
//! keyring gen --name alice
//! keyring list
//! keyring export alice > alice.pub
//! keyring sign --key alice message.txt > message.sig
//! keyring verify alice.pub message.txt message.sig
//! ```
//!
//! Private keys are held in a passphrase-encrypted store
//! (`~/.config/backpack/keyring.veil` by default).

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use keyring::{
    default_keystore_path, format_signature, parse_signature, KeyStore, PublicIdentity, PATH_ENV,
};

/// Environment variable holding the keystore passphrase (skips prompting).
const PASS_ENV: &str = "BACKPACK_PASSPHRASE";

#[derive(Parser)]
#[command(
    name = "keyring",
    version,
    about = "Manage Ed25519/X25519 identities",
    after_help = "EXAMPLES:\n  \
        keyring gen --name alice\n  \
        keyring list\n  \
        keyring export alice > alice.pub\n  \
        keyring sign --key alice msg.txt > msg.sig\n  \
        keyring verify alice.pub msg.txt msg.sig\n\n\
        The private keystore is encrypted under a passphrase. Set \
        BACKPACK_PASSPHRASE to avoid prompts (scripts/CI); set \
        BACKPACK_KEYRING to override its path."
)]
struct Cli {
    /// Path to the keystore file (overrides the default and $BACKPACK_KEYRING).
    #[arg(long, global = true)]
    keyring: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new identity.
    Gen {
        #[arg(long)]
        name: String,
    },
    /// List stored identities and their fingerprints.
    List,
    /// Print an identity's public line (share this).
    Export {
        name: String,
    },
    /// Delete an identity from the store.
    Rm {
        name: String,
    },
    /// Sign a file (or stdin) with an identity's signing key.
    Sign {
        #[arg(short, long)]
        key: String,
        /// Message file. Omit or "-" to read stdin.
        input: Option<PathBuf>,
    },
    /// Verify a signature: verify <pubfile> <message> <sigfile>.
    Verify {
        pubfile: PathBuf,
        message: PathBuf,
        sigfile: PathBuf,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("keyring: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Gen { name } => cmd_gen(&cli, name),
        Cmd::List => cmd_list(&cli),
        Cmd::Export { name } => cmd_export(&cli, name),
        Cmd::Rm { name } => cmd_rm(&cli, name),
        Cmd::Sign { key, input } => cmd_sign(&cli, key, input.as_ref()),
        Cmd::Verify {
            pubfile,
            message,
            sigfile,
        } => cmd_verify(pubfile, message, sigfile),
    }
}

fn cmd_gen(cli: &Cli, name: &str) -> Result<()> {
    let path = store_path(cli)?;
    let creating = !path.exists();
    let pass = passphrase(creating)?;
    let mut store = KeyStore::open(&path, pass.as_bytes())?;
    let id = store.generate(name)?.public();
    store.save(pass.as_bytes())?;
    println!("created {} [{}]", id.name, id.fingerprint());
    println!("{}", id.to_line());
    Ok(())
}

fn cmd_list(cli: &Cli) -> Result<()> {
    let path = store_path(cli)?;
    if !path.exists() {
        println!("(no keystore at {})", path.display());
        return Ok(());
    }
    let pass = passphrase(false)?;
    let store = KeyStore::open(&path, pass.as_bytes())?;
    if store.is_empty() {
        println!("(no identities)");
        return Ok(());
    }
    for id in store.identities() {
        println!("{:<20} {}", id.name, id.fingerprint());
    }
    Ok(())
}

fn cmd_export(cli: &Cli, name: &str) -> Result<()> {
    let path = store_path(cli)?;
    let pass = passphrase(false)?;
    let store = KeyStore::open(&path, pass.as_bytes())?;
    let id = store
        .get(name)
        .ok_or_else(|| anyhow!("no identity named {name:?}"))?
        .public();
    println!("{}", id.to_line());
    Ok(())
}

fn cmd_rm(cli: &Cli, name: &str) -> Result<()> {
    let path = store_path(cli)?;
    let pass = passphrase(false)?;
    let mut store = KeyStore::open(&path, pass.as_bytes())?;
    if !store.remove(name) {
        bail!("no identity named {name:?}");
    }
    store.save(pass.as_bytes())?;
    println!("removed {name}");
    Ok(())
}

fn cmd_sign(cli: &Cli, key: &str, input: Option<&PathBuf>) -> Result<()> {
    let msg = read_input(input)?;
    let path = store_path(cli)?;
    let pass = passphrase(false)?;
    let store = KeyStore::open(&path, pass.as_bytes())?;
    let kp = store
        .get(key)
        .ok_or_else(|| anyhow!("no identity named {key:?}"))?;
    let sig = kp.sign(&msg);
    println!("{}", format_signature(&sig));
    Ok(())
}

fn cmd_verify(pubfile: &PathBuf, message: &PathBuf, sigfile: &PathBuf) -> Result<()> {
    let pub_txt =
        fs::read_to_string(pubfile).with_context(|| format!("reading {}", pubfile.display()))?;
    let id = PublicIdentity::parse(&pub_txt)?;
    let msg = fs::read(message).with_context(|| format!("reading {}", message.display()))?;
    let sig_txt =
        fs::read_to_string(sigfile).with_context(|| format!("reading {}", sigfile.display()))?;
    let sig = parse_signature(&sig_txt)?;

    if id.verify(&msg, &sig) {
        println!("OK: valid signature by {} [{}]", id.name, id.fingerprint());
        Ok(())
    } else {
        eprintln!("BAD: signature does not verify");
        std::process::exit(1);
    }
}

/// Resolve the keystore path: --keyring, then $BACKPACK_KEYRING, then the
/// per-user config directory.
fn store_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = &cli.keyring {
        return Ok(p.clone());
    }
    default_keystore_path()
        .ok_or_else(|| anyhow!("cannot determine config directory; set {PATH_ENV}"))
}

/// Obtain the keystore passphrase from $BACKPACK_PASSPHRASE or by prompting.
/// When `confirm` is set (creating a new store), the prompt is entered twice.
fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var(PASS_ENV) {
        if p.is_empty() {
            bail!("{PASS_ENV} must not be empty");
        }
        return Ok(Zeroizing::new(p));
    }
    let p1 = rpassword::prompt_password("Keystore passphrase: ").context("reading passphrase")?;
    if confirm {
        if p1.is_empty() {
            bail!("passphrase must not be empty");
        }
        let p2 =
            rpassword::prompt_password("Confirm passphrase: ").context("reading passphrase")?;
        if p1 != p2 {
            bail!("passphrases do not match");
        }
    }
    Ok(Zeroizing::new(p1))
}

fn read_input(input: Option<&PathBuf>) -> Result<Vec<u8>> {
    match input {
        Some(p) if p.as_os_str() != "-" => {
            fs::read(p).with_context(|| format!("reading {}", p.display()))
        }
        _ => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .context("reading stdin")?;
            Ok(buf)
        }
    }
}
