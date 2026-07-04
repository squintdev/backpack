//! `canary` — issue, renew, and check warrant canaries.
//!
//! ```text
//! canary new --key ops --days 30 --statement "No warrants received." -o canary.txt
//! canary renew canary.txt --key ops --days 30 -o canary.txt
//! canary check canary.txt [--previous old.txt] [--pub trusted.pub]
//! ```

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use canary::{format_duration, format_ts, now_unix, Canary, Status};
use clap::{Parser, Subcommand};
use keyring::{default_keystore_path, KeyStore, PublicIdentity, PATH_ENV};
use zeroize::Zeroizing;

const PASS_ENV: &str = "BACKPACK_PASSPHRASE";

#[derive(Parser)]
#[command(
    name = "canary",
    version,
    about = "Warrant canaries: signed, expiring dead-man statements",
    after_help = "EXAMPLES:\n  \
        canary new --key ops --days 30 --statement \"No warrants received.\" -o canary.txt\n  \
        canary renew canary.txt --key ops --days 30 -o canary.txt\n  \
        canary check canary.txt --previous last-month.txt --pub ops.pub\n\n\
        A canary is a dead-man switch: readers treat an expired or missing\n\
        canary as the signal. Renew before the window closes. Set\n\
        BACKPACK_PASSPHRASE to skip keystore prompts."
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
    /// Sign a new canary statement.
    New {
        /// Identity to sign with.
        #[arg(short, long)]
        key: String,
        /// Validity window in days.
        #[arg(long, default_value_t = 30)]
        days: u64,
        /// Sequence number (bump manually if not renewing from a file).
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// Statement text. Omit to read it from --file or stdin.
        #[arg(long)]
        statement: Option<String>,
        /// Read the statement from a file.
        #[arg(long, conflicts_with = "statement")]
        file: Option<PathBuf>,
        /// Write the signed canary here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Re-sign an existing canary: same statement, fresh window, sequence+1.
    Renew {
        /// The current canary document.
        input: PathBuf,
        /// Identity to sign with (must match the canary's key).
        #[arg(short, long)]
        key: String,
        /// Validity window in days.
        #[arg(long, default_value_t = 30)]
        days: u64,
        /// Write the renewed canary here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a canary: signature, expiry, and optional succession.
    Check {
        /// The canary document (or "-" for stdin).
        input: PathBuf,
        /// The previously seen canary, to detect rollback.
        #[arg(long)]
        previous: Option<PathBuf>,
        /// Trusted BPKEY1 public identity the canary must be signed by.
        #[arg(long = "pub")]
        pubfile: Option<PathBuf>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("canary: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::New {
            key,
            days,
            seq,
            statement,
            file,
            output,
        } => cmd_new(
            &cli,
            key,
            *days,
            *seq,
            statement.as_deref(),
            file.as_ref(),
            output.as_ref(),
        ),
        Cmd::Renew {
            input,
            key,
            days,
            output,
        } => cmd_renew(&cli, input, key, *days, output.as_ref()),
        Cmd::Check {
            input,
            previous,
            pubfile,
        } => cmd_check(input, previous.as_ref(), pubfile.as_ref()),
    }
}

fn cmd_new(
    cli: &Cli,
    key: &str,
    days: u64,
    seq: u64,
    statement: Option<&str>,
    file: Option<&PathBuf>,
    output: Option<&PathBuf>,
) -> Result<()> {
    let text = match (statement, file) {
        (Some(s), _) => s.to_string(),
        (None, Some(p)) => {
            fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
        }
        (None, None) => {
            eprintln!("Enter statement, end with Ctrl-D:");
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };
    let kp_store = open_store(cli)?;
    let kp = kp_store
        .get(key)
        .ok_or_else(|| anyhow!("no identity named {key:?}"))?;
    let c = Canary::issue(kp, &text, now_unix(), days * 86_400, seq)?;
    emit(&c, output)?;
    eprintln!(
        "signed by {} — sequence {}, expires {}",
        key,
        c.sequence,
        format_ts(c.expires)
    );
    Ok(())
}

fn cmd_renew(
    cli: &Cli,
    input: &PathBuf,
    key: &str,
    days: u64,
    output: Option<&PathBuf>,
) -> Result<()> {
    let old = Canary::parse(
        &fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?,
    )?;
    old.verify().context("existing canary")?;
    let store = open_store(cli)?;
    let kp = store
        .get(key)
        .ok_or_else(|| anyhow!("no identity named {key:?}"))?;
    let c = old.renew(kp, now_unix(), days * 86_400)?;
    emit(&c, output)?;
    eprintln!(
        "renewed — sequence {} -> {}, expires {}",
        old.sequence,
        c.sequence,
        format_ts(c.expires)
    );
    Ok(())
}

fn cmd_check(input: &PathBuf, previous: Option<&PathBuf>, pubfile: Option<&PathBuf>) -> Result<()> {
    let text = if input.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        buf
    } else {
        fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?
    };
    let c = Canary::parse(&text)?;

    // Pin to a trusted key if supplied — otherwise trust-on-first-use.
    if let Some(p) = pubfile {
        let trusted = PublicIdentity::parse(
            &fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )?;
        if trusted.ed != c.identity.ed {
            eprintln!("BAD: canary signed by a different key than {}", p.display());
            std::process::exit(1);
        }
    }

    if c.verify().is_err() {
        eprintln!("BAD: signature does not verify");
        std::process::exit(1);
    }

    if let Some(p) = previous {
        let prev = Canary::parse(
            &fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )?;
        prev.verify().context("previous canary")?;
        if let Err(e) = c.check_succession(&prev) {
            eprintln!("BAD: {e}");
            std::process::exit(1);
        }
    }

    println!(
        "signer:   {} [{}]",
        c.identity.name,
        c.identity.fingerprint()
    );
    println!("sequence: {}", c.sequence);
    println!("issued:   {}", format_ts(c.issued));
    println!("expires:  {}", format_ts(c.expires));
    match c.status(now_unix()) {
        Status::Valid { remaining } => {
            println!("status:   ALIVE ({} remaining)", format_duration(remaining));
            Ok(())
        }
        Status::Expired { overdue } => {
            println!(
                "status:   EXPIRED ({} overdue) — treat as tripped",
                format_duration(overdue)
            );
            std::process::exit(2);
        }
    }
}

fn emit(c: &Canary, output: Option<&PathBuf>) -> Result<()> {
    let doc = c.render();
    match output {
        Some(p) => fs::write(p, &doc).with_context(|| format!("writing {}", p.display())),
        None => io::stdout().write_all(doc.as_bytes()).context("stdout"),
    }
}

fn open_store(cli: &Cli) -> Result<KeyStore> {
    let path = match &cli.keyring {
        Some(p) => p.clone(),
        None => default_keystore_path()
            .ok_or_else(|| anyhow!("cannot determine config directory; set {PATH_ENV}"))?,
    };
    if !path.exists() {
        bail!(
            "no keystore at {} — create an identity with `keyring gen` first",
            path.display()
        );
    }
    let pass = passphrase()?;
    Ok(KeyStore::open(&path, pass.as_bytes())?)
}

fn passphrase() -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var(PASS_ENV) {
        if p.is_empty() {
            bail!("{PASS_ENV} must not be empty");
        }
        return Ok(Zeroizing::new(p));
    }
    let p = rpassword::prompt_password("Keystore passphrase: ").context("reading passphrase")?;
    Ok(Zeroizing::new(p))
}
