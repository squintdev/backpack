//! `stamp` — timestamp proofs via OpenTimestamps.
//!
//! ```text
//! stamp file.pdf                  # -> file.pdf.ots (pending)
//! stamp upgrade file.pdf.ots      # hours later: fetch Bitcoin attestation
//! stamp verify file.pdf           # check file.pdf.ots against Bitcoin
//! stamp info file.pdf.ots         # show the proof structure
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use stamp::calendar::{DEFAULT_CALENDARS, DEFAULT_ESPLORA};
use stamp::{digest_reader, Attestation, Check, Proof};

#[derive(Parser)]
#[command(
    name = "stamp",
    version,
    about = "Timestamp proofs: prove a file existed at a point in time",
    after_help = "EXAMPLES:\n  \
        stamp report.pdf                 # writes report.pdf.ots (pending)\n  \
        stamp upgrade report.pdf.ots     # after ~a few hours: Bitcoin-anchored\n  \
        stamp verify report.pdf          # checks the proof against Bitcoin\n\n\
        Proofs are OpenTimestamps-compatible (.ots) — anyone can verify them\n\
        with any OTS client. Calendars only ever see a blinded hash, never\n\
        the file or even its digest."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Stamp a file: submit its (blinded) hash to calendar servers.
    Stamp {
        file: PathBuf,
        /// Calendar server URL (repeatable; defaults to the public pool).
        #[arg(short, long)]
        calendar: Vec<String>,
        /// Output proof path (default: <file>.ots).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Fetch Bitcoin attestations for a pending proof.
    Upgrade {
        /// The .ots proof file (upgraded in place).
        proof: PathBuf,
    },
    /// Verify a file against its proof.
    Verify {
        file: PathBuf,
        /// Proof path (default: <file>.ots).
        #[arg(short, long)]
        proof: Option<PathBuf>,
        /// Esplora API for block lookups.
        #[arg(long, default_value = DEFAULT_ESPLORA)]
        esplora: String,
        /// Skip network checks; report attestations only.
        #[arg(long)]
        offline: bool,
    },
    /// Show a proof's structure and attestations.
    Info { proof: PathBuf },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("stamp: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Stamp {
            file,
            calendar,
            output,
        } => cmd_stamp(&file, &calendar, output),
        Cmd::Upgrade { proof } => cmd_upgrade(&proof),
        Cmd::Verify {
            file,
            proof,
            esplora,
            offline,
        } => cmd_verify(&file, proof, &esplora, offline),
        Cmd::Info { proof } => cmd_info(&proof),
    }
}

fn file_digest(path: &Path) -> Result<[u8; 32]> {
    let mut f = fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(digest_reader(&mut f)?)
}

fn cmd_stamp(file: &Path, calendars: &[String], output: Option<PathBuf>) -> Result<()> {
    let digest = file_digest(file)?;
    println!("sha256:  {}", hex::encode(digest));

    let cals: Vec<&str> = if calendars.is_empty() {
        DEFAULT_CALENDARS.to_vec()
    } else {
        calendars.iter().map(String::as_str).collect()
    };
    let (proof, outcomes) = stamp::stamp(digest, &cals);
    for (cal, r) in &outcomes {
        match r {
            Ok(()) => println!("submit:  ok   {cal}"),
            Err(e) => println!("submit:  FAIL {e}"),
        }
    }
    let proof = proof?;

    let out = output.unwrap_or_else(|| {
        let mut p = file.as_os_str().to_owned();
        p.push(".ots");
        PathBuf::from(p)
    });
    fs::write(&out, proof.serialize()?).with_context(|| format!("writing {}", out.display()))?;
    println!("wrote:   {}", out.display());
    println!(
        "pending — run `stamp upgrade {}` in a few hours",
        out.display()
    );
    Ok(())
}

fn cmd_upgrade(path: &Path) -> Result<()> {
    let mut proof = Proof::deserialize(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    let (upgraded, remaining) = stamp::upgrade(&mut proof)?;
    if upgraded > 0 {
        fs::write(path, proof.serialize()?)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    println!("upgraded: {upgraded} attestation(s), {remaining} still pending");
    if remaining > 0 {
        println!("try again later — calendars aggregate into Bitcoin every few hours");
    }
    Ok(())
}

fn cmd_verify(file: &Path, proof: Option<PathBuf>, esplora: &str, offline: bool) -> Result<()> {
    let proof_path = proof.unwrap_or_else(|| {
        let mut p = file.as_os_str().to_owned();
        p.push(".ots");
        PathBuf::from(p)
    });
    let proof = Proof::deserialize(
        &fs::read(&proof_path).with_context(|| format!("reading {}", proof_path.display()))?,
    )?;
    let digest = file_digest(file)?;
    let esplora = if offline { None } else { Some(esplora) };
    let checks = stamp::verify(&proof, digest, esplora)?;

    let mut verified = 0;
    let mut mismatched = 0;
    for c in &checks {
        match c {
            Check::BitcoinVerified { height, block_time } => {
                verified += 1;
                println!(
                    "OK: existed by {} (Bitcoin block {height})",
                    canary_ts(*block_time)
                );
            }
            Check::BitcoinMismatch { height } => {
                mismatched += 1;
                println!("BAD: commitment does not match block {height} merkle root");
            }
            Check::BitcoinUnchecked { height } => {
                println!("bitcoin attestation for block {height} (not checked: offline)");
            }
            Check::Pending { uri } => {
                println!("pending at {uri} — run `stamp upgrade`");
            }
            Check::Unknown => println!("unknown attestation type (skipped)"),
        }
    }
    if mismatched > 0 {
        bail!("{mismatched} attestation(s) FAILED verification");
    }
    if verified == 0 {
        println!("no Bitcoin-verified attestation yet");
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_info(path: &Path) -> Result<()> {
    let proof = Proof::deserialize(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    println!("file sha256: {}", hex::encode(proof.digest));
    let mut n = 0;
    for (msg, att) in proof.timestamp.walk(&proof.digest)? {
        n += 1;
        match att {
            Attestation::Bitcoin { height } => {
                println!("attestation {n}: Bitcoin block {height}");
                println!("  merkle root {}", hex::encode(&msg));
            }
            Attestation::Pending { uri } => println!("attestation {n}: pending at {uri}"),
            Attestation::Unknown { tag, .. } => {
                println!("attestation {n}: unknown type {}", hex::encode(tag))
            }
        }
    }
    Ok(())
}

/// RFC 3339 for block times (same converter canary uses, inlined to avoid a
/// dependency between the tools).
fn canary_ts(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let rem = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe as i64 + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}
