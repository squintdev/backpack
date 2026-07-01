//! `split` — split a secret into shares, and recombine them.
//!
//! ```text
//! printf 'my master password' | split deal -k 3 -n 5
//! split combine share-01.txt share-03.txt share-05.txt
//! ```
//!
//! Any `k` of the `n` shares reconstruct the secret; any `k - 1` reveal nothing.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use split::{combine, deal, TAG_PREFIX};

#[derive(Parser)]
#[command(
    name = "split",
    version,
    about = "Shamir secret sharing: split a secret into k-of-n shares",
    after_help = "EXAMPLES:\n  \
        printf 'master password' | split deal -k 3 -n 5\n  \
        split deal -k 2 -n 3 --input seed.txt --out-dir shares/\n  \
        split combine share-01.txt share-02.txt\n  \
        cat shares/*.txt | split combine\n\n\
        SECURITY: v0.1. Any k shares reveal the secret in full; store them \
        separately. A threshold of k=1 offers no protection and is rejected."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Split a secret (from --input or stdin) into shares.
    Deal(Deal),
    /// Recombine shares (from file arguments or stdin) into the secret.
    Combine(Combine),
}

#[derive(clap::Args)]
struct Deal {
    /// Threshold: shares required to reconstruct.
    #[arg(short, long)]
    k: u8,
    /// Total number of shares to produce.
    #[arg(short, long)]
    n: u8,
    /// Read the secret from this file instead of stdin.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Write shares as files in this directory (share-NN.txt) instead of stdout.
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct Combine {
    /// Share files to read. If none are given, shares are read from stdin.
    files: Vec<PathBuf>,
    /// Write the recovered secret here instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("split: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Deal(a) => run_deal(a),
        Cmd::Combine(a) => run_combine(a),
    }
}

fn run_deal(a: Deal) -> Result<()> {
    let secret = match &a.input {
        Some(p) => fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => read_stdin_bytes()?,
    };
    if secret.is_empty() {
        anyhow::bail!("secret is empty");
    }

    let shares = deal(&secret, a.k, a.n)?;

    match &a.out_dir {
        None => {
            let mut out = io::stdout().lock();
            for s in &shares {
                writeln!(out, "{s}")?;
            }
        }
        Some(dir) => {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            let width = shares.len().to_string().len();
            for (i, s) in shares.iter().enumerate() {
                let path = dir.join(format!("share-{:0width$}.txt", i + 1, width = width));
                fs::write(&path, format!("{s}\n"))
                    .with_context(|| format!("writing {}", path.display()))?;
                println!("wrote {}", path.display());
            }
            eprintln!(
                "Distribute these {} shares separately; any {} reconstruct the secret.",
                a.n, a.k
            );
        }
    }
    Ok(())
}

fn run_combine(a: Combine) -> Result<()> {
    let raw = if a.files.is_empty() {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .context("reading shares from stdin")?;
        s
    } else {
        let mut s = String::new();
        for p in &a.files {
            s.push_str(&fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?);
            s.push('\n');
        }
        s
    };

    // Keep only lines that look like shares; ignore blanks and comments.
    let shares: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with(TAG_PREFIX))
        .map(str::to_string)
        .collect();
    if shares.is_empty() {
        anyhow::bail!("no share lines found (expected lines starting with {TAG_PREFIX})");
    }

    let secret = combine(&shares)?;

    match &a.output {
        Some(p) => fs::write(p, &secret).with_context(|| format!("writing {}", p.display()))?,
        None => io::stdout().lock().write_all(&secret)?,
    }
    Ok(())
}

fn read_stdin_bytes() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::stdin()
        .read_to_end(&mut buf)
        .context("reading secret from stdin")?;
    Ok(buf)
}
