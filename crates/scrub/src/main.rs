//! `scrub` — strip identifying metadata from files before you share them.
//!
//! ```text
//! scrub photo.jpg              # -> photo.clean.jpg (original kept)
//! scrub -n report.pdf          # dry run: list what would be removed
//! scrub -i *.png               # overwrite in place
//! ```
//!
//! Supported: JPEG, PNG, PDF. Other formats are reported and skipped.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use scrub::{strip, Report};

#[derive(Parser)]
#[command(
    name = "scrub",
    version,
    about = "Strip identifying metadata from files",
    long_about = "Remove EXIF, XMP, IPTC, and document metadata from files before sharing.\n\n\
        Supported formats: JPEG, PNG, PDF. Metadata that affects rendering \
        (color profiles, gamma) is preserved. By default a cleaned copy is \
        written alongside the original as <name>.clean.<ext>; the original is \
        left untouched.",
    after_help = "EXAMPLES:\n  \
        scrub photo.jpg                Write photo.clean.jpg, keep original\n  \
        scrub -n leak.pdf              Dry run: show what would be removed\n  \
        scrub -i a.jpg b.png           Overwrite files in place\n  \
        scrub doc.pdf -o clean.pdf     Choose the output name\n\n\
        SECURITY: v0.1. Removes container metadata, not content watermarks or \
        data embedded in the pixels/text themselves."
)]
struct Cli {
    /// Files to scrub.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Show what would be removed without writing anything.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Overwrite each original file in place.
    #[arg(short = 'i', long, conflicts_with = "output")]
    in_place: bool,

    /// Output path (only valid with a single input file).
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = validate(&cli) {
        eprintln!("scrub: {e:#}");
        std::process::exit(2);
    }

    let mut had_error = false;
    for file in &cli.files {
        if let Err(e) = process(file, &cli) {
            eprintln!("scrub: {}: {e:#}", file.display());
            had_error = true;
        }
    }
    if had_error {
        std::process::exit(1);
    }
}

fn validate(cli: &Cli) -> Result<()> {
    if cli.output.is_some() && cli.files.len() != 1 {
        bail!("--output requires exactly one input file");
    }
    Ok(())
}

fn process(path: &Path, cli: &Cli) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (out, report) = strip(&bytes)?;

    print_report(path, &report, cli.dry_run);

    if cli.dry_run || !report.changed() {
        return Ok(());
    }

    let dest = resolve_dest(path, cli);
    write_atomic(&dest, &out)?;
    println!("  -> wrote {}", dest.display());
    Ok(())
}

fn print_report(path: &Path, report: &Report, dry_run: bool) {
    if !report.changed() {
        println!("{} [{}]: already clean", path.display(), report.format);
        return;
    }
    let verb = if dry_run { "would remove" } else { "removing" };
    println!(
        "{} [{}]: {} {} item(s):",
        path.display(),
        report.format,
        verb,
        report.removed.len()
    );
    for item in &report.removed {
        println!("  - {item}");
    }
}

/// Decide where cleaned bytes go: in place, an explicit path, or a
/// `<stem>.clean.<ext>` sibling.
fn resolve_dest(path: &Path, cli: &Cli) -> PathBuf {
    if cli.in_place {
        return path.to_path_buf();
    }
    if let Some(o) = &cli.output {
        return o.clone();
    }
    derived_name(path)
}

fn derived_name(path: &Path) -> PathBuf {
    let mut name = OsString::new();
    match path.file_stem() {
        Some(stem) => name.push(stem),
        None => name.push("out"),
    }
    name.push(".clean");
    if let Some(ext) = path.extension() {
        name.push(".");
        name.push(ext);
    }
    path.with_file_name(name)
}

/// Write bytes to a temp sibling then rename over the destination, so an
/// interrupted write never leaves a corrupt file (important when `-i`
/// overwrites the only copy).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".scrub.tmp");
    let tmp = path.with_file_name(tmp_name);

    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("finalizing {}", path.display()))?;
    Ok(())
}
