//! `scrub` — strip identifying metadata from files.
//!
//! The library exposes format detection and per-format strippers plus a
//! [`strip`] convenience that dispatches on the detected format. The `scrub`
//! binary is a thin CLI over this API.

pub mod detect;
pub mod jpeg;
pub mod pdf;
pub mod png;
pub mod report;

use anyhow::{anyhow, Result};

pub use detect::{detect, Kind};
pub use report::Report;

/// Detect the format of `bytes` and strip its metadata.
///
/// Returns the cleaned bytes and a [`Report`] of what was removed. Errors if the
/// format is unsupported or the file cannot be parsed.
pub fn strip(bytes: &[u8]) -> Result<(Vec<u8>, Report)> {
    match detect(bytes) {
        Some(Kind::Jpeg) => jpeg::strip(bytes),
        Some(Kind::Png) => png::strip(bytes),
        Some(Kind::Pdf) => pdf::strip(bytes),
        None => Err(anyhow!(
            "unsupported or unrecognized format (need JPEG/PNG/PDF)"
        )),
    }
}
