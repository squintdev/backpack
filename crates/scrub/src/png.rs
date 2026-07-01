//! PNG metadata stripping.
//!
//! Removes ancillary chunks that carry text, timestamps, or EXIF, while keeping
//! every chunk that affects rendering (IHDR, PLTE, IDAT, IEND, gAMA, cHRM, sRGB,
//! iCCP, tRNS, bKGD, pHYs, …).

use anyhow::{Context, Result};
use img_parts::png::Png;
use img_parts::Bytes;

use crate::report::Report;

/// Ancillary chunk kinds that carry metadata rather than pixels.
const DROP_KINDS: &[[u8; 4]] = &[*b"tEXt", *b"zTXt", *b"iTXt", *b"tIME", *b"eXIf"];

pub fn strip(input: &[u8]) -> Result<(Vec<u8>, Report)> {
    let mut png = Png::from_bytes(Bytes::copy_from_slice(input)).context("parsing PNG")?;
    let mut report = Report::new("PNG");

    png.chunks_mut().retain(|chunk| {
        let kind = chunk.kind();
        let drop = DROP_KINDS.contains(&kind);
        if drop {
            report.removed.push(chunk_label(&kind));
        }
        !drop
    });

    let out = png.encoder().bytes();
    Ok((out.to_vec(), report))
}

fn chunk_label(kind: &[u8; 4]) -> String {
    let name = String::from_utf8_lossy(kind);
    let desc = if *kind == *b"tIME" {
        "modification time"
    } else if *kind == *b"eXIf" {
        "EXIF"
    } else {
        "text metadata"
    };
    format!("{name} chunk ({desc})")
}
