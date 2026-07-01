//! JPEG metadata stripping.
//!
//! Removes the privacy-bearing application segments (EXIF, XMP, IPTC/Photoshop,
//! maker notes, thumbnails) and comments, while keeping segments that affect
//! rendering: APP0 (JFIF), APP2 (ICC color profile), APP14 (Adobe transform).

use anyhow::{Context, Result};
use exif::{In, Reader, Tag};
use img_parts::jpeg::Jpeg;
use img_parts::Bytes;

use crate::report::Report;

/// Application markers kept because they affect how the image renders.
const KEEP_APP: &[u8] = &[0xE0, 0xE2, 0xEE]; // JFIF, ICC, Adobe
const COM: u8 = 0xFE; // JPEG comment

pub fn strip(input: &[u8]) -> Result<(Vec<u8>, Report)> {
    let exif_note = exif_summary(input);

    let mut jpeg = Jpeg::from_bytes(Bytes::copy_from_slice(input)).context("parsing JPEG")?;
    let mut report = Report::new("JPEG");

    let mut app1_seen = false;
    let note = exif_note.clone();
    jpeg.segments_mut().retain(|seg| {
        let m = seg.marker();
        let drop = (0xE1..=0xEF).contains(&m) && !KEEP_APP.contains(&m) || m == COM;
        if drop {
            report.removed.push(match m {
                // First APP1 is typically EXIF; a later one is usually XMP.
                0xE1 if !app1_seen => {
                    app1_seen = true;
                    note.clone().unwrap_or_else(|| "EXIF/XMP metadata (APP1)".to_string())
                }
                0xE1 => "XMP metadata (APP1)".to_string(),
                0xED => "IPTC/Photoshop metadata (APP13)".to_string(),
                COM => "JPEG comment".to_string(),
                _ => format!("application segment APP{} (0x{m:02X})", m - 0xE0),
            });
        }
        !drop
    });

    let out = jpeg.encoder().bytes();
    Ok((out.to_vec(), report))
}

/// Summarize EXIF for the removal report, flagging GPS location specifically.
fn exif_summary(input: &[u8]) -> Option<String> {
    let mut cur = std::io::Cursor::new(input);
    let exif = Reader::new().read_from_container(&mut cur).ok()?;
    let count = exif.fields().count();
    if count == 0 {
        return None;
    }
    let has_gps = exif.get_field(Tag::GPSLatitude, In::PRIMARY).is_some()
        || exif.get_field(Tag::GPSLongitude, In::PRIMARY).is_some();
    let mut s = format!("EXIF ({count} fields");
    if has_gps {
        s.push_str(", GPS location present");
    }
    s.push_str(") (APP1)");
    Some(s)
}
