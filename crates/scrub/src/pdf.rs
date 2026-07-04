//! PDF metadata stripping.
//!
//! Removes the document Info dictionary (author, title, producer, creation and
//! modification dates) and the XMP metadata stream referenced by the catalog.

use anyhow::{Context, Result};
use lopdf::Document;

use crate::report::Report;

pub fn strip(input: &[u8]) -> Result<(Vec<u8>, Report)> {
    let mut doc = Document::load_mem(input).context("parsing PDF")?;
    let mut report = Report::new("PDF");

    // Info dictionary. Removing only the trailer reference leaves the orphaned
    // object in the file, so delete the object itself as well.
    let info_ref = doc
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|o| o.as_reference().ok());
    let info_removed = doc.trailer.remove(b"Info").is_some();
    if let Some(id) = info_ref {
        doc.objects.remove(&id);
    }
    if info_removed {
        report
            .removed
            .push("document info dictionary (author, title, producer, dates)".to_string());
    }

    // The XMP metadata stream hangs off the document catalog (root). Find its
    // reference before mutating the catalog, then delete both the catalog entry
    // and the stream object.
    if let Ok(root_id) = doc.trailer.get(b"Root").and_then(|o| o.as_reference()) {
        let meta_ref = doc
            .get_object(root_id)
            .ok()
            .and_then(|o| o.as_dict().ok())
            .and_then(|d| d.get(b"Metadata").ok())
            .and_then(|o| o.as_reference().ok());

        let mut removed = false;
        if let Ok(obj) = doc.get_object_mut(root_id) {
            if let Ok(dict) = obj.as_dict_mut() {
                removed = dict.remove(b"Metadata").is_some();
            }
        }
        if let Some(id) = meta_ref {
            doc.objects.remove(&id);
        }
        if removed {
            report.removed.push("XMP metadata stream".to_string());
        }
    }

    let mut out = Vec::new();
    doc.save_to(&mut out).context("writing PDF")?;
    Ok((out, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Object, Stream};

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Build a minimal PDF carrying an Info dictionary and an XMP metadata
    /// stream, and return its serialized bytes.
    fn pdf_with_metadata() -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.add_object(dictionary! {
            "Type" => "Pages",
            "Kids" => Vec::<Object>::new(),
            "Count" => 0,
        });
        let info_id = doc.add_object(dictionary! {
            "Author" => Object::string_literal("Agent Smith"),
            "Producer" => Object::string_literal("SecretTool"),
        });
        let meta_id = doc.add_object(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<x:xmpmeta>hidden-location</x:xmpmeta>".to_vec(),
        ));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "Metadata" => meta_id,
        });
        doc.trailer.set("Root", catalog_id);
        doc.trailer.set("Info", info_id);

        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn removes_info_and_xmp() {
        let input = pdf_with_metadata();
        assert!(contains(&input, b"Agent Smith"));
        assert!(contains(&input, b"hidden-location"));

        let (out, report) = strip(&input).unwrap();
        assert_eq!(report.removed.len(), 2);

        // The orphaned objects must be gone from the bytes, not merely
        // dereferenced (regression: trailer.remove alone left them in-file).
        assert!(!contains(&out, b"Agent Smith"), "Info survived");
        assert!(!contains(&out, b"hidden-location"), "XMP survived");

        // File still loads and the catalog no longer references metadata.
        let reloaded = Document::load_mem(&out).unwrap();
        assert!(reloaded.trailer.get(b"Info").is_err());
        let root = reloaded
            .trailer
            .get(b"Root")
            .unwrap()
            .as_reference()
            .unwrap();
        let catalog = reloaded.get_object(root).unwrap().as_dict().unwrap();
        assert!(catalog.get(b"Metadata").is_err());
    }

    #[test]
    fn clean_pdf_reports_nothing() {
        // Strip once, then a second pass should find nothing to remove.
        let (out, _) = strip(&pdf_with_metadata()).unwrap();
        let (_, report) = strip(&out).unwrap();
        assert!(!report.changed());
    }
}
