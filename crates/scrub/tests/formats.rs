//! Integration tests over real JPEG/PNG fixtures (in `tests/assets/`), each
//! carrying a known comment string we can assert has been removed.

use scrub::strip;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn jpeg_comment_removed() {
    let input = include_bytes!("assets/photo.jpg");
    assert!(contains(input, b"SECRET-safehouse-42.3601N"));

    let (out, report) = strip(input).unwrap();
    assert!(report.changed());
    assert!(
        !contains(&out, b"SECRET-safehouse-42.3601N"),
        "comment survived"
    );

    // A second pass finds nothing, and the JPEG is still structurally valid.
    let (_, report2) = strip(&out).unwrap();
    assert!(!report2.changed());
    assert!(out.starts_with(&[0xFF, 0xD8, 0xFF]));
}

#[test]
fn png_text_removed() {
    let input = include_bytes!("assets/img.png");
    assert!(contains(input, b"internal-eyes-only"));

    let (out, report) = strip(input).unwrap();
    assert!(report.changed());
    assert!(
        !contains(&out, b"internal-eyes-only"),
        "text chunk survived"
    );

    let (_, report2) = strip(&out).unwrap();
    assert!(!report2.changed());
    assert!(out.starts_with(&[0x89, b'P', b'N', b'G']));
}

#[test]
fn unsupported_format_errors() {
    assert!(strip(b"just some bytes").is_err());
}
