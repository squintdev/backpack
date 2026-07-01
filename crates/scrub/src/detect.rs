/// Supported file formats, identified by magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Jpeg,
    Png,
    Pdf,
}

/// Identify a file by its leading bytes, ignoring the extension.
pub fn detect(bytes: &[u8]) -> Option<Kind> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(Kind::Jpeg)
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some(Kind::Png)
    } else if bytes.starts_with(b"%PDF") {
        Some(Kind::Pdf)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_by_magic() {
        assert_eq!(detect(&[0xFF, 0xD8, 0xFF, 0xE0]), Some(Kind::Jpeg));
        assert_eq!(
            detect(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0]),
            Some(Kind::Png)
        );
        assert_eq!(detect(b"%PDF-1.7\n"), Some(Kind::Pdf));
    }

    #[test]
    fn rejects_unknown_and_empty() {
        assert_eq!(detect(b"not an image"), None);
        assert_eq!(detect(b""), None);
        // Extension is irrelevant; content-only detection.
        assert_eq!(detect(b"GIF89a"), None);
    }
}
