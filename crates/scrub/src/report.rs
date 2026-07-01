/// What a strip pass found and removed from one file.
pub struct Report {
    /// Human-readable format name, e.g. "JPEG".
    pub format: &'static str,
    /// One label per removed metadata item.
    pub removed: Vec<String>,
}

impl Report {
    pub fn new(format: &'static str) -> Self {
        Report {
            format,
            removed: Vec::new(),
        }
    }

    /// True if anything was (or would be) removed.
    pub fn changed(&self) -> bool {
        !self.removed.is_empty()
    }
}
