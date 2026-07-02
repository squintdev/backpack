//! Terminal clipboard via OSC 52.
//!
//! Emitting `ESC ] 52 ; c ; <base64> BEL` asks the terminal emulator to place
//! the text on the system clipboard. Works in modern emulators (foot, kitty,
//! alacritty, wezterm, xterm with `allowWindowOps`) and over SSH; the bare
//! Linux VT has no clipboard, where this is a harmless no-op.

use std::io::Write;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Ask the terminal to copy `text` to the system clipboard. Best-effort:
/// errors are ignored (a VT without clipboard support just drops the escape).
pub fn copy(text: &str) {
    let payload = STANDARD.encode(text.as_bytes());
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{payload}\x07");
    let _ = out.flush();
}
