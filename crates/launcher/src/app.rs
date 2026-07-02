//! Launcher state and key handling, free of terminal I/O so transitions are
//! unit-testable. The event loop interprets the [`Action`] we return.

use ratatui::crossterm::event::KeyCode;

/// A launchable tool in the suite.
pub struct Tool {
    /// Binary name, resolved next to the launcher binary (or on PATH).
    pub bin: &'static str,
    /// Display name in the menu.
    pub name: &'static str,
    /// One-line tagline shown in the menu row.
    pub tagline: &'static str,
    /// Longer description for the detail pane.
    pub about: &'static [&'static str],
    /// Example invocations shown in the detail pane.
    pub examples: &'static [&'static str],
    /// Full-screen TUI tool: hand over the terminal with no args prompt.
    pub interactive: bool,
}

/// The tool registry: what the deck can boot into.
pub const TOOLS: &[Tool] = &[
    Tool {
        bin: "keyring-tui",
        name: "KEYRING",
        tagline: "identity mgr [TUI]",
        about: &[
            "Manage Ed25519/X25519 identities in a passphrase-encrypted store.",
            "Browse, generate, export, and delete. Signing lives in the CLI.",
        ],
        examples: &["(interactive — opens full-screen)"],
        interactive: true,
    },
    Tool {
        bin: "veil",
        name: "VEIL",
        tagline: "file encryption",
        about: &[
            "Encrypt/decrypt files with a passphrase or a recipient's public key.",
            "Argon2id + ChaCha20-Poly1305; X25519 for recipient mode.",
        ],
        examples: &[
            "enc secret.pdf",
            "dec secret.pdf.veil",
            "enc -r alice.pub secret.pdf",
            "dec --identity alice secret.pdf.veil",
        ],
        interactive: false,
    },
    Tool {
        bin: "scrub",
        name: "SCRUB",
        tagline: "metadata stripper",
        about: &[
            "Strip EXIF/GPS, XMP, IPTC, and PDF metadata before sharing.",
            "JPEG, PNG, PDF — detected by content, not extension.",
        ],
        examples: &["-n photo.jpg", "photo.jpg", "-i a.jpg b.png"],
        interactive: false,
    },
    Tool {
        bin: "split",
        name: "SPLIT",
        tagline: "shamir sharing",
        about: &[
            "Split a secret into n shares where any k reconstruct it.",
            "Wrong or insufficient shares are detected, not silently wrong.",
        ],
        examples: &[
            "deal -k 3 -n 5 --input seed.txt --out-dir shares/",
            "combine shares/share-1.txt shares/share-3.txt shares/share-5.txt",
        ],
        interactive: false,
    },
    Tool {
        bin: "keyring",
        name: "SIGN/VERIFY",
        tagline: "signatures",
        about: &[
            "Sign files and verify signatures with keyring identities.",
            "verify is stateless: needs only the public line + message + sig.",
        ],
        examples: &[
            "sign --key alice msg.txt",
            "verify alice.pub msg.txt msg.sig",
            "list",
        ],
        interactive: false,
    },
];

/// What the event loop should do after a key press.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Keep drawing.
    None,
    /// Leave the launcher.
    Quit,
    /// Hand the terminal to a full-screen tool (no args).
    RunInteractive { bin: &'static str },
    /// Run a CLI tool with the user's args, show output, wait for a key.
    RunCommand { bin: &'static str, args: String },
    /// Drop to a shell.
    Shell,
}

/// Which interaction mode the launcher is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Menu,
    /// Typing arguments for the selected (non-interactive) tool.
    Args,
}

pub struct App {
    pub selected: usize,
    pub mode: Mode,
    pub args: String,
    /// Last command + trimmed output, shown in the detail pane after a run.
    pub last_run: Option<(String, String)>,
}

impl Default for App {
    fn default() -> Self {
        App {
            selected: 0,
            mode: Mode::Menu,
            args: String::new(),
            last_run: None,
        }
    }
}

impl App {
    pub fn tool(&self) -> &'static Tool {
        &TOOLS[self.selected]
    }

    pub fn on_key(&mut self, code: KeyCode) -> Action {
        match self.mode {
            Mode::Menu => self.on_key_menu(code),
            Mode::Args => self.on_key_args(code),
        }
    }

    fn on_key_menu(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.selected = (self.selected + 1) % TOOLS.len();
                Action::None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected = self.selected.checked_sub(1).unwrap_or(TOOLS.len() - 1);
                Action::None
            }
            KeyCode::Char('!') => Action::Shell,
            KeyCode::Enter => {
                let tool = self.tool();
                if tool.interactive {
                    Action::RunInteractive { bin: tool.bin }
                } else {
                    self.args.clear();
                    self.mode = Mode::Args;
                    Action::None
                }
            }
            KeyCode::Char(c) => {
                // Number keys jump straight to a tool.
                if let Some(d) = c.to_digit(10) {
                    let idx = d as usize;
                    if idx >= 1 && idx <= TOOLS.len() {
                        self.selected = idx - 1;
                    }
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    fn on_key_args(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Menu;
                self.args.clear();
                Action::None
            }
            KeyCode::Enter => {
                self.mode = Mode::Menu;
                let args = self.args.clone();
                self.args.clear();
                Action::RunCommand {
                    bin: self.tool().bin,
                    args,
                }
            }
            KeyCode::Backspace => {
                self.args.pop();
                Action::None
            }
            KeyCode::Char(c) => {
                self.args.push(c);
                Action::None
            }
            _ => Action::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            app.on_key(KeyCode::Char(c));
        }
    }

    fn app_at(selected: usize) -> App {
        App {
            selected,
            ..App::default()
        }
    }

    #[test]
    fn navigation_wraps_both_ways() {
        let mut app = App::default();
        app.on_key(KeyCode::Up);
        assert_eq!(app.selected, TOOLS.len() - 1);
        app.on_key(KeyCode::Down);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn number_keys_jump() {
        let mut app = App::default();
        app.on_key(KeyCode::Char('3'));
        assert_eq!(app.selected, 2);
        // Out-of-range digit is ignored.
        app.on_key(KeyCode::Char('9'));
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn enter_on_interactive_tool_hands_over() {
        let mut app = app_at(0); // keyring-tui
        assert!(TOOLS[0].interactive);
        assert_eq!(
            app.on_key(KeyCode::Enter),
            Action::RunInteractive { bin: "keyring-tui" }
        );
        assert_eq!(app.mode, Mode::Menu);
    }

    #[test]
    fn enter_on_cli_tool_opens_args_then_runs() {
        let mut app = app_at(1); // veil
        assert_eq!(app.on_key(KeyCode::Enter), Action::None);
        assert_eq!(app.mode, Mode::Args);
        type_str(&mut app, "enc secret.pdf");
        let action = app.on_key(KeyCode::Enter);
        assert_eq!(
            action,
            Action::RunCommand {
                bin: "veil",
                args: "enc secret.pdf".to_string()
            }
        );
        assert_eq!(app.mode, Mode::Menu);
        assert!(app.args.is_empty());
    }

    #[test]
    fn esc_cancels_args() {
        let mut app = app_at(2); // scrub
        app.on_key(KeyCode::Enter);
        type_str(&mut app, "-n x.jpg");
        assert_eq!(app.on_key(KeyCode::Esc), Action::None);
        assert_eq!(app.mode, Mode::Menu);
        assert!(app.args.is_empty());
    }

    #[test]
    fn quit_and_shell() {
        let mut app = App::default();
        assert_eq!(app.on_key(KeyCode::Char('!')), Action::Shell);
        assert_eq!(app.on_key(KeyCode::Char('q')), Action::Quit);
    }
}
