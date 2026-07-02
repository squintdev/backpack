//! `keyring-tui` — a terminal UI over the keyring identity store.
//!
//! Unlocks the same encrypted keystore as the `keyring` CLI, then lets you
//! browse identities and generate / delete / export them interactively.
//! Signing and verification remain in the `keyring` CLI.

mod app;
mod ui;

use anyhow::{anyhow, bail, Context, Result};
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use zeroize::Zeroizing;

use app::App;

/// Keystore passphrase environment variable (shared across the suite).
const PASS_ENV: &str = "CIPHERPUNK_PASSPHRASE";

fn main() {
    if let Err(e) = run() {
        eprintln!("keyring-tui: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let path = keyring::default_keystore_path()
        .ok_or_else(|| anyhow!("cannot determine keystore path; set {}", keyring::PATH_ENV))?;

    // Unlock in the normal terminal (cooked mode) before entering the TUI.
    let creating = !path.exists();
    if creating {
        eprintln!("Creating a new keystore at {}", path.display());
    }
    let pass = passphrase(creating)?;
    let store = keyring::KeyStore::open(&path, pass.as_bytes())
        .context("opening keystore (wrong passphrase?)")?;

    let mut app = App::new(store, pass, path);
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui::render(f, app))?;
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key.code),
            _ => {}
        }
    }
    Ok(())
}

/// Keystore passphrase from `$CIPHERPUNK_PASSPHRASE` or an interactive prompt.
/// When `confirm` is set (new store), the prompt is entered twice.
fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var(PASS_ENV) {
        if p.is_empty() {
            bail!("{PASS_ENV} must not be empty");
        }
        return Ok(Zeroizing::new(p));
    }
    let p1 = rpassword::prompt_password("Keystore passphrase: ").context("reading passphrase")?;
    if confirm {
        if p1.is_empty() {
            bail!("passphrase must not be empty");
        }
        let p2 =
            rpassword::prompt_password("Confirm passphrase: ").context("reading passphrase")?;
        if p1 != p2 {
            bail!("passphrases do not match");
        }
    }
    Ok(Zeroizing::new(p1))
}
