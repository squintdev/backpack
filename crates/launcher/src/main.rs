//! `backpack` — the suite as one TUI client.
//!
//! Everything happens inside the TUI: the keystore unlocks via an in-screen
//! masked prompt, and every tool (identities, nostr, veil, scrub, split,
//! sign/verify) is a native screen — no shelling out, no cooked-mode detours.
//! `!` still drops to a real shell for everything else.

mod app;
mod clipboard;
mod form;
mod session;
mod theme;
mod ui;

use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use app::{App, Pending};

fn main() {
    if let Err(e) = run() {
        eprintln!("backpack: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // `backpack --keyring /media/usb/keyring.veil` runs against any keystore
    // (the run-from-USB flow); it simply sets the same env var Session reads.
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--keyring" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--keyring needs a path"))?;
                std::env::set_var(keyring::PATH_ENV, path);
            }
            "--help" | "-h" => {
                println!("backpack [--keyring <path>]");
                println!("  --keyring  open this keystore file (e.g. a USB drive)");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument {other:?} (try --help)"),
        }
    }
    let mut app = App::new();
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        // A queued slow op: draw a WORKING overlay, run it, redraw with results.
        if let Some(op) = app.pending.take() {
            let label = match &op {
                Pending::NostrPost { .. } => "publishing",
                Pending::NostrFetch { .. } => "fetching",
                Pending::NostrRelayTest { .. } => "testing relays",
                Pending::NostrRebroadcast { .. } => "rebroadcasting history",
                Pending::SatsAddress { .. }
                | Pending::SatsBalance { .. }
                | Pending::SatsHistory { .. } => "scanning the chain",
                Pending::SatsPrepare { .. } => "building transaction",
                Pending::SatsBroadcast { .. } => "broadcasting",
                Pending::StampFile { .. } => "submitting to calendars",
                Pending::StampUpgrade { .. } => "querying calendars",
                Pending::StampVerify { .. } => "checking Bitcoin",
                _ => "working",
            };
            terminal.draw(|f| {
                ui::render(f, app);
                ui::render_working(f, label);
            })?;
            app.execute(op);
            continue;
        }

        if app.should_quit {
            if let Some(mut s) = app.signer.take() {
                s.stop();
            }
            return Ok(());
        }
        if app.shell_requested {
            app.shell_requested = false;
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            outside_tui(terminal, || {
                println!("(exit the shell to return to backpack)");
                Command::new(&shell)
                    .status()
                    .with_context(|| format!("launching {shell}"))
            })?;
            continue;
        }

        // While the signer runs, poll so its live request log refreshes even
        // without keypresses; otherwise block until the next key.
        if app.signer.is_some() {
            if event::poll(Duration::from_millis(300))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.on_key(key.code);
                    }
                }
            }
        } else if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                app.on_key(key.code);
            }
        }
        if let Some(text) = app.clipboard.take() {
            clipboard::copy(&text);
        }
    }
}

/// Leave the TUI, run `f` in cooked mode, then re-enter. Used only for the
/// `!` shell escape — every suite feature is a native screen.
fn outside_tui<T>(
    terminal: &mut ratatui::DefaultTerminal,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    ratatui::restore();
    let result = f();
    *terminal = ratatui::init();
    result
}
