//! `cipherpunk` — the boot menu for the suite.
//!
//! This is the binary a cyberdeck starts at login: a full-screen menu that
//! launches the suite's tools and takes the terminal back when they exit.
//! Interactive tools (keyring-tui) get the tty handed over directly; CLI tools
//! get an argument prompt and run in cooked mode so their own prompts
//! (passphrases) work, then the menu resumes.

mod app;
mod ui;

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use app::{Action, App};

fn main() {
    if let Err(e) = run() {
        eprintln!("cipherpunk: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut app = App::default();
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;
        let action = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key.code),
            _ => Action::None,
        };
        match action {
            Action::None => {}
            Action::Quit => return Ok(()),
            Action::RunInteractive { bin } => {
                let status = outside_tui(terminal, || {
                    Command::new(resolve(bin))
                        .status()
                        .with_context(|| format!("launching {bin}"))
                })?;
                app.last_run = Some((bin.to_string(), describe(status)));
            }
            Action::RunCommand { bin, args } => {
                let cmdline = format!("{bin} {args}");
                let status = outside_tui(terminal, || {
                    println!("┌─ $ {cmdline}");
                    let exe = resolve(bin).display().to_string();
                    // Run through sh so quoting and globs behave like a shell;
                    // stdio is inherited so the tool's own prompts work.
                    let status = Command::new("sh")
                        .arg("-c")
                        .arg(format!("{exe} {args}"))
                        .status()
                        .with_context(|| format!("launching {bin}"))?;
                    println!("└─ {}", describe(status));
                    pause()?;
                    Ok(status)
                })?;
                app.last_run = Some((cmdline, describe(status)));
            }
            Action::Shell => {
                let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
                outside_tui(terminal, || {
                    println!("(exit the shell to return to the menu)");
                    Command::new(&shell)
                        .status()
                        .with_context(|| format!("launching {shell}"))
                })?;
            }
        }
    }
}

/// Leave the TUI, run `f` with the terminal in cooked mode, then re-enter.
/// The alternate screen is restored even if `f` fails.
fn outside_tui<T>(
    terminal: &mut ratatui::DefaultTerminal,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    ratatui::restore();
    let result = f();
    *terminal = ratatui::init();
    result
}

/// Resolve a suite binary: prefer a sibling of this executable (the deploy
/// layout — all binaries in one directory), fall back to `$PATH`.
fn resolve(bin: &str) -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(bin);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(bin)
}

fn describe(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(0) => "ok".to_string(),
        Some(n) => format!("exit {n}"),
        None => "killed by signal".to_string(),
    }
}

/// Block until the user presses any key.
///
/// Uses crossterm (raw mode + `event::read`) rather than reading Rust's
/// buffered stdin: mixing the two input consumers on one tty leaves bytes
/// stranded in the wrong buffer and dead-locks the menu's input afterwards.
fn pause() -> Result<()> {
    print!("[any key] to return ");
    std::io::stdout().flush()?;
    enable_raw_mode()?;
    let result = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => break Ok(()),
            Ok(_) => continue,
            Err(e) => break Err(e.into()),
        }
    };
    disable_raw_mode()?;
    println!();
    result
}
