//! TUI application state and key handling, kept free of terminal I/O so the
//! transitions can be unit-tested.

use std::path::{Path, PathBuf};

use keyring::{KeyStore, PublicIdentity};
use ratatui::crossterm::event::KeyCode;
use zeroize::Zeroizing;

/// Which interaction mode the UI is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Browsing the identity list.
    List,
    /// Typing a name for a new identity.
    Input,
    /// Confirming deletion of the selected identity.
    ConfirmDelete,
}

pub struct App {
    store: KeyStore,
    pass: Zeroizing<String>,
    path: PathBuf,
    pub selected: usize,
    pub mode: Mode,
    pub input: String,
    pub status: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(store: KeyStore, pass: Zeroizing<String>, path: PathBuf) -> Self {
        App {
            store,
            pass,
            path,
            selected: 0,
            mode: Mode::List,
            input: String::new(),
            status: String::new(),
            should_quit: false,
        }
    }

    pub fn identities(&self) -> Vec<PublicIdentity> {
        self.store.identities()
    }

    pub fn keystore_path(&self) -> &Path {
        &self.path
    }

    /// The identity currently highlighted, if any.
    pub fn selected_identity(&self) -> Option<PublicIdentity> {
        self.identities().into_iter().nth(self.selected)
    }

    pub fn on_key(&mut self, code: KeyCode) {
        match self.mode {
            Mode::List => self.on_key_list(code),
            Mode::Input => self.on_key_input(code),
            Mode::ConfirmDelete => self.on_key_confirm(code),
        }
    }

    fn on_key_list(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),
            KeyCode::Char('g') => {
                self.input.clear();
                self.status.clear();
                self.mode = Mode::Input;
            }
            KeyCode::Char('d') if self.selected_identity().is_some() => {
                self.mode = Mode::ConfirmDelete;
            }
            KeyCode::Char('e') => self.export_selected(),
            _ => {}
        }
    }

    fn on_key_input(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.input.clear();
                self.mode = Mode::List;
            }
            KeyCode::Enter => self.commit_new_identity(),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
    }

    fn on_key_confirm(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('y') => self.delete_selected(),
            KeyCode::Char('n') | KeyCode::Esc => self.mode = Mode::List,
            _ => {}
        }
    }

    fn move_down(&mut self) {
        let n = self.identities().len();
        if n > 0 && self.selected + 1 < n {
            self.selected += 1;
        }
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn commit_new_identity(&mut self) {
        let name = self.input.trim().to_string();
        self.mode = Mode::List;
        self.input.clear();
        match self.store.generate(&name) {
            Ok(_) => match self.store.save(self.pass.as_bytes()) {
                Ok(()) => {
                    self.selected = self.identities().len().saturating_sub(1);
                    self.status = format!("created {name}");
                }
                Err(e) => self.status = format!("saved failed: {e}"),
            },
            Err(e) => self.status = format!("error: {e}"),
        }
    }

    fn delete_selected(&mut self) {
        self.mode = Mode::List;
        let Some(id) = self.selected_identity() else {
            return;
        };
        self.store.remove(&id.name);
        match self.store.save(self.pass.as_bytes()) {
            Ok(()) => {
                self.selected = self.selected.min(self.identities().len().saturating_sub(1));
                self.status = format!("removed {}", id.name);
            }
            Err(e) => self.status = format!("save failed: {e}"),
        }
    }

    fn export_selected(&mut self) {
        let Some(id) = self.selected_identity() else {
            return;
        };
        let file = format!("{}.pub", id.name);
        match std::fs::write(&file, format!("{}\n", id.to_line())) {
            Ok(()) => self.status = format!("exported {file}"),
            Err(e) => self.status = format!("export failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("keyring-tui-test-{}-{n}.veil", std::process::id()))
    }

    fn app_with(path: &Path) -> App {
        let store = KeyStore::open(path, b"pw").unwrap();
        App::new(store, Zeroizing::new("pw".to_string()), path.to_path_buf())
    }

    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            app.on_key(KeyCode::Char(c));
        }
    }

    #[test]
    fn generate_via_keys_persists() {
        let path = temp_path();
        let mut app = app_with(&path);
        app.on_key(KeyCode::Char('g')); // open input
        assert_eq!(app.mode, Mode::Input);
        type_str(&mut app, "alice");
        app.on_key(KeyCode::Enter);
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.identities().len(), 1);

        // Reopening from disk shows it was saved.
        let reopened = KeyStore::open(&path, b"pw").unwrap();
        assert!(reopened.get("alice").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn duplicate_name_reports_error() {
        let path = temp_path();
        let mut app = app_with(&path);
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "alice");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "alice");
        app.on_key(KeyCode::Enter);
        assert_eq!(app.identities().len(), 1);
        assert!(app.status.contains("error"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn delete_confirm_removes_and_persists() {
        let path = temp_path();
        let mut app = app_with(&path);
        for name in ["alice", "bob"] {
            app.on_key(KeyCode::Char('g'));
            type_str(&mut app, name);
            app.on_key(KeyCode::Enter);
        }
        assert_eq!(app.identities().len(), 2);
        app.selected = 0;
        app.on_key(KeyCode::Char('d'));
        assert_eq!(app.mode, Mode::ConfirmDelete);
        app.on_key(KeyCode::Char('y'));
        assert_eq!(app.identities().len(), 1);
        assert!(app.selected_identity().is_some());

        let reopened = KeyStore::open(&path, b"pw").unwrap();
        assert!(reopened.get("alice").is_none());
        assert!(reopened.get("bob").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn delete_cancel_keeps_identity() {
        let path = temp_path();
        let mut app = app_with(&path);
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "alice");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Char('d'));
        app.on_key(KeyCode::Char('n')); // cancel
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.identities().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn selection_stays_in_bounds() {
        let path = temp_path();
        let mut app = app_with(&path);
        app.on_key(KeyCode::Down); // empty list, no panic
        app.on_key(KeyCode::Up);
        assert_eq!(app.selected, 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn quit_key_sets_flag() {
        let path = temp_path();
        let mut app = app_with(&path);
        app.on_key(KeyCode::Char('q'));
        assert!(app.should_quit);
        std::fs::remove_file(&path).ok();
    }
}
