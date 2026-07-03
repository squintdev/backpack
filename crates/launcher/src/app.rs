//! Launcher application state: the unlock gate, one state machine per native
//! tool screen, and the pending-op queue the main loop executes between
//! frames (so a "WORKING" frame renders before any slow call).
//!
//! No terminal I/O here — everything is unit-testable.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{anyhow, bail, Result};
use ratatui::crossterm::event::KeyCode;

use crate::form::{Field, Form, FormEvent};
use crate::session::Session;

// ---------------------------------------------------------------- home menu

pub struct MenuEntry {
    pub name: &'static str,
    pub tagline: &'static str,
    pub about: &'static [&'static str],
}

pub const MENU: &[MenuEntry] = &[
    MenuEntry {
        name: "IDENTITIES",
        tagline: "keys & npubs",
        about: &[
            "Your Ed25519/X25519/secp256k1 identities, in the encrypted store.",
            "Generate, export, delete; see each identity's npub.",
        ],
    },
    MenuEntry {
        name: "NOSTR",
        tagline: "decentralized notes",
        about: &[
            "Publish and read Nostr notes, signed with an identity.",
            "Spread across relays no one owns.",
        ],
    },
    MenuEntry {
        name: "VEIL",
        tagline: "file encryption",
        about: &[
            "Encrypt/decrypt files with a passphrase or to a person.",
            "Argon2id + ChaCha20-Poly1305; X25519 recipient mode.",
        ],
    },
    MenuEntry {
        name: "SCRUB",
        tagline: "metadata stripper",
        about: &[
            "Strip EXIF/GPS, XMP, and PDF metadata before sharing.",
            "Preview first, then write a cleaned copy.",
        ],
    },
    MenuEntry {
        name: "SPLIT",
        tagline: "shamir sharing",
        about: &[
            "Split a secret into n shares where any k recover it.",
            "Wrong or missing shares are detected, never silent garbage.",
        ],
    },
    MenuEntry {
        name: "SIGN/VERIFY",
        tagline: "signatures",
        about: &[
            "Sign files with an identity; verify anyone's signature",
            "from their public line. Verification needs no passphrase.",
        ],
    },
];

// ---------------------------------------------------------------- screens

pub enum IdMode {
    List,
    New(Form),
    ConfirmDelete,
    /// Confirming a private-key reveal.
    RevealConfirm,
    /// Showing the nsec (private key) — c copies, Esc clears.
    Reveal { nsec: String },
}

pub struct IdentitiesState {
    pub selected: usize,
    pub mode: IdMode,
    pub status: String,
}

pub enum NostrMode {
    Menu(usize),
    Whoami(Form),
    Post(Form),
    ConfirmPost { identity: String, text: String },
    Fetch(Form),
    Timeline(Form),
    Follow(Form),
    FollowsForm(Form),
    ProfileWho(Form),
    ProfileEdit { identity: String, form: Form },
    SignerWho(Form),
    Signer,
    ExploreWho(Form),
    Explore {
        identity: String,
        entries: Vec<SuggestEntry>,
        selected: usize,
        status: String,
    },
    DmsWho(Form),
    SendDm(Form),
    ConfirmDm { identity: String, recipient_hex: String, recipient_label: String, text: String },
    /// Interactive follow list: j/k select, d unfollow (with confirm).
    Follows {
        identity: String,
        entries: Vec<FollowEntry>,
        selected: usize,
        confirm_unfollow: bool,
    },
    Results {
        title: String,
        lines: Vec<String>,
        /// Payload staged to the clipboard when the user presses c.
        copy: Option<String>,
        /// Vertical scroll offset (long timelines).
        scroll: u16,
    },
}

/// One row in the FOLLOWS screen.
#[derive(Clone)]
pub struct FollowEntry {
    pub label: String,
    pub npub: String,
    pub hex: String,
}

/// One row in the EXPLORE (suggested follows) screen.
#[derive(Clone)]
pub struct SuggestEntry {
    pub label: String,
    pub about: String,
    pub npub: String,
    pub hex: String,
    pub score: u32,
}

pub const NOSTR_MENU: &[&str] = &[
    "TIMELINE  notes from who I follow",
    "POST      publish a note",
    "FETCH     read one author",
    "FOLLOW    add an author",
    "FOLLOWS   manage my follows",
    "EXPLORE   find people to follow",
    "MESSAGES  read my DMs",
    "SEND DM   encrypted message",
    "PROFILE   view / edit my profile",
    "WHOAMI    show my npub",
    "SIGNER    be a bunker (NIP-46)",
];

pub enum VeilMode {
    Menu(usize),
    Form(usize, Form),
    Results { title: String, lines: Vec<String> },
}

pub const VEIL_MENU: &[&str] = &[
    "ENCRYPT  with a passphrase",
    "ENCRYPT  to a recipient (.pub)",
    "DECRYPT  with a passphrase",
    "DECRYPT  with my identity",
];

pub enum ScrubMode {
    Form(Form),
    Report { path: String, lines: Vec<String>, changed: bool },
    Results { lines: Vec<String> },
}

pub enum SplitMode {
    Menu(usize),
    Deal(Form),
    Combine(Form),
    Results { title: String, lines: Vec<String> },
}

pub const SPLIT_MENU: &[&str] = &[
    "DEAL     split a secret into shares",
    "COMBINE  recover from shares",
];

pub enum SignMode {
    Menu(usize),
    Sign(Form),
    Verify(Form),
    Results { title: String, lines: Vec<String> },
}

pub const SIGN_MENU: &[&str] = &[
    "SIGN     a file with my identity",
    "VERIFY   someone's signature",
];

pub enum Screen {
    Home { selected: usize },
    Identities(IdentitiesState),
    Nostr(NostrMode),
    Veil(VeilMode),
    Scrub(ScrubMode),
    Split(SplitMode),
    Sign(SignMode),
}

// ---------------------------------------------------------------- pending ops

/// Slow work queued by a key handler; the main loop draws a WORKING frame,
/// then calls [`App::execute`].
pub enum Pending {
    NostrPost { identity: String, text: String },
    NostrFetch { author: String, limit: u32 },
    NostrTimeline { identity: String, limit: u32 },
    NostrFollow { identity: String, author: String, name: Option<String> },
    NostrUnfollow { identity: String, author_hex: String },
    NostrFollows { identity: String },
    NostrProfileLoad { identity: String },
    NostrProfileSave { identity: String, updates: Vec<(String, String)> },
    NostrDmsLoad { identity: String },
    NostrDmSend { identity: String, recipient_hex: String, text: String },
    NostrExplore { identity: String },
    NostrExploreFollow { identity: String, author_hex: String },
    NostrSignerStart { identity: String },
    VeilEncPass { input: String, output: String, pass: String },
    VeilEncRecipient { input: String, pub_path: String, output: String },
    VeilDecPass { input: String, output: String, pass: String },
    VeilDecIdentity { input: String, identity: String, output: String },
}

// ---------------------------------------------------------------- gate + app

pub enum Gate {
    /// Waiting for the keystore passphrase (masked, in-TUI).
    Locked { form: Form, creating: bool },
    Open(Session),
}

/// A running NIP-46 signer (background thread + shared log).
pub struct SignerState {
    pub url: String,
    pub relay: String,
    pub identity: String,
    pub log: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SignerState {
    /// Signal the thread to stop and join it.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub struct App {
    pub gate: Gate,
    pub screen: Screen,
    pub pending: Option<Pending>,
    pub should_quit: bool,
    pub shell_requested: bool,
    /// Text staged for the terminal clipboard (emitted as OSC 52 by the loop).
    pub clipboard: Option<String>,
    /// The active NIP-46 signer, if the SIGNER screen is running one.
    pub signer: Option<SignerState>,
}

impl App {
    pub fn new() -> Self {
        let creating = Session::is_new();
        let fields = if creating {
            vec![
                Field::masked("new keystore passphrase"),
                Field::masked("confirm passphrase"),
            ]
        } else {
            vec![Field::masked("keystore passphrase")]
        };
        let title = if creating { "create keystore" } else { "unlock keystore" };
        App {
            gate: Gate::Locked { form: Form::new(title, fields), creating },
            screen: Screen::Home { selected: 0 },
            pending: None,
            should_quit: false,
            shell_requested: false,
            clipboard: None,
            signer: None,
        }
    }

    pub fn session(&self) -> Option<&Session> {
        match &self.gate {
            Gate::Open(s) => Some(s),
            _ => None,
        }
    }

    // ------------------------------------------------------------- input

    pub fn on_key(&mut self, code: KeyCode) {
        if matches!(self.gate, Gate::Locked { .. }) {
            self.on_key_locked(code);
            return;
        }
        match &self.screen {
            Screen::Home { .. } => self.on_key_home(code),
            Screen::Identities(_) => self.on_key_identities(code),
            Screen::Nostr(_) => self.on_key_nostr(code),
            Screen::Veil(_) => self.on_key_veil(code),
            Screen::Scrub(_) => self.on_key_scrub(code),
            Screen::Split(_) => self.on_key_split(code),
            Screen::Sign(_) => self.on_key_sign(code),
        }
    }

    fn on_key_locked(&mut self, code: KeyCode) {
        let Gate::Locked { form, creating } = &mut self.gate else {
            return;
        };
        match form.on_key(code) {
            FormEvent::Cancel => self.should_quit = true,
            FormEvent::Editing => {}
            FormEvent::Submit => {
                let pass = form.value(0).to_string();
                if pass.is_empty() {
                    form.error = Some("passphrase must not be empty".into());
                    return;
                }
                if *creating && form.value(1) != pass {
                    form.error = Some("passphrases do not match".into());
                    return;
                }
                match Session::unlock(&pass) {
                    Ok(session) => self.gate = Gate::Open(session),
                    Err(e) => form.error = Some(format!("{e}")),
                }
            }
        }
    }

    fn on_key_home(&mut self, code: KeyCode) {
        let Screen::Home { selected } = &mut self.screen else {
            return;
        };
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('!') => self.shell_requested = true,
            KeyCode::Char('j') | KeyCode::Down => *selected = (*selected + 1) % MENU.len(),
            KeyCode::Char('k') | KeyCode::Up => {
                *selected = selected.checked_sub(1).unwrap_or(MENU.len() - 1)
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let idx = c.to_digit(10).unwrap() as usize;
                if (1..=MENU.len()).contains(&idx) {
                    *selected = idx - 1;
                }
            }
            KeyCode::Enter => {
                let idx = *selected;
                self.screen = self.open_screen(idx);
            }
            _ => {}
        }
    }

    fn open_screen(&self, idx: usize) -> Screen {
        match idx {
            0 => Screen::Identities(IdentitiesState {
                selected: 0,
                mode: IdMode::List,
                status: String::new(),
            }),
            1 => Screen::Nostr(NostrMode::Menu(0)),
            2 => Screen::Veil(VeilMode::Menu(0)),
            3 => Screen::Scrub(ScrubMode::Form(Form::new(
                "scrub a file",
                vec![Field::new("file path")],
            ))),
            4 => Screen::Split(SplitMode::Menu(0)),
            _ => Screen::Sign(SignMode::Menu(0)),
        }
    }

    fn first_identity(&self) -> String {
        self.session()
            .and_then(Session::first_identity)
            .unwrap_or_default()
    }

    // ------------------------------------------------------------- identities

    fn on_key_identities(&mut self, code: KeyCode) {
        let mut back_home = false;
        let mut queue_copy: Option<String> = None;
        {
            let Gate::Open(session) = &mut self.gate else {
                return;
            };
            let Screen::Identities(st) = &mut self.screen else {
                return;
            };
            match &mut st.mode {
                IdMode::List => match code {
                    KeyCode::Esc | KeyCode::Char('q') => back_home = true,
                    KeyCode::Char('j') | KeyCode::Down => {
                        let n = session.identities().len();
                        if n > 0 && st.selected + 1 < n {
                            st.selected += 1;
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        st.selected = st.selected.saturating_sub(1)
                    }
                    KeyCode::Char('g') => {
                        st.mode = IdMode::New(Form::new("new identity", vec![Field::new("name")]));
                    }
                    KeyCode::Char('e') => {
                        st.status = match export_identity(session, st.selected) {
                            Ok(file) => format!("exported {file}"),
                            Err(e) => format!("export failed: {e}"),
                        };
                    }
                    KeyCode::Char('n') => {
                        st.status = match nostr_init_selected(session, st.selected) {
                            Ok(msg) => msg,
                            Err(e) => format!("nostr-init failed: {e}"),
                        };
                    }
                    KeyCode::Char('c') => match selected_npub(session, st.selected) {
                        Ok(npub) => {
                            queue_copy = Some(npub);
                            st.status = "npub copied ✓".to_string();
                        }
                        Err(e) => st.status = format!("copy failed: {e}"),
                    },
                    KeyCode::Char('d') if !session.identities().is_empty() => {
                        st.mode = IdMode::ConfirmDelete;
                    }
                    KeyCode::Char('x') if !session.identities().is_empty() => {
                        st.mode = IdMode::RevealConfirm;
                    }
                    _ => {}
                },
                IdMode::New(form) => match form.on_key(code) {
                    FormEvent::Cancel => st.mode = IdMode::List,
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let name = form.value(0).to_string();
                        let generated = session.store.generate(&name).map(|_| ());
                        match generated
                            .map_err(anyhow::Error::from)
                            .and_then(|_| session.save())
                        {
                            Ok(()) => {
                                st.selected = session.identities().len().saturating_sub(1);
                                st.status = format!("created {name}");
                                st.mode = IdMode::List;
                            }
                            Err(e) => form.error = Some(format!("{e}")),
                        }
                    }
                },
                IdMode::RevealConfirm => match code {
                    KeyCode::Char('y') => {
                        let name = session
                            .identities()
                            .get(st.selected)
                            .map(|i| i.name.clone());
                        st.mode = match name.as_deref().map(|n| session.nostr_key(n)) {
                            Some(Ok(sk)) => IdMode::Reveal {
                                nsec: bp_nostr::nip19::nsec_encode(&sk).to_string(),
                            },
                            Some(Err(e)) => {
                                st.status = format!("{e}");
                                IdMode::List
                            }
                            None => IdMode::List,
                        };
                    }
                    KeyCode::Char('n') | KeyCode::Esc => st.mode = IdMode::List,
                    _ => {}
                },
                IdMode::Reveal { nsec } => match code {
                    KeyCode::Char('c') => {
                        queue_copy = Some(nsec.clone());
                        st.status = "nsec copied ✓ — paste only where you trust".to_string();
                    }
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        st.status.clear();
                        st.mode = IdMode::List;
                    }
                    _ => {}
                },
                IdMode::ConfirmDelete => match code {
                    KeyCode::Char('y') => {
                        if let Some(id) = session.identities().get(st.selected).cloned() {
                            session.store.remove(&id.name);
                            st.status = match session.save() {
                                Ok(()) => format!("removed {}", id.name),
                                Err(e) => format!("save failed: {e}"),
                            };
                            st.selected = st
                                .selected
                                .min(session.identities().len().saturating_sub(1));
                        }
                        st.mode = IdMode::List;
                    }
                    KeyCode::Char('n') | KeyCode::Esc => st.mode = IdMode::List,
                    _ => {}
                },
            }
        }
        if back_home {
            self.screen = Screen::Home { selected: 0 };
        }
        if queue_copy.is_some() {
            self.clipboard = queue_copy;
        }
    }

    // ------------------------------------------------------------- nostr

    fn on_key_nostr(&mut self, code: KeyCode) {
        let first = self.first_identity();
        let mut back_home = false;
        let mut queue: Option<Pending> = None;
        let mut queue_copy: Option<String> = None;
        let mut leave_signer = false;
        let mut copy_signer_url = false;
        {
            let Gate::Open(session) = &self.gate else {
                return;
            };
            let Screen::Nostr(mode) = &mut self.screen else {
                return;
            };
            match mode {
                NostrMode::Menu(sel) => match code {
                    KeyCode::Esc | KeyCode::Char('q') => back_home = true,
                    KeyCode::Char('j') | KeyCode::Down => *sel = (*sel + 1) % NOSTR_MENU.len(),
                    KeyCode::Char('k') | KeyCode::Up => {
                        *sel = sel.checked_sub(1).unwrap_or(NOSTR_MENU.len() - 1)
                    }
                    KeyCode::Enter => {
                        *mode = match *sel {
                            0 => NostrMode::Timeline(Form::new(
                                "timeline",
                                vec![
                                    Field::new("identity").with_value(&first),
                                    Field::new("limit").with_value("30"),
                                ],
                            )),
                            1 => NostrMode::Post(Form::new(
                                "post a note",
                                vec![
                                    Field::new("identity").with_value(&first),
                                    Field::new("text"),
                                ],
                            )),
                            2 => NostrMode::Fetch(Form::new(
                                "fetch notes",
                                vec![
                                    Field::new("author (npub or hex)"),
                                    Field::new("limit").with_value("10"),
                                ],
                            )),
                            3 => NostrMode::Follow(Form::new(
                                "follow an author",
                                vec![
                                    Field::new("identity").with_value(&first),
                                    Field::new("author (npub or hex)"),
                                    Field::new("petname (optional)"),
                                ],
                            )),
                            4 => NostrMode::FollowsForm(Form::new(
                                "my follows",
                                vec![Field::new("identity").with_value(&first)],
                            )),
                            5 => NostrMode::ExploreWho(Form::new(
                                "find people to follow",
                                vec![Field::new("identity").with_value(&first)],
                            )),
                            6 => NostrMode::DmsWho(Form::new(
                                "read messages",
                                vec![Field::new("identity").with_value(&first)],
                            )),
                            7 => NostrMode::SendDm(Form::new(
                                "send encrypted DM",
                                vec![
                                    Field::new("identity").with_value(&first),
                                    Field::new("to (npub or hex)"),
                                    Field::new("message"),
                                ],
                            )),
                            8 => NostrMode::ProfileWho(Form::new(
                                "my profile",
                                vec![Field::new("identity").with_value(&first)],
                            )),
                            10 => NostrMode::SignerWho(Form::new(
                                "be a signer (bunker)",
                                vec![Field::new("identity").with_value(&first)],
                            )),
                            _ => NostrMode::Whoami(Form::new(
                                "whoami",
                                vec![Field::new("identity").with_value(&first)],
                            )),
                        };
                    }
                    _ => {}
                },
                NostrMode::Whoami(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(0),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let name = form.value(0).to_string();
                        match nostr_whoami(session, &name) {
                            Ok(lines) => {
                                let npub = lines.first().cloned();
                                *mode = NostrMode::Results {
                                    title: format!("{name}'s nostr key"),
                                    lines,
                                    copy: npub,
                                    scroll: 0,
                                }
                            }
                            Err(e) => form.error = Some(format!("{e}")),
                        }
                    }
                },
                NostrMode::Post(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(1),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        let text = form.value(1).to_string();
                        if text.is_empty() {
                            form.error = Some("note text is empty".into());
                        } else if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            *mode = NostrMode::ConfirmPost { identity, text };
                        }
                    }
                },
                NostrMode::ConfirmPost { identity, text } => match code {
                    KeyCode::Char('y') => {
                        queue = Some(Pending::NostrPost {
                            identity: identity.clone(),
                            text: text.clone(),
                        });
                    }
                    KeyCode::Char('n') | KeyCode::Esc => *mode = NostrMode::Menu(1),
                    _ => {}
                },
                NostrMode::Fetch(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(2),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let author = form.value(0).to_string();
                        let limit: u32 = form.value(1).parse().unwrap_or(10);
                        if author.is_empty() {
                            form.error = Some("author is required".into());
                        } else {
                            queue = Some(Pending::NostrFetch { author, limit });
                        }
                    }
                },
                NostrMode::Timeline(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(0),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        let limit: u32 = form.value(1).parse().unwrap_or(30);
                        if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrTimeline { identity, limit });
                        }
                    }
                },
                NostrMode::Follow(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(3),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        let author = form.value(1).to_string();
                        let name = Some(form.value(2).to_string()).filter(|s| !s.is_empty());
                        if author.is_empty() {
                            form.error = Some("author is required".into());
                        } else if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrFollow { identity, author, name });
                        }
                    }
                },
                NostrMode::FollowsForm(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(4),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrFollows { identity });
                        }
                    }
                },
                NostrMode::ExploreWho(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(5),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrExplore { identity });
                        }
                    }
                },
                NostrMode::Explore { identity, entries, selected, .. } => match code {
                    KeyCode::Esc | KeyCode::Char('q') => *mode = NostrMode::Menu(5),
                    KeyCode::Char('j') | KeyCode::Down if *selected + 1 < entries.len() => {
                        *selected += 1
                    }
                    KeyCode::Char('k') | KeyCode::Up => *selected = selected.saturating_sub(1),
                    KeyCode::Char('c') => {
                        if let Some(e) = entries.get(*selected) {
                            queue_copy = Some(e.npub.clone());
                        }
                    }
                    KeyCode::Char('f') => {
                        if let Some(e) = entries.get(*selected) {
                            queue = Some(Pending::NostrExploreFollow {
                                identity: identity.clone(),
                                author_hex: e.hex.clone(),
                            });
                        }
                    }
                    _ => {}
                },
                NostrMode::DmsWho(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(6),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrDmsLoad { identity });
                        }
                    }
                },
                NostrMode::SendDm(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(7),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        let to = form.value(1).to_string();
                        let text = form.value(2).to_string();
                        if to.is_empty() || text.is_empty() {
                            form.error = Some("recipient and message are required".into());
                        } else if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            match bp_nostr::nip19::pubkey_to_hex(&to) {
                                Ok(hex) => {
                                    *mode = NostrMode::ConfirmDm {
                                        identity,
                                        recipient_label: to.clone(),
                                        recipient_hex: hex,
                                        text,
                                    };
                                }
                                Err(e) => form.error = Some(format!("{e}")),
                            }
                        }
                    }
                },
                NostrMode::ConfirmDm { identity, recipient_hex, text, .. } => match code {
                    KeyCode::Char('y') => {
                        queue = Some(Pending::NostrDmSend {
                            identity: identity.clone(),
                            recipient_hex: recipient_hex.clone(),
                            text: text.clone(),
                        });
                    }
                    KeyCode::Char('n') | KeyCode::Esc => *mode = NostrMode::Menu(7),
                    _ => {}
                },
                NostrMode::SignerWho(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(10),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrSignerStart { identity });
                        }
                    }
                },
                NostrMode::Signer => match code {
                    KeyCode::Char('c') => copy_signer_url = true,
                    KeyCode::Esc | KeyCode::Char('q') => leave_signer = true,
                    _ => {}
                },
                NostrMode::ProfileWho(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(8),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let identity = form.value(0).to_string();
                        if let Err(e) = session.nostr_key(&identity) {
                            form.error = Some(format!("{e}"));
                        } else {
                            queue = Some(Pending::NostrProfileLoad { identity });
                        }
                    }
                },
                NostrMode::ProfileEdit { identity, form } => match form.on_key(code) {
                    FormEvent::Cancel => *mode = NostrMode::Menu(8),
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let updates: Vec<(String, String)> = ["name", "about", "picture", "nip05"]
                            .iter()
                            .enumerate()
                            .map(|(i, k)| (k.to_string(), form.value(i).to_string()))
                            .collect();
                        queue = Some(Pending::NostrProfileSave {
                            identity: identity.clone(),
                            updates,
                        });
                    }
                },
                NostrMode::Follows { identity, entries, selected, confirm_unfollow } => {
                    if *confirm_unfollow {
                        match code {
                            KeyCode::Char('y') => {
                                if let Some(entry) = entries.get(*selected) {
                                    queue = Some(Pending::NostrUnfollow {
                                        identity: identity.clone(),
                                        author_hex: entry.hex.clone(),
                                    });
                                }
                                *confirm_unfollow = false;
                            }
                            KeyCode::Char('n') | KeyCode::Esc => *confirm_unfollow = false,
                            _ => {}
                        }
                    } else {
                        match code {
                            KeyCode::Esc | KeyCode::Char('q') => *mode = NostrMode::Menu(4),
                            KeyCode::Char('j') | KeyCode::Down
                                if *selected + 1 < entries.len() =>
                            {
                                *selected += 1;
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                *selected = selected.saturating_sub(1)
                            }
                            KeyCode::Char('c') => {
                                if let Some(entry) = entries.get(*selected) {
                                    queue_copy = Some(entry.npub.clone());
                                }
                            }
                            KeyCode::Char('d') if !entries.is_empty() => {
                                *confirm_unfollow = true;
                            }
                            _ => {}
                        }
                    }
                }
                NostrMode::Results { lines, copy, scroll, .. } => match code {
                    KeyCode::Char('j') | KeyCode::Down => {
                        *scroll = scroll.saturating_add(1).min(lines.len() as u16)
                    }
                    KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
                    KeyCode::PageDown => {
                        *scroll = scroll.saturating_add(10).min(lines.len() as u16)
                    }
                    KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                    KeyCode::Char('c') => {
                        if let Some(text) = copy.clone() {
                            queue_copy = Some(text);
                            if !lines.iter().any(|l| l.contains("copied ✓")) {
                                lines.push("copied ✓".to_string());
                            }
                        }
                    }
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        *mode = NostrMode::Menu(0);
                    }
                    _ => {}
                },
            }
        }
        if back_home {
            self.screen = Screen::Home { selected: 1 };
        }
        if queue.is_some() {
            self.pending = queue;
        }
        if copy_signer_url {
            if let Some(s) = &self.signer {
                self.clipboard = Some(s.url.clone());
            }
        }
        if leave_signer {
            if let Some(mut s) = self.signer.take() {
                s.stop();
            }
            self.screen = Screen::Nostr(NostrMode::Menu(10));
        }
        if queue_copy.is_some() {
            self.clipboard = queue_copy;
        }
    }

    // ------------------------------------------------------------- veil

    fn on_key_veil(&mut self, code: KeyCode) {
        let first = self.first_identity();
        let mut back_home = false;
        let mut queue: Option<Pending> = None;
        {
            let Screen::Veil(mode) = &mut self.screen else {
                return;
            };
            match mode {
                VeilMode::Menu(sel) => match code {
                    KeyCode::Esc | KeyCode::Char('q') => back_home = true,
                    KeyCode::Char('j') | KeyCode::Down => *sel = (*sel + 1) % VEIL_MENU.len(),
                    KeyCode::Char('k') | KeyCode::Up => {
                        *sel = sel.checked_sub(1).unwrap_or(VEIL_MENU.len() - 1)
                    }
                    KeyCode::Enter => *mode = VeilMode::Form(*sel, veil_form(*sel, &first)),
                    _ => {}
                },
                VeilMode::Form(op, form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = VeilMode::Menu(*op),
                    FormEvent::Editing => {}
                    FormEvent::Submit => match veil_pending(*op, form) {
                        Ok(p) => queue = Some(p),
                        Err(e) => form.error = Some(format!("{e}")),
                    },
                },
                VeilMode::Results { .. } => {
                    if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                        *mode = VeilMode::Menu(0);
                    }
                }
            }
        }
        if back_home {
            self.screen = Screen::Home { selected: 2 };
        }
        if queue.is_some() {
            self.pending = queue;
        }
    }

    // ------------------------------------------------------------- scrub

    fn on_key_scrub(&mut self, code: KeyCode) {
        let mut back_home = false;
        {
            let Screen::Scrub(mode) = &mut self.screen else {
                return;
            };
            match mode {
                ScrubMode::Form(form) => match form.on_key(code) {
                    FormEvent::Cancel => back_home = true,
                    FormEvent::Editing => {}
                    FormEvent::Submit => {
                        let path = form.value(0).to_string();
                        match scrub_scan(&path) {
                            Ok((lines, changed)) => {
                                *mode = ScrubMode::Report { path, lines, changed }
                            }
                            Err(e) => form.error = Some(format!("{e}")),
                        }
                    }
                },
                ScrubMode::Report { path, changed, .. } => match code {
                    KeyCode::Enter if *changed => {
                        let result = scrub_apply(path);
                        *mode = ScrubMode::Results {
                            lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        };
                    }
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                        *mode = ScrubMode::Form(Form::new(
                            "scrub a file",
                            vec![Field::new("file path")],
                        ));
                    }
                    _ => {}
                },
                ScrubMode::Results { .. } => {
                    if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                        *mode = ScrubMode::Form(Form::new(
                            "scrub a file",
                            vec![Field::new("file path")],
                        ));
                    }
                }
            }
        }
        if back_home {
            self.screen = Screen::Home { selected: 3 };
        }
    }

    // ------------------------------------------------------------- split

    fn on_key_split(&mut self, code: KeyCode) {
        let mut back_home = false;
        {
            let Screen::Split(mode) = &mut self.screen else {
                return;
            };
            match mode {
                SplitMode::Menu(sel) => match code {
                    KeyCode::Esc | KeyCode::Char('q') => back_home = true,
                    KeyCode::Char('j') | KeyCode::Down => *sel = (*sel + 1) % SPLIT_MENU.len(),
                    KeyCode::Char('k') | KeyCode::Up => {
                        *sel = sel.checked_sub(1).unwrap_or(SPLIT_MENU.len() - 1)
                    }
                    KeyCode::Enter => {
                        *mode = if *sel == 0 {
                            SplitMode::Deal(Form::new(
                                "deal shares",
                                vec![
                                    Field::new("secret file"),
                                    Field::new("k (threshold)").with_value("3"),
                                    Field::new("n (shares)").with_value("5"),
                                    Field::new("output directory").with_value("shares"),
                                ],
                            ))
                        } else {
                            SplitMode::Combine(Form::new(
                                "combine shares",
                                vec![
                                    Field::new("share files (space-separated)"),
                                    Field::new("write secret to (optional)")
                                        .with_placeholder("display only"),
                                ],
                            ))
                        };
                    }
                    _ => {}
                },
                SplitMode::Deal(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = SplitMode::Menu(0),
                    FormEvent::Editing => {}
                    FormEvent::Submit => match split_deal(form) {
                        Ok(lines) => {
                            *mode = SplitMode::Results { title: "shares dealt".into(), lines }
                        }
                        Err(e) => form.error = Some(format!("{e}")),
                    },
                },
                SplitMode::Combine(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = SplitMode::Menu(1),
                    FormEvent::Editing => {}
                    FormEvent::Submit => match split_combine(form) {
                        Ok(lines) => {
                            *mode =
                                SplitMode::Results { title: "secret recovered".into(), lines }
                        }
                        Err(e) => form.error = Some(format!("{e}")),
                    },
                },
                SplitMode::Results { .. } => {
                    if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                        *mode = SplitMode::Menu(0);
                    }
                }
            }
        }
        if back_home {
            self.screen = Screen::Home { selected: 4 };
        }
    }

    // ------------------------------------------------------------- sign

    fn on_key_sign(&mut self, code: KeyCode) {
        let first = self.first_identity();
        let mut back_home = false;
        {
            let Gate::Open(session) = &self.gate else {
                return;
            };
            let Screen::Sign(mode) = &mut self.screen else {
                return;
            };
            match mode {
                SignMode::Menu(sel) => match code {
                    KeyCode::Esc | KeyCode::Char('q') => back_home = true,
                    KeyCode::Char('j') | KeyCode::Down => *sel = (*sel + 1) % SIGN_MENU.len(),
                    KeyCode::Char('k') | KeyCode::Up => {
                        *sel = sel.checked_sub(1).unwrap_or(SIGN_MENU.len() - 1)
                    }
                    KeyCode::Enter => {
                        *mode = if *sel == 0 {
                            SignMode::Sign(Form::new(
                                "sign a file",
                                vec![
                                    Field::new("identity").with_value(&first),
                                    Field::new("message file"),
                                ],
                            ))
                        } else {
                            SignMode::Verify(Form::new(
                                "verify a signature",
                                vec![
                                    Field::new("public line file (.pub)"),
                                    Field::new("message file"),
                                    Field::new("signature file (.sig)"),
                                ],
                            ))
                        };
                    }
                    _ => {}
                },
                SignMode::Sign(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = SignMode::Menu(0),
                    FormEvent::Editing => {}
                    FormEvent::Submit => match sign_file(session, form) {
                        Ok(lines) => *mode = SignMode::Results { title: "signed".into(), lines },
                        Err(e) => form.error = Some(format!("{e}")),
                    },
                },
                SignMode::Verify(form) => match form.on_key(code) {
                    FormEvent::Cancel => *mode = SignMode::Menu(1),
                    FormEvent::Editing => {}
                    FormEvent::Submit => match verify_file(form) {
                        Ok(lines) => {
                            *mode = SignMode::Results { title: "verification".into(), lines }
                        }
                        Err(e) => form.error = Some(format!("{e}")),
                    },
                },
                SignMode::Results { .. } => {
                    if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                        *mode = SignMode::Menu(0);
                    }
                }
            }
        }
        if back_home {
            self.screen = Screen::Home { selected: 5 };
        }
    }

    // ------------------------------------------------------------- pending

    /// Execute a queued slow operation (the main loop calls this after
    /// rendering a WORKING frame) and route the result to the right screen.
    pub fn execute(&mut self, op: Pending) {
        let Gate::Open(session) = &self.gate else {
            return;
        };
        match op {
            Pending::NostrPost { identity, text } => {
                let result = nostr_post(session, &identity, &text);
                if let Screen::Nostr(mode) = &mut self.screen {
                    let (lines, copy) = match result {
                        Ok(lines) => {
                            let id = lines
                                .first()
                                .and_then(|l| l.strip_prefix("event id "))
                                .map(str::to_string);
                            (lines, id)
                        }
                        Err(e) => (vec![format!("failed: {e}")], None),
                    };
                    *mode = NostrMode::Results { title: "post".into(), lines, copy, scroll: 0 };
                }
            }
            Pending::NostrFetch { author, limit } => {
                let result = nostr_fetch(&author, limit);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = NostrMode::Results {
                        title: "fetch".into(),
                        lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        copy: None,
                        scroll: 0,
                    };
                }
            }
            Pending::NostrTimeline { identity, limit } => {
                let result = nostr_timeline(session, &identity, limit);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = NostrMode::Results {
                        title: "timeline".into(),
                        lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        copy: None,
                        scroll: 0,
                    };
                }
            }
            Pending::NostrFollow { identity, author, name } => {
                let result = nostr_follow(session, &identity, &author, name);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = NostrMode::Results {
                        title: "follow".into(),
                        lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        copy: None,
                        scroll: 0,
                    };
                }
            }
            Pending::NostrUnfollow { identity, author_hex } => {
                let result = nostr_unfollow(session, &identity, &author_hex)
                    .and_then(|_| nostr_follow_entries(session, &identity));
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = match result {
                        Ok(entries) => NostrMode::Follows {
                            identity,
                            selected: 0,
                            entries,
                            confirm_unfollow: false,
                        },
                        Err(e) => NostrMode::Results {
                            title: "unfollow".into(),
                            lines: vec![format!("failed: {e}")],
                            copy: None,
                            scroll: 0,
                        },
                    };
                }
            }
            Pending::NostrFollows { identity } => {
                let result = nostr_follow_entries(session, &identity);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = match result {
                        Ok(entries) => NostrMode::Follows {
                            identity,
                            selected: 0,
                            entries,
                            confirm_unfollow: false,
                        },
                        Err(e) => NostrMode::Results {
                            title: "follows".into(),
                            lines: vec![format!("failed: {e}")],
                            copy: None,
                            scroll: 0,
                        },
                    };
                }
            }
            Pending::NostrProfileLoad { identity } => {
                let result = nostr_profile_form(session, &identity);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = match result {
                        Ok(form) => NostrMode::ProfileEdit { identity, form },
                        Err(e) => NostrMode::Results {
                            title: "profile".into(),
                            lines: vec![format!("failed: {e}")],
                            copy: None,
                            scroll: 0,
                        },
                    };
                }
            }
            Pending::NostrProfileSave { identity, updates } => {
                let result = nostr_profile_save(session, &identity, &updates);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = NostrMode::Results {
                        title: "profile".into(),
                        lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        copy: None,
                        scroll: 0,
                    };
                }
            }
            Pending::NostrExplore { identity } => {
                let result = nostr_suggestions(session, &identity);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = match result {
                        Ok(entries) => NostrMode::Explore {
                            identity,
                            entries,
                            selected: 0,
                            status: String::new(),
                        },
                        Err(e) => NostrMode::Results {
                            title: "explore".into(),
                            lines: vec![format!("failed: {e}")],
                            copy: None,
                            scroll: 0,
                        },
                    };
                }
            }
            Pending::NostrExploreFollow { identity, author_hex } => {
                let followed = nostr_follow(session, &identity, &author_hex, None);
                let rebuilt = nostr_suggestions(session, &identity);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = match rebuilt {
                        Ok(entries) => NostrMode::Explore {
                            identity,
                            entries,
                            selected: 0,
                            status: match followed {
                                Ok(_) => "followed ✓".to_string(),
                                Err(e) => format!("follow failed: {e}"),
                            },
                        },
                        Err(e) => NostrMode::Results {
                            title: "explore".into(),
                            lines: vec![format!("failed: {e}")],
                            copy: None,
                            scroll: 0,
                        },
                    };
                }
            }
            Pending::NostrSignerStart { identity } => {
                match start_signer(session, &identity) {
                    Ok(state) => {
                        self.signer = Some(state);
                        if let Screen::Nostr(mode) = &mut self.screen {
                            *mode = NostrMode::Signer;
                        }
                    }
                    Err(e) => {
                        if let Screen::Nostr(mode) = &mut self.screen {
                            *mode = NostrMode::Results {
                                title: "signer".into(),
                                lines: vec![format!("failed: {e}")],
                                copy: None,
                                scroll: 0,
                            };
                        }
                    }
                }
            }
            Pending::NostrDmsLoad { identity } => {
                let result = nostr_dms(session, &identity);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = NostrMode::Results {
                        title: "messages".into(),
                        lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        copy: None,
                        scroll: 0,
                    };
                }
            }
            Pending::NostrDmSend { identity, recipient_hex, text } => {
                let result = nostr_dm_send(session, &identity, &recipient_hex, &text);
                if let Screen::Nostr(mode) = &mut self.screen {
                    *mode = NostrMode::Results {
                        title: "send dm".into(),
                        lines: result.unwrap_or_else(|e| vec![format!("failed: {e}")]),
                        copy: None,
                        scroll: 0,
                    };
                }
            }
            Pending::VeilEncPass { input, output, pass } => {
                let r = veil_run_enc_pass(&input, &output, &pass);
                self.finish_veil(r);
            }
            Pending::VeilEncRecipient { input, pub_path, output } => {
                let r = veil_run_enc_recipient(&input, &pub_path, &output);
                self.finish_veil(r);
            }
            Pending::VeilDecPass { input, output, pass } => {
                let r = veil_run_dec_pass(&input, &output, &pass);
                self.finish_veil(r);
            }
            Pending::VeilDecIdentity { input, identity, output } => {
                let result = match session.store.get(&identity) {
                    Some(kp) => {
                        let sk = kp.x_secret();
                        veil_run_dec_identity(&input, &sk, &output)
                    }
                    None => Err(anyhow!("no identity named {identity:?}")),
                };
                self.finish_veil(result);
            }
        }
    }

    fn finish_veil(&mut self, result: Result<Vec<String>>) {
        if let Screen::Veil(mode) = &mut self.screen {
            match result {
                Ok(lines) => *mode = VeilMode::Results { title: "done".into(), lines },
                Err(e) => match mode {
                    VeilMode::Form(_, form) => form.error = Some(format!("{e}")),
                    _ => {
                        *mode = VeilMode::Results {
                            title: "failed".into(),
                            lines: vec![format!("{e}")],
                        }
                    }
                },
            }
        }
    }
}

// ---------------------------------------------------------------- operations

fn export_identity(session: &Session, selected: usize) -> Result<String> {
    let ids = session.identities();
    let id = ids.get(selected).ok_or_else(|| anyhow!("nothing selected"))?;
    let file = format!("{}.pub", id.name);
    std::fs::write(&file, format!("{}\n", id.to_line()))?;
    Ok(file)
}

fn nostr_init_selected(session: &mut Session, selected: usize) -> Result<String> {
    let ids = session.identities();
    let id = ids.get(selected).ok_or_else(|| anyhow!("nothing selected"))?;
    let name = id.name.clone();
    if session.store.nostr_init(&name)? {
        session.save()?;
        Ok(format!("added Nostr key to {name}"))
    } else {
        Ok(format!("{name} already has a Nostr key"))
    }
}

/// The npub of the identity at `selected`, for clipboard copy.
fn selected_npub(session: &Session, selected: usize) -> Result<String> {
    let ids = session.identities();
    let id = ids.get(selected).ok_or_else(|| anyhow!("nothing selected"))?;
    Ok(nostr_whoami(session, &id.name)?
        .into_iter()
        .next()
        .expect("whoami returns npub first"))
}

/// The npub (and hex) for an identity in the session store.
pub fn nostr_whoami(session: &Session, name: &str) -> Result<Vec<String>> {
    let sk = session.nostr_key(name)?;
    let pk_hex = bp_nostr::event::pubkey_hex(&sk)?;
    let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();
    Ok(vec![bp_nostr::nip19::npub_encode(&pk), pk_hex])
}

fn nostr_post(session: &Session, identity: &str, text: &str) -> Result<Vec<String>> {
    let sk = session.nostr_key(identity)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let ev = bp_nostr::event::sign_event(
        &sk,
        now,
        bp_nostr::event::KIND_TEXT_NOTE,
        vec![],
        text.to_string(),
    )?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let mut lines = vec![format!("event id {}", ev.id)];
    let mut accepted = 0;
    for (url, result) in bp_nostr::client::publish(&relays, &ev) {
        match result {
            Ok(_) => {
                accepted += 1;
                lines.push(format!("{url}: accepted"));
            }
            Err(e) => lines.push(format!("{url}: {e}")),
        }
    }
    if accepted == 0 {
        bail!("no relay accepted the note");
    }
    Ok(lines)
}

fn nostr_fetch(author: &str, limit: u32) -> Result<Vec<String>> {
    let author_hex = bp_nostr::nip19::pubkey_to_hex(author)?;
    let filter = bp_nostr::relay::Filter {
        authors: Some(vec![author_hex]),
        kinds: Some(vec![bp_nostr::event::KIND_TEXT_NOTE]),
        p_tags: None,
        since: None,
        limit: Some(limit),
    };
    let relays = bp_nostr::client::resolve_relays(&[]);
    let (url, events, dropped) =
        bp_nostr::client::fetch(&relays, &filter).map_err(|e| anyhow!(e))?;
    let mut lines = Vec::new();
    if events.is_empty() {
        lines.push(format!("(no notes found on {url})"));
    }
    for ev in &events {
        lines.push(format!("── {}… @ {}", &ev.pubkey[..12], ev.created_at));
        for l in ev.content.lines() {
            lines.push(format!("   {l}"));
        }
    }
    lines.push(format!(
        "({} notes from {url}, signatures verified{})",
        events.len(),
        if dropped > 0 {
            format!(", {dropped} bad dropped")
        } else {
            String::new()
        }
    ));
    Ok(lines)
}

fn nostr_timeline(session: &Session, identity: &str, limit: u32) -> Result<Vec<String>> {
    let sk = session.nostr_key(identity)?;
    let me = bp_nostr::event::pubkey_hex(&sk)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let contacts = bp_nostr::client::follows(&relays, &me).map_err(|e| anyhow!(e))?;
    if contacts.is_empty() {
        return Ok(vec![
            "not following anyone yet".to_string(),
            "add authors via FOLLOW".to_string(),
        ]);
    }
    let authors: Vec<String> = contacts.iter().map(|c| c.pubkey.clone()).collect();
    let events = bp_nostr::client::fetch_timeline(&relays, authors.clone(), limit)
        .map_err(|e| anyhow!(e))?;
    let profiles = bp_nostr::client::fetch_profiles(&relays, authors).unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut lines = Vec::new();
    for ev in &events {
        let who = contacts
            .iter()
            .find(|c| c.pubkey == ev.pubkey)
            .and_then(|c| c.petname.clone())
            .or_else(|| {
                profiles
                    .get(&ev.pubkey)
                    .and_then(|m| bp_nostr::profile::field(m, "name"))
            })
            .unwrap_or_else(|| format!("{}…", &ev.pubkey[..12.min(ev.pubkey.len())]));
        lines.push(format!("── {who} · {}", age_label(now, ev.created_at)));
        for l in ev.content.lines() {
            lines.push(format!("   {l}"));
        }
        lines.push(String::new());
    }
    lines.push(format!(
        "({} notes from {} follows, signatures verified — j/k to scroll)",
        events.len(),
        contacts.len()
    ));
    Ok(lines)
}

/// "3m" / "2h" / "5d" style relative age.
fn age_label(now: u64, then: u64) -> String {
    let secs = now.saturating_sub(then);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

fn nostr_follow(
    session: &Session,
    identity: &str,
    author: &str,
    name: Option<String>,
) -> Result<Vec<String>> {
    let sk = session.nostr_key(identity)?;
    let target = bp_nostr::nip19::pubkey_to_hex(author)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let count =
        bp_nostr::client::follow(&relays, &sk, &target, name).map_err(|e| anyhow!(e))?;
    Ok(vec![format!("now following {count} author(s)")])
}

fn nostr_unfollow(session: &Session, identity: &str, author_hex: &str) -> Result<()> {
    let sk = session.nostr_key(identity)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    bp_nostr::client::unfollow(&relays, &sk, author_hex).map_err(|e| anyhow!(e))?;
    Ok(())
}

fn start_signer(session: &Session, identity: &str) -> Result<SignerState> {
    let sk = session.nostr_key(identity)?;
    let signer_pk = bp_nostr::event::pubkey_hex(&sk)?;
    let relay = bp_nostr::client::resolve_relays(&[])
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no relay configured"))?;
    let secret = bp_nostr::nip46::random_secret();
    let url = bp_nostr::nip46::bunker_url(&signer_pk, &relay, &secret);

    let stop = Arc::new(AtomicBool::new(false));
    let log = Arc::new(Mutex::new(vec![format!("listening on {relay}")]));

    let sk_bytes: [u8; 32] = *sk;
    let relay_thread = relay.clone();
    let stop_thread = stop.clone();
    let log_thread = log.clone();
    let handle = std::thread::spawn(move || {
        let result = bp_nostr::client::run_signer(
            &relay_thread,
            &sk_bytes,
            &secret,
            &stop_thread,
            |l| {
                let mut g = log_thread.lock().unwrap();
                g.push(format!("{} · {} → {}", l.client, l.method, l.outcome));
                let len = g.len();
                if len > 200 {
                    g.drain(0..len - 200);
                }
            },
        );
        if let Err(e) = result {
            log_thread.lock().unwrap().push(format!("stopped: {e}"));
        }
    });

    Ok(SignerState {
        url,
        relay,
        identity: identity.to_string(),
        log,
        stop,
        handle: Some(handle),
    })
}

fn nostr_suggestions(session: &Session, identity: &str) -> Result<Vec<SuggestEntry>> {
    let sk = session.nostr_key(identity)?;
    let me = bp_nostr::event::pubkey_hex(&sk)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let my_follows: Vec<String> = bp_nostr::client::follows(&relays, &me)
        .map_err(|e| anyhow!(e))?
        .into_iter()
        .map(|c| c.pubkey)
        .collect();
    let suggestions =
        bp_nostr::client::suggest_follows(&relays, &my_follows, &me, 25).map_err(|e| anyhow!(e))?;
    Ok(suggestions
        .into_iter()
        .map(|s| {
            let pk: [u8; 32] = hex::decode(&s.pubkey).unwrap().try_into().unwrap();
            let npub = bp_nostr::nip19::npub_encode(&pk);
            SuggestEntry {
                label: s.name.unwrap_or_else(|| format!("{}…", &npub[..16])),
                about: s.about.unwrap_or_default(),
                npub,
                hex: s.pubkey,
                score: s.score,
            }
        })
        .collect())
}

fn nostr_dms(session: &Session, identity: &str) -> Result<Vec<String>> {
    let sk = session.nostr_key(identity)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let dms = bp_nostr::client::fetch_dms(&relays, &sk, 40).map_err(|e| anyhow!(e))?;
    if dms.is_empty() {
        return Ok(vec!["(no direct messages found)".to_string()]);
    }
    let partners: Vec<String> = dms.iter().map(|d| d.partner.clone()).collect();
    let profiles = bp_nostr::client::fetch_profiles(&relays, partners).unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut lines = Vec::new();
    for dm in &dms {
        let who = profiles
            .get(&dm.partner)
            .and_then(|m| bp_nostr::profile::field(m, "name"))
            .unwrap_or_else(|| format!("{}…", &dm.partner[..12.min(dm.partner.len())]));
        let arrow = if dm.outgoing { "→ to" } else { "← from" };
        lines.push(format!("{arrow} {who} · {}", age_label(now, dm.created_at)));
        for l in dm.text.lines() {
            lines.push(format!("   {l}"));
        }
        lines.push(String::new());
    }
    lines.push(format!("({} messages, decrypted locally — j/k to scroll)", dms.len()));
    Ok(lines)
}

fn nostr_dm_send(
    session: &Session,
    identity: &str,
    recipient_hex: &str,
    text: &str,
) -> Result<Vec<String>> {
    let sk = session.nostr_key(identity)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let results =
        bp_nostr::client::send_dm(&relays, &sk, recipient_hex, text).map_err(|e| anyhow!(e))?;
    let accepted = results.iter().filter(|(_, r)| r.is_ok()).count();
    Ok(vec![
        format!("sent to {accepted}/{} relay(s)", results.len()),
        "encrypted (NIP-04) — text is private, metadata is not".to_string(),
    ])
}

/// Fetch the identity's current kind-0 and build a prefilled edit form.
fn nostr_profile_form(session: &Session, identity: &str) -> Result<Form> {
    let sk = session.nostr_key(identity)?;
    let me = bp_nostr::event::pubkey_hex(&sk)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let map = bp_nostr::client::latest_profile(&relays, &me).map_err(|e| anyhow!(e))?;
    let get = |k: &str| bp_nostr::profile::field(&map, k).unwrap_or_default();
    Ok(Form::new(
        "edit profile (empty clears a field)",
        vec![
            Field::new("name").with_value(get("name")),
            Field::new("about").with_value(get("about")),
            Field::new("picture (url)").with_value(get("picture")),
            Field::new("nip05").with_value(get("nip05")),
        ],
    ))
}

fn nostr_profile_save(
    session: &Session,
    identity: &str,
    updates: &[(String, String)],
) -> Result<Vec<String>> {
    let sk = session.nostr_key(identity)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let borrowed: Vec<(&str, String)> = updates
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    bp_nostr::client::set_profile(&relays, &sk, &borrowed).map_err(|e| anyhow!(e))?;
    Ok(vec![
        "profile published".to_string(),
        "fields set by other clients were preserved".to_string(),
    ])
}

fn nostr_follow_entries(session: &Session, identity: &str) -> Result<Vec<FollowEntry>> {
    let sk = session.nostr_key(identity)?;
    let me = bp_nostr::event::pubkey_hex(&sk)?;
    let relays = bp_nostr::client::resolve_relays(&[]);
    let contacts = bp_nostr::client::follows(&relays, &me).map_err(|e| anyhow!(e))?;
    Ok(contacts
        .into_iter()
        .map(|c| {
            let pk: [u8; 32] = hex::decode(&c.pubkey).unwrap().try_into().unwrap();
            let npub = bp_nostr::nip19::npub_encode(&pk);
            FollowEntry {
                label: c.petname.unwrap_or_else(|| format!("{}…", &npub[..16])),
                npub,
                hex: c.pubkey,
            }
        })
        .collect())
}

fn veil_form(op: usize, first_identity: &str) -> Form {
    match op {
        0 => Form::new(
            "encrypt with passphrase",
            vec![
                Field::new("input file"),
                Field::new("output").with_placeholder("<input>.veil"),
                Field::masked("passphrase"),
                Field::masked("confirm passphrase"),
            ],
        ),
        1 => Form::new(
            "encrypt to recipient",
            vec![
                Field::new("input file"),
                Field::new("recipient .pub file"),
                Field::new("output").with_placeholder("<input>.veil"),
            ],
        ),
        2 => Form::new(
            "decrypt with passphrase",
            vec![
                Field::new("input file (.veil)"),
                Field::new("output").with_placeholder("strip .veil"),
                Field::masked("passphrase"),
            ],
        ),
        _ => Form::new(
            "decrypt with identity",
            vec![
                Field::new("input file (.veil)"),
                Field::new("identity").with_value(first_identity),
                Field::new("output").with_placeholder("strip .veil"),
            ],
        ),
    }
}

fn veil_pending(op: usize, form: &Form) -> Result<Pending> {
    let input = form.value(0).to_string();
    if input.is_empty() {
        bail!("input file is required");
    }
    match op {
        0 => {
            let pass = form.value(2).to_string();
            if pass.is_empty() {
                bail!("passphrase must not be empty");
            }
            if form.value(3) != pass {
                bail!("passphrases do not match");
            }
            Ok(Pending::VeilEncPass { input, output: form.value(1).to_string(), pass })
        }
        1 => {
            let pub_path = form.value(1).to_string();
            if pub_path.is_empty() {
                bail!("recipient .pub file is required");
            }
            Ok(Pending::VeilEncRecipient {
                input,
                pub_path,
                output: form.value(2).to_string(),
            })
        }
        2 => {
            let pass = form.value(2).to_string();
            if pass.is_empty() {
                bail!("passphrase must not be empty");
            }
            Ok(Pending::VeilDecPass { input, output: form.value(1).to_string(), pass })
        }
        _ => {
            let identity = form.value(1).to_string();
            if identity.is_empty() {
                bail!("identity is required");
            }
            Ok(Pending::VeilDecIdentity {
                input,
                identity,
                output: form.value(2).to_string(),
            })
        }
    }
}

fn enc_out(input: &Path, output: &str) -> PathBuf {
    if output.is_empty() {
        veil::enc_output_for(input)
    } else {
        PathBuf::from(output)
    }
}

fn dec_out(input: &Path, output: &str) -> Result<PathBuf> {
    if output.is_empty() {
        veil::dec_output_for(input)
    } else {
        Ok(PathBuf::from(output))
    }
}

fn veil_run_enc_pass(input: &str, output: &str, pass: &str) -> Result<Vec<String>> {
    let input = Path::new(input);
    let out = enc_out(input, output);
    veil::encrypt_path(input, &out, &veil::EncKey::Passphrase(pass.as_bytes()))?;
    Ok(vec![format!("encrypted -> {}", out.display())])
}

fn veil_run_enc_recipient(input: &str, pub_path: &str, output: &str) -> Result<Vec<String>> {
    let txt = std::fs::read_to_string(pub_path)?;
    let recipient = keyring::PublicIdentity::parse(&txt)?;
    let input = Path::new(input);
    let out = enc_out(input, output);
    veil::encrypt_path(input, &out, &veil::EncKey::Recipient(recipient.x))?;
    Ok(vec![format!(
        "encrypted for {} -> {}",
        recipient.name,
        out.display()
    )])
}

fn veil_run_dec_pass(input: &str, output: &str, pass: &str) -> Result<Vec<String>> {
    let input = Path::new(input);
    let out = dec_out(input, output)?;
    veil::decrypt_path(input, &out, &veil::DecKey::Passphrase(pass.as_bytes()))?;
    Ok(vec![format!("decrypted -> {}", out.display())])
}

fn veil_run_dec_identity(input: &str, sk: &[u8; 32], output: &str) -> Result<Vec<String>> {
    let input = Path::new(input);
    let out = dec_out(input, output)?;
    veil::decrypt_path(input, &out, &veil::DecKey::IdentitySecret(sk))?;
    Ok(vec![format!("decrypted -> {}", out.display())])
}

fn scrub_scan(path: &str) -> Result<(Vec<String>, bool)> {
    let bytes = std::fs::read(path)?;
    let (_, report) = scrub::strip(&bytes)?;
    let mut lines = vec![format!("[{}]", report.format)];
    if report.changed() {
        for item in &report.removed {
            lines.push(format!("- {item}"));
        }
        lines.push(String::new());
        lines.push("Enter = write cleaned copy · Esc = cancel".to_string());
    } else {
        lines.push("already clean".to_string());
    }
    let changed = report.changed();
    Ok((lines, changed))
}

fn scrub_apply(path: &str) -> Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    let (out, report) = scrub::strip(&bytes)?;
    let p = Path::new(path);
    let mut name = p
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "out".into());
    name.push(".clean");
    if let Some(ext) = p.extension() {
        name.push(".");
        name.push(ext);
    }
    let dest = p.with_file_name(name);
    std::fs::write(&dest, &out)?;
    Ok(vec![
        format!("removed {} item(s)", report.removed.len()),
        format!("wrote {}", dest.display()),
        "original kept unchanged".to_string(),
    ])
}

fn split_deal(form: &Form) -> Result<Vec<String>> {
    let secret = std::fs::read(form.value(0))
        .map_err(|e| anyhow!("reading secret file {}: {e}", form.value(0)))?;
    let k: u8 = form
        .value(1)
        .parse()
        .map_err(|_| anyhow!("k must be a number"))?;
    let n: u8 = form
        .value(2)
        .parse()
        .map_err(|_| anyhow!("n must be a number"))?;
    let dir = PathBuf::from(form.value(3));
    let shares = split::deal(&secret, k, n)?;
    std::fs::create_dir_all(&dir)?;
    let mut lines = Vec::new();
    for (i, s) in shares.iter().enumerate() {
        let path = dir.join(format!("share-{}.txt", i + 1));
        std::fs::write(&path, format!("{s}\n"))?;
        lines.push(format!("wrote {}", path.display()));
    }
    lines.push(format!(
        "any {k} of {n} recover the secret — store them separately"
    ));
    Ok(lines)
}

fn split_combine(form: &Form) -> Result<Vec<String>> {
    let mut share_lines = Vec::new();
    for path in form.value(0).split_whitespace() {
        let text =
            std::fs::read_to_string(path).map_err(|e| anyhow!("reading {path}: {e}"))?;
        share_lines.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| l.starts_with(split::TAG_PREFIX))
                .map(str::to_string),
        );
    }
    if share_lines.is_empty() {
        bail!("no share lines found in those files");
    }
    let secret = split::combine(&share_lines)?;
    let dest = form.value(1);
    if dest.is_empty() {
        Ok(vec![
            "recovered secret:".to_string(),
            String::from_utf8_lossy(&secret).to_string(),
        ])
    } else {
        std::fs::write(dest, &secret)?;
        Ok(vec![format!("recovered secret written to {dest}")])
    }
}

fn sign_file(session: &Session, form: &Form) -> Result<Vec<String>> {
    let identity = form.value(0);
    let msg_path = form.value(1);
    let kp = session
        .store
        .get(identity)
        .ok_or_else(|| anyhow!("no identity named {identity:?}"))?;
    let msg = std::fs::read(msg_path).map_err(|e| anyhow!("reading {msg_path}: {e}"))?;
    let sig = kp.sign(&msg);
    let sig_path = format!("{msg_path}.sig");
    std::fs::write(&sig_path, format!("{}\n", keyring::format_signature(&sig)))?;
    Ok(vec![format!("wrote {sig_path}")])
}

fn verify_file(form: &Form) -> Result<Vec<String>> {
    let pub_txt = std::fs::read_to_string(form.value(0))
        .map_err(|e| anyhow!("reading {}: {e}", form.value(0)))?;
    let id = keyring::PublicIdentity::parse(&pub_txt)?;
    let msg =
        std::fs::read(form.value(1)).map_err(|e| anyhow!("reading {}: {e}", form.value(1)))?;
    let sig_txt = std::fs::read_to_string(form.value(2))
        .map_err(|e| anyhow!("reading {}: {e}", form.value(2)))?;
    let sig = keyring::parse_signature(&sig_txt)?;
    if id.verify(&msg, &sig) {
        Ok(vec![format!(
            "OK: valid signature by {} [{}]",
            id.name,
            id.fingerprint()
        )])
    } else {
        Ok(vec!["BAD: signature does not verify".to_string()])
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Tests mutate the process-wide BACKPACK_KEYRING env var — serialize them.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn fresh_store_env() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "launcher-app-{}-{n}.veil",
            std::process::id()
        ));
        std::env::set_var("BACKPACK_KEYRING", &p);
        p
    }

    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            app.on_key(KeyCode::Char(c));
        }
    }

    fn unlocked_app() -> App {
        let mut app = App::new();
        type_str(&mut app, "pw");
        app.on_key(KeyCode::Enter);
        if matches!(app.gate, Gate::Locked { .. }) {
            // creating: confirm field
            type_str(&mut app, "pw");
            app.on_key(KeyCode::Enter);
        }
        assert!(matches!(app.gate, Gate::Open(_)), "gate should open");
        app
    }

    #[test]
    fn unlock_flow_creates_and_reopens() {
        let _guard = env_lock();
        let path = fresh_store_env();
        {
            let mut app = unlocked_app();
            app.on_key(KeyCode::Enter); // IDENTITIES
            app.on_key(KeyCode::Char('g'));
            type_str(&mut app, "alice");
            app.on_key(KeyCode::Enter);
        }
        assert!(path.exists());

        let mut app = App::new();
        type_str(&mut app, "wrong");
        app.on_key(KeyCode::Enter);
        match &app.gate {
            Gate::Locked { form, .. } => assert!(form.error.is_some()),
            _ => panic!("wrong passphrase must not open the gate"),
        }
        if let Gate::Locked { form, .. } = &mut app.gate {
            form.fields[0].value.clear();
        }
        type_str(&mut app, "pw");
        app.on_key(KeyCode::Enter);
        assert!(matches!(app.gate, Gate::Open(_)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mismatched_create_passphrases_rejected() {
        let _guard = env_lock();
        let path = fresh_store_env();
        let mut app = App::new();
        type_str(&mut app, "one");
        app.on_key(KeyCode::Enter);
        type_str(&mut app, "two");
        app.on_key(KeyCode::Enter);
        match &app.gate {
            Gate::Locked { form, .. } => assert!(form.error.is_some()),
            _ => panic!("mismatch must not open"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn identities_generate_and_npub_whoami() {
        let _guard = env_lock();
        let path = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "carol");
        app.on_key(KeyCode::Enter);

        let session = app.session().unwrap();
        assert_eq!(session.identities().len(), 1);
        let lines = nostr_whoami(session, "carol").unwrap();
        assert!(lines[0].starts_with("npub1"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn nostr_post_requires_confirmation() {
        let _guard = env_lock();
        let path = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "dave");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Esc); // home

        app.on_key(KeyCode::Char('2')); // NOSTR entry
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Char('j')); // POST
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Enter); // identity prefilled -> text
        type_str(&mut app, "hello");
        app.on_key(KeyCode::Enter); // submit -> confirm
        assert!(matches!(
            &app.screen,
            Screen::Nostr(NostrMode::ConfirmPost { .. })
        ));
        assert!(app.pending.is_none(), "must not publish before y");
        app.on_key(KeyCode::Char('n'));
        assert!(app.pending.is_none());
        assert!(matches!(&app.screen, Screen::Nostr(NostrMode::Menu(_))));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn veil_roundtrip_via_screens() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("veil-scr-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("msg.txt");
        std::fs::write(&input, b"deck data").unwrap();

        let mut app = unlocked_app();
        app.on_key(KeyCode::Char('3')); // VEIL entry
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Enter); // enc-pass form
        type_str(&mut app, &input.display().to_string());
        app.on_key(KeyCode::Enter); // output default
        app.on_key(KeyCode::Enter); // -> passphrase
        type_str(&mut app, "sk");
        app.on_key(KeyCode::Enter);
        type_str(&mut app, "sk");
        app.on_key(KeyCode::Enter); // submit
        let op = app.pending.take().expect("encrypt queued");
        app.execute(op);
        assert!(matches!(&app.screen, Screen::Veil(VeilMode::Results { .. })));
        let enc = dir.join("msg.txt.veil");
        assert!(enc.exists());

        app.on_key(KeyCode::Enter); // results -> menu
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Char('j')); // dec-pass
        app.on_key(KeyCode::Enter);
        type_str(&mut app, &enc.display().to_string());
        app.on_key(KeyCode::Enter);
        type_str(&mut app, &dir.join("msg.out").display().to_string());
        app.on_key(KeyCode::Enter);
        type_str(&mut app, "sk");
        app.on_key(KeyCode::Enter);
        let op = app.pending.take().expect("decrypt queued");
        app.execute(op);
        assert_eq!(std::fs::read(dir.join("msg.out")).unwrap(), b"deck data");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn split_deal_and_combine_via_screens() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("split-scr-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("seed.txt");
        std::fs::write(&secret, b"correct horse").unwrap();
        let out = dir.join("shares");

        let mut app = unlocked_app();
        app.on_key(KeyCode::Char('5')); // SPLIT entry
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Enter); // DEAL form
        type_str(&mut app, &secret.display().to_string());
        app.on_key(KeyCode::Enter); // -> k (3)
        app.on_key(KeyCode::Enter); // -> n (5)
        app.on_key(KeyCode::Enter); // -> output dir
        if let Screen::Split(SplitMode::Deal(form)) = &mut app.screen {
            form.fields[3].value = out.display().to_string();
        }
        app.on_key(KeyCode::Enter); // submit
        assert!(matches!(
            &app.screen,
            Screen::Split(SplitMode::Results { .. })
        ));
        assert!(out.join("share-1.txt").exists());

        app.on_key(KeyCode::Enter); // -> menu
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Enter); // COMBINE
        let files = format!(
            "{} {} {}",
            out.join("share-1.txt").display(),
            out.join("share-3.txt").display(),
            out.join("share-5.txt").display()
        );
        type_str(&mut app, &files);
        app.on_key(KeyCode::Enter); // optional output
        app.on_key(KeyCode::Enter); // submit
        match &app.screen {
            Screen::Split(SplitMode::Results { lines, .. }) => {
                assert!(lines.iter().any(|l| l.contains("correct horse")));
            }
            _ => panic!("expected results"),
        }
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn sign_and_verify_via_screens() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sign-scr-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let msg = dir.join("m.txt");
        std::fs::write(&msg, b"payload").unwrap();

        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "erin");
        app.on_key(KeyCode::Enter);
        let pub_line = app.session().unwrap().identities()[0].to_line();
        let pub_path = dir.join("erin.pub");
        std::fs::write(&pub_path, format!("{pub_line}\n")).unwrap();
        app.on_key(KeyCode::Esc);

        app.on_key(KeyCode::Char('6')); // SIGN/VERIFY entry
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Enter); // SIGN form
        app.on_key(KeyCode::Enter); // identity prefilled -> message file
        type_str(&mut app, &msg.display().to_string());
        app.on_key(KeyCode::Enter);
        assert!(matches!(&app.screen, Screen::Sign(SignMode::Results { .. })));
        let sig = dir.join("m.txt.sig");
        assert!(sig.exists());

        app.on_key(KeyCode::Enter); // -> menu
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Enter); // VERIFY
        type_str(&mut app, &pub_path.display().to_string());
        app.on_key(KeyCode::Enter);
        type_str(&mut app, &msg.display().to_string());
        app.on_key(KeyCode::Enter);
        type_str(&mut app, &sig.display().to_string());
        app.on_key(KeyCode::Enter);
        match &app.screen {
            Screen::Sign(SignMode::Results { lines, .. }) => {
                assert!(lines[0].starts_with("OK:"), "{lines:?}");
            }
            _ => panic!("expected results"),
        }
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn copy_stages_npub_for_clipboard() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "frank");
        app.on_key(KeyCode::Enter);

        // c on the identity list stages the npub.
        app.on_key(KeyCode::Char('c'));
        let staged = app.clipboard.take().expect("clipboard staged");
        assert!(staged.starts_with("npub1"));
        assert!(!staged.contains(' '), "payload must be the bare npub");
        app.on_key(KeyCode::Esc);

        // c on the WHOAMI results stages the same npub.
        app.on_key(KeyCode::Char('2'));
        app.on_key(KeyCode::Enter); // NOSTR menu
        app.on_key(KeyCode::Up); // wrap to last entry (SIGNER)
        app.on_key(KeyCode::Up); // -> WHOAMI
        app.on_key(KeyCode::Enter); // WHOAMI form (identity prefilled)
        app.on_key(KeyCode::Enter); // submit
        assert!(matches!(&app.screen, Screen::Nostr(NostrMode::Results { .. })));
        app.on_key(KeyCode::Char('c'));
        assert_eq!(app.clipboard.take().as_deref(), Some(staged.as_str()));
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn timeline_and_follow_queue_pendings() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "grace");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Esc);

        app.on_key(KeyCode::Char('2'));
        app.on_key(KeyCode::Enter); // NOSTR menu, TIMELINE selected
        app.on_key(KeyCode::Enter); // timeline form
        app.on_key(KeyCode::Enter); // identity prefilled -> limit
        app.on_key(KeyCode::Enter); // submit
        assert!(matches!(
            app.pending.take(),
            Some(Pending::NostrTimeline { limit: 30, .. })
        ));

        // FOLLOW form validates author presence.
        if let Screen::Nostr(mode) = &mut app.screen {
            *mode = NostrMode::Menu(3);
        }
        app.on_key(KeyCode::Enter); // follow form
        app.on_key(KeyCode::Enter); // identity -> author (empty)
        app.on_key(KeyCode::Enter); // -> petname
        app.on_key(KeyCode::Enter); // submit with empty author
        match &app.screen {
            Screen::Nostr(NostrMode::Follow(form)) => assert!(form.error.is_some()),
            _ => panic!("expected follow form error"),
        }
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn follows_list_unfollow_needs_confirm_and_results_scroll() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.screen = Screen::Nostr(NostrMode::Follows {
            identity: "grace".into(),
            entries: vec![FollowEntry {
                label: "fj".into(),
                npub: "npub1abc".into(),
                hex: "ff".repeat(32),
            }],
            selected: 0,
            confirm_unfollow: false,
        });
        app.on_key(KeyCode::Char('d')); // ask
        app.on_key(KeyCode::Char('n')); // decline
        assert!(app.pending.is_none());
        app.on_key(KeyCode::Char('d'));
        app.on_key(KeyCode::Char('y')); // confirm
        assert!(matches!(
            app.pending.take(),
            Some(Pending::NostrUnfollow { .. })
        ));

        // Results scroll offset moves with j/k and clamps at zero.
        app.screen = Screen::Nostr(NostrMode::Results {
            title: "timeline".into(),
            lines: (0..50).map(|i| format!("line {i}")).collect(),
            copy: None,
            scroll: 0,
        });
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::PageDown);
        match &app.screen {
            Screen::Nostr(NostrMode::Results { scroll, .. }) => assert_eq!(*scroll, 12),
            _ => panic!("expected results"),
        }
        app.on_key(KeyCode::PageUp);
        app.on_key(KeyCode::Char('k'));
        app.on_key(KeyCode::Char('k'));
        app.on_key(KeyCode::Char('k'));
        match &app.screen {
            Screen::Nostr(NostrMode::Results { scroll, .. }) => assert_eq!(*scroll, 0),
            _ => panic!("expected results"),
        }
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn profile_flow_queues_load_then_save() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "hana");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Esc);

        // PROFILE -> identity form -> queues a load.
        if let Gate::Open(_) = app.gate {
            app.screen = Screen::Nostr(NostrMode::Menu(8));
        }
        app.on_key(KeyCode::Enter); // ProfileWho form
        app.on_key(KeyCode::Enter); // identity prefilled -> submit
        assert!(matches!(
            app.pending.take(),
            Some(Pending::NostrProfileLoad { .. })
        ));

        // Edit form (constructed directly; load is a network op) -> save
        // carries all four fields, including cleared ones.
        app.screen = Screen::Nostr(NostrMode::ProfileEdit {
            identity: "hana".into(),
            form: Form::new(
                "edit profile (empty clears a field)",
                vec![
                    Field::new("name").with_value("old-name"),
                    Field::new("about"),
                    Field::new("picture (url)"),
                    Field::new("nip05"),
                ],
            ),
        });
        type_str(&mut app, "!"); // append to prefilled name
        app.on_key(KeyCode::Enter); // -> about
        type_str(&mut app, "deck operator");
        app.on_key(KeyCode::Enter); // -> picture
        app.on_key(KeyCode::Enter); // -> nip05
        app.on_key(KeyCode::Enter); // submit
        match app.pending.take() {
            Some(Pending::NostrProfileSave { updates, .. }) => {
                assert_eq!(updates.len(), 4);
                assert_eq!(updates[0], ("name".to_string(), "old-name!".to_string()));
                assert_eq!(updates[1].1, "deck operator");
                assert_eq!(updates[2].1, ""); // empty -> clears on merge
            }
            other => panic!("expected save, got {:?}", other.is_some()),
        }
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn send_dm_requires_confirmation() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "ivy");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Esc);

        // SEND DM at menu index 6.
        if let Gate::Open(_) = app.gate {
            app.screen = Screen::Nostr(NostrMode::Menu(7));
        }
        app.on_key(KeyCode::Enter); // SendDm form
        app.on_key(KeyCode::Enter); // identity prefilled -> to
        let npub = {
            let s = app.session().unwrap();
            nostr_whoami(s, "ivy").unwrap()[0].clone()
        };
        type_str(&mut app, &npub);
        app.on_key(KeyCode::Enter); // -> message
        type_str(&mut app, "hi self");
        app.on_key(KeyCode::Enter); // submit -> confirm
        assert!(matches!(&app.screen, Screen::Nostr(NostrMode::ConfirmDm { .. })));
        assert!(app.pending.is_none());
        app.on_key(KeyCode::Char('n')); // decline
        assert!(app.pending.is_none());
        assert!(matches!(&app.screen, Screen::Nostr(NostrMode::Menu(_))));
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn send_dm_rejects_empty_recipient() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "jack");
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Esc);
        if let Gate::Open(_) = app.gate {
            app.screen = Screen::Nostr(NostrMode::Menu(7));
        }
        app.on_key(KeyCode::Enter);
        app.on_key(KeyCode::Enter); // identity -> to (empty)
        app.on_key(KeyCode::Enter); // -> message (empty)
        app.on_key(KeyCode::Enter); // submit
        match &app.screen {
            Screen::Nostr(NostrMode::SendDm(form)) => assert!(form.error.is_some()),
            _ => panic!("expected send-dm form error"),
        }
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn explore_follow_and_copy_queue_actions() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        // Directly construct an Explore screen (suggestions are a network op).
        let entry = SuggestEntry {
            label: "fiatjaf".into(),
            about: "nostr".into(),
            npub: "npub1fiatjaf".into(),
            hex: "ab".repeat(32),
            score: 5,
        };
        app.screen = Screen::Nostr(NostrMode::Explore {
            identity: "kim".into(),
            entries: vec![entry.clone(), entry],
            selected: 0,
            status: String::new(),
        });
        app.on_key(KeyCode::Char('j'));
        if let Screen::Nostr(NostrMode::Explore { selected, .. }) = &app.screen {
            assert_eq!(*selected, 1);
        } else {
            panic!("expected explore");
        }
        app.on_key(KeyCode::Char('c'));
        assert_eq!(app.clipboard.take().as_deref(), Some("npub1fiatjaf"));
        app.on_key(KeyCode::Char('f'));
        assert!(matches!(
            app.pending.take(),
            Some(Pending::NostrExploreFollow { .. })
        ));
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn reveal_nsec_needs_confirm_and_stages_copy() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Enter); // IDENTITIES
        app.on_key(KeyCode::Char('g'));
        type_str(&mut app, "leo");
        app.on_key(KeyCode::Enter);

        app.on_key(KeyCode::Char('x')); // ask
        assert!(matches!(
            &app.screen,
            Screen::Identities(IdentitiesState { mode: IdMode::RevealConfirm, .. })
        ));
        app.on_key(KeyCode::Char('n')); // decline -> no reveal
        assert!(matches!(
            &app.screen,
            Screen::Identities(IdentitiesState { mode: IdMode::List, .. })
        ));

        app.on_key(KeyCode::Char('x'));
        app.on_key(KeyCode::Char('y')); // confirm -> reveal
        match &app.screen {
            Screen::Identities(IdentitiesState { mode: IdMode::Reveal { nsec }, .. }) => {
                assert!(nsec.starts_with("nsec1"));
            }
            _ => panic!("expected reveal"),
        }
        app.on_key(KeyCode::Char('c')); // copy the nsec
        assert!(app.clipboard.take().is_some_and(|c| c.starts_with("nsec1")));
        app.on_key(KeyCode::Esc); // hide
        assert!(matches!(
            &app.screen,
            Screen::Identities(IdentitiesState { mode: IdMode::List, .. })
        ));
        std::fs::remove_file(&store).ok();
    }

    #[test]
    fn home_navigation_shell_and_quit() {
        let _guard = env_lock();
        let store = fresh_store_env();
        let mut app = unlocked_app();
        app.on_key(KeyCode::Char('4'));
        assert!(matches!(app.screen, Screen::Home { selected: 3 }));
        app.on_key(KeyCode::Char('!'));
        assert!(app.shell_requested);
        app.on_key(KeyCode::Char('q'));
        assert!(app.should_quit);
        std::fs::remove_file(&store).ok();
    }
}
