//! Rendering for the launcher client. Amber-phosphor monochrome, like a P3
//! CRT. All screens share the banner, the form renderer, and the keybar.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    App, Gate, IdMode, NostrMode, Screen, ScrubMode, SignMode, SplitMode, VeilMode, MENU,
    NOSTR_MENU, SIGN_MENU, SPLIT_MENU, VEIL_MENU,
};
use crate::form::Form;
use crate::session::Session;
use crate::theme::*;

/// ANSI-Shadow "BACKPACK", 64 columns — fits an 80-column deck screen.
const BANNER: [&str; 6] = [
    "██████╗  █████╗  ██████╗██╗  ██╗██████╗  █████╗  ██████╗██╗  ██╗",
    "██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝",
    "██████╔╝███████║██║     █████╔╝ ██████╔╝███████║██║     █████╔╝ ",
    "██╔══██╗██╔══██║██║     ██╔═██╗ ██╔═══╝ ██╔══██║██║     ██╔═██╗ ",
    "██████╔╝██║  ██║╚██████╗██║  ██╗██║     ██║  ██║╚██████╗██║  ██╗",
    "╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝",
];

pub fn render(f: &mut Frame, app: &App) {
    let banner_h = if f.area().width >= 80 && f.area().height >= 22 { 8 } else { 2 };
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_banner(f, root[0]);

    match &app.gate {
        Gate::Locked { form, .. } => {
            render_gate(f, root[1], form);
            render_keybar(f, root[2], &[("enter", "unlock"), ("esc", "quit")]);
        }
        Gate::Open(session) => match &app.screen {
            Screen::Home { selected } => {
                render_home(f, root[1], *selected, session);
                render_keybar(
                    f,
                    root[2],
                    &[
                        ("↑↓/jk", "select"),
                        ("1-6", "jump"),
                        ("enter", "open"),
                        ("!", "shell"),
                        ("q", "quit"),
                    ],
                );
            }
            Screen::Identities(st) => {
                render_identities(f, root[1], st, session);
                render_keybar(
                    f,
                    root[2],
                    &[
                        ("g", "generate"),
                        ("e", "export"),
                        ("n", "nostr key"),
                        ("d", "delete"),
                        ("esc", "back"),
                    ],
                );
            }
            Screen::Nostr(mode) => {
                render_nostr(f, root[1], mode);
                render_keybar(f, root[2], mode_keys_nostr(mode));
            }
            Screen::Veil(mode) => {
                render_veil(f, root[1], mode);
                render_keybar(f, root[2], generic_keys(matches!(mode, VeilMode::Menu(_))));
            }
            Screen::Scrub(mode) => {
                render_scrub(f, root[1], mode);
                render_keybar(f, root[2], &[("enter", "continue"), ("esc", "back")]);
            }
            Screen::Split(mode) => {
                render_split(f, root[1], mode);
                render_keybar(f, root[2], generic_keys(matches!(mode, SplitMode::Menu(_))));
            }
            Screen::Sign(mode) => {
                render_sign(f, root[1], mode);
                render_keybar(f, root[2], generic_keys(matches!(mode, SignMode::Menu(_))));
            }
        },
    }
}

/// A full-frame "WORKING" overlay drawn before executing a pending op.
pub fn render_working(f: &mut Frame, label: &str) {
    let area = centered(40, 3, f.area());
    f.render_widget(Clear, area);
    let p = Paragraph::new(Line::from(Span::styled(
        format!("▚▚ {label} …"),
        bold(alert()),
    )))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).border_style(phosphor()));
    f.render_widget(p, area);
}

fn generic_keys(is_menu: bool) -> &'static [(&'static str, &'static str)] {
    if is_menu {
        &[("↑↓/jk", "select"), ("enter", "open"), ("esc", "back")]
    } else {
        &[("tab", "next field"), ("enter", "go"), ("esc", "back")]
    }
}

fn mode_keys_nostr(mode: &NostrMode) -> &'static [(&'static str, &'static str)] {
    match mode {
        NostrMode::Menu(_) => &[("↑↓/jk", "select"), ("enter", "open"), ("esc", "back")],
        NostrMode::ConfirmPost { .. } => &[("y", "publish"), ("n", "cancel")],
        NostrMode::Results { .. } => &[("enter/esc", "back")],
        _ => &[("tab", "next field"), ("enter", "go"), ("esc", "back")],
    }
}

// ------------------------------------------------------------------ pieces

fn render_banner(f: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if area.height >= 8 {
        for row in BANNER {
            lines.push(Line::from(Span::styled(row, bold(phosphor()))));
        }
        lines.push(Line::from(Span::styled(
            "─── privacy · sovereignty · crypto ───",
            dim(),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::styled("░▒▓ ", dim()),
            Span::styled("B A C K P A C K", bold(phosphor())),
            Span::styled(" ▓▒░", dim()),
        ]));
    }
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}

fn render_gate(f: &mut Frame, area: Rect, form: &Form) {
    let w = 54.min(area.width.saturating_sub(2));
    let h = (form.fields.len() as u16) * 2 + 3 + form.error.is_some() as u16;
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    render_form(f, rect, form);
}

fn render_home(f: &mut Frame, area: Rect, selected: usize, session: &Session) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(34), Constraint::Min(30)])
        .split(area);

    let items: Vec<ListItem> = MENU
        .iter()
        .enumerate()
        .map(|(i, e)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", i + 1), dim()),
                Span::styled(format!("{:<12}", e.name), bold(accent())),
                Span::styled(e.tagline, dim()),
            ]))
        })
        .collect();
    let list = List::default()
        .items(items)
        .block(titled_block(" ▞▞ BACKPACK "))
        .highlight_style(selected_style())
        .highlight_symbol("▶");
    let mut state = ListState::default();
    state.select(Some(selected));
    f.render_stateful_widget(list, cols[0], &mut state);

    let entry = &MENU[selected];
    let mut lines: Vec<Line> = entry
        .about
        .iter()
        .map(|l| Line::from(Span::styled(*l, phosphor())))
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("identities ", dim()),
        Span::styled(session.identities().len().to_string(), accent()),
        Span::styled("   keystore ", dim()),
        Span::styled(session.path.display().to_string(), accent()),
    ]));
    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(titled_block(&format!(" ▞▞ {} ", entry.name)));
    f.render_widget(p, cols[1]);
}

fn render_identities(
    f: &mut Frame,
    area: Rect,
    st: &crate::app::IdentitiesState,
    session: &Session,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(34), Constraint::Min(30)])
        .split(area);

    let ids = session.identities();
    let items: Vec<ListItem> = ids
        .iter()
        .map(|id| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<14}", truncate(&id.name, 14)), bold(accent())),
                Span::styled(id.fingerprint(), dim()),
            ]))
        })
        .collect();
    let block = titled_block(&format!(" ▞▞ IDENTITIES ({}) ", ids.len()));
    if items.is_empty() {
        f.render_widget(
            Paragraph::new("no identities\n\npress g to generate one")
                .alignment(Alignment::Center)
                .style(dim())
                .block(block),
            cols[0],
        );
    } else {
        let list = List::default()
            .items(items)
            .block(block)
            .highlight_style(selected_style())
            .highlight_symbol("▶");
        let mut state = ListState::default();
        state.select(Some(st.selected.min(ids.len().saturating_sub(1))));
        f.render_stateful_widget(list, cols[0], &mut state);
    }

    let mut lines: Vec<Line> = Vec::new();
    if let Some(id) = ids.get(st.selected) {
        lines.push(kv("name        ", &id.name));
        lines.push(kv("fingerprint ", &id.fingerprint()));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("public line (share this):", dim())));
        lines.push(Line::from(Span::styled(id.to_line(), phosphor())));
        lines.push(Line::from(""));
        match session.store.get(&id.name).and_then(|k| k.nostr_secret()) {
            Some(sk) => {
                if let Ok(pk_hex) = bp_nostr::event::pubkey_hex(&sk) {
                    let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();
                    lines.push(kv("npub        ", &bp_nostr::nip19::npub_encode(&pk)));
                }
            }
            None => lines.push(Line::from(Span::styled(
                "no Nostr key — press n to add one",
                alert(),
            ))),
        }
    } else {
        lines.push(Line::from(Span::styled("generate an identity with g", dim())));
    }
    if !st.status.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(st.status.clone(), alert())));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(titled_block(" ▞▞ DETAILS ")),
        cols[1],
    );

    match &st.mode {
        IdMode::New(form) => render_popup_form(f, form),
        IdMode::ConfirmDelete => {
            let name = ids.get(st.selected).map(|i| i.name.clone()).unwrap_or_default();
            render_confirm(f, &format!("Delete {name}?  (y/n)"));
        }
        IdMode::List => {}
    }
}

fn render_nostr(f: &mut Frame, area: Rect, mode: &NostrMode) {
    match mode {
        NostrMode::Menu(sel) => render_submenu(f, area, " ▞▞ NOSTR ", NOSTR_MENU, *sel),
        NostrMode::Whoami(form) | NostrMode::Post(form) | NostrMode::Fetch(form) => {
            render_form_page(f, area, form)
        }
        NostrMode::ConfirmPost { identity, text } => {
            let lines = vec![
                Line::from(Span::styled("about to publish — public + permanent", bold(alert()))),
                Line::from(""),
                Line::from(vec![Span::styled("as   ", dim()), Span::styled(identity.clone(), accent())]),
                Line::from(vec![Span::styled("note ", dim()), Span::styled(text.clone(), phosphor())]),
                Line::from(""),
                Line::from(Span::styled("y = publish · n = cancel", dim())),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .block(titled_block(" ▞▞ CONFIRM ")),
                area,
            );
        }
        NostrMode::Results { title, lines } => render_lines(f, area, title, lines),
    }
}

fn render_veil(f: &mut Frame, area: Rect, mode: &VeilMode) {
    match mode {
        VeilMode::Menu(sel) => render_submenu(f, area, " ▞▞ VEIL ", VEIL_MENU, *sel),
        VeilMode::Form(_, form) => render_form_page(f, area, form),
        VeilMode::Results { title, lines } => render_lines(f, area, title, lines),
    }
}

fn render_scrub(f: &mut Frame, area: Rect, mode: &ScrubMode) {
    match mode {
        ScrubMode::Form(form) => render_form_page(f, area, form),
        ScrubMode::Report { path, lines, .. } => {
            render_lines(f, area, &format!("scrub report — {path}"), lines)
        }
        ScrubMode::Results { lines } => render_lines(f, area, "scrubbed", lines),
    }
}

fn render_split(f: &mut Frame, area: Rect, mode: &SplitMode) {
    match mode {
        SplitMode::Menu(sel) => render_submenu(f, area, " ▞▞ SPLIT ", SPLIT_MENU, *sel),
        SplitMode::Deal(form) | SplitMode::Combine(form) => render_form_page(f, area, form),
        SplitMode::Results { title, lines } => render_lines(f, area, title, lines),
    }
}

fn render_sign(f: &mut Frame, area: Rect, mode: &SignMode) {
    match mode {
        SignMode::Menu(sel) => render_submenu(f, area, " ▞▞ SIGN/VERIFY ", SIGN_MENU, *sel),
        SignMode::Sign(form) | SignMode::Verify(form) => render_form_page(f, area, form),
        SignMode::Results { title, lines } => render_lines(f, area, title, lines),
    }
}

// ------------------------------------------------------------------ widgets

fn render_submenu(f: &mut Frame, area: Rect, title: &str, entries: &[&str], sel: usize) {
    let items: Vec<ListItem> = entries
        .iter()
        .map(|e| ListItem::new(Line::from(Span::styled(*e, accent()))))
        .collect();
    let list = List::default()
        .items(items)
        .block(titled_block(title))
        .highlight_style(selected_style())
        .highlight_symbol("▶");
    let mut state = ListState::default();
    state.select(Some(sel));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_form_page(f: &mut Frame, area: Rect, form: &Form) {
    render_form(f, area, form);
}

fn render_form(f: &mut Frame, area: Rect, form: &Form) {
    let mut lines: Vec<Line> = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let marker = if focused { "▶ " } else { "  " };
        let shown: String = if field.masked {
            "●".repeat(field.value.chars().count())
        } else if field.value.is_empty() && !field.placeholder.is_empty() {
            field.placeholder.clone()
        } else {
            field.value.clone()
        };
        let value_style = if field.value.is_empty() && !field.placeholder.is_empty() {
            dim()
        } else if focused {
            bold(alert())
        } else {
            phosphor()
        };
        let mut spans = vec![
            Span::styled(marker, accent()),
            Span::styled(format!("{:<28}", field.label), dim()),
            Span::styled(shown, value_style),
        ];
        if focused {
            spans.push(Span::styled("█", phosphor()));
        }
        lines.push(Line::from(spans));
        lines.push(Line::from(""));
    }
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(format!("✗ {err}"), bold(alert()))));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(titled_block(&format!(" ▞▞ {} ", form.title))),
        area,
    );
}

fn render_popup_form(f: &mut Frame, form: &Form) {
    let area = centered(50, (form.fields.len() as u16) * 2 + 3, f.area());
    f.render_widget(Clear, area);
    render_form(f, area, form);
}

fn render_confirm(f: &mut Frame, msg: &str) {
    let area = centered(50, 3, f.area());
    f.render_widget(Clear, area);
    let p = Paragraph::new(Line::from(Span::styled(msg.to_string(), bold(alert()))))
        .alignment(Alignment::Center)
        .block(titled_block(" confirm "));
    f.render_widget(p, area);
}

fn render_lines(f: &mut Frame, area: Rect, title: &str, lines: &[String]) {
    let text: Vec<Line> = lines
        .iter()
        .map(|l| Line::from(Span::styled(l.clone(), phosphor())))
        .collect();
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(titled_block(&format!(" ▞▞ {title} "))),
        area,
    );
}

fn render_keybar(f: &mut Frame, area: Rect, keys: &[(&str, &str)]) {
    let mut spans: Vec<Span> = Vec::new();
    for (key, label) in keys {
        spans.push(Span::styled(format!(" {key} "), selected_style()));
        spans.push(Span::styled(format!(" {label}  "), dim()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn titled_block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(phosphor())
        .title(Span::styled(title.to_string(), bold(phosphor())))
}

fn selected_style() -> ratatui::style::Style {
    selected()
}

fn kv(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(key.to_string(), dim()),
        Span::styled(value.to_string(), accent()),
    ])
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

/// A rectangle `width_pct` wide and `height` rows tall, centered in `area`.
fn centered(width_pct: u16, height: u16, area: Rect) -> Rect {
    let w = area.width * width_pct / 100;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect { x, y, width: w, height }
}
