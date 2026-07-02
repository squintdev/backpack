//! Rendering for the keyring TUI. Pure view logic over [`App`].

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Mode};

pub fn render(f: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(f.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(root[0]);

    render_list(f, app, body[0]);
    render_details(f, app, body[1]);
    render_status(f, app, root[1]);

    match app.mode {
        Mode::Input => render_input_popup(f, app),
        Mode::ConfirmDelete => render_confirm_popup(f, app),
        Mode::List => {}
    }
}

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let ids = app.identities();
    let items: Vec<ListItem> = ids
        .iter()
        .map(|id| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<16}", truncate(&id.name, 16)),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(id.fingerprint(), Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" identities ({}) ", ids.len()));

    if items.is_empty() {
        let hint = Paragraph::new("no identities\n\npress g to generate one")
            .alignment(Alignment::Center)
            .block(block);
        f.render_widget(hint, area);
        return;
    }

    let list = List::default()
        .items(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(app.selected.min(ids.len().saturating_sub(1))));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_details(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" details ");
    let text = match app.selected_identity() {
        None => vec![Line::from("Select or generate an identity.")],
        Some(id) => vec![
            Line::from(vec![
                Span::styled("name        ", Style::default().fg(Color::DarkGray)),
                Span::raw(id.name.clone()),
            ]),
            Line::from(vec![
                Span::styled("fingerprint ", Style::default().fg(Color::DarkGray)),
                Span::styled(id.fingerprint(), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "public identity (share this):",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                id.to_line(),
                Style::default().fg(Color::Green),
            )),
        ],
    };
    let p = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let help = "g generate · e export · d delete · j/k move · q quit";
    let line = if app.status.is_empty() {
        Span::styled(help, Style::default().fg(Color::DarkGray))
    } else {
        Span::styled(app.status.clone(), Style::default().fg(Color::Magenta))
    };
    let p = Paragraph::new(Line::from(line)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", app.keystore_path().display())),
    );
    f.render_widget(p, area);
}

fn render_input_popup(f: &mut Frame, app: &App) {
    let area = centered(50, 3, f.area());
    f.render_widget(Clear, area);
    let p = Paragraph::new(Line::from(vec![
        Span::raw(&app.input),
        Span::styled("▏", Style::default().fg(Color::Cyan)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" new identity name (Enter=ok, Esc=cancel) "),
    );
    f.render_widget(p, area);
}

fn render_confirm_popup(f: &mut Frame, app: &App) {
    let name = app
        .selected_identity()
        .map(|i| i.name)
        .unwrap_or_default();
    let area = centered(50, 3, f.area());
    f.render_widget(Clear, area);
    let p = Paragraph::new(Line::from(format!("Delete {name}?  (y/n)")))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" confirm ")
                .border_style(Style::default().fg(Color::Red)),
        );
    f.render_widget(p, area);
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
    Rect {
        x,
        y,
        width: w,
        height,
    }
}
