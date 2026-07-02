//! Rendering for the launcher. Phosphor-terminal aesthetic, restricted to the
//! basic ANSI palette so it renders identically on the Linux framebuffer
//! console (the cyberdeck target) and any desktop emulator.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Mode, TOOLS};

/// ANSI-Shadow "CIPHERPUNK", 78 columns — fits an 80-column deck screen.
const BANNER: [&str; 6] = [
    " ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗",
    "██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔══██╗██║   ██║████╗  ██║██║ ██╔╝",
    "██║     ██║██████╔╝███████║█████╗  ██████╔╝██████╔╝██║   ██║██╔██╗ ██║█████╔╝ ",
    "██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██║╚██╗██║██╔═██╗ ",
    "╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║     ╚██████╔╝██║╚██╗██║██║  ██╗",
    " ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝ ╚═══╝╚═╝  ╚═╝",
];

const PHOSPHOR: Color = Color::Green;
const ACCENT: Color = Color::Cyan;
const ALERT: Color = Color::Magenta;
const DIM: Color = Color::DarkGray;

pub fn render(f: &mut Frame, app: &App) {
    let banner_h = if f.area().width >= 80 { 8 } else { 3 };
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_banner(f, root[0]);
    render_body(f, app, root[1]);
    render_keys(f, app, root[2]);
}

fn render_banner(f: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if area.height >= 8 {
        for row in BANNER {
            lines.push(Line::from(Span::styled(
                row,
                Style::default().fg(PHOSPHOR).add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(Line::from(Span::styled(
            "─── privacy · sovereignty · crypto ───",
            Style::default().fg(DIM),
        )));
    } else {
        // Narrow screen: single-line badge.
        lines.push(Line::from(vec![
            Span::styled("░▒▓ ", Style::default().fg(DIM)),
            Span::styled(
                "C I P H E R P U N K",
                Style::default().fg(PHOSPHOR).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ▓▒░", Style::default().fg(DIM)),
        ]));
        lines.push(Line::from(Span::styled(
            "privacy · sovereignty · crypto",
            Style::default().fg(DIM),
        )));
    }
    let p = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(p, area);
}

fn render_body(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(38), Constraint::Min(30)])
        .split(area);
    render_menu(f, app, cols[0]);
    render_detail(f, app, cols[1]);
}

fn render_menu(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = TOOLS
        .iter()
        .enumerate()
        .map(|(i, t)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", i + 1), Style::default().fg(DIM)),
                Span::styled(
                    format!("{:<12}", t.name),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(t.tagline, Style::default().fg(DIM)),
            ]))
        })
        .collect();

    let list = List::default()
        .items(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR))
                .title(Span::styled(
                    "▞▞ TOOLS ",
                    Style::default().fg(PHOSPHOR).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(
            Style::default()
                .bg(PHOSPHOR)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶");

    let mut state = ListState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let tool = app.tool();
    let mut lines: Vec<Line> = Vec::new();

    for l in tool.about {
        lines.push(Line::from(Span::styled(*l, Style::default().fg(Color::Gray))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "EXAMPLES",
        Style::default().fg(DIM).add_modifier(Modifier::UNDERLINED),
    )));
    for ex in tool.examples {
        lines.push(Line::from(vec![
            Span::styled("  $ ", Style::default().fg(DIM)),
            Span::styled(format!("{} ", tool.bin), Style::default().fg(ACCENT)),
            Span::styled(*ex, Style::default().fg(PHOSPHOR)),
        ]));
    }

    if app.mode == Mode::Args {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "ARGS (Enter=run · Esc=cancel)",
            Style::default().fg(ALERT).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(vec![
            Span::styled("  $ ", Style::default().fg(DIM)),
            Span::styled(format!("{} ", tool.bin), Style::default().fg(ACCENT)),
            Span::styled(app.args.clone(), Style::default().fg(Color::White)),
            Span::styled("█", Style::default().fg(PHOSPHOR)),
        ]));
    }

    if let Some((cmd, result)) = &app.last_run {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("LAST RUN ", Style::default().fg(DIM)),
            Span::styled(cmd.clone(), Style::default().fg(ACCENT)),
        ]));
        lines.push(Line::from(Span::styled(
            format!("  {result}"),
            Style::default().fg(DIM),
        )));
    }

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PHOSPHOR))
                .title(Span::styled(
                    format!("▞▞ {} ", tool.name),
                    Style::default().fg(PHOSPHOR).add_modifier(Modifier::BOLD),
                )),
        );
    f.render_widget(p, area);
}

fn render_keys(f: &mut Frame, app: &App, area: Rect) {
    let keys: &[(&str, &str)] = match app.mode {
        Mode::Menu => &[
            ("↑↓/jk", "select"),
            ("1-5", "jump"),
            ("enter", "launch"),
            ("!", "shell"),
            ("q", "quit"),
        ],
        Mode::Args => &[("enter", "run"), ("esc", "cancel")],
    };
    let mut spans: Vec<Span> = Vec::new();
    for (key, label) in keys {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default().bg(PHOSPHOR).fg(Color::Black),
        ));
        spans.push(Span::styled(
            format!(" {label}  "),
            Style::default().fg(DIM),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
