//! Amber phosphor palette — classic P3 CRT, monochrome. Truecolor RGB; the
//! bare Linux VT approximates onto its 16-color palette (docs/deploy.md shows
//! how to retune the console).

use ratatui::style::{Color, Modifier, Style};

pub const PHOSPHOR: Color = Color::Rgb(0xFF, 0xB0, 0x00);
pub const ACCENT: Color = Color::Rgb(0xFF, 0xD1, 0x4A);
pub const ALERT: Color = Color::Rgb(0xFF, 0xE0, 0x82);
pub const DIM: Color = Color::Rgb(0x8F, 0x62, 0x00);

pub fn phosphor() -> Style {
    Style::default().fg(PHOSPHOR)
}
pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}
pub fn alert() -> Style {
    Style::default().fg(ALERT)
}
pub fn dim() -> Style {
    Style::default().fg(DIM)
}
pub fn bold(s: Style) -> Style {
    s.add_modifier(Modifier::BOLD)
}
/// Inverse video for selections: black on amber.
pub fn selected() -> Style {
    Style::default()
        .bg(PHOSPHOR)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD)
}
