//! A small form engine: labeled single-line fields (optionally masked),
//! focus cycling, and submit/cancel events. Every native screen and the
//! unlock modal build on this, so editing behaves identically everywhere.

use ratatui::crossterm::event::KeyCode;

pub struct Field {
    pub label: &'static str,
    pub value: String,
    /// Render as ●●● (passphrases).
    pub masked: bool,
    /// Shown dimly when the value is empty (defaults, hints).
    pub placeholder: String,
}

impl Field {
    pub fn new(label: &'static str) -> Self {
        Field {
            label,
            value: String::new(),
            masked: false,
            placeholder: String::new(),
        }
    }

    pub fn masked(label: &'static str) -> Self {
        Field {
            masked: true,
            ..Field::new(label)
        }
    }

    pub fn with_placeholder(mut self, hint: impl Into<String>) -> Self {
        self.placeholder = hint.into();
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FormEvent {
    /// Still editing.
    Editing,
    /// Enter on the last field (or ctrl-flavored submit).
    Submit,
    /// Esc.
    Cancel,
}

pub struct Form {
    pub title: &'static str,
    pub fields: Vec<Field>,
    pub focus: usize,
    /// Error from the last submit attempt, shown under the fields.
    pub error: Option<String>,
}

impl Form {
    pub fn new(title: &'static str, fields: Vec<Field>) -> Self {
        Form {
            title,
            fields,
            focus: 0,
            error: None,
        }
    }

    /// Value of field `i`, trimmed.
    pub fn value(&self, i: usize) -> &str {
        self.fields[i].value.trim()
    }

    pub fn on_key(&mut self, code: KeyCode) -> FormEvent {
        match code {
            KeyCode::Esc => FormEvent::Cancel,
            KeyCode::Enter => {
                if self.focus + 1 < self.fields.len() {
                    self.focus += 1;
                    FormEvent::Editing
                } else {
                    FormEvent::Submit
                }
            }
            KeyCode::Tab | KeyCode::Down => {
                self.focus = (self.focus + 1) % self.fields.len();
                FormEvent::Editing
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = self.focus.checked_sub(1).unwrap_or(self.fields.len() - 1);
                FormEvent::Editing
            }
            KeyCode::Backspace => {
                self.fields[self.focus].value.pop();
                FormEvent::Editing
            }
            KeyCode::Char(c) => {
                self.fields[self.focus].value.push(c);
                FormEvent::Editing
            }
            _ => FormEvent::Editing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form2() -> Form {
        Form::new("t", vec![Field::new("a"), Field::masked("b")])
    }

    fn type_str(f: &mut Form, s: &str) {
        for c in s.chars() {
            f.on_key(KeyCode::Char(c));
        }
    }

    #[test]
    fn enter_advances_then_submits() {
        let mut f = form2();
        type_str(&mut f, "hello");
        assert_eq!(f.on_key(KeyCode::Enter), FormEvent::Editing); // -> field 2
        assert_eq!(f.focus, 1);
        type_str(&mut f, "pw");
        assert_eq!(f.on_key(KeyCode::Enter), FormEvent::Submit);
        assert_eq!(f.value(0), "hello");
        assert_eq!(f.value(1), "pw");
    }

    #[test]
    fn tab_cycles_and_esc_cancels() {
        let mut f = form2();
        f.on_key(KeyCode::Tab);
        assert_eq!(f.focus, 1);
        f.on_key(KeyCode::Tab);
        assert_eq!(f.focus, 0);
        f.on_key(KeyCode::BackTab);
        assert_eq!(f.focus, 1);
        assert_eq!(f.on_key(KeyCode::Esc), FormEvent::Cancel);
    }

    #[test]
    fn backspace_edits_focused_field() {
        let mut f = form2();
        type_str(&mut f, "abc");
        f.on_key(KeyCode::Backspace);
        assert_eq!(f.value(0), "ab");
    }
}
