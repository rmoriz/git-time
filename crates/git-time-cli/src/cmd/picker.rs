//! The cursor UI behind `git time tsa select`.
//!
//! Two pure pieces and one terminal driver. [`Selection`] is the state — where
//! the cursor is, what is ticked, what was typed — and [`Selection::apply_key`]
//! is the whole reducer: it maps one [`Key`] to the next state and to an
//! [`Outcome`], with no I/O at all. [`frame`] renders a state to one string.
//! That keeps the interesting part testable without a terminal; the driver
//! below only reads bytes and paints.
//!
//! Terminal control is `stty` and nothing else: no new runtime dependency.
//! `-g` captures the current settings, `raw -echo min 0 time 1` makes reads
//! single-key and non-blocking (a decisecond wait), and a `Drop` guard puts the
//! captured value back — also on panic. The alternate screen and a hidden
//! cursor bracket the session. Where `stty` is missing or refuses, [`open`]
//! returns `None` and the caller falls back to the line prompt.
//!
//! Typed numbers still work: digits, `,` and `-` append to a buffer on the
//! prompt line, and `enter` runs it through the same parser the line prompt
//! uses. A non-empty buffer wins over the ticks, so the two input styles cannot
//! fight each other.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

use git_time_core::presets::Preset;

use crate::cmd::tsa::parse_choice;

/// The keys the selector understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Move up, wrapping at the top.
    Up,
    /// Move down, wrapping at the bottom.
    Down,
    /// Jump to the first row.
    Home,
    /// Jump to the last row.
    End,
    /// Tick or untick the row under the cursor.
    Toggle,
    /// Tick every row.
    All,
    /// Untick every row.
    None,
    /// Save the selection.
    Enter,
    /// Abort without writing, or clear a non-empty buffer first.
    Escape,
    /// Abort without writing, buffer or not.
    Quit,
    /// Remove the last typed character.
    Backspace,
    /// A character of a typed selection.
    Typed(char),
}

/// What a key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Redraw and read another key.
    Stay,
    /// Leave the UI and use these zero-based indices.
    Save(Vec<usize>),
    /// Leave the UI without writing.
    Abort,
}

/// The picker's state.
#[derive(Debug, Default, Clone)]
pub struct Selection {
    cursor: usize,
    chosen: Vec<usize>,
    typed: String,
    error: Option<String>,
}

impl Selection {
    /// The row indices ticked so far, in ascending order.
    #[must_use]
    pub fn chosen(&self) -> &[usize] {
        &self.chosen
    }

    /// Where the cursor is.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether `index` is ticked.
    #[must_use]
    pub fn is_chosen(&self, index: usize) -> bool {
        self.chosen.contains(&index)
    }

    /// What was typed on the prompt line.
    #[must_use]
    pub fn typed(&self) -> &str {
        &self.typed
    }

    /// The one-line complaint shown under the prompt, if any.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Apply one key.
    ///
    /// The cursor wraps, so `k` at the first row lands on the last. Every key
    /// clears a stale error line: it belongs to the previous `enter`.
    pub fn apply_key(&mut self, key: Key, count: usize) -> Outcome {
        self.error = None;
        match key {
            Key::Up => {
                self.cursor = if self.cursor == 0 {
                    count - 1
                } else {
                    self.cursor - 1
                }
            }
            Key::Down => self.cursor = (self.cursor + 1) % count,
            Key::Home => self.cursor = 0,
            Key::End => self.cursor = count.saturating_sub(1),
            Key::Toggle => {
                if let Some(position) = self.chosen.iter().position(|index| *index == self.cursor) {
                    self.chosen.remove(position);
                } else {
                    self.chosen.push(self.cursor);
                    self.chosen.sort_unstable();
                }
            }
            Key::All => self.chosen = (0..count).collect(),
            Key::None => self.chosen.clear(),
            Key::Backspace => {
                self.typed.pop();
            }
            Key::Typed(character) => self.typed.push(character),
            // Escape clears a half-typed buffer before it leaves.
            Key::Escape if !self.typed.is_empty() => self.typed.clear(),
            Key::Escape | Key::Quit => return Outcome::Abort,
            Key::Enter if self.typed.is_empty() => return Outcome::Save(self.chosen.clone()),
            Key::Enter => match parse_choice(&self.typed, count) {
                Ok(chosen) => return Outcome::Save(chosen),
                Err(message) => self.error = Some(message),
            },
        }
        Outcome::Stay
    }
}

/// The bytes of one key as a [`Key`], or `None` for something unrecognised.
///
/// An escape sequence arrives as several bytes; the driver hands them over
/// together. A lone `\x1b` is the escape key, `\x7f`/`\x08` delete, and `\x03`
/// is `ctrl-c`, which raw mode no longer turns into a signal.
#[must_use]
pub fn parse_key(bytes: &[u8]) -> Option<Key> {
    match bytes {
        b"\x1b[A" | b"\x1bOA" | b"k" | b"h" => Some(Key::Up),
        b"\x1b[B" | b"\x1bOB" | b"j" | b"l" => Some(Key::Down),
        b"\x1b[H" | b"\x1b[1~" | b"\x1bOH" => Some(Key::Home),
        b"\x1b[F" | b"\x1b[4~" | b"\x1bOF" => Some(Key::End),
        b"\x1b" => Some(Key::Escape),
        b"q" | b"\x03" => Some(Key::Quit),
        b" " => Some(Key::Toggle),
        b"a" => Some(Key::All),
        b"n" => Some(Key::None),
        b"\r" | b"\n" => Some(Key::Enter),
        b"\x7f" | b"\x08" => Some(Key::Backspace),
        [byte] if byte.is_ascii_digit() || *byte == b',' || *byte == b'-' => {
            Some(Key::Typed(char::from(*byte)))
        }
        _ => None,
    }
}

/// One full frame: the rows, the help line, the count and the prompt.
///
/// Fixed-width columns keep the markers aligned; a terminal narrower than 100
/// columns wraps, which is ugly but readable.
#[must_use]
pub fn frame(selection: &Selection, presets: &[Preset]) -> String {
    let mut out = String::with_capacity(1024 + presets.len() * 96);
    for (index, preset) in presets.iter().enumerate() {
        let cursor = if index == selection.cursor() {
            '>'
        } else {
            ' '
        };
        let tick = if selection.is_chosen(index) { 'x' } else { ' ' };
        let trust = match preset.fingerprint {
            Some(fingerprint) => format!("pinned {}", abbreviate(fingerprint)),
            None => "tofu".to_owned(),
        };
        out.push_str(&format!(
            "{cursor} [{tick}] {:>2}  {:<20} {:<45} {trust:<24}{}\n",
            index + 1,
            preset.name,
            preset.url,
            if preset.insecure_http {
                "insecure-http"
            } else {
                ""
            },
        ));
    }
    out.push_str("space toggle  a all  n none  j/k or arrows move  enter save  q abort\n");
    out.push_str(&format!("{} selected\n", selection.chosen().len()));
    out.push_str(&format!("> {}_", selection.typed()));
    if let Some(error) = selection.error() {
        out.push_str(&format!("\n{error}"));
    }
    out.push('\n');
    out
}

/// A fingerprint abbreviated for a row: the head, an ellipsis, the tail.
fn abbreviate(fingerprint: &str) -> String {
    if fingerprint.len() <= 20 {
        return fingerprint.to_owned();
    }
    let cut = fingerprint.len() - 6;
    format!("{}…{}", &fingerprint[..9], &fingerprint[cut..])
}

/// A terminal in raw mode, restored on drop.
pub struct Raw {
    saved: String,
}

impl Raw {
    /// Capture the current settings, then go raw on the alternate screen.
    ///
    /// `None` means no `stty` or a refusal; the caller falls back to the line
    /// prompt instead of failing.
    #[must_use]
    pub fn open() -> Option<Self> {
        let saved = stty(&["-g"])?;
        stty(&["raw", "-echo", "min", "0", "time", "1"])?;
        print!("\x1b[?1049h\x1b[?25l");
        let _ = std::io::stdout().flush();
        Some(Self { saved })
    }

    /// One key's bytes, empty when nothing arrived inside the decisecond.
    ///
    /// An escape byte is followed by up to two more in the same sequence.
    #[must_use]
    pub fn read_key(&mut self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3);
        let mut byte = [0_u8; 1];
        match std::io::stdin().read(&mut byte) {
            Ok(0) | Err(_) => return Vec::new(),
            Ok(_) => bytes.push(byte[0]),
        }
        // Only an escape sequence can be longer than one byte.
        while bytes[0] == 0x1b && bytes.len() < 3 {
            match std::io::stdin().read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => bytes.push(byte[0]),
            }
        }
        bytes
    }

    /// Paint one frame, clearing what was there.
    pub fn paint(&self, frame: &str) {
        print!("\x1b[H\x1b[2J{frame}");
        let _ = std::io::stdout().flush();
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        print!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stdout().flush();
        let _ = stty(&[&self.saved]);
    }
}

/// Run `stty` with `args`, returning its stdout when it succeeded.
fn stty(args: &[&str]) -> Option<String> {
    let output = Command::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Drive the UI until a key saves or aborts.
///
/// `None` when the terminal cannot be put into raw mode; the caller then falls
/// back to the line prompt.
pub fn run(selection: &mut Selection, presets: &[Preset]) -> Option<Outcome> {
    let mut terminal = Raw::open().or_else(|| {
        eprintln!("rfc3161: note: no raw terminal; falling back to the line prompt");
        None
    })?;
    loop {
        terminal.paint(&frame(selection, presets));
        let bytes = terminal.read_key();
        let Some(key) = parse_key(&bytes) else {
            continue;
        };
        match selection.apply_key(key, presets.len()) {
            Outcome::Stay => {}
            outcome => return Some(outcome),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, Outcome, Selection, frame, parse_key};
    use git_time_core::presets;

    fn picked() -> Selection {
        Selection::default()
    }

    fn press(selection: &mut Selection, key: Key) -> Outcome {
        selection.apply_key(key, presets::PRESETS.len())
    }

    #[test]
    fn the_cursor_wraps_at_both_ends() {
        let mut selection = picked();
        press(&mut selection, Key::Up);
        assert_eq!(selection.cursor(), presets::PRESETS.len() - 1);
        press(&mut selection, Key::Down);
        assert_eq!(selection.cursor(), 0);
        press(&mut selection, Key::Down);
        assert_eq!(selection.cursor(), 1);
    }

    #[test]
    fn home_and_end_jump() {
        let mut selection = picked();
        press(&mut selection, Key::End);
        assert_eq!(selection.cursor(), presets::PRESETS.len() - 1);
        press(&mut selection, Key::Home);
        assert_eq!(selection.cursor(), 0);
    }

    #[test]
    fn space_toggles_the_row_under_the_cursor() {
        let mut selection = picked();
        press(&mut selection, Key::Down);
        press(&mut selection, Key::Toggle);
        assert_eq!(selection.chosen(), [1]);
        press(&mut selection, Key::Toggle);
        assert!(selection.chosen().is_empty());
    }

    #[test]
    fn all_and_none_are_wholesale() {
        let mut selection = picked();
        press(&mut selection, Key::All);
        assert_eq!(selection.chosen().len(), presets::PRESETS.len());
        press(&mut selection, Key::None);
        assert!(selection.chosen().is_empty());
    }

    #[test]
    fn a_typed_buffer_parses_on_enter() {
        let mut selection = picked();
        for key in [Key::Typed('1'), Key::Typed(','), Key::Typed('3')] {
            assert_eq!(press(&mut selection, key), Outcome::Stay);
        }
        assert_eq!(selection.typed(), "1,3");
        assert_eq!(press(&mut selection, Key::Enter), Outcome::Save(vec![0, 2]));
    }

    #[test]
    fn backspace_edits_the_buffer() {
        let mut selection = picked();
        press(&mut selection, Key::Typed('1'));
        press(&mut selection, Key::Typed('2'));
        press(&mut selection, Key::Backspace);
        assert_eq!(selection.typed(), "1");
    }

    #[test]
    fn escape_clears_a_buffer_before_it_aborts() {
        let mut selection = picked();
        press(&mut selection, Key::Typed('1'));
        assert_eq!(press(&mut selection, Key::Escape), Outcome::Stay);
        assert!(selection.typed().is_empty());
        assert_eq!(press(&mut selection, Key::Escape), Outcome::Abort);
    }

    #[test]
    fn quit_leaves_even_with_a_buffer() {
        let mut selection = picked();
        press(&mut selection, Key::Typed('1'));
        assert_eq!(press(&mut selection, Key::Quit), Outcome::Abort);
        assert_eq!(selection.typed(), "1");
    }

    #[test]
    fn enter_on_an_empty_buffer_saves_the_ticks() {
        let mut selection = picked();
        press(&mut selection, Key::Toggle);
        press(&mut selection, Key::Down);
        press(&mut selection, Key::Down);
        press(&mut selection, Key::Toggle);
        assert_eq!(press(&mut selection, Key::Enter), Outcome::Save(vec![0, 2]));
    }

    #[test]
    fn an_invalid_buffer_stays_and_shows_one_line() {
        let mut selection = picked();
        for key in [Key::Typed('9'), Key::Typed('9')] {
            press(&mut selection, key);
        }
        assert_eq!(press(&mut selection, Key::Enter), Outcome::Stay);
        let error = selection.error().expect("an error line");
        assert!(error.contains("not a selection"), "{error}");
        // The next key clears it again.
        press(&mut selection, Key::Backspace);
        assert!(selection.error().is_none());
    }

    #[test]
    fn parse_key_reads_the_arrows_and_the_letters() {
        // Arrows arrive as escape sequences, whichever of the two forms.
        assert_eq!(parse_key(b"\x1b[A"), Some(Key::Up));
        assert_eq!(parse_key(b"\x1bOB"), Some(Key::Down));
        assert_eq!(parse_key(b"k"), Some(Key::Up));
        assert_eq!(parse_key(b"j"), Some(Key::Down));
        assert_eq!(parse_key(b"\x03"), Some(Key::Quit));
        assert_eq!(parse_key(b"q"), Some(Key::Quit));
        assert_eq!(parse_key(b"\x7f"), Some(Key::Backspace));
        assert_eq!(parse_key(b"-"), Some(Key::Typed('-')));
        assert_eq!(parse_key(b"Z"), None);
    }

    #[test]
    fn the_frame_marks_exactly_the_cursor_row() {
        let mut selection = picked();
        press(&mut selection, Key::Down);
        press(&mut selection, Key::Toggle);
        let rendered = frame(&selection, &presets::PRESETS);
        let marked: Vec<&str> = rendered
            .lines()
            .filter(|line| line.starts_with("> ["))
            .collect();
        assert_eq!(marked.len(), 1, "{rendered}");
        assert!(marked[0].contains("digicert"), "{rendered}");
        // Ticked rows carry [x], the rest [ ].
        assert!(marked[0].contains("[x]"), "{rendered}");
        let unticked = rendered.lines().filter(|line| line.contains("[ ]")).count();
        assert_eq!(unticked, presets::PRESETS.len() - 1, "{rendered}");
    }

    #[test]
    fn print_a_demo_frame() {
        let mut selection = picked();
        press(&mut selection, Key::Down);
        press(&mut selection, Key::Toggle);
        let mut text = frame(&selection, &presets::PRESETS);
        // Keep the first four rows and the tofu row.
        let mut out = String::new();
        for (index, line) in text.lines().enumerate() {
            if index < 4 || index == 8 || index >= presets::PRESETS.len() {
                out.push_str(line);
                out.push('\n');
                if index == 3 {
                    out.push_str("   …\n");
                }
            }
        }
        text.clear();
        eprint!("{out}");
    }

    #[test]
    fn the_frame_shows_the_trust_tier_and_the_help() {
        let rendered = frame(&picked(), &presets::PRESETS);
        assert!(rendered.contains("pinned "), "{rendered}");
        assert!(rendered.contains("tofu"), "{rendered}");
        assert!(rendered.contains("insecure-http"), "{rendered}");
        assert!(rendered.contains("0 selected"), "{rendered}");
        assert!(rendered.contains("enter save"), "{rendered}");
        assert!(rendered.contains("> _"), "{rendered}");
    }

    #[test]
    fn a_short_fingerprint_is_not_abbreviated() {
        assert_eq!(super::abbreviate("AB:CD"), "AB:CD");
        assert!(super::abbreviate(&"A".repeat(40)).contains('…'));
    }
}
