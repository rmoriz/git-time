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

use crate::cmd::anchors;
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
        // An empty table still has to answer every key without underflowing.
        if count == 0 {
            return match key {
                Key::Quit | Key::Escape => Outcome::Abort,
                Key::Enter if self.typed.is_empty() => Outcome::Save(self.chosen.clone()),
                Key::Enter => match parse_choice(&self.typed, 0) {
                    Ok(chosen) => Outcome::Save(chosen),
                    Err(message) => {
                        self.error = Some(message);
                        Outcome::Stay
                    }
                },
                _ => Outcome::Stay,
            };
        }
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

const NAME_WIDTH: usize = 18;
const TRUST_WIDTH: usize = 16;
const HELP: &str = "space toggle  a all  n none  j/k or arrows move  enter save  q abort";

/// One screen frame for a `rows` x `cols` terminal.
///
/// Narrow and windowed on purpose. The row itself carries only what a choice
/// needs — cursor, tick, index, name, trust tier with the pinned root's expiry,
/// transport — at fixed widths, so a wrapped line cannot push the table off the
/// top of a default terminal. The endpoint of the cursor row is printed in full
/// below the list instead of costing a column.
///
/// At most `rows - 1` lines, at most `cols - 1` columns, lines separated by
/// `\r\n` and the last one not terminated. All three leave the bottom row and
/// the last column free: a line that fills the last column wraps, a trailing
/// newline advances a line, and either scrolls a screen that is already full.
/// The list is a window that keeps the cursor visible and marks a cut edge with
/// `…`; the footer (URL, help, count, prompt, error) is always there. Below the
/// room the footer needs, it degrades to the cursor row and the footer.
#[must_use]
pub fn frame(selection: &Selection, presets: &[Preset], rows: usize, cols: usize) -> String {
    let len = presets.len();
    let cursor = selection.cursor().min(len.saturating_sub(1));
    let url = presets.get(cursor).map_or("", |preset| preset.url);
    // One instant for the whole frame, so a repaint cannot straddle midnight.
    let now = jiff::Timestamp::now();

    // Footer: URL, help, count, prompt, and the error line when there is one.
    let footer = 4 + usize::from(selection.error().is_some());
    let budget = rows.saturating_sub(footer).saturating_sub(1).max(1);

    let mut lines: Vec<String> = Vec::with_capacity(budget + footer);
    if len > 0 {
        let capacity = budget.min(len);
        let mut start = cursor.saturating_sub(capacity.saturating_sub(1));
        start = start.min(len - capacity);
        let mut end = start + capacity;
        // A marker eats a row; make room without losing the cursor.
        let mut real = capacity;
        if start > 0 {
            real = real.saturating_sub(1);
        }
        if end < len {
            real = real.saturating_sub(1);
        }
        real = real.max(1).min(len);
        start = cursor.saturating_sub(real - 1).min(len - real);
        end = (start + real).min(len);

        if start > 0 {
            lines.push("  …".to_owned());
        }
        for (index, preset) in presets.iter().enumerate().take(end).skip(start) {
            lines.push(row(selection, index, preset, now));
        }
        if end < len {
            lines.push("  …".to_owned());
        }
    }

    lines.push(format!("url: {url}"));
    lines.push(HELP.to_owned());
    lines.push(format!("{} selected", selection.chosen().len()));
    lines.push(format!("> {}_", selection.typed()));
    if let Some(error) = selection.error() {
        lines.push(error.to_owned());
    }

    // One column short of the edge, or the terminal wraps the row and the next
    // `\r\n` lands two lines down.
    let width = cols.saturating_sub(1).max(1);
    let mut out = String::with_capacity((budget + footer) * 64);
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.push_str("\r\n");
        }
        out.push_str(&fit(line, width));
    }
    out
}

/// One row, at the fixed widths, with the long fields fitted.
fn row(selection: &Selection, index: usize, preset: &Preset, now: jiff::Timestamp) -> String {
    let cursor = if index == selection.cursor() {
        '>'
    } else {
        ' '
    };
    let tick = if selection.is_chosen(index) { 'x' } else { ' ' };
    // The default bundle path is what `install` writes; a configured path is not
    // known here, and a preset that is pinned here is pinned there.
    let anchor = anchors::dir().join(format!("{}.pem", preset.name));
    let trust = trust(preset, anchors::roots(&anchor).as_deref(), now);
    format!(
        " {cursor} [{tick}] {:>2}  {:<NAME_WIDTH$} {:<TRUST_WIDTH$} {}",
        index + 1,
        fit(preset.name, NAME_WIDTH),
        fit(&trust, TRUST_WIDTH),
        if preset.insecure_http { "http" } else { "" },
    )
}

/// The trust column: `pin <YYYY-MM-DD>` with its verdict for a pinned root,
/// `EXPIRED` once none of the bundle's roots is valid at `now`, `tofu` without
/// a published root, and `pin -` for one that is not pinned here.
///
/// The local bundle is read first, because for a preset that publishes no root
/// it is the only copy: such an authority is exactly where a hidden date hurts.
/// The date is what a reader weighs a rotation by, so it sits where the choice
/// is made.
fn trust(preset: &Preset, roots: Option<&[anchors::RootRow]>, now: jiff::Timestamp) -> String {
    if let Some(roots) = roots.filter(|roots| !roots.is_empty()) {
        if roots
            .iter()
            .all(|root| anchors::expired(&root.not_after, now))
        {
            return "EXPIRED".to_owned();
        }
        if let Some(root) = roots.last() {
            return format!("pin {}", anchors::expiry_text(&root.not_after, now));
        }
    }
    if preset.fingerprints.is_empty() {
        "tofu".to_owned()
    } else {
        "pin -".to_owned()
    }
}

/// `text` cut to `width` characters, with `…` when it had to be cut.
///
/// Character-wise, so a multi-byte name cannot split a code point.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let Some(room) = width.checked_sub(1) else {
        return String::new();
    };
    let mut out: String = text.chars().take(room).collect();
    out.push('…');
    out
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
        // `raw` clears `opost`, so it has to be re-set after it; without it every
        // `\n` would walk to the right margin. `onlcr` is cleared too, or the
        // frame's own `\r\n` would become `\r\r\n`.
        stty(&["raw", "-echo", "min", "0", "time", "1", "opost", "-onlcr"])?;
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

/// The terminal's `(rows, cols)`, re-read every frame so a resize is caught.
///
/// `(24, 80)` when there is no answer: a sane frame beats none.
fn size() -> (usize, usize) {
    stty(&["size"])
        .and_then(|output| {
            let mut parts = output.split_whitespace();
            let rows: usize = parts.next()?.parse().ok()?;
            let cols: usize = parts.next()?.parse().ok()?;
            (rows > 0 && cols > 0).then_some((rows, cols))
        })
        .unwrap_or((24, 80))
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
    let (mut rows, mut cols) = size();
    terminal.paint(&frame(selection, presets, rows, cols));
    loop {
        let bytes = terminal.read_key();
        let Some(key) = parse_key(&bytes) else {
            // The only silent change the frame shows is a resize.
            let (next_rows, next_cols) = size();
            if (next_rows, next_cols) != (rows, cols) {
                rows = next_rows;
                cols = next_cols;
                terminal.paint(&frame(selection, presets, rows, cols));
            }
            continue;
        };
        (rows, cols) = size();
        match selection.apply_key(key, presets.len()) {
            Outcome::Stay => terminal.paint(&frame(selection, presets, rows, cols)),
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
        let rendered = frame(&selection, &presets::PRESETS, 40, 80);
        let marked: Vec<&str> = rendered
            .lines()
            .filter(|line| line.trim_start().starts_with("> ["))
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
        eprint!("{}", frame(&selection, &presets::PRESETS, 24, 80));
    }

    #[test]
    fn the_frame_shows_the_trust_tier_and_the_help() {
        let rendered = frame(&picked(), &presets::PRESETS, 24, 80);
        assert!(rendered.contains("pin "), "{rendered}");
        assert!(rendered.contains("tofu"), "{rendered}");
        assert!(rendered.contains(" http"), "{rendered}");
        assert!(rendered.contains("0 selected"), "{rendered}");
        assert!(rendered.contains("enter save"), "{rendered}");
        assert!(rendered.contains("> _"), "{rendered}");
    }

    /// Frame lines without the `\r`, so a test can compare and measure them.
    fn shards(rendered: &str) -> Vec<&str> {
        rendered
            .split("\r\n")
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn long_preset() -> presets::Preset {
        presets::Preset {
            name: "a-name-that-is-exactly-forty-chars-long!!",
            url: "http://an-endpoint.example/that/is/long/enough/to/need/room/tsr",
            anchor_url: "http://an-endpoint.example/ca.pem",
            chain: &[],
            alg: "sha256",
            policy: None,
            fingerprints: &["05:63:B8:63:0D:62:D7:5A:BB:C8:AB:1E:4B:DF:B5:A8:99:B2:4D:43"],
            insecure_http: true,
            curated: false,
        }
    }

    #[test]
    fn every_line_is_crlf_and_fits_the_width() {
        for cols in [40, 60, 80] {
            for cursor in 0..presets::PRESETS.len() {
                let mut selection = picked();
                selection.apply_key(Key::Down, presets::PRESETS.len());
                for _ in 0..cursor {
                    press(&mut selection, Key::Down);
                }
                let rendered = frame(&selection, &presets::PRESETS, 24, cols);
                assert!(
                    !rendered.ends_with('\n'),
                    "as {cols}/{cursor}: no trailing line"
                );
                assert_eq!(
                    rendered.matches("\r\n").count(),
                    shards(&rendered).len() - 1,
                    "CRLF between lines only, as {cols}/{cursor}"
                );
                for line in shards(&rendered) {
                    assert!(
                        !line.contains('\r'),
                        "no lone CR as {cols}/{cursor}: {line:?}"
                    );
                    assert!(
                        line.chars().count() < cols,
                        "{} >= {cols} at cursor {cursor}: {line:?}",
                        line.chars().count()
                    );
                }
            }
        }
    }

    #[test]
    fn the_frame_never_exceeds_the_terminal_rows() {
        for rows in [8, 24, 40] {
            let mut selection = picked();
            press(&mut selection, Key::End);
            let rendered = frame(&selection, &presets::PRESETS, rows, 80);
            // One line short of the bottom, or a full screen scrolls.
            assert!(
                rendered.lines().count() < rows,
                "{} lines for {rows} rows",
                rendered.lines().count()
            );
            assert!(!rendered.ends_with('\n'), "no trailing line at {rows} rows");
        }
    }

    #[test]
    fn the_cursor_row_and_the_footer_are_always_rendered() {
        // At the top nothing is cut above.
        let rendered = frame(&picked(), &presets::PRESETS, 8, 80);
        let lines = shards(&rendered);
        assert!(lines[0].contains("freetsa"), "{rendered}");
        // The fingerprint itself is abbreviated; the *row* is not cut off.
        assert!(lines[0].trim_start().starts_with("> ["), "{rendered}");

        // At the last row the cursor row is there and a `…` marks the top cut.
        let mut selection = picked();
        press(&mut selection, Key::End);
        let rendered = frame(&selection, &presets::PRESETS, 8, 80);
        let lines = shards(&rendered);
        assert_eq!(lines[0].trim(), "…", "the top cut is marked: {rendered}");
        assert!(
            lines
                .iter()
                .any(|line| line.trim_start().starts_with("> [") && line.contains("accv")),
            "{rendered}"
        );

        // The footer is in both, the prompt unconditionally.
        for rendered in [frame(&picked(), &presets::PRESETS, 8, 80), rendered] {
            assert!(rendered.contains("selected"), "{rendered}");
            assert!(rendered.contains("> _"), "{rendered}");
            assert!(rendered.contains("url: "), "{rendered}");
        }
    }

    #[test]
    fn long_fields_are_cut_with_an_ellipsis_and_keep_the_columns_aligned() {
        let row_of = |presets: &[presets::Preset]| {
            let rendered = frame(&picked(), presets, 24, 60);
            shards(&rendered)
                .into_iter()
                .find(|line| line.trim_start().starts_with("> ["))
                .expect("the cursor row")
                .to_owned()
        };

        // A 40-character name, cut. The trust column holds `pin <day>`,
        // `EXPIRED` or `pin -`; a verdict is cut inside its own column, so with
        // no bundle pinned here only the name needs the ellipsis.
        let long = row_of(&[long_preset()]);
        assert!(long.chars().count() < 60, "{long:?}");
        assert_eq!(long.matches('…').count(), 1, "the name is cut: {long:?}");

        // The trust column starts at the same place whether the name was cut or not.
        let column = |line: &str, marker: &str| {
            let at = line
                .find(marker)
                .unwrap_or_else(|| panic!("`{marker}` in {line:?}"));
            line[..at].chars().count()
        };
        let short = row_of(&presets::PRESETS[1..2]); // digicert: pinned and `http`
        assert_eq!(
            column(&long, "pin "),
            column(&short, "pin "),
            "{long:?} / {short:?}"
        );
        assert_eq!(
            column(&long, "http"),
            column(&short, "http"),
            "{long:?} / {short:?}"
        );
        assert_eq!(column(&long, "pin "), 11 + super::NAME_WIDTH + 1);
    }

    #[test]
    fn a_forty_column_frame_leaves_the_last_column_free() {
        for cursor in [0, 10, presets::PRESETS.len() - 1] {
            let mut selection = picked();
            for _ in 0..cursor {
                press(&mut selection, Key::Down);
            }
            let rendered = frame(&selection, &presets::PRESETS, 12, 40);
            assert!(rendered.lines().count() <= 11, "{rendered:?}");
            for line in rendered.lines() {
                assert_ne!(line.chars().count(), 40, "a full line wraps: {line:?}");
                assert!(line.chars().count() < 40, "{line:?}");
            }
        }
    }

    #[test]
    fn the_last_line_is_not_terminated_and_nothing_doubles_the_carriage_return() {
        let rendered = frame(&picked(), &presets::PRESETS, 24, 80);
        assert!(!rendered.ends_with('\n'), "{rendered:?}");
        assert!(!rendered.contains("\r\r\n"), "{rendered:?}");
        assert!(rendered.ends_with("> _"), "{rendered:?}");
    }

    #[test]
    fn an_empty_table_answers_every_key() {
        let mut selection = picked();
        for key in [
            Key::Up,
            Key::Down,
            Key::Home,
            Key::End,
            Key::Toggle,
            Key::Enter,
        ] {
            let _ = selection.apply_key(key, 0);
        }
        let expected = selection.chosen().to_vec();
        assert_eq!(selection.apply_key(Key::Enter, 0), Outcome::Save(expected));
        assert!(frame(&selection, &[], 24, 80).contains("url: "));
    }

    #[test]
    fn a_short_fingerprint_is_not_abbreviated() {
        assert_eq!(super::fit("AB:CD", 16), "AB:CD");
        assert!(super::fit(&"A".repeat(40), 16).ends_with('…'));
    }

    /// Midnight UTC of `year-month-day`, as a frame takes its `now`.
    fn at(year: i16, month: i8, day: i8) -> jiff::Timestamp {
        jiff::civil::date(year, month, day)
            .at(0, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::UTC)
            .expect("an instant")
            .timestamp()
    }

    fn root(not_after: &str) -> super::anchors::RootRow {
        super::anchors::RootRow {
            fingerprint: "AB:CD".to_owned(),
            not_after: not_after.to_owned(),
        }
    }

    #[test]
    fn the_trust_column_says_the_pin_and_its_date() {
        let preset = presets::find("digicert").expect("a pinned preset");
        assert_eq!(
            super::trust(preset, Some(&[root("2030-01-01")]), at(2026, 1, 1)),
            "pin 2030-01-01"
        );
        // The verdict rides along while the day takes the room it needs.
        assert_eq!(
            super::trust(preset, Some(&[root("2027-01-01")]), at(2026, 12, 1)),
            "pin 2027-01-01 (expires soon)"
        );
    }

    #[test]
    fn an_authority_without_a_live_root_says_expired() {
        let preset = presets::find("digicert").expect("a pinned preset");
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2020-01-01"), root("2020-02-01")]),
                at(2026, 1, 1)
            ),
            "EXPIRED"
        );
        // One live root is enough, and the newest root's day is the one shown.
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2020-01-01"), root("2030-01-01")]),
                at(2026, 1, 1)
            ),
            "pin 2030-01-01"
        );
    }

    #[test]
    fn an_unpublished_preset_without_a_bundle_stays_tofu() {
        let preset = presets::find("swisssign").expect("a TOFU preset");
        assert_eq!(super::trust(preset, None, at(2026, 1, 1)), "tofu");
    }

    /// The local bundle is the only copy of an unpublished root, so the date
    /// and its verdict have to be reachable for exactly that preset too.
    #[test]
    fn a_pinned_unpublished_preset_says_its_date() {
        let preset = presets::find("swisssign").expect("a TOFU preset");
        assert_eq!(
            super::trust(preset, Some(&[root("2030-01-01")]), at(2026, 1, 1)),
            "pin 2030-01-01"
        );
        assert_eq!(
            super::trust(preset, Some(&[root("2020-01-01")]), at(2026, 1, 1)),
            "EXPIRED"
        );
    }

    #[test]
    fn a_published_root_that_is_not_pinned_here_has_no_date() {
        let preset = presets::find("digicert").expect("a pinned preset");
        assert_eq!(super::trust(preset, None, at(2026, 1, 1)), "pin -");
        assert_eq!(super::trust(preset, Some(&[]), at(2026, 1, 1)), "pin -");
    }
}
