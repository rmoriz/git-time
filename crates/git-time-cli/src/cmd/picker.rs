//! The cursor UI behind `git time tsa select`.
//!
//! Two pure pieces and one terminal driver. [`Selection`] is the state — where
//! the cursor is, what is ticked, what was typed — and [`Selection::apply_key`]
//! is the whole reducer: it maps one [`Key`] to the next state and to an
//! [`Outcome`], with no I/O at all. [`frame`] renders a state and a [`Probes`]
//! snapshot to one string. That keeps the interesting part testable without a
//! terminal; the driver below only reads bytes, drains answers and paints.
//!
//! A [`Cell`] is display material only: what a probe served says what an
//! authority currently publishes, while the local bundle stays what a seal is
//! checked against. The two are never conflated — a served date reads `fetch`,
//! a pinned one `pin`.
//!
//! Probing happens in the driver's idle time. The opening snapshot comes from
//! the cache, the first frame is painted from it, and answers are drained
//! between key reads; a slow or dead authority costs a repaint and never the
//! screen. `r` asks every authority again, keeping the previous dates until a
//! fresh answer replaces them.
//!
//! Terminal control is `stty` and nothing else: no new runtime dependency.
//! `-g` captures the current settings, `raw -echo min 0 time 1` makes reads
//! single-key and non-blocking (a decisecond wait), and a `Drop` guard puts the
//! captured value back — also on panic. The alternate screen and a hidden
//! cursor bracket the session. Where `stty` is missing or refuses, [`Raw::open`]
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
use crate::cmd::probe;
use crate::cmd::tsa::{looming, parse_choice};

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
    /// Ask for every probe to be fetched again.
    ///
    /// The driver does the work; the reducer only has to not swallow the key.
    Refresh,
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
    /// A selection that starts with `ticked` already ticked.
    ///
    /// The caller hands over whatever is configured, which can repeat an index;
    /// the constructor sorts and dedupes so the rest of the state can assume the
    /// invariant the toggle keeps.
    #[must_use]
    pub fn ticked(ticked: &[usize]) -> Self {
        let mut chosen = ticked.to_vec();
        chosen.sort_unstable();
        chosen.dedup();
        Self {
            chosen,
            ..Self::default()
        }
    }

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
            // The driver probes, the reducer only redraws.
            Key::Refresh => {}
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
        b"r" => Some(Key::Refresh),
        b"\x7f" | b"\x08" => Some(Key::Backspace),
        [byte] if byte.is_ascii_digit() || *byte == b',' || *byte == b'-' => {
            Some(Key::Typed(char::from(*byte)))
        }
        _ => None,
    }
}

const NAME_WIDTH: usize = 18;
// Wide enough for `fetch expires <day>`, the longest trust text: a near expiry
// keeps both the word and the date instead of being cut inside its own column.
const TRUST_WIDTH: usize = 24;
// Everything on a row outside the trust cell: the cursor, tick, index and the
// separating spaces, then the space before the transport column and the column
// itself. A narrow terminal cuts the cell to keep this room, so a served date
// never costs the visible `http`.
const ROW_PREFIX_WIDTH: usize = 12;
const TRANSPORT_WIDTH: usize = 5;
const HELP: &str =
    "space toggle  a all  n none  j/k or arrows move  r refresh  enter save  q abort";

/// What the probe said about one row, as the trust column shows it.
///
/// Display material only: a [`Cell::Known`] date never outranks the local pin,
/// it only stands in for one while no root is pinned here — and marks a pin
/// when the served root is one the bundle does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    /// Nothing was asked: today's `pin`/`tofu` wording, unchanged.
    Idle,
    /// Queued or in flight.
    Pending,
    /// A served root this authority publishes, with its date and fingerprint.
    Known(probe::Cached),
    /// A reply whose roots are none this authority publishes.
    Unpublished,
    /// No reply, or one that could not be judged.
    Failed,
}

/// The cells of a table, one per row, as the worker left them.
///
/// A snapshot the frame reads: the driver owns it, overwrites single cells from
/// the worker's answers and hands the frame a `&Probes`. A repeat answer simply
/// overwrites, so the newest reply for an index is the one shown.
#[derive(Debug, Clone)]
pub struct Probes {
    cells: Vec<Cell>,
}

impl Probes {
    /// A table where nothing was asked.
    #[must_use]
    pub fn idle(count: usize) -> Self {
        Self {
            cells: vec![Cell::Idle; count],
        }
    }

    /// A table where every row is waiting for its first answer.
    #[must_use]
    pub fn pending(count: usize) -> Self {
        Self {
            cells: vec![Cell::Pending; count],
        }
    }

    /// Set the cell of `index`; an index outside the table is ignored.
    pub fn set(&mut self, index: usize, cell: Cell) {
        if let Some(slot) = self.cells.get_mut(index) {
            *slot = cell;
        }
    }

    /// The cell of `index`, [`Cell::Idle`] outside the table.
    #[must_use]
    pub fn cell(&self, index: usize) -> Cell {
        self.cells.get(index).cloned().unwrap_or(Cell::Idle)
    }

    /// How many rows answered a failure.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| matches!(cell, Cell::Failed))
            .count()
    }

    /// The ids of the rows whose served root is not a published one.
    ///
    /// These are the rotation signal: the authority answers with a root the
    /// preset does not name, so the pin (or its absence) is what it always was
    /// while the authority has moved on.
    #[must_use]
    pub fn unpublished(&self, presets: &[Preset]) -> Vec<&'static str> {
        self.cells
            .iter()
            .enumerate()
            .filter(|(_, cell)| matches!(cell, Cell::Unpublished))
            .filter_map(|(index, _)| presets.get(index).map(|preset| preset.name))
            .collect()
    }
}

/// One screen frame for a `rows` x `cols` terminal.
///
/// Narrow and windowed on purpose. The row itself carries only what a choice
/// needs — cursor, tick, index, name, trust tier with the pinned root's expiry
/// or the date a probe served, transport — at fixed widths, so a wrapped line
/// cannot push the table off the top of a default terminal. The endpoint of the
/// cursor row is printed in full below the list instead of costing a column.
/// Where the terminal is too narrow for the whole row, the trust cell is what is
/// cut, so the served date never hides the transport.
///
/// At most `rows - 1` lines from seven rows up, at most `cols - 1` columns,
/// lines separated by `\r\n` and the last one not terminated. All three leave
/// the bottom row and the last column free: a line that fills the last column
/// wraps, a trailing newline advances a line, and either scrolls a screen that
/// is already full. The list is a window that keeps the cursor visible and marks
/// a cut edge with `…`; the footer (URL, help, count, prompt, the probe tally,
/// error) is always there. Below the room the footer needs, it degrades: first
/// the cut marks go, then the help, then the count — the URL, the prompt, the
/// tally and the error stay, and so does the cursor row.
///
/// The frame needs seven rows to stay inside the terminal: four footer lines,
/// one for the screen edge and one cursor row leave one spare for a cut mark.
/// Under seven the footer wins and the frame may reach past the bottom; the
/// cursor row is still in it.
#[must_use]
pub fn frame(
    selection: &Selection,
    presets: &[Preset],
    probes: &Probes,
    rows: usize,
    cols: usize,
) -> String {
    let len = presets.len();
    let cursor = selection.cursor().min(len.saturating_sub(1));
    let url = presets.get(cursor).map_or("", |preset| preset.url);
    // One instant for the whole frame, so a repaint cannot straddle midnight.
    let now = jiff::Timestamp::now();

    // One column short of the edge, or the terminal wraps the row and the next
    // `\r\n` lands two lines down.
    let width = cols.saturating_sub(1).max(1);

    // Footer: URL, help, count, prompt, the probe tally, and the error line when
    // there is one.
    let failed = probes.failed();
    let unpublished = probes.unpublished(presets);
    let footer = 4
        + usize::from(selection.error().is_some())
        + usize::from(failed > 0)
        + usize::from(!unpublished.is_empty());
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
            lines.push(row(selection, index, preset, probes, width, now));
        }
        if end < len {
            lines.push("  …".to_owned());
        }
    }

    let count = format!("{} selected", selection.chosen().len());
    lines.push(format!("url: {url}"));
    lines.push(HELP.to_owned());
    lines.push(count.clone());
    lines.push(format!("> {}_", selection.typed()));
    if failed > 0 {
        lines.push(format!("probe failed: {failed}"));
    }
    if !unpublished.is_empty() {
        lines.push(format!(
            "served root not published: {}",
            unpublished.join(", ")
        ));
    }
    if let Some(error) = selection.error() {
        lines.push(error.to_owned());
    }

    // A tall footer (a probe tally, an error) can leave no room for a cut mark;
    // the cursor row and the footer matter more, so the marks go first.
    let allowed = rows.saturating_sub(1).max(1);
    while lines.len() > allowed {
        match lines.iter().position(|line| line == "  …") {
            Some(index) => {
                lines.remove(index);
            }
            None => break,
        }
    }
    // Then the help and the count give way — a longer line each than the ones
    // that stay, and nothing a reader needs to make the next key press.
    for optional in [HELP, count.as_str()] {
        if lines.len() <= allowed {
            break;
        }
        if let Some(index) = lines.iter().position(|line| line == optional) {
            lines.remove(index);
        }
    }

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
fn row(
    selection: &Selection,
    index: usize,
    preset: &Preset,
    probes: &Probes,
    width: usize,
    now: jiff::Timestamp,
) -> String {
    let cursor = if index == selection.cursor() {
        '>'
    } else {
        ' '
    };
    let tick = if selection.is_chosen(index) { 'x' } else { ' ' };
    // The default bundle path is what `install` writes; a configured path is not
    // known here, and a preset that is pinned here is pinned there.
    let anchor = anchors::dir().join(format!("{}.pem", preset.name));
    let trust = trust(
        preset,
        anchors::roots(&anchor).as_deref(),
        now,
        probes.cell(index),
    );
    // A narrow terminal cuts the cell, not the transport: only the space that
    // always trails the cell is reserved on a row that carries none, and at
    // least one character of the cell survives so a narrow frame is not blank
    // there.
    let trailing = if preset.insecure_http {
        TRANSPORT_WIDTH
    } else {
        1
    };
    let trust_width = TRUST_WIDTH
        .min(width.saturating_sub(ROW_PREFIX_WIDTH + NAME_WIDTH + trailing))
        .max(1);
    format!(
        " {cursor} [{tick}] {:>2}  {:<NAME_WIDTH$} {:<trust_width$} {}",
        index + 1,
        fit(preset.name, NAME_WIDTH),
        fit(&trust, trust_width),
        if preset.insecure_http { "http" } else { "" },
    )
}

/// The trust column: `pin <YYYY-MM-DD>` for a pinned root, `pin expires
/// <YYYY-MM-DD>` when that day is close, `EXPIRED` once none of the bundle's
/// roots is valid at `now`, `tofu` without a published root, and `pin -` for one
/// that is not pinned here.
///
/// A pin always wins over the probe, because the local bundle is what a seal is
/// checked against. What the probe found is then a second fact: a served root
/// the bundle does not hold appends ` !`, the rotation signal, instead of
/// replacing the pinned date. A failed or unpublished probe marks nothing.
///
/// Only a row with no root in the bundle shows the cell: `fetch [expires ]
/// <date>`, `fetch EXPIRED`, `?` for a failed or unpublished probe, and `…`
/// while it is pending. `fetch` is a word of its own so a probed date is never
/// mistaken for a pinned one.
///
/// The verdict leads the date instead of trailing it in parentheses: the column
/// is narrow and cut, and `expires 2027-01-01` keeps both the word and the day
/// readable where `2027-01-01 (expi…` loses the day first.
///
/// The local bundle is read first, because for a preset that publishes no root
/// it is the only copy: such an authority is exactly where a hidden date hurts.
/// The date is what a reader weighs a rotation by, so it sits where the choice
/// is made — and it is the newest live root's, since a bundle's order is
/// append order and not date order.
fn trust(
    preset: &Preset,
    roots: Option<&[anchors::RootRow]>,
    now: jiff::Timestamp,
    cell: Cell,
) -> String {
    let roots = roots.filter(|roots| !roots.is_empty());
    if let Some(roots) = roots {
        let mut pinned = if roots
            .iter()
            .all(|root| anchors::expired(&root.not_after, now))
        {
            "EXPIRED".to_owned()
        } else {
            match looming(roots, now) {
                Some(root) => match anchors::expiry_label(&root.not_after, now) {
                    "(expires soon)" => format!("pin expires {}", root.not_after),
                    _ => format!("pin {date}", date = root.not_after),
                },
                None => "EXPIRED".to_owned(),
            }
        };
        if let Cell::Known(cached) = cell
            && !roots
                .iter()
                .any(|root| root.fingerprint == cached.fingerprint)
        {
            pinned.push_str(" !");
        }
        return pinned;
    }
    match cell {
        Cell::Known(cached) => served(&cached, now),
        Cell::Unpublished | Cell::Failed => "?".to_owned(),
        Cell::Pending => "…".to_owned(),
        // Nothing was asked: the fallback keeps the line prompt's wording.
        Cell::Idle => {
            if preset.fingerprints.is_empty() {
                "tofu".to_owned()
            } else {
                "pin -".to_owned()
            }
        }
    }
}

/// A served date, in the same verdict-leads-the-day shape as a pin.
fn served(cached: &probe::Cached, now: jiff::Timestamp) -> String {
    if anchors::expired(&cached.not_after, now) {
        return "fetch EXPIRED".to_owned();
    }
    match anchors::expiry_label(&cached.not_after, now) {
        "(expires soon)" => format!("fetch expires {}", cached.not_after),
        _ => format!("fetch {date}", date = cached.not_after),
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

/// Whether `cached` still names a root `preset` publishes.
///
/// The comparison is by digest width: the cache always holds the SHA-256 that
/// [`anchors::fingerprint`] wrote, while most presets publish only a SHA-1, and
/// a 64-character digest can never equal a 40-character one. The cached value is
/// normalized first (colons stripped, lowercased) because a hand-edited or older
/// entry need not be in the bare lowercase form the cache itself writes.
///
/// A preset that publishes nothing at the cached width cannot be checked at all,
/// so the entry is accepted and the week-long [`probe::TTL`] is what bounds an
/// unchecked date. A preset that does publish at that width rejects anything
/// else: a rotation inside the TTL would otherwise show a date for a root the
/// row no longer claims, and an unpinned row has no `!` to say so.
fn still_published(preset: &Preset, cached: &probe::Cached) -> bool {
    let bare = |value: &str| value.replace(':', "").to_ascii_lowercase();
    let served = bare(&cached.fingerprint);
    let at_width: Vec<String> = preset
        .fingerprints
        .iter()
        .map(|fingerprint| bare(fingerprint))
        .filter(|fingerprint| fingerprint.len() == served.len())
        .collect();
    if at_width.is_empty() {
        return true;
    }
    at_width.contains(&served)
}

/// The opening snapshot and the indices a worker still has to fetch.
///
/// A fresh cache entry shows at once and is not queued; everything else waits
/// for its first answer. A preset that publishes no root is never probed: with
/// nothing to match a reply can only be `Unpublished`, and the row's own `tofu`
/// wording says more. A cached root the preset no longer publishes is treated
/// as a miss, so the row is asked again instead of showing a rotated date.
#[must_use]
pub fn seed(presets: &[Preset], now: jiff::Timestamp) -> (Probes, Vec<usize>) {
    let mut probes = Probes::pending(presets.len());
    let mut missing = Vec::new();
    for (index, preset) in presets.iter().enumerate() {
        if preset.fingerprints.is_empty() {
            probes.set(index, Cell::Idle);
        } else if let Some(cached) =
            probe::cached(preset.name, now).filter(|cached| still_published(preset, cached))
        {
            probes.set(index, Cell::Known(cached));
        } else {
            missing.push(index);
        }
    }
    (probes, missing)
}

/// The complement of `missing`: the rows a worker must not queue.
///
/// [`seed`] names what to fetch, while [`probe::Prober::start`] takes what to
/// leave alone — the two are easy to hand over the wrong way round.
pub(crate) fn skip_of(missing: &[usize], count: usize) -> Vec<usize> {
    (0..count)
        .filter(|index| !missing.contains(index))
        .collect()
}

/// Take every finished answer into `probes`, answering whether one arrived.
///
/// A refresh can make a row answer twice, so the index is the key and the last
/// answer is the one left in the table. Every surface that puts answers into a
/// table goes through [`take`], so the cell vocabulary cannot drift between
/// them — between keys it is fed by [`absorb`], and once at the end by
/// [`probe::Prober::settle`]'s returned results.
pub(crate) fn absorb(prober: &probe::Prober, probes: &mut Probes) -> bool {
    take(probes, prober.drain())
}

/// Write `results` into `probes`, answering whether any arrived.
fn take(probes: &mut Probes, results: Vec<(usize, probe::Served)>) -> bool {
    if results.is_empty() {
        return false;
    }
    for (index, served) in results {
        probes.set(
            index,
            match served {
                probe::Served::Known(cached) => Cell::Known(cached),
                probe::Served::Unpublished => Cell::Unpublished,
                probe::Served::Failed => Cell::Failed,
            },
        );
    }
    true
}

/// Requeue the probed rows and mark them waiting.
///
/// Nothing is dropped up front: the requeue forces the fetch, so the old entry
/// only matters when the answer is not [`probe::Served::Known`]. A failed or
/// unpublished reply therefore leaves the previous entry in place, still stamped
/// with its old fetch time, and the TTL ages it out on its own — a refresh run
/// into a network blip does not cost the dates the next run would show. The cell
/// still goes [`Cell::Pending`] so the frame shows the work; after a failure it
/// stays `?` for this run.
///
/// `presets` is the table the prober was started on, so its indices are the
/// queue's. An idle row publishes nothing, so it is skipped rather than being
/// turned into a question mark it cannot answer.
///
/// Drain order is not round order: this does not supersede an answer already in
/// flight, so a slow earlier reply can land after the fresh one and stick. A
/// refresh makes the newest answer likely, not certain.
fn refresh(presets: &[Preset], probes: &mut Probes, prober: &probe::Prober) {
    let mut idle = Vec::new();
    for (index, preset) in presets.iter().enumerate() {
        if preset.fingerprints.is_empty() {
            idle.push(index);
        } else {
            probes.set(index, Cell::Pending);
        }
    }
    prober.refresh(&idle);
}

/// Drive the UI until a key saves or aborts.
///
/// `None` when the terminal cannot be put into raw mode; the caller then falls
/// back to the line prompt, whose snapshot ([`Probes::idle`]) never probes.
///
/// The first frame is painted from the cache before any fetch is started, and
/// answers are drained between key reads; a slow or dead authority costs a
/// repaint and never the screen. A silent decisecond repaints only when an
/// answer arrived or the terminal was resized. The key that leaves waits
/// [`probe::SETTLE`] for the rows already in flight: that last frame is wiped by
/// the alternate-screen teardown moments later, so what really outlives the run
/// is the cache the workers wrote.
pub fn run(
    selection: &mut Selection,
    presets: &'static [Preset],
    probes: &mut Probes,
) -> Option<Outcome> {
    let mut terminal = Raw::open().or_else(|| {
        eprintln!("rfc3161: note: no raw terminal; falling back to the line prompt");
        None
    })?;
    let (seeded, missing) = seed(presets, jiff::Timestamp::now());
    let skip = skip_of(&missing, presets.len());
    *probes = seeded;
    let (mut rows, mut cols) = size();
    // The frame is on the screen before the first socket opens.
    terminal.paint(&frame(selection, presets, probes, rows, cols));
    let prober = probe::Prober::start(presets, probe::network_fetch(), &skip);
    loop {
        let bytes = terminal.read_key();
        let answered = absorb(&prober, probes);
        let Some(key) = parse_key(&bytes) else {
            // The only silent changes the frame shows are an answer and a resize.
            let (next_rows, next_cols) = size();
            let resized = (next_rows, next_cols) != (rows, cols);
            if resized {
                rows = next_rows;
                cols = next_cols;
            }
            if resized || answered {
                terminal.paint(&frame(selection, presets, probes, rows, cols));
            }
            continue;
        };
        (rows, cols) = size();
        if key == Key::Refresh {
            refresh(presets, probes, &prober);
            terminal.paint(&frame(selection, presets, probes, rows, cols));
            continue;
        }
        match selection.apply_key(key, presets.len()) {
            Outcome::Stay => terminal.paint(&frame(selection, presets, probes, rows, cols)),
            outcome => {
                // The key is the last one: nothing new is fetched, and the rows
                // already in flight get `SETTLE` to answer. The frame they reach
                // is wiped with the alternate screen right after, but the worker
                // wrote the cache before sending, so the next run reads it.
                // Painting has to happen before `Raw` drops and the screen goes.
                if take(probes, prober.settle()) {
                    terminal.paint(&frame(selection, presets, probes, rows, cols));
                }
                return Some(outcome);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::{Cell, Key, Outcome, Probes, Selection, frame, parse_key};
    use crate::cmd::probe::Cached;
    use git_time_core::presets;

    /// The captured FreeTSA root, which is the one fixture a preset publishes.
    const FREETSA_ROOT: &[u8] =
        include_bytes!("../../../git-time-core/tests/fixtures/freetsa_root.pem");

    fn picked() -> Selection {
        Selection::default()
    }

    /// A selection with the cursor pressed down `index` rows.
    fn picked_at(index: usize) -> Selection {
        let mut selection = picked();
        for _ in 0..index {
            press(&mut selection, Key::Down);
        }
        selection
    }

    fn press(selection: &mut Selection, key: Key) -> Outcome {
        selection.apply_key(key, presets::PRESETS.len())
    }

    /// A served answer with a fingerprint no bundle here holds.
    fn cached(not_after: &str) -> Cached {
        cached_of(not_after, "aa".repeat(32))
    }

    fn cached_of(not_after: &str, fingerprint: impl ToString) -> Cached {
        Cached {
            not_after: not_after.to_owned(),
            fingerprint: fingerprint.to_string(),
        }
    }

    /// An idle table the given `cells` are set in, as the driver would.
    fn probes_with(cells: &[(usize, Cell)]) -> Probes {
        let mut probes = Probes::idle(presets::PRESETS.len());
        for (index, cell) in cells {
            probes.set(*index, cell.clone());
        }
        probes
    }

    /// The cursor row of a frame with the cursor on `index`, uncut.
    fn rendered(probes: &Probes, index: usize) -> String {
        frame(&picked_at(index), &presets::PRESETS, probes, 24, 80)
            .lines()
            .find(|line| line.trim_start().starts_with("> ["))
            .expect("the cursor row")
            .to_owned()
    }

    /// The FreeTSA root's fingerprint in `anchors::fingerprint` spelling.
    fn freetsa_fp() -> String {
        let text = std::str::from_utf8(FREETSA_ROOT).expect("PEM is text");
        let body = text
            .split_once("-----\n")
            .and_then(|(_, rest)| rest.split_once("\n-----END"))
            .map(|(body, _)| body.replace('\n', ""))
            .expect("a PEM block");
        super::anchors::fingerprint(&BASE64.decode(body).expect("base64"))
    }

    /// Pin the FreeTSA fixture here, probe freetsa with `cell` and return its
    /// row. The caller holds the `XDG_CONFIG_HOME` lock across the frame.
    fn pinned_and_probed(cell: Cell) -> String {
        let xdg = tempfile::TempDir::new().expect("xdg dir");
        unsafe { std::env::set_var("XDG_CONFIG_HOME", xdg.path()) };
        let anchors = xdg.path().join("git-time/anchors");
        std::fs::create_dir_all(&anchors).expect("anchors dir");
        std::fs::write(anchors.join("freetsa.pem"), FREETSA_ROOT).expect("pin a root");
        let index = presets::PRESETS
            .iter()
            .position(|preset| preset.name == "freetsa")
            .expect("the freetsa row");
        rendered(&probes_with(&[(index, cell)]), index)
    }

    /// An empty `XDG_CONFIG_HOME` held for the test, so a row that has a bundle
    /// on the machine running the suite still renders as unpinned. The lock is
    /// returned first so it is dropped before the directory it guards.
    fn empty_home() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let lock = crate::cmd::probe::tests::xdg_lock();
        let xdg = tempfile::TempDir::new().expect("xdg dir");
        unsafe { std::env::set_var("XDG_CONFIG_HOME", xdg.path()) };
        (lock, xdg)
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
    fn the_constructor_dedupes_and_sorts_a_seed() {
        let mut selection = Selection::ticked(&[2, 0, 2]);
        assert_eq!(selection.chosen(), [0, 2]);
        // `a` still takes all and `n` still clears the seeded ticks.
        press(&mut selection, Key::All);
        assert_eq!(selection.chosen().len(), presets::PRESETS.len());
        press(&mut selection, Key::None);
        assert!(selection.chosen().is_empty());
        assert_eq!(press(&mut selection, Key::Enter), Outcome::Save(Vec::new()));
    }

    #[test]
    fn the_frame_marks_the_seeded_rows() {
        let rendered = frame(
            &Selection::ticked(&[0, 2]),
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            24,
            80,
        );
        assert!(rendered.contains("[x]  1"), "{rendered}");
        assert!(rendered.contains("[x]  3"), "{rendered}");
        assert!(rendered.contains("[ ]  2"), "{rendered}");
        assert!(rendered.contains("2 selected"), "{rendered}");
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
        let rendered = frame(
            &selection,
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            40,
            80,
        );
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
        eprint!(
            "{}",
            frame(
                &selection,
                &presets::PRESETS,
                &Probes::idle(presets::PRESETS.len()),
                24,
                80
            )
        );
    }

    #[test]
    fn the_frame_shows_the_trust_tier_and_the_help() {
        let rendered = frame(
            &picked(),
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            24,
            80,
        );
        assert!(rendered.contains("pin "), "{rendered}");
        // No built-in row is TOFU now, so the table shows the published tier;
        // the other two tiers come from constructed presets, so this does not
        // depend on which anchors the machine running the suite happens to have.
        assert!(!rendered.contains("tofu"), "{rendered}");
        let unpublished = frame(&picked(), &[unpublished()], &Probes::idle(1), 24, 80);
        assert!(unpublished.contains("tofu"), "{unpublished}");
        let missing = frame(
            &picked(),
            &[published_without_bundle()],
            &Probes::idle(1),
            24,
            80,
        );
        assert!(missing.contains("pin -"), "{missing}");
        assert!(rendered.contains(" http"), "{rendered}");
        assert!(rendered.contains("0 selected"), "{rendered}");
        assert!(rendered.contains("enter save"), "{rendered}");
        assert!(rendered.contains("> _"), "{rendered}");
        // Nothing was probed, so neither tally line is drawn.
        assert!(!rendered.contains("probe failed:"), "{rendered}");
        assert!(
            !rendered.contains("served root not published:"),
            "{rendered}"
        );
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
                let rendered = frame(
                    &selection,
                    &presets::PRESETS,
                    &Probes::idle(presets::PRESETS.len()),
                    24,
                    cols,
                );
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
            let rendered = frame(
                &selection,
                &presets::PRESETS,
                &Probes::idle(presets::PRESETS.len()),
                rows,
                80,
            );
            // One line short of the bottom, or a full screen scrolls.
            assert!(
                rendered.lines().count() < rows,
                "{} lines for {rows} rows",
                rendered.lines().count()
            );
            assert!(!rendered.ends_with('\n'), "no trailing line at {rows} rows");
        }

        // Everything the footer can hold — an error, a failure and an
        // unpublished row — still has to leave the last row free at every size,
        // so the help and the count give way rather than overflow.
        let probes = probes_with(&[(0, Cell::Failed), (6, Cell::Unpublished)]);
        let mut selection = picked();
        press(&mut selection, Key::Typed('9'));
        press(&mut selection, Key::Typed('9'));
        assert!(matches!(press(&mut selection, Key::Enter), Outcome::Stay));
        assert!(selection.error().is_some(), "the premise: an error line");
        for rows in 7..=24 {
            let rendered = frame(&selection, &presets::PRESETS, &probes, rows, 80);
            // `<= rows - 1`, spelled as clippy wants it.
            assert!(
                rendered.lines().count() < rows,
                "{} lines for {rows} rows",
                rendered.lines().count()
            );
        }
        // What gives way is the help and the count, in that order — never the
        // URL, the prompt, the tallies or the error.
        let tight = frame(&selection, &presets::PRESETS, &probes, 7, 80);
        for kept in [
            "url: ",
            "> 99_",
            "probe failed: 1",
            "served root not published: ",
            "not a selection",
        ] {
            assert!(tight.contains(kept), "`{kept}` survives: {tight:?}");
        }
        assert!(!tight.contains(" selected"), "{tight:?}");
        assert!(!tight.contains("enter save"), "{tight:?}");
    }

    #[test]
    fn the_cursor_row_and_the_footer_are_always_rendered() {
        // At the top nothing is cut above.
        let rendered = frame(
            &picked(),
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            8,
            80,
        );
        let lines = shards(&rendered);
        assert!(lines[0].contains("freetsa"), "{rendered}");
        // The fingerprint itself is abbreviated; the *row* is not cut off.
        assert!(lines[0].trim_start().starts_with("> ["), "{rendered}");

        // At the last row the cursor row is there and a `…` marks the top cut.
        let mut selection = picked();
        press(&mut selection, Key::End);
        let rendered = frame(
            &selection,
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            8,
            80,
        );
        let lines = shards(&rendered);
        assert_eq!(lines[0].trim(), "…", "the top cut is marked: {rendered}");
        assert!(
            lines
                .iter()
                .any(|line| line.trim_start().starts_with("> [") && line.contains("accv")),
            "{rendered}"
        );

        // The footer is in both, the prompt unconditionally.
        for rendered in [
            frame(
                &picked(),
                &presets::PRESETS,
                &Probes::idle(presets::PRESETS.len()),
                8,
                80,
            ),
            rendered,
        ] {
            assert!(rendered.contains("selected"), "{rendered}");
            assert!(rendered.contains("> _"), "{rendered}");
            assert!(rendered.contains("url: "), "{rendered}");
        }
    }

    #[test]
    fn long_fields_are_cut_with_an_ellipsis_and_keep_the_columns_aligned() {
        let row_of = |presets: &[presets::Preset]| {
            let rendered = frame(&picked(), presets, &Probes::idle(presets.len()), 24, 60);
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
            let rendered = frame(
                &selection,
                &presets::PRESETS,
                &Probes::idle(presets::PRESETS.len()),
                12,
                40,
            );
            assert!(rendered.lines().count() <= 11, "{rendered:?}");
            for line in rendered.lines() {
                assert_ne!(line.chars().count(), 40, "a full line wraps: {line:?}");
                assert!(line.chars().count() < 40, "{line:?}");
            }
        }
    }

    #[test]
    fn the_last_line_is_not_terminated_and_nothing_doubles_the_carriage_return() {
        let rendered = frame(
            &picked(),
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            24,
            80,
        );
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
        assert!(frame(&selection, &[], &Probes::idle(0), 24, 80).contains("url: "));
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

    /// A preset that publishes no root: what a hand-added, unmeasured authority
    /// looks like. No built-in row is in that position any more, so the table
    /// cannot supply one; the TOFU display path still has to be covered.
    fn unpublished() -> presets::Preset {
        presets::Preset {
            name: "unpublished",
            url: "http://tsa.example/tsr",
            anchor_url: "http://tsa.example/tsr",
            chain: &[],
            alg: "sha256",
            policy: None,
            fingerprints: &[],
            insecure_http: true,
            curated: false,
        }
    }

    /// A preset that publishes a root but has none pinned locally: the `pin -`
    /// tier. Constructed for the same reason as [`unpublished`], so the
    /// assertion does not depend on what is pinned on the machine. The name is
    /// its own so `frame()` cannot find a stray `unpublished.pem` of a reader.
    fn published_without_bundle() -> presets::Preset {
        presets::Preset {
            name: "published-but-local",
            fingerprints: &["AA:BB:CC"],
            ..unpublished()
        }
    }

    #[test]
    fn unpublished_is_tofu() {
        assert!(unpublished().fingerprints.is_empty());
        assert_eq!(published_without_bundle().fingerprints, ["AA:BB:CC"]);
    }

    #[test]
    fn the_trust_column_says_the_pin_and_its_date() {
        let preset = presets::find("digicert").expect("a pinned preset");
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2030-01-01")]),
                at(2026, 1, 1),
                Cell::Idle
            ),
            "pin 2030-01-01"
        );
        // The verdict leads the day, so a cut column keeps both readable.
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2027-01-01")]),
                at(2026, 12, 1),
                Cell::Idle
            ),
            "pin expires 2027-01-01"
        );
    }

    #[test]
    fn an_authority_without_a_live_root_says_expired() {
        let preset = presets::find("digicert").expect("a pinned preset");
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2020-01-01"), root("2020-02-01")]),
                at(2026, 1, 1),
                Cell::Idle
            ),
            "EXPIRED"
        );
        // One live root is enough, and the newest root's day is the one shown.
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2020-01-01"), root("2030-01-01")]),
                at(2026, 1, 1),
                Cell::Idle
            ),
            "pin 2030-01-01"
        );
        // Bundle order is append order, not date order: a retired root appended
        // behind a live one must not become the date the reader weighs.
        assert_eq!(
            super::trust(
                preset,
                Some(&[root("2030-01-01"), root("2020-02-01")]),
                at(2026, 1, 1),
                Cell::Idle
            ),
            "pin 2030-01-01"
        );
    }

    /// A pinned, live root renders as `pin <day>` in the trust column, and the
    /// column keeps the width `TRUST_WIDTH` gives it.
    #[test]
    fn the_frame_prints_a_pinned_date_in_the_trust_column() {
        // `XDG_CONFIG_HOME` is process-wide: an unlocked test elsewhere could
        // repoint it between `set_var` and `frame()`.
        let _xdg = crate::cmd::probe::tests::xdg_lock();
        let xdg = tempfile::TempDir::new().expect("xdg dir");
        unsafe { std::env::set_var("XDG_CONFIG_HOME", xdg.path()) };
        let anchors = xdg.path().join("git-time/anchors");
        std::fs::create_dir_all(&anchors).expect("anchors dir");
        // The fixture root closes in 2041, so the date is a live one.
        std::fs::write(
            anchors.join("digicert.pem"),
            include_bytes!("../../../git-time-core/tests/fixtures/freetsa_root.pem"),
        )
        .expect("pin a root");

        let preset = &presets::PRESETS[1..2]; // digicert: published, pinned, http
        let rendered = frame(&picked(), preset, &Probes::idle(preset.len()), 24, 80);
        let line = shards(&rendered)
            .into_iter()
            .find(|line| line.trim_start().starts_with("> ["))
            .expect("the cursor row")
            .to_owned();
        assert!(line.contains("pin 2041-03-07"), "{line:?}");
        // `http` starts one space past the column, which is `TRUST_WIDTH` wide.
        let column = |marker: &str| {
            line.find(marker)
                .unwrap_or_else(|| panic!("`{marker}` in {line:?}"))
        };
        assert_eq!(
            column("http") - column("pin "),
            super::TRUST_WIDTH + 1,
            "{line:?}"
        );
    }

    #[test]
    fn an_unpublished_preset_without_a_bundle_stays_tofu() {
        let preset = unpublished();
        assert!(preset.fingerprints.is_empty(), "the premise: no pin");
        assert_eq!(
            super::trust(&preset, None, at(2026, 1, 1), Cell::Idle),
            "tofu"
        );
    }

    /// The local bundle is the only copy of an unpublished root, so the date
    /// and its verdict have to be reachable for exactly that preset too.
    #[test]
    fn a_pinned_unpublished_preset_says_its_date() {
        let preset = unpublished();
        assert_eq!(
            super::trust(
                &preset,
                Some(&[root("2030-01-01")]),
                at(2026, 1, 1),
                Cell::Idle
            ),
            "pin 2030-01-01"
        );
        assert_eq!(
            super::trust(
                &preset,
                Some(&[root("2020-01-01")]),
                at(2026, 1, 1),
                Cell::Idle
            ),
            "EXPIRED"
        );
    }

    #[test]
    fn a_published_root_that_is_not_pinned_here_has_no_date() {
        let preset = presets::find("digicert").expect("a pinned preset");
        assert_eq!(
            super::trust(preset, None, at(2026, 1, 1), Cell::Idle),
            "pin -"
        );
        assert_eq!(
            super::trust(preset, Some(&[]), at(2026, 1, 1), Cell::Idle),
            "pin -"
        );
    }

    #[test]
    fn an_unpinned_row_shows_the_served_date() {
        let _home = empty_home();
        let probes = probes_with(&[(3, Cell::Known(cached("2099-01-01")))]);
        let line = rendered(&probes, 3);
        assert!(line.contains("fetch 2099-01-01"), "{line:?}");
    }

    /// The near wording lives in `served`, so a fixed `now` keeps this from
    /// expiring with the calendar; the frame reaching it is covered above.
    #[test]
    fn a_near_served_date_keeps_the_word_and_the_day() {
        assert_eq!(
            super::served(&cached("2027-01-01"), at(2026, 12, 1)),
            "fetch expires 2027-01-01"
        );
        assert_eq!(
            super::served(&cached("2020-01-01"), at(2026, 12, 1)),
            "fetch EXPIRED"
        );
    }

    #[test]
    fn a_failed_or_unpublished_probe_is_a_question_mark() {
        let _home = empty_home();
        for cell in [Cell::Failed, Cell::Unpublished] {
            let line = rendered(&probes_with(&[(3, cell)]), 3);
            assert!(line.contains(" ? "), "{line:?}");
        }
    }

    #[test]
    fn a_pending_row_knows_nothing_yet() {
        let _home = empty_home();
        let line = rendered(&probes_with(&[(3, Cell::Pending)]), 3);
        assert!(line.contains(" … "), "{line:?}");
    }

    #[test]
    fn an_idle_row_keeps_the_old_wording() {
        let _home = empty_home();
        let line = rendered(&probes_with(&[(3, Cell::Idle)]), 3);
        assert!(line.contains("pin -"), "{line:?}");
    }

    #[test]
    fn a_served_root_the_bundle_lacks_marks_the_pin() {
        let _xdg = crate::cmd::probe::tests::xdg_lock();
        // FreeTSA's root is pinned (2041-03-07); the probe names a root the
        // bundle does not hold, so the pin is marked.
        let line = pinned_and_probed(Cell::Known(cached_of("2035-02-09", "cc".repeat(32))));
        assert!(line.contains("pin 2041-03-07 !"), "{line:?}");
    }

    #[test]
    fn a_served_root_the_bundle_holds_stays_quiet() {
        let _xdg = crate::cmd::probe::tests::xdg_lock();
        let line = pinned_and_probed(Cell::Known(cached_of("2041-03-07", freetsa_fp())));
        assert!(!line.contains('!'), "{line:?}");
    }

    #[test]
    fn a_failed_probe_does_not_mark_a_pin() {
        let _xdg = crate::cmd::probe::tests::xdg_lock();
        let line = pinned_and_probed(Cell::Failed);
        assert!(line.contains("pin 2041-03-07"), "{line:?}");
        assert!(!line.contains('!'), "{line:?}");
    }

    #[test]
    fn the_footer_counts_failures_and_names_unpublished_rows() {
        let probes = probes_with(&[(3, Cell::Failed), (6, Cell::Unpublished)]);
        let out = frame(&picked(), &presets::PRESETS, &probes, 24, 80);
        assert!(out.contains("probe failed: 1"), "{out}");
        assert!(out.contains("served root not published: "), "{out}");
        assert!(out.contains("globalsign-r6"), "{out}");
    }

    #[test]
    fn a_narrow_terminal_cuts_the_cell_not_the_transport() {
        let _home = empty_home();
        let probes = probes_with(&[(1, Cell::Known(cached("2099-01-01")))]);
        let out = frame(&picked_at(1), &presets::PRESETS, &probes, 24, 40);
        for line in out.lines() {
            assert!(line.chars().count() <= 39, "{line:?}");
        }
        let row = out
            .lines()
            .find(|line| line.contains("digicert"))
            .expect("the cursor row");
        assert!(row.ends_with("http"), "{row:?}");
    }

    /// One column narrower than the row's fixed parts: the cell saturates at one
    /// character instead of eating the transport by one.
    #[test]
    fn a_very_narrow_row_keeps_the_transport() {
        let _home = empty_home();
        let probes = probes_with(&[(1, Cell::Known(cached("2099-01-01")))]);
        let out = frame(&picked_at(1), &presets::PRESETS, &probes, 24, 36);
        let row = out
            .lines()
            .find(|line| line.contains("digicert"))
            .expect("the cursor row");
        assert!(row.chars().count() <= 35, "{row:?}");
        assert!(row.ends_with("ht…"), "{row:?}");
    }

    /// The help is the widest fixed line and sits one character inside an
    /// 80-column frame's edge: a longer one would lose its tail, `q abort`
    /// included, without a test noticing.
    #[test]
    fn the_help_line_is_not_cut() {
        let rendered = frame(
            &picked(),
            &presets::PRESETS,
            &Probes::idle(presets::PRESETS.len()),
            24,
            80,
        );
        let help = rendered
            .lines()
            .find(|line| line.contains("enter save"))
            .expect("the help line");
        assert_eq!(help, super::HELP);
        assert!(help.chars().count() < 80, "{}", help.chars().count());
    }

    #[test]
    fn r_asks_for_a_refetch() {
        assert_eq!(parse_key(b"r"), Some(Key::Refresh));
        assert_eq!(press(&mut picked(), Key::Refresh), Outcome::Stay);
    }

    /// The row of `name`, the lookup the seed tests key on.
    fn index_of(name: &str) -> usize {
        presets::PRESETS
            .iter()
            .position(|preset| preset.name == name)
            .expect("the preset row")
    }

    /// A shared `XDG_CONFIG_HOME` with an empty probe cache.
    ///
    /// Other tests' workers fill the same directory concurrently, so the cache
    /// is emptied of every row before a test seeds one of its own.
    fn empty_cache() -> std::sync::MutexGuard<'static, ()> {
        let lock = crate::cmd::probe::tests::xdg_lock();
        crate::cmd::probe::tests::xdg();
        for preset in &presets::PRESETS {
            let _ = super::probe::forget(preset.name);
        }
        lock
    }

    /// The SHA-256 a preset publishes, in the bare lowercase form the worker
    /// writes: `anchors::fingerprint` abbreviates to exactly that.
    fn cached_sha256(preset: &str) -> String {
        presets::find(preset)
            .expect("the preset")
            .fingerprints
            .iter()
            .map(|fingerprint| fingerprint.replace(':', "").to_ascii_lowercase())
            .find(|fingerprint| fingerprint.len() == 64)
            .expect("a published SHA-256")
    }

    /// A bare lowercase SHA-256 no preset publishes.
    fn unknown_sha256() -> String {
        "bb".repeat(32)
    }

    #[test]
    fn a_fresh_cache_entry_seeds_a_known_cell_and_is_not_queued() {
        let _cache = empty_cache();
        let freetsa = index_of("freetsa");
        let _ = super::probe::store(
            "freetsa",
            &cached_of("2035-02-09", cached_sha256("freetsa")),
            jiff::Timestamp::now(),
        );
        let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
        assert!(matches!(probes.cell(freetsa), Cell::Known(_)));
        assert!(!missing.contains(&freetsa));
        assert!(missing.contains(&index_of("aped")));
    }

    /// A SHA-1-only preset can never validate the SHA-256 the cache holds, so
    /// the entry is shown rather than refetched on every launch.
    #[test]
    fn a_sha1_only_preset_accepts_the_sha256_the_cache_holds() {
        let _cache = empty_cache();
        let certum = index_of("certum");
        let preset = presets::find("certum").expect("the preset");
        assert!(
            preset
                .fingerprints
                .iter()
                .all(|value| value.replace(':', "").len() != 64),
            "the premise: certum publishes no SHA-256"
        );
        let _ = super::probe::store(
            "certum",
            &cached_of("2035-02-09", unknown_sha256()),
            jiff::Timestamp::now(),
        );
        let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
        assert!(matches!(probes.cell(certum), Cell::Known(_)));
        assert!(!missing.contains(&certum));
    }

    #[test]
    fn a_cached_root_the_preset_no_longer_publishes_is_asked_again() {
        let _cache = empty_cache();
        let freetsa = index_of("freetsa");
        // A SHA-256, but not the one freetsa publishes: the table rotated
        // inside the TTL.
        let _ = super::probe::store(
            "freetsa",
            &cached_of("2035-02-09", unknown_sha256()),
            jiff::Timestamp::now(),
        );
        let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
        assert!(matches!(probes.cell(freetsa), Cell::Pending));
        assert!(
            missing.contains(&freetsa),
            "the stale entry is fetched again"
        );
    }

    #[test]
    fn presets_without_a_published_root_seed_idle_and_are_not_queued() {
        // No built-in row has an empty list today; assert on the shipped table so
        // a future tofu row does not start probing pointlessly.
        let _cache = empty_cache();
        let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
        for (index, preset) in presets::PRESETS.iter().enumerate() {
            if preset.fingerprints.is_empty() {
                assert!(matches!(probes.cell(index), Cell::Idle));
                assert!(!missing.contains(&index));
            }
        }
    }

    /// Poll `prober` until nothing is queued or in flight.
    ///
    /// `pending` counts in-flight rows too, so zero means every reply is
    /// already in the channel.
    fn wait(prober: &super::probe::Prober) {
        for _ in 0..250 {
            if prober.pending() == 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("the queue drains");
    }

    #[test]
    fn a_prober_skips_the_rows_the_seed_already_answered() {
        let _cache = empty_cache();
        let _ = super::probe::store(
            "certum",
            &cached_of("2035-02-09", unknown_sha256()),
            jiff::Timestamp::now(),
        );
        let (_, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
        let skip = super::skip_of(&missing, presets::PRESETS.len());
        assert!(skip.contains(&index_of("certum")), "a fresh entry is kept");
        assert!(
            !skip.contains(&index_of("aped")),
            "an unknown row is fetched"
        );
    }

    #[test]
    fn a_drained_answer_repaints_and_the_last_answer_wins() {
        let _cache = empty_cache();
        let index = index_of("freetsa");
        let cached_row = index_of("certum");
        // One row carries a cache entry, so the table `seed` hands over is the
        // one under test — a seeded `Known` has to survive the drain and only
        // the answers' own indices may change. The value is the 64-character
        // SHA-256 the worker writes; certum publishes only a SHA-1, so the
        // width rule is what accepts it.
        let _ = super::probe::store(
            "certum",
            &cached_of("2035-02-09", unknown_sha256()),
            jiff::Timestamp::now(),
        );
        // The handover `run` performs. Every other row answers prose except
        // FreeTSA's, whose reply flips from the fixture to prose before the
        // refresh: the second drain has to overwrite the `Known` the first left
        // for that same index.
        let (mut probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
        let skip = super::skip_of(&missing, presets::PRESETS.len());
        let freetsa = presets::PRESETS[index].url;
        let known = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let fetch: super::probe::Fetch = {
            let known = Arc::clone(&known);
            Arc::new(move |url, _| {
                if url == freetsa && known.load(std::sync::atomic::Ordering::Relaxed) {
                    Ok::<Vec<u8>, String>(FREETSA_ROOT.to_vec())
                } else {
                    Ok::<Vec<u8>, String>(b"<html>not a certificate</html>".to_vec())
                }
            })
        };
        let prober = super::probe::Prober::start(&presets::PRESETS, fetch, &skip);
        let before = probes.clone();
        wait(&prober);
        assert!(
            super::absorb(&prober, &mut probes),
            "the answer changed the frame"
        );
        assert!(matches!(probes.cell(index), Cell::Known(_)));
        // The seeded cell kept its date, and no other row moved.
        assert!(
            matches!(probes.cell(cached_row), Cell::Known(found) if found.not_after == "2035-02-09"),
            "{:?}",
            probes.cell(cached_row)
        );
        // Every row the worker left alone is exactly as the seed left it.
        for untouched in &skip {
            assert_eq!(
                probes.cell(*untouched),
                before.cell(*untouched),
                "row {untouched}"
            );
        }

        known.store(false, std::sync::atomic::Ordering::Relaxed);
        prober.refresh(&skip);
        wait(&prober);
        assert!(
            super::absorb(&prober, &mut probes),
            "the newer answer repaints"
        );
        assert!(matches!(probes.cell(index), Cell::Failed));
        assert!(
            matches!(probes.cell(cached_row), Cell::Known(_)),
            "still seeded"
        );
        assert!(!super::absorb(&prober, &mut probes), "nothing left to show");
    }

    #[test]
    fn a_refresh_reasks_every_probed_row_and_leaves_tofu_alone() {
        let _cache = empty_cache();
        let certum = index_of("certum");
        let _ = super::probe::store(
            "certum",
            &cached_of("2035-02-09", unknown_sha256()),
            jiff::Timestamp::now(),
        );
        // A gate parks the workers, so no answer can replace the cells the
        // refresh writes before they are asserted.
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let fetch: super::probe::Fetch = {
            let gate = Arc::clone(&gate);
            Arc::new(move |_, _| {
                let (open, wake) = &*gate;
                let mut ready = open.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
                drop(ready);
                Ok::<Vec<u8>, String>(b"<html>not a certificate</html>".to_vec())
            })
        };
        let prober = super::probe::Prober::start(&presets::PRESETS, Arc::clone(&fetch), &[]);
        let mut probes = Probes::idle(presets::PRESETS.len());
        probes.set(certum, Cell::Known(cached("2035-02-09")));
        super::refresh(&presets::PRESETS, &mut probes, &prober);
        assert!(matches!(probes.cell(certum), Cell::Pending), "asked again");
        // Nothing is dropped up front: until a `Known` answer overwrites it, the
        // old entry survives a refresh whose replies fail.
        assert!(
            super::probe::cached("certum", jiff::Timestamp::now()).is_some(),
            "the cached answer survives the requeue"
        );

        // A preset that publishes no root would only ever answer `Unpublished`,
        // so it is not queued and keeps its own wording.
        let tofu: &'static [presets::Preset] = Box::leak(vec![unpublished()].into_boxed_slice());
        // As `run` starts it: the idle row is already skipped by the seed.
        let tofu_prober = super::probe::Prober::start(tofu, fetch, &[0]);
        let mut tofu_probes = Probes::idle(1);
        super::refresh(tofu, &mut tofu_probes, &tofu_prober);
        assert!(matches!(tofu_probes.cell(0), Cell::Idle), "tofu stays tofu");
        assert_eq!(tofu_prober.pending(), 0, "nothing was queued");
    }
}
