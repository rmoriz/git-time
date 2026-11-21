# The preset table carries its roots' expiry

Short design. `presets.rs` holds 21 roots, each with a measured fingerprint and
no date. The roots expire; the table is the one place where a reader cannot see
that. This adds the `notAfter` of the newest root a preset publishes, as a
measured constant, and shows it wherever a date would otherwise be missing.

## Why

A pinned bundle and a probe both answer "when does this die" today. Neither
answers it about the *table*. Every commit costs a request per configured
authority, so a root that has reached its last year sits in the shipped list,
gets configured, and only shows up as `(expires soon)` after someone pinned it.
The fingerprint list already encodes a rotation at release time; this is the
second half of the same fact, and baking it in is what makes a stale row a
failure in CI rather than a discovery at seal time.

## Goals

- Every built-in row carries the date of the root it publishes now, as a
  `YYYY-MM-DD` constant next to the newest fingerprint.
- A row no longer says `-` when nothing is pinned: it says `listed <date>`, with
  the usual `(expires soon)` / `expired` verdict.
- The date is a fallback only. A pinned bundle beats it, a probe beats it.
- A test fails when any row's date is in the past, so the expiry reaches a
  release decision instead of a user.

## Non-goals

- No date on a custom row: it publishes nothing to measure, so it keeps `tofu`.
- No use of the date at pin time. A pin still prints the fetched certificate's
  own `notAfter`; the table is display-only.
- No new fetch, cache or timer: `tsa preset list --refresh` already asks every
  publishing authority and is the re-measure step.
- The verdicts, the probe, the quorum and the block format are untouched.

## Anti-goals

- A table date read as a pin, or as current.
- A stale date accepted quietly because the build was green last week.

## Approaches

**A — a measured date in the preset table (chosen).** Offline, instant, and it
turns the table's own expiry into a build-time fact. Costs hand-measured values
and a re-measure step.

**B — probe only.** What exists now: correct on a live terminal, `-` on the line
prompt and on a plain `preset list`, and nothing at all about a row nobody
configured.

**C — prose in `docs/manual.md`.** No struct change, but nothing to test and
nothing in the listing.

## The design

- `Preset::not_after: Option<&'static str>`, `YYYY-MM-DD`, the `notAfter` of the
  newest root the preset publishes — the same root whose fingerprint is last.
  `Some` for all 21 rows, `None` only on the runtime row `rows()` builds for a
  custom id.
- One resolver picks the date and its source: the local bundle, then the probe
  cache, then the table. `tsa list`, `tsa preset list` and the picker all read
  it through that resolver, so the three cannot disagree.
- Wording: the picker prints `listed <date>` where it prints `fetch <date>`
  today; the listings print the plain date with the usual verdict. `expired`
  keeps applying: a table date never suppresses a verdict.
- JSON gains `not_after_source` (`bundle`, `probe`, `preset`, or null) beside
  the existing `not_after`.
- The `presets.rs` header gains the paragraph: the dates are measured at release,
  `preset list --refresh` shows what each authority serves, and a row within a
  year of expiry is rotated or dropped before the tag.
- Tests: every row carries a well-formed date, no row's date is in the past, the
  bundle and the probe each win over the table, and a custom row still reads
  `tofu`.

## What is left to the builder

The 21 values themselves, measured through the existing fetch path. Where the
newest served root differs from the newest fingerprint, that is a rotation the
release has not recorded yet; it goes into both lists, newest last.
