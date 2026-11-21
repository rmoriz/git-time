# Preset Expiry Dates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every built-in TSA preset the `notAfter` of the root it publishes, and show it as a fallback date so a preset's own expiry is visible offline and fails CI once it passes.

**Architecture:** One `Option<&'static str>` field on the `Copy` table row, filled with a measured value at release. A single precedence rule (pinned bundle, then probe, then table) is implemented in the three surfaces that show a date, with a vocabulary of its own so a table date never reads as a pin.

**Tech Stack:** Rust 2024, `jiff` for dates, `clap` for the CLI, the existing `probe` cache and `anchors::expiry_text` verdicts.

**Spec:** `docs/superpowers/specs/2026-11-21-preset-not-after-design.md`

## Global Constraints

- `Preset` stays `Copy`; the new field is `not_after: Option<&'static str>`.
- Every value is `YYYY-MM-DD`, the newest root the preset publishes — the same root whose fingerprint is last in the list.
- Precedence is absolute: local bundle, then probe cache, then the table. The table never wins over a live fact.
- The table date is display-only. A pin still prints the fetched certificate's own `notAfter`.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` clean before every commit.
- Commit messages say why; no `Co-Authored-By` trailer.
- A custom row (`presets::find(name).is_none()`) is decided by the lookup, never by the field.
- New prose in comments and docs is British sentence case, matching the files it lands in.

## Review Focus

- A served root that is newer than the last fingerprint: the date must belong to that root, and the fingerprint list must gain it in the same commit.
- A cached probe line read as a measurement: every measurement run starts with `--refresh` against a fresh `XDG_CONFIG_HOME`.
- A row the probe cannot reach (`?` after a refresh): the date is not invented, and the reason is in the commit body.
- A bundle that exists but does not parse: `roots` is `None`, so the row must keep `missing` and still may show the table date.
- A custom row that one day carries `Some`: the lookup decides, so it still reads `tofu`.

---

### Task 1: The field and every literal site

**Files:**
- Modify: `crates/git-time-core/src/presets.rs:94-151` (the struct), and each of the 21 literals at `:156-430`
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:1102-1119` (the runtime custom row), `:1936-1946`, `:1960-1963`, `:2011-2023`
- Modify: `crates/git-time-cli/src/cmd/picker.rs:1191-1203`, `:1221-1233`, `:1524-1566`, `:1628-1640`
- Modify: `crates/git-time-cli/src/cmd/probe.rs:873-886`
- Test: `crates/git-time-core/src/presets.rs` (tests module)

**Interfaces:**
- Produces: `git_time_core::presets::Preset::not_after: Option<&'static str>`, `None` on the runtime custom row and on every test literal that is not a real authority.

- [ ] **Step 1: Write the failing test**

In `crates/git-time-core/src/presets.rs`, in `mod tests`:

```rust
#[test]
fn a_table_row_can_carry_the_date_its_newest_root_expires() {
    let freetsa = find("freetsa").expect("a preset");
    assert_eq!(freetsa.not_after, Some("2041-03-07"));
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cargo test -p git-time-core presets::tests::a_table_row_can_carry_the_date_its_newest_root_expires`
Expected: FAIL — `no field 'not_after' on Preset`.

- [ ] **Step 3: Add the field**

`not_after: Option<&'static str>` on `Preset`, documented as the `notAfter` of the newest published root, `YYYY-MM-DD`, `None` when nothing is published, and with the sentence that this is the one value in the table that goes stale, so a release re-measures it.

Every literal in `presets.rs` gets `not_after: None` for now; every literal outside it gets `not_after: None` too.

- [ ] **Step 4: Run the suite**

Run: `cargo test -p git-time-core && cargo test -p git-time-cli`
Expected: PASS, `freetsa` included (its value is filled in Task 2, so set that one to `Some("2041-03-07")` now).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "presets: carry each row's newest root expiry

A table row says when its authority publishes a root and what that root
hashes to, but not when it dies, so a stale row is only found at seal
time. The field is filled by the next commit; the runtime custom row and
the fixture literals have nothing to publish and stay None."
```

### Task 2: The measured values and their guards

**Files:**
- Modify: `crates/git-time-core/src/presets.rs` (all 21 literals)
- Test: `crates/git-time-core/src/presets.rs` (tests module)

**Interfaces:**
- Consumes: `Preset::not_after` from Task 1.

- [ ] **Step 1: Write the failing tests**

```rust
/// Every row carries a date, spelled the one way the listings compare it.
#[test]
fn every_preset_carries_a_well_formed_not_after() {
    for preset in &PRESETS {
        let not_after = preset.not_after.unwrap_or_else(|| panic!("{}", preset.name));
        assert_eq!(not_after.len(), 10, "{}", preset.name);
        assert!(
            not_after.parse::<jiff::civil::Date>().is_ok(),
            "{}: {not_after}",
            preset.name
        );
    }
}

/// The canary: a root that has expired is a release decision, not a user's
/// surprise. A failure here means the row is rotated or dropped, then the
/// date is re-measured.
#[test]
fn no_preset_has_already_expired() {
    let today = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date();
    for preset in &PRESETS {
        let not_after = preset
            .not_after
            .expect("a date")
            .parse::<jiff::civil::Date>()
            .expect("a date");
        assert!(not_after > today, "{}: {not_after}", preset.name);
    }
}
```

`git-time-core` cannot call the CLI's `anchors::expired`, hence the civil-date comparison.

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p git-time-core presets::tests`
Expected: FAIL — 20 rows have no date.

- [ ] **Step 3: Measure all 21**

```bash
cargo build -p git-time-cli && d=$(mktemp -d) && git -C "$d" init -q
XDG_CONFIG_HOME="$d/xdg" target/debug/git-time --directory "$d" tsa preset list --refresh
```

Every row reports `fetch <date>`; that is the date to record. A row that reports `?` or `served root not published: <id>` has moved since the table was written: `target/debug/git-time --directory "$d" anchor fetch <anchor_url> --id <id> [--insecure-http] --accept <id>=<fingerprint it prints>`, then record both the new fingerprint and its date. Put the cause in the commit body for each row so changed. Read the cache only as a check, never as the source: `--refresh` on a fresh `XDG_CONFIG_HOME` is the measurement.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p git-time-core presets::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "presets: record when each published root expires

Measured through the endpoint or the authority's own publication, the
same way the fingerprints were. The past-date test is the point: when a
row reaches its last day the build says so instead of a user."
```

### Task 3: Show the date, weakest claim last

**Files:**
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:486-527` (`pin_state`), `:344-421` (`list`)
- Modify: `crates/git-time-cli/src/cmd/picker.rs:528-581` (`trust`), after `:594` (new `listed`)
- Test: `crates/git-time-cli/src/cmd/tsa.rs` (tests module), `crates/git-time-cli/tests/registry.rs`

**Interfaces:**
- Produces: `picker::listed(not_after: &str, now: jiff::Timestamp) -> String` — `listed EXPIRED`, `listed expires <date>`, or `listed <date>`.
- Consumes: `Preset::not_after`.

- [ ] **Step 1: Write the failing tests**

In `tsa.rs` tests, extend the missing-date tests: a preset with a date and nothing pinned reads `listed <date>`; with a live root in `roots` it reads the root's date, not the table's; with `Cell::Known` it reads the served wording; a custom row with a hypothetical `Some` still reads `tofu`.

```rust
let dated = presets::Preset { not_after: Some("2026-12-02"), ..*published };
assert_eq!(pin_state(&dated, None, Cell::Idle, false, soon), "listed 2026-12-02 (expires soon)");
assert_eq!(pin_state(&dated, Some(&roots), Cell::Failed, false, soon), "2026-12-02 (expires soon)");
assert_eq!(pin_state(&dated, None, served.clone(), false, soon), "fetch expires 2026-12-02");
assert_eq!(pin_state(&custom_dated, None, Cell::Idle, false, soon), "tofu");
```

In `registry.rs`, beside `preset_list_says_expired_for_a_dead_pinned_bundle`: with no bundle at all and no probe run, `preset list` names the table date; and with a stale pinned bundle beside it, the bundle's `EXPIRED` still wins.

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p git-time-cli pin_state && cargo test -p git-time-cli --test registry preset_list`
Expected: FAIL — the idle branch returns `-`.

- [ ] **Step 3: Implement**

`pin_state`: in the `Cell::Idle` arm, after the custom-row check and before the empty-fingerprint check, `format!("listed {}", anchors::expiry_text(preset.not_after?, now))` when `preset.not_after` is `Some`.

`trust`: the same in its `Cell::Idle` arm, through the new `listed`, which mirrors `served` with the word `listed`.

`list` (the `tsa list` text and JSON): when `roots` is `None` and the id is a preset with a date, use the table date with `expiry_text`. `missing` stays as it is, so a broken bundle still says `missing` beside the date.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p git-time-cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "presets: show a row's own expiry when nothing local answers

The bundle wins, the probe wins, the table is the last word: a fresh
machine can see that a preset is due a rotation before pinning it. The
word is 'listed', so a table date never reads as a pin or a served one."
```

### Task 4: The source in JSON, and the documents

**Files:**
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:364-395` (JSON), `crates/git-time-core/src/presets.rs:1-87` (header), `docs/manual.md:350-375`, `docs/git-time.1` (unicode date section), `docs/STATUS.md:16` and the guarantee table
- Test: `crates/git-time-cli/tests/registry.rs`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing test**

In `registry.rs`: `tsa list --json` on a configured preset with no bundle carries `"not_after_source": "preset"` and the table date; with a bundle it is `"bundle"`; a custom id with no bundle is `null`.

- [ ] **Step 2: Run it to make sure it fails**

Run: `cargo test -p git-time-cli --test registry not_after_source`
Expected: FAIL — the key is absent.

- [ ] **Step 3: Implement**

The JSON gains `not_after_source` (`bundle`, `preset`, or null) beside `not_after`. The `presets.rs` header gains the paragraph: the dates are measured at release, `preset list --refresh` shows what each authority serves, and a row within a year of expiry is rotated or dropped before the tag. `docs/manual.md` and the man page gain one sentence on the `listed` word and that re-measure step. `docs/STATUS.md` gets a release-notes bullet and a guarantee-table row.

- [ ] **Step 4: Run the suite**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: name where a date came from, and the re-measure step

JSON needs the source to be machine-readable, and a release needs to
know the table is a measurement with a shelf life rather than a fact the
build keeps true."
```
