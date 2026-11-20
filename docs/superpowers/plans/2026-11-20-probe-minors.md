# Probe and preset-listing minors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the deferred minors from the probe-dates review without changing what a probe decides or shows on a live terminal.

**Architecture:** Six small, independent cleanups around the probe cache and `tsa preset list`: one shared config-home resolver, a cache entry that only parses in the one shape the writer produces, one rendering vocabulary for both surfaces with an injected instant, a rotation marker that survives a failed refresh, a test for the frame's sub-seven-row degradation, and hermetic tests plus one man-page correction. Each task lands its own test and commit; nothing touches verification or the picker's fetch loop.

**Tech Stack:** Rust 2024, `jiff` for instants, `tempfile` for test homes, `cargo test --offline`.

**Spec:** `docs/superpowers/specs/2026-11-19-tsa-probe-dates-design.md` (binding for the cache format, the `!` marker, and the "failed refresh keeps the date" rule). Deferred items come from `/Volumes/Cache/workspaces/tsa-probe-dates/.superpowers/sdd/2026-11-19-tsa-probe-dates/progress.md`; the plan records each one rather than restating the review.

## Global Constraints

- Every `cargo` run is `--offline`.
- Tests stay hermetic: an `XDG_CONFIG_HOME` under the `probe::tests::xdg_lock()` for anything that reads `anchors/` or `probe/`, never the developer's `.config`.
- No behaviour change to a probe's verdict, the cache TTL, or verification.
- Commit messages say why; no `Co-Authored-By` trailer.
- `cargo fmt --all --check` and `cargo clippy --offline --workspace --all-targets -- -D warnings` are green before each commit.

## Review Focus

- A hand-edited or truncated cache line: must be `?` and refetched, never a wrong date or a false rotation marker.
- A cached fingerprint in a non-bare spelling (colons, uppercase): after Task 2 it must not reach a comparison at all; no comparison may normalize at read time.
- A refresh that fails: the row must keep the rotation marker and the old entry, and the next run must re-seed from it.
- A terminal shorter than seven rows: the cursor row and the prompt must survive even though the frame may reach past the bottom.
- A test that leaves global state behind (`XDG_CONFIG_HOME` at a deleted directory): must be harmless to the next test under the lock.

---

### Task 1: One config home for anchors and probe

**Files:**
- Modify: `crates/git-time-cli/src/cmd/anchors.rs:41-52`
- Modify: `crates/git-time-cli/src/cmd/probe.rs:43-54`
- Test: `crates/git-time-cli/src/cmd/probe.rs` (`mod tests`)

**Interfaces:**
- Produces: `pub fn config_home() -> PathBuf` in `anchors`, the config base without a leaf; `anchors::dir()` and `probe::dir()` keep their signatures.

- [ ] **Step 1: Write the failing test**

In `probe::tests`, next to the `xdg_lock` helpers:

```rust
#[test]
fn both_state_dirs_hang_off_one_config_home() {
    let _guard = xdg_lock();
    let base = std::path::PathBuf::from(xdg());
    unsafe { std::env::set_var("XDG_CONFIG_HOME", &base) };
    let home = crate::cmd::anchors::config_home();
    assert_eq!(home, base);
    assert_eq!(super::dir(), home.join("git-time/probe"));
    assert_eq!(crate::cmd::anchors::dir(), home.join("git-time/anchors"));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --offline -p git-time-cli both_state_dirs_hang_off_one_config_home`
Expected: FAIL to compile — no `anchors::config_home` yet.

- [ ] **Step 3: Move the base out of `anchors::dir`**

In `anchors.rs`, add above `dir`:

```rust
/// The config directory itself, `$XDG_CONFIG_HOME` or `~/.config`, with no
/// leaf. Both state directories join it, so they cannot drift apart.
#[must_use]
pub fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"))
}
```

Make `anchors::dir` `config_home().join("git-time").join("anchors")` and keep its doc. In `probe.rs`, delete the body of `dir` and call `super::anchors::config_home().join("git-time").join("probe")`, keeping both doc comments (adjust `probe::dir`'s to say the probe leaf is its own).

- [ ] **Step 4: Run the tests**

Run: `cargo test --offline -p git-time-cli`
Expected: PASS, including `both_state_dirs_hang_off_one_config_home`.

- [ ] **Step 5: Commit**

```sh
git add crates/git-time-cli/src/cmd/anchors.rs crates/git-time-cli/src/cmd/probe.rs
git commit -m "refactor: resolve the config home in one place for anchors and probe"
```

---

### Task 2: Only a bare SHA-256 entry is a cache entry

**Files:**
- Modify: `crates/git-time-cli/src/cmd/probe.rs:60-100` (`cached`)
- Modify: `crates/git-time-cli/src/cmd/picker.rs:680-712` (`still_published`, drop the local `bare`)
- Test: `crates/git-time-cli/src/cmd/probe.rs` (`mod tests`), `crates/git-time-cli/src/cmd/picker.rs` (`mod tests`)

**Interfaces:**
- `probe::cached(id, now) -> Option<Cached>` keeps its signature; it now returns `None` for any entry the worker could not have written (a non-day `not_after`, a fingerprint that is not 64 lowercase hex).
- `picker::still_published(preset, cached) -> bool` keeps its signature and compares the cached fingerprint without normalizing.

- [ ] **Step 1: Write the failing tests**

In `probe::tests`, a helper that writes one raw line, then:

```rust
#[test]
fn only_a_day_and_a_bare_sha256_parse() {
    let _guard = xdg_lock();
    let now = jiff::Timestamp::from_second(1_800_000_000).expect("instant");
    let good = "cc".repeat(32);
    let cases = [
        ("2041-03-07", good.clone(), true),
        ("2041-03-07", format!("CC:{}", good[2..].to_uppercase()), false),
        ("2041-03-07", good[..40].to_owned(), false),
        ("2041-03-07", good[..63].to_owned(), false),
        ("2041-03-07", format!("{good}0"), false),
        ("2041-03-07", "zz".repeat(32), false),
        ("07.03.2041", good, false),
    ];
    for (index, (day, fingerprint, accepted)) in cases.iter().enumerate() {
        let id = format!("shape-{index}");
        write_entry(&id, &format!("{day}\t1800000000\t{fingerprint}"));
        assert_eq!(
            super::cached(&id, now).is_some(),
            *accepted,
            "{day} {fingerprint}"
        );
    }
}
```

`write_entry` is a small test helper: create `super::dir()` and `std::fs::write(dir.join(id), line)`. (Reuse or add one; `store` cannot write a malformed line.)

In `picker::tests`, extend the seed test (`a_fresh_cache_entry_seeds_a_known_cell_and_is_not_queued` or a new one) with a malformed entry:

```rust
#[test]
fn a_malformed_entry_is_a_miss_not_a_date() {
    let _cache = empty_cache();
    std::fs::create_dir_all(super::probe::dir()).expect("probe dir");
    std::fs::write(
        super::probe::dir().join("certum"),
        format!("2041-03-07\t{}\tCC:{}\n", jiff::Timestamp::now().as_second(), "cc".repeat(32)),
    )
    .expect("entry");
    let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
    assert!(missing.contains(&index_of("certum")));
    assert!(matches!(probes.cell(index_of("certum")), Cell::Pending));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --offline -p git-time-cli only_a_day_and_a_bare_sha256_parse a_malformed_entry_is_a_miss_not_a_date`
Expected: FAIL — the colon/uppercase cases are wrongly accepted, and the malformed entry seeds `Known`.

- [ ] **Step 3: Validate in `cached`**

After splitting the three fields and the extra-field check, add:

```rust
if not_after.parse::<jiff::civil::Date>().is_err()
    || fingerprint.len() != 64
    || !fingerprint
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
{
    return None;
}
```

Update the doc: a line whose fingerprint is not 64 lowercase hex, or whose day is not a day, is stale like the rest.

- [ ] **Step 4: Drop the read-time normalizer in `still_published`**

Delete the `bare` closure for the cached value: compare `cached.fingerprint` directly, and filter preset values by `fingerprint.len() == cached.fingerprint.len()`. The published side still needs normalizing — the table spells values uppercase and colon-separated — so strip and lowercase each published value before the width filter. Adjust the doc: the cache only holds the bare lowercase spelling now, while the width differs between a SHA-1 preset value and the SHA-256 entry and the spelling is still the table's.

- [ ] **Step 5: Run the suite**

Run: `cargo test --offline -p git-time-cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add -A crates/git-time-cli/src/cmd
git commit -m "fix: reject a cache entry the worker could not have written"
```

---

### Task 3: One `served` renderer and an injected instant

**Files:**
- Modify: `crates/git-time-cli/src/cmd/picker.rs:572-582` (`served` → `pub(crate)`)
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:479-511` (`pin_state`), delete `tsa::served` (`:527-539`)
- Test: `crates/git-time-cli/src/cmd/tsa.rs` (`mod tests`)

**Interfaces:**
- `picker::served(cached: &probe::Cached, now: jiff::Timestamp) -> String` is `pub(crate)`; `tsa::served` is gone.
- `tsa::pin_state(preset, cell, expiry, rotated, now)` takes the instant as its last argument.

- [ ] **Step 1: Write the failing test**

In `tsa::tests`, next to the existing `pin_state` assertions:

```rust
#[test]
fn pin_state_judges_a_served_date_against_the_passed_instant() {
    use crate::cmd::picker::Cell;

    let preset = presets::find("freetsa").expect("a published preset");
    let served = Cell::Known(crate::cmd::probe::Cached {
        not_after: "2026-12-02".to_owned(),
        fingerprint: "aa".repeat(32),
    });
    let before = jiff::Timestamp::from_second(1_793_000_000).expect("2026-11-01");
    let after = jiff::Timestamp::from_second(1_800_000_000).expect("2027-01-15");
    assert_eq!(
        pin_state(&preset, served.clone(), None, false, before),
        "fetch expires 2026-12-02"
    );
    assert_eq!(
        pin_state(&preset, served, None, false, after),
        "fetch EXPIRED"
    );
}
```

Adjust the other `pin_state` calls in the module to pass `jiff::Timestamp::now()`.

- [ ] **Step 2: Run it and watch the compile fail**

Run: `cargo test --offline -p git-time-cli pin_state_judges_a_served_date_against_the_passed_instant`
Expected: FAIL — five arguments where four are declared.

- [ ] **Step 3: Implement**

Make `picker::served` `pub(crate)` (its doc already reads for both surfaces). Delete `tsa::served`; in `pin_state`, call `picker::served(&cached, now)` and drop the sentence "A served date carries no certificate of its own, so its verdict is judged against the clock here" — replace it with "`now` judges a served date against the caller's instant, not a second clock read." At the single production call site, pass `now` after the `rotated` argument.

- [ ] **Step 4: Run the tests**

Run: `cargo test --offline -p git-time-cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/git-time-cli/src/cmd/picker.rs crates/git-time-cli/src/cmd/tsa.rs
git commit -m "refactor: render a served date from one function and one instant"
```

---

### Task 4: A rotation marker survives a failed refresh

**Files:**
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:513-525` (`rotated`), `:596-608` (call site)
- Modify: `crates/git-time-cli/src/cmd/picker.rs:527-568` (`trust`, the same fallback)
- Test: `crates/git-time-cli/src/cmd/tsa.rs` (`mod tests`, `a_rotated_authority_is_marked`), `crates/git-time-cli/src/cmd/picker.rs` (`mod tests`, `a_failed_probe_keeps_a_rotation_already_cached`)
- Docs: `docs/manual.md:216-224`, `docs/git-time.1` (the `--refresh` paragraph), `docs/superpowers/specs/2026-11-19-tsa-probe-dates-design.md:95` (rendering bullet)

**Interfaces:**
- `rotated(preset: &presets::Preset, roots: Option<&[anchors::RootRow]>, cell: picker::Cell, now: jiff::Timestamp) -> bool`.

- [ ] **Step 1: Write the failing tests**

In `a_rotated_authority_is_marked`, seed the cache instead of relying on the machine, and cover the fallback:

```rust
let _guard = crate::cmd::probe::tests::xdg_lock();
crate::cmd::probe::tests::xdg();
let _ = crate::cmd::probe::forget("freetsa");
```

Then, with `foreign`'s date stored via `probe::store("freetsa", &cached, jiff::Timestamp::now())`:

```rust
for cell in [Cell::Failed, Cell::Pending, Cell::Idle, Cell::Unpublished] {
    assert!(rotated(preset, Some(&roots), cell, jiff::Timestamp::now()), "the last answer still rotates");
}
```

and after storing `held`'s value instead, the same loop is false. Keep the existing `Known` assertions and the no-bundle/empty-bundle ones; the final three assertions (`Failed/Pending/Idle` without a cache) now run after `forget("freetsa")`.

- [ ] **Step 2: Run and watch it fail**

Run: `cargo test --offline -p git-time-cli a_rotated_authority_is_marked`
Expected: FAIL on the first fallback case.

- [ ] **Step 3: Implement**

```rust
fn rotated(
    preset: &presets::Preset,
    roots: Option<&[anchors::RootRow]>,
    cell: picker::Cell,
    now: jiff::Timestamp,
) -> bool {
    let Some(roots) = roots.filter(|roots| !roots.is_empty()) else {
        return false;
    };
    // A row that holds no served root — failed, still waiting, or never asked —
    // still has the last answer in the cache; a refresh that failed must not
    // blink the marker off. `Unpublished` names no root of its own either.
    let cached = match cell {
        picker::Cell::Known(cached) => Some(cached),
        _ => probe::cached(preset.name, now),
    };
    match cached {
        Some(cached) => !roots.iter().any(|root| root.fingerprint == cached.fingerprint),
        None => false,
    }
}
```

Update its doc to say the comparison falls back to the cache and why. Pass `preset` and `now` at the call site. Apply the same fallback to `picker::trust` (which already has both) and update its doc sentence "a failed or unpublished probe marks nothing" — cover it with `a_failed_probe_keeps_a_rotation_already_cached`, built by storing a foreign entry and rendering a `Cell::Failed` row over a pinned fixture. Update the `preset_list`/`refresh` docs: a failed or unpublished reply leaves the marker standing for this run while the cell shows `?`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --offline -p git-time-cli`
Expected: PASS.

- [ ] **Step 5: Update the three docs**

`manual.md`: in the refresh sentence ("A refresh drops nothing first, so one that fails leaves the previous date in place"), append "and its ` !` marker, which comes from the cache rather than from the failed reply". Man page: the same in its own voice. Spec rendering bullet: add "`!` is read from the cached answer when the row holds none, so a failed refresh keeps it", and amend the failure-mode row "pinned row, one probe fails" to "`pin <date> !` when the last answer rotated, else `pin <date>`".

- [ ] **Step 6: Commit**

```sh
git add crates/git-time-cli/src/cmd/tsa.rs docs/manual.md docs/git-time.1 docs/superpowers/specs/2026-11-19-tsa-probe-dates-design.md
git commit -m "fix: keep the rotation marker through a failed refresh"
```

---

### Task 5: Pin the frame's behaviour below seven rows

**Files:**
- Test: `crates/git-time-cli/src/cmd/picker.rs` (`mod tests`)

**Interfaces:**
- `frame(selection, presets, probes, rows, cols)` keeps its signature.

- [ ] **Step 1: Write the test**

Next to `the_frame_never_exceeds_the_terminal_rows`:

```rust
#[test]
fn under_seven_rows_the_cursor_row_and_the_prompt_survive() {
    let probes = probes_with(&[(0, Cell::Failed), (6, Cell::Unpublished)]);
    let mut selection = picked();
    press(&mut selection, Key::End);
    press(&mut selection, Key::Typed('9'));
    press(&mut selection, Key::Typed('9'));
    let _ = press(&mut selection, Key::Enter);
    for rows in 1..=6 {
        let rendered = frame(&selection, &presets::PRESETS, &probes, rows, 80);
        let first = rendered.split("\r\n").next().expect("a first line");
        assert!(first.starts_with("> "), "the cursor row leads at {rows}: {first:?}");
        assert!(rendered.contains("> 99_"), "the prompt survives at {rows}");
        assert!(rendered.contains("url: "), "the URL survives at {rows}");
    }
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --offline -p git-time-cli under_seven_rows_the_cursor_row_and_the_prompt_survive`
Expected: PASS if the current `max(1)` budget and the degrade order do what the module doc says. If it fails, fix the build order so the cursor row is pushed first and `lines.truncate` is not used on it; report which rows failed in the commit body.

- [ ] **Step 3: Adjust the module doc if it overclaims**

The doc says the frame "may reach past the bottom" under seven rows, which the test now pins alongside the cursor-row guarantee. Keep the sentence and the `rows - 1` claim for seven and up; no wording change is expected.

- [ ] **Step 4: Commit**

```sh
git add crates/git-time-cli/src/cmd/picker.rs
git commit -m "test: pin the sub-seven-row frame degradation"
```

---

### Task 6: Hermetic footer tests, a held temp home, and the man page

**Files:**
- Modify: `crates/git-time-cli/src/cmd/picker.rs:946-959` (`pinned_and_probed` and its three callers), `:1153`, `:1306`, `:1721`, `:1763`
- Modify: `crates/git-time-cli/src/cmd/picker.rs:1998-2044` (open the gate at the end)
- Modify: `docs/git-time.1:514-536`

**Interfaces:**
- `pinned_and_probed(cell) -> (String, tempfile::TempDir)`; each caller binds `let (line, _home) = ...`.

- [ ] **Step 1: Return the temp home**

`pinned_and_probed` ends with `(rendered(...), xdg)`; its three callers become `let (line, _home) = pinned_and_probed(...);`. This keeps the directory alive past the assertion instead of leaving `XDG_CONFIG_HOME` on a deleted path.

- [ ] **Step 2: Hold an empty home in the four footer/help tests**

Add `let _home = empty_home();` as the first line of `the_frame_shows_the_trust_tier_and_the_help`, `the_cursor_row_and_the_footer_are_always_rendered`, `the_footer_counts_failures_and_names_unpublished_rows` and `the_help_line_is_not_cut`. If any assertion depends on a pinned row of the developer's machine, adapt it to the empty home (the empty home means every row is unpublished, which the help/URL/count assertions do not care about).

- [ ] **Step 3: Let the parked refresh test finish**

At the end of `a_refresh_reasks_every_probed_row_and_leaves_tofu_alone`, before the `tofu_prober` block:

```rust
*gate.0.lock().expect("gate") = true;
gate.1.notify_all();
```

so the first prober's workers stop parking on the condvar before the test ends.

- [ ] **Step 4: Fix the man page's `tofu` claim**

Line ~521-525 says `preset list` prints "their pinned fingerprint or tofu". No built-in row is tofu; the column is the newest published fingerprint. Replace with "the newest fingerprint the authority publishes, and `tofu` only for a hand-added row that publishes none", and keep the existing "No current row is in the `tofu` position." as the explanation.

- [ ] **Step 5: Run the suite**

Run: `cargo test --offline -p git-time-cli`
Expected: PASS. If a footer test now renders a different but equally valid line, adjust the assertion to the empty-home output and note it.

- [ ] **Step 6: Commit**

```sh
git add crates/git-time-cli/src/cmd/picker.rs docs/git-time.1
git commit -m "test: hold the temp home, unpark the refresh prober, fix the tofu wording"
```

---

### Task 7: Whole-branch checks

- [ ] **Step 1: Format and lint**

Run: `cargo fmt --all --check && cargo clippy --offline --workspace --all-targets -- -D warnings`
Expected: both silent.

- [ ] **Step 2: Full suite**

Run: `cargo test --offline`
Expected: all suites `ok`, 0 failed.

- [ ] **Step 3: Read the diff against `main`**

Run: `git diff main --stat && git diff main -- crates/git-time-cli/src/cmd | head -400`
Expected: only the six concerns above; no stray normalizer, no second `served`, no `now()` left inside `pin_state`.

---

## Self-review

**Spec coverage:** cache shape (Task 2), `!` from the cached answer (Task 4), served-vs-pin vocabulary and one clock (Task 3), `dir()` sharing (Task 1), sub-seven rows (Task 5), hermetic tests (Task 6). The deferred item "`ta s::served` copied instead of widened" is Task 3. "`rotated` compares raw strings where `still_published` normalizes" is resolved by Task 2 removing the normalizer, not by copying it into `rotated`.

**Not taken, and why:** the `r`-while-typing item is moot (typed characters are only `0-9 , -`, so `r` can never be a buffer character); `Prober::start` still spawns four threads for an empty queue (they park and `Drop` wakes them, and every caller needs a prober object); the plan text that still says "forget" is a record of the earlier plan, not shipped behaviour.

**Type consistency:** `Cached`, `Cell`, `RootRow` and both `dir()` signatures are unchanged; only `pin_state` and `rotated` gain a `now`/`preset` argument, and both call sites are updated in the same task.
