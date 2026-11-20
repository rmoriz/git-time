# Configured authorities in the listings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a hand-added `time.tsa.<id>` authority a first-class row in `tsa select` and `tsa preset list`, and close the four parked probe minors from the 2026-11-20 review.

**Architecture:** Approach A from the spec. `tsa::rows(repo)` clones the built-in table, applies any configured section to a preset row, and appends unknown configured ids as TOFU rows with leaked strings, returning `&'static [Preset]` so every existing `&'static [Preset]` signature and test call site stands. Both renderers resolve a new `Preset::anchor_path` before falling back to `dir()/<name>.pem`. Custom rows are never probed, are ticked at start, are kept (not re-pinned) when chosen, and are disabled when unticked.

**Tech Stack:** Rust 2024, `jiff`, the existing `picker`/`probe`/`anchors`/`install` modules; `cargo test --offline` only.

**Spec:** `docs/superpowers/specs/2026-11-20-configured-authorities-design.md`

## Global Constraints

- `cargo` runs `--offline`; `cargo fmt --all --check` and `cargo clippy --offline --workspace --all-targets -- -D warnings` are green before every commit.
- Tests hermetic: `GIT_CONFIG_GLOBAL=/dev/null`, temp `XDG_CONFIG_HOME` under `probe::tests::xdg_lock()`, `git init` into a `tempfile::TempDir`, no sockets.
- One `now` per run; no row may straddle an expiry between its date and its marker.
- Row order is fixed: built-ins in table order, then configured-only rows in id order.
- No new config key; no change to a probe verdict, the TTL, or verification.
- Commit messages say why, no `Co-Authored-By` trailer.
- Deferred probes are not queued: custom rows carry an empty `fingerprints` list and stay `Idle`.

## Review Focus

1. An unknown id with an `anchor` but no `url` — must not become a row, and must survive every save because it is not in `unwanted`.
2. A configured preset id pointed at a non-default anchor path — the row and `install::pin` must both read/write that path, never `dir()/<id>.pem`.
3. A fresh cache, where `skip` covers every row — `r` must still fetch, so workers spawn on the refresh.
4. Unticking a custom row — the section is removed, the anchor file is not.
5. A custom row with no bundle — `tofu` on both surfaces, never `?` or `pin -`.

## Execution

Task 1 first, alone (it touches every `Preset` literal). Tasks 2 and 4 run **in parallel** — their file sets are disjoint (`picker.rs`/`tsa.rs` vs `probe.rs`). Task 3 follows 2 (same file). Task 5 follows 3 and 4. Task 6 is the gate.

---

### Task 1: A row table that names configured authorities

**Files:**
- Modify: `crates/git-time-core/src/presets.rs` (the `Preset` struct, its doc, all 21 `PRESETS` literals and any test literal)
- Modify: `crates/git-time-cli/src/cmd/anchors.rs:580` (`listing` visibility)
- Modify: `crates/git-time-cli/src/cmd/tsa.rs` (new `rows` + leak helpers)
- Test: `crates/git-time-cli/src/cmd/tsa.rs` (`mod tests`)
- Modify literals only: `crates/git-time-cli/src/cmd/picker.rs` (6 sites), `crates/git-time-cli/src/cmd/probe.rs` (2 sites), `crates/git-time-cli/src/cmd/tsa.rs` (3 sites)

**Interfaces:**
- Produces: `pub anchor_path: Option<&'static Path>` on `Preset`; `Preset` derives `Clone`; `pub(crate) fn tsa::rows(repo: &Repo) -> Result<&'static [Preset], Exit>`.

- [ ] **Step 1: Add the field and the derive**

In `presets.rs`, `#[derive(Debug, Clone)]` and after `insecure_http`:

```rust
    /// Where this authority's bundle is pinned, when the repository configured a
    /// path other than the default `dir()/<name>.pem`. `None` is the default.
    pub anchor_path: Option<&'static Path>,
```

Add `use std::path::Path;` and `anchor_path: None,` to every literal. Run `cargo build --offline -p git-time-cli` and add `anchor_path: None,` to each of the 11 CLI literals the compiler names.

- [ ] **Step 2: Expose the listing**

`anchors::listing` becomes `pub(crate) fn listing(...)`; its doc gains that `tsa::rows` reads sections through it.

- [ ] **Step 3: Write the failing tests**

Follow the `the_seed_is_the_configured_presets_in_table_order` fixture (`tsa.rs:1445-1456`): a `TempDir`, `git init -q`, `Repo::open`, and a local `configure(dir, id, url, anchor)` helper that runs `git config --local time.tsa.<id>.url <url>` and `.anchor <anchor>`.

```rust
#[test]
fn a_configured_section_is_a_custom_row_last_with_tofu() {
    // "zz-acme" with a url and an anchor; assert rows() has PRESETS.len() + 1
    // entries, the last named "zz-acme", `fingerprints` empty, `anchor_path`
    // Some(resolved anchor), `curated` false.
}

#[test]
fn an_unknown_section_without_a_url_is_no_row() {
    // "zz-noauth" with only an anchor; rows() has PRESETS.len() entries and no
    // such name.
}

#[test]
fn a_configured_preset_takes_the_section_url_and_path() {
    // configure "freetsa" with a mirror url and a custom anchor; exactly one
    // freetsa row, its url the mirror, its anchor_path the custom path.
}

#[test]
fn custom_rows_are_sorted_and_never_duplicate() {
    // configure "zz-b" and "zz-a"; both appear once, in that order, after the
    // table.
}
```

- [ ] **Step 4: Run them, expect a missing `rows`**

Run: `cargo test --offline -p git-time-cli rows -- --nocapture`
Expected: `error[E0425]: cannot find function `rows``.

- [ ] **Step 5: Implement `rows`**

```rust
/// The rows a surface shows: the built-in table, then every section a path in.
///
/// A configured id the table knows overrides its row from the section — the
/// section is what seals, so the row must name what it points at, and a mirror
/// still serves the published roots the `!` marker is judged against. An unknown
/// id needs a url to be enableable at all, so a url-less section is no row and
/// is left alone by `apply`. Strings are leaked: the process is about to exit,
/// and every `&'static [Preset]` signature then stands unchanged.
fn rows(repo: &Repo) -> Result<&'static [Preset], Exit>
```

Read `anchors::listing(repo)?` once into a map of id → section fields. Start from `presets::PRESETS.to_vec()`. For each id in `anchors::tsa_ids(repo)?` order: when it names a preset, override that index's url/alg/policy/insecure_http from the section where set and set `anchor_path` to `Some(leaked anchors::resolve(repo, path))`; otherwise, if the section has a url, push a custom row (leaked name/url, `alg` default `"sha256"`, leaked policy when set, empty `anchor_url`, empty `chain`, empty `fingerprints`, `curated: false`, `anchor_path: Some(leaked path)`, `insecure_http` from the section). Leak with `Box::leak(text.into_boxed_str())` / `Box::leak(path.into_boxed_path())` and return `Box::leak(rows.into_boxed_slice())`.

- [ ] **Step 6: Run the four tests**

Run: `cargo test --offline -p git-time-cli rows -- --nocapture`
Expected: 4 passed.

- [ ] **Step 7: Full gate**

Run: `cargo fmt --all && cargo fmt --all --check && cargo clippy --offline --workspace --all-targets -- -D warnings && cargo test --offline -p git-time-cli`
Expected: clean, all suites pass.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: build the listing rows from the configuration too

A hand-added authority was configured but in neither surface where one is
chosen, so it could only be reached by remembering it. rows() merges those
sections behind the table: an unknown id joins as a TOFU row that carries
its own url and bundle path, and a known id takes the section's endpoint so
the row and the probe describe what the repository seals with."
```

---

### Task 2: Render configured rows honestly (parallel with Task 4)

**Files:**
- Modify: `crates/git-time-cli/src/cmd/picker.rs:461-472` (`row`), `:513-570` (`trust` doc only)
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:466-496` (`pin_state`), `:595-630` (`preset_list`)
- Test: `crates/git-time-cli/src/cmd/tsa.rs` (`mod tests`, next to `a_rotated_authority_is_marked`), `crates/git-time-cli/src/cmd/picker.rs` (`mod tests`, next to `the_trust_column_says_the_pin_and_its_date`)

**Interfaces:**
- Consumes: `Preset::anchor_path`, `tsa::rows` (Task 1).
- Produces: `fn pin_state(preset: &presets::Preset, roots: Option<&[anchors::RootRow]>, cell: picker::Cell, rotated: bool, now: jiff::Timestamp) -> String` — the caller no longer computes `expiry`.

- [ ] **Step 1: Write the failing expired-pin test**

In `picker::tests`, call `super::trust` directly — no test-only re-export:

```rust
#[test]
fn an_all_expired_bundle_says_expired_on_both_surfaces() {
    use crate::cmd::anchors::RootRow;
    use crate::cmd::picker::Cell;
    let preset = presets::find("digicert").expect("a preset");
    let roots = [RootRow { fingerprint: "aa".repeat(32), not_after: "2020-01-01".to_owned() }];
    let now = jiff::Timestamp::now();
    assert_eq!(super::trust(preset, Some(&roots), now, Cell::Idle), "EXPIRED");
    assert_eq!(
        crate::cmd::tsa::pin_state_for_test(preset, Some(&roots), Cell::Idle, false, now),
        "EXPIRED"
    );
}
```

Add `#[cfg(test)] pub(crate) use pin_state as pin_state_for_test;` in `tsa.rs` if `pin_state` stays private to the module.

- [ ] **Step 2: Write the failing custom-row tests**

In `tsa::tests`:

```rust
#[test]
fn a_custom_row_with_no_bundle_says_tofu_and_a_builtin_says_pin_dash() {
    // pin_state for a custom Preset (name "zz-acme", empty fingerprints) with
    // roots None, Cell::Idle -> "tofu"; the freetsa row with roots None,
    // Cell::Idle -> "pin -" is the picker's word, and preset_list's built-in
    // idle row is "-".
}
```

In `picker::tests`, a frame test with one custom row from a `configured_custom()` fixture: the row renders `tofu`, and with an anchor file pinned to a known date it renders that date rather than `pin -`.

- [ ] **Step 3: Run, expect FAIL**

Run: `cargo test --offline -p git-time-cli pin_state an_all_expired`
Expected: FAIL — the all-expired bundle renders the `Cell::Idle` branch.

- [ ] **Step 4: Change `pin_state`**

Move the bundle branch in from `trust`: a non-empty bundle whose roots are all `anchors::expired` says `EXPIRED`; otherwise the newest live root's `anchors::expiry_text`; only without a bundle does the cell decide, and the `Cell::Idle` branch answers `tofu` when `presets::find(&preset.name).is_none()`, `not pinned` when the row publishes nothing, `-` otherwise. Keep the ` !` append unchanged and after the state is built.

- [ ] **Step 5: Resolve the path in both renderers**

`picker::row` and `preset_list`: `let anchor = preset.anchor_path.map(Path::to_path_buf).unwrap_or_else(|| anchors::dir().join(format!("{}.pem", preset.name)));`. `preset_list` drops its own `expiry` computation and passes `roots.as_deref()`.

- [ ] **Step 6: `preset_list` uses rows**

Replace `presets::PRESETS` with the `rows(repo)?` slice in `preset_list` only (`seed`, the refresh filter, the `skip_of` count, `Prober::start` and the loop), rename its `_repo` parameter to `repo`, and print `custom` in the scope column when `presets::find(&preset.name).is_none()`.

- [ ] **Step 7: Run the tests**

Run: `cargo test --offline -p git-time-cli 'expired|custom_row' -- --nocapture`
Expected: pass.

- [ ] **Step 8: Check the picker column and the gate**

Run the full gate as in Task 1 Step 7.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "fix: say EXPIRED for a dead pin and tofu for a custom row

preset list fell through to the probe cell when every root of a bundle had
expired, so a dead pin read ? or - where the picker said EXPIRED. pin_state
takes the roots and owns that branch now. Both renderers also read the
configured bundle path, and a custom row says tofu instead of the pin-dash
wording its empty publication list would otherwise earn."
```

---

### Task 3: Keep-only custom rows through selection and apply

**Files:**
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:868-1000` (`select`, `accepted`, `already_enabled`, `ask`), `:1075-1106` (`apply`)

**Interfaces:**
- Consumes: `tsa::rows` (Task 1), `pin_state`'s new shape (Task 2).
- Produces: none for later tasks; `apply`, `accepted`, `already_enabled` and `ask` take `rows: &[Preset]`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_configured_custom_row_is_ticked_and_kept() {
    // configure "zz-acme" (url + anchor). already_enabled -> index of zz-acme
    // in rows() is present. apply(&repo, &[that index], &BTreeMap::new(), true)
    // prints "would keep zz-acme" and leaves the section in the config.
}

#[test]
fn an_unticked_custom_row_is_disabled_but_keeps_its_anchor() {
    // configure "zz-acme"; apply with an empty chosen list; the section is gone
    // and the anchor file still exists.
}

#[test]
fn an_anchor_only_unknown_section_survives_a_save() {
    // configure "zz-noauth" with only an anchor; apply empty; section remains.
}

#[test]
fn a_bare_accept_ignores_a_chosen_custom_row() {
    // accepted(&["aa".to_owned()], &[freetsa_index, custom_index], "select")
    // resolves to freetsa.
}

#[test]
fn a_chosen_preset_keeps_its_configured_anchor_path() {
    // configure "freetsa" with a custom anchor path and
    // GIT_TIME_ANCHOR_FETCH_CMD="cat crates/git-time-core/tests/fixtures/freetsa_root.pem";
    // apply over that row; the bundle is written to the custom path and the
    // section still names it. `install::pin` resolves config itself and is
    // unchanged; this proves the row did not send it to dir()/<id>.pem.
}
```

- [ ] **Step 2: Run, expect FAIL**

Run: `cargo test --offline -p git-time-cli 'custom_row_is_ticked|survives_a_save'`
Expected: FAIL — `already_enabled` never returns a custom index.

- [ ] **Step 3: Thread the rows through**

`select` builds `let rows = rows(repo)?` once, uses `rows.len()` for `Probes::idle`, passes `rows` to `picker::run`, `ask`, `parse_choice`, `accepted` and `apply`. `already_enabled(repo, rows)` maps every `anchors::tsa_ids(repo)?` id to its `rows` position and sorts. `accepted` filters chosen indices to rows `presets::find` knows before `one_or_id`.

- [ ] **Step 4: Apply keeps a custom row**

`unwanted` is every configured id that is a row and not chosen, mapped back through `rows` (names), so an unknown anchor-only section, absent from rows, is never in it. In the chosen loop use `rows.get(*index)`; when `presets::find(&preset.name).is_none()`, print `would keep {name} ({url})` under `--dry-run` and `kept {name} ({url})` otherwise, then `continue` — no `install::pin`.

- [ ] **Step 5: Print `custom` in the line prompt**

`ask`'s scope word: `custom` when `presets::find(&preset.name).is_none()`, else the existing `default`/`opt-in`.

- [ ] **Step 6: Run the tests and the gate**

Expected: 4 new tests pass, full gate clean.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: keep a configured authority through the selector

The selector's answer is the whole set, so a custom row it cannot see
survives only by accident. As a row it starts ticked, an empty answer keeps
it, an unticked one disables it, and a chosen one is kept rather than
re-pinned because there is no anchor URL to fetch from. A bare --accept
still ignores it: the run fetches nothing for one."
```

---

### Task 4: Spawn probe workers only when there is work (parallel with Task 2)

**Files:**
- Modify: `crates/git-time-cli/src/cmd/probe.rs:225-266` (`Shared`, `start`), `:268-281` (`refresh`), `:305-323` (`settle`), `:349-356` (`Drop`)
- Test: `crates/git-time-cli/src/cmd/probe.rs` (`mod tests`)

**Interfaces:**
- Produces: unchanged public signatures; `start` may now leave the worker set empty, and `refresh` starts it on the first refresh that enqueues a row.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_fully_skipped_table_spawns_no_worker() {
    // Prober::start(&PRESETS, fetch_that_panics, &(0..PRESETS.len()).collect()) ;
    // pending() == 0; settle() returns empty without the fetch running.
}

#[test]
fn the_first_refresh_starts_the_workers() {
    // start with every row skipped, refresh with an empty skip, absorb until
    // pending() == 0; the rows answered.
}
```

- [ ] **Step 2: Run, expect FAIL on threads (assert on a spawn counter, not timing)**

Add a `#[cfg(test)] static SPAWNED: AtomicUsize` incremented in the spawn helper, assert `0` after `start`. Run: `cargo test --offline -p git-time-cli spawns_no_worker`
Expected: FAIL — `start` spawns PROBE_THREADS.

- [ ] **Step 3: Move the sender into `Shared`**

`Shared` gains `sender: Mutex<Option<Sender<(usize, Served)>>>` and `workers: AtomicBool`. `start` stores `Some(sender)`, enqueues, and calls `spawn(&shared)` only when the queue is non-empty. `spawn` returns early when `workers.swap(true, ..)` was already true or the sender is gone, then starts `PROBE_THREADS` threads with a clone.

- [ ] **Step 4: `refresh` starts the workers**

Enqueue under the lock; if anything was enqueued, drop the guard, `spawn(&self.shared)`, then notify. `settle` and `Drop` close the queue, `take()` the sender out so the channel can still end, and `settle` returns `drain()` at once when `pending() == 0`.

- [ ] **Step 6: `probe::forget` becomes `#[cfg(test)]`**

Delete the `#[allow(dead_code)]` and put `#[cfg(test)]` on `forget`; it is called only from tests. Run `cargo clippy --offline --workspace --all-targets -- -D warnings` — it must stay clean with and without `cfg(test)`.

- [ ] **Step 7: Run the tests, then the gate**

Expected: pass, full gate clean.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "perf: start probe workers only when a row is queued

A plain preset list or selector with a fresh cache spawned four threads that
exited at once. The sender moves into the shared state and the workers start
on the first queueing call instead, including a later r: a refresh that
enqueues nothing still starts nothing. forget() also stops claiming to be
dead code — only tests call it, and cfg(test) says so."
```

---

### Task 5: Docs and the two stale claims (after Tasks 3 and 4)

**Files:**
- Modify: `docs/manual.md:206-230` (preset list + select sections), `docs/git-time.1:514-545`, `:660-700`
- Modify: `docs/STATUS.md:203-235` (known gaps), `:126-160` (release notes)

- [ ] **Step 1: Manual and man page**

Both: a configured authority is listed too, scope `custom`, a custom row is kept not fetched and is pinned with `anchor fetch --id`, an all-expired bundle says `EXPIRED`, and a custom row with no pin says `tofu`. Rewrite the manual sentence that calls `tofu` and `not pinned` tiers no built-in needs. Render with `mandoc docs/git-time.1 | col -bx` and read the changed paragraphs.

- [ ] **Step 2: STATUS**

The `time-dropped` known gap becomes what `drop::prune` does: entries whose object no longer resolves and the oldest beyond 200, on every drop and seal. Add the configured-row behaviour to the release-notes list.

- [ ] **Step 3: Commit**

```bash
git add docs
git commit -m "docs: describe configured rows, and correct the drop gap

The listings now show configured authorities, so the manual and man page say
how a custom row behaves. STATUS called time-dropped unpruned long after
drop::prune capped and pruned it."
```

---

### Task 6: Gate

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --offline --workspace --all-targets -- -D warnings`
- [ ] `cargo test --offline` — all suites, expecting 0 failed
- [ ] `git diff main` read once, end to end, against the Review Focus list
