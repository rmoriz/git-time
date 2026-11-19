# Probe dates for unpinned presets — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show every authority's root expiry in the picker, fetched in the background and cached, so an unpinned row stops being a blank.

**Architecture:** A new `cmd/probe.rs` owns an on-disk cache (one file per authority: date, fetch time, root fingerprint) and a four-thread worker that fetches a bundle and keeps the date only when the served root matches a fingerprint the preset publishes. The picker paints from a snapshot, so the network never delays a frame; results arrive over one channel the key loop drains. A probe pins nothing and writes only under `probe/`.

**Tech Stack:** Rust 2024, `tokio` (already a dependency, current-thread runtime inside the worker), the existing `anchors::fetch_chain`, `stty`-driven TUI, no new crates.

**Spec:** `docs/superpowers/specs/2026-11-19-tsa-probe-dates-design.md`

## Global Constraints

- No new dependencies; `Cargo.lock` stays as it is.
- Every command runs `--offline`: `cargo test --offline -p git-time-cli`, `cargo clippy --offline --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.
- Tests are hermetic: `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, a temp `XDG_CONFIG_HOME`, and no socket — a test that must fetch sets `GIT_TIME_ANCHOR_FETCH_CMD` or injects the `Fetch` closure.
- Commit messages say *why*; no `Co-Authored-By` trailer.
- A probe is display-only: it must never write `anchors/`, and nothing in verification, quorum or the block format changes.
- `anchors::fingerprint` is the only fingerprint spelling the cache and the `!` comparison use (lowercase hex SHA-256).
- The cache never holds a certificate, only the three fields.

## Review Focus

- A host with no network at all: every probe fails, rows read `?`, the picker still saves. Test in Task 5 (worker) and Task 7 (pty).
- A reply that is prose, a token, or a leaf-first chain: no root matches a published value, so `Unpublished`, not a crash and not a bogus date. Test in Task 2.
- `GIT_TIME_ANCHOR_FETCH_CMD` set (the suite, and air-gapped users): the probe honours it; the stub's stdout may be garbage. Test in Task 3 and Task 7.
- A missing or read-only config home: a failed cache write must not abort the picker. Test in Task 1.
- A terminal too narrow for the widened trust cell: `fit` still cuts the row to one line and the transport column stays on it. Test in Task 4.

---

### Task 1: The probe cache

**Files:**
- Create: `crates/git-time-cli/src/cmd/probe.rs`
- Modify: `crates/git-time-cli/src/cmd/mod.rs` (declare `pub mod probe;` after `picker`)
- Test: `crates/git-time-cli/src/cmd/probe.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces:
  - `pub fn dir() -> PathBuf` — `$XDG_CONFIG_HOME`-or-`~/.config`, then `git-time/probe`
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct Cached { pub not_after: String, pub fingerprint: String }`
  - `pub const TTL: i64 = 7 * 86_400;`
  - `pub fn cached(id: &str, now: jiff::Timestamp) -> Option<Cached>` — only when the entry is younger than `TTL`
  - `pub fn store(id: &str, served: &Cached, now: jiff::Timestamp) -> bool`
  - `pub fn forget(id: &str) -> bool`

- [ ] **Step 1: Write the failing tests**

```rust
use super::{Cached, TTL, cached, forget, store};

fn at(seconds: i64) -> jiff::Timestamp {
    jiff::Timestamp::from_second(seconds).expect("a second")
}

fn served() -> Cached {
    Cached {
        not_after: "2035-02-09".to_owned(),
        fingerprint: "aa".repeat(32),
    }
}

#[test]
fn a_stored_entry_reads_back_within_the_ttl() {
    store("x", &served(), at(1_000));
    let entry = cached("x", at(1_000 + TTL - 1)).expect("still fresh");
    assert_eq!(entry.not_after, "2035-02-09");
    assert_eq!(entry.fingerprint, "aa".repeat(32));
}

#[test]
fn an_entry_older_than_the_ttl_is_stale() {
    store("x", &served(), at(1_000));
    assert!(cached("x", at(1_000 + TTL + 1)).is_none());
}

#[test]
fn a_rewritten_entry_replaces_the_date() {
    store("x", &served(), at(1_000));
    let newer = Cached {
        not_after: "2040-01-01".to_owned(),
        fingerprint: "bb".repeat(32),
    };
    store("x", &newer, at(1_100));
    let entry = cached("x", at(1_100)).expect("fresh");
    assert_eq!(entry.not_after, "2040-01-01");
}

#[test]
fn a_malformed_entry_is_stale_not_an_error() {
    let path = super::dir().join("x");
    std::fs::create_dir_all(super::dir()).expect("dir");
    std::fs::write(&path, "not a date\nnope\n").expect("write");
    assert!(cached("x", at(1_000)).is_none());
}

#[test]
fn forgetting_removes_the_entry() {
    store("x", &served(), at(1_000));
    assert!(forget("x"));
    assert!(cached("x", at(1_000)).is_none());
    assert!(!forget("x"));
}

#[test]
fn a_write_under_a_read_only_parent_does_not_panic() {
    let root = super::dir().join("ro");
    std::fs::create_dir_all(&root).expect("dir");
    let mut permissions = std::fs::metadata(&root).expect("metadata").permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&root, permissions).expect("chmod");
    let entry = Cached { not_after: "2035-02-09".to_owned(), fingerprint: "aa".repeat(32) };
    store("ro/x", &entry, at(1_000));
    assert!(cached("ro/x", at(1_000)).is_none());
    let mut permissions = std::fs::metadata(&root).expect("metadata").permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(&root, permissions).expect("chmod");
}
```

Tests that write need a temp `XDG_CONFIG_HOME`; other tests in this crate already point it at a temp dir, so `dir()` resolves per test process. Give each test its own id (`x`, `ro/x`) so they cannot collide.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --offline -p git-time-cli probe::tests`
Expected: FAIL — `probe` is not a module yet, then `unresolved import`.

- [ ] **Step 3: Implement the module**

One tab-separated line per file: `<not_after>\t<fetched_at_seconds>\t<fingerprint>`. `cached` splits exactly three fields, parses the seconds as `i64`, and compares `now.as_second() - at <= TTL`; `store` does `create_dir_all(dir())` and `fs::write`, both `let _ =`-tolerant and answering `false` on failure; `forget` is `fs::remove_file` mapped to `bool`. Document at the top why the cache is not the pin: a probe's date is provisional, the pin still decides trust.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --offline -p git-time-cli probe::tests`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/src/cmd/probe.rs crates/git-time-cli/src/cmd/mod.rs
git commit -m "feat: cache a probed root date for a week

The picker has to say when a root the user has not pinned dies out, and
asking the authority on every frame is not affordable. A week-old answer
still catches a rotation, so the ttl is short and the entry is only ever
display material."
```

---

### Task 2: Which date a reply justifies

**Files:**
- Modify: `crates/git-time-cli/src/cmd/probe.rs`
- Modify: `crates/git-time-cli/src/cmd/anchors.rs:491` (`parse_certificates` becomes `pub(crate)`)
- Test: `crates/git-time-cli/src/cmd/probe.rs`

**Interfaces:**
- Consumes: `super::install::fingerprint_matches(&[&'static str], &[u8]) -> Option<&'static str>`, `super::anchors::{fingerprint, not_after}`, `git_time_core::presets::Preset`.
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub enum Served { Known(Cached), Unpublished, Failed }`
  - `pub fn probed_from(preset: &Preset, bundle: &[u8], now: jiff::Timestamp) -> Served`

- [ ] **Step 1: Write the failing tests**

The root fixture is `crates/git-time-core/tests/fixtures/freetsa_root.pem`; for a
second root the test generates one with `openssl` (the `stale_ca` config from
`tests/registry.rs`, copied into this module). Cross-authority cases use the
FreeTSA root against the `aped` preset. Assert:

```rust
#[test]
fn a_published_root_yields_its_date() {
    let preset = presets::find("freetsa").expect("preset");
    let bundle = std::fs::read(FREETSA_ROOT).expect("fixture");
    match super::probed_from(preset, &bundle, at(1_000)) {
        super::Served::Known(cached) => {
            assert!(cached.not_after.starts_with("20"), "{}", cached.not_after);
            assert!(!cached.fingerprint.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_root_nothing_published_is_unpublished() {
    // The FreeTSA root is not a value the APED preset publishes.
    let preset = presets::find("aped").expect("preset");
    let other = std::fs::read(FREETSA_ROOT).expect("fixture");
    assert!(matches!(
        super::probed_from(preset, &other, at(1_000)),
        super::Served::Unpublished
    ));
}

#[test]
fn prose_is_failed() {
    let preset = presets::find("freetsa").expect("preset");
    assert!(matches!(
        super::probed_from(preset, b"<html>204 OK</html>", at(1_000)),
        super::Served::Failed
    ));
}

#[test]
fn the_newest_live_matching_root_wins() {
    // Two matching roots, one expired in 2020: the live one's date is the one
    // shown. `stale_ca` and the fingerprint helpers are `tests/registry.rs`
    // helpers; copy them here or lift them into a shared test module.
    let stale = std::fs::read(stale_ca(&dir)).expect("fixture");
    let live = std::fs::read(FREETSA_ROOT).expect("fixture");
    let mut bundle = stale.clone();
    bundle.extend(std::fs::read_to_string(FREETSA_ROOT).expect("fixture").as_str().as_bytes());
    let (stale_fp, live_fp) = (colon(&stale), colon(&freetsa_der()));
    let published: &'static [&'static str] =
        Box::leak(vec![stale_fp.as_str(), live_fp.as_str()].into_boxed_slice());
    let preset = Preset {
        name: "both",
        url: "",
        anchor_url: "",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: published,
        insecure_http: false,
        curated: false,
    };
    match super::probed_from(&preset, &bundle, at(1_000)) {
        super::Served::Known(cached) => assert_ne!(cached.not_after, "2020-02-01"),
        other => panic!("{other:?}"),
    }
}
```

Note that the stale fixture is DER and the live one PEM, so the concatenation also exercises the parser's mixed input.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --offline -p git-time-cli probe::tests`
Expected: FAIL — `Served` and `probed_from` do not exist.

- [ ] **Step 3: Implement `probed_from`**

`anchors::parse_certificates(bundle)`; for each certificate take `to_der()`, keep it when `fingerprint_matches(preset.fingerprints, &der)` is `Some`, and pair it with `fingerprint(&der)` and `not_after(&certificate)`. No parsed certificate or no match ⇒ `Failed` / `Unpublished` respectively. Among matched pairs pick the one with the greatest `not_after` that is not `anchors::expired`, else the greatest overall; a date that does not parse as `YYYY-MM-DD` is `Failed`. Document that a match on any published value is the whole check, because a leaf can never carry a root's fingerprint.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --offline -p git-time-cli probe::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/src/cmd/probe.rs crates/git-time-cli/src/cmd/anchors.rs
git commit -m "feat: believe a probed date only against a published root

A timestamp endpoint answers a GET with prose and some authorities serve a
leaf first, so the reply alone says nothing. Matching every certificate
against the preset's published values is what makes a date worth printing,
and an unmatched reply is reported rather than shown."
```

---

### Task 3: The worker

**Files:**
- Modify: `crates/git-time-cli/src/cmd/probe.rs`
- Test: `crates/git-time-cli/src/cmd/probe.rs`

**Interfaces:**
- Consumes: `Served`, `probed_from`, `probe::store`, `super::anchors::fetch_chain`.
- Produces:
  - `pub type Fetch = std::sync::Arc<dyn Fn(&str, &[&str]) -> Result<Vec<u8>, String> + Send + Sync>;`
  - `pub fn network_fetch() -> Fetch`
  - `pub struct Prober` with `pub fn start(presets: &'static [Preset], fetch: Fetch, skip: &[usize]) -> Self`, `pub fn refresh(&self, skip: &[usize])`, `pub fn drain(&self) -> Vec<(usize, Served)>`, `pub fn pending(&self) -> usize`, `pub fn failed(&self) -> usize`, and `Drop` that closes the queue
  - `PROBE_THREADS: usize = 4`

- [ ] **Step 1: Write the failing tests**

A `Fetch` closure over a static `Mutex<Vec<String>>` of requested URLs, answering a FreeTSA root for any URL and a `Cached`-shaped assertion; a helper that waits for `pending() == 0` with a bounded loop (`std::thread::sleep(Duration::from_millis(20))`, at most 250 rounds) because the worker is threaded.

```rust
#[test]
fn a_result_carries_the_index_and_is_stored() {
    let presets: &'static [Preset] = &presets::PRESETS;
    let prober = super::Prober::start(presets, answering(FREETSA_ROOT), &[]);
    let results = wait(&prober);
    assert!(results.iter().any(|(index, served)| {
        *index == freetsa_index() && matches!(served, super::Served::Known(_))
    }));
    assert!(super::cached("freetsa", jiff::Timestamp::now()).is_some());
}

#[test]
fn skipped_indices_are_not_fetched() {
    let urls = urls();
    let prober = super::Prober::start(&presets::PRESETS, answering(FREETSA_ROOT), &[1]);
    wait(&prober);
    assert!(!urls.lock().unwrap().contains(&presets::PRESETS[1].url.to_owned()));
}

#[test]
fn a_failing_fetch_counts_and_answers_failed() {
    let failing: super::Fetch = std::sync::Arc::new(|_, _| Err("down".to_owned()));
    let prober = super::Prober::start(&presets::PRESETS, failing, &[]);
    let results = wait(&prober);
    assert!(results.iter().all(|(_, served)| matches!(served, super::Served::Failed)));
    assert_eq!(prober.failed(), presets::PRESETS.len());
}

#[test]
fn refresh_queues_everything_again() {
    let prober = super::Prober::start(&presets::PRESETS, answering(FREETSA_ROOT), &[]);
    wait(&prober);
    prober.refresh(&[]);
    assert!(prober.pending() > 0);
    wait(&prober);
}
```

The tests mutate `XDG_CONFIG_HOME`-relative files like Task 1; the answering closure ignores the URL because every row is fetched with the same fixture.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --offline -p git-time-cli probe::tests`
Expected: FAIL — no `Prober`.

- [ ] **Step 3: Implement the worker**

`start` spawns `PROBE_THREADS` detached `std::thread`s over `Arc<(Mutex<VecDeque<usize>>, Condvar)>` and an `mpsc::channel`. Each thread: wait on the condvar while the queue is empty and not closed; pop an index; call `fetch(preset.url, preset.chain)`; on `Ok` compute `probed_from(preset, &bytes, Timestamp::now())` and `store` a `Known`; send `(index, served)` and bump an `AtomicUsize` for `Failed`/`Unpublished` (a `Failed` only when the send also worked). `drain` is `try_iter().collect()`, `pending` is the queue length, `Drop` sets `closed` and notifies all. `network_fetch` builds a `current_thread` runtime with `enable_all()` per call and `block_on(anchors::fetch_chain(url, chain))`. No joining anywhere: the process exit ends the threads.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --offline -p git-time-cli probe::tests`
Expected: PASS. Re-run once: the tests are timing-sensitive only through `pending()`, so a flake means the wait helper is wrong, not the worker.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/src/cmd/probe.rs
git commit -m "feat: fetch probed roots on four detached threads

Twenty parallel sockets take the picker's first frame hostage, and one
thread makes a hang serialise a whole table. Four threads behind a queue
keep the frame free and finish a full table inside the existing 10s
timeout per row."
```

---

### Task 4: Render the probe states

**Files:**
- Modify: `crates/git-time-cli/src/cmd/picker.rs:30-214` (`Key::Refresh`, `parse_key`, `HELP`, `TRUST_WIDTH`)
- Modify: `crates/git-time-cli/src/cmd/picker.rs:233-349` (`frame`, `row`, `trust`)
- Test: `crates/git-time-cli/src/cmd/picker.rs` (existing `mod tests`, plus every `frame(...)` call site in them)

**Interfaces:**
- Consumes: `super::probe::Cached`.
- Produces:
  - `pub enum Cell { Idle, Pending, Known(probe::Cached), Unpublished, Failed }` (`Copy`)
  - `pub struct Probes` with `pub fn idle(count: usize) -> Self`, `pub fn pending(count: usize) -> Self`, `pub fn set(&mut self, index: usize, cell: Cell)`, `pub fn cell(&self, index: usize) -> Cell`, `pub fn failed(&self) -> usize`, `pub fn unpublished(&self, presets: &[Preset]) -> Vec<&'static str>`
  - `pub fn frame(selection: &Selection, presets: &[Preset], probes: &Probes, rows: usize, cols: usize) -> String`
  - `Key::Refresh`

- [ ] **Step 1: Write the failing tests**

Replace `trust(...)`'s three arguments with a fourth `Cell`, and add:

```rust
#[test]
fn an_unpinned_row_shows_the_served_date() {
    let probes = probes_with(&[(3, Cell::Known(cached("2035-02-09")))]);
    let line = rendered(&probes, 3);
    assert!(line.contains("fetch 2035-02-09"), "{line:?}");
}

#[test]
fn a_near_served_date_keeps_the_word_and_the_day() {
    let probes = probes_with(&[(3, Cell::Known(cached("2027-01-01")))]);
    let line = rendered(&probes, 3);
    assert!(line.contains("fetch expires 2027-01-01"), "{line:?}");
}

#[test]
fn a_failed_or_unpublished_probe_is_a_question_mark() {
    for cell in [Cell::Failed, Cell::Unpublished] {
        let line = rendered(&probes_with(&[(3, cell)]), 3);
        assert!(line.contains(" ? "), "{line:?}");
    }
}

#[test]
fn a_pending_row_knows_nothing_yet() {
    let line = rendered(&probes_with(&[(3, Cell::Pending)]), 3);
    assert!(line.contains(" … "), "{line:?}");
}

#[test]
fn an_idle_row_keeps_the_old_wording() {
    let line = rendered(&probes_with(&[(3, Cell::Idle)]), 3);
    assert!(line.contains("pin -"), "{line:?}");
}

#[test]
fn a_served_root_the_bundle_lacks_marks_the_pin() {
    // FreTSA's root is pinned (2041-03-07); the probe names a root the bundle
    // does not hold, so the pin is marked.
    let line = pinned_and_probed(Cell::Known(cached_of("2035-02-09", "cc".repeat(32))));
    assert!(line.contains("pin 2041-03-07 !"), "{line:?}");
}

#[test]
fn a_served_root_the_bundle_holds_stays_quiet() {
    let line = pinned_and_probed(Cell::Known(cached_of("2041-03-07", &freetsa_fp())));
    assert!(!line.contains('!'), "{line:?}");
}

#[test]
fn a_failed_probe_does_not_mark_a_pin() {
    let line = pinned_and_probed(Cell::Failed);
    assert!(line.contains("pin 2041-03-07"), "{line:?}");
    assert!(!line.contains('!'), "{line:?}");
}

#[test]
fn the_footer_counts_failures_and_names_unpublished_rows() {
    let probes = probes_with(&[(3, Cell::Failed), (5, Cell::Unpublished)]);
    let out = frame(&picked(), &presets::PRESETS, &probes, 24, 80);
    assert!(out.contains("probe failed: 1"), "{out}");
    assert!(out.contains("served root not published: "), "{out}");
    assert!(out.contains("globalsign-r6"), "{out}");
}

#[test]
fn a_narrow_terminal_cuts_the_cell_not_the_transport() {
    let probes = probes_with(&[(1, Cell::Known(cached("2035-02-09")))]);
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

#[test]
fn r_asks_for_a_refetch() {
    assert_eq!(parse_key(b"r"), Some(Key::Refresh));
    assert_eq!(press(&mut picked(), Key::Refresh), Outcome::Stay);
}
```

`cached(date)` builds a `probe::Cached` with an unused fingerprint and `cached_of(date, fingerprint)` with both; `probes_with` is `Probes::idle(len)` plus `set` for each pair; `rendered(&probes, i)` frames with the cursor on `i` (`picked_at(i)` presses `Key::Down` `i` times); `pinned_and_probed(cell)` writes the FreeTSA fixture to `anchors/freetsa.pem`, sets freetsa's cell to `cell`, and returns freetsa's row; `freetsa_fp()` is `anchors::fingerprint` of the fixture's DER. Update all existing `frame(selection, presets, rows, cols)` calls with a `&Probes::idle(presets::PRESETS.len())` argument and every `trust(...)` call with `Cell::Idle`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --offline -p git-time-cli picker::`
Expected: FAIL — arity mismatches, then missing items.

- [ ] **Step 3: Implement**

`TRUST_WIDTH` 24. `trust` matches the cell only when the local bundle gives no root: `Known` prints `fetch [expires ]<date>` (or `fetch EXPIRED`), `Unpublished`/`Failed` print `?`, `Pending` prints `…`, `Idle` falls through to the existing `tofu` / `pin -` tails, which keep their order. A pinned row appends ` !` when the cell is `Known` and no `RootRow::fingerprint` equals `cached.fingerprint`. Footer: after the prompt line push `probe failed: n` when `n > 0` and `served root not published: <ids>` when non-empty, raising `footer` by their count. `HELP` gains `r refresh`. `Key::Refresh` is a `Stay` arm in `apply_key`; the driver, not the reducer, does the work.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --offline -p git-time-cli picker::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/src/cmd/picker.rs
git commit -m "feat: say what a probe found in the trust column

fetch/…/? separates a served date from a pinned one, so the column never
claims more than the local bundle backs. A served root the bundle does not
hold is the rotation signal and gets a marker instead of silently replacing
the pinned date."
```

---

### Task 5: Wire the worker into the driver

**Files:**
- Modify: `crates/git-time-cli/src/cmd/picker.rs:456-481` (`run`)
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:779-803` (the `probes` seed and pass-through)
- Test: `crates/git-time-cli/src/cmd/picker.rs` (a seeded `Probes` test), `crates/git-time-cli/tests/install.rs` checkpoint for the handover signature

**Interfaces:**
- Consumes: `Prober`, `Probes`, `probe::cached`.
- Produces:
  - `pub fn seed(presets: &[Preset], now: jiff::Timestamp) -> (Probes, Vec<usize>)` — cells for fresh entries are `Known`, the rest `Pending`, and the returned indices are the ones a worker must fetch
  - `pub fn run(selection: &mut Selection, presets: &[Preset], probes: &mut Probes) -> Option<Outcome>`

- [ ] **Step 1: Write the failing tests**

`certum_index()` and `aped_index()` are lookups of the preset names in `presets::PRESETS`; `cached_of` is the Task 4 helper, as is `super::probe::store`.

```rust
#[test]
fn a_fresh_cache_entry_seeds_a_known_cell_and_is_not_queued() {
    super::probe::store("certum", &cached_of("2035-02-09", "aa"), jiff::Timestamp::now());
    let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
    assert!(matches!(probes.cell(certum_index()), Cell::Known(_)));
    assert!(!missing.contains(&certum_index()));
    assert!(missing.contains(&aped_index()));
}

#[test]
fn presets_without_a_published_root_seed_idle_and_are_not_queued() {
    // No built-in row has an empty list today; assert on the shipped table so a
    // future tofu row does not start probing pointlessly.
    let (probes, missing) = super::seed(&presets::PRESETS, jiff::Timestamp::now());
    for (index, preset) in presets::PRESETS.iter().enumerate() {
        if preset.fingerprints.is_empty() {
            assert!(matches!(probes.cell(index), Cell::Idle));
            assert!(!missing.contains(&index));
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --offline -p git-time-cli picker::seed`
Expected: FAIL — no `seed`.

- [ ] **Step 3: Implement**

`seed` is a pure read over `probe::cached` and `preset.fingerprints`. `run` gains a `probes: &mut Probes` parameter, calls `seed` only after `Raw::open` succeeded (so the line-prompt path never probes), starts a `Prober` with `probe::network_fetch()` and the returned skip list, and in the loop drains into `probes` before painting. Unparsed keys (the decisecond with nothing) repaint only when the drain changed something; a resize still repaints. `Key::Refresh`: `probe::forget` every non-idle preset, mark every cell `Pending`, `prober.refresh(&[])`, repaint. `tsa::select` builds `Probes::idle(len)` for the fallback, and `run` replaces it via `seed` on the raw path.

- [ ] **Step 4: Run the tests, then the whole suite**

Run: `cargo test --offline -p git-time-cli picker::` then `cargo test --offline`
Expected: PASS, including the existing handover test.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/src/cmd/picker.rs crates/git-time-cli/src/cmd/tsa.rs
git commit -m "feat: probe in the picker's idle time

The frame paints from a snapshot before any socket opens, and results are
drained between key reads, so a slow or dead authority costs a repaint and
never the screen. r forgets the cache and asks again."
```

---

### Task 6: `tsa preset list` reads the cache and can refresh

**Files:**
- Modify: `crates/git-time-cli/src/cmd/tsa.rs:103-116` (`PresetCommand::List { refresh }`), `:178` (await), `:456-514` (`pin_state`, `preset_list`)
- Test: `crates/git-time-cli/tests/registry.rs` (a `preset list` case near the existing ones)

**Interfaces:**
- Consumes: `probe::{cached, forget, network_fetch, Prober}`, `picker::{Cell, Probes, seed}`.
- Produces: `async fn preset_list(_repo: &Repo, refresh: bool) -> Exit`.

- [ ] **Step 1: Write the failing test**

Drive the binary: `git time tsa preset list`, with `XDG_CONFIG_HOME` set and `GIT_TIME_ANCHOR_FETCH_CMD` a stub answering a FreeTSA root whose date is `2041-03-07`. Assert (a) without `--refresh` the run prints today's `-` for freetsa and writes no `probe/freetsa`, and (b) after `--refresh` the run prints `2041-03-07` for freetsa and a second plain run still prints it from the cache. Also assert a second `--refresh` calls the stub again (count the invocations in a file the stub appends to).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --offline -p git-time-cli --test registry preset_list`
Expected: FAIL — `--refresh` is an unknown flag.

- [ ] **Step 3: Implement**

`List { #[arg(long)] refresh: bool }`; `preset_list` seeds like the picker does and, with `refresh`, drops every entry, runs a `Prober` with `network_fetch()`, and loops `std::thread::sleep(Duration::from_millis(100))` until `pending() == 0` (no cap: `preset list` is the place to wait). It prints through the same `Cell` vocabulary as the picker, `tofu` for an empty fingerprint list, and the existing `-` for `Cell::Idle`. Keep the `(anchored)`/`(missing)` tail unchanged.

- [ ] **Step 4: Run the test, then the suite**

Run: `cargo test --offline -p git-time-cli --test registry preset_list` then `cargo test --offline`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/src/cmd/tsa.rs crates/git-time-cli/tests/registry.rs
git commit -m "feat: let preset list fill and show the probe cache

The headless surface gets the same dates as the picker, which is what makes
the cache useful to a timer or a CI job. Reading stays offline; only
--refresh opens a socket."
```

---

### Task 7: A terminal run, end to end

**Files:**
- Test: `crates/git-time-cli/tests/registry.rs` (reuse `run_time_pty`)

**Interfaces:**
- Consumes: everything above, through the binary.

- [ ] **Step 1: Write the failing test**

With `run_time_pty(dir, xdg, &["tsa", "select"], &[("GIT_TIME_ANCHOR_FETCH_CMD", stub)], "q\n")`, the stub appends `$GIT_TIME_ANCHOR_URL` to a log and prints the FreeTSA root. After the run assert `stdout` contains `fetch ` and a date, the log holds `https://freetsa.org/tsr`, and the second run with a stub that exits 1 still shows the cached date and exits 0. Also assert `probe/freetsa` exists and holds no `BEGIN CERTIFICATE`. `None` from `run_time_pty` skips, as the other pty tests do.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --offline -p git-time-cli --test registry probe`
Expected: FAIL — the output holds no `fetch`.

- [ ] **Step 3: Implement what the test finds missing**

Expect two things the unit tests cannot see: the frame paints before the first result, and `q` quits with a probe still in flight. If the exit waits for a thread, drop the handle; if the alternate-screen teardown races the drain, cap the drain at one `try_iter` per loop.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --offline -p git-time-cli --test registry probe`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-cli/tests/registry.rs
git commit -m "test: run the picker's probe through a real terminal

The unit tests never see the frame before a socket opens or the exit with a
probe in flight, and both are what a user meets. A cache-only second run
pins the offline path."
```

---

### Task 8: Say it in the docs

**Files:**
- Modify: `docs/manual.md:290-330` (the picker legend)
- Modify: `docs/git-time.1` (the `tsa select` and `preset list` sections, near `(expires soon)` at :529)
- Modify: `docs/STATUS.md:121` (add the row)
- Modify: `README.md` only if it shows the picker

- [ ] **Step 1: Update the legend**

`manual.md` gains the `fetch`, `…`, `?` and `!` meanings, the 7-day cache and its path, `r`, `preset list --refresh`, and the sentence that a probe pins nothing. The man page gets the same in its own voice, with `r` in the key list. `STATUS.md` gets one row: `| a served date is probed, cached for a week, and shown apart from a pin | probe, tsa select, tsa preset list | shipped |`.

- [ ] **Step 2: Check the man page renders**

Run: `man -l docs/git-time.1 | col -b | grep -n "refresh\|fetch" `
Expected: the new lines, no groff warnings.

- [ ] **Step 3: Commit**

```bash
git add docs/manual.md docs/git-time.1 docs/STATUS.md
git commit -m "docs: explain probed dates, the cache and r

A reader who sees fetch next to a date has to know it is not a pin and
that a week-old answer is possible, or the column reads as evidence."
```

---

## Self-Review

**Spec coverage:** cache + TTL (Task 1), fingerprint check and newest-live choice (Task 2), four threads and `r` (Tasks 3, 5), rendering vocabulary and widened cell (Task 4), `preset list`/`--refresh` (Task 6), the no-raw and stub paths (Tasks 5, 7), docs (Task 8). Non-goals hold: no anchor write, no probe for `tofu` rows, no change to verification.

**Open choice the spec left:** footer wording (`probe failed: n`, `served root not published: <ids>`) and pool-vs-thread (four threads) are fixed in Tasks 3 and 4.
