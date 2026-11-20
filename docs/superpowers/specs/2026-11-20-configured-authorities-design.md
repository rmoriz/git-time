# Configured authorities in the listings

Status: approved approach (A) and pick resolutions; design awaiting approval.

## Intent

A repository can already carry hand-added timestamp authorities: `git time tsa add` writes a
`time.tsa.<id>.url`/`.anchor` section, and `tsa list` shows it. Neither surface where an authority
is *chosen* knows about it. `tsa select` and `tsa preset list` iterate the compiled-in
`presets::PRESETS`, so a hand-added authority is invisible exactly where the user decides what to
query, and the `tofu` tier the column already has never renders. The 2026-11-20 probe-dates review
recorded this as a deferred gap.

The same review deferred four smaller items. They ride along: an expired pin in `preset list`
rendering `?`/`-` where the picker says `EXPIRED`, `Prober::start` spawning four worker threads for
an empty queue, `probe::forget`'s blanket `allow(dead_code)`, and a `STATUS.md` "known gap" that
says `time-dropped` is never pruned when `drop::prune` has pruned it since before the review.

## Goals

1. A configured authority is a row in both listings, after the built-ins, with its own live state:
   pinned date, `EXPIRED`, `!` where a rotation is known, `tofu` where nothing is pinned.
2. Selecting it in `tsa select` keeps it; unticking it removes its section, exactly as an unticked
   preset is removed.
3. `preset list` marks such a row `custom`, so nothing reads as a built-in preset.
4. A configured authority that points at a non-default anchor path is rendered from *that* path,
   not from `dir()/<id>.pem`.
5. A bundle whose roots are all expired says `EXPIRED` on both surfaces.
6. A plain `preset list` and a plain `tsa select` spawn no probe worker.
7. The four small items are closed without changing a verdict, the TTL, or verification.

## Non-goals

- Making a custom row *fetchable* from `select`/`preset list`. There is no anchor URL in the config
  for one, so a selected custom row is kept, not re-pinned; `git time anchor fetch --id` stays the
  way to pin it. A future `time.tsa.<id>.anchor-url` plus `tsa add --anchor-url` would lift this.
- Probing custom rows. A probe judges a served root against a published fingerprint list; a custom
  authority has none, so it has no `fetch <date>` and no `!`. It shows its pin state only.
- Changing what `tsa add`, `anchor fetch`, `install` or `tsa preset add` write.
- Ticking built-in rows differently from today. `already_enabled` keeps seeding from config.

## Anti-goals

- A row whose pin state is read from the wrong bundle. A custom path rendered as `pin -` while the
  authority is pinned elsewhere is worse than not listing it.
- An unticked custom row surviving a save, or a kept one losing its configured url, alg or policy.
- Two sources of truth for the anchor path between the renderer and `install::pin`.
- A picker whose index space and `apply`'s disagree: choosing row 23 must act on row 23.

## Constraints

- Tests hermetic (`GIT_CONFIG_GLOBAL=/dev/null`, temp `XDG_CONFIG_HOME`), `cargo` runs `--offline`,
  `fmt --check` and `clippy -D warnings` green before every commit.
- One `now` per run; a row must not straddle an expiry between its date and its marker.
- The row order is stable: built-ins in table order, then configured-only rows in id order.
- No new config key, no change to `Preset`'s published-data semantics beyond the one path field.
- A probe worker is started only when there is something to fetch, whichever call first puts it
  there.

## Approaches

**A — leak the merged table (chosen).** `tsa::rows(&repo)` returns `&'static [Preset]`: the built-in
table, then one row per configured section the table does not name, each owned string leaked for the
process. `Preset` gains `anchor_path: Option<&'static Path>`; `None` means the default
`dir()/<name>.pem`, and the two renderers resolve through it. `picker::run`, `frame`, `seed`,
`Prober::start` and `install::pin` keep their `&'static [Preset]` shapes, so 93 existing call sites
and every probe path stay untouched. Custom rows carry empty fingerprints, which `seed`, `refresh`
and `trust` already treat as "nothing published": idle, unqueued, `tofu`.

*Trade-off:* `Preset` is a type about published data and now carries one piece of local config, and
the process leaks a handful of strings per run. In exchange the diff stays inside `tsa.rs`, two
renderers, `tz::apply` and the docs, and no test that renders a static table changes.

**B — an owned `Row` type in the CLI.** `Row { name: String, url: String, …, anchor: PathBuf,
builtin: bool }`; `Preset` stays purely published; `run`, `frame`, `seed`, `Prober`, `trust` and
`install::pin` all take `&[Row]`, and `Prober` owns its rows. The honest model. Rejected because it
rewrites 93 call sites and splits `install`'s `Authority = Preset` alias for no behavioural gain — a
CLI process is about to exit anyway, so the leak costs nothing observable.

**C — add `time.tsa.<id>.anchor-url` so custom rows re-fetch.** Crosses A or B. Real value, but
existing rows would still lack the key and stay keep-only, so it buys nothing now and doubles the
config surface. Deferred.

## Design

### Rows

`tsa::rows(repo) -> Result<&'static [Preset], Exit>`:

- Clone `presets::PRESETS` (`Preset` derives `Clone`; all fields are cheap).
- Read every `time.tsa.<id>.*` section once (`anchors::listing`), and for each id that carries a
  `url` or an `anchor` (`anchors::tsa_ids` already draws that line), in id order:
  - if the id names a preset, override that row from the section — leaked `url`, `alg`, `policy`,
    `insecure_http` where set, and `anchor_path` always: the section is what seals and what the
    probe must talk to, and a mirror serves the same published roots, so the `!` comparison stays
    meaningful;
  - if the id is unknown and has a `url`, push a row from the section: leaked name, url, `alg`
    (default `sha256`), leaked `policy` when set, `insecure_http`, `anchor_url` and `chain` empty,
    `fingerprints` empty, `curated: false`, `anchor_path: Some(leaked path)`.
- Leak the vector and return the slice.

An unknown id with an `anchor` but no `url` is not renderable (nothing could be enabled from it) and
is **not** a row: it must therefore also stay out of `unwanted`, so no save deletes a section the
table never showed. A preset id with an `anchor` and no `url` is a row, because the preset supplies
the url.

### Rendering

`picker::row` and `preset_list` resolve `preset.anchor_path`, else `dir()/<name>.pem`, and read the
bundle from there. Nothing else about the column changes.

`pin_state` gains the expired branch the picker's `trust` already has: a non-empty bundle whose roots
are all expired says `EXPIRED`, with the `!` rule unchanged on top of it. It takes the roots
`preset_list` already read.

`preset_list`'s scope column gains `custom` for a row `presets::find` does not know. The line prompt
in `tsa select` prints the same three words.

A custom row with no bundle reads `tofu` on both surfaces — the same word `trust` already gives an
empty fingerprint list, and the honest one for trust on first use. `not pinned` stays for a
hand-added *preset* that publishes no root (none ships today, the branch keeps its unit test).

### Selection and apply

- `already_enabled` seeds every configured id's index in the row table, so an empty answer keeps
  everything including custom rows.
- `accepted` and `apply` take the row slice instead of `PRESETS`; every `presets::PRESETS.get(index)`
  becomes `rows.get(index)`.
- `accepted` keeps only ids the table knows: a custom row is never fetched, so a bare `--accept`
  fingerprint resolving to one would name an authority the run does not fetch.
- `apply`'s `unwanted` is every *row* that is configured and not chosen — preset or custom — so
  unticking disables either. `disable` is unchanged: it removes the section and leaves the anchor
  file.
- For a chosen custom row `apply` prints `kept <id> (<url>)` (or `would keep …` under `--dry-run`)
  and does not call `install::pin`. A chosen preset row still pins as today.
- `ask`/`parse_choice` take the row count; numbering covers every row.

### The four small items

- Probe workers start lazily. `Shared` keeps the `Sender`, `start` spawns the workers only when its
  initial queue has a row, `refresh` spawns them on the first refresh that enqueues anything (so a
  fresh cache does not leave `r` dead), and `settle` takes the sender out first so the channel still
  ends on its own. A queue that never fills spawns nothing and `settle` returns after one `drain`.
- `probe::forget` becomes `#[cfg(test)]` — it is called only from tests.
- `STATUS.md`'s `time-dropped` gap becomes what `drop::prune` does: dead objects dropped and the
  oldest beyond 200, on every drop and seal.

### Docs

Manual and man page: `tsa select` and `tsa preset list` list configured authorities too, `custom`
scope, keep-only semantics, `EXPIRED` on an all-expired bundle, that a custom row reads `tofu`, and
that a custom row is pinned with `anchor fetch --id`. The manual sentence naming `tofu` and
`not pinned` as tiers no built-in needs is rewritten: both render now.

## Tests

- Rows: a configured section appears last with `tofu`; an anchor-only unknown id does not appear and
  survives a save; a configured preset id gets the configured url and path without duplicating.
- Picker: a custom row renders `tofu` and its configured bundle's date, not `pin -`.
- `preset_list`: an expired pin says `EXPIRED` on both surfaces' rendered state, a custom row says
  `custom`, and a kept custom row keeps its section and url under `--dry-run` and for real.
- Selection: an empty answer seeds a custom row; unticking it yields `unwanted`; `--accept` with a
  bare fingerprint and a chosen custom row still resolves to the one preset row chosen.
- `Prober::start` on a fully skipped table spawns nothing and settles at once; a `refresh` on it
  spawns and answers.
- The existing suite stays green; no test that renders `&presets::PRESETS` changes.

## Left to the builder

- Whether the leaked helpers live in `tsa.rs` or a small `picker::rows` module, and whether
  `anchors::listing` becomes `pub(crate)` so the sections are read once.
- The exact `kept` wording and whether a kept custom row prints its pin state.
- Whether the picker should mark a custom row in the name column as well as the wording.
- Test placement and names.
