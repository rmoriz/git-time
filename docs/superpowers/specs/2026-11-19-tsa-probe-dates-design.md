# Probe dates for unpinned presets

Short design. The picker (`tsa select`, and `install` handing over to it) shows a
root's expiry only for an authority already pinned on this machine; the other
rows say `pin -`. The one field that says *when this row needs attention* is
known for a second at measure time and then thrown away, and nothing looks again.

## Why

Choosing an authority blind means choosing one whose root may be months from
expiry, or already rotating. `pin -` is honest but useless: it says "not pinned
here", not "here is what the authority serves and when it dies". Nine of the
twenty-one presets read that way on a fresh machine, and they are exactly the
ones a new user has never seen a date for.

## Goals

- Every row carries the expiry of the root the authority serves **now**, within
  seconds of opening the picker, without the table waiting for the network.
- A served date is only believed when the served root matches a fingerprint the
  preset publishes.
- A refresh is cheap enough to happen on its own: a cached date is reused for a
  week, `r` refetches, and a handler that fetched a moment ago is not asked
  twice.
- Failure is visible and harmless: `?` in the row, a count in the footer, and
  the picker still saves.

## Non-goals

- A probe pins nothing. It writes no anchor, so `pin -` and the save path stay
  the only things that make a root trusted.
- No probing in the line-prompt fallback, and none in `tsa list`.
- No scheduler, daemon or background service. `tsa preset list --refresh` is the
  thing to put in a timer if someone wants one.
- Quorum, verification and the block format are untouched.

## Anti-goals

- The first frame waiting on a socket.
- A probe writing into `anchors/`, or over a `--accept` decision.
- A week-old date presented as current: the word `fetch` and the stored
  timestamp keep it distinct from `pin`.

## Approaches

**A — bake a measured date into the preset table.** Offline and instant, but a
claim about the day it was measured; goes stale exactly when a rotation makes it
interesting, and needs a re-measure step nobody owns.

**B — probe with a cache (chosen).** The table stays offline, the picker stays
instant, and the date comes from the authority itself. Costs: network in a
picker, plain-http endpoints, and a cache that can lie for up to the TTL — hence
`fetch` as its own word and the fingerprint check before a date counts.

**C — leave it and make `pin -` actionable.** One key press on the cursor row.
Cheapest, but still one press per authority and no overview.

B was picked. A's staleness is the problem the question was about; C does not
answer "which of these is about to expire".

## Decisions (mine, correct them)

- **Cache** in `probe::dir()`, a sibling of `anchors/`
  (`$XDG_CONFIG_HOME/git-time/probe/<id>`), one line of three tab-separated
  fields: the `YYYY-MM-DD`, the unix time it was fetched, and the SHA-256 of the
  served root in `anchors::fingerprint` spelling. Config home rather than
  `XDG_CACHE_HOME` because `dir()` already honours it and every test points it
  at one temp dir. The date is what a listing reads; a line whose other fields
  will not parse is stale. The fingerprint is carried because the `!` marker is
  a comparison against the local bundle and would otherwise vanish on restart.
- **TTL 7 days.** A week-old date still catches a rotation; the window is short
  enough that a stale row is rare.
- **A probe is accepted only against a published fingerprint**
  (`install::fingerprint_matches`, any value, its own digest length). A bundle
  that matches nothing is `?` and the footer names it `served root not
  published` — that line is the rotation signal. An empty fingerprint list
  (none left) is `?` too, since nothing can be checked.
- **Only a live, matching root's date is used**: the newest one still valid at
  `now`, which is the root a pin would fetch first.
- **Threads: four**, a queue by preset index, one `anchors::fetch_chain` per row
  with its existing 10 s timeout. Detached; the process exit ends them. Results
  go over one `mpsc` channel that the key loop drains between keys.
- **Rendering.** Pinned rows keep `pin <date>` unchanged, plus `!` when a
  matching probe names a root the local bundle does not hold. Unpinned rows:
  `fetch <date>`, `fetch expires <date>` within 90 days, `fetch EXPIRED` past,
  `…` while queued or in flight, `?` when the probe failed. `TRUST_WIDTH` grows
  to 24 to fit `fetch expires <date>`.
- **`r` refreshes**: requeue every row, repaint. The help line gains it. No
  entry is dropped first: the requeue forces the fetch, and a reply that is not
  `Known` leaves the previous entry to age out against the TTL, so a refresh
  during a network blip does not wipe the dates the next run shows.
- **`tsa preset list`** reads the cache and never fetches, gaining `--refresh`
  that runs the same probe and prints the same column.
- **The last frame before the user leaves is not special**: no fetch is repeated
  once its result has arrived, because the cache is written first.

## Where it lives

`cmd/probe.rs` (new: cache read/write, the worker, `probed_from`),
`picker.rs` (snapshot argument to `frame`, the `…`/`?`/`fetch`/`!` cells, `r`),
`tsa.rs` (`preset list` reading and `--refresh`), `manual.md` and `git-time.1`
(legend), `STATUS.md` (a row).

## Failure modes to test

| Situation | Expected |
|---|---|
| picker opens with no cache | first frame draws before any fetch is awaited |
| entry fresh | that id is not fetched |
| entry 8 days old | that id is refetched |
| `r` | every id is refetched, a `Known` answer replaces the old entry |
| stub serves a published root | `fetch <date>` |
| stub serves a foreign root | `?` and `served root not published` |
| stub fails | `?`, the picker still saves |
| pinned row, stub serves another published root | `pin <date> !` |
| pinned row, one probe fails | `pin <date>`, no `!` |
| no raw terminal | no fetch at all, `pin -` as today |
| `GIT_TIME_ANCHOR_FETCH_CMD` set | no socket, the stub answers |
| after a probe | the cache holds a date and a timestamp, no certificate |

## Left to the builder

Footer wording for the failure count and the rotation line, pool vs. single
thread, and whether `preset list --refresh` reuses the picker's worker.
