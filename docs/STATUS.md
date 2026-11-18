# git-time — implementation status

Design: `docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md`
Plan: `docs/superpowers/plans/2026-11-18-git-time-rfc3161.md`
Ledger (per-task decisions and rulings, git-ignored): `.superpowers/sdd/2026-11-18-git-time-rfc3161/progress.md`

## What works today

`git commit` seals itself with RFC 3161 tokens from one or more authorities, verified locally
before they are stored, and written into the commit object.

```console
$ git time install --preset public      # wires the hooks, fetches anchors
$ git commit -m "add entry point"       # the only command the user types
rfc3161: sealed e595e4c by 1/2 TSA(s)
```

Real transcript from this machine with FreeTSA pinned, its anchor present, and the TSA
unreachable (the host firewall blocks the binary's egress):

```
rfc3161: sealed e595e4c under quorum (0 of 1) — see git time verify
[main 71068e2] add third
add third

X-RFC3161-Imprint: sha256:826b49a7b93ae87cf483701418fddbf95d0c43bc2dcb6571e222331288ee5a7a
X-RFC3161-Object: 71068e2caa5a3fbf20d03ad72c55d012caed45d2
X-RFC3161-Fail: id=ai-moda; reason=anchor-ai-moda-could-not-be-read…
X-RFC3161-Fail: id=freetsa; reason=timeout
```

The commit exists, the worktree is clean, `git fsck` is silent, and the artifact says exactly
which authority failed and why. That is the fail-open contract: a dead TSA costs evidence, never
a commit.

Sealed commits survive: clone/push (the block is in the object), signature re-creation under the
same header (`gpgsig` or `gpgsig-sha256`), merges, cherry-picks, rebases, `--amend`, `--allow-empty`,
and detached HEAD.

## Implemented and reviewed (Tasks 1–14)

| Task | Delivered |
|---|---|
| 1–2 | fail-closed commit parser, byte-exact composer, pre-image extraction |
| 3–4 | imprint digests, trailer codec (zstd, bounded decode, size cap) |
| 5 | signature inspection, key extraction, re-signing (OpenPGP + SSH, sha1/sha256 repos) |
| 6 | repo plumbing, CAS ref move with retry classification |
| 7–8 | RFC 3161 request/response, parallel fan-out with deadline, quorum, retries, capped bodies |
| 9 | fail-closed token verification (CMS + chain to pinned root + signed-attr binding + strict EKU) |
| 10 | seal orchestrator with the pre-CAS invariant, idempotence, notes mode |
| 11 | hook (post-commit, post-merge), `seal --range`, `drop`, `pre-commit` gate, published-commit guard |
| 12 | `install`/`uninstall`/`doctor`, hook chaining without destroying user hooks, presets |
| 13 | `verify`/`log`: verdict matrix, per-TSA evidence, JSON, quorum and signature gates |
| 14 | `tsa add/list/remove`, `tsa preset list/add`, `tsa select`, `anchor fetch/list/pin`, shared preset table |

399 tests (one a live-network test, `#[ignore]`), `clippy -D warnings`, `fmt --check` clean. Every
task passed an independent review with fix rounds; the crypto review attacked nine specific
failure modes and mutation-tested the two load-bearing checks.

## Verification

`git time verify [--range R] [--require-sealed] [--require-signed] [--json] [<commit>…]` judges
each commit once, without a TSA call, and exits `0` only on a clean PASS. A tampered message, a
bad token, a missing anchor and a broken signature all fail; a dropped marker and a committer
date after the token's genTime are reported without failing. `git time log [--range R]` prints the
same evidence as one line per commit; `log` is a record and exits `0` when it could read
everything, so only `verify` gates.

## Authority registry

`git time tsa add <url>` registers an authority in the **local** config; the id is derived from
the host unless `--id` names one, and is restricted to `[a-z0-9-]`. `http://` needs
`--insecure-http`, a policy OID is validated by the request builder before anything is written,
and a duplicate id changes nothing. `tsa remove` deletes the section whole.

`anchor fetch <url> --id <id>` parses a bundle into certificates before replacing the pinned
file, so a failed or garbled fetch never destroys a working anchor. It writes the configured
`time.tsa.<id>.anchor` path when there is one (the file the policy reads), else the anchors
directory, and needs `--insecure-http` for a plain `http` bundle URL. `anchor pin` writes
`time.anchors-lock` (one `<id> <sha256>` line per authority) and `--check` names changed and
unparseable ids.
The lock is a review artifact, **not a trust store**: verification keeps judging from the pinned
bundle, and deleting the lock changes no verdict.

Presets live in `git_time_core::presets`; `install --preset public` and `tsa preset add` write
the same keys from that one table. Only `anchor fetch` and `preset add` touch the network, and
both honour `GIT_TIME_ANCHOR_FETCH_CMD`. A preset's published root fingerprint is checked before
it is pinned; a mismatch is refused and leaves the previous anchor alone. The presets without one
are trust on first use and print the fetched fingerprint, which is the only reviewable artifact of
the first pin. Plain-`http` presets record `time.tsa.<id>.insecure-http` and warn at seal time.

## Adoption (Task 15)

`README.md` is the front door, `docs/manual.md` the operator manual. `.github/workflows/ci.yml`
runs fmt, clippy and the suite on Ubuntu and macOS; `.github/workflows/release.yml` builds the two
musl and two darwin targets on a `v*` tag, with `SHA256SUMS`. Each workflow builds both targets of
an OS in one job, so a tag push occupies one macOS runner rather than four — four parallel macOS
jobs overran the runner slots once and a queued job was cancelled before it started, publishing
nothing. The release workflow refuses to publish unless the same suite is green. `tests/live_tsa.rs` is the ignored
smoke test against the public authorities:

```console
$ cargo test -p git-time-cli --test live_tsa -- --ignored --nocapture
```

It skips when the network is gone and removes its repository and fetched anchors otherwise.

## Deviations from the design, and why

| Design said | Shipped | Reason |
|---|---|---|
| everything from `post-commit` | `post-commit` **and** `post-merge` | measured: `git merge` fires `pre-merge-commit`/`post-merge`, never `post-commit` |
| `STALE` verdict for replayed patches | `BAD-IMPRINT` | with `Object` being derived, the imprint already decides; one less verdict |
| `X-RFC3161-Object` = commit oid | oid of the *timestamped bytes* (`hash-object` of the pre-image) | the input oid is not reproducible from the sealed object; this is, and makes idempotence work for signed/note commits |
| RFC 3161 §2.3 via the library | enforced by us: critical EKU, sole purpose `timeStamping` | `webpki` ignores EKU criticality; FreeTSA’s leaf satisfies the strict reading |
| `Required` keys seconds-only | also `10s`, `500ms` | ergonomics |
| `UNSIGNED` verdict | unsigned commit stays `SEALED`, reported as `unsigned` in the `signature` field; `--require-signed` fails it | a gate is not evidence: the verdict names what the block is, and CI reads `pass` for the policy |
| any commit may be sealed | never rewrite a commit reachable from a remote-tracking ref | `post-merge` also fires on a fast-forward `git pull`; sealing would make the next push non-fast-forward |

## Known gaps

- Verdicts are computed per commit and never replayed across a range: a forged parent does not
  taint a child.
- `--preset public` fetches anchors over the network; behind a firewall it warns and leaves the
  repo unsealed rather than broken (`doctor` names the missing anchor).
- `seal --range` cannot rewrite descendants of a range member; those dangle until re-sealed.
- Failure reasons are sanitised into one trailer line, so an absolute path appears truncated.
- `time-dropped` grows without pruning in long-lived clones.
