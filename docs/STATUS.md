# git-time — implementation status

Design: `docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md`
Plan: `docs/superpowers/plans/2026-11-18-git-time-rfc3161.md`
Ledger (per-task decisions and rulings, git-ignored): `.superpowers/sdd/2026-11-18-git-time-rfc3161/progress.md`

## What works today

`git commit` seals itself with RFC 3161 tokens from one or more authorities, verified locally
before they are stored, and written into the commit object.

```console
$ git time tsa select                   # tick the authorities; anchors are pinned
$ git time install                      # wires the hooks
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
X-RFC3161-Fail: id=digicert; reason=anchor-digicert-could-not-be-read…
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
file, so a failed or garbled fetch never destroys a working anchor. A root that is neither
published by a preset nor already pinned is refused until `--accept` names it. It writes the
configured `time.tsa.<id>.anchor` path when there is one (the file the policy reads), else the
anchors directory, and needs `--insecure-http` for a plain `http` bundle URL. `anchor pin` writes
`time.anchors-lock` (one `<id> <sha256>` line per root) and `--check` names added, removed and
unparseable ids.
The lock is a review artifact, **not a trust store**: verification keeps judging from the pinned
bundle, and deleting the lock changes no verdict.

Anchors live on the machine, never in the repository, so a clone trusts nothing and reports every
token `UNTRUSTED`. `tsa restore` backfills from the one part of the setup the clone still has: it
reads the authority ids out of the evidence and pins each preset among them against the published
root. Ids without a preset name no URL anywhere, so they are named with the `add`/`fetch` steps and
the run fails; an id whose bundle is gone but that is still configured is pinned again by `install`.

Presets live in `git_time_core::presets`; `tsa select` and `tsa preset add` write keys from that
one table. Only `anchor fetch`, `preset add`, `tsa restore` and a selection touch the network, and they all
honour `GIT_TIME_ANCHOR_FETCH_CMD`. A preset's published root fingerprint is checked before
it is pinned; a mismatch is refused and leaves the previous anchor alone. A row without a published
root, such as a hand-added authority, is trust on first use and prints the fetched fingerprint,
which is the only reviewable artifact of the first pin. Plain-`http` presets record
`time.tsa.<id>.insecure-http`; all of them share one capped warning
line at seal time.

## Surviving a root rotation (shipped)

Every row is in the tree with a test; the halves were tasks 1–13 of
`docs/superpowers/plans/2026-11-19-tsa-rotation.md` and the whole story is one scenario
(`history_survives_a_rotation_end_to_end`, task 14: seal under A, refuse the fetch to B, accept it,
old commit still verifies, new block names B, one line added to the lock). `docs/manual.md` has the
operator section.

| Guarantee | Where it lives | Status |
|---|---|---|
| the token's signed signer identifier is enforced (`ess-missing`, `ess-mismatch`, `ess-malformed`, `tsa-name`) | `git_time_core::verify::token` | shipped |
| a bundle may carry several roots; every certificate is classified and each root is a trust anchor in file order | `AnchorStore`, `Anchor::roots` | shipped |
| a root vouches only for tokens inside its own validity window | `roots_at`, the candidate loop | shipped |
| a block names the roots valid at its tokens' `genTime`, inside the signed block | `X-RFC3161-Anchor`, `docs/format.md` | shipped |
| `anchor fetch` refuses a changed root, prints both fingerprints and writes nothing | `anchor fetch` | shipped |
| `--accept <id>=<fingerprint>` appends ahead of the retired root, deduplicated | `install`, `anchor fetch`, `tsa restore`, `tsa preset add` | shipped |
| the lock records one line per root, so a rotation is an `added` and a `removed` line | `anchor pin`, `anchor pin --check` | shipped |
| `doctor` names `no root valid now` and a HEAD-named root that is not pinned | `doctor` | shipped |
| `verify --openssl` embeds the roots the block names plus all pinned intermediates, judged with `-attime` | `verify --openssl` | shipped |
| the expiry column marks past and near dates and reads them from the local bundle | `tsa list`, `tsa select`, `tsa preset list` | shipped |
| a preset keeps a list of published roots, so an accepted rotation is recorded at release time | `presets` | shipped |
| the refusal vocabulary and the anchor line are specified | `docs/format.md` | shipped |

## Adoption (Task 15)

`README.md` is the front door, `docs/manual.md` the operator manual. `.github/workflows/ci.yml`
runs fmt, clippy and the suite on Ubuntu, for branches and pull requests. The four targets are built
only on a tag, by `.github/workflows/release.yml`, in two jobs (one per OS); its macOS job runs the
same suite before it packages, and the publish is refused unless the suite is green. That is
deliberate: the account serves about two concurrent macOS runners and cancels a job that queues for
more than fifteen minutes, which fails the run, so an ordinary push spends no slot on binaries
nobody waits for. A job so cancelled twice is what kept `v0.1.0` from publishing. A release attaches
the four bare binaries and nothing else — no archive, no checksum file — so a download is a
`chmod +x` and a run. The musl targets build in separate target dirs, so no host-built build script
crosses a container boundary.

A tag is the only thing that reaches that build: a documentation-only push costs the Ubuntu suite
and nothing more. The suite still runs on both, so an empty check list never appears on a pull
request. No markdown file is compiled in, so a doc change cannot break a build either.

GitHub reports capacity constraints on arm64 macOS runners, and a queued-out job is cancelled
after fifteen minutes, so the darwin job targets the Intel pool (`macos-15-intel`) instead of
`macos-latest` and fails itself at thirty. When it is cancelled anyway,
`.github/workflows/macos-retry.yml` reruns the failed jobs once — on a tag that means the macOS job
and the publish that was waiting on it; `v0.1.0` published on the first retry. The retry is bounded
by `run_attempt == 1`, so a genuinely broken job stays red. A tag is never force-pushed to work
around it. `tests/live_tsa.rs` is the ignored smoke test against the public authorities:

```console
$ cargo test -p git-time-cli --test live_tsa -- --ignored --nocapture
```

It skips when the network is gone and removes its repository and fetched anchors otherwise.

### Why the macOS fixtures name their algorithms

The suite is the same everywhere, but the `openssl` a run meets is not: macOS `/usr/bin/openssl` is
LibreSSL 3.3.6, and the CI image puts Homebrew `openssl@1.1` (1.1.1w) ahead of it. Their defaults are
outside what `webpki` verifies, and every symptom below started as a red macOS leg with no clue in
the log — hence the fixture rules and the `openssl version -a` line a failed seal now prints:

| Old-`openssl` default | Symptom | Fixture now |
|---|---|---|
| `x509 -req` / `req -x509` sign SHA-1 | `reason=invalid-untrusted`: `webpki` has no SHA-1 verification algorithm at all | `-sha256` on every certificate |
| `req -newkey ec` writes `SpecifiedECDomain` instead of a named curve | `reason=invalid-malformed`: no curve OID to map to a key type | `-pkeyopt ec_param_enc:named_curve` |
| `-CAcreateserial` writes a bare `.srl` into `$TMPDIR`, not next to the CA | parallel fixtures read each other's half-written serial | a per-CA serial file with `-CAserial` |
| 1.1.1 adds `basicConstraints CA:TRUE` to `req -x509` by itself, so `-addext basicConstraints` duplicates it | `ExtensionValueInvalid` from `webpki`, which refuses duplicate extensions | CA extensions from a `-config` section |

Three `openssl`s are worth testing against, because each broke something the others did not:
`/usr/bin` first (LibreSSL), `/opt/homebrew/opt/openssl@1.1/bin` first (1.1.1, what CI sees) and the
Homebrew default (4.x). Keep `~/.cargo/bin` before `/opt/homebrew/bin` in a probe `PATH`, or the
Homebrew `rustc` shadows the pinned toolchain and the cross target loses `core`.

The verifier itself also learned the two token shapes, because a TSA may emit them: SHA-1 signer
infos are verified through a pre-hash fallback (`ring` has no SHA-1), and an explicit-parameter leaf
is tried against both supported curves. A *chain* whose own signatures are SHA-1, or whose CA states
explicit parameters, still fails in `webpki` (see the known gaps).

## Deviations from the design, and why

| Design said | Shipped | Reason |
|---|---|---|
| everything from `post-commit` | `post-commit` **and** `post-merge` | measured: `git merge` fires `pre-merge-commit`/`post-merge`, never `post-commit` |
| `STALE` verdict for replayed patches | `BAD-IMPRINT` | with `Object` being derived, the imprint already decides; one less verdict |
| `--openssl` script re-derives the commit with `git` and `awk` | payload embedded: pre-image in clear, tokens base64 | it needs only `openssl`, and a reader sees exactly what is judged |
| block without a token and without a `Fail` line is `UNDER-QUORUM` | `NONE` | nothing was asked, so no authority stayed silent; the line is said with the setup that is missing |
| `X-RFC3161-Object` = commit oid | oid of the *timestamped bytes* (`hash-object` of the pre-image) | the input oid is not reproducible from the sealed object; this is, and makes idempotence work for signed/note commits |
| RFC 3161 §2.3 via the library | enforced by us: critical EKU, sole purpose `timeStamping` | `webpki` ignores EKU criticality; FreeTSA’s leaf satisfies the strict reading |
| `Required` keys seconds-only | also `10s`, `500ms` | ergonomics |
| `UNSIGNED` verdict | unsigned commit stays `SEALED`, reported as `unsigned` in the `signature` field; `--require-signed` fails it | a gate is not evidence: the verdict names what the block is, and CI reads `pass` for the policy |
| any commit may be sealed | never rewrite a commit reachable from a remote-tracking ref | `post-merge` also fires on a fast-forward `git pull`; sealing would make the next push non-fast-forward |
| the path is held to `timeStamping` exactly | `required_if_present` on the path, the strict rule only on the signer | RFC 5280 makes a CA's EKU a restriction only when present; the DFN, Belgium and CESnet CAs carry none |
| the GET body is the bundle only if PEM | a PEM, DER or PKCS#7 certificate body is the bundle | Belgian and Portuguese roots are served as DER; the bundle format is PEM, so the body is re-encoded |
| the anchor is the reply's root | the root the top certificate's AIA `caIssuers` leads to when the reply stops short | ten authorities embed no root; the measured fingerprints were read from that pointer, and every fetched certificate still has to pass the pin |
| the bundle is one URL | a preset may carry a chain of issuer URLs, appended behind the root | `cartaodecidadao` embeds the signing leaf alone and publishes no `caIssuers`; without its two issuers the chain cannot be built, and pinning only the root would make every token `untrusted` |
| DER as written | three tolerated shapes: unsorted signed attributes, fractional genTime, a two-byte policy OID | Apple and Lex Persona sign the attribute order they wrote; Lex Persona sends milliseconds; Apple stamps under `1.2.3`, which `der`'s OID decoder refuses. Each reading stays inside the signature |

## Known gaps

- Verdicts are computed per commit and never replayed across a range: a forged parent does not
  taint a child.
- A selection fetches anchors over the network; behind a firewall it warns and leaves the
  repo unsealed rather than broken (`doctor` names the missing anchor).
- `seal --range` cannot rewrite descendants of a range member; those dangle until re-sealed.
- Failure reasons are sanitised into one trailer line, so an absolute path appears truncated.
- `webpki` has no SHA-1 and no explicit-parameter support for *certificate* signatures: a TSA whose
  chain is signed SHA-1, or whose CA encodes its curve explicitly, is rejected as `invalid-untrusted`
  before the token itself is judged. The token's own CMS signature handles both shapes, so only the
  chain build relies on `webpki`; walking the chain ourselves would lift it.
- `time-dropped` grows without pruning in long-lived clones.
