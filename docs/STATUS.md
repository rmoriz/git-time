# git-time — implementation status

Design: `docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md`
Plan: `docs/superpowers/plans/2026-11-18-git-time-rfc3161.md`
Ledger (per-task decisions and rulings, git-ignored): `.superpowers/sdd/2026-11-18-git-time-rfc3161/progress.md`

## Release notes (v0.3.1)

A later release adds its own heading above this one.

- The decoder behind stored tokens moves to zstd 1.6.0 (`zstd` 0.14.5), which closes
  CVE-2026-124851 and a batch of memory-safety bugs upstream. Token payloads are zstd frames a third
  party wrote, so this is the path where the fix matters: `git time verify`, `show` and `log` read
  them with the fixed decoder.
- The DER stack moves to `der` 0.8 / `x509-cert` 0.3, with `cms` 0.3.0-rc.2 so CMS, DER and X.509
  stay on one type generation — a CMS type on the old generation meets no conversion to the new one.
  Nothing in the CLI changes; the suite pins the bytes of every fixture and golden, and the ignored
  live test seals and verifies against a real authority through the new parsers before a release
  goes out. `sigstore-tsa` stays on 0.16 and meets us only at the byte-based `DerCertificate`.
- `unsafe` is denied workspace-wide. The one remaining block is the `signal(2)` call that restores
  `SIGPIPE`'s default, with its SAFETY argument inline; the test harnesses that set process
  environment carry a reasoned `allow` each, under `undocumented_unsafe_blocks`.
- `rust-toolchain.toml` pins the exact compiler the checks and the release build use (1.100.0), and
  `clippy.toml` reads the 1.88 floor so no suggestion reaches past what a packager may build with.
- `jiff` 1.0 and `base64` 0.23; the four `to_zoned` call sites become `to_zoned_datetime` for the
  `Zoned` → `ZonedDateTime` rename. Neither reaches a command-line surface.
- The suite stops flaking on a loaded runner: a killed `gpg-agent` is waited out until it is reaped
  rather than until `pgrep` stops listing it, and the probe table's refresh test parks its workers in
  a gate instead of racing a file read that can answer a row before the assertion.
- The workflow actions move to the Node 24 line (`checkout` v7, `cache` v6, `upload-artifact` v7,
  `download-artifact` v8, `action-gh-release` v3). `download-artifact` v8 also checks artifact
  digests and fails the release on a mismatch instead of warning about it.

## Release notes (v0.3.0)

A later release adds its own heading above this one.

- `--accept` that named nothing the anchor served reported a successful first pin, where nothing had
  been pinned to compare against; that is a mismatch now. `Applied::Replaced` carries how many roots
  were compared, so a checked root and a repeated one no longer look alike, and a `confirm` naming
  one root says how many others it covers instead of confirming the bundle silently.
- The pin line is printed before the marker is written, so a warning about an unconfirmed pin is no
  longer preceded by a success line; a first pin under a configured authority names that scoped
  wording in its remedy. `doctor` fetches from the preset's anchor URL rather than a guessed one,
  `tsa pin-state` lists rows the way `tsa list` does, and `scoped_get`/`unset_key` clear every
  duplicate of a key.
- A check tag now fails in seconds on a manifest that disagrees with it, and the release jobs carry
  bounded timeouts: a tag that would publish four binaries naming another release, or stall on a
  queued runner, no longer waits to be noticed by hand.
- The test fixtures stop leaking `gpg-agent`/`scdaemon` pairs. The drop SIGKILLs the agent and its
  children and waits, a home whose owning pid is dead is reaped by the next run, and homes from
  before the marker are only reaped once a minute old so a starting run is never raced. Measured
  with 150 leftovers against 40 free process slots: the suite failed before and passes after, and
  the process count is flat across runs.
- The README shows the seal path as a diagram instead of only prose, and documents `time.required`
  and the cost of a single pinned authority — the key is read wherever evidence is judged, never
  stored in a commit, so raising it re-grades older seals.
- RustCrypto moves to the constant-time generation: `rsa` 0.10 on `crypto-bigint` 0.7, `p384` 0.14,
  `sha1`/`sha2` 0.11. This clears RUSTSEC-2023-0071 and RUSTSEC-2026-0387 (RSA and `crypto-bigint`
  timing), and `url` 2.5.9 clears RUSTSEC-2026-0592; it also collapses the duplicated generation
  the tree had been building. `cargo deny` gates advisories, licenses, bans and sources in CI, and
  dependabot opens weekly grouped update PRs.

## Release notes (v0.2.0)

A later release adds its own heading above this one.

- A preset now carries the `notAfter` of its newest published root, measured at release and shown
  as `listed <date>` where neither a bundle nor a cached answer says anything. A test fails once a
  date passes, so a stale row reaches a release decision instead of a user.
- `tsa add <url> --fingerprint <fp>` stores the expected root, so a custom authority's first pin is
  a comparison rather than trust on first use. A first pin without one is marked
  `time.tsa.<id>.tofu`; `doctor` reports it and exits 1, the seal warns on one capped line, and
  `git time anchor confirm <id> [<fp>]` clears it. A re-fetch of the same root does not.
- The preset table gains `actalis`. Its free endpoint re-dates the token to 2030-09-22 and answers
  on plain http only (port 443 times out), so the row is opt-in. It chains to the general Actalis
  Authentication Root CA, not to the TSA root the legal repository advertises; the measured
  Authentication Root is pinned, and the anchor comes from Actalis's published root and
  intermediate downloads because a GET of the endpoint leaves the next POST at 503.
- Every request now carries a `git-time/<version>` `User-Agent`; Actalis's front proxy answers a
  request without one with 503. A probe reads a preset's anchor URL rather than its endpoint for
  the same reason.
- The served date a probe answers now outranks the table in `tsa list` too, and a rotation reply
  that appends a root nothing compared keeps the unconfirmed pin's marker. `insecure-http` is read
  strictly there, so a junk value is a configuration error like everywhere else. A marked pin whose
  bundle is gone names the fetch that restores it before `confirm`, and `confirm` unsets the key in
  the scope it actually lives in.

## Release notes (v0.1.0)

A later release adds its own heading above this one.

- `log`, `verify` and every other command read the policy with one `git config` call instead of
  eleven, judge a commit with one `cat-file` instead of two, and check a signature on the object
  git already stores instead of hashing it back in. `git time log | head` on a 149-commit
  repository went from 0.18 s to 0.07 s.

- A row that publishes a root also carries the `notAfter` of its newest published one, measured at
  release and shown as `listed <date>` where neither a bundle nor a cached answer says anything. A
  test fails once a preset date passes, so a stale row reaches a release decision instead of a user.
- `tsa select` and `tsa preset list` show the expiry a published authority is actually serving
  when no root is pinned here, so a rotation is visible before it is accepted. The answer is cached
  for seven days under `$XDG_CONFIG_HOME/git-time/probe/`, and `--refresh` (or `r`) is the one path
  that asks. A plain run stays offline.
- A served root the local bundle does not hold appends ` !` — on `pin <date>` as well as beside
  `?`. The marker is read from the cached answer, so a failed refresh keeps it instead of blinking
  it off.
- The cache only accepts the one entry shape a probe writes; a hand-edited or truncated line is a
  miss and is refetched rather than shown as a date.
- `tsa add <url> --fingerprint <fp>` stores the expected root, so a custom authority's first pin is
  a comparison rather than trust on first use. A first pin without one is marked
  `time.tsa.<id>.tofu`; `doctor` reports it and exits 1, the seal warns on one capped line, and
  `git time anchor confirm <id> [<fp>]` clears it. A re-fetch of the same root does not.
- Listing a served date is judged against one instant per run, so a row cannot straddle an expiry.
- `tsa select` and `tsa preset list` also list a configured `time.tsa.<id>` authority no preset
  knows, after the built-ins and marked `custom` where a scope is shown. Such a row starts
  ticked, is kept rather than fetched when chosen, and loses its section when unticked (the bundle
  stays on disk). It publishes nothing, so it is never probed: it reads `tofu` until its own
  bundle is pinned, `EXPIRED` once every root there is past, and is pinned with
  `git time anchor fetch <url> --id <id> [--insecure-http]`. An unknown section with no url is no
  row and survives a save.

- The preset table gains `actalis`. Its free endpoint re-dates the token to 2030-09-22 and answers
  on plain http only (port 443 times out), so the row is opt-in. It chains to the general Actalis
  Authentication Root CA, not to the TSA root the legal repository advertises; the measured
  Authentication Root is pinned. A probe now reads a preset's anchor URL rather than its endpoint,
  because a GET of Actalis's endpoint leaves the next POST at 503.

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
it is pinned; a mismatch is refused and leaves the previous anchor alone. An authority without a
published root can be given an expected fingerprint with `tsa add --fingerprint`, which the next
pin compares and refuses on mismatch; without one the pin is trust on first use, marked with
`time.tsa.<id>.tofu`, and `doctor` keeps naming it until `git time anchor confirm` records the
comparison. `anchor fetch` prints the fetched fingerprint, the artifact the comparison is made
against. Plain-`http` presets record
`time.tsa.<id>.insecure-http`; each marker kind has its own capped warning
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
| `--accept` appends ahead of the retired root, deduplicated (bare only when exactly one authority is in play, else `<id>=<fingerprint>`) | `install`, `anchor fetch`, `tsa restore`, `tsa preset add` | shipped |
| the lock records one line per root, so a rotation is an `added` and a `removed` line | `anchor pin`, `anchor pin --check` | shipped |
| `doctor` names `no root valid now` and a HEAD-named root that is not pinned | `doctor` | shipped |
| a first pin with nothing to compare is marked, `doctor` names it with the confirming command, and `anchor confirm` clears it | `anchor fetch`, `anchor confirm`, `doctor` | shipped |
| `tsa add --fingerprint` makes the next pin a comparison, refusing a different root | `tsa add`, `accept::apply` | shipped |
| `verify --openssl` embeds the roots the block names plus all pinned intermediates, judged with `-attime` | `verify --openssl` | shipped |
| the expiry column marks past and near dates and reads them from the local bundle | `tsa list`, `tsa select`, `tsa preset list` | shipped |
| a served date is probed, cached for a week, and shown apart from a pin | probe, tsa select, tsa preset list | shipped |
| a preset's own newest-root expiry is shown as `listed <date>` when nothing local answers, re-measured at release and failing a test once past | `presets`, `tsa list`, `tsa preset list`, `tsa select` | shipped |
| a preset keeps a list of published roots, so an accepted rotation is recorded at release time | `presets` | shipped |
| the refusal vocabulary and the anchor line are specified | `docs/format.md` | shipped |

## Adoption (Task 15)

`README.md` is the front door, `docs/manual.md` the operator manual. `.github/workflows/ci.yml`
runs fmt, clippy and the suite on Ubuntu, for branches and pull requests. The four targets are built
only on a `v*` tag, by `.github/workflows/release.yml`, in two jobs (one per OS); its macOS job runs
the same suite before it packages, and the publish is refused unless the suite is green. That is
deliberate: the account serves about two concurrent macOS runners and cancels a job that queues for
more than fifteen minutes, which fails the run, so an ordinary push spends no slot on binaries
nobody waits for. A job so cancelled twice is what kept `v0.1.0` from publishing. A release attaches
the four bare binaries and nothing else — no archive, no checksum file — so a download is a
`chmod +x` and a run. The musl targets build in separate target dirs, so no host-built build script
crosses a container boundary.

A `v*` tag is the only thing that reaches that build: a documentation-only push costs the Ubuntu
suite and nothing more. The suite still runs on branches and pull requests, so an empty check list
never appears on a pull request. No markdown file is compiled in, so a doc change cannot break a
build either.

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
LibreSSL 3.3.6, and the CI image puts Homebrew `openssl@1.1` (1.1.1w) ahead of it. The tag build's
macOS job prepends `openssl@3` and asserts it; the fixture rules below come from the older default
because the image's own PATH still hands it out elsewhere. Their defaults are
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
- `time-dropped` is bounded, not exact: `drop::prune` runs on every drop, on every hook seal and on
  `seal --force`, and drops the entries whose object no longer resolves plus the oldest beyond 200.
  A commit that still exists therefore leaves the record when it is sealed again with `--force`
  (which forgets it) or when the cap pushes it out, and a file that cannot be rewritten leaves its
  stale line behind, which `seal` reports as `skipped (dropped)`.
