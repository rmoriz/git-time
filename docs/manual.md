# git-time operator manual

This is the operator manual: the configuration, the commands and the failure modes. For the
one-page pitch see the [README](../README.md); for the design and its measurements see
[docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md](superpowers/specs/2026-11-18-git-time-rfc3161-design.md).
Where this manual and the design disagree, the deviations table in [STATUS.md](STATUS.md) wins,
because it describes the shipped code.

Every command takes the global `-C DIR` option to run in another repository.

## Configuration

All keys are read from git configuration (`git config time.…`), normally in the repository-local
file written by `git time install`; the one exception is the `time.anchors-lock` file below. An
unknown value for a key with a fixed vocabulary is a configuration error (exit `2`), never a
silent fallback to the default.

| Key | Default | What it changes |
|---|---|---|
| `time.required` | `1` | Successes needed for a seal to count as sealed; `0` means best effort. |
| `time.deadline` | `10s` | Hard bound on the whole fan-out, not per authority. |
| `time.on-failure` | `warn` | `warn` prints and exits 0; `fail` prints and exits 3 (git ignores it, wrappers do not). |
| `time.gate` | `post-commit` | `post-commit` seals after the object exists; `pre-commit` is a reachability probe that refuses the commit on a short quorum. |
| `time.store` | `trailer` | Where evidence goes: `trailer` (inside the object), `note` (`refs/notes/rfc3161`) or `both`. |
| `time.seal-during-rebase` | `all` | Which rewritten commits a rebase seals: `all`, only the `tip`, or `off` with a `seal --range` hint. |
| `time.record-failures` | `true` | Whether a failed authority leaves an `X-RFC3161-Fail` line in the block. |
| `time.enabled` | `true` | Whether the hook seals at all. |
| `time.max-trailer-bytes` | `65536` | Budget for the trailer block; a breach drops the largest token and records `oversized`. |
| `time.anchors-lock` | file named `time.anchors-lock` | The review artifact `anchor pin` writes in the repository root; not a config key and not a trust store. |
| `time.tsa.<id>.url` | — | The endpoint requests are posted to; required for every authority. |
| `time.tsa.<id>.anchor` | — | The pinned PEM bundle the tokens are judged against; required. |
| `time.tsa.<id>.alg` | `sha256` | The imprint and request algorithm: `sha256` or `sha512`. |
| `time.tsa.<id>.policy` | unset | A TSA policy OID to request; validated before it is written. |
| `time.tsa.<id>.timeout` | `6s` | Per-attempt timeout. |

Durations accept `500ms`, `10s`, `3m` and bare seconds. A relative anchor path is resolved
against the repository; `~/` resolves against `HOME`.

`time.required` counts **distinct** authorities. A configured authority whose anchor bundle does
not load is left out of the seal and recorded as a `Fail` for its id (unless failures are not
recorded); only when no authority has a usable anchor does the seal refuse.

## Commands

Exit codes are one contract for every command: `0` success (a skip is a success), `1` evidence or
seal failure, `2` usage or configuration. The hook is the one exception: it exits `3` on failure
only under `time.on-failure = fail`, because git ignores a `post-commit` status. Its gate exits
`1`.

### `git time hook <event>`

The entrypoint the shims call. `event` is `post-commit`, `post-merge`, `pre-commit` or
`pre-merge-commit`; trailing arguments are passed through (`post-merge 1` is a squash). A merge
never runs `post-commit`, which is why both post hooks exist. The two `pre-*` events are the gate
and only do work under `time.gate = pre-commit`. Exits `0`, `3` under `on-failure = fail`, or `1`
from a refusing gate.

### `git time seal [--range RANGE] [--force]`

Seal HEAD, or every commit of `RANGE` oldest first. A dropped commit says `skipped (dropped)`;
`--force` seals it and re-seals a commit whose block already matches. The range form parks HEAD on
each commit and puts it back, leaving index and worktree alone; only a range ending at the branch
tip is sealed through the branch. Exits `0`, `1` if a commit could not be sealed, `2` on a bad
range or config.

### `git time drop`

Leave the next commit unsealed on purpose. The marker lives in the git directory and survives the
shell; `verify` reports `UNSEALED (dropped)`. Exits `0` or `2`.

### `git time verify [--range RANGE] [--require-sealed] [--require-signed] [--json] [<commit>…]`

Judge each commit once, without calling a TSA. `PASS`/`FAIL`, the short oid, the verdict and the
verified quorum, then one indented line per TSA answer and per failing gate. `--require-sealed`
fails an unsealed commit and `--require-signed` fails an unsigned one; both are gates, not
verdicts. `--json` prints one document. Exits `0` only when every commit passes, `1` on any
evidence or gate failure, `2` on usage or config.

### `git time log [--range RANGE] [--json] [<commit>…]`

The same evidence as one line per commit: short oid, TSA ids, genTimes, verdict. This is a record,
not a judgement: it exits `0` whenever it could read everything, and `1` only for a commit it could
not read. `--json` carries no `pass`, `gates` or `required`.

### `git time install [--preset public|none] [--no-tsa]`

Wire the hooks and configure authorities. `post-commit` and `post-merge` are always wired;
`pre-commit` and `pre-merge-commit` only under `time.gate = pre-commit`. A foreign hook is
preserved as `<name>.pre-time` (then `.pre-time.<n>`) and chained, never overwritten. `--preset
public` (the default) writes every entry of the built-in authority table and fetches their anchors;
`--preset none` or `--no-tsa` writes no authority. A failed anchor fetch is a warning, not a
failure; `doctor` names the gap. Exits `0` or `2`.

A preset with a published root fingerprint is checked before it is pinned: a bundle whose root
hashes to anything else is refused with both values named, any existing pin is left untouched, and
the install still exits `0` (the hooks are worth wiring; `doctor` names the missing anchor). A
preset without one is trust on first use and prints the fetched root fingerprint, which is the
value to compare against the authority's publication.

### `git time uninstall [--force]`

Remove our shims, including the `pre-*` ones, and restore every preserved hook by rename. A
hand-edited shim is named and left in place; `--force` keeps the edit under the next preserved
name and restores the original — or leaves it where it is when nothing was ever preserved. Running
it twice succeeds. Exits `0` or `2`.

### `git time doctor [--json]`

Report what is wired and pinned: the binary, the hooks directory, one state per hook (`ours`,
`chained`, `foreign`, `absent`, `not-executable`, `dangling`), whether the gate agrees with the
`pre-*` hooks, how many authorities are configured, each anchor's path and fingerprint, and
whether sealing is enabled. Each problem is repeated as a `problem:` line. Exits `0` healthy, `1`
on any problem, `2` on usage or config.

### `git time tsa add <url> [--id ID] [--anchor PATH] [--alg sha256|sha512] [--policy OID] [--timeout DURATION] [--insecure-http]`

Register an authority in the local config. The id derives from the host and is restricted to
`[a-z0-9-]`; a duplicate id is refused without writing. `http://` needs `--insecure-http`. Exits
`0`, `1` for an existing id, `2` for a bad URL, id, duration or policy.

### `git time tsa list [--json]` / `git time tsa remove <id>`

List the configured authorities with their anchor state and fingerprint, or delete a whole
`time.tsa.<id>` section. `remove` exits `1` when the id is unknown. Both exit `2` on usage or
config.

### `git time tsa preset list` / `git time tsa preset add <name>`

Print the built-in presets, or configure one, anchor included, through the install fetch path.
`preset add` exits `1` when the anchor could not be pinned (a one-off add exists to pin), and `2`
for an unknown name. A root fingerprint that does not match is a refusal, so a pinned preset never
takes a substituted root.

`install --preset public`, the default, writes the two `default` rows: `freetsa` and `digicert`,
both pinned against a measured root. `--preset all` writes every row. Two is the default because
every configured authority costs a request on every commit and every plain-http one costs a warning;
`digicert` is the second because it is pinned and the most available of the rest, and two rather
than one so `required = 1` still has a fallback. `sectigo` is not a default: its endpoint refuses
the TLS handshake on some stacks. Everything else is opt-in.

The table is ordered the `default` rows first. For a TOFU row no value can be checked, so
`preset add` prints the fetched root fingerprint in full — that line is what makes the first pin
reviewable, and `git time anchor pin` records it in `time.anchors-lock` afterwards so a later
change is visible.

| Preset | Endpoint | Scope | Root |
|---|---|---|---|
| `freetsa` | `https://freetsa.org/tsr` | default | pinned SHA-256 fingerprint |
| `digicert` | `http://timestamp.digicert.com` | default | pinned SHA-1 fingerprint, plain http |
| `sectigo` | `https://timestamp.sectigo.com/qualified` | opt-in | pinned SHA-1 fingerprint |
| `certum` | `http://time.certum.pl` | opt-in | pinned SHA-1 fingerprint, plain http |
| `izenpe` | `http://tsa.izenpe.com` | opt-in | pinned SHA-256 fingerprint, unverified, plain http |
| `acs-microsoft` | `http://timestamp.acs.microsoft.com` | opt-in | pinned SHA-1 fingerprint, plain http |
| `globalsign-r6` | `http://timestamp.globalsign.com/tsa/r6advanced1` | opt-in | pinned SHA-1 fingerprint, plain http |
| `aped` | `https://timestamp.aped.gov.gr/qtss` | opt-in | pinned SHA-1 fingerprint |
| `cartaodecidadao` | `http://ts.cartaodecidadao.pt/tsa/server` | opt-in | TOFU, plain http |
| `swisssign` | `http://tsa.swisssign.net` | opt-in | TOFU, plain http |
| `apple` | `http://timestamp.apple.com/ts01` | opt-in | pinned SHA-1 fingerprint, plain http |
| `dfn` | `http://zeitstempel.dfn.de` | opt-in | pinned SHA-1 fingerprint, plain http |
| `globalsign-advanced` | `http://rfc3161timestamp.globalsign.com/advanced` | opt-in | pinned SHA-1 fingerprint, plain http |
| `comodoca` | `http://timestamp.comodoca.com` | opt-in | TOFU, plain http |
| `identrust` | `http://timestamp.identrust.com` | opt-in | pinned SHA-1 fingerprint, plain http |
| `quovadis-eu` | `http://ts.quovadisglobal.com/eu` | opt-in | pinned SHA-1 fingerprint, plain http |
| `ssl-com` | `http://ts.ssl.com` | opt-in | pinned SHA-1 fingerprint, plain http |
| `belgium` | `http://tsa.belgium.be/connect` | opt-in | pinned SHA-1 fingerprint, plain http |
| `cesnet` | `https://tsa.cesnet.cz:3162/tsa` | opt-in | pinned SHA-1 fingerprint |
| `cra-ge` | `http://tsa.cra.ge/signserver/tsa?workerName=qtsa` | opt-in | pinned SHA-1 fingerprint, plain http |
| `lex-persona` | `http://tsa.lex-persona.com/tsa` | opt-in | pinned SHA-1 fingerprint, plain http |
| `accv` | `http://tss.accv.es:8318/tsa` | opt-in | pinned SHA-1 fingerprint, plain http |

A `http://` authority is recorded with `time.tsa.<id>.insecure-http = true`. At seal time, where the
policy is loaded, all of them share **one** warning line: five ids are named, the rest counted
(`… and 2 more`). The token integrity comes from the signature against the pinned root, not from
the transport; only the imprint and availability are exposed.

Every preset but `freetsa` is fetched by asking the endpoint for a token and taking the self-signed
root of the reply; only FreeTSA publishes a plain PEM.

Each endpoint appears once. An authority that answers on several URLs keeps one row: `cesnet` is
carried on its TLS port only, and `http://time.certum.pl` is the `certum` row, so no `certum-legacy`
row exists. A query string belongs to the endpoint and is stored and posted verbatim, as with
`cra-ge`.

The pinned values were measured by querying the endpoint and walking the chain (the reply's
certificates, plus the AIA `caIssuers` pointer where the root was not embedded). `izenpe` is the
exception: fetching its root failed, so its value is supplied and **unverified**. Two earlier values
were wrong for their endpoint and are replaced by the measured ones — `sectigo` and `certum` now
carry the fingerprint of the root their endpoint actually chains to. Without that, a pinned preset
would refuse its own authority forever.

### `git time tsa select [--preset public|none] [--interactive] [--dry-run]`

Choose interactively which preset authorities this repository uses, then pin the chosen anchors and
remove the preset sections that were not chosen. A section whose id is not a preset is untouched.

```
1) freetsa https://freetsa.org/tsr default pinned A6:37:9E:7C:…:AA:BC
2) digicert http://timestamp.digicert.com default pinned 05:63:B8:63:…:4D:43 insecure-http
3) sectigo https://timestamp.sectigo.com/qualified opt-in pinned CB:73:94:4C:…:43:07
4) certum http://time.certum.pl opt-in pinned 07:E0:32:E0:…:06:9E insecure-http
…
10) swisssign http://tsa.swisssign.net opt-in tofu insecure-http
…
22) accv http://tss.accv.es:8318/tsa opt-in pinned 93:05:7A:88:…:64:17 insecure-http
Authorities to enable (e.g. 1,3-4, all, none): 1,2,10
enabled freetsa (https://freetsa.org/tsr) fingerprint A6:37:9E:7C:…:AA:BC
enabled digicert (http://timestamp.digicert.com) fingerprint 05:63:B8:63:…:4D:43
enabled swisssign (http://tsa.swisssign.net) fingerprint 61:A2:9F:…:3E
```

The scope column says `default` for what `install` writes without a flag and `opt-in` for the rest;
`select` does not preselect anything, `all` really means all. A `pinned` row is checked against the
table when it is pinned and a mismatch is a refusal. A `tofu` row can only be reviewed by reading
the fingerprint the command prints, which is why it is printed in full; `git time anchor pin`
records the pinned bundle's fingerprint in `time.anchors-lock` so a later change is caught.

Indices are one-based, ranges are inclusive, and an empty answer means `none`. Anything else is
reported in one line and asked again, three times, then the command exits `2`. Each enabled
authority prints `enabled <id> (<url>) fingerprint <sha1>`; one that cannot be pinned prints
`failed <id>: <reason>` and makes the command exit `1`. `--dry-run` prints what it would do and
changes nothing.

The command asks a question, so a stdin that is not a terminal is refused (`2`) rather than left to
hang. `--interactive` says the answer is being piped. A script that needs no prompt uses
`--preset public|none`, `git time tsa preset add <id>`, or `git time tsa add <url>`.

### `git time anchor fetch <url> --id ID [--insecure-http]`

Fetch a PEM bundle and pin it for `ID`. The bundle is parsed before it replaces anything, so a
garbled fetch never destroys a working anchor. It writes the configured
`time.tsa.<id>.anchor` when one is set (the file the policy reads), else the anchors directory.
Exits `0`, `1` for an unusable bundle, `2` for a bad id, URL or config.

### `git time anchor list [--json]`

Name each configured anchor with its SHA-256 fingerprint and `notAfter`. Exits `0` or `2`.

### `git time anchor pin [--check]`

Write `time.anchors-lock`, one `<id> <sha256>` line per configured authority, or compare the
anchors against it and name every missing, unparseable, changed and unrecorded id. Exits `0`, `1`
on a mismatch or an unusable anchor, `2` on config errors.

## Operational notes

- **`git commit --no-verify` still seals.** It only skips `pre-commit` (and `pre-merge-commit` on a
  merge); `post-commit` and `post-merge` always run, so the commit is still sealed.
- **`GIT_TIME_SKIP=1`** (any non-empty value) disables the hook for one command and nothing else.
  It also works when exported in front of `git commit`.
- **Sealing later.** `git time seal --range HEAD~5..HEAD` seals an existing range; each rewritten
  commit is a new object, whose printed id is where its evidence lives. A dropped commit is skipped
  unless `--force`. Descendants of a rewritten range member are not repointed: the range members
  dangle from the branch until they are re-sealed or the branch is rebuilt.
- **Published commits.** A commit reachable from a remote-tracking ref is not rewritten by the
  hook; it prints `rfc3161: skipping published <oid> (run: git time seal --force)`. Sealing it
  would move the branch ahead of its remote and force the next push.
- **`log` versus `verify`.** `log` reports what is there and exits `0`; `verify` judges and gates.
  Use `verify` in CI and `log` for reading.
- **Anchors are the trust store.** A token is only as good as its pinned bundle. `anchor pin` is a
  review artifact: deleting the lock changes no verdict.

## Troubleshooting

### `doctor`

Read the fields top to bottom. `binary: missing` means the shims cannot seal — put `git-time` on
`PATH`. `hook <name>: not-executable` names the file to `chmod +x`. `hook <name>: dangling` is a
symlink to a gone target. `hook <name>: foreign` means a shim is not ours. `gate: … (mismatch)`
means `time.gate` disagrees with the installed `pre-*` hooks; rerun `git time install`. `tsa: 0
configured` means no authority. `anchor <id>: … missing` or `unparseable` is the bundle to restore.
`enabled: false` explains a silent hook, and `problems: N` is the count that decides the exit code.

`doctor --json` carries the same facts for a script; `problems` is the list that decides the exit
code.

### A failure block

A failing seal writes one line per failed authority:

```
X-RFC3161-Fail: id=freetsa; reason=timeout
```

The id names the authority and the reason is the sanitised error (`timeout`, `http-503`,
`anchor-<id>-could-not-be-read…`, …). The commit is still there. Reproduce the cause with
`git time doctor`, restore the anchor or endpoint, then `git time seal --force` if you want fresh
evidence on that commit. A single failure reason is one line, so an absolute path appears
truncated.

### Anchor pinning

Pin deliberately, before you rely on an authority:

```console
$ git time anchor pin            # record the fingerprints you reviewed
$ git time anchor pin --check    # in CI, or after an update
mismatch freetsa: anchor changed
```

`anchor fetch` replaces a bundle only after every certificate parsed, so a failed fetch leaves the
old one in place. A changed fingerprint is not automatically wrong — but it is a change you should
have reviewed. `git time tsa list` and `anchor list` print the current fingerprints to compare
against the authority's published value out of band.

### Double signing prompt on smartcards

A signed commit is signed by git and re-signed by the seal, so a hostile smartcard can prompt
twice per commit. `gpg-agent` normally caches the PIN after the first one. If it does not, seal
such commits explicitly instead of from the hook:

```console
$ GIT_TIME_SKIP=1 git commit -S -m "…"
$ git time seal
```

A cancelled second signature abandons the seal and leaves the original commit untouched — a
signed commit is never rewritten unsigned.

## Testing the live network path

The ignored integration test exercises real authorities end to end: it installs the public
preset, commits, requires `SEALED`, and verifies with exit 0. It skips with a message when the
network or the authorities are unavailable, and removes its temporary repository and the anchors
it fetched.

```console
$ cargo test -p git-time-cli --test live_tsa -- --ignored --nocapture
```
