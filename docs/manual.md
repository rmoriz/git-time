# git-time operator manual

This is the operator manual: the configuration, the commands and the failure modes. For the
one-page pitch see the [README](../README.md); for the design and its measurements see
[docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md](superpowers/specs/2026-11-18-git-time-rfc3161-design.md).
Where this manual and the design disagree, the deviations table in [STATUS.md](STATUS.md) wins,
because it describes the shipped code.

Every command takes the global `-C DIR` option to run in another repository.

The evidence the tool writes is specified in [format.md](format.md), for tools that read or produce
it without this one.

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

### `git time verify --openssl [--require-sealed] [--require-signed] <commit>`

Judge each commit once, without calling a TSA. `PASS`/`FAIL`, the short oid, the verdict and the
verified quorum, then one indented line per TSA answer — its verdict, genTime and signer serial,
on a pass as much as on a failure — and one per failing gate. Records are separated by a blank
line. The anchor fingerprint is left to `--json`: it is the same long string on every pass.
`--require-sealed`
fails an unsealed commit and `--require-signed` fails an unsigned one; both are gates, not
verdicts. The verdict vocabulary is `sealed`, `under-quorum`, `none`, `unsealed`, `bad-imprint`,
`bad-token`, `untrusted`, `bad-sig` and `unsigned`; `none` is a block that asked nobody because no
authority was configured when it was sealed, and it is reported with the two commands that set an
authority up. `--json` prints one document. Exits `0` only when every commit passes, `1` on any
evidence or gate failure, `2` on usage or config.

#### `--openssl` audit script

`--openssl` prints, and only prints, a POSIX `sh` script that re-verifies the tokens of one commit
with the `openssl` command, so a third party can check the evidence without trusting this tool's
crypto. The command runs nothing itself and exits `0` once the script is printed. The script needs
`openssl` with its `ts` command and nothing else — no `git`, no `zstd` — and writes only into one
`mktemp -d` directory that it removes again, also when it is interrupted: a signal stops it with
`130`/`143`/`129` and only `EXIT` cleans up, so `rm -rf` runs once and never against a stale path.
Before it recurses, the cleanup checks that the path is absolute and below a directory — the only
shape `mktemp` returns — so a lost `$scratch` cannot turn into `rm -rf /` or `rm -rf .`.

The script carries its payload: the commit's pre-image is printed into it as clear text, with the
tokens base64-encoded below it. It therefore reads no repository, and a reader sees the commit
being judged — headers, message and all — before any token. Keep it next to the commit it names;
it is tied to that history only by the bytes inside it. A message that is not UTF-8 cannot be
printed as text and falls back to base64 for the whole pre-image (git warns on such commits).

Exactly one commit has to be named and only that commit appears: the script is an artifact for a
single seal, so `--range` is refused and no default to `HEAD` happens. A missing or second commit
is a usage error (exit `2`). Run it once per commit to audit a series.

Use an OpenSSL, not the LibreSSL that ships as `/usr/bin/openssl` on macOS: its `ts` command is
older, has no `-purpose`, and refuses SHA-384/SHA-512 tokens. When such an `openssl` is found the
script still runs, prints a `NOTE` naming the version, and skips the EKU check rather than passing
it silently; tokens the older ESS check cannot handle then fail with LibreSSL's own reason.

The embedded pre-image is hashed and compared with the block's `X-RFC3161-Imprint` before any
token is trusted, so a payload edited by hand is caught. Each token is decoded and checked with
`openssl ts -verify -purpose timestampsign`, with that same pre-image as its `-data`, against the
anchor of the authority. The anchor is looked up at `$XDG_CONFIG_HOME/git-time/anchors/<id>.pem`
(or `$HOME/.config/…`), then at the path the generating machine had; the bundle is passed whole as
`-CAfile`, so its intermediates are trust material too. `PASS`/`FAIL` per token, a summary, and
exit `1` when anything failed.

A token whose authority has no anchor is a failure that names both paths it looked at. A commit with
no token is summarised as `SKIP`, so an unsealed or dropped commit stays visible instead of
vanishing. `--require-sealed` and `--require-signed` were applied when the script was generated and
are named in it, but the script does not re-check them. Only tokens in the commit trailer are audited: a seal kept only in a note
is not reached. `--json` and `--openssl` exclude each other, as do `--range` and `--openssl`.

### `git time log [--range RANGE] [--json] [<commit>…]`

The same evidence as one line per commit: short oid, TSA ids, genTimes, verdict. This is a record,
not a judgement: it exits `0` whenever it could read everything, and `1` only for a commit it could
not read. `--json` carries no `pass`, `gates` or `required`.

### `git time install [--no-tsa] [--accept <id>=<fingerprint>]`

Wire the hooks. `post-commit` and `post-merge` are always wired; `pre-commit` and
`pre-merge-commit` only under `time.gate = pre-commit`. A foreign hook is preserved as
`<name>.pre-time` (then `.pre-time.<n>`) and chained, never overwritten.

The authority set is chosen by configuration, not by a flag. `time.tsa.*` sections that already
exist are left exactly as they are, so a second run, or a hand-made setup, survives. When none
exist, `install` hands over to `git time tsa select` inline on a terminal. A stdin that is not a
terminal is refused with exit `2` and one line naming the three scriptable routes — `git time tsa
select`, `git time tsa preset add <id>`, `git time tsa add <url>` — because a prompt nobody answers
would hang a script. `--no-tsa` writes no authority at all.

A rotation is refused unless `--accept <id>=<fingerprint>` names the fetched root; `install` pins
several authorities, so the flag is per id and repeatable, and a bare fingerprint is accepted only
when the run pins exactly one authority. See [Surviving a TSA rotation](#surviving-a-tsa-rotation).

A fetch that fails is a warning, not a failure; `doctor` names the gap, and under `time.gate =
pre-commit` the summary says commits will be refused. Exits `0` or `2`.

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

The `default` scope marks the curated pair — `freetsa` and `digicert`, both pinned against a
measured root. It is what the selector recommends, not a preselection; `install` writes it only
through the selector. Two is the recommendation because every configured authority costs a request
on every commit and every plain-http one costs a warning; `digicert` is the second because it is
pinned and the most available of the rest, and two rather than one so `required = 1` still has a
fallback. `sectigo` is not recommended: its endpoint refuses the TLS handshake on some stacks.
Everything else is opt-in.

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
| `izenpe` | `http://tsa.izenpe.com` | opt-in | pinned SHA-256 fingerprint, plain http |
| `acs-microsoft` | `http://timestamp.acs.microsoft.com` | opt-in | pinned SHA-1 fingerprint, plain http |
| `globalsign-r6` | `http://timestamp.globalsign.com/tsa/r6advanced1` | opt-in | pinned SHA-1 fingerprint, plain http |
| `aped` | `https://timestamp.aped.gov.gr/qtss` | opt-in | pinned SHA-1 fingerprint |
| `cartaodecidadao` | `http://ts.cartaodecidadao.pt/tsa/server` | opt-in | pinned SHA-1 fingerprint, plain http, anchor at the state PKI |
| `swisssign` | `http://tsa.swisssign.net` | opt-in | TOFU, plain http, answers `400` since 11/2026 |
| `apple` | `http://timestamp.apple.com/ts01` | opt-in | pinned SHA-1 fingerprint, plain http |
| `dfn` | `http://zeitstempel.dfn.de` | opt-in | pinned SHA-1 fingerprint, plain http |
| `globalsign-advanced` | `http://rfc3161timestamp.globalsign.com/advanced` | opt-in | pinned SHA-1 fingerprint, plain http |
| `comodoca` | `http://timestamp.comodoca.com` | opt-in | pinned SHA-1 fingerprint, plain http |
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

An anchor URL is fetched with a GET; a body carrying a certificate — PEM, DER or a PKCS#7
collection — is the bundle. Everything else — a timestamp endpoint answers a GET with prose or with
`405`/`403` because it wants a POST — falls through to asking the URL for a token and taking the
self-signed root of the reply, walking the top certificate's AIA `caIssuers` where the reply stops
short of the root. `freetsa` and `dfn` publish a PEM; `cartaodecidadao` publishes its root at the Portuguese state PKI
and its two issuers beside it, which the preset names as a chain because its own reply carries the
signing leaf alone and no `caIssuers`; every other preset keeps its endpoint. A chain member is
appended behind the root and is only a path — trust still comes from the pinned root.

Each endpoint appears once. An authority that answers on several URLs keeps one row: `cesnet` is
carried on its TLS port only, and `http://time.certum.pl` is the `certum` row, so no `certum-legacy`
row exists. A query string belongs to the endpoint and is stored and posted verbatim, as with
`cra-ge`.

The pinned values were measured by querying the endpoint and walking the chain (the reply's
certificates, plus the AIA `caIssuers` pointer where the root was not embedded). `izenpe` is the
one exception: its value is supplied, and the walk now reaches the same root, so a live run
compares against it. `swisssign` is the only TOFU row left: every query is answered with a `400`.
Two earlier values
were wrong for their endpoint and are replaced by the measured ones — `sectigo` and `certum` now
carry the fingerprint of the root their endpoint actually chains to. Without that, a pinned preset
would refuse its own authority forever.

### `git time tsa select [--interactive] [--dry-run]`

Choose which preset authorities this repository uses, then pin the chosen anchors and remove the
preset sections that were not chosen. A section whose id is not a preset is untouched, and saving
with nothing selected is therefore the removal path.

The list is a cursor UI on the alternate screen. Nothing is preselected: the selection is the user's
to make, and `a` really is all 22.

```
   [ ]  1  freetsa            pin A6:37:9E:7C… 
 > [x]  2  digicert           pin 05:63:B8:63… http
   [ ]  3  sectigo            pin CB:73:94:4C… 
   [ ]  4  certum             pin 07:E0:32:E0… http
   [ ]  5  izenpe             pin 8E:5B:8B:AE… http
   [ ]  6  acs-microsoft      pin F4:00:42:E2… http
   [ ]  7  globalsign-r6      pin 13:9B:1C:71… http
   [ ]  8  aped               pin 44:4D:AE:31… 
   [ ]  9  cartaodecidadao    pin E8:9D:08:31… http
   [ ] 10  swisssign          tofu             http
   [ ] 11  apple              pin 61:1E:5B:66… http
   [ ] 12  dfn                pin 58:81:54:65… http
   [ ] 13  globalsign-advanc… pin 13:9B:1C:71… http
   [ ] 14  comodoca           pin 52:42:1A:EA… http
   [ ] 15  identrust          pin BA:29:41:60… http
   [ ] 16  quovadis-eu        pin 1B:8E:EA:57… http
   [ ] 17  ssl-com            pin B7:AB:33:08… http
   [ ] 18  belgium            pin 98:98:9F:EE… http
  …
url: http://timestamp.digicert.com
space toggle  a all  n none  j/k or arrows move  enter save  q abort
1 selected
> _
```

| Key | Effect |
|---|---|
| `j`, `k`, `l`, `h`, down, up | Move the cursor; it wraps at both ends |
| `Home`, `End`, `[H`, `[F` | Jump to the first, the last row |
| `space` | Tick or untick the row under the cursor |
| `a` | Tick every row |
| `n` | Untick every row |
| `enter` | Save and pin the ticks |
| `q`, `esc`, `ctrl-c` | Leave without writing |
| `0`–`9`, `,`, `-` | Append to the prompt line |
| `backspace` | Delete the last typed character |
| `esc` (with typed text) | Clear the prompt line, do not leave |

Typed input is the previous line prompt, kept for muscle memory and for piping: a non-empty buffer
is applied by `enter` through the same parser (`1,3-4`, `all`, `none`), so `printf '1,3\n' | git
time tsa select --interactive` still works. A buffer that does not parse shows one error line and
keeps the frame. A terminal that cannot be put into raw mode at all falls back to the line prompt of
the early versions, saying so in one line.

The `pin` column is the trust tier: the root is checked against the table when it is pinned and a
mismatch is a refusal. `tofu` can only be reviewed by reading the fingerprint the command prints —
`git time anchor pin` records the pinned bundle's fingerprint in `time.anchors-lock` so a later
change is caught. `http` marks a plain-`http` endpoint; the endpoint of the cursor row is printed in
full below the list.

The list is a window sized to the terminal: the footer, the URL line and the cursor row stay on
screen, a cut edge is marked `…`, and the frame is re-measured from the terminal each key so a
resize is honoured. The last row and the last column stay free, so nothing wraps and the screen
never scrolls under the frame. On a terminal too short for the footer it degrades to the cursor row
and the footer.

Each enabled authority prints `enabled <id> (<url>) fingerprint <sha1>`; one that cannot be pinned
prints `failed <id>: <reason>` and makes the command exit `1` while the others still pin. Under
`time.gate = pre-commit` a missing anchor also warns that commits will be refused. `--dry-run`
prints the outcome and changes nothing.

The command asks a question, so a stdin that is not a terminal is refused (`2`) rather than left to
hang. `--interactive` says the answer is being piped. There are three routes that never ask:
`git time tsa select` on a terminal, `git time tsa preset add <id>` for one preset, and `git time
tsa add <url>` for an endpoint of your own.

### `git time anchor fetch <url> --id ID [--insecure-http] [--accept FINGERPRINT]`

Fetch a bundle and pin it for `ID`. The body is read as PEM, DER or PKCS#7 — a CA's download is
often the latter two — and when `ID` is a preset, that preset's chain of issuers is fetched and
appended behind the root. The bundle is parsed before it replaces anything, so a garbled fetch
never destroys a working anchor. It writes the configured `time.tsa.<id>.anchor` when one is set
(the file the policy reads), else the anchors directory. Exits `0`, `1` for an unusable bundle, `2`
for a bad id, URL or config.

A root that is neither published by a preset nor already pinned is a rotation: the fetch refuses,
prints both fingerprints and changes nothing. `--accept` takes the fetched root's bare fingerprint
(the fetch addresses one id) and appends it next to the retired one.

### `git time anchor list [--json]`

Name each configured anchor with its SHA-256 fingerprint and `notAfter`. Exits `0` or `2`.

### `git time anchor pin [--check]`

Write `time.anchors-lock`, one `<id> <sha256>` line per root of every configured authority, or
compare the anchors against it and name every missing, unparseable, added, removed and unrecorded
id. Exits `0`, `1` on a mismatch or an unusable anchor, `2` on config errors.

## Surviving a TSA rotation

An authority rotates when a key gets old, a root expires or one leaks. The rotation must not cost
the history that authority already sealed, and it must not enter trust by itself: a fetch keeps the
old bundle and refuses a root it does not expect.

The refusal names both values and the way out:

```console
$ git time anchor fetch https://tsa.example.net/tsr --id tsa-example-net
git time anchor: the root fetched for `tsa-example-net` from https://tsa.example.net/tsr does not
match: expected F1:C6:…:9A, got 01:0A:…:00; the bundle was not pinned and the existing anchor is
untouched
git time anchor: pass `--accept 01:0A:…:00` to append it next to the pinned root
```

Compare the `got` value with the fingerprint the authority publishes out of band. When it is the
one you expect, repeat the command with the flag. `anchor fetch` addresses one id, so its `--accept`
takes the bare fingerprint. `install` and `tsa restore` can address several authorities at once and
take `--accept <id>=<fingerprint>`, repeatable; a bare value is accepted only when exactly one
authority is in play, and otherwise the ids are named.

The accepted root is **appended** ahead of the retired one, never written over it. Old tokens keep
chaining to the root that signed them, and each root only vouches for tokens inside its own
validity window. Verification intersects the pinned roots with the fingerprints the commit's block
names, so a new root never blesses an old token and an old root never vouches for a new one. The
block line (`X-RFC3161-Anchor`) is covered by the commit signature and names the roots valid at the
token's `genTime`.

The append changes `time.anchors-lock`, one line per root. Review it and commit it with the
rotation: the diff is the record of the decision and what later reviewers see.

```diff
  tsa-example-net f1c6c6fe6969cfb65118326f162c3f25886f493e9e8186599cf233bcaade129a
+ tsa-example-net 010a2d31e7873a9d92dadb7f9a7a5b03ddfdafa6eef32defbd4508594e4b700
```

`git time anchor pin --check` reports the same change as an `added` line per new root and exits `1`
until the lock is updated, which is what makes a rotation visible in CI.

`doctor` names a rotation twice: ``anchor <id>`` `has no root valid now` when every pinned root
has expired — the next seal's tokens would be `UNTRUSTED` — and ``HEAD names `anchor <id>`
fingerprint …, which is not pinned`` when the commit at HEAD was sealed under a root this machine
does not have. Both lines carry the command that brings the root.

On a clone that lacks the root, `verify` reports `UNTRUSTED` with `anchor-not-pinned`, names the
fingerprint the block requires and points at `git time tsa restore`. `tsa restore` reads the ids and
named roots out of the evidence, pins a preset when the fetched root is the published one, and
otherwise reports the new root for an `--accept <id>=<fingerprint>`. Presets only: an id of your own
is named with the `tsa add`/`anchor fetch` steps.

A reader on an older `git-time` still decodes the block — the `X-RFC3161-Anchor` line is unknown to
it and ignored — and judges the token against the first certificate of the pinned bundle. Old
evidence therefore keeps verifying there as long as the retired root is still first; a commit
sealed later under the new root is `UNTRUSTED` on that reader. That is the state before this
feature: upgrade the reader rather than change the evidence.

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

`anchor fetch` parses a bundle before it touches the pinned file, so a failed fetch leaves the old
one in place. A changed root is refused until it is accepted by fingerprint; see
[Surviving a TSA rotation](#surviving-a-tsa-rotation). Once accepted it is appended, never
substituted. `git time tsa list` and `anchor list` print the current fingerprints to compare
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
