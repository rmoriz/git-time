# git-time

`git commit` gains a verifiable RFC 3161 timestamp from several independent authorities, stored
inside the commit object itself. Type nothing extra: install once, then keep committing.

The promise is one line long — **type nothing extra**. No wrapper, no daemon, no extra command
before or after a commit, and no prompt on the normal path.

![git-time in a terminal: selecting authorities, installing the hooks, committing, verifying](docs/git-time.gif)

## Quick start

```console
$ cargo install --path crates/git-time-cli    # or: cargo build --release
$ git time tsa select                         # tick the authorities, anchors are pinned
$ git time install                            # wires the hooks
$ git commit -m "add entry point"             # the only command the user types
$ git time verify                             # judges the evidence, gates CI
```

`cargo install` without `--path` needs the crates published, which they are not yet; use the
`--path` form above, or build and put `target/release/git-time` on `PATH`.

**`git-time` has to be on `PATH`**, not merely called by path once. The hooks git runs are shell
shims that look the binary up as a bare command (`command -v git-time`) at commit time, with git's
environment and no shell aliases; `cargo install` already places it in `~/.cargo/bin`, otherwise
copy it to something like `/usr/local/bin`. Without it on `PATH` the shims exit `0` and the commit
is made **unsealed** and silently so — `git time doctor` names a missing binary, and `git time
verify` reports `UNSEALED`.

The same four commands print under `git time -h` and `git time --help`, so the binary carries its
own onboarding.

A seal should not depend on our verifier being the only witness: `git time verify --openssl
<commit>` prints a POSIX `sh` script that carries the commit and its tokens and re-checks them with
`openssl ts -verify` alone — no git, no zstd, no network. Hand it to someone who does not want to
trust this tool's own crypto.

`tsa select` is a cursor list. `j`/`k` or the arrows move, `space` ticks, `a` and `n` take or clear
everything, `r` asks the authorities again, and digits typed on the prompt line take that selection
(`1,3-4`, `all`, `none`).
Authorities already configured start ticked, a `custom` row among them. The `pin` column is the
trust tier: the root is checked against the table and a mismatch is a refusal. An unpinned
published root reads the date the table measured, as `listed <date>`, and `enter` pins it; a
published root the table never dated reads `pin -`. The probe below replaces the wording with `…`
and then the served date, so the table date is what the line prompt keeps.
`tofu` is a `custom` row's tier: such a row publishes no root to check, so its first pin is a
comparison when `tsa add --fingerprint` stored a value and otherwise trust on first use, reviewed by
reading the fingerprint `git time anchor fetch` prints and recorded with `git time anchor confirm`
once `doctor` starts naming it. `enter` pins only the built-in
rows and keeps a custom one exactly as it is; saving with a custom row unticked removes its section,
like any other. A section in a wider config scope (a machine-wide `time.tsa.<id>`) has nothing to
remove locally, so `enter` leaves it there and says so.
`http` marks a plain-http endpoint; the full URL of the cursor row is printed below the list, so no
column has to carry it.

```console
 > [x]  1  freetsa            pin 2041-03-07 
   [x]  2  digicert           pin 2031-11-10 http
   [ ]  3  sectigo            pin 2045-10-04 
   [ ]  4  certum             …                        http
   [ ]  5  izenpe             pin 2045-09-23 http
  …
url: https://freetsa.org/tsr
space toggle  a all  n none  j/k or arrows move  r refresh  enter save  q abort
2 selected
> _
```

`enter` saves and pins; `q`, `esc` or `ctrl-c` leave without writing. A change keeps the other
configured authorities because they start ticked; `n` clears every tick, and saving that empty set
is how sections are removed. The `pin` dates are the roots' expiry; a root in its last 90 days
reads `pin expires <date>`, a bundle all past reads `EXPIRED`. `git time install` on a repository
with no authority hands over to the same UI, so installing and choosing can be one step.

The picker also asks each authority's published root URL in the background and fills the column in while
nothing is pinned here: `fetch <date>` is the newest root the authority served, `…` means the
answer is still out, and `?` means it failed or served no published root; a row that publishes
nothing — every custom one — is never asked and keeps `tofu`. `fetch` is not a pin — a probe pins
nothing — and the answer is cached for a week under `$XDG_CONFIG_HOME/git-time/probe/` (or
`~/.config/…`), so a date can be up to a week old until `r` asks again. Only answers are cached,
so a failed or unpublished row is asked again on the next run. A served root the pinned bundle does
not hold appends `!`, which is a rotation to look at.

In a script, no prompt happens: `git time tsa preset add <id>` enables one preset and `git time
tsa add <url>` a hand-picked endpoint, both never asking. A `tsa select` without a terminal exits
`2` with those routes named rather than hanging; `--interactive` means an answer is being piped.
`--dry-run` prints the outcome and writes nothing.

Anchors are per machine, so a clone starts out trusting none of them and `verify` reports every
token `UNTRUSTED` until they are backfilled. `git time tsa restore` reads the authority ids out of
the evidence — the one part of the setup a clone still has — and pins each one it recognises as a
preset, checked against that preset's published root. An id that is not a preset carries no URL
anywhere and is named with the `tsa add`/`anchor fetch` steps instead. Give the root you expect to
`tsa add --fingerprint` and the first pin is a comparison; without one it is trust on first use,
marked and kept in `git time doctor` until `git time anchor confirm` records the comparison against
the authority's own publication. `git time anchor pin` then
records the fingerprints for review, and `git time anchor pin --check` catches a bundle that has
changed since.

When an authority rotates its root, `anchor fetch` refuses the new one, prints both fingerprints
and leaves the old bundle alone. Compare the fetched value with the authority's own publication and
repeat with `--accept` — bare for `anchor fetch` and `tsa preset add`, as `<id>=<fingerprint>` for
`install` and `tsa restore`, where a bare value needs exactly one authority in play. The root is
written next to the retired one rather than replacing it, so current commits keep verifying both
and each root only vouches inside its own validity window.
The sorted `time.anchors-lock` diff carries both roots and is what you review and commit. See
[the manual](docs/manual.md#surviving-a-tsa-rotation).

## Install from a release binary

No toolchain needed. Pick the asset for your platform from
[the latest release](https://github.com/rmoriz/git-time/releases/latest):

Each release asset is the bare binary for its target, named after it — nothing
to unpack, no checksum file beside it.

| Platform | Asset |
|---|---|
| Linux, x86-64 | `git-time-x86_64-unknown-linux-musl` |
| Linux, arm64 | `git-time-aarch64-unknown-linux-musl` |
| macOS, Apple silicon | `git-time-aarch64-apple-darwin` |
| macOS, Intel | `git-time-x86_64-apple-darwin` |

```console
$ VERSION=0.2.0
$ TARGET=x86_64-unknown-linux-musl        # or aarch64-apple-darwin, etc.

$ curl -fLO https://github.com/rmoriz/git-time/releases/download/v$VERSION/git-time-$TARGET
$ install -m 0755 git-time-$TARGET ~/.local/bin/git-time   # ensure ~/.local/bin is on PATH
$ git time --version

$ cd /path/to/a/repo
$ git time install
$ git commit -m "add entry point"
```

Verifying the checksum before running the binary is worth the extra line: the whole point of this
tool is evidence you can check yourself.

A `v*` tagged version builds the same four binaries and publishes them; an ordinary push only runs
the suite, so runner minutes are spent where they are useful. The
Linux builds are static (`static-pie`); the macOS builds link the system libraries.

## A real transcript

Sealing on an ordinary commit:

```console
$ git commit -m "add entry point"
rfc3161: sealed e595e4c by 1/2 TSA(s)
```

And the same machine with FreeTSA pinned, its anchor present, and the TSA unreachable (the host
firewall blocks the binary's egress):

```
rfc3161: sealed e595e4c under quorum (0 of 1) — see git time verify
[main 71068e2] add third
add third

X-RFC3161-Imprint: sha256:826b49a7b93ae87cf483701418fddbf95d0c43bc2dcb6571e222331288ee5a7a
X-RFC3161-Object: 71068e2caa5a3fbf20d03ad72c55d012caed45d2
X-RFC3161-Fail: id=digicert; reason=anchor-digicert-could-not-be-read…
X-RFC3161-Fail: id=freetsa; reason=timeout
```

The commit exists, the worktree is clean, `git fsck` is silent, and the artifact says exactly which
authority failed and why. A dead TSA costs evidence, never a commit.

## Built-in authorities

`git time tsa select` is how any of these get configured; `git time tsa preset add <name>` writes
one by name, and `--accept` takes a rotated root there. The table lives in `git_time_core::presets`.
The `default` rows are the curated pair the docs recommend, nothing more; belonging to them alone
ticks nothing — only an already configured section starts ticked.

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
| `actalis` | `http://timestamp.actalis.it` | opt-in | pinned SHA-1 fingerprint, plain http, anchor at the Actalis PKI |

Root fingerprints were measured by querying each endpoint and walking its chain — the reply's
certificates plus the top certificate's AIA `caIssuers` where the root is not embedded. izenpe's
value was supplied and is confirmed by that walk. Every built-in row is pinned today; trust on
first use is what a hand-added, unpublished authority gets. Two earlier values were wrong for
their endpoint and were replaced by measured ones: `sectigo` belongs to a different Sectigo root
than the one the endpoint chains to, and `certum` too (`07:E0:32:E0:…`, Certum Trusted Network CA).
`actalis` is the same trap from the other side: its legal repository advertises a dedicated TSA
root (`40:95:73:77:…`), but the free endpoint chains to the general Actalis Authentication Root CA
(`F3:73:B3:87:…`, CCADB A000073), so that is the measured pin. The endpoint serves no TLS at all,
and a GET of it leaves the next POST at 503, so the anchor comes from Actalis's own root and
intermediate downloads instead.

A pinned fingerprint makes the *first* fetch verifiable: a bundle whose root hashes to anything
else is refused and an existing pin is left alone. Where no fingerprint is published the fetch is
trust on first use, so the fetched root is printed in full for a reader to compare. A download may
be PEM, DER or PKCS#7; `cartaodecidadao` names its issuers as a chain because its reply carries the
signing leaf alone. Plain `http`
costs no integrity — the token is verified against the pinned root — but it exposes the imprint and
lets an attacker block the authority; an insecure authority keeps printing a warning at seal time.

## How it works

[![Sequence diagram of the seal path: the post-commit hook strips the trailer block and the
signature, hashes the pre-image, queries the pinned authorities in parallel, verifies each token
against its anchor, composes and signs the new commit, then moves the ref by compare-and-swap](docs/seal-path.png)](docs/seal-path.html)

The same twelve steps, with the ordering that makes a seal sound, in
[full size](docs/seal-path.html) and as a [vector drawing](docs/seal-path.svg).

1. The hook reads the commit git just wrote and strips its trailer block and signature.
2. It hashes that pre-image: a SHA-256 imprint.
3. Every configured TSA is queried in parallel over the same imprint, each with its own nonce,
   algorithm and policy.
4. Each reply is verified locally — CMS, chain to the pinned anchor at the token's genTime, ESS
   binding, policy, strict EKU — before anything is stored.
5. The surviving tokens become a trailer block appended to the verbatim message.
6. A signed commit is re-signed over the new bytes, under the same header name (`gpgsig` or
   `gpgsig-sha256`); a failure abandons the seal rather than the signature.
7. The new object is written with `hash-object -w -t commit`, which fsck-validates it.
8. The ref is moved with a compare-and-swap, so a commit made in the meantime is never clobbered.

If you are curious where the tokens go, they are ordinary commit headers:

```console
$ git cat-file commit HEAD | tail -4
X-RFC3161-Imprint: sha256:826b49a7…
X-RFC3161-Object: 71068e2…
X-RFC3161-Token: ver=1; id=freetsa; …
```

## Guarantees

- **Evidence survives a clone.** The tokens are inside the object, so `clone`, `push` and `mirror`
  carry them; nothing lives in a side ref.
- **A commit signature is preserved.** A signed commit is re-signed under the same header, so the
  commit stays signed; a signing failure leaves the original untouched.
- **A dead TSA never costs a commit.** The quorum defaults to one of several, failures are recorded
  in the block, and the hook exits 0 unless you ask otherwise.

## Non-guarantees

- **No hosting integration.** GitHub or GitLab will not show or enforce the tokens; nothing on the
  receive side checks them.
- **No transparency log.** There is no Rekor or equivalent in v1; the evidence is the tokens and
  the pinned anchors.
- **`git commit` prints the pre-seal hash.** Sealing rewrites the commit, so the oid git prints is
  the one before the trailer; the hook prints the real one on stderr.

## Documentation

- [Seal path diagram](docs/seal-path.html) — the hook's sequence, twelve steps, rendered from the
  README image.
- [Operator manual](docs/manual.md) — every config key, command, exit code and failure mode.
- [Trailer format](docs/format.md) — the wire format, so another tool can read or write a seal.
- [Man page](docs/git-time.1) — the commands on one page, in roff.
- [Design](docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md) — the contract and the
  measured probes behind it.
- [Demo cast](docs/git-time.asciinema) — the asciinema recording behind the README GIF.
- [Implementation status](docs/STATUS.md) — what ships, what deviates from the design, and why.

## License

GNU General Public License, version 2 only (GPL-2.0-only). See [LICENSE](LICENSE).

```
Copyright (C) 2026 Roland Moriz

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.
```
