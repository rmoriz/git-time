# Design: surviving a TSA key rotation

Status: approved approach (append-on-explicit-yes + time-scoped roots). Reviewed
by a builder check; the nine questions it raised are settled below and marked
**[check]**.

## Intent

A timestamp authority will rotate its signing key, its intermediates and its
root — because a key is old, because a root expires, or because one leaked. Two
things have to hold at the same time:

1. every token ever issued stays verifiable, including after the root that
   signed it is retired, and
2. new seals use the authority's new key without a code change.

Today (1) breaks as soon as somebody re-pins: verification builds one trust
anchor from the first certificate of one bundle per authority, and every fetch
replaces that bundle. A downstream clone that re-fetches therefore turns all
earlier commits of that authority `UNTRUSTED`, with no way back except restoring
an old file by hand.

Expiry itself is already right: every certificate is judged at the token's
`genTime`, so an expired root keeps its old tokens valid. Only the trust set is
unable to hold two generations.

## Goals

- A pinned authority may carry several roots. Each root only vouches inside its
  own validity window, so a 2031 root cannot bless a 2026 token.
- Old evidence keeps verifying after a rotation, on the machine that sealed it
  and on a clone that backfills.
- Accepting a rotated root is a deliberate human step, not a side effect of a
  fetch.
- Evidence says which anchor it needs, so a future verifier can tell the
  difference between "you lack the root" and "this token is forged".

## Non-goals

- Revoking a root (a compromised root stays trusted for its window; removal is a
  later `anchor remove`).
- Cross-signed bridges, CRL/OCSP re-checks at verification time, or a
  transparency log for anchors.
- Automatic upstream discovery of a rotation. Somebody has to notice and say
  yes; the lock diff and `doctor` make noticing cheap.
- Sealing a commit whose tokens are older than every pinned root without
  re-fetching (that is the `UNTRUSTED` path, by design).

## Anti-goals

- A fetch that silently changes what history verifies.
- Trusting a certificate the token carries, or a root on first sight without
  printing it.
- A token from outside a root's validity window passing because another pinned
  root happened to chain.

## Constraints from the existing system

- The anchor bundle format is a bare PEM list; the first certificate is a root,
  the rest are intermediates. No header line exists and none may be needed to
  read a bundle.
- `time.anchors-lock` is a review artifact, never trust material.
- The block is covered by the commit signature. Format changes are additive; a
  reader that does not know a line must still decode the block.
- `git time verify --openssl` is a third-party artifact and gets only what is
  embedded in it.
- `Invalid` is `Copy`, its `as_str()` is a stable machine string published in
  `docs/format.md`, and `commit.rs` derives the `UNTRUSTED` verdict from it.

## Approaches considered

- **A — append anything a fetch brings, warn only.** Simple; a fetch is the
  trust decision. An upstream compromise enters trust unattended.
- **B — append only on an explicit accept.** A fetch that finds the published
  fingerprint unmatchable keeps the old bundle, prints both fingerprints and
  exits non-zero; `--accept <fingerprint>` appends. One deliberate step, and the
  printed value is what the human compares with the authority's publication.
- **C — time-scope the roots.** Every root is a candidate only at `genTime`s
  inside its own validity. Removes the "old root blesses new tokens" hole that
  a plain multi-root store opens.

Picked: **B with C**, as agreed. B alone still lets an old token verify against
the wrong generation; C alone still changes trust on a fetch. Together, a token
is trusted only by a root that was valid when the token was made *and* that a
human let in.

## Design

### Bundle layout

All certificates of a bundle are parsed; a certificate whose issuer equals its
subject is a **root**, every other one is an intermediate. Roots are trust
anchors, in file order. A bundle with no root is unusable (`TrustError::NoRoot`),
as an empty bundle is today. Fingerprints are deduplicated on write, so
re-accepting the same root twice is a no-op.

`Anchor::root` becomes `Anchor::roots: Vec<DerCertificate>` (first entry = the
primary, for display and the lock's first line). `AnchorStore::anchor(id)`
returns the whole generation set.

### Verification

1. Candidates are the pinned roots of `id` whose `notBefore <= genTime <=
   notAfter`, intersected with the block's named fingerprints for `id`.
2. No candidate is a distinct failure each way — two new `Invalid` variants
   **[check]**:
   - `NoRootAtGenTime` (`no-root-at-gen-time`) when every pinned root is
     outside its window,
   - `AnchorNotPinned` (`anchor-not-pinned`) when the block names fingerprints
     and none of them is pinned.
   Both map to `UNTRUSTED`: the counting in `commit.rs` matches on the family,
   not on the variant, and `format.md`'s reason table gains the two strings.
   The block lives in `commit.rs`, so the named-filter check runs there too:
   `token()` is handed the block's fingerprints for its id and reports
   `AnchorNotPinned` itself, `commit.rs` never post-processes an evidence line.
3. Every candidate becomes a `webpki` trust anchor; one `verify_for_usage` call
   with all of them, the same `required_if_present` EKU rule as today.
4. Everything else — imprint, nonce, ESS, `genTime` window, signer EKU — is
   unchanged.

### Block line

One line per authority, sorted by id, emitted after `Imprint`/`Object` and
before the `Token` lines:

```
X-RFC3161-Anchor: id=<id>; sha256=<fp>[,<fp>...]
```

`<fp>` is the SHA-256 fingerprint in the legal preset spelling (uppercase hex,
colon separated).

**Which roots it names [check]:** the roots valid at the `genTime` of that
authority's tokens, unioned over its tokens — not at the committer time. That
matters exactly in the backfill case: an old commit sealed after a rotation gets
a token whose genTime is now, so the line must name the *new* root, or the fresh
commit would be `UNTRUSTED` the moment it exists. Computing it at the token's
time also means no pre-request filter, and it names only roots that can actually
verify what was received. During an overlap that is several roots; an authority
with no token (only a `Fail` line) contributes no line.

Reading it is a filter, never a trust decision: the root still has to be
pinned. Its uses are a clone knowing what to fetch, and a swapped bundle no
longer being able to re-point history silently.

A block without the line (every commit made before this change) has no filter.
A reader that predates the line still decodes the block and uses its first root;
after a rotation it reports `UNTRUSTED`, which is exactly the state before this
work.

The line is inside the signed block, so it is covered by the commit signature.

**It is a first-class field [check], not an `extra`:** `extra` is re-emitted
last, after `Fail`, and a canonical position before `Token` is what a third-party
creator needs. `TrailerBlock` gains `anchors: BTreeMap<String, Vec<String>>`,
`docs/format.md` §2/§3/§8, the reason table, the fixture and `format_doc` move
with it. Decoding is fail-closed like `Token`/`Fail`: a malformed value, a
duplicate id, a fingerprint that is not SHA-256 hex, or an id with neither a
`Token` nor a `Fail` line rejects the whole block.

### Accepting a rotation

- **`anchor fetch` gains the check it never had [check].** It currently renames
  a successful fetch over the file unconditionally; it will refuse a different
  root instead, exactly as `install` does. The comparison target depends on the
  id:
  - a preset id is compared against the preset's published fingerprint list and
    against what is already pinned,
  - a hand-added id (no preset) with an existing bundle: refused, both
    fingerprints printed — nobody published a value, so somebody has to look,
  - an id with nothing pinned: trust on first use, the fingerprint is printed,
  - a fetched root that is already pinned (any spelling) is not a change: the
    chain material is updated and nothing warns, which also makes a revert to a
    previously pinned root quiet.
- `--accept <fingerprint>` appends. The value must equal the fetched root's
  fingerprint (a typo, or a second replacement in between, fails) and the
  fetched roots and intermediates are appended, deduplicated, in fetch order.
  When nothing is pinned, `--accept` is just a pin.
- **`install --accept` is per id [check]:** `install` pins N authorities, so a
  bare fingerprint is ambiguous and would "pass on the wrong authority". The
  spelling is `--accept <id>=<fingerprint>`, repeatable; the bare form is
  accepted only when the run pins exactly one authority. `anchor fetch` has one
  id, so it takes the bare value. `tsa restore` takes the `id=fp` form,
  repeatable, with the same single-id exception.
- Append is ordered and deduplicated; previous roots keep their position so
  `pin --check` diffs read as additions.

### Presets

`Preset::fingerprint: Option<&str>` becomes
`Preset::fingerprints: &[&str]` **[check]**: every published root the preset
knows, newest last. A match against any of them is a match; the line names which
one matched. Digests stay length-taken from the expectation, but the comparison
is per fingerprint, not per preset, so a preset carrying both a SHA-1 and a
SHA-256 value (some authorities publish only SHA-1) still works.

Rotations are recorded in the preset table at release time (value printed by an
`--accept` run), so fresh installs match again. Until then `install` fails with
the mismatch and the accept hint, which is the correct state: somebody has to
look at the new root.

### Lock and doctor

`anchor pin` writes one `<id> <fingerprint>` line per root, sorted by id then
fingerprint. `--check` reports `added` and `removed` roots separately, so a
rotation is visibly a two-sided change.

`doctor` gains two problems and stays **HEAD-only [check]** — it never reads
objects today, and the next commit is what it can act on:

- `anchor <id>: <n> root(s), none valid now — the authority may have rotated;
  fetch it and pass --accept <id>=<fingerprint>` (a problem: the next seal's
  tokens would be `UNTRUSTED`),
- a root named by HEAD's block that is not pinned here (a problem: this commit
  does not verify).

Old commits are `verify`'s and `tsa restore`'s business, so a history that names
roots the machine lacks does not fail doctor.

### `verify --openssl`

The generated script embeds, as its whole `-CAfile`, the roots the block names
that are valid at `genTime` — plus **all pinned intermediates [check]**, because
`cartaodecidadao`'s token carries only the signing leaf and publishes no
`caIssuers`; a roots-only file could not build that path. When the block names
nothing, every root is embedded, as today.

`-attime <genTime>` is passed so the chain is judged at the token's time.
LibreSSL has no `-attime`; like `-purpose`, it is probed, named in a `NOTE`, and
then left out — the script still verifies, validity is judged at run time in
that case.

### `tsa restore`

`named_tsas` also returns the block's named fingerprints. Restore pins a preset
when the fetched root is the named one; a fetched root that is not named (a
later rotation) needs `--accept <id>=<fingerprint>` and is otherwise reported
and left unpinned. **The commit signature is not required [check]:** restore
judges nothing today, and a forged block can only choose among the authority's
*currently published* roots, which the preset comparison already checks. The
signature state is printed per commit so a reader sees which blocks were
unverified when they chose.

### Expiry display

A root's `notAfter` is the cheapest rotation signal there is, and today only
`anchor list` names it (as a full timestamp, after the fingerprint). The three
surfaces where an authority is *chosen* say nothing: `tsa select`, `tsa list`
and `tsa preset list`. They gain the date as `YYYY-MM-DD` **[check]**.

- **Source is the pinned bundle only.** The date is read from the pinned root,
  locally. A preset that was never pinned has no certificate here, so it prints
  `not pinned`; `tsa preset list` and the picker do not fetch 22 endpoints for a
  screen. The preset's own expiry is not baked into the table — the table's value
  would go stale exactly when a rotation makes it interesting.
- **Past and near are marked.** A date in the past is followed by `expired`; a
  date within 90 days by `(expires soon)`. The picker has one narrow column and
  prints `EXPIRED` or `expires` + date; it never prints a bare date that could be
  read as fine.
- **Several roots** (after an accept) are several dates: `tsa list` prints one
  indented line per root with its own verdict, the picker the latest date among
  the roots still valid now, `EXPIRED` when none is.
- `tsa list --json` carries `not_after` per root, and `anchor list` moves to the
  same date-only spelling so the two commands cannot disagree.

This is display only: no verdict, no exit code and no config depends on it. The
pickable set does not change, and an expired root does not remove an authority
whose newer root is fine.

## Parts left to the builder

- Exact wording of the accept hints and the two `Untrusted` messages.
- Test fixture shape for a rotated authority (two CA generations in one test
  tree, plus a token signed by the old one).
- Whether `anchor fetch --accept` prints the appended bundle or only a count.

## Failure modes to test

| Situation | Expected |
|---|---|
| old token, root rotated and appended | passes |
| old token, new root only | `UNTRUSTED`, names the block's fingerprint |
| token whose genTime is after its root's `notAfter` | `UNTRUSTED`, "no root valid at genTime" |
| token from root B, genTime in the overlap | passes against either root |
| accept with a wrong fingerprint | refused, bundle untouched |
| accept the same root twice | one root, no error |
| block line naming an unpinned root | `UNTRUSTED`, restore hint |
| `pin --check` after a rotation | reports the added root |
| `--openssl` on an old token after a rotation | embeds the old root, `-attime`, passes |
| `--openssl` under LibreSSL | `NOTE`, no `-attime`, still verifies |
| seal after a rotation (backfill or normal) | line names the root valid at the token's genTime |
| second `install` after an accept | no mismatch, both roots kept |
| malformed or duplicated `Anchor` line | block rejected |
| restore on a block naming a root the preset no longer publishes | reported, needs `--accept id=fp` |
| `tsa list`/`tsa select` on a pinned expired root | `YYYY-MM-DD expired` / `EXPIRED` |
| `tsa preset list` on a preset that was never pinned | `not pinned`, no network |
| a root expiring in 30 days | `(expires soon)` |

## Compatibility

Additive at every layer: old bundles are valid (all certificates classified by
self-signedness, the existing single-root file keeps working), old blocks decode,
old readers keep verifying what they could verify before. Nothing is written in
a place an older binary cannot read.
