# git-time — RFC 3161 timestamps on every commit

Status: **APPROVED 2026-11-18** — D1 trailer, D2 `required=1`, D3 `warn` (+ optional `pre-commit` gate), D4 presets freetsa + ai.moda. Execution: subagent-driven.
Date: 2026-11-18
Author: design session (agent), for rmoriz

## 1. Intent

Every `git commit` gets independent, cryptographically verifiable proof that
this exact commit object existed no later than T, from **several Time-Stamp
Authorities (TSAs) queried in parallel**, stored **inside the commit object**
so it travels with clone/push and is part of the git history — not a side
channel like notes, not a local log.

The user's UX bar:

> `git commit -m 'comment' file` does all the TSA magic in the background.

Normal path: no extra commands, no prompts, no daemon. Failures degrade
instead of trapping the user in a broken commit.

Why: long-horizon evidence that code existed at a time, resistant to later
backdating by the committer and to any one TSA being offline, compromised or
discredited.

## 2. Goals

- G1 `commit`, incl. `merge`, `rebase`, `cherry-pick`, `amend`, `-S`, leaves a
  commit carrying N independently verifiable RFC 3161 tokens.
- G2 Tokens live in the commit object → survive clone/push/mirror and are
  covered by the object hash **and** by any commit signature.
- G3 N configured TSAs are queried **concurrently** over the same imprint,
  each with its own nonce, digest algorithm and policy.
- G4 Offline, fail-closed verification of a commit or range with CI exit codes.
- G5 Never lose the commit, never leave index/worktree inconsistent, never
  destroy an existing GPG/SSH signature.
- G6 Bounded latency: hard deadline, per-TSA timeout, quorum.

## 3. Non-goals

- No hosting integration, no receive-side enforcement.
- Not a replacement for `git commit -S` (§9).
- v1 timestamps commits only (tags: v2; blobs/trees/patches: no).
- No transparency log (Rekor) in v1 — a later, optional fourth anchor.
- No TSA server side; client only.

## 4. Anti-goals

- A1 `git commit` fails or loses the commit because a TSA is down.
- A2 Evidence that stays local (notes-only, `.git/` files) so a clone has none.
- A3 Serial TSA calls adding seconds to every commit.
- A4 Tokens that "verify" against whatever certificate they carry.
- A5 Silent acceptance of a bad token (wrong imprint, malformed CMS, cert
  not valid at genTime).
- A6 A rewrite that breaks rebase, `--amend`, or a signature (measured hazard).
- A7 Dropping a commit header the rewrite cannot reproduce.

## 5. Constraints (measured on this machine)

| Fact | Evidence |
|---|---|
| Empty repo; Rust 1.99 (MSRV 1.88), git 2.56.1, openssl 4.1, `sigstore-tsa` 0.16, `tydence` prior art | tool versions, crates.io |
| Token ≈ 4.6 KB DER / 6.2 KB b64 / **2.9 KB zstd** (freetsa embeds its chain) | `/tmp/gt-tsa2.*` |
| 3 parallel TSA calls **0.56 s** wall vs ≈1.3 s serial | timing run |
| `git commit --amend` **refused mid-rebase**: `fatal: You are in the middle of a cherry-pick -- cannot amend` | probe 03 |
| `--amend` also fails on commits that become empty (`--allow-empty` needed) | exp7 |
| `commit-tree` **silently drops `mergetag`**; also re-derives `encoding` from ambient config | expD |
| `hash-object -w -t commit --stdin` preserves every header verbatim (incl. `mergetag`, unknown headers, order), runs fsck validation, and round-trips all message shapes byte-exactly | expD/expF |
| Trailer appended after the message; strip → byte-identical pre-image | probes 01/04 |
| Signature must be computed **over the trailer block**, imprint **without** it; both verify afterwards (openpgp + ssh) | expG/expH |
| `update-ref` rejecting `verify`+`update` on the same ref in `--stdin`; single `update ref new old` is the CAS | expG |
| `--no-verify` still runs `post-commit`; post-commit exit status is **ignored** by git | exp3 |
| Verification distinguishes imprint mismatch and untrusted anchor (both rejected) | probe 05 |
| Prior art: `tydence` (separate stamp commits), `sigstore-tsa` (client+verify) | crates.io/README |

macOS + Linux, POSIX `sh` hooks; Windows only via Git-Bash, best effort.

## 6. Approaches considered

**A — tokens in a commit trailer, object rewritten post-hoc.** *Pros:* proof
inside the hash-covered object, survives clone, offline-verifiable; the only
approach where "part of the history" is true by construction. *Cons:* hash
changes after git printed it (§13); a signature must be re-created (§9);
rebased commits must be re-sealed.

**B — tokens in `refs/notes/rfc3161`.** *Pros:* no hash churn, signature
untouched. *Cons:* separate ref, not pushed by default, not hash-covered; a
clone has zero evidence (A2).

**C — separate "stamp" commits over a manifest** (the `tydence` model).
*Pros:* no rewrite, batchable. *Cons:* the timestamp belongs to the stamp
commit, not the commit you made; needs explicit `tydence stamp` runs.

**Recommendation: A**, with `time.store = note` as a documented downgrade and
C's manifest idea for `seal --range` batching.

**Rewrite primitive: `git hash-object -w -t commit --stdin`, not
`git commit --amend` and not `git commit-tree`.** `--amend` is refused during
rebase (probe 03) and fails on now-empty commits. `commit-tree` is shorter but
*drops `mergetag`* — silently unbinding a signed tag from a merge commit (A7)
— and derives `encoding` from ambient config instead of the object. We
therefore compose the object bytes ourselves, which also means we sign it
ourselves. A targeted rebuild of headers the API happens to expose would
reintroduce the same class of bug.

Sub-decision, *when* to obtain tokens: post-commit rewrite (chosen) vs
`prepare-commit-msg` with a *predicted* commit object. Git assigns the
committer timestamp after hooks return, so prediction is approximate; also a
hard gate would require doing the work twice.

## 7. Architecture

One binary `git-time` on `PATH`, invoked by git as `git time …` (plugin
dispatch). Crates: `git-time-core` (library), `git-time-cli` (thin binary).

The hook is **synchronous**. That is what makes `git commit && git push`
correct and `time.deadline` meaningful; no queue, no lock file, no daemon.
`post-commit` exit status is ignored by git (measured), so `on-failure=fail`
is loud + exit 3 for wrappers only; a real hard gate is `time.gate = pre-commit`
(a cheap reachability probe before the object exists, so a dead TSA set can
still stop the commit).

```
git commit | git merge
   │ git writes C, updates HEAD, runs the matching hook
   ▼
.git/hooks/post-commit ─► git time hook post-commit     (sync, budgeted)
.git/hooks/post-merge  ─► git time hook post-merge      (merges never fire post-commit)
                              │
      1 resolve ref: symref HEAD or detached oid        (capture, for CAS)
      2 C ← cat-file commit <oid>; skip if HEAD moved
      3 P ← C minus trailer block minus gpgsig*          (fail closed on parse)
      4 D ← digest(P); sign_state ← gpgsig present?
      5 fan out to N TSAs in parallel over D (nonce/alg/policy/deadline)
      6 verify every response locally, keep good, record failures
      7 object′ ← headers verbatim + message + trailer block
      8 assert: strip(object′) == P            (abort otherwise)
      9 if sign_state: sig ← sign(object′ minus gpgsig)   (abort if it fails)
     10 oid′ ← hash-object -w -t commit    (fsck-validated)
     11 update-ref -m "rfc3161 seal" <ref> oid′ <oid>      (CAS)
     12 stderr: "rfc3161: sealed 1a2b3c4 by 2/3 TSAs"
```

Components (`git-time-core`): `object` (byte-exact parse/compose, header
table incl. `mergetag`, `encoding`, unknown headers; fail-closed), `imprint`,
`tsa` (`trait TsaBackend`; production impl over `sigstore-tsa`, rustls, per-TSA
rate limit, jittered retry, timeout), `verify` (CMS/TSTInfo, chain to pinned
anchor valid at genTime, ESSCertID, policy), `sigcheck` (git/ssh-keygen
subprocess), `store` (trailer codec, note fallback), `policy`, `repo` (only
place that shells out).

Signing order, precisely: **token imprint excludes trailer and signature;
signature covers the object including the trailer block.** Both are provable
in opposite directions (probe 04).

## 8. Data model

### 8.1 Trailer block

Own paragraph, appended after the verbatim message (which already ends in
`\n`; we append `"\n"` then the lines):

```
X-RFC3161-Imprint: sha256:9f2c…41
X-RFC3161-Object: 4f1c9e0…            ; oid the tokens were taken over
X-RFC3161-Token: ver=1; id=freetsa; alg=sha256; policy=1.2.3.4.1; nonce=9c1f3ab2; tst=<b64url(zstd)>
X-RFC3161-Token: ver=1; id=digicert; alg=sha512; policy=1.2.3.4.1; nonce=7712fe04; tst=<…>
X-RFC3161-Fail: id=ai-moda; reason=http-503
```

- One `Token` line per TSA → parallelism visible in the artifact, no single
  point of proof.
- `nonce` repeated so the request is rebuildable byte-identically without
  storing query DER.
- `Object` makes `format-patch` → `git am` replay gradeable as `STALE`
  instead of `BAD-IMPRINT` (§10).
- `Fail` lines distinguish "tried and failed" from "never tried".
- zstd-19, base64url unpadded, one line per token. A 3-TSA commit grows
  ≈10 KB; `--oneline` unaffected. `time.max-trailer-bytes` (64 KB) breach
  drops the largest token with a `Fail: oversized` line → verdict
  `UNDER-QUORUM`, never plain `SEALED`.
- Parsing is order-insensitive and tolerant of `git interpret-trailers`
  normalisation; the block is always last.

### 8.2 Rewrite invariants (all measured)

- `P` = object with the trailing `X-RFC3161-*` block **and** every
  `gpgsig`/`gpgsig-sha256` header *with its continuation lines* removed.
- Every other byte of the header section (order, `mergetag`, `encoding`,
  unknown headers) is copied verbatim; the message is copied verbatim.
- Before `update-ref`, the tool re-derives `P` from the composed bytes and
  requires byte equality with the sealed `P`. Mismatch ⇒ abort, commit stays
  untouched. This assertion, not an assumption, is the contract.
- Already-sealed commit (user ran `--amend`): strip stale tokens, fresh nonce,
  re-seal. A replayed patch keeps the old block until re-sealed.
- `hash-object` fsck-validates; a malformed rebuild is refused before any ref
  move.
- `update-ref <ref> <new> <old>` is the CAS. On mismatch: retry ≤3 if the same
  object is still reachable, else abort with a `git time seal` hint.
- Rebasing: `time.seal-during-rebase = all|tip|off` (default `all`). `off`
  leaves commits `UNSEALED` and prints the `seal --range` command; nothing is
  lost.

### 8.3 Config

```ini
[time]
  required = 1              ; successes needed; 0 = best effort
  deadline = 10s
  on-failure = warn         ; warn | fail (loud + exit 3; git ignores it)
  gate = post-commit        ; post-commit | pre-commit (hard gate)
  store = trailer           ; trailer | note | both
  seal-during-rebase = all
  record-failures = true
[time "tsa.freetsa"]
  url = https://freetsa.org/tsr
  anchor = ~/.config/git-time/anchors/freetsa-2026.pem
  alg = sha256
  policy = 1.2.3.4.1
  timeout = 6s
```

`time.enabled` is repo-global unless `extensions.worktreeConfig` is on
(`--worktree`), since the hooks dir is shared by all worktrees.

### 8.4 Trust

Anchors pinned per TSA and required; no "trust the token's chain" mode (A4).
Presets ship URL + anchor + policy for public TSAs; `tsa add <preset>` prints
the fetched fingerprint for eyeballing, `anchor pin` records the digest in a
tracked lock file (opt-in `time.anchors-lock`). `doctor` reports anchor age and
mismatch; mismatch fails closed.

## 9. Commit signing (GPG / SSH)

| Question | Answered by | Trust |
|---|---|---|
| Who authored this? | signature | key trust |
| When did it exist? | RFC 3161 token | TSA anchors |

An OpenPGP signature's creation time is self-asserted and freely backdatable,
so it is not a timestamp and we never treat it as one; the token does not
replace the signature either.

- Signature state is read from the **object**, not config: `gpgsig` present ⇒
  re-sign after the rewrite. This is what makes `git commit --no-gpg-sign`
  work (config alone would override the opt-out).
- Signing key is taken **from the existing signature** (OpenPGP issuer via
  `gpg --list-packets`, SSH embedded public key) and passed explicitly;
  config is only a fallback, with a warning.
- Re-sign failure (PIN cancelled, smartcard gone) ⇒ **abandon the seal**,
  leave the original commit untouched and warn. A signed commit is never
  rewritten unsigned.
- Cost: two signing operations per commit (git's, ours); `gpg-agent` caches,
  so normally one prompt. `time.seal-signed = after` defers signed commits to
  `git time seal` for hostile smartcards.
- `verify` reports signature and timestamp separately; valid token + bad
  signature is `BADSIG`/`UNSIGNED`, never a blanket PASS.

## 10. Verification

`git time verify [--range A..B] [--require-sealed] [--require-signed] [--json] [<commit>…]`

Per commit: parse block → recompose `P` → compare digest to the declared
imprint → per token: CMS parse, TSTInfo imprint, nonce, chain to pinned anchor
valid at genTime, ESSCertID, policy, genTime vs committer date (warn if the
committer is later — backdating or skew). Verdict needs `required` valid
tokens from distinct TSAs.

`SEALED`, `UNDER-QUORUM` (with reasons), `UNSEALED`, `STALE` (token valid but
`Object` ≠ current `P`; replayed/edited patch), `BAD-IMPRINT`, `BAD-TOKEN`,
`UNTRUSTED`, `BADSIG`. Exit 0/1/2. The verdict is the evidence; `BADSIG` is its
own verdict, while an unsigned commit stays `SEALED` and is reported as
`unsigned` in the `signature` field — `--require-signed` is the gate that fails
it. `git time log` prints the audit view.

## 11. Install / skip / uninstall

`git time install` resolves the hooks dir via `git rev-parse --git-path hooks`
(honours `core.hooksPath`), chains foreign hooks by renaming them
`<name>.pre-time`, restores on `uninstall`. It wires **two** hooks: `post-commit`
for ordinary commits and `post-merge` for merges, because git does not run
`post-commit` for a merge (measured on 2.56: `pre-merge-commit` and `post-merge`
fire, `post-commit` does not). It also configures TSAs:
The authority set is the repository's: an existing `time.tsa.*` config is kept,
an empty one hands over to the `tsa select` cursor UI (freshest curated pair:
freetsa + digicert, `--preset` was dropped later); if anchors cannot be fetched
the install still succeeds with a loud warning and `doctor` flags "no TSA
configured" — the first commit after install is never silently unsealed without
a notice.

Shim: `command -v git-time >/dev/null && exec git time hook post-commit; exit 0`.

Skips: `--no-verify` does **not** skip (post-commit always runs) → document
`GIT_TIME_SKIP=1`, `time.enabled=false`, `git time seal --range HEAD~5..HEAD`
for later sealing, `git time drop` to mark intentional.

## 12. Decisions (resolved 2026-11-18)

- **D1 Storage:** commit trailer. Notes remain a per-repo downgrade.
- **D2 Quorum:** `required = 1` of N.
- **D3 Failure mode:** `warn` by default; `fail` + `gate = pre-commit` opt-in.
- **D4 Presets:** freetsa + ai.moda.
- **D5 Execution:** subagent-driven, one task per fresh implementer.

## 13. Risks

| Risk | Mitigation |
|---|---|
| Hash changes after git printed it | hook prints the real oid; reflog shows both; `log`/`status` consistent |
| TSA latency blocks the shell | deadline + `required=1`; worst case ≈ deadline; `seal-during-rebase=tip` for big replays |
| TSA sees metadata | only a digest + nonce |
| Token volume | zstd, size cap, per-TSA opt-out |
| Anchor substitution | out-of-band anchors, `pin`, fingerprint printed on verify |
| `mergetag`/`encoding` loss | `hash-object` verbatim rebuild + pre-CAS assertion + test matrix |
| TSA dies/discredited | multi-TSA; `verify` names the backing TSAs |

## 14. Delivery slices

1. `object` + `imprint`: byte-exact compose/parse, header matrix, fail-closed
   parse, round-trip property tests.
2. `store` codec + `verify` skeleton (no network) over the probe corpus.
3. `tsa` backend, parallel fan-out, local token verification; live freetsa.
4. `hook`, `install`, `doctor`; rebase/merge/cherry-pick/amend/`-S` matrices.
5. `verify` end-to-end + verdict matrix, `log`, `seal --range`, `drop`.
6. Docs, presets, `anchor pin`, release (cargo + CI artifacts, tap later).

## 15. Evidence

`docs/superpowers/specs/probes/*.sh` reproduce §5 (byte identity, rebase,
amend refusal, signature survival, live TSA + fail-closed matrix); all five
pass. Extra probes from the builder-check round live in `/tmp/gt-expD–H`:
`mergetag` loss via `commit-tree`, `hash-object` fidelity, signing order,
`update-ref` CAS behaviour.
