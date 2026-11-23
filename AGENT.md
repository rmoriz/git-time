# AGENT.md

Notes for agents (and humans driving them) working in this repository.

## Provenance

This repository was designed and implemented with **OpenCode 2** driving **DeepSeek V4.1 Flash**.
The work was done spec-first: a design document with measured probes, a task-by-task plan, an
independent review and a fix round per task, and a ledger of decisions — all of which are checked
in under `docs/` so the reasoning survives the session that produced it.

Attribution matters here for a reason beyond credit: the safety properties below are only
believable because each one has a test that fails when the property is removed. If you change
them, keep that property.

## What this is

`git-time` seals `git commit` objects with RFC 3161 timestamp tokens from several authorities,
queried in parallel and verified locally before they are stored inside the commit object.

- Library: `crates/git-time-core` (objects, imprint, trailer codec, TSA client, verification, seal)
- Binary: `crates/git-time-cli` (`git time …`)
- Design: `docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md`
- Plan: `docs/superpowers/plans/2026-11-18-git-time-rfc3161.md`
- Status, deviations, known gaps: `docs/STATUS.md`

## Invariants — do not "simplify" these away

1. **Rewrite with `git hash-object -w -t commit`, never `git commit --amend` and never
   `git commit-tree`.** `--amend` is refused during rebase and fails on now-empty commits;
   `commit-tree` silently drops the `mergetag` header, which unbinds a signed tag from a merge.
2. **The pre-CAS invariant is the product.** After composing the sealed object, the tool strips
   the trailer block and the signature and requires byte equality with the sealed pre-image. No
   ref moves until that holds. Removing the assertion turns a sound rewrite into a guess.
3. **Imprint excludes the trailer and the signature; the signature covers the trailer.** Get the
   order wrong and either the token or the signature is invalid.
4. **Signature state is read from the object, not from config.** This is what makes
   `git commit --no-gpg-sign` work and what keeps `gpgsig-sha256` (SHA-256 repositories) alive.
5. **Verification is fail-closed.** Missing anchor ⇒ `UNTRUSTED`; a valid token over a broken
   signature is never a PASS; the imprint is recomputed, never trusted from the block.
6. **One dead TSA never costs a commit.** Failures become `Fail` records, quorum decides, the
   hook exits 0 under `warn`.
7. **Merges are sealed from `post-merge`.** Git does not run `post-commit` for a merge (measured).
8. **Never rewrite a commit reachable from a remote-tracking ref.** `post-merge` also fires on a
   fast-forward `git pull`; sealing then would make the next push non-fast-forward.

## Working in this repo

```sh
cargo test --offline                     # 745 tests + 1 ignored live test
cargo clippy --offline --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check                         # advisories, licenses, bans, sources
cargo test -p git-time-cli --test live_tsa -- --ignored --nocapture   # real TSA, needs network
```

- Build `--offline` when the sandbox blocks egress; the dependency set is in `Cargo.lock` and the
  local cargo cache is usually primed. A per-process firewall (Lulu and similar) can block the
  `git-time` binary while `curl` works — that shows up as `Fail: reason=timeout`, which is the
  fail-open path working, not a bug.
- Tests must be hermetic: `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, temp
  `GNUPGHOME`, throwaway CA, loopback stub TSAs. Never read the developer's real keys or config.
- Fixtures in `crates/git-time-core/tests/fixtures/` are real captured bytes; their `README.md`
  records provenance. Do not regenerate them casually.
- Commit messages: no `Co-Authored-By` trailers (repo owner's preference), and say *why* the
  change exists, not just what moved.

## Releasing

The version lives in `[workspace.package]` in the root `Cargo.toml`, and `git-time-cli` pins the
path dependency to it — a bump that misses that crate does not build. A release is one commit
carrying: both manifests, `Cargo.lock`, the `docs/git-time.1` `.TH` date and version, the README's
`VERSION=` snippet, the test count in `AGENT.md`, and a `## Release notes (vX.Y.Z)` section above
the previous one in `docs/STATUS.md`. `git time --version` and the man page have to agree with the
tag, because the workflow's preflight refuses a disagreement in seconds and nothing downstream
would notice.

Then tag annotated, not lightweight (`git tag -a -m "git-time X.Y.Z"`), push `main` first and the
tag second. The workflow runs fmt, clippy and the suite, builds the four targets and publishes with
`generate_release_notes: true`.

That auto body is a changelog link and nothing else, so **the release body is set by hand once the
release exists**: `gh release edit vX.Y.Z --notes-file <file>`, with the STATUS notes under a
`## Notes` heading and, above them, the install preamble from the previous release — assets link,
the four quick-start commands, and what (if anything) a user has to migrate. Notes written only
into `STATUS.md` and never onto the release reach nobody but the repository.

## When docs and code disagree

`docs/STATUS.md` records deliberate deviations from the design and is the authority for shipped
behaviour. The design document is the contract that was approved; if behaviour must change, update
the design and STATUS together rather than leaving the two to drift.

## Hooks and user files

`git time install` chains foreign hooks by renaming them, never overwriting an existing preserved
hook, and `uninstall` refuses to delete a hook the user edited. Any change in that area keeps the
same rule: never destroy a user's file, and make the refusal path visible.
