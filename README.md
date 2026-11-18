# git-time

`git commit` gains a verifiable RFC 3161 timestamp from several independent authorities, stored
inside the commit object itself. Type nothing extra: install once, then keep committing.

The promise is one line long — **type nothing extra**. No wrapper, no daemon, no extra command
before or after a commit, and no prompt on the normal path.

## Quick start

```console
$ cargo install --path crates/git-time-cli    # or: cargo build --release
$ git time install --preset public            # wires the hooks, fetches anchors
$ git commit -m "add entry point"             # the only command the user types
$ git time verify                             # judges the evidence, gates CI
```

`cargo install` without `--path` needs the crates published, which they are not yet; use the
`--path` form above, or build and put `target/release/git-time` on `PATH`.

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
X-RFC3161-Fail: id=ai-moda; reason=anchor-ai-moda-could-not-be-read…
X-RFC3161-Fail: id=freetsa; reason=timeout
```

The commit exists, the worktree is clean, `git fsck` is silent, and the artifact says exactly which
authority failed and why. A dead TSA costs evidence, never a commit.

## How it works

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

- [Operator manual](docs/manual.md) — every config key, command, exit code and failure mode.
- [Design](docs/superpowers/specs/2026-11-18-git-time-rfc3161-design.md) — the contract and the
  measured probes behind it.
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
