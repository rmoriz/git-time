# A fingerprint on `tsa add`, and a pin that says it was unconfirmed

Short design. A first pin with no expectation is trust on first use, and nothing
records that it happened. The printed fingerprint is the only chance to review
it, on the terminal where the fetch ran. This lets a person hand in the expected
fingerprint up front, marks a pin that had none, and has `doctor` keep naming it
until someone confirms it.

## Why

Every built-in preset publishes a fingerprint, so `preset add`, `install`,
`select` and `restore` all check what they pin. A custom authority publishes
nothing, so its first `anchor fetch` accepts whatever the network hands back,
and the tool then treats it exactly like a checked pin — `doctor` green, `pin -`
gone, the seal warning saying "integrity is still verified". Nothing in the
repository later disturbs that, as the seal path only ever verifies against the
pinned root.

## Goals

- `tsa add <url> --fingerprint <fp>` stores an expectation, so the first pin of
  a custom authority is a check rather than TOFU.
- A pin that did happen with nothing to compare is marked, and `doctor` reports
  it, with the command that clears it.
- `git time anchor confirm <id> [<fingerprint>]` is that command: the place a
  human's out-of-band comparison is recorded.
- The seal warning stops implying that a TOFU pin was verified.

## Non-goals

- No `tofu` verdict in the block format, and nothing new in `verify`: the marker
  is a fact about this machine's pin, not about the evidence.
- No publication discovery for a custom id, and no probing of one.
- No change to what is trusted: a marked pin verifies in full, exactly as now.
- `preset add` is untouched; a preset's publication is already the expectation.

## Anti-goals

- A marked pin that behaves worse than an unmarked one at seal or verify.
- A marker that clears itself because a later fetch served the same root: an
  attacker serving the same fake root twice is not a confirmation.
- A `doctor` finding with no runnable fix.

## Constraints

`tsa add` writes config and fetches nothing, so `--fingerprint` is *stored*
there and checked at the next fetch — which is `install` or `tsa select`, the
two paths that pin. The flag therefore refuses a value no fetch could compare:
anything but 20 or 32 colon-separated upper-case hex octets.

## Approaches

**A — a stored expectation, a marker, and a confirm verb (chosen).** The
expectation joins the existing comparison in `accept::apply`, so every pinning
verb honours it without new fetch logic, and the marker gives `doctor` something
to report until a human signs off.

**B — a `tofu` verdict in the block.** The evidence would carry "this was
unconfirmed", which a reader of the repository can see. Costs a format change
and does not help the pin itself, which is where the review belongs; a later
`confirm` would not rewrite old blocks.

**C — `--fingerprint` alone.** Cheapest, but with no marker there is nothing to
ask `doctor` about, so an unconfirmed pin looks exactly like a checked one.

## The design

- `time.tsa.<id>.fingerprint` holds the expected root, in the preset table's
  spelling. It is written by `tsa add --fingerprint` and read out of band by the
  pinning callers.
- `accept::apply` gains it as an expectation, ordered after a block's named
  roots and after a preset's publication and before "already pinned". A match
  against it pins and clears the marker; a mismatch is the existing refusal
  naming both values.
- `time.tsa.<id>.tofu = true` is written when `apply` takes the trust-on-first-use
  branch. It is cleared by a match against a named, published or configured
  value, by `--accept`, and by `anchor confirm`. A re-fetch of the same root
  leaves it.
- `anchor confirm <id>` clears the marker and prints the roots it confirmed. With
  a fingerprint, the pinned bundle must carry that root or the command fails;
  the bare form confirms the root the listings report and prints every root, so
  the transcript records what was confirmed.
- `doctor` prints `anchor <id>: tofu <sha256>` and a `problem:` line with
  `git time anchor confirm <id> <sha256>` in it, and exits `1`. JSON carries
  `"tofu": true`.
- The seal warning gains its own capped line (`rfc3161: warning: N pins are
  trust-on-first-use (<ids>); compare out of band, then git time anchor confirm`)
  whenever a configured id carries the marker, so the existing
  "integrity is still verified" line is no longer the last word.

## What the docs say

`docs/manual.md`'s TOFU paragraph currently ends "the first pin can only be
reviewed by reading the fingerprint `anchor fetch` prints". It becomes the flag
and the confirm step. `docs/git-time.1`'s SECURITY CONSIDERATIONS gains the same
two commands in a sentence. `docs/STATUS.md` gets the guarantee table row.

## Tests

The marker is set by `anchor fetch` and by `install`; it survives a re-fetch of
the same root; it is cleared by `confirm`, by `--accept` and by a published
match. `tsa add --fingerprint` writes the key, and a later fetch of a different
root is refused without `--accept`. `confirm` with a value the bundle does not
carry fails and leaves the marker. `doctor` names it, exits `1`, and drops the
line once confirmed. `--fingerprint` refuses `dead:beef`.

## What is left to the builder

Where the callers read the configured value without making it a `Policy` field;
only `tofu` is loaded into the policy, for the warning.
