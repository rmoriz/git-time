# The `X-RFC3161` commit trailer block — format version 1

This document specifies the bytes `git-time` appends to a commit message, so
that a tool written in another language can read a sealed commit, judge it, or
produce a conforming one. It is the format, not the pitch: for usage see the
[README](../README.md), for the configuration and failure modes the
[manual](manual.md).

The block is *evidence, not trust*: it records what was hashed and one RFC 3161
token per authority that answered. Whether the evidence is worth anything is
decided by verification against pinned anchor certificates (§8).

## 0. Conventions

`MUST`, `MUST NOT`, `SHOULD` and `MAY` are RFC 2119. Byte values are written
`0x0a`; `LF` is `0x0a`, `SP` is `0x20`, `CR` is `0x0d`.

The reference implementation is `crates/git-time-core/src/store.rs` (the codec),
`object.rs` (the pre-image) and `verify/` (the judge). Where this document and
that code disagree, the code is right and the document is a bug.

## 1. What the block is

A block is one or more lines in the **message** of a commit object, in the last
paragraph, each line beginning with `X-RFC3161-`. It is appended by the sealing
tool after the author's message, separated from it by exactly one empty line,
and the object ends with a single `LF` after the last block line:

```
tree 4500086a…
parent 03de93a3…
author … 1795040011 +0100
committer … 1795040011 +0100

readme: say which roots are pinned now

The table still called … why.
                                     <- the separating empty line
X-RFC3161-Imprint: sha256:be7de724…
X-RFC3161-Token: ver=1; id=freetsa; …
```

The author's message is copied verbatim; sealing never reflows it. The trailing
block paragraph is the whole of it: a blank line ends the block, so a block in
the middle of a message is not a block.

The block belongs to the commit object, not to a note or a header, so it travels
with the object through every clone and mirror and is covered by the commit
signature (§7). It is therefore visible in `git log`, `git format-patch` and in
any forge's commit view.

**Size.** A block is a paragraph of a commit message and `git` has no limit on
those, but a §5 budget bounds it: 65 536 bytes by default, configurable. One
token is capped at 1 048 576 bytes in both directions.

## 2. Grammar

ABNF per RFC 5234; `UTF8-octets` and `pct-encoded` are from RFC 3629/3986.

```abnf
block        = line *( LF line )            ; no trailing LF inside the block
line         = "X-RFC3161-" name ": " value
name         = "Imprint" / "Object" / "Token" / "Fail" / extra-name
extra-name   = 1*( UTF8-octets )            ; but no ":", SP, CR, LF
value        = imprint-value / object-value / token-value / fail-value / extra-value

imprint-value = alg ":" hexdig
object-value  = 40hexdig / 64hexdig
alg           = "sha256" / "sha512"
hexdig        = 2HEXDIG                     ; 32 bytes for sha256, 64 for sha512

token-value  = "ver=1; " "id=" label "; " "alg=" alg "; "
               [ "policy=" label "; " ] "nonce=" hexdig+ "tst=" tst
fail-value   = "id=" label "; " "reason=" label
label        = 1*( %x21-3a / %x3c-7e )      ; printable ASCII, no ";" and no SP
tst          = base64url

extra-value  = 1*( UTF8-octets )            ; but no CR or LF
```

`base64url` is RFC 4648 §5 with the padding `=` omitted; the decoded bytes MUST
be a zstd frame (§4).

Decoding of numbers and case is lenient where re-encoding is strict:

| Field | On decode | On encode |
|---|---|---|
| `Imprint` hex | any case, exact algorithm width | lowercase |
| `nonce` hex | any case, even length | lowercase |
| `Object` | exactly 40 or 64 lowercase hex | lowercase |
| field order inside `Token` | fixed, see §3 | fixed |
| line order inside the block | any, see §3 | canonical, see §3 |

`nonce` is 1 to 64 bytes. Every `name`, `id`, `policy` and `reason` is UTF-8;
`tst` is ASCII.

## 3. Fields

The canonical rendering order is `Imprint`, `Object`, `Token*`, `Fail*`, then
unknown fields. A reader MUST accept any order of lines, and MUST re-emit
unknown fields verbatim and last. Inside a `Token` or `Fail` value the order is
fixed and a reader MUST reject an out-of-order, missing or trailing field: the
value is a record, not a bag.

### `Imprint` — exactly once

What was timestamped, as `alg:hex`. The bytes hashed are the pre-image of §6,
and a verifier MUST recompute them for the algorithm this field names. A
duplicate `Imprint`, or a block without one, is malformed.

`sha256` and `sha512` are the only algorithms. Which one is used is a property
of the authority's configuration, not of the commit: an imprint names exactly
one.

### `Object` — at most once

The object id the tokens were taken over: `git hash-object` of the pre-image
bytes, 40 hex for SHA-1 repositories, 64 for SHA-256. Provenance only — a
verifier MUST NOT trust it and MUST recompute the imprint instead. It exists so
that a replayed commit (`format-patch` → `am`) can be told apart from a
tampered one.

### `Token` — zero or more

One authority's RFC 3161 `TimeStampResp` token, in the fields `ver`, `id`,
`alg`, optional `policy`, `nonce`, `tst`.

- `ver` is the block version, `1`. A reader MUST refuse any other value. It is
  first, so a reader can branch before it parses the rest.
- `id` is the local name of the authority (`time.tsa.<id>.…`). Two `Token`
  lines MUST NOT share an id; a repeated id is one authority's answer twice.
- `alg` is the digest the *request* asked for, which MUST equal `Imprint`'s.
- `policy` is the policy OID the request asked for, dotted decimal, present
  exactly when a policy was requested.
- `nonce` is the request nonce, so the query is rebuildable byte-identically
  without storing its DER.
- `tst` is the token, compressed and encoded (§4).

There is no field for the authority's URL: it is configuration, and an authority
may move. Trust therefore comes from the anchor pinned under that `id`, never
from the block.

### `Fail` — zero or more

An authority that was asked and did not deliver a usable token, as `id` and
`reason`. A `Fail` line turns "was never asked" into "was asked and failed",
which is what makes a quorum shortfall legible.

`reason` is one of:

| Reason | Meaning |
|---|---|
| `timeout`, `http-503`, … | Transport or protocol failure, sanitised: ASCII alphanumerics and `-.:/_()` kept, everything else collapsed to `-`, at most 200 characters. |
| `invalid-<kind>` | A token arrived and verification refused it. `<kind>` is one of `imprint`, `nonce`, `untrusted`, `cert-not-valid-at-gen-time`, `policy`, `malformed`, `expired`. |
| `oversized` | The token was over the 1 MiB cap or the block budget, and was dropped (§5). |
| `no-anchor-pinned` | The authority is configured but has no anchor, so it was not asked. |

A reason is prose for a human; a verifier MUST NOT branch on its text.

### Unknown fields

An unknown `name` MUST be preserved verbatim, in file order, and re-emitted
after the known ones. That is what makes an added field a compatible change
(§9). `extra-value` may contain `;` and SP, but not CR or LF.

## 4. `tst`: the token on one line

The token bytes, compressed with zstd at level 19 and encoded base64url without
padding. Compression is not decoration: commit messages travel through mail,
patches and forge search indexes, and a raw DER token is roughly double the
size.

A reader MUST refuse, with a distinct error:

- bytes that are not valid unpadded base64url;
- bytes that are not a zstd frame, or whose window log announces more than
  2^23 bytes;
- a frame announcing, or decompressing to, more than 1 048 576 bytes. Check by
  announcing size where the frame carries one, and otherwise by reading at most
  one byte past the cap.

The token itself is opaque here: it is the CMS `ContentInfo` of RFC 3161 §2.4.2,
`id-smime-ct-TSTInfo`. Its structure is RFC 3161's business, and §8 says what a
verifier MUST check in it.

## 5. Budget

A block that does not fit its budget is shortened by dropping the **largest**
rendered token and recording `X-RFC3161-Fail: id=<id>; reason=oversized`, until
it fits. Ties drop the first of the largest. A token over 1 MiB is dropped the
same way before anything is rendered, so a block a writer emits is always one a
reader can parse. A block that does not fit with no tokens left is a failure,
never a truncated block.

The default budget is `time.max-trailer-bytes` = 65 536. A writer SHOULD use it
and MUST record every drop, so a short block still says how many authorities
answered how.

Dropping a token never drops the `Imprint`: a block with no tokens and only
`Fail` lines still grades as `under-quorum`, not as unsealed.

## 6. The pre-image

The pre-image is what an imprint is hashed over. Take the commit object and:

1. remove every `gpgsig` and `gpgsig-sha256` header together with all of its
   continuation lines (a continuation line begins with one `SP`) — a signature
   covers the block and therefore cannot be inside the hashed bytes;
2. if the message ends with a paragraph whose every line begins `X-RFC3161-`
   (the last paragraph, and only that one), remove that paragraph and the one
   `LF` that separated it from the message;
3. hash the remaining bytes with the algorithm `Imprint` names.

Nothing else changes: every other header (order, `mergetag`, `encoding`,
unknown ones), the author and committer lines and the remaining message bytes —
including any trailing `LF` of the message — are hashed exactly as they are.

Rebuilding the object from a pre-image has to be byte-exact, or the artifact is
not auditable: `pre-image bytes`, one `LF`, the block bytes, one `LF`. A writer
MUST compare the result with what it is about to store and abort on a
difference.

The pre-image is the artifact's *content* side: an impression of everything in
the commit except the evidence and the signature over it.

## 7. Producing a block

In order, because each step's bytes are covered by a later one:

1. Build the commit object as usual, unsigned and without a block.
2. Derive the pre-image (§6) and hash it with the configured algorithm.
3. Ask every usable authority for a token over that imprint, in parallel, with a
   fresh random nonce each and the assembly deadline as a hard bound. An
   authority without an anchor is not asked and gets `no-anchor-pinned`.
4. Verify each answer against the imprint, its nonce and the pinned anchors
   (§8), then build the block from the tokens that verified and a `Fail` line
   for each that did not.
5. Render, drop tokens over budget (§5), append the block to the message.
6. Sign the object **after** the block is in place, so the signature covers it.
7. Write the object, `fsck` it, and move the ref with a compare-and-swap
   (`git update-ref <ref> <new> <old>`). On a mismatch, retry while the old
   object is still reachable, else abort — a commit that lost its evidence is
   left untouched rather than half-sealed.

A commit already reachable from a remote-tracking ref is not rewritten by the
hook: rewriting it would move the branch ahead of its remote. Re-sealing such a
commit is an explicit command.

Sealing is idempotent: re-sealing an object that already answers the same
pre-image is a no-op. A re-sealed amended commit drops the stale block first and
keeps the author's message.

## 8. Verifying a block

A verifier MUST, in this order, and fail closed on any step:

1. **Parse** the block by §2–§5. Malformed is malformed, never a guess.
2. **Recompute** the pre-image (§6), hash it with `Imprint`'s algorithm and
   compare in constant time. A mismatch is `bad-imprint` whatever the block
   claims — a signature over a changed message does not save it.
3. **Judge each token** (`RFC 3161` §2.4.2, RFC 5652 §5.1, RFC 5280):
   - parse CMS and its TSTInfo; `messageImprint` MUST equal the recomputed
     digest, and `hashAlgorithm` MUST equal `alg`;
   - `nonce` MUST equal the token's `nonce`, and `policy` the token's `policy`
     when one is present;
   - the CMS signature MUST verify under the signer's key;
   - the signer's certificate MUST chain to the anchor pinned under `id`, with
     every certificate valid at the token's `genTime` (a certificate may omit
     the EKU if it is not the signer; any that carries it MUST carry
     `id-kp-timeStamping`);
   - the signer MUST have a critical extended key usage of exactly
     `id-kp-timeStamping` and nothing else (RFC 3161 §2.3);
   - the ESS signing certificate attribute, when present, MUST name the signer;
   - `genTime` MUST lie in the accepted window: half-open, 24 hours around the
     commit — the earlier of the committer time and now, minus one day, to the
     later of them plus one day.
4. **Count** the distinct ids whose token verified and compare with the required
   quorum.
5. **Verify the signature** of the commit itself, once: evidence under a broken
   signature is not a pass.
6. **Report** one verdict per commit:

| Verdict | Meaning |
|---|---|
| `sealed` | Quorum met, signature acceptable. |
| `under-quorum` | Some token verified, fewer than required. |
| `unsealed` | No block (or a deliberate drop marker). |
| `bad-imprint` | The pre-image does not hash to `Imprint`. |
| `bad-token` | Tokens exist, none verified. |
| `untrusted` | Anchors are missing or do not match, so trust cannot be decided. |
| `bad-sig` | The commit signature is broken or uncheckable. |
| `unsigned` | Unsigned while a signature was required. |

A token is judged on its **own** imprint algorithm and its own id, never on the
block's good name. `Object` is reported, not trusted. A committer time later
than `genTime` is a warning, not a failure: it says clock skew or backdating,
not a broken token.

## 9. Compatibility

The version lives in each `Token` value, so a block may mix versions in
principle; `ver=1` is the only one today. Changes are:

- **Additive** (no version bump): a new `X-RFC3161-<Name>` line, a new `reason`
  value, a new `alg`. Old readers preserve or refuse the token and keep working.
- **Breaking** (new `ver`): anything inside a `Token` value, the meaning of an
  existing field, or the pre-image rules.

A reader that meets a `Token` version it does not know MUST record that token as
unreadable and keep the block; it MUST NOT drop the other tokens.

## 10. Worked example

A real sealed commit, byte for byte: `tests/fixtures/format_example.commit`.
Its message body is followed by the separating empty line and the block, and the
block begins on its own line. `tst` is shown elided here; the appendix is the
complete object.

```
tree 4500086a5dcaa93ad6c9eb0b719ba57c67ffae21
parent 03de93a3d35b013b64ebdaf29d20f3b1cb739271
author Roland Moriz <roland@moriz.de> 1795040011 +0100
committer Roland Moriz <roland@moriz.de> 1795040011 +0100

readme: say which roots are pinned now

The table still called cartaodecidadao and comodoca trust on first use,
and izenpe unverified, after the walk measured them. swisssign is the one
TOFU row left and now says why.

X-RFC3161-Imprint: sha256:be7de7244f3a555901e9f2c79bf594dce3cd5eb255c3c04aac40e67ce4146e35
X-RFC3161-Object: 9535462acdff0c2e98ff53c0d17a8b87a44ff64f
X-RFC3161-Token: ver=1; id=freetsa; alg=sha256; policy=1.2.3.4.1; nonce=e25e7f7181682511; tst=…
```

The pre-image of that object is the same header section and message with the
block and the separating empty line removed, and it hashes to the `Imprint`. The
`Object` value is `git hash-object` of exactly those bytes.

## 11. Staying true

The document is not prose about the code, it is checked against it:
`crates/git-time-core/tests/format_doc.rs` reads the appendix back out of this
file, hashes its pre-image against the `Imprint`, decodes the block with the
reference codec and asserts the result. A change to the codec that this document
does not describe fails the suite.

## Appendix — the example object, complete

<!-- format-doc:begin -->

```
tree 4500086a5dcaa93ad6c9eb0b719ba57c67ffae21
parent 03de93a3d35b013b64ebdaf29d20f3b1cb739271
author Roland Moriz <roland@moriz.de> 1795040011 +0100
committer Roland Moriz <roland@moriz.de> 1795040011 +0100

readme: say which roots are pinned now

The table still called cartaodecidadao and comodoca trust on first use,
and izenpe unverified, after the walk measured them. swisssign is the one
TOFU row left and now says why.

X-RFC3161-Imprint: sha256:be7de7244f3a555901e9f2c79bf594dce3cd5eb255c3c04aac40e67ce4146e35
X-RFC3161-Object: 9535462acdff0c2e98ff53c0d17a8b87a44ff64f
X-RFC3161-Token: ver=1; id=freetsa; alg=sha256; policy=1.2.3.4.1; nonce=e25e7f7181682511; tst=KLUv_QBofVwAVKUwghIWBgkqhkiG9w0BBwKgghIHAwIBAzEPMA0GCWCGSAFlAwQCAwUAMIIBjwYLCRABBKCCAX4EggF6dgIBAQYEKgMEATAvMAsBBCC-feckTzpVWQHp8seb9ZTc481eslXDwEqsQOZ85BRuNQIECi352BgPMjAyNjExMTgyMjEzMzJaAQH_AgkA4l5_cYFoJRETpIIBDwsxETAPBgNVBAoMCEZyZWUgVFNBMQwwCgsMA3YwdA0MbVRoaXMgY2VydGlmaWNhdGUgZGlnaXRhbGx5IHNpZ25zIGRvY3VtZW50cyBhbmQgdGltZSBzdGFtcCByZXF1ZXNtYWRlIHVzaW5nIHRoZSBmdHNhLm9yZyBvbmxpbmVydmljZXMxGDAWAwwPd3d3LjEkMCIJARYVYmxlemFzQG1haWxib3gSMBAHDAlXdWVyemJ1CzAJBhMCREUIDAZCYXllcm6ggg5nMIIGYDCCBEigAwIBAsLphhYNqOnNMA0BDYGVExAwDhMHUm9vdCBDQRMiMCATZy5jb20TEzAeFw0yNjAyMTUxOTQ0MjJaFw00MDAyMDIwdgfOPQIBBgUrgQQAIgNiAASiFeGhstbLhxix0o4UAumNSwHUUlOe3DBvs8fYs580wADW59oqGSCx15bp61TSmXkwLm1JW48XnbLLizP6ZtjcvshV3H9uz2bS53sgDXhg1wLbIhAtraC-fHCytHeuVaujggHmMIIB4h0TBAIwADAdDgQWBBQVwL0m69RdgtFdkyYxL-9wsotGXjAfIwSAFPpVDYw0ZlFDTPfns6dsla965qSXMAsPBAQDAgbAMBYlBAgrBgEFBQcDCDBsAQEEYDBeMDMwAoYnaHR0cDovLy9mcy9jYS5wZW0wJwGGGzoyNTYwMDcfBDAwLjAsoCqgKIYmY3JsL3JfY2EuMIHIIASBwDCBvTCBugYDKwUIMIGyAgEWX2Nwcy5odG1sMDImcGRmMEcCMDsaOSB0cnVzdGVTb2Z0d2FyZSBhIFMgKFNhYVMpA4ICAQBrMVS_YfnfMr0ziZnesBUOrDNRrNNgt3IgMNDwNhwl6oKWHVIhlYnM_5boljfbpZTAbqvxHI3ztT0_swxQOqTat5qBJRAY_VH1n_T4M9uDjSuu3qfh0ZH5PL9ENqoVW44i5NT_znQev2MGXOAHwz9kZwwzz9MFX6hbGhBqWa-nlAqb7Y72KFzj33m1OVHxV2Wl4YD9f91bZTFpUEGW4Ktbkmxpf_iGIPaf4WHpoBW_O6EzofMKYlz4yXyEBh0wRRVyXltLrj-MFHqhe-PsMBllq_dCaO4W_F-AuHElu7aUYWMASelphWAJiUsNMr5HAoeCSSgilqf1CSoWC-k6e4334Fym-Iy4csMex-PG4rSdqXJVQ-AWEdRajSPKh7yDfpNkdnO6yqQJ_tSd11XQ5cL0M9jWuCD1zHlgA-u-R2cry3yo23jD7qTGLhZqUvXCyWigH30_Q_RXjjDwrc4DJiQ-gRY0FhdTYqlvgMBPr4LcJKnNksivdj-kbz7bVSbrBAzRiazK9l841_5XMtP9BvD0hKCpQFvP9PSgCC8EQnKqgSe26FSJBaAQcA5TnK8NF4jkbElBxf_zyh7P3IjHso35jtgUWD1_itg9BJWbYUwJ4tfILpB2F0wbk1GcZDCDZoyW3Xf3trApz_Zd93gF3joc9Hh9RFveKRzWQ7ddUt3egTCCB_8wggXnwYAxNjAzMTMwMTUyMTMxMDMwN4ICIgEPAAoCtgKODjAy8REQ2WTNqUudAnjhlCrpE6qlmQfNppeTmVvZrH4zutn-NwTaHAGpjSGv4_WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx0s_MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlelb-PqT---fOa2oY0-NaMM7l_xcNHPOaMz0_2olk0i22hbKeVhvokPCqhFhzsuhKsmq4Of_o-t6dI7sx5h0nPMm4gGSRhfq-z6BTRgCrqQG2FOLoVFgt6iIm_BnNffUr7VDYd3zZmIwFOj_H3DKHoGik_xK3E82YA2ZulVOFRW_zj4ApjPa5OFbpIkd0pmzxzdEcL479hSA9dFiyVmSxPtY5ze1P-BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw_Xn_XTFNzRBM3cq8lBOAVt_PAX5-uFcv1S9wFE8YjaBfWCP1jdBil-c4e-0tdywT2oJmYBBF_kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj_C4SvapiDN837gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q_YVs7H_nU4c4Ixxxz4f67fcVqM2ITKentbCMCAwEAAaOCAk4wggJKMAwFMAMwDg8BxoHKgcIwgb-hgZukgZiCMywwKjAooCagJIYiz8cwgcQwgcEGCgQBgfIkAQE3KzApaK9-v5OFYu9M6ztYC-L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM_ipwoLtnxyxGsbCPhcQjuTvzm-ylN6VwTMmIlVyVSLKYZcdSjt_eCUN-41K7sD7GVmxZBAFILnBDmTGJmLkrU0KuuIpj8lI_E6Z6NnmuP2-RAQSHsfBQi6sssnXMo4HOW5gtPO7gDrUpVXID--1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLzaWuhtpAtd7ffwEbASgzB7E-NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZDctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G-UC41DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW99y90xcwr1ZIDUwM_xQ_noO8FRhm0LoPC73Ef-J4ZBdrvWwauF3zJe33d4ibxEcb8_pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G_VT7OF669xM6hbUt5G21JE4cNK6NNucS-fzg1JPX0-3VhsYZjj7D5uljRvQXrJ8iHgr_M6j2oLHvTAI2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pkxggHtMIIB6QKjoIG4MBoDMQ0wHAUxDxcNMCsCDDEcMBowBBRIH9U8U004QYDAKGUZoDb5iFRHZjBPBDFCBEDy73H0NTJMdri5NrQNGGWvMG2euK5mzeC_tVZNW3eoFN43Ibo0jm9iQyEU46mt3tNjZwdk-WKPPjE6ufgeN68dBAMEBGgwZgIxAKKHYM72rJJ4UFse3CDAtdALEa3l4EYfWguQNNAOVPoN2sx7n5dDl_rsZybSJz3Aiu5tTPJOpdCZ5IoJLf1sYSo_6p4PhAB-4zjOJ5aiUvtg9JYPobntVwdu6S_30iAhv3goUEQghYiIugEi2o7jIEmdIaFAIglKyo-S8nhqDaC-QhQT3TA4AnfhbWgkhoSEfgXwM8QHnZ0GQ_YYuBIqCFiuBBAxkQaQkaWQ3fnJ5p01f8zUh7v_jDcJZle-yTTpFBWYooX2Jy37GUJ-DrE_JPsX3TcOVrpheOB5SZt1W7QmGa0wqzKW3QlIrOGJQjhMtsGZVNIO1B0txglh1KYFMgDsEJYFLMH6tqYOMWxyMLqunNmzneY-55rAaGb6E48GNjChKMCkrSL-2-UndP7RuzfLHwn4B9IOk9EWNNhj8f6c2CarrWuG-rVNgs0Va17OueyAGV8mwcyuKG4AFwlxHFO8PBwHl-JaI23ogLCWrbZxIhrSh-Q_tdBpNUizZt8e7T5b7rDZIBeRwwJGD3GnSFfFKNPOjPYJdg
X-RFC3161-Fail: id=dfn; reason=invalid-untrusted
X-RFC3161-Fail: id=belgium; reason=invalid-untrusted
```
<!-- format-doc:end -->
