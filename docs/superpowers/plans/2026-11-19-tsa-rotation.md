# TSA Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a timestamp authority rotate its root without breaking old evidence: several pinned roots per id, each valid only inside its own window, an explicit accept step, and a signed block line naming the root a token needs.

**Architecture:** The trust store holds a root list per id instead of one root. Verification candidates are the roots valid at the token's `genTime`, intersected with the fingerprints the block names. Bundles are appended only after a human passes `--accept <id>=<fp>`. Every display that names an authority also names its root's expiry date.

**Tech Stack:** Rust 2021, `x509-cert`, `der`, `webpki` (via `sigstore-tsa`), `clap`.

**Spec:** `docs/superpowers/specs/2026-11-19-tsa-rotation-design.md`

## Global Constraints

- No `Co-Authored-By` trailer. Commit messages state *why*, not a diff summary.
- Docs and release notes go into git and are pushed in the same session.
- CI never touches the network: every new test runs against local fixtures.
- `docs/format.md` is normative, version `1`, additive-only; its appendix must equal `tests/fixtures/format_example.commit` byte for byte.
- The `--openssl` script stays `openssl`-only: no `git`, no `awk`, no `zstd`.
- Verification stays fail-closed: unknown root, unknown line, unknown shape is a refusal.
- Entity names: `git time`, `time.tsa.<id>.*`, `Invalid`, `Verdict`, `TrustError`.
- Every new public item gets a doc comment in the file's voice, and `cargo clippy --all-targets -D warnings` stays clean.

## Review Focus

1. **A bundle whose first certificate is not self-signed** (a mis-fetched intermediate): must be `TrustError::NoRoot`, not a silent anchor.
2. **A root whose `notAfter` equals the token's `genTime` exactly**: candidates are half-open-inclusive at both ends (`notBefore <= genTime <= notAfter`), boundary test required.
3. **A block naming an id that has no token and no `Fail`**: a decode error, not an ignored line.
4. **Duplicate `Anchor:` line for one id, and duplicate fingerprints inside one line**: refused / collapsed, respectively.
5. **A pinned root with the same subject as another (re-key)**: both stay, fingerprint decides.

---

### Task 1: Trust store holds a root list

**Files:**
- Modify: `crates/git-time-core/src/trust.rs`
- Test: `crates/git-time-core/tests/verify_token.rs` (has the CA/token fixtures)

**Interfaces:**
- Consumes: `read_bundle`, `DerCertificate`, `TrustError`.
- Produces:
  - `pub struct Anchor { pub roots: Vec<DerCertificate>, pub intermediates: Vec<DerCertificate> }`
  - `TrustError::NoRoot { id: String, path: PathBuf }`
  - `AnchorStore::append(&mut self, id: &str, path: &Path) -> Result<usize, TrustError>` — adds only certificates whose DER is not already present, returns how many roots were new.
  - `Anchor::roots_at(&self, at: jiff::Timestamp) -> Vec<&DerCertificate>`
  - `is_self_signed(certificate: &x509_cert::Certificate) -> bool` (issuer == subject, DER compared via `to_der`).

- [ ] **Step 1: Write the failing tests**

In `crates/git-time-core/tests/verify_token.rs`:

```rust
#[test]
fn a_bundle_starting_with_an_intermediate_has_no_root() {
    let dir = scratch();
    let (_, ca_pem) = throwaway_tsa_token_signed_with(dir.path(), "critical,timeStamping", "sha256");
    let ca = std::fs::read_to_string(&ca_pem).expect("read CA");
    let leaf = std::fs::read_to_string(dir.path().join("tsa-leaf.pem")).expect("read leaf");
    // The leaf first, the CA second.
    let path = bundle(dir.path(), "reversed.pem", &format!("{leaf}{ca}"));
    let error = AnchorStore::load(&[(ID.to_owned(), path)]).expect_err("no root");
    assert!(matches!(error, git_time_core::trust::TrustError::NoRoot { .. }), "{error:?}");
}

#[test]
fn appending_keeps_both_roots_and_dedupes() {
    // Both throwaway CAs have the same subject CN — this is the re-key case:
    // same name, different key. Both roots have to survive, the fingerprint
    // decides which one verifies.
    // The helper writes fixed file names, so each generation needs its own dir.
    let first_dir = scratch();
    let second_dir = scratch();
    let (_, first) = throwaway_tsa_token_signed_with(first_dir.path(), "critical,timeStamping", "sha256");
    let (_, second) = throwaway_tsa_token_signed_with(second_dir.path(), "critical,timeStamping", "sha256");
    let path = bundle(first_dir.path(), "one.pem", &std::fs::read_to_string(&first).unwrap());
    let mut store = AnchorStore::load(&[(ID.to_owned(), path)]).expect("first root");
    assert_eq!(store.anchor(ID).unwrap().roots.len(), 1);

    let appended = bundle(second_dir.path(), "two.pem", &std::fs::read_to_string(&second).unwrap());
    assert_eq!(store.append(ID, &appended).expect("append"), 1);
    assert_eq!(store.anchor(ID).unwrap().roots.len(), 2);
    assert_eq!(store.append(ID, &appended).expect("again"), 0);
    assert_eq!(store.anchor(ID).unwrap().roots.len(), 2);
}

#[test]
fn roots_at_respects_the_boundaries() {
    // Build a bundle from a throwaway CA, read its notBefore/notAfter, and
    // assert: a time before notBefore or after notAfter yields nothing, and a
    // time equal to either boundary yields the root.
}
```

- [ ] **Step 2: Run them, expect `no method named append` / field `root` errors**

Run: `cargo test --offline -p git-time-core --test verify_token -- a_bundle_starting appending_keeps roots_at`
Expected: FAIL to compile.

- [ ] **Step 3: Change `Anchor`, `insert`, add `append`/`roots_at`/`is_self_signed`**

`insert` becomes: read the bundle, `partition` by `is_self_signed`, error `NoRoot` when the root list is empty (path and id in the error), store it. `append` does the same, then extends the existing `Anchor` skipping DERs already in `roots`/`intermediates`, and returns the count of newly added roots. `roots_at` parses each root with `x509_cert::Certificate::from_der` (`at` as `UnixTime` seconds), keeps `not_before <= at <= not_after`, and returns them in bundle order.

Detail: `TrustError` gains a `NoRoot` variant with the same `Display` style as `Empty`; `read_bundle`'s "first block is the root" contract moves to `insert`/`append`.

- [ ] **Step 4: Run the three tests, then the whole core suite**

Run: `cargo test --offline -p git-time-core`
Expected: PASS. Compile errors in `verify/token.rs` and `doctor` are expected next task; fix only signature breaks (`anchor.root` → `anchor.roots[0]`) so the workspace builds.

- [ ] **Step 5: Commit**

```bash
git add crates/git-time-core/src/trust.rs crates/git-time-core/tests/verify_token.rs
git commit -m "trust: hold every root a bundle carries, not just the first

A rotated authority has to keep its retired root: verification judges
certificates at the token's genTime, so an expired root is still exactly the
right anchor for the evidence it signed. One root per id forced a choice
between old and new evidence."
```

---

### Task 2: The block carries an `Anchor` line

**Files:**
- Modify: `crates/git-time-core/src/store.rs` (`TrailerBlock`, `render`, decode/validation)
- Modify: `crates/git-time-core/src/seal.rs:300`, `crates/git-time-core/src/verify/commit.rs` (struct literals)
- Test: `crates/git-time-core/tests/store.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub anchors: BTreeMap<String, Vec<String>>` on `TrailerBlock`; line form `X-RFC3161-Anchor: id=<id>; sha256=<FP>[,<FP>...]`, rendered after `Object` and before the first `Token`.

- [ ] **Step 1: Write the failing tests** in `crates/git-time-core/tests/store.rs`

```rust
#[test]
fn an_anchor_line_round_trips_in_place() {
    // block with anchors {"a": ["AA:..."]} and one token for "a"; encode, then
    // assert the encoded text has the Anchor line before the Token line, and
    // that decode returns the same map.
}

#[test]
fn an_anchor_line_naming_no_token_or_fail_rejects_the_block() {
    // anchors has "ghost", tokens/failures empty -> decode(&encoded) is Err.
}

#[test]
fn a_duplicate_anchor_line_rejects_the_block() {
    // two Anchor lines for the same id, hand-written -> Err.
}

#[test]
fn anchor_fingerprints_must_be_sha256_hex() {
    // "id=a; sha256=nothex" -> Err; a SHA-1 colon string ("AB:CD:...", 20 octets) -> Err.
}
```

- [ ] **Step 2: Run, expect missing field errors**

Run: `cargo test --offline -p git-time-core --test store`
Expected: FAIL to compile.

- [ ] **Step 3: Implement field, render and decode**

Parse `id=` and `sha256=` with the existing `take`/`require` helpers; split the fingerprint value on `,`; each part must be 32 colon-separated hex octets (accept both cases, normalize to upper case). Reject: unknown key order, missing id, duplicate id, id not in `tokens ∪ failures`, empty part. Render one line per id from the `BTreeMap`, each id once.

Fill the field at every `TrailerBlock { .. }` literal (`seal.rs`, `commit.rs` tests, `store.rs` tests) with `BTreeMap::new()` for now.

- [ ] **Step 4: Run the store suite and the workspace build**

Run: `cargo test --offline -p git-time-core --test store`, then `cargo build --offline`
Expected: PASS / builds.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "store: a block names the anchor its tokens need

The evidence, not the clock, says which root a verifier has to find. That is
what tells a clone whose bundle lacks the root apart from a forged token, and
it keeps a swapped bundle from silently re-pointing history."
```

---

### Task 3: Roots are candidates only inside their own window

**Files:**
- Modify: `crates/git-time-core/src/verify/token.rs` (`Invalid`, `token`, `Parsed::authenticate`, `verify_chain`)
- Modify: `crates/git-time-core/src/verify/commit.rs` (`judge_tokens`, verdict counting)
- Test: `crates/git-time-core/tests/verify_token.rs` (add a stamp parameter to the throwaway helper)

**Interfaces:**
- Consumes: `Anchor::roots_at`, `TrailerBlock.anchors`.
- Produces:
  - `Invalid::NoRootAtGenTime`, `Invalid::AnchorNotPinned`, `as_str()` = `"no-root-at-gen-time"`, `"anchor-not-pinned"`.
  - `pub fn token(record, imprint, gen_time_range, anchors, named: &[String]) -> TokenVerdict` (both invalid variants are `Untrusted`-family: extend the counting).
  - `TsaEvidence.anchors: Vec<String>` (the fingerprints the block named for that id).

- [ ] **Step 1: Write the failing tests**

Helper change first: `throwaway_tsa_token_under` (line 635) gains a `stamp: Option<&str>` argument placed before `intermediate`; when it is `Some`, use that 15-character `YYYYMMDDhhmmssZ` instead of now at the existing rewrite site (line ~796). The three existing wrappers pass `None`. Then a wrapper `fn throwaway_tsa_token_stamped_at(dir: &Path, stamp: &str) -> (Vec<u8>, PathBuf)` calls it with `Some(stamp)`. The CA is minted with `-days 2`, so a 2050 stamp is outside its window.

The record shape is the one the SHA-1 test uses (line 168): `policy: None`, `nonce: NONCE.to_vec()`, `alg: Alg::Sha256`, the returned token bytes.

```rust
#[test]
fn a_token_signed_before_the_pinned_root_was_valid_is_refused() {
    let dir = scratch();
    // 2050: long after the two-day throwaway CA has expired.
    let (token, ca_pem) = throwaway_tsa_token_stamped_at(dir.path(), "20500101000000Z");
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord {
        id: ID.to_owned(),
        alg: Alg::Sha256,
        policy: None,
        nonce: NONCE.to_vec(),
        token,
    };
    let named = Vec::new();
    assert_eq!(
        verify::token(&record, &imprint(), wide_range(), &anchors, &named),
        TokenVerdict::Invalid(Invalid::NoRootAtGenTime)
    );
}

#[test]
fn a_named_root_that_is_not_pinned_is_its_own_reason() {
    let dir = scratch();
    let anchors = anchors(dir.path());
    let named = vec!["00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33".to_owned()];
    assert_eq!(
        verify::token(&record(), &imprint(), wide_range(), &anchors, &named),
        TokenVerdict::Invalid(Invalid::AnchorNotPinned)
    );
}

#[test]
fn a_named_root_that_matches_still_verifies() {
    let dir = scratch();
    let (token, ca_pem) =
        throwaway_tsa_token_signed_with(dir.path(), "critical,timeStamping", "sha256");
    let der = sigstore_types::DerCertificate::from_pem(&std::fs::read_to_string(&ca_pem).expect("read CA"))
        .expect("CA is PEM");
    let named = vec![git_time_core::trust::fingerprint(der.as_bytes())];
    let anchors = AnchorStore::load(&[(ID.to_owned(), ca_pem)]).expect("throwaway CA loads");
    let record = TokenRecord { id: ID.to_owned(), alg: Alg::Sha256, policy: None, nonce: NONCE.to_vec(), token };
    assert!(verify::token(&record, &imprint(), wide_range(), &anchors, &named).is_valid());
}
```

- [ ] **Step 2: Run, expect failures**

Run: `cargo test --offline -p git-time-core --test verify_token -- a_token_signed_before a_named_root_that`
Expected: FAIL.

- [ ] **Step 3: Implement the candidate filter**

In `token()`: after the imprint/policy checks, compute `candidates = anchor.roots_at(parsed.tst.gen_time)`; if `candidates.is_empty()` return `NoRootAtGenTime`. Then, when `!named.is_empty()`, compare `crate::trust::fingerprint(candidate.as_bytes())` against `named` (case-insensitive) and keep matches; if none, return `AnchorNotPinned`.

`authenticate` verifies the CMS signature once, then tries `verify_chain` for each candidate root in order and returns `Ok(())` on the first success; all failing is `Untrusted`. `verify_chain(root, authority_parts, gen_time)` takes the root instead of reading `anchor.root`.

In `commit.rs::judge_tokens`: pass `block.anchors.get(&record.id).map(Vec::as_slice).unwrap_or_default()`, set `TsaEvidence.anchors` from the same slice, and count `Invalid::AnchorNotPinned` and `Invalid::NoRootAtGenTime` as `untrusted` for the verdict. Extend each invalid's detail: unpinned-named → ``the block names anchor <fp>, which is not pinned; `git time tsa restore` fetches it``; no-window → `no pinned root for `<id>` is valid at the token's genTime`.

- [ ] **Step 4: Run the core suite**

Run: `cargo test --offline -p git-time-core`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "verify: a root only vouches inside its own validity window

Before, any pinned root could chain any token, so after a rotation the retired
root blessed new timestamps and the new one blessed old ones. The window is a
property of the root, so it is checked before the chain is even attempted."
```

---

### Task 4: The seal writes the line

**Files:**
- Modify: `crates/git-time-core/src/seal.rs:254-310`
- Test: `crates/git-time-core/tests/seal.rs`

**Interfaces:**
- Consumes: `TokenVerdict::Valid { gen_time, .. }`, `Anchor::roots_at`, `TrailerBlock.anchors`.
- Produces: nothing public.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_sealed_block_names_the_roots_valid_at_the_tokens_time() {
    // stub TSA + anchor store with the stub root; seal a commit; decode the
    // block and assert `anchors["stub"]` holds that root's fingerprint.
}
```

- [ ] **Step 2: Run, expect an empty map**

Run: `cargo test --offline -p git-time-core --test seal -- names_the_roots`
Expected: FAIL (`anchors["stub"]` missing).

- [ ] **Step 3: Collect and write**

While accepting a token, on `TokenVerdict::Valid { gen_time, .. }` insert into a `BTreeMap<String, BTreeSet<String>>` every `trust::fingerprint(root.as_bytes())` from `anchors.anchor(&record.id)?.roots_at(gen_time)`. Move it into the block as `BTreeMap<String, Vec<String>>` (set order). An id whose only answer failed gets no line.

- [ ] **Step 4: Run the seal suite**

Run: `cargo test --offline -p git-time-core --test seal`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "seal: write down the root each token was checked against

The roots are taken at the answer's genTime, not at the committer time. A
backfilled old commit is stamped now: naming the root of the committer date
would name the dead one and make the fresh commit unverifiable on sight."
```

---

### Task 5: Verify reports the two new reasons

**Files:**
- Modify: `crates/git-time-cli/src/cmd/verify.rs` (hints in `print_human`, `--json` fields)
- Modify: `crates/git-time-cli/src/cmd/log.rs` if it prints details
- Test: `crates/git-time-cli/tests/verify_cli.rs`

**Interfaces:**
- Consumes: `TsaEvidence.anchors`, `Invalid::as_str`.
- Produces: JSON `per_tsa[].anchors: [..]`; hint lines for both reasons.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_block_naming_an_unpinned_root_is_untrusted_with_a_restore_hint() {
    // sealed repo, empty XDG anchors; expect exit 1, "UNTRUSTED 0/1", and one
    // detail line containing "tsa restore" and the fingerprint.
}

#[test]
fn json_carries_the_anchors_the_block_names() {
    // same repo; per_tsa[0]["anchors"] is the named fingerprint list.
}
```

- [ ] **Step 2: Run, expect failures**

Run: `cargo test --offline -p git-time-cli --test verify_cli -- a_block_naming_an_unpinned`
Expected: FAIL.

- [ ] **Step 3: Implement**

`print_human`: for `anchor-not-pinned`, print `  <id>: <detail>` (detail already names the fingerprint) plus a second line `` `git time tsa restore` pins it``. For `no-root-at-gen-time`, print the detail and `  run `git time anchor fetch` and accept the root that is valid now`. In the JSON evidence, add `"anchors": [..]` from `TsaEvidence.anchors`.

- [ ] **Step 4: Run the verify suite**

Run: `cargo test --offline -p git-time-cli --test verify_cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "verify: say which root is missing, and how to bring it

'UNTRUSTED' alone used to mean three different things: nothing pinned, a
forgery, or a rotated authority. The block now names its root, so the answer
can be exact and name the command that fixes it."
```

---

### Task 6: A preset knows every fingerprint it published

**Files:**
- Modify: `crates/git-time-core/src/presets.rs` (type, all 22 entries, module docs)
- Modify: `crates/git-time-cli/src/cmd/install.rs` (`digest_for`, `install_anchor`, `pin_preset`), `tsa.rs::preset_list`/`picker.rs::row`
- Test: `crates/git-time-cli/tests/install.rs`, `crates/git-time-core/src/presets.rs` doc test

**Interfaces:**
- Consumes: existing preset table.
- Produces: `pub fingerprints: &'static [&'static str]`; `pub fn matching_digest(expected: &str, der: &[u8]) -> String` in `install.rs` (length from the expectation, as `digest_for` does today), `pub fn fingerprint_matches(fingerprints: &[&str], der: &[u8]) -> Option<&'static str>` returning the value that matched.

- [ ] **Step 1: Write the failing test** in `install.rs`

```rust
#[test]
fn any_published_fingerprint_of_a_preset_accepts_the_root() {
    // fixture authority with two fingerprints (current + retired); fetched root
    // equals the retired one -> accepted and the line names that value.
}
```

- [ ] **Step 2: Run, expect `fingerprints` not found**

Run: `cargo test --offline -p git-time-cli --test install -- any_published`
Expected: FAIL.

- [ ] **Step 3: Implement**

Replace `fingerprint: Option<&str>` with `fingerprints: &'static [&'static str]` (`&[]` for TOFU); keep every current value as the last slice element. Every call site that used `preset.fingerprint` uses `fingerprint_matches(...)`; the TOFU path is now `fingerprints.is_empty()`. `digest_for` stays for single-value comparisons inside `matching_digest`.

- [ ] **Step 4: Run install, registry and preset tests**

Run: `cargo test --offline -p git-time-cli --test install --test registry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "presets: keep a list of published roots, not one

A rotation gives an authority two legitimate values in the wild. One slot meant
either a release or a spurious mismatch warning for every fetch afterwards."
```

---

### Task 7: Accepting a rotation is an explicit step

**Files:**
- Modify: `crates/git-time-cli/src/cmd/anchor.rs` (`fetch`, `Command::Fetch`)
- Modify: `crates/git-time-cli/src/cmd/install.rs` (`run`, `pin`, `install_anchor`), `crates/git-time-cli/src/main.rs:147-151`
- Modify: `crates/git-time-cli/src/cmd/tsa.rs` (`Restore`, `restore`, `pin_preset`)
- Create: `crates/git-time-cli/src/cmd/accept.rs`
- Modify: `crates/git-time-cli/src/cmd/mod.rs` (add `pub mod accept;`)
- Test: `crates/git-time-cli/tests/install.rs`, `crates/git-time-cli/tests/registry.rs`

**Interfaces:**
- Consumes: `AnchorStore::append`, `fingerprint_matches`, `named_tsas`.
- Produces:
  - `accept::parse(value: &str) -> Result<(String, String), String>` — `id=fp`; a bare value is returned as `(String::new(), fp)`.
  - `accept::one_or_id(values: &[String], pinned_ids: &[&str]) -> Result<BTreeMap<String, String>, String>` — resolves bare values, errors when a bare value meets more than one id.
  - `anchor fetch --accept <FINGERPRINT>`; `install --accept <ID=FINGERPRINT>` (repeatable); `tsa restore --accept <ID=FINGERPRINT>` (repeatable).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn fetch_refuses_a_changed_root_and_appends_it_on_accept() { /* anchor fetch: first pin, then a second CA, refuse, then --accept <fp> appends */ }

#[test]
fn accept_with_a_wrong_fingerprint_changes_nothing() { /* bundle bytes identical afterwards */ }

#[test]
fn a_bare_accept_on_a_two_authority_install_is_refused() { /* exit 2, names both ids */ }

#[test]
fn restore_appends_a_named_root_after_accept() { /* block names the new root; restore without accept reports it, with id=fp pins it */ }
```

- [ ] **Step 2: Run, expect unknown-argument errors**

Run: `cargo test --offline -p git-time-cli --test install -- fetch_refuses accept_with_a_wrong a_bare_accept`
Expected: FAIL.

- [ ] **Step 3: Implement the flow**

`anchor fetch`: fetch, parse; compare the root against (a) the preset's `fingerprints`, (b) the roots already in the target bundle; equal to a pinned root → overwrite the file with the fetch and print `anchor <id>: chain material updated`. New root and no pinned bundle → TOFU (print the fingerprint). New root and a pinned bundle → refuse, print expected (published or pinned, whichever applied) and found, exit 1; with `--accept <fp>`, require `fp == found`, `append`, print `anchor <id>: <n> root(s) appended, <m> now pinned`.

`install::pin`: same comparison through `fingerprint_matches` and the pinned bundle; on mismatch: refuse unless `--accept id=fp` matches the fetched root, then append. `main.rs` collects `--accept` into `Vec<String>` and passes it down.

`tsa restore`: for a named id, if the fetched root equals a named fingerprint → append/pin; if not, report both values and, unless `--accept id=fp` matches, leave it unpinned. Print the commit's signature state next to each restored commit (`sigcheck` is already at hand in `commit.rs`), so a reader sees which blocks were unverified when they chose.

Where nothing is pinned, `--accept` behaves as a plain pin. Never write on a mismatch a human did not confirm.

- [ ] **Step 4: Run both suites**

Run: `cargo test --offline -p git-time-cli --test install`, `cargo test --offline -p git-time-cli --test registry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "anchor: accept a rotated root only when a human says so

A fetch used to rename whatever arrived over the bundle. Since a bundle now
carries history, a silent replacement would change what every old commit
verifies against. The fetched value has to match the published one, or be
accepted explicitly by fingerprint."
```

---

### Task 8: The lock records every root

**Files:**
- Modify: `crates/git-time-cli/src/cmd/anchor.rs:230-300` (`pin`, `check`)
- Test: `crates/git-time-cli/tests/registry.rs`

**Interfaces:**
- Consumes: the bundle's roots.
- Produces: lock lines `<id> <fingerprint>` per root; `check` prints `added <id> <fp>` / `removed <id> <fp>`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn check_reports_an_added_root_after_an_accept() {
    // pin, append a second root via the append helper, expect "added <id> <fp>" and exit 1
}
```

- [ ] **Step 2: Run, expect `mismatch` instead of `added`**

Run: `cargo test --offline -p git-time-cli --test registry -- added_root`
Expected: FAIL.

- [ ] **Step 3: Implement**

`pin` writes one line per root (sorted by id, then fingerprint). `check` builds `BTreeSet<(id, fp)>` on both sides, reports the set difference in both directions, and keeps the existing `missing`/`unparseable` messages.

- [ ] **Step 4: Run the suite**

Run: `cargo test --offline -p git-time-cli --test registry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "anchor: a rotation has to show up as two lines in the lock

With one line per authority a rotation rewrote the reviewed value in place, so
the diff looked like an update instead of a replaced root. Added and removed
are named separately now."
```

---

### Task 9: Doctor sees an overdue rotation

**Files:**
- Modify: `crates/git-time-cli/src/cmd/doctor.rs:200-230`
- Test: `crates/git-time-cli/tests/install.rs`

**Interfaces:**
- Consumes: the bundle's roots, HEAD's block.
- Produces: two problems; the anchor report JSON gains `roots` (count) and `expired` (count).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn doctor_problems_no_root_valid_now() { /* stale-only bundle -> exit 1, line names `--accept` */ }

#[test]
fn doctor_problems_a_head_anchoring_an_unpinned_root() { /* HEAD's line names an absent root -> exit 1 */ }
```

- [ ] **Step 2: Run, expect no such line**

Run: `cargo test --offline -p git-time-cli --test install -- doctor_problems`
Expected: FAIL.

- [ ] **Step 3: Implement**

Per configured id: count roots and how many are valid at now (`roots_at(now)`); when there are roots and none is valid, `problem`. Read HEAD's block (`store::decode` on its trailer, ignore errors) and for each id/fingerprint not pinned, `problem` with the id and fingerprint. Informational line otherwise: `anchor <id>: <n> root(s), latest notAfter <date>`.

- [ ] **Step 4: Run the install suite**

Run: `cargo test --offline -p git-time-cli --test install`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "doctor: name a root set that can no longer verify anything

An authority with only expired roots still answers, and every new seal then
records evidence that cannot be checked. That is exactly the week a rotation
should be noticed in."
```

---

### Task 10: The audit script gets the right root and the right time

**Files:**
- Modify: `crates/git-time-cli/src/cmd/verify.rs` (`Payload`, `payload`, the `OPENSSL_HEADER` probe, `OPENSSL_TOKEN`)
- Test: `crates/git-time-cli/tests/verify_cli.rs`

**Interfaces:**
- Consumes: the evidence's named fingerprints, `Anchor::roots_at`, `Anchor.intermediates`.
- Produces: a per-token `anchor.b64` heredoc holding PEM of the named, time-valid roots plus every pinned intermediate, decoded to `$scratch/anchor.pem`; `-attime <genTime as seconds>` emitted only when `ts -verify` supports it, with a `NOTE` otherwise.

Today the token block resolves `$candidate`/`$fallback` (a path on the generating machine) and passes that as `-CAfile`. **The embedded file becomes the source, the paths stay as fallback:** the script is a self-contained audit and must not depend on a bundle that may have rotated since.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn the_script_embeds_only_the_root_the_token_names() {
    // two roots pinned for one id, block names the first: the anchor.b64 heredoc
    // decodes to a PEM that holds that root and not the other.
}

#[test]
fn the_script_passes_attime_and_notes_when_unsupported() {
    // generated script has `-attime <genTime seconds>`; the probe branch carries
    // a NOTE naming the omission when `ts -verify` rejects the flag.
}
```

- [ ] **Step 2: Run, expect the second root to be embedded too**

Run: `cargo test --offline -p git-time-cli --test verify_cli -- embeds_only_the_root passes_attime`
Expected: FAIL.

- [ ] **Step 3: Implement**

`Payload.tokens` becomes `Vec<(String, String, Vec<u8>)>` — id, token DER, CAfile PEM bytes. Build the CAfile in `payload()`: take `store.anchor(id)`, keep `roots_at(gen_time)` narrowed to the block's named fingerprints for that id (all valid roots when nothing is named), PEM-encode them, then append every pinned intermediate and every intermediate the token carried (the token's own chain already reaches the verifier through the token; the pinned ones are the missing half). Emit it as `quote_heredoc(..., "anchor", pem)` next to the token heredoc, decode to `$scratch/anchor.pem` and pass that as `-CAfile`; keep `$candidate`/`$fallback` as the fallback when the decode fails.

`-attime`: the probe goes next to the existing `purpose` probe in `OPENSSL_HEADER` (`openssl ts -verify -attime 1 -token_in … ` on a throwaway token, or simply `openssl version`-independent flag trial) and sets `attime=` to `-attime` or empty; when empty, `printf 'NOTE %s %s: this openssl has no -attime, validity is judged at run time\n'` and omit the flag. The flag value is the token's `genTime` in whole seconds, baked at generation time.

- [ ] **Step 4: Run the suite and one live-looking run**

Run: `cargo test --offline -p git-time-cli --test verify_cli`, then `./target/debug/git-time verify --openssl HEAD | sh`
Expected: PASS, `OK`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "verify --openssl: judge the chain at the token's own time

The script ran at wall-clock time, so a valid 2026 token fails once its leaf
expires. -attime is what openssl already has for this; where the local ts lacks
it, the NOTE says the run judged at now."
```

---

### Task 11: Show expiry dates where authorities are chosen

**Files:**
- Modify: `crates/git-time-cli/src/cmd/anchors.rs` (helper), `tsa.rs` (`list`, `preset_list`), `picker.rs` (`row`, `TRUST_WIDTH`), `doctor.rs`, `anchor.rs::list`
- Test: `crates/git-time-cli/tests/registry.rs`, `crates/git-time-cli/tests/install.rs`

**Interfaces:**
- Produces: `anchors::not_after(certificate: &x509_cert::Certificate) -> String` (`YYYY-MM-DD`), `anchors::expiry_label(not_after: &str, now: jiff::Timestamp) -> &'static str` (`""`, `"expired"`, `"(expires soon)"` with a 90-day horizon).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn tsa_list_marks_an_expired_root() { /* fixture CA with -days 1 and a rewound clock via attime helper -> "expired" */ }

#[test]
fn preset_list_says_not_pinned_without_an_anchor() { /* empty XDG -> "not pinned", no network */ }

#[test]
fn json_carries_not_after() { /* tsa list --json has the date-only field */ }
```

- [ ] **Step 2: Run, expect missing column**

Run: `cargo test --offline -p git-time-cli --test registry -- expired_root`
Expected: FAIL.

- [ ] **Step 3: Implement**

`tsa list`: one indented line per root `  root <fp> <YYYY-MM-DD><verdict>`; the authority line keeps its first root's date. `preset list`: date when pinned, else `not pinned`. `picker::row`: `pin <date>` / `tofu` in the trust column, `EXPIRED` when no root is valid now. `anchor list`: date-only, then `expired` marker. `doctor`: date next to the fingerprint.

- [ ] **Step 4: Run both suites**

Run: `cargo test --offline -p git-time-cli --test registry`, `cargo test --offline -p git-time-cli --test install`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "tsa: show when a root expires, where the choice is made

A picker that hides the date hides the one fact that explains a failing
authority a week later. Unpinned presets say so instead of guessing: there is
no certificate here to read."
```

---

### Task 12: Make the format document and fixture match

**Files:**
- Modify: `docs/format.md` (§2 grammar, §3 order, §8 verifier steps, reason table, appendix), `crates/git-time-core/tests/format_doc.rs`, `crates/git-time-core/tests/fixtures/format_example.commit`
- Test: `crates/git-time-core/tests/format_doc.rs`

**Interfaces:**
- Consumes: the codec from Task 2.

- [ ] **Step 1: Add the failing document assertions**

```rust
#[test]
fn the_anchor_line_is_documented_before_the_tokens() { /* §2 has the grammar, §3 the position before `Token` */ }

#[test]
fn the_reason_table_lists_both_root_refusals() { /* no-root-at-gen-time, anchor-not-pinned */ }
```

- [ ] **Step 2: Run, expect failures**

Run: `cargo test --offline -p git-time-core --test format_doc`
Expected: FAIL.

- [ ] **Step 3: Write it**

Grammar (`Anchor: id=<TOKEN>; sha256=<FP>[,...]`, both required, id must occur in a `Token` or `Fail`), the position in §3 before `Token`, the optionality rule (absent → no filter; unknown to older readers → ignored, §9), the candidate rule (`notBefore <= genTime <= notAfter`, intersection with named), the two new values in the §3 `invalid-<kind>` list, and the appendix/fixture byte-for-byte with one `Anchor` line added.

- [ ] **Step 4: Run the format suite**

Run: `cargo test --offline -p git-time-core --test format_doc`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "format: specify the anchor line and the two root refusals

Without it a third-party reader cannot tell a missing root from a forgery, and
the worked example would stop being a valid block at the first rotation."
```

---

### Task 13: End-to-end rotation, docs and release notes

**Files:**
- Modify: `crates/git-time-cli/tests/verify_cli.rs` (full scenario), `docs/manual.md`, `docs/git-time.1`, `README.md`, `docs/STATUS.md`
- Release notes: the workflow publishes with `generate_release_notes: true`, so the commit bodies of these tasks *are* the notes; at tag time the body is edited to lead with the rotation paragraph (`--accept`, the lock diff, what an old reader sees).
- Test: the scenario test below

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing scenario**

```rust
#[test]
fn history_survives_a_rotation_end_to_end() {
    // seal with root A (fixture), record oid; swap the TSA to root B, attempt a
    // fetch -> refused; `--accept` -> appended; old oid still verifies; a new
    // commit verifies; block for the new commit names B, old block names A.
}
```

- [ ] **Step 2: Run, expect the refusal to be the current behaviour without accept**

Run: `cargo test --offline -p git-time-cli --test verify_cli -- survives_a_rotation`
Expected: FAIL at the accept step.

- [ ] **Step 3: Document it**

Manual section on rotation (`--accept` forms, the lock diff, `doctor`'s lines, what an old reader sees), man page equivalents (`mandoc -Tlint` clean), README paragraph, STATUS table rows, release note.

- [ ] **Step 4: Verify everything**

Run: `cargo fmt --all && cargo clippy --offline --all-targets -q -- -D warnings && cargo test --offline && mandoc -Tlint docs/git-time.1`
Expected: clean, 0 failed, lint 0.

- [ ] **Step 5: Commit and push**

```bash
git add -A
git commit -m "test: prove a rotation keeps the history it left behind

The unit cases pin each half; this one runs the whole thing on one repository,
because the failure mode worth fearing is the pair of them being individually
right and jointly wrong."
git push origin HEAD
```

---

## Self-Review

- Spec coverage: bundle layout → T1; verification/window/named filter → T3; block line → T2, T4; accept → T7; lock → T8; doctor → T9; `--openssl` → T10; expiry display → T11; format → T12; presets → T6; end-to-end → T13.
- The two review-focus items not yet referenced are pinned by T1 (`NoRoot`) and T2 (`ghost` id, duplicates); the re-key case is T1's dedupe-by-DER plus T3's fingerprint intersection.
- Types named once: `roots`, `append`, `roots_at`, `IsRoot`… (`is_self_signed`), `named`, `anchors`, `fingerprints`, `accept::parse`, `accept::one_or_id`, `not_after`, `expiry_label`. Later tasks use those names only.
