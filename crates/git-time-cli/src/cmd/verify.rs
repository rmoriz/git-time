//! `git time verify`: judge the evidence of commits.
//!
//! One line per commit — `PASS`/`FAIL`, the short oid, the verdict and the
//! verified quorum — and, for a failure, one indented line per TSA answer. A
//! trust refusal adds one line naming the command that brings the missing root:
//! `anchor-not-pinned` says to restore it, `no-root-at-gen-time` to fetch the
//! authority's current bundle. Nothing is run for it; the hint is text.
//! Warnings are indented lines too, on a PASS as well, because they are the
//! reason to look twice. `--json` prints the same findings as one document
//! instead, with the roots each block names.
//!
//! Read-only apart from the signature check: `sigcheck::verify` writes the
//! checked commit back into the object database with `hash-object -w`, so a
//! loose object may appear for a signed commit. No ref, index or worktree is
//! touched and no TSA is called.
//!
//! `--require-sealed` and `--require-signed` are **gates, not verdicts**: the
//! verdict stays what the evidence is (`unsealed`, `sealed`, …) and a gate only
//! takes the commit's `pass` away. The human `PASS`/`FAIL`, the exit code and
//! the JSON `pass` are all rendered from that one field, so they cannot
//! disagree. The exit code is `0` only when every commit passes, `1` for any
//! evidence or gate failure, `2` for a usage or configuration problem.
//!
//! `--openssl` instead prints a POSIX `sh` script that re-verifies the same
//! tokens with the `openssl` command, for a reader who does not want to trust
//! this tool's own crypto. The generator runs nothing itself; the same
//! selection (`--range`, the commit arguments, the gates) applies, but the
//! script needs `git`, `openssl` (with `ts`) and `zstd`, and it re-checks the
//! gates only where a missing seal leaves no token to verify — a gate that is
//! about the signature is decided here and merely named in the script.
//!
//! The script carries the material, not a pointer to it: the pre-image, every
//! token and the roots each token was judged against are embedded base64, and
//! the chain is checked at the token's own genTime. A bundle that has since
//! rotated or moved, or a leaf that has since expired, does not make the script
//! fail a seal that was sound when it was made.

use git_time_core::object::PreImage;
use git_time_core::policy::Policy;
use git_time_core::store;
use git_time_core::trust::{AnchorStore, fingerprint};
use git_time_core::verify::{CommitEvidence, Invalid, SignatureStatus, Verdict, commit, gen_time};
use serde_json::{Value, json};

use crate::cmd::anchors::pem_block;
use crate::cmd::{Exit, open, short};

/// What to demand of every commit.
///
/// A gate passes when the evidence does not show what it forbids; it is not a
/// verdict of its own. The names are the stable machine spelling.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Require {
    /// An unsealed commit fails.
    sealed: bool,
    /// An unsigned commit fails.
    signed: bool,
}

impl Require {
    /// The active gates, in evaluation order.
    fn names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.sealed {
            names.push(SEALED_GATE);
        }
        if self.signed {
            names.push(SIGNED_GATE);
        }
        names
    }

    /// The active gates `evidence` does not pass.
    fn failing(&self, evidence: &CommitEvidence) -> Vec<&'static str> {
        let mut failing = Vec::new();
        if self.sealed && evidence.verdict == Verdict::Unsealed {
            failing.push(SEALED_GATE);
        }
        if self.signed && evidence.signature == SignatureStatus::Unsigned {
            failing.push(SIGNED_GATE);
        }
        failing
    }
}

/// The gate name for `--require-sealed`.
const SEALED_GATE: &str = "require-sealed";

/// The gate name for `--require-signed`.
const SIGNED_GATE: &str = "require-signed";

/// Run `git time verify`.
pub fn run(
    directory: Option<std::path::PathBuf>,
    range: Option<String>,
    require_sealed: bool,
    require_signed: bool,
    commits: Vec<String>,
    json_output: bool,
    openssl_output: bool,
) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let policy = match Policy::load(&repo) {
        Ok(policy) => policy,
        Err(error) => return Exit::config(format!("cannot read the policy: {error}")),
    };
    if openssl_output && commits.len() != 1 {
        // The script is handed to an auditor for one seal, so the selection is
        // narrowed here rather than discovered after the script exists: a
        // second commit would make it a different artifact.
        return Exit::usage(
            "git time verify --openssl: name exactly one commit — the script audits one seal; \
             run it once per commit",
        );
    }
    let oids = match super::targets(&repo, "verify", range.as_deref(), &commits) {
        Ok(oids) => oids,
        Err(exit) => return exit,
    };
    if openssl_output && oids.len() != 1 {
        // A single argument can still be a range (`A..B`), which is why the
        // resolved count is checked as well as the argument count.
        return Exit::usage(format!(
            "git time verify --openssl: `{}` names {} commits; the script audits one — use one \
             commit, not a range",
            commits[0],
            oids.len()
        ));
    }

    let require = Require {
        sealed: require_sealed,
        signed: require_signed,
    };
    if openssl_output {
        return print_openssl(&repo, &policy, &oids, &require);
    }
    let required = policy.required;
    let mut failed = false;
    let mut evidence = Vec::with_capacity(oids.len());
    let mut errors = Vec::new();
    for oid in &oids {
        match commit(&repo, policy.anchors(), oid, &policy) {
            Ok(found) => {
                if !passes(&found, &require) {
                    failed = true;
                }
                evidence.push(found);
            }
            Err(error) => {
                failed = true;
                errors.push((oid.clone(), error.to_string()));
            }
        }
    }

    if json_output {
        print_json(&evidence, &errors, &require, required);
    } else {
        // One blank line between records: every record is more than one line,
        // and without the gap the next `PASS` reads as part of the previous
        // commit's answers.
        let mut first = true;
        for found in &evidence {
            if !first {
                println!();
            }
            first = false;
            print_human(found, &require, required);
        }
        for (oid, error) in &errors {
            if !first {
                println!();
            }
            first = false;
            println!("FAIL {} ERROR 0/{required} TSA(s)", short(oid));
            println!("  {error}");
        }
    }

    if failed {
        Exit::with(1, String::new())
    } else {
        Exit::ok()
    }
}

/// Whether `evidence` is a PASS: the verdict passes and every active gate does.
fn passes(evidence: &CommitEvidence, require: &Require) -> bool {
    evidence.verdict.is_pass() && require.failing(evidence).is_empty()
}

/// Print the `--openssl` script: one block per commit, the embedded pre-image
/// and, per token, one self-contained `openssl ts -verify` call.
///
/// Nothing in the script reads the repository. The pre-image, the tokens and the
/// anchor PEM of each token are written into it as base64 at generation time, so
/// the script is a document in its own right: `openssl base64 -d` shows the
/// commit that is being audited. The imprint check still hashes those bytes, so
/// a hand-edited payload is caught even though no history is walked.
///
/// The anchors come from the pin, narrowed to the roots the block names and to
/// the token's own genTime, which is also what `-attime` passes to openssl: a
/// bundle that has since rotated is not the bundle the token met, and wall-clock
/// time would fail a token that outlived its leaf.
///
/// A commit that carries no token is a `SKIP` line, not silence; a gate is
/// named but not re-checked, because checking it would mean re-implementing
/// `verify`. A generation problem (a commit that cannot be read) does not fail
/// the generator: the script says so and exits non-zero when it runs.
fn print_openssl(
    repo: &git_time_core::repo::Repo,
    policy: &Policy,
    oids: &[String],
    require: &Require,
) -> Exit {
    let mut script = String::from(OPENSSL_HEADER);
    script.push_str(OPENSSL_BODY);
    for oid in oids {
        let short = short(oid);
        let evidence = match commit(repo, policy.anchors(), oid, policy) {
            Ok(evidence) => evidence,
            Err(error) => {
                script.push_str(&format!(
                    "\n# ---- commit {short} — unreadable ----\n\
                     commits=$((commits+1))\n\
                     printf 'SKIP {short} unreadable: {}\\n'\n\
                     skipped=$((skipped+1))\n",
                    error.to_string().replace('\'', "'\\''"),
                ));
                continue;
            }
        };
        let gates = require.failing(&evidence);
        let payload = payload(repo, oid, policy.anchors());
        let Some(Payload {
            imprint,
            pre_image,
            tokens,
        }) = payload.filter(|payload| !payload.tokens.is_empty())
        else {
            let mut reason = evidence.verdict.as_str().to_owned();
            if !gates.is_empty() {
                reason.push_str(&format!(" ({})", gates.join(", ")));
            }
            script.push_str(&format!(
                "\n# ---- commit {short} — no token ----\n\
                 commits=$((commits+1))\n\
                 printf 'SKIP {short} {reason}\\n'\n\
                 skipped=$((skipped+1))\n"
            ));
            if !gates.is_empty() {
                script.push_str("gated=$((gated+1))\n");
            }
            continue;
        };

        let imprint = imprint.to_trailer_value();
        let (alg, hex) = imprint.split_once(':').unwrap_or((imprint.as_str(), ""));
        script.push_str(&format!(
            "\n# ---- commit {short} ({oid}) ----\n\
             short='{short}'\n\
             alg='{alg}'\n\
             imprint='{hex}'\n\
             commits=$((commits+1))\n"
        ));
        if !gates.is_empty() {
            // The gate was decided at generation time. The script still
            // verifies every token, and the summary counts the commit as a
            // failure, so a gate cannot quietly become a PASS.
            script.push_str(&format!(
                "# gate not re-checked by this script: {}\n\
                 gated=$((gated+1))\n\
                 printf 'NOTE {short} {}\\n'\n",
                gates.join(", "),
                gates.join(", "),
            ));
        }
        script.push_str(&render_pre(&pre_image));
        script.push_str(OPENSSL_COMMIT);
        for (index, (id, der, ca_file)) in tokens.iter().enumerate() {
            let configured = policy
                .tsas
                .iter()
                .find(|tsa| &tsa.id == id)
                .map(|tsa| quote(&tsa.anchor.to_string_lossy()))
                .unwrap_or_default();
            script.push_str(&format!(
                "\n# token {}: {id}\nid='{}'\nfallback='{configured}'\n",
                index + 1,
                quote(id),
            ));
            quote_heredoc(&mut script, "token", &base64_lines(der));
            // The roots the token was judged against, and nothing else: the
            // bundle on this machine may have rotated since, and a path here
            // says nothing about the bytes the token met.
            quote_heredoc(&mut script, "anchor", &base64_lines(ca_file));
            // Whole seconds only, and only when the token names a genTime: the
            // chain has to be judged at the token's own time.
            match gen_time(der).map(|gen_time| gen_time.as_second()) {
                Some(second) => script.push_str(&format!("attime_value='{second}'\n")),
                None => script.push_str("attime_value=''\n"),
            }
            script.push_str(OPENSSL_TOKEN);
        }
    }

    script.push_str(OPENSSL_SUMMARY);
    print!("{script}");
    Exit::ok()
}

/// What a commit block embeds: the declared imprint, the pre-image and every
/// `(id, token, anchor)` of the commit.
struct Payload {
    imprint: git_time_core::imprint::Digest,
    pre_image: PreText,
    /// Per token: the TSA id, the raw token DER and the `-CAfile` PEM the token
    /// is judged against.
    tokens: Vec<(String, Vec<u8>, Vec<u8>)>,
}

/// How the pre-image is carried.
///
/// Normally it is printed in clear, so a reader sees the commit being judged. A
/// commit message is arbitrary bytes though, and a message that is not UTF-8
/// would not survive being written as text, so it falls back to base64.
enum PreText {
    Clear { text: String, bytes: usize },
    Base64(String),
}

/// Read `oid`'s block into a [`Payload`].
///
/// The token bytes are the decoded DER; the heredoc carries them base64-encoded,
/// because the script needs no zstd and no base64url translation of its own. The
/// same holds for the anchor PEM, which is built from the pinned store — the
/// block's named fingerprints, narrowed at the token's genTime — so the script
/// does not depend on a bundle that may have rotated or moved since.
fn payload(repo: &git_time_core::repo::Repo, oid: &str, anchors: &AnchorStore) -> Option<Payload> {
    let (object, _raw) = repo.read_commit(oid).ok()?;
    let pre: PreImage = object.pre_image(store::PREFIX);
    let block = store::decode(pre.trailer.as_deref()?).ok().flatten()?;
    let pre_image = match String::from_utf8(pre.bytes.clone()) {
        Ok(text) => PreText::Clear {
            text,
            bytes: pre.bytes.len(),
        },
        Err(_) => PreText::Base64(base64_lines(&pre.bytes)),
    };
    Some(Payload {
        imprint: block.imprint,
        pre_image,
        tokens: block
            .tokens
            .iter()
            .map(|token| {
                let named = block.anchors.get(&token.id).map_or(&[][..], Vec::as_slice);
                let anchor = anchor_pem(anchors, &token.id, &token.token, named);
                (token.id.clone(), token.token.clone(), anchor)
            })
            .collect(),
    })
}

/// The PEM to judge `token` against: the pinned roots of `id` that are valid at
/// the token's genTime, narrowed to the `named` fingerprints, plus every pinned
/// intermediate.
///
/// An unpinned id, a token whose genTime cannot be read or a store with no root
/// valid then yields nothing: the script falls back to the paths it knows and
/// says when neither exists. The token's own chain is not repeated here; it
/// already travels inside the token.
fn anchor_pem(anchors: &AnchorStore, id: &str, token: &[u8], named: &[String]) -> Vec<u8> {
    let Some(gen_time) = gen_time(token) else {
        return Vec::new();
    };
    let Some(anchor) = anchors.anchor(id) else {
        return Vec::new();
    };
    let mut pem = Vec::new();
    for root in anchor.roots_at(gen_time) {
        if named.is_empty()
            || named
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(&fingerprint(root.as_bytes())))
        {
            pem.extend(pem_block(root.as_bytes()));
        }
    }
    if pem.is_empty() {
        return pem;
    }
    for intermediate in &anchor.intermediates {
        pem.extend(pem_block(intermediate.as_bytes()));
    }
    pem
}

/// The clear-text form of a pre-image, or its base64 form when it is not text.
///
/// A heredoc always ends in one LF that the commit may not have, so the clear
/// form trims the file back to the recorded byte count afterwards — the bytes
/// hashed are exactly the bytes the commit had.
fn render_pre(pre_image: &PreText) -> String {
    match pre_image {
        PreText::Clear { text, bytes } => {
            let mut out = format!("pre_bytes={bytes}\n");
            heredoc(&mut out, "pre", text, "");
            out.push_str(
                "head -c \"$pre_bytes\" \"$scratch/pre\" > \"$scratch/pre.exact\"\n\
                 mv \"$scratch/pre.exact\" \"$scratch/pre\"\n",
            );
            out
        }
        PreText::Base64(encoded) => {
            let mut out = String::new();
            quote_heredoc(&mut out, "pre", encoded);
            out.push_str(
                "openssl base64 -d -in \"$scratch/pre.b64\" -out \"$scratch/pre\" 2> \"$scratch/err\"\n",
            );
            out
        }
    }
}

/// `body` as base64, 64 characters per line.
fn base64_lines(body: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 1);
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out
}

/// Write `body` as a quoted heredoc into `$scratch/<name><suffix>`.
///
/// A commit message can contain any line, so the delimiter is the bare name
/// unless that line occurs in `body`; then it is numbered until it does not.
fn heredoc(script: &mut String, name: &str, body: &str, suffix: &str) {
    let mut delimiter = name.to_owned();
    let mut counter = 0;
    while body.lines().any(|line| line == delimiter) {
        counter += 1;
        delimiter = format!("{name}_{counter}");
    }
    script.push_str(&format!(
        "cat > \"$scratch/{name}{suffix}\" <<'{delimiter}'\n{body}{delimiter}\n"
    ));
}

/// A base64 heredoc, into `$scratch/<name>.b64`.
fn quote_heredoc(script: &mut String, name: &str, body: &str) {
    heredoc(script, name, body, ".b64");
}

/// Quote `text` for a single-quoted `sh` string, without the outer quotes.
fn quote(text: &str) -> String {
    text.replace('\'', r"'\''")
}

/// The top of the `--openssl` script.
///
/// The gate caveat is here rather than in a commit block because it holds for
/// the whole run.
const OPENSSL_HEADER: &str = r##"#!/bin/sh
# Independent re-verification of one sealed commit with openssl alone.
#
# Generated by `git time verify --openssl`. Nothing here reads the repository:
# the commit is printed below in clear and its tokens are written out
# base64-encoded, because they are binary. Keep the file with the commit it
# names; `openssl base64 -d` decodes a token block.
#
# The pre-image is the commit object without its gpgsig/gpgsig-sha256 headers and
# without the trailing X-RFC3161-* paragraph. Its hash has to equal the imprint
# the block declares before any token is trusted; that is how an edited payload
# is caught. Each token is then checked with `openssl ts -verify` against the
# anchor of its authority, and `openssl ts -verify` must also accept the token's
# `-data`, which is that same pre-image.
#
# Requires: openssl with the `ts` command — no git, no zstd, no other tool.
#
# The base64 blocks are many lines, so `base64 -d` is used without `-A`: the
# LibreSSL one decodes nothing at all when a multi-line input meets that flag.
#
# The anchor is embedded per token: the roots the token was judged against, at
# the token's own genTime, plus the intermediates pinned for its authority. The
# bundle on the generating machine is only the fallback when the generation could
# not resolve one; a bundle that has since rotated or moved is no longer the
# bundle the token met. Each token block also carries its genTime in seconds, and
# it is passed as `-attime` so the chain is judged at that time and not at the
# clock of this run.
#
# The fallback paths are $XDG_CONFIG_HOME/git-time/anchors/<id>.pem (or
# $HOME/.config/...), then the path the generating machine had; if neither
# exists, the token fails and both paths are named. A bundle is passed whole as
# -CAfile, so its intermediates count as trust material too.
#
# An openssl whose `ts -verify` has no `-attime` prints a NOTE up front and the
# chain is then judged at run time.
#
# `--require-sealed` and `--require-signed` were decided when this script was
# generated: a commit that fails one is named in a NOTE and counted, not
# re-checked.
#
# Everything the script writes goes into one mktemp -d directory, removed on
# exit. Only EXIT cleans up: the signals exit with their usual code, so the
# trap runs once and a Ctrl-C stops the script instead of leaving it working
# against a deleted directory.
set -eu

scratch=$(mktemp -d) || exit 1

# `rm -rf` is only as safe as its argument, and a recursion into `/` is slow to
# undo. So the path is checked first: it has to be absolute and below a
# directory, which is what mktemp returns and nothing else here can be. `--`
# keeps a leading dash from being read as an option.
cleanup() {
    case $scratch in
    /*/*) rm -rf -- "$scratch" ;;
    esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
"##;

/// The counters, the `-purpose` probe and the `-attime` probe, before any
/// commit block.
const OPENSSL_BODY: &str = r##"
commits=0
tokens=0
passed=0
failed=0
skipped=0
gated=0

# LibreSSL's `ts verify` is older: no `-purpose`, and its ESS check refuses
# SHA-384/SHA-512 tokens. The EKU is therefore asked for only where the local
# openssl knows the flag, and a version that lacks it says so up front.
purpose=
openssl_version=$(openssl version 2> /dev/null || :)
if ! openssl ts -verify -purpose timestampsign 2>&1 | grep -q '^usage:'; then
    purpose=-purpose
else
    printf 'NOTE %s: no `ts -verify -purpose`; the timestamping EKU is not re-checked and SHA-384/SHA-512 tokens may be refused\n' "$openssl_version"
fi

# The chain is judged at the token's own genTime, never at the wall clock: a
# token outlives the leaf that signed it, and judging at now would fail it for
# being old rather than for being wrong. Same trial, same note: an openssl
# without `-attime` says that it judged at now.
attime=
if ! openssl ts -verify -attime 1 2>&1 | grep -q '^usage:'; then
    attime=-attime
else
    printf 'NOTE %s %s: this openssl has no -attime, validity is judged at run time\n' "$openssl_version" -attime
fi
"##;

/// One token's inline block: decode, resolve its anchor and ask openssl.
///
/// `$short`, `$id`, `$fallback` and `$attime_value` are set by the generated
/// lines above it; the anchor is embedded per token as `anchor.b64`.
const OPENSSL_TOKEN: &str = r##"
tokens=$((tokens+1))
if ! openssl base64 -d -in "$scratch/token.b64" -out "$scratch/token.der" 2> "$scratch/err"; then
    printf 'FAIL %s %s: the token does not decode\n' "$short" "$id"
    failed=$((failed+1))
else
    # The embedded roots are the ones this token was judged against; a bundle on
    # this machine may have rotated since. The paths are only the fallback for a
    # token the generation could not resolve an anchor for.
    anchor=
    if openssl base64 -d -in "$scratch/anchor.b64" -out "$scratch/anchor.pem" 2> "$scratch/err" \
        && [ -s "$scratch/anchor.pem" ]; then
        anchor="$scratch/anchor.pem"
    else
        if [ -n "${XDG_CONFIG_HOME:-}" ]; then
            candidate="$XDG_CONFIG_HOME/git-time/anchors/$id.pem"
        else
            candidate="${HOME:-}/.config/git-time/anchors/$id.pem"
        fi
        if [ -f "$candidate" ]; then
            anchor=$candidate
        elif [ -n "$fallback" ] && [ -f "$fallback" ]; then
            anchor=$fallback
        fi
    fi
    if [ -z "$anchor" ]; then
        printf 'FAIL %s %s: no anchor pinned (looked at %s and %s)\n' "$short" "$id" "$candidate" "$fallback"
        failed=$((failed+1))
    else
        if [ -n "$purpose" ]; then
            set -- -purpose timestampsign
        else
            set --
        fi
        if [ -n "$attime" ] && [ -n "$attime_value" ]; then
            set -- "$@" "$attime" "$attime_value"
        fi
        if openssl ts -verify -token_in -in "$scratch/token.der" -data "$scratch/pre" \
            -CAfile "$anchor" "$@" > "$scratch/out" 2> "$scratch/err"; then
            printf 'PASS %s %s\n' "$short" "$id"
            passed=$((passed+1))
        else
            reason=$(grep -v '^Using configuration' "$scratch/err" | head -n 1 || :)
            printf 'FAIL %s %s: %s\n' "$short" "$id" "${reason:-openssl rejected the token}"
            failed=$((failed+1))
        fi
    fi
fi
"##;

/// The imprint check of one commit block. `$short`, `$alg` and `$imprint` are
/// set by the generated lines above it.
const OPENSSL_COMMIT: &str = r##"
if ! openssl dgst "-$alg" -r < "$scratch/pre" > "$scratch/hash" 2> "$scratch/err"; then
    printf 'FAIL %s imprint: the pre-image cannot be hashed\n' "$short"
    failed=$((failed+1))
else
    read -r got rest < "$scratch/hash" || got=
    if [ "$got" != "$imprint" ]; then
        printf 'FAIL %s imprint: the pre-image does not hash to the declared imprint\n' "$short"
        failed=$((failed+1))
    fi
fi
"##;

/// The summary and the exit status.
const OPENSSL_SUMMARY: &str = r##"
printf '\n%d commit(s), %d token(s): %d passed, %d failed, %d skipped, %d gate(s) not re-checked\n' \
    "$commits" "$tokens" "$passed" "$failed" "$skipped" "$gated"
if [ "$failed" -ne 0 ] || [ "$gated" -ne 0 ]; then
    printf 'FAILED\n'
    exit 1
fi
printf 'OK\n'
"##;

/// Why a failing gate failed, for the human reader.
fn gate_reason(gate: &str) -> &'static str {
    if gate == SIGNED_GATE {
        "the commit is unsigned"
    } else {
        "the commit is not sealed"
    }
}

/// Print one commit's line and, for a failure, its reasons.
fn print_human(evidence: &CommitEvidence, require: &Require, required: usize) {
    let pass = passes(evidence, require);
    let mut marks: Vec<String> = Vec::new();
    if evidence.dropped {
        marks.push("dropped".to_owned());
    }
    marks.extend(require.failing(evidence).into_iter().map(str::to_uppercase));
    let detail = if marks.is_empty() {
        String::new()
    } else {
        format!(" ({})", marks.join(", "))
    };
    println!(
        "{} {} {}{} {}/{} TSA(s)",
        if pass { "PASS" } else { "FAIL" },
        short(&evidence.oid),
        evidence.verdict.as_str().to_uppercase(),
        detail,
        evidence.valid,
        required,
    );
    // Printed on a pass too: "SEALED" says a quorum was reached, not by whom,
    // and an authority is only worth counting if a reader can see which one it
    // was and when it answered. The anchor stays in `--json`; on every pass it
    // is the same long fingerprint and drowns the line.
    for tsa in &evidence.per_tsa {
        let mut line = format!("  {}: {}", tsa.id, tsa.verdict);
        if let Some(gen_time) = tsa.gen_time {
            line.push(' ');
            line.push_str(&gen_time.to_string());
        }
        if let Some(detail) = &tsa.detail {
            line.push_str(": ");
            line.push_str(detail);
        }
        if let Some(serial) = &tsa.serial {
            line.push_str("; serial ");
            line.push_str(serial);
        }
        println!("{line}");
    }
    if evidence.verdict == Verdict::None {
        // The one verdict whose cause is not in the commit: nothing exists on
        // this machine to judge against, and the ids are in the evidence.
        println!(
            "  no TSA was configured when this was sealed; `git time tsa select` picks one, \
             `git time tsa restore` pins the authorities older commits name"
        );
    }
    // A trust refusal is the only failure with a next step, and the two reasons
    // have different ones: a root the block names is fetched back, a root that
    // is simply too old is replaced. Printed once per record, not per token: a
    // commit with three unnamed roots gets the hint once. The hint only names
    // the command; nothing here runs it.
    if evidence
        .per_tsa
        .iter()
        .any(|tsa| tsa.verdict == Invalid::AnchorNotPinned.as_str())
    {
        println!("  `git time tsa restore` pins it");
    }
    if evidence
        .per_tsa
        .iter()
        .any(|tsa| tsa.verdict == Invalid::NoRootAtGenTime.as_str())
    {
        println!("  run `git time anchor fetch` and accept the root that is valid now");
    }
    if !pass {
        for gate in require.failing(evidence) {
            println!("  gate {gate}: {}", gate_reason(gate));
        }
    }
    // Warnings do not fail a commit, but they are the reason it is worth a
    // second look, so they are printed on a PASS too.
    for warning in &evidence.warnings {
        println!("  warning: {warning}");
    }
}

/// Print the whole run as one JSON document.
///
/// An error entry has the same shape as a commit entry — `signature` is `null`,
/// `per_tsa` and `warnings` are empty — so a consumer needs no shape switch.
fn print_json(
    evidence: &[CommitEvidence],
    errors: &[(String, String)],
    require: &Require,
    required: usize,
) {
    let gates = require.names();
    let mut commits: Vec<Value> = evidence
        .iter()
        .map(|found| commit_json(found, require, required, &gates))
        .collect();
    for (oid, error) in errors {
        commits.push(json!({
            "oid": oid,
            "verdict": "error",
            "error": error,
            "imprint": null,
            "object": null,
            "signature": null,
            "per_tsa": [],
            "warnings": [],
            "dropped": false,
            "valid": 0,
            "required": required,
            "gates": gates,
            "pass": false,
        }));
    }
    match serde_json::to_string_pretty(&json!({ "commits": commits })) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("git time: cannot render JSON: {error}"),
    }
}

/// One commit as the JSON object the schema promises.
fn commit_json(
    evidence: &CommitEvidence,
    require: &Require,
    required: usize,
    gates: &[&str],
) -> Value {
    json!({
        "oid": evidence.oid,
        "verdict": evidence.verdict.as_str(),
        "imprint": evidence.imprint.as_ref().map(|imprint| imprint.to_trailer_value()),
        "object": evidence.object_field,
        "signature": evidence.signature.as_str(),
        "per_tsa": evidence
            .per_tsa
            .iter()
            .map(|tsa| json!({
                "id": tsa.id,
                "gen_time": tsa.gen_time.map(|gen_time| gen_time.to_string()),
                "verdict": tsa.verdict,
                "detail": tsa.detail,
                "serial": tsa.serial,
                "anchor": tsa.anchor,
                "anchors": tsa.anchors,
            }))
            .collect::<Vec<_>>(),
        "warnings": evidence.warnings,
        "dropped": evidence.dropped,
        "valid": evidence.valid,
        "required": required,
        "gates": gates,
        "pass": passes(evidence, require),
    })
}
