//! `git time verify`: judge the evidence of commits.
//!
//! One line per commit — `PASS`/`FAIL`, the short oid, the verdict and the
//! verified quorum — and, for a failure, one indented line per TSA answer.
//! Warnings are indented lines too, on a PASS as well, because they are the
//! reason to look twice. `--json` prints the same findings as one document
//! instead.
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

use git_time_core::policy::Policy;
use git_time_core::verify::{CommitEvidence, SignatureStatus, Verdict, commit};
use serde_json::{Value, json};

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
) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let policy = match Policy::load(&repo) {
        Ok(policy) => policy,
        Err(error) => return Exit::config(format!("cannot read the policy: {error}")),
    };
    let oids = match super::targets(&repo, "verify", range.as_deref(), &commits) {
        Ok(oids) => oids,
        Err(exit) => return exit,
    };

    let require = Require {
        sealed: require_sealed,
        signed: require_signed,
    };
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
