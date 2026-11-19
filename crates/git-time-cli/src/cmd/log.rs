//! `git time log`: one line of evidence per commit.
//!
//! The line is meant to be skimmed and grepped, so it is fixed-width-ish and
//! positional: short oid, the TSA ids, the genTime of every valid token, and
//! the verdict. A commit without a valid genTime says `-` in that column
//! rather than dropping the field, so the columns never shift.
//!
//! Like `verify` this is read-only and calls no TSA; the evidence it prints is
//! whatever the commits and the pinned anchors already carry.
//!
//! `log` is a record; it exits `0` when it could read everything. Use
//! `git time verify` to gate CI. Because of that split the JSON entries carry
//! no `pass`, `gates` or `required`: a gate is `verify`'s business and a `log`
//! document never advertises a judgement it does not enforce. `verdict`,
//! `per_tsa`, `imprint`, `object`, `signature`, `dropped`, `warnings` and `oid`
//! are reported; `valid` goes with `required` and is dropped too. Exit `1`
//! means a commit could not be read, never that a verdict failed. Commit
//! arguments and a range are resolved exactly like `verify`'s.

use git_time_core::policy::Policy;
use git_time_core::verify::{CommitEvidence, commit};
use serde_json::{Value, json};

use crate::cmd::{Exit, open, short, targets};

/// Run `git time log`.
pub fn run(
    directory: Option<std::path::PathBuf>,
    range: Option<String>,
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
    let oids = match targets(&repo, "log", range.as_deref(), &commits) {
        Ok(oids) => oids,
        Err(exit) => return exit,
    };

    let mut failed = false;
    if json_output {
        // A JSON document is one value, so this path still collects; only the
        // judging is spread over the pool.
        let mut evidence = Vec::with_capacity(oids.len());
        let mut errors = Vec::new();
        super::stream::ordered(
            &oids,
            |oid| commit(&repo, policy.anchors(), oid, &policy).map_err(|error| error.to_string()),
            |index, outcome| match outcome {
                Ok(found) => evidence.push(found),
                Err(error) => {
                    failed = true;
                    errors.push((oids[index].clone(), error));
                }
            },
        );
        print_json(&evidence, &errors);
    } else {
        // Plain output streams: a line appears as soon as its commit is judged,
        // still in walk order.
        super::stream::ordered(
            &oids,
            |oid| commit(&repo, policy.anchors(), oid, &policy).map_err(|error| error.to_string()),
            |index, outcome| match outcome {
                Ok(found) => print_line(&found),
                Err(error) => {
                    failed = true;
                    eprintln!("{}: {error}", short(&oids[index]));
                }
            },
        );
    }

    // Only a commit that could not be read fails the log; a verdict never does.
    if failed {
        Exit::with(1, String::new())
    } else {
        Exit::ok()
    }
}

/// Print the whole run as one JSON document of evidence, no judgement.
///
/// An error entry has the same shape as a commit entry — `signature` is `null`,
/// `per_tsa` and `warnings` are empty — so a consumer needs no shape switch.
fn print_json(evidence: &[CommitEvidence], errors: &[(String, String)]) {
    let mut commits: Vec<Value> = evidence.iter().map(entry_json).collect();
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
        }));
    }
    match serde_json::to_string_pretty(&json!({ "commits": commits })) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("git time: cannot render JSON: {error}"),
    }
}

/// One commit as the JSON object the log promises.
fn entry_json(evidence: &CommitEvidence) -> Value {
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
    })
}

/// Print the one line for `evidence`.
fn print_line(evidence: &CommitEvidence) {
    let ids: Vec<&str> = evidence.per_tsa.iter().map(|tsa| tsa.id.as_str()).collect();
    let times: Vec<String> = evidence
        .per_tsa
        .iter()
        .filter_map(|tsa| tsa.gen_time.map(|gen_time| gen_time.to_string()))
        .collect();
    println!(
        "{} {} {} {}",
        short(&evidence.oid),
        if ids.is_empty() {
            "-".to_owned()
        } else {
            ids.join(",")
        },
        if times.is_empty() {
            "-".to_owned()
        } else {
            times.join(",")
        },
        evidence.verdict.as_str(),
    );
}
