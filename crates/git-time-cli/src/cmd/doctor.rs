//! `git time doctor`: say what is wired, what is pinned, and what is wrong.
//!
//! One line per fact, on stdout, so the output can be read and grepped: where the
//! binary is, which hooks directory git uses, the state of every hook this tool
//! owns (`ours`, `chained`, `foreign`, `absent`, `not-executable`, `dangling`),
//! whether `time.gate` agrees with each installed `pre-*` hook, how many
//! authorities are configured, and each anchor's path, SHA-256 fingerprint and
//! first certificate's expiry.
//!
//! These things make it exit `1`: no authority at all, an anchor that is missing,
//! unreadable or not a parseable certificate bundle, an anchor bundle with no
//! root valid now, a HEAD block naming a root this machine has not pinned, a gate
//! that disagrees with the hooks name by name, an unknown `time.gate` value, a
//! shim or preserve that lost its execute bit, and a dangling symlink at a hook
//! name. A shim that
//! cannot reach the binary is one too. Everything else is reported without
//! failing — a foreign hook is normal, an absent hook is what an uninstalled
//! repository looks like. `--json` prints the report as one object instead of the
//! lines.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use der::Decode as _;
use git_time_core::repo::Repo;
use git_time_core::store;
use git_time_core::trust::{self, AnchorStore};
use serde_json::{Map, Value, json};

use crate::cmd::anchor::first_certificate;
use crate::cmd::{Exit, anchors, hooks, open};

/// Run `git time doctor`.
pub fn run(directory: Option<std::path::PathBuf>, json_output: bool) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    match report(&repo, json_output) {
        Ok(code) => Exit::with(code, String::new()),
        Err(exit) => exit,
    }
}

/// The report being assembled.
struct Report {
    /// One line per fact, in the order doctor means them.
    lines: Vec<String>,
    /// The problems, each also repeated as a `problem:` line.
    problems: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            problems: Vec::new(),
        }
    }

    fn say(&mut self, line: String) {
        self.lines.push(line);
    }

    fn problem(&mut self, problem: String) {
        self.lines.push(format!("problem: {problem}"));
        self.problems.push(problem);
    }
}

/// Build and print the report; the code is `1` when there is a problem.
fn report(repo: &Repo, json_output: bool) -> Result<u8, Exit> {
    let mut report = Report::new();

    let binary = binary_on_path();
    match &binary {
        Some(path) => report.say(format!("binary: {}", path.display())),
        None => {
            report.say("binary: missing (git-time is not on PATH)".to_owned());
            report.problem("git-time is not on PATH, so the shims cannot seal".to_owned());
        }
    }

    let dir = hooks::hooks_dir(repo)?;
    report.say(format!("hooks dir: {}", dir.display()));
    let mut states = Vec::with_capacity(hooks::ALL_HOOKS.len());
    for name in hooks::ALL_HOOKS {
        let state = if dir.exists() {
            hooks::state(&dir, name)
        } else {
            hooks::State::Absent
        };
        report.say(format!("hook {name}: {}", state.as_str()));
        match state {
            hooks::State::NotExecutable => {
                let target = hooks::not_executable(&dir, name).unwrap_or_else(|| dir.join(name));
                report.problem(format!(
                    "the {name} hook is not executable (run: chmod +x {})",
                    target.display()
                ));
            }
            hooks::State::Dangling => report.problem(format!(
                "the {name} hook is a symlink whose target is gone (run: git time install)"
            )),
            _ => {}
        }
        states.push((name, state));
    }

    // The state doctor found at `name`.
    let state_of = |name: &str| {
        states
            .iter()
            .find(|(seen, _)| *seen == name)
            .map_or(hooks::State::Absent, |(_, state)| *state)
    };

    let gate = repo
        .config_non_empty("time.gate")
        .map_err(Exit::config)?
        .unwrap_or_else(|| "post-commit".to_owned());
    let gate_kind = match gate.to_ascii_lowercase().as_str() {
        "pre-commit" => Some(true),
        "post-commit" => Some(false),
        _ => None,
    };
    let mut findings = Vec::new();
    match gate_kind {
        Some(true) => {
            for name in hooks::PRE_HOOKS {
                let state = state_of(name);
                if !state.wired() {
                    findings.push(format!(
                        "hook {name} is {} but time.gate is `{gate}` (run: git time install)",
                        state.as_str()
                    ));
                }
            }
        }
        Some(false) => {
            for name in hooks::PRE_HOOKS {
                let state = state_of(name);
                if state.wired() {
                    findings.push(format!(
                        "hook {name} is installed but time.gate is `{gate}` \
                         (run: git time uninstall, or set time.gate = pre-commit)"
                    ));
                }
            }
        }
        None => findings.push(format!(
            "unknown time.gate value `{gate}` (use `post-commit` or `pre-commit`; \
             run: git time install)"
        )),
    }
    let gate_matches = findings.is_empty();
    report.say(format!(
        "gate: {gate} ({})",
        if gate_matches {
            "hooks match"
        } else {
            "mismatch"
        }
    ));
    for finding in findings {
        report.problem(format!("gate mismatch: {finding}"));
    }

    let ids = anchors::tsa_ids(repo)?;
    report.say(format!("tsa: {} configured", ids.len()));
    if ids.is_empty() {
        report.problem("no TSA configured (run: git time tsa select)".to_owned());
    }

    let configured = anchors::configured(repo)?;
    let mut anchor_reports = Vec::with_capacity(ids.len());
    // The roots each id may still vouch with, by fingerprint. A bundle that
    // fails to load pins nothing, so a block naming it is reported below.
    let mut pinned: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // One instant for the whole run: every bundle is judged as of one moment.
    let now = jiff::Timestamp::now();
    for id in &ids {
        match configured.iter().find(|anchor| &anchor.id == id) {
            None => {
                report.say(format!(
                    "anchor {id}: missing (no `time.tsa.{id}.anchor` configured)"
                ));
                report.problem(format!("missing anchor for `{id}`: not configured"));
                anchor_reports.push(json!({
                    "id": id,
                    "path": Value::Null,
                    "fingerprint": Value::Null,
                    "missing": true,
                    "unparseable": false,
                    "roots": 0,
                    "expired": 0,
                }));
            }
            Some(anchor) => match std::fs::read(&anchor.path) {
                Err(error) => {
                    report.say(format!(
                        "anchor {id}: {} missing ({error})",
                        anchor.path.display()
                    ));
                    report.problem(format!(
                        "missing anchor for `{id}`: {} ({error})",
                        anchor.path.display()
                    ));
                    anchor_reports.push(json!({
                        "id": id,
                        "path": anchor.path,
                        "fingerprint": Value::Null,
                        "missing": true,
                        "unparseable": false,
                        "roots": 0,
                        "expired": 0,
                    }));
                }
                Ok(bytes) => {
                    // The same load the policy does, so a bundle that is only
                    // PEM-shaped is a problem here rather than `Untrusted` at
                    // the next commit.
                    let parse = AnchorStore::load(&[(id.clone(), anchor.path.clone())]);
                    let fingerprint = anchors::fingerprint(&bytes);
                    let expiry = first_certificate(&bytes)
                        .and_then(|der| x509_cert::Certificate::from_der(&der).ok())
                        .map(|certificate| {
                            format!(
                                " {}",
                                anchors::expiry_text(&anchors::not_after(&certificate), now)
                            )
                        })
                        .unwrap_or_default();
                    report.say(format!(
                        "anchor {id}: {} sha256 {fingerprint}{expiry}",
                        anchor.path.display()
                    ));
                    let mut roots = 0;
                    let mut expired = 0;
                    if let Err(ref error) = parse {
                        report.problem(format!(
                            "unparseable anchor for `{id}` at {}: {error}",
                            anchor.path.display()
                        ));
                    } else if let Ok(store) = &parse
                        && let Some(entry) = store.anchor(id)
                    {
                        let valid = entry.roots_at(now);
                        roots = entry.roots.len();
                        expired = roots - valid.len();
                        pinned.insert(
                            id.clone(),
                            entry
                                .roots
                                .iter()
                                .map(|root| trust::fingerprint(root.as_bytes()))
                                .collect(),
                        );
                        if roots > 0 {
                            if valid.is_empty() {
                                report.problem(format!(
                                    "`anchor {id}` has no root valid now (accept a fresh one: \
                                     git time tsa restore {id} --accept <id>=<fp>)"
                                ));
                            } else {
                                let latest = entry
                                    .roots
                                    .iter()
                                    .filter_map(|root| {
                                        x509_cert::Certificate::from_der(root.as_bytes()).ok()
                                    })
                                    .filter_map(|certificate| {
                                        i64::try_from(
                                            certificate
                                                .tbs_certificate
                                                .validity
                                                .not_after
                                                .to_unix_duration()
                                                .as_secs(),
                                        )
                                        .ok()
                                    })
                                    .max()
                                    .and_then(|second| jiff::Timestamp::from_second(second).ok())
                                    .map_or_else(
                                        || "-".to_owned(),
                                        |at| at.strftime("%Y-%m-%d").to_string(),
                                    );
                                report.say(format!(
                                    "anchor {id}: {roots} root(s), latest notAfter {latest}"
                                ));
                            }
                        }
                    }
                    anchor_reports.push(json!({
                        "id": id,
                        "path": anchor.path,
                        "fingerprint": fingerprint,
                        "missing": false,
                        "unparseable": parse.is_err(),
                        "roots": roots,
                        "expired": expired,
                    }));
                }
            },
        }
    }
    // HEAD's own block names the roots its evidence was checked against. A
    // fingerprint this machine has not pinned makes that evidence unreadable
    // later, which is exactly the rotation a human has to accept now.
    let mut unpinned: BTreeSet<(String, String)> = BTreeSet::new();
    if let Ok(Some(oid)) = repo.resolve_ref("HEAD")
        && let Ok((object, _)) = repo.read_commit(&oid)
        && let Some(trailer) = object.pre_image(store::PREFIX).trailer
        && let Ok(Some(block)) = store::decode(&trailer)
    {
        for (id, fingerprints) in &block.anchors {
            for fingerprint in fingerprints {
                if !pinned
                    .get(id)
                    .is_some_and(|known| known.contains(fingerprint))
                {
                    unpinned.insert((id.clone(), fingerprint.clone()));
                }
            }
        }
    }
    for (id, fingerprint) in unpinned {
        report.problem(format!(
            "HEAD names `anchor {id}` fingerprint {fingerprint}, which is not pinned \
             (git time tsa restore {id} --accept {id}={fingerprint})"
        ));
    }
    // An anchor for an id without a url is invisible to the policy; say so.
    for anchor in &configured {
        if !ids.contains(&anchor.id) {
            report.say(format!(
                "anchor {}: {} (no url configured, unused)",
                anchor.id,
                anchor.configured.display()
            ));
        }
    }

    let enabled = repo
        .config_non_empty("time.enabled")
        .map_err(Exit::config)?
        .is_none_or(|value| {
            !matches!(
                value.to_ascii_lowercase().as_str(),
                "false" | "no" | "off" | "0"
            )
        });
    report.say(format!("enabled: {enabled}"));
    let problem_count = report.problems.len();
    report.say(format!("problems: {problem_count}"));

    let code = if report.problems.is_empty() { 0 } else { 1 };
    if json_output {
        let hooks: Map<String, Value> = states
            .iter()
            .map(|(name, state)| ((*name).to_owned(), json!(state.as_str())))
            .collect();
        let value = json!({
            "binary": binary,
            "hooks_dir": dir,
            "hooks": hooks,
            "gate": { "value": gate, "hooks_match": gate_matches },
            "tsa": ids.len(),
            "anchors": anchor_reports,
            "enabled": enabled,
            "problems": report.problems,
        });
        match serde_json::to_string_pretty(&value) {
            Ok(text) => println!("{text}"),
            Err(error) => return Err(Exit::config(format!("cannot render JSON: {error}"))),
        }
    } else {
        for line in &report.lines {
            println!("{line}");
        }
    }
    Ok(code)
}

/// The `git-time` executable on `PATH`, if any.
#[must_use]
pub fn binary_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("git-time"))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}
